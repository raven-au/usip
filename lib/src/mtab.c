/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>

#define INCLUDE_USIP_POLICY
#include "usip.h"

struct get_mtab {
	struct mounts *mounts;
	int status;
};

static void mtab_add_mounts(struct get_mtab *mtab, struct mounts *mounts)
{
	struct mounts *mnts = mtab->mounts;

	if (!mnts)
		mtab->mounts = mounts;
	else {
		while (mnts->next)
			mnts = mnts->next;
		mnts->next = mounts;
	}
}

static int get_mtab_entries(struct nlattr *attr, struct mounts **mounts)
{
	struct mounts *mnt, *last;
	struct nlattr *this;
	int remaining;
	int ret = 0;

	*mounts = mnt = NULL;

	remaining = nla_len(attr);
	this = nla_data(attr);
	while (nla_ok(this, remaining)) {
		struct mounts *new;
		char *entry;

		new = malloc(sizeof(struct mounts));
		if (!new) {
			ret = -NLE_NOMEM;
			usip_mtab_free_mounts(mnt);
			goto out;
		}
		new->next = NULL;

		entry = nla_strdup(this);
		if (!entry) {
			ret = -NLE_NOMEM;
			usip_mtab_free_mounts(mnt);
			goto out;
		}
		new->entry = entry;

		if (!mnt)
			mnt = last = new;
		else {
			last->next = new;
			last = new;
		}

		this = nla_next(this, &remaining);
	}

	*mounts = mnt;
out:
	return ret;
}

void usip_mtab_free_mounts(struct mounts *mounts)
{
	struct mounts *this = mounts;

	while (this) {
		struct mounts *next = this->next;

		free(this->entry);
		free(this);
		this = next;
	}
}

static int parse_get_mtab_reply(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[USIP_ATTRS_MAX + 1];
	struct get_mtab *mtab = (struct get_mtab *) arg;

        genlmsg_parse(nlh, 0, attrs, USIP_ATTRS_MAX, usip_policy);

        if (!attrs[USIP_ATTR_STATUS])
                return NL_OK;

	if (attrs[USIP_MTAB_ATTR_MTAB]) {
		struct mounts *mounts = NULL;
		int ret;

		ret = get_mtab_entries(attrs[USIP_MTAB_ATTR_MTAB], &mounts);
		if (ret) {
			usip_mtab_free_mounts(mounts);
			mtab->mounts = NULL;
			mtab->status = ret;
			ret = NL_STOP;
			goto out;
		}
		mtab_add_mounts(mtab, mounts);
		printf("called mtab_add_mounts()\n");
	}

	mtab->status = nla_get_s32(attrs[USIP_ATTR_STATUS]);
	printf("mtab->status %d\n", mtab->status);
	if (mtab->status == USIP_MTAB_DONE) {
		printf("return NL_STOP\n");
		return NL_STOP;
	}
out:
        return NL_OK;
}

int usip_mtab_get_mtab(unsigned int action,
		       unsigned int table, struct mounts **mounts)
{
	struct usip_message_info umi;
	struct get_mtab mtab;
	char *name;
	int fd;
	int ret = 0;

	mtab.mounts = NULL;
	mtab.status = 0;

	ret = usip_init();
	if (ret)
		goto out;

	switch (table) {
	case USIP_MTAB_TABLE_MOUNTS:
		name = "/proc/self/mounts";
		break;
	case USIP_MTAB_TABLE_MOUNTINFO:
		name = "/proc/self/mountinfo";
		break;
	case USIP_MTAB_TABLE_MOUNTSTATS:
		name = "/proc/self/mountstats";
		break;
	default:
		ret = -NLE_INVAL;
		goto out;
	}

	fd = open(name, O_RDONLY);
	if (fd == -1) {
		ret = -NLE_NOACCESS;
		goto out;
	}

	ret = usip_new_msg(&umi, action, NLM_F_REQUEST|NLM_F_ACK);
	if (ret < 0)
		goto out;

	ret = nla_put_s32(umi.msg, USIP_MTAB_ATTR_MTABFD, fd);
        if (ret < 0) {
                nlmsg_free(umi.msg);
		goto out;
        }

	ret = usip_send_msg_with_reply(umi.msg, parse_get_mtab_reply, &mtab);
	if (ret < 0)
		goto out;

	*mounts = mtab.mounts;
out:
	usip_close();
	return ret;
}
