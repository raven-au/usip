/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/jiffies.h>

#include "usip.h"
#include "internal.h"

#define USIP_MTAB_BUF_SIZE	256
#define USIP_RECORDS_PER_MSG	8

static int process_buffer(char *buf, char **fragment, struct sk_buff *msg)
{
	char *work, *save;
	size_t len;

	len = strlen(buf);
	if (*fragment)
		len += strlen(*fragment);
	work = kzalloc(len, GFP_KERNEL);
	if (!work)
		return -ENOMEM;
	save = work;

	if (!*fragment)
		strcpy(work, buf);
	else {
		strcpy(work, *fragment);
		strcat(work, buf);
		kfree(*fragment);
		*fragment = NULL;
	}

	while (work) {
		char *line;
		size_t l_len;
		int err;

		line = strsep(&work, "\n");
		if (!line)
			break;
		l_len = strlen(line);
		line[l_len] = 0;
		if (!work) {
			*fragment = kstrdup(line, GFP_KERNEL);
			if (!*fragment) {
				kfree(save);
				return -ENOMEM;
			}
			break;
		}

		err = nla_put_string(msg, NLA_STRING, line);
		if (err) {
			kfree(save);
			return -ENOMEM;
		}
	}
	kfree(save);

	return 0;
}

static int usip_mtab_read_mtab_chunk(struct usip_message_info *umi,
				     struct file *mt, char *fragment)
{
	struct nlattr *mt_ents;
	char *buf;
	loff_t pos;
	int i, err;

	buf = kmalloc(USIP_MTAB_BUF_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	mt_ents = nla_nest_start(umi->msg, USIP_MTAB_ATTR_MTAB);
	if (!mt_ents) {
		err = -EMSGSIZE;
		nla_nest_cancel(umi->msg, mt_ents);
		goto out;
	}

	/* TODO: fill to integral number of entries <=
	 * message payload size (currently set to force
	 * multi-part message for testing.
	 */
	for (i = 0; i < USIP_RECORDS_PER_MSG; i++) {
		size_t count;

		memset(buf, 0, USIP_MTAB_BUF_SIZE);

		pos = mt->f_pos;
		count = kernel_read(mt, buf, USIP_MTAB_BUF_SIZE - 1, &pos);
		if (!count) {
			err = USIP_MTAB_DONE;
			nla_nest_end(umi->msg, mt_ents);
			goto out;
		}
		if (count < 0) {
			err = count;
			nla_nest_cancel(umi->msg, mt_ents);
			goto out;
		}
		buf[count] = 0;
		mt->f_pos = pos;

		err = process_buffer(buf, &fragment, umi->msg);
		if (err) {
			nla_nest_cancel(umi->msg, mt_ents);
			goto out;
		}
	}
	err = USIP_MTAB_CONTINUE;
	nla_nest_end(umi->msg, mt_ents);
out:
	kfree(buf);

	return err;
}

static int usip_mtab_read_mtab(struct genl_info *info, struct file *mt)
{
	struct usip_message_info umi;
	char *fragment = NULL;
	bool done = false;
	int err;

	umi.info = info;

	while (!done) {
		int ret;

		err = usip_new_msg(&umi, USIP_MTAB_CMD_GET_MTAB, NLM_F_MULTI);
		if (err)
			goto out;

		err = usip_mtab_read_mtab_chunk(&umi, mt, fragment);
		if (err < 0) {
			nlmsg_free(umi.msg);
			goto out;
		}

		if (err == USIP_MTAB_DONE) {
			info->nlhdr->nlmsg_type |= NLMSG_DONE;
			done = true;
		}


		ret = usip_send_status(&umi, USIP_ATTR_STATUS, err);
		if (ret < 0) {
			err = ret;
			goto out;
		}
	}

	if (fragment)
		kfree(fragment);

	return err;
out:
	if (fragment)
		kfree(fragment);
	return usip_send_status_reply(info, USIP_MTAB_CMD_GET_MTAB, err);
}

int usip_mtab_get_mtab(struct sk_buff *skb, struct genl_info *info)
{
	struct file *mt;
	int mtabfd;
	int err;

	mt = NULL;

	err = -EINVAL;
	if (!info->attrs[USIP_MTAB_ATTR_MTABFD])
		goto out;

	err = -EBADF;
	mtabfd = nla_get_s32(info->attrs[USIP_MTAB_ATTR_MTABFD]);
	if (!mtabfd)
		goto out;
	mt = fget(mtabfd);
	if (!mt)
		goto out;
	if (!mt->f_op || !mt->f_op->read)
		goto out_fput;

	err = usip_mtab_read_mtab(info, mt);

	fput(mt);

	return err;

out_fput:
	fput(mt);
out:
	return usip_send_status_reply(info, USIP_MTAB_CMD_GET_MTAB, err);
}

static int
mtab_get_request_params(struct sk_buff* skb, struct notifier *notifier)
{
	notifier->mc_group = USIP_MC_MTAB_GROUP;
	notifier->mtab.event = get_jiffies_64();
	return 0;
}

static int
mtab_put_reply_params(struct sk_buff* skb, struct event_notify *notify)
{
	int err = 0;

	err = nla_put_u32(skb, USIP_EVENT_ATTR_ACTION, notify->action);
	if (err)
		pr_err("can't put event action in message: error %d\n", err);

	err = nla_put_u8(skb, USIP_EVENT_ATTR_CMD, notify->cmd);
	if (err)
		pr_err("can't put event cmd in message: error %d\n", err);

	return err;
}

static struct notifier *
mtab_match_notifier(struct notifier *notifiers, struct event_notify *notify)
{
	struct notifier *this;

	this = notifiers;
	while (this) {
		if (this->type != notify->type)
			goto next;
		if (this->action && this->action != notify->action)
			goto next;
		if (this->cmd && this->cmd != notify->cmd)
			goto next;
		if (notify->mtab.event &&
		    time_before64(this->mtab.event, notify->mtab.event))
		    break;
next:
		this = this->next;
	}

	if (this) {
		notify->mc_group = this->mc_group;
		notify->action = this->action;
		notify->cmd = this->cmd;
	}

	return this;
}

static int mtab_notify(struct net *net,
		       struct notifier *notifier,
		       struct event_notify *notify)
{
	unsigned int flags = notifier->flags;
	int ret = 0;

	if (flags & USIP_FLAGS_NOTIFIER_KERN_LOG)
		pr_err("log event\n");

	if (flags & USIP_FLAGS_NOTIFIER_NOTIFY)
		ret = usip_send_notification(net, notifier, notify);
	return ret;
}

static const struct usip_notifier_ops usip_mtab_ops = {
	.get_request_params = mtab_get_request_params,
	.put_reply_params = mtab_put_reply_params,
	.match_notifier = mtab_match_notifier,
	.notify = mtab_notify,
	.release = NULL,
};

void usip_mtab_set_ops(struct notifier *notifier)
{
	notifier->ops = &usip_mtab_ops;
}

int usip_notify_mtab_event(unsigned int action, unsigned char cmd, u64 event)
{
	struct event_notify *new;
	/*struct pid *pid;*/

	if (!usip_have_listeners() ||
	    !usip_event_handler_running())
		goto out;

	new = usip_event_notify_alloc(GFP_NOWAIT|__GFP_NORETRY);
	if (!new)
		return -ENOMEM;

	new->mnt_ns = current->nsproxy->mnt_ns;
	new->type = USIP_EVENT_TYPE_MTAB;
	new->action = action;
	new->cmd = cmd;
	new->ops = NULL;
	new->mtab.event = event;

	usip_event_queue(new);
out:
	return 0;
}

