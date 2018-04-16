/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <pthread.h>

#define INCLUDE_USIP_POLICY
#include "usip.h"

struct usip_mtab_control {
	int family;
	struct nl_sock *sock;
	unsigned short version;
};
struct usip_mtab_control ctl;

static bool init_done = false;
static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

int usip_init(void)
{
	struct nl_sock *sock;
	int family, fd, cl_flags;
	int ret = 0;

	pthread_mutex_lock(&init_mutex);
	if (init_done)
		goto out;

	sock = nl_socket_alloc();
	if (!sock) {
		ret = -NLE_NOMEM;
		goto out;
	}

	ret = genl_connect(sock);
	if (ret < 0) {
		nl_socket_free(sock);
		goto out;
	}

	fd = nl_socket_get_fd(sock);
	if ((cl_flags = fcntl(fd, F_GETFD, 0)) != -1) {
		cl_flags |= FD_CLOEXEC;
		fcntl(fd, F_SETFD, cl_flags);
	}

	family = genl_ctrl_resolve(sock, USIP_FAMILY);
	if (family < 0) {
		ret = family;
		nl_socket_free(sock);
		goto out;
	}


	ctl.sock = sock;
	ctl.family = family;
	ctl.version = USIP_VERSION;

	init_done = true;
out:
	pthread_mutex_unlock(&init_mutex);
	return ret;
}

void usip_close(void)
{
	pthread_mutex_lock(&init_mutex);
	if (!ctl.sock)
		goto out;

	if (!init_done)
		goto out;

	nl_close(ctl.sock);
	nl_socket_free(ctl.sock);
	ctl.sock = NULL;
	ctl.family = 0;
	init_done = false;
out:
	pthread_mutex_unlock(&init_mutex);
}

int usip_ping(void)
{
	struct usip_message_info umi;
	unsigned int status;
	int ret = 0;

	ret = usip_init();
	if (ret)
		goto out;

	ret = usip_new_msg(&umi,
			   USIP_CMD_PING,
			   NLM_F_REQUEST|NLM_F_ACK);
	if (ret < 0)
		goto out;

	ret = usip_send_msg_with_reply(umi.msg,
				       usip_parse_status_reply, &status);
	if (ret < 0) {
                nlmsg_free(umi.msg);
		goto out;
	}

	if (!status)
		ret = std_err_to_nle_err(status);
out:
	usip_close();
	return ret;
}

const char *usip_perror(int nle_error)
{
	return nl_geterror(nle_error);
}

int std_err_to_nle_err(int error)
{
	int nle_error;

	if (error < 0)
		error = -error;

	switch (error) {
	case EINVAL:
		nle_error = NLE_INVAL;
		break;
	case ENOENT:
		nle_error = NLE_OBJ_NOTFOUND;
		break;
	case ENOMEM:
		nle_error = NLE_NOMEM;
		break;
	case ERANGE:
		nle_error = NLE_MSGSIZE;
		break;
	case EPERM:
		nle_error = NLE_PERM;
	default:
		nle_error = NLE_FAILURE;
	}

	return nle_error;
}

int usip_new_msg(struct usip_message_info *umi, uint8_t cmd, int flags)
{
	struct nl_msg *msg;
	void *hdr;
	int err;

	err = -NLE_NOMEM;

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	hdr =  genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
			   ctl.family, 0, flags, cmd, USIP_VERSION);
	if (!hdr) {
		nlmsg_free(msg);
		goto out;
	}

	err = 0;
	umi->msg = msg;
	umi->hdr = hdr;
out:
	return err;
};

static struct nl_cb *alloc_cb(nl_recvmsg_msg_cb_t func, int cb_type, void *arg)
{
	struct nl_cb *cb;
	int ret;

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb) {
		errno = -NLE_NOMEM;
		return NULL;
	}

	ret = nl_cb_set(cb, cb_type, NL_CB_CUSTOM, func, arg);
	if (ret < 0) {
		errno = ret;
		nl_cb_put(cb);
		return NULL;
	}

	return cb;
}

int usip_parse_status_reply(struct nl_msg *msg, void *arg)
{
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *attrs[USIP_ATTRS_MAX + 1];
        int *status = (int *) arg;

        genlmsg_parse(nlh, 0, attrs, USIP_ATTRS_MAX, usip_policy);

        if (!attrs[USIP_ATTR_STATUS])
                return NL_OK;

        *status = nla_get_s32(attrs[USIP_ATTR_STATUS]);

        return NL_STOP;
}

int usip_send_msg_with_reply(struct nl_msg *msg,
			     nl_recvmsg_msg_cb_t func, void *arg)
{
	struct nl_cb *cb;
	int ret = 0;

	ret = nl_send_auto_complete(ctl.sock, msg);
	if (ret < 0)
		goto out;

	nlmsg_free(msg);

	cb = alloc_cb(func, NL_CB_VALID, arg);
	if (!cb) {
		ret = errno;
		goto out;
	}

	ret = nl_recvmsgs(ctl.sock, cb);
	if (ret < 0) {
		nl_cb_put(cb);
		goto out;
	}

	nl_cb_put(cb);

	ret = nl_wait_for_ack(ctl.sock);
out:
	return ret;
}
