/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <errno.h>

#define INCLUDE_USIP_POLICY
#include "usip.h"

struct event *usip_event_alloc(void)
{
	struct event *event;
	int status;

	event = malloc(sizeof(struct event));
	if (!event)
		return NULL;
	memset(event, 0, sizeof(struct event));

	status = pthread_rwlock_init(&event->rwlock, NULL);
	if (status) {
		free(event);
		errno = status;
		return NULL;
	}

	return event;
}

static void usip_free_notifiers(struct event *event)
{
	struct notifier *notifier;
	struct status;

	pthread_rwlock_wrlock(&event->rwlock);
	notifier = event->notifiers;
	while (notifier) {
		struct notifier *next = notifier->next;

		free(notifier);
		notifier = next;
	}
	pthread_rwlock_unlock(&event->rwlock);
}

void usip_event_free(struct event *event)
{
	usip_free_notifiers(event);
	pthread_rwlock_destroy(&event->rwlock);
	free(event);
}

static void usip_set_ops(struct notifier *notifier)
{
	printf("notifier->type %x USIP_EVENT_TYPE_STORAGE %x\n",
			notifier->type, USIP_EVENT_TYPE_STORAGE);
	switch (notifier->type) {
	case USIP_EVENT_TYPE_STORAGE:
		usip_set_storage_ops(notifier);
		break;
	default:
		break;
	}
}

int usip_add_notifier(struct event *event, struct notifier *notifier)
{
	struct notifier *new;
	int status;

	new = malloc(sizeof(struct notifier));
	if (!new)
		return NLE_NOMEM;
	memset(new, 0, sizeof(struct notifier));

	new->mc_grp_name = notifier->mc_grp_name;
	new->type = notifier->type;
	new->action = notifier->action;
	new->cmd = notifier->cmd;
	new->flags = notifier->flags;
	new->callback = notifier->callback;
	new->arg = notifier->arg;
	usip_set_ops(new);
	new->next = NULL;

	status = pthread_rwlock_wrlock(&event->rwlock);
	if (status) {
		free(new);
		return std_err_to_nle_err(status);
	}

	if (!event->notifiers)
		event->notifiers = new;
	else {
		new->next = event->notifiers;
		event->notifiers = new;
	}

	pthread_rwlock_unlock(&event->rwlock);

	return 0;
}

struct notify_register {
	struct event *event;
	int status;
};

static int parse_register_reply(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlattr *attrs[USIP_ATTRS_MAX + 1];
	struct notify_register *notify = arg;

	genlmsg_parse(nlh, 0, attrs, USIP_ATTRS_MAX, usip_policy);

	if (!attrs[USIP_ATTR_STATUS])
		return NL_OK;

	notify->status = nla_get_s32(attrs[USIP_ATTR_STATUS]);
	if (notify->status)
		return NL_STOP;

	if (!attrs[USIP_EVENT_ATTR_GROUP] ||
	    !attrs[USIP_EVENT_ATTR_ID]) {
		notify->status = -ENOENT;
		return NL_STOP;
	}

	notify->event->group = nla_get_s32(attrs[USIP_EVENT_ATTR_GROUP]);
	notify->event->id = nla_get_s32(attrs[USIP_EVENT_ATTR_ID]);

	return NL_STOP;
}

int usip_notify_register(struct event *event)
{
	struct notify_register notify;
	const struct usip_notifier_ops *ops;
	struct usip_message_info umi;
	struct nlattr *notifiers;
	struct notifier *this;
	int status;
	int ret = 0;

	ret = usip_init();
	if (ret)
		goto out;

	ret = usip_new_msg(&umi,
			   USIP_EVENT_CMD_REGISTER, NLM_F_REQUEST|NLM_F_ACK);
	if (ret < 0) {
		printf("usip_new_msg() failed\n");
		goto out;
	}

	if (event->flags) {
		ret = nla_put_u32(umi.msg, USIP_EVENT_ATTR_FLAGS, event->flags);
		if (ret < 0) {
			printf("nla_put_u32() flags failed\n");
                	nlmsg_free(umi.msg);
			goto out;
		}
	}

	notifiers = nla_nest_start(umi.msg, USIP_EVENT_ATTR_NOTIFIERS);
	if (!notifiers) {
		printf("nla_nest_start() notifiers failed\n");
                nlmsg_free(umi.msg);
		ret = NLE_MSGSIZE;
		goto out;
	}

	status = pthread_rwlock_rdlock(&event->rwlock);
	if (status) {
		printf("rwlock failed\n");
               	nlmsg_free(umi.msg);
		ret = std_err_to_nle_err(status);
		goto out;
	}

	this = event->notifiers;
	while (this) {
		ret = nla_put_u32(umi.msg, USIP_EVENT_ATTR_TYPE, this->type);
		if (ret < 0) {
			printf("nla_put_u32() type failed\n");
			nla_nest_cancel(umi.msg, notifiers);
                	nlmsg_free(umi.msg);
			goto out_unlock;
		}

		ret = nla_put_u32(umi.msg, USIP_EVENT_ATTR_ACTION, this->action);
		if (ret < 0) {
			printf("nla_put_u32() action failed %d\n", ret);
			nla_nest_cancel(umi.msg, notifiers);
                	nlmsg_free(umi.msg);
			goto out_unlock;
		}

		ret = nla_put_u8(umi.msg, USIP_EVENT_ATTR_ACTION, this->cmd);
		if (ret < 0) {
			printf("nla_put_u8() cmd failed %d\n", ret);
			nla_nest_cancel(umi.msg, notifiers);
                	nlmsg_free(umi.msg);
			goto out_unlock;
		}

		ret = nla_put_u32(umi.msg, USIP_EVENT_ATTR_ACTION, this->flags);
		if (ret < 0) {
			printf("nla_put_u32() flags failed %d\n", ret);
			nla_nest_cancel(umi.msg, notifiers);
                	nlmsg_free(umi.msg);
			goto out_unlock;
		}

		ops = this->ops;
		if (!ops || !ops->put_request_params)
			goto next;

		ret = ops->put_request_params(event, this, umi.msg);
		if (ret < 0) {
			printf("put_request_params() failed %d\n", ret);
			nla_nest_cancel(umi.msg, notifiers);
        	       	nlmsg_free(umi.msg);
			goto out_unlock;
		}
next:
		this = this->next;
	}

	nla_nest_end(umi.msg, notifiers);

	pthread_rwlock_unlock(&event->rwlock);

	notify.event = event;
	ret = usip_send_msg_with_reply(umi.msg, parse_register_reply, &notify);
	if (ret < 0)
		goto out;

	if (notify.status) {
		printf("register failed failed notify.status %d\n", notify.status);
		ret = std_err_to_nle_err(notify.status);
		goto out;
	}
	ret = 0;

	usip_close();
	return 0;

out_unlock:
	pthread_rwlock_unlock(&event->rwlock);
out:
	usip_close();
	return ret;
}

int usip_notify_unregister(struct event *event)
{
	struct usip_message_info umi;
	unsigned int status;
	int ret = 0;

	ret = usip_init();
	if (ret)
		goto out;

	ret = usip_new_msg(&umi,
			   USIP_EVENT_CMD_UNREGISTER,
			   NLM_F_REQUEST|NLM_F_ACK);
	if (ret < 0)
		goto out;

	ret = nla_put_s32(umi.msg, USIP_EVENT_ATTR_GROUP, event->group);
	if (ret < 0) {
		nlmsg_free(umi.msg);
		goto out;
	}

	ret = nla_put_s32(umi.msg, USIP_EVENT_ATTR_ID, event->id);
	if (ret < 0) {
		nlmsg_free(umi.msg);
		goto out;
	}

	status = 0;
	ret = usip_send_msg_with_reply(umi.msg,
				       usip_parse_status_reply, &status);
	if (ret < 0)
		goto out;

	if (status)
		ret = std_err_to_nle_err(status);
out:
	usip_close();
	return ret;
}

struct mc_group {
	int group;
	struct mc_group *next;
};

static int
usip_add_group_memberships(struct nl_sock *mc_sock, struct mc_group *grps)
{
	struct mc_group *this = grps;
	int err;

	while (this) {
		err = nl_socket_add_membership(mc_sock, this->group);
		if (err < 0) {
			printf("failed to add mc group %d\n", this->group);
			break;
		}
		this = this->next;
	}
	return err;
}

/*
static void
usip_drop_group_memberships(struct nl_sock *mc_sock, struct mc_group *grps)
{
	struct mc_group *this = grps;

	while (this) {
		struct mc_group *next = this->next;

		nl_socket_drop_membership(mc_sock, this->group);
		free(this);
		this = next;		
	}
}
*/

static void usip_free_mc_groups(struct mc_group *grps)
{
	struct mc_group *this = grps;

	while (this) {
		struct mc_group *next = this->next;

		free(this);
		this = next;		
	}
}

/*
static void dump_mc_groups(struct mc_group *grps)
{
	struct mc_group *this = grps;

	while (this) {
		printf("dump_mc_groups: group %d\n", this->group);
		this = this->next;		
	}
}
*/

static int usip_add_mc_groups(struct nl_sock *mc_sock, struct event *event)
{
	struct notifier *notifier;
	struct mc_group *grps = NULL;
	int status;
	int ret = 0;

	status = pthread_rwlock_rdlock(&event->rwlock);
	if (status) {
		ret = std_err_to_nle_err(status);
		goto out_err;
	}

	notifier = event->notifiers;
	while (notifier) {
		struct mc_group *new, *this;
		int gid;

		gid = genl_ctrl_resolve_grp(mc_sock,
					    USIP_FAMILY, notifier->mc_grp_name);
		if (gid < 0) {
			printf("failed to resolve mc group %s\n", notifier->mc_grp_name);
			ret = gid;
			goto out_unlock;
		}

		notifier = notifier->next;

		this = grps;
		while (this) {
			if (this->group == gid)
				break;
			this = this->next;
		}

		if (this)
			continue;

		new = malloc(sizeof(struct mc_group));
		if (!new)
			goto out_unlock;
		memset(new, 0, sizeof(struct mc_group));

		new->group = gid;

		if (!grps)
			grps = new;
		else {
			new->next = grps;
			grps = new;
		}
	}

	pthread_rwlock_unlock(&event->rwlock);

	ret = usip_add_group_memberships(mc_sock, grps);
	if (ret < 0) {
		printf("usip_add_group_memberships failed\n");
		usip_free_mc_groups(grps);
		goto out_err;
	}

	usip_free_mc_groups(grps);

	return 0;

out_unlock:
	pthread_rwlock_unlock(&event->rwlock);
out_err:
	/*usip_drop_group_memberships(mc_sock, grps);*/
	return ret;
}

static int usip_handle_notify(struct nl_msg *msg, void *arg)
{
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *attrs[USIP_ATTRS_MAX + 1];
        struct notify_params *params = (struct notify_params *) arg;
	struct event *event = params->event;
	unsigned int type;
	unsigned int action;
	unsigned char cmd;
	int group;
	int ret;

        genlmsg_parse(nlh, 0, attrs, USIP_ATTRS_MAX, usip_policy);

	printf("event callback called\n");

	if (!attrs[USIP_EVENT_ATTR_TYPE]) {
		printf("event type not set in notification\n");
		params->status = NLE_INVAL;
		goto done;
	}
	type = nla_get_u32(attrs[USIP_EVENT_ATTR_TYPE]);

	if (!attrs[USIP_EVENT_ATTR_GROUP]) {
		printf("event group not set in notification\n");
		params->status = NLE_INVAL;
		goto done;
	}
        group = nla_get_s32(attrs[USIP_EVENT_ATTR_GROUP]);

	if (!attrs[USIP_EVENT_ATTR_ACTION]) {
		printf("event action not set in notification\n");
		params->status = NLE_INVAL;
		goto done;
	}
	action = nla_get_u32(attrs[USIP_EVENT_ATTR_ACTION]);

	if (!attrs[USIP_EVENT_ATTR_CMD]) {
		printf("event cmd not set in notification\n");
		params->status = NLE_INVAL;
		goto done;
	}
	cmd = nla_get_u8(attrs[USIP_EVENT_ATTR_CMD]);

	printf("event got params\n");

	if (!event->group || event->group == group) {
		struct notifier *notifier = event->notifiers;
		const struct usip_notifier_ops *ops = NULL;

		while (notifier) {
			if (notifier->type != type ||
			    notifier->action != action ||
			    notifier->cmd != cmd) {
				notifier = notifier->next;
				continue;
			}

			printf("notifier->ops %p\n", notifier->ops);
			ops = notifier->ops;
			if (!ops || !ops->get_reply_params)
				break;
			printf("call get_reply_params\n");
			ret = ops->get_reply_params(event, notifier, attrs);
			printf("ret %d\n", ret);
			if (ret) {
				params->status = ret;
				goto done;
			}

			break;
		}

		ret = NLE_INVAL;
		if (!notifier) {
			params->status = ret;
			goto done;
		}

		printf("notifier %p notifier->callback %p\n", notifier, notifier->callback);
		if (notifier->callback) {
			unsigned int action;

			if (notifier->cmd)
				action = notifier->cmd;
			else if (notifier->action)
				action = notifier->action;
			else {
				params->status = ret;
				goto done;
			}
			
			ret = notifier->callback(action, notifier->arg);
			if (ret)
				params->status = std_err_to_nle_err(ret);
		}

		if (ops && ops->release)
			ops->release(event, notifier);
	}
done:
        return NL_STOP;
}

static int poll_nl_sock(struct nl_sock *mc_sock, int timeout)
{
	struct pollfd fds[1];
	int ret;

	fds[0].fd = nl_socket_get_fd(mc_sock);
	fds[0].events = POLLIN;

	ret = poll(fds, 1, timeout * 1000);
	if (ret <= 0) {
		if (ret == 0)
			ret = -ETIMEDOUT;
		else
			ret = -errno;
	}

	return ret;
}

int usip_mc_notify(struct notify_params *params)
{
	struct nl_sock *mc_sock;
	struct event *event = params->event;
	int family;
	int fd, cl_flags;
	int ret = 0;
	int timeout = 10;

	mc_sock = nl_socket_alloc();
	if (!mc_sock) {
		ret = -NLE_NOMEM;
		goto out;
	}

	/* Disable seq checks on multicast sockets. */
	nl_socket_disable_seq_check(mc_sock);
	nl_socket_disable_auto_ack(mc_sock);

	/* Allow interrupting receive */
	nl_socket_set_nonblocking(mc_sock);

	/* 
	 * Define a callback function, which will be called for
	 * each notification received.
	 */
	nl_socket_modify_cb(mc_sock,
			    NL_CB_VALID, NL_CB_CUSTOM,
			    usip_handle_notify, params);

	ret = genl_connect(mc_sock);
	if (ret < 0)
		goto out_free;

	fd = nl_socket_get_fd(mc_sock);
	if ((cl_flags = fcntl(fd, F_GETFD, 0)) != -1) {
		cl_flags |= FD_CLOEXEC;
		fcntl(fd, F_SETFD, cl_flags);
	}

	family = genl_ctrl_resolve(mc_sock, USIP_FAMILY);
	if (family < 0) {
		ret = family;
		goto out_free;
	}

	ret = usip_add_mc_groups(mc_sock, event);
	if (ret < 0) {
		printf("usip_add_mc_groups failed\n");
		goto out_free;
	}

	params->done = 0;
	while (!params->done) {
		ret = poll_nl_sock(mc_sock, timeout);
		if (ret < 0) {
			if (ret == -ETIMEDOUT)
				continue;
			if (ret == -EINTR)
				ret = 0;
			break;
		}

		ret = nl_recvmsgs(mc_sock, nl_socket_get_cb(mc_sock));
		if (ret < 0) {
			printf("nl_recvmsgs failed\n");
			goto out_free;
		}
	}

out_free:
	nl_socket_free(mc_sock);
out:
	return ret;
}
