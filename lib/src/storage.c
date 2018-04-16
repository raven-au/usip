/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <sys/time.h>

#include "usip.h"

struct packed_timeval {
	  __time_t tv_sec;
	  __suseconds_t tv_usec;
} __packed;

static int storage_get_enospc_params(struct event *event, struct nlattr **attrs)
{
	struct packed_timeval *ptv;
	int ret;

	ret = NLE_INVAL;

	if (!attrs[USIP_EVENT_ATTR_PID])
		goto done;
	event->storage.pid = nla_get_u32(attrs[USIP_EVENT_ATTR_PID]);
	printf("pid: %u\n", event->storage.pid);

	if (!attrs[USIP_EVENT_ATTR_VPID])
		goto get_uid;
	event->storage.vpid = nla_get_u32(attrs[USIP_EVENT_ATTR_VPID]);

get_uid:
	if (!attrs[USIP_EVENT_ATTR_UID])
		goto done;
	event->storage.uid = nla_get_u32(attrs[USIP_EVENT_ATTR_UID]);
	printf("uid: %u\n", event->storage.uid);

	if (!attrs[USIP_EVENT_ATTR_INO])
		goto done;
	event->storage.ino = nla_get_u64(attrs[USIP_EVENT_ATTR_INO]);

	if (!attrs[USIP_EVENT_ATTR_MOUNTPOINT])
		goto done;
	event->storage.mp = nla_strdup(attrs[USIP_EVENT_ATTR_MOUNTPOINT]);
	if (!event->storage.mp) {
		ret = NLE_NOMEM;
		goto done;
	}

	if (!attrs[USIP_EVENT_ATTR_DEVICE])
		goto done;
	event->storage.dev = nla_strdup(attrs[USIP_EVENT_ATTR_DEVICE]);
	if (!event->storage.dev) {
		ret = NLE_NOMEM;
		free(event->storage.mp);
		goto done;
	}

	if (!attrs[USIP_EVENT_ATTR_TIME])
		goto done;
	ptv = nla_data(attrs[USIP_EVENT_ATTR_TIME]);
	printf("ptv->tv_sec %lu ptv->tv_usec %lu\n", ptv->tv_sec, ptv->tv_usec);
	event->storage.tv.tv_sec = ptv->tv_sec;
	event->storage.tv.tv_usec = ptv->tv_usec;

	ret = 0;
done:
	return ret;
}

static int storage_get_reply_params(struct event *event,
				    struct notifier *notifier,
				    struct nlattr **attrs)
{
	int ret = 0;

	switch (notifier->action) {
	case USIP_NOTIFY_ENOSPC:
		ret = storage_get_enospc_params(event, attrs);
		if (ret)
			goto out;
		break;
	default:
		break;
	}
out:
	return ret;
}

static void storage_release_enospc(struct event *event)
{
	free(event->storage.mp);
	free(event->storage.dev);
}

static void storage_release(struct event *event, struct notifier *notifier)
{
	switch (notifier->action) {
	case USIP_NOTIFY_ENOSPC:
		storage_release_enospc(event);
		break;
	default:
		break;
	}
}

static const struct usip_notifier_ops usip_storage_ops = {
	.put_request_params = NULL,
	.get_reply_params = storage_get_reply_params,
	.release = storage_release,
};

void usip_set_storage_ops(struct notifier *notifier)
{
	notifier->ops = &usip_storage_ops;
}
