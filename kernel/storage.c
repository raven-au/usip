/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <linux/mount.h>
#include <linux/jiffies.h>
#include <linux/fs_struct.h>

#include "usip.h"
#include "internal.h"

static int
storage_get_request_params(struct sk_buff* skb, struct notifier *notifier)
{
	notifier->mc_group = USIP_MC_STORAGE_GROUP;
	return 0;
}

static int put_enospc_params(struct sk_buff *skb, struct event_notify *notify)
{
	unsigned long i_ino;
	struct packed_timeval {
	        __kernel_time_t         tv_sec;
        	__kernel_suseconds_t    tv_usec;
	} __packed ptv;
	pid_t pid, vpid;
	char *mp, *dev;
	int err = 0;

	mp = dev = NULL;

	pid = notify->storage.pid;
	vpid = notify->storage.vpid;
	i_ino = notify->storage.path.dentry->d_inode->i_ino;

	mp = get_mp_path(&notify->storage.path, &notify->storage.root);
	if (IS_ERR(mp)) {
		err = PTR_ERR(mp);
		goto out;
	}

	dev = get_dev_path(&notify->storage.path);
	if (IS_ERR(dev)) {
		err = PTR_ERR(dev);
		goto out;
	}

	err = nla_put_u32(skb, USIP_EVENT_ATTR_PID, notify->storage.pid);
	if (!err)
		goto put_vpid;
	pr_err("can't put storage event pid in message: error %d\n", err);
	goto out;

put_vpid:
	if (notify->storage.pid == notify->storage.vpid)
		goto put_uid;
	err = nla_put_u32(skb, USIP_EVENT_ATTR_VPID, notify->storage.vpid);
	if (!err)
		goto put_uid;
	pr_err("can't put storage event vpid in message: error %d\n", err);
	goto out;

put_uid:
	err = nla_put_u32(skb, USIP_EVENT_ATTR_UID, notify->storage.uid);
	if (!err)
		goto put_ino;
	pr_err("can't put storage event ino in message: error %d\n", err);
	goto out;

put_ino:
	err = nla_put_u64_64bit(skb, USIP_EVENT_ATTR_INO, i_ino, USIP_ATTR_PAD);
	if (!err)
		goto put_mountpoint;
	pr_err("can't put storage event uid in message: error %d\n", err);
	goto out;

put_mountpoint:
	err = nla_put_string(skb, USIP_EVENT_ATTR_MOUNTPOINT, mp);
	if (!err)
		goto put_device;
	pr_err("can't put storage event mountpoint in message: error %d\n", err);
	goto out;

put_device:
	err = nla_put_string(skb, USIP_EVENT_ATTR_DEVICE, dev);
	if (!err)
		goto put_time;
	pr_err("can't put storage event device in message: error %d\n", err);
	goto out;

put_time:
	ptv.tv_sec = notify->storage.time.tv_sec;
	ptv.tv_usec = notify->storage.time.tv_usec;
	pr_info("ptv.tv_sec %lu ptv.tv_usec %lu\n", ptv.tv_sec, ptv.tv_usec);
	err = nla_put(skb, USIP_EVENT_ATTR_TIME,
		      sizeof(struct packed_timeval), &ptv);
	if (!err)
		goto out;
	pr_err("can't put storage event time in message: error %d\n", err);
out:
	kfree(mp);
	kfree(dev);
	return err;
}

static int
storage_put_reply_params(struct sk_buff *skb, struct event_notify *notify)
{
	int err = 0;

	err = nla_put_u32(skb, USIP_EVENT_ATTR_ACTION, notify->action);
	if (err) {
		pr_err("can't put event action in message: error %d\n", err);
		goto out;
	}

	err = nla_put_u8(skb, USIP_EVENT_ATTR_CMD, notify->cmd);
	if (err) {
		pr_err("can't put event cmd in message: error %d\n", err);
		goto out;
	}

	switch (notify->action) {
	case USIP_NOTIFY_ENOSPC:
		err = put_enospc_params(skb, notify);
		break;
	default:
		break;
	}
out:
	return err;
}

static struct notifier *
storage_match_notifier(struct notifier *notifiers, struct event_notify *notify)
{
	struct notifier *this;

	this = notifiers;
	while (this) {
		pr_info("this->type %u notify->type %u\n", this->type, notify->type);
		if (this->type != notify->type)
			goto next;
		pr_info("this->action %u notify->action %u\n", this->action, notify->action);
		if (this->action && this->action != notify->action)
			goto next;
		pr_info("this->cmd %u notify->cmd %u\n", this->cmd, notify->cmd);
		if (this->cmd && this->cmd != notify->cmd)
			goto next;
		pr_info("matched notifier\n");
		/* TODO: storage event selecttion */
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

static int storage_notify(struct notifier *notifier, struct event_notify *notify)
{
	unsigned int flags = notifier->flags;
	int ret = 0;

	pr_info("flags 0x%x USIP_FLAGS_NOTIFIER_KERN_LOG 0x%x\n",
			flags, USIP_FLAGS_NOTIFIER_KERN_LOG);

	if (flags & USIP_FLAGS_NOTIFIER_KERN_LOG) {
		pr_info("notifier->action 0x%x USIP_NOTIFY_ENOSPC 0x%x\n",
			       	notifier->action, USIP_NOTIFY_ENOSPC);
		switch (notifier->action) {
		case USIP_NOTIFY_ENOSPC:
			ret = usip_log_enospc_event(notify);
			pr_info("ret %d\n", ret);
			break;
		}
	}

	if (flags & USIP_FLAGS_NOTIFIER_NOTIFY)
		ret = usip_send_notification(notifier, notify);

	return ret;
}

static void storage_release_notifier(struct notifier *notifier)
{
}

static struct usip_notifier_ops usip_storage_ops = {
	.get_request_params = storage_get_request_params,
	.put_reply_params = storage_put_reply_params,
	.match_notifier = storage_match_notifier,
	.notify = storage_notify,
	.release = storage_release_notifier,
};

void usip_storage_set_ops(struct notifier *notifier)
{
	notifier->ops = &usip_storage_ops;
}

static void storage_release_notify(struct event_notify *notify)
{
	if (notify->storage.need_put) {
		path_put(&notify->storage.path);
		path_put(&notify->storage.root);
		notify->storage.need_put = 0;
	}
}

static const struct usip_event_notify_ops usip_storage_notify_ops = {
	.release = storage_release_notify,
};

int usip_notify_storage_event(unsigned int action, unsigned char cmd, struct path *path)
{
	struct event_notify *new;
	struct pid *pid;
	kuid_t kuid;
	kgid_t kgid;

	if (!usip_have_listeners() ||
	    !usip_event_handler_running()) {
		pr_info("not notifing\n");
		goto out;
	}

	pid = get_task_pid(current, PIDTYPE_PID);
	if (!pid)
		return -EINVAL;

	new = usip_event_notify_alloc(GFP_ATOMIC);
	if (!new) {
		put_pid(pid);
		return -ENOMEM;
	}

	current_uid_gid(&kuid, &kgid);

	new->mnt_ns = current->nsproxy->mnt_ns;
	new->type = USIP_EVENT_TYPE_STORAGE;
	new->action = action;
	new->cmd = cmd;
	new->storage.pid = pid_nr(pid);
	new->storage.vpid = pid_vnr(pid);
	new->storage.uid = from_kuid_munged(current_user_ns(), kuid);
	new->storage.gid = from_kgid_munged(current_user_ns(), kgid);
	do_gettimeofday(&new->storage.time);
	get_fs_root(current->fs, &new->storage.root);
	new->storage.path = *path;
	path_get(&new->storage.path);
	new->storage.need_put = 1;

	put_pid(pid);

	usip_event_queue(new);
out:
	return 0;
}
