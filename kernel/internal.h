/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#ifndef _INTERNAL_H
#define _INTERNAL_H

#include <uapi/linux/limits.h>
#include <linux/sched/task.h>
#include <linux/list.h>
#include <linux/time.h>

#include "usip.h"

extern struct genl_family usip_family;

struct usip_message_info {
	struct genl_info *info;
	struct sk_buff *msg;
	void *hdr;
};

struct event {
	s32 id;
	s32 group;
	u32 flags;
	struct notifier *notifiers;
};

struct listener {
	u32 flags;
	struct event event;
	struct hlist_node entry;
};

struct mtab_notify_params {
	u64 event;
};

struct storage_notify_params {
	pid_t pid;
	pid_t vpid;
	unsigned int uid;
	unsigned int gid;
	struct path root;
	struct path path;
	unsigned short need_put;
	struct timeval time;
};

struct usip_event_notify_ops;

struct event_notify {
	void *mnt_ns;
	u32 mc_group;
	s32 group;
	u32 type;
	u32 action;
	u8 cmd;
	union {
		struct mtab_notifier_params mtab;
		struct storage_notify_params storage;
	};
	const struct usip_event_notify_ops *ops;
	struct list_head entry;
};

struct usip_notifier_ops {
	int (*get_request_params)(struct sk_buff* skb, struct notifier *);
	int (*put_reply_params)(struct sk_buff* skb, struct event_notify *);
	struct notifier *(*match_notifier)(struct notifier *, struct event_notify *);
	int (*notify)(struct notifier *, struct event_notify *);
	void (*release)(struct notifier *);
};

struct usip_event_notify_ops {
	void (*release)(struct event_notify *);
};

int usip_new_msg(struct usip_message_info *, u8, unsigned int);
int usip_send_status(struct usip_message_info *, int, s32);
int usip_send_status_reply(struct genl_info *, u8, s32);
int usip_new_mc_msg(struct usip_message_info *, u32, s32, unsigned int);
int usip_send_notification(struct notifier *, struct event_notify *);
char *get_mp_path(struct path *, struct path *);
char *get_dev_path(struct path *);

int usip_ping(struct sk_buff *, struct genl_info *);

bool usip_have_listeners(void);
bool usip_event_handler_running(void);
void usip_event_queue(struct event_notify *);

int usip_event_register(struct sk_buff *, struct genl_info *);
int usip_event_unregister(struct sk_buff *, struct genl_info *);
struct notifier *usip_add_notifier(struct notifier *, u32, u32, u8, u32);

struct event_notify *usip_event_notify_alloc(gfp_t);
void usip_event_notify_free(struct event_notify *);

int usip_mtab_get_mtab(struct sk_buff *, struct genl_info *);
void usip_mtab_set_ops(struct notifier *);
int usip_notify_mtab_event(unsigned int, unsigned char, u64);

void usip_storage_set_ops(struct notifier *);
int usip_notify_storage_event(unsigned int, unsigned char, struct path *);

int usip_log_enospc_event(struct event_notify *);

/* Testing commands functions */
int usip_test_mtab(struct sk_buff *, struct genl_info *);
int usip_test_enospc(struct sk_buff *, struct genl_info *);
#endif
