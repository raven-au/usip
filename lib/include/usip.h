/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <pthread.h>

#include <netlink/netlink.h>
#include <netlink/errno.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/handlers.h>

#include "../../kernel/usip.h"

extern struct usip_mtab_control ctl;

struct usip_message_info {
	struct nl_msg *msg;
	void *hdr;
};

#define USIP_MTAB_TABLE_MOUNTS		0x01
#define USIP_MTAB_TABLE_MOUNTINFO	0x02
#define USIP_MTAB_TABLE_MOUNTSTATS	0x04

struct mounts {
	char *entry;
	struct mounts *next;
};

struct storage_event {
	pid_t pid;
	pid_t vpid;
	unsigned int uid;
	unsigned int gid;
	unsigned long ino;
	char *mp;
	char *dev;
	struct timeval tv;
};

struct event {
	s32 id;
	s32 group;
	u32 flags;
	union {
		struct storage_event storage;
	};
	pthread_rwlock_t rwlock;
	struct notifier *notifiers;
};

struct usip_notifier_ops {
	int (*put_request_params)(struct event *,
				  struct notifier *, struct nl_msg *);
	int (*get_reply_params)(struct event *,
				struct notifier *, struct nlattr **);
	void (*release)(struct event *, struct notifier *);
};

struct notify_params {
	struct event *event;
	unsigned int done;
	int status;
};

/* Utility functions */
int usip_init(void);
void usip_close(void);
const char *usip_perror(int);
int std_err_to_nle_err(int);
int usip_new_msg(struct usip_message_info *, uint8_t, int);
int usip_send_msg_with_reply(struct nl_msg *, nl_recvmsg_msg_cb_t, void *);
int usip_parse_status_reply(struct nl_msg *, void *);

/* Usip netlink commands */
int usip_ping(void);
int usip_mtab_get_mtab(unsigned int, unsigned int, struct mounts **);
void usip_mtab_free_mounts(struct mounts *);

/* Notification system functions */
struct event *usip_event_alloc(void);
void usip_event_free(struct event *);
int usip_add_notifier(struct event *, struct notifier *);
void usip_set_storage_ops(struct notifier *);
int usip_notify_register(struct event *);
int usip_notify_unregister(struct event *);
int usip_mc_notify(struct notify_params *params);
