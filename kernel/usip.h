/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#ifndef _UAPI_LINUX_USIP_H
#define _UAPI_LINUX_USIP_H

#include <linux/types.h>

#if defined(__KERNEL__)
#include <linux/netlink.h>
#include <net/genetlink.h>
#else
#include <stdint.h>
typedef uint8_t  u8;
typedef uint16_t u16;
typedef int32_t  s32;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ":%s: " fmt, __func__

#define USIP_FAMILY	"usip_family"
#define USIP_VERSION	1

#define USIP_MC_MTAB_GROUP_NAME		"mcg_mtab"
#define USIP_MC_STORAGE_GROUP_NAME	"mcg_storage"

#define USIP_FLAGS_LISTENER_GLOBAL	0x0001

#define USIP_FLAGS_NOTIFIER_NOTIFY	0x0001
#define USIP_FLAGS_NOTIFIER_KERN_LOG	0x0002
#define USIP_FLAGS_NOTIFIER_LOG		0x0004

#define USIP_MTAB_DONE		0x00
#define USIP_MTAB_CONTINUE	0x01

enum usip_event_type_attrs {
	USIP_EVENT_TYPE_UNSPEC,

	USIP_EVENT_TYPE_MTAB,
	USIP_EVENT_TYPE_STORAGE,

	__USIP_EVENT_TYPE_MAX,
};
#define USIP_EVENT_TYPE_MAX	(__USIP_EVENT_TYPE_MAX - 1)

enum usip_attrs {
	USIP_ATTR_UNSPEC,

	USIP_ATTR_STATUS,

	USIP_EVENT_ATTR_NOTIFIERS,
	USIP_EVENT_ATTR_TYPE,
	USIP_EVENT_ATTR_FLAGS,
	USIP_EVENT_ATTR_ACTION,
	USIP_EVENT_ATTR_CMD,
	USIP_EVENT_ATTR_GROUP,
	USIP_EVENT_ATTR_ID,

	/* Storage reply attrs */
	USIP_EVENT_ATTR_PID,
	USIP_EVENT_ATTR_VPID,
	USIP_EVENT_ATTR_UID,
	USIP_EVENT_ATTR_GID,
	USIP_EVENT_ATTR_INO,
	USIP_EVENT_ATTR_MOUNTPOINT,
	USIP_EVENT_ATTR_DEVICE,
	USIP_EVENT_ATTR_TIME,

	USIP_MTAB_ATTR_CHANGED,

	USIP_MTAB_ATTR_MTABFD,
	USIP_MTAB_ATTR_MTAB,

	USIP_TEST_ATTR_PATH,

	USIP_ATTR_PAD,

	__USIP_ATTR_MAX,
};
#define USIP_ATTRS_MAX	(__USIP_ATTR_MAX - 1)

enum usip_notify {
	USIP_NOTIFY_UNSPEC,

	USIP_NOTIFY_ENOSPC,
	USIP_NOTIFY_MOUNT,
	USIP_NOTIFY_UMOUNT,

	__USIP_NOTIFY_MAX,
};
#define USIP_NOTIFY_MAX	(__USIP_NOTIFY_MAX - 1)

enum usip_commands {
	USIP_CMD_UNSPEC,

	USIP_CMD_NOOP,

	/* Client ping */
	USIP_CMD_PING,

	/* mtab notifier registration */
	USIP_EVENT_CMD_REGISTER,
	USIP_EVENT_CMD_UNREGISTER,

	USIP_MTAB_CMD_GET_MTAB,		/* Get mount table */
	USIP_MTAB_CMD_CHANGED,		/* Get changed mtab entries */

	/* Tesing commands */
	USIP_TEST_CMD_MTAB,
	USIP_TEST_CMD_ENOSPC,

	__USIP_CMD_MAX,
};
#define USIP_CMDS_MAX	(__USIP_CMD_MAX - 1)

enum usip_mc_groups {
	USIP_MC_MTAB_GROUP,
	USIP_MC_STORAGE_GROUP,
	__USIP_MCGRP_MAX,
};
#define USIP_MCGRPS_MAX (__USIP_MCGRP_MAX)

#ifdef INCLUDE_USIP_POLICY
static struct nla_policy usip_policy[USIP_ATTRS_MAX + 1] = {
	[USIP_ATTR_STATUS]		= { .type = NLA_S32 },
	[USIP_EVENT_ATTR_NOTIFIERS]	= { .type = NLA_NESTED },
	[USIP_EVENT_ATTR_TYPE]		= { .type = NLA_U32 },
	[USIP_EVENT_ATTR_ACTION]	= { .type = NLA_U32 },
	[USIP_EVENT_ATTR_CMD]		= { .type = NLA_U8 },
	[USIP_EVENT_ATTR_GROUP]		= { .type = NLA_S32 },
	[USIP_EVENT_ATTR_ID]		= { .type = NLA_S32 },
	[USIP_MTAB_ATTR_CHANGED]	= { .type = NLA_U32 },
	[USIP_MTAB_ATTR_MTABFD]		= { .type = NLA_S32 },
	[USIP_MTAB_ATTR_MTAB]		= { .type = NLA_NESTED },
	[USIP_TEST_ATTR_PATH]		= { .type = NLA_STRING },
	[USIP_EVENT_ATTR_PID]		= { .type = NLA_U32 },
	[USIP_EVENT_ATTR_VPID]		= { .type = NLA_U32 },
	[USIP_EVENT_ATTR_UID]		= { .type = NLA_U32 },
	[USIP_EVENT_ATTR_GID]		= { .type = NLA_U32 },
	[USIP_EVENT_ATTR_INO]		= { .type = NLA_U64 },
	[USIP_EVENT_ATTR_MOUNTPOINT]	= { .type = NLA_STRING },
	[USIP_EVENT_ATTR_DEVICE]	= { .type = NLA_STRING },
	[USIP_EVENT_ATTR_TIME]		= { .type = NLA_BINARY },
};
#endif

struct usip_notifier_ops;

struct mtab_notifier_params {
	u64 event;
};

struct notifier {
	const char *mc_grp_name;
	u32 mc_group;
	u32 type;
	u32 action;
	u8 cmd;
	u32 flags;
	union {
		struct mtab_notifier_params mtab;
	};
	const struct usip_notifier_ops *ops;
#if !defined(__KERNEL__)
	int (*callback)(unsigned int, void *);
	void *arg;
#endif
	struct notifier *next;
};

#endif  /* _UAPI_LINUX_USIP_H */
