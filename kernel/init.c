/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <linux/module.h>

/*testing */
#include <linux/namei.h>
#include <linux/fs_struct.h>

extern int vfs_path_lookup(struct dentry *, struct vfsmount *,
                           const char *, unsigned int, struct path *);

#define INCLUDE_USIP_POLICY
#include "usip.h"
#include "internal.h"

int __init usip_event_init(void);
void __exit usip_event_exit(void);

static struct genl_ops usip_ops[] = {
	{
		.cmd = USIP_CMD_PING,
		.flags = 0,
		.policy = usip_policy,
		.doit = usip_ping,
		.dumpit = NULL,
	},
	{
		.cmd = USIP_EVENT_CMD_REGISTER,
		.flags = 0,
		.policy = usip_policy,
		.doit = usip_event_register,
		.dumpit = NULL,
	},
	{
		.cmd = USIP_EVENT_CMD_UNREGISTER,
		.flags = 0,
		.policy = usip_policy,
		.doit = usip_event_unregister,
		.dumpit = NULL,
	},
	{
		.cmd = USIP_MTAB_CMD_GET_MTAB,
		.flags = 0,
		.policy = usip_policy,
		.doit = usip_mtab_get_mtab,
		.dumpit = NULL,
	},
	{
		.cmd = USIP_MTAB_CMD_CHANGED,
		.flags = 0,
		.policy = usip_policy,
		.doit = usip_mtab_get_mtab,
		.dumpit = NULL,
	},
	/* Testing commands */
	{
		.cmd = USIP_TEST_CMD_MTAB,
		.flags = 0,
		.policy = usip_policy,
		.doit = usip_test_mtab,
		.dumpit = NULL,
	},
	{
		.cmd = USIP_TEST_CMD_ENOSPC,
		.flags = 0,
		.policy = usip_policy,
		.doit = usip_test_enospc,
		.dumpit = NULL,
	},
};

static const struct genl_multicast_group usip_mcgrps[] = {
	[USIP_MC_MTAB_GROUP]	= { .name = USIP_MC_MTAB_GROUP_NAME, },
	[USIP_MC_STORAGE_GROUP]	= { .name = USIP_MC_STORAGE_GROUP_NAME, },
};

struct genl_family usip_family = {
        .name = USIP_FAMILY,
	.version = USIP_VERSION,
	.hdrsize = 0,
	.maxattr = USIP_ATTRS_MAX,
	.ops = usip_ops,
	.n_ops = ARRAY_SIZE(usip_ops),
	.mcgrps = usip_mcgrps,
	.n_mcgrps = ARRAY_SIZE(usip_mcgrps),
};

extern int __init usip_misc_init(void);
extern void usip_misc_exit(void);

int usip_ping(struct sk_buff *skb, struct genl_info *info)
{
	return usip_send_status_reply(info, USIP_CMD_PING, 1);
}

int __init usip_init(void)
{
	int err;

	err = genl_register_family(&usip_family);
	if (err) {
		pr_err("failed to register usip genl family\n");
		return err;
	}

	err = usip_event_init();
	if (err) {
		genl_unregister_family(&usip_family);
		pr_err("failed to initialize event sub-system\n");
		return err;
	}

	return 0;
}

void __exit usip_exit(void)
{
	usip_event_exit();
	genl_unregister_family(&usip_family);
}

module_init(usip_init)
module_exit(usip_exit)
MODULE_LICENSE("GPL");
