/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <linux/string.h>
#include <linux/slab.h>

#include "usip.h"
#include "internal.h"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define fmt_pid "pid %d, uid %d, inum %lu on %s (%s): filesystem full\n"
#define fmt_vpid \
	"pid %d (vpid %d), uid %d, inum %lu on %s (%s): filesystem full\n"

int usip_log_enospc_event(struct event_notify *notify)
{
	unsigned long i_ino;
	char *mp, *dev;
	pid_t pid, vpid;
	int err = 0;

	i_ino = notify->storage.path.dentry->d_inode->i_ino;

	mp = get_mp_path(&notify->storage.path, &notify->storage.root);
	if (IS_ERR(mp)) {
		err = PTR_ERR(mp);
		goto out;
	}

	dev = get_dev_path(&notify->storage.path);
	if (IS_ERR(dev)) {
		kfree(mp);
		err = PTR_ERR(dev);
		goto out;
	}

	pid = notify->storage.pid;
	vpid = notify->storage.vpid;

	if (!vpid || pid == vpid)
		pr_info(fmt_pid, pid, notify->storage.uid, i_ino, mp, dev);
	else
		pr_info(fmt_vpid, pid, vpid,
			notify->storage.uid, i_ino, mp, dev);
	kfree(mp);
	kfree(dev);
out:
	return err;
}
