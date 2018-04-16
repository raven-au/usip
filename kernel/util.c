/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <linux/fs_struct.h>
#include <linux/seq_file.h>
#include <linux/mm.h>

#include "usip.h"
#include "internal.h"

/* testing */
#include "mount.h"

int usip_new_msg(struct usip_message_info *umi, u8 cmd, unsigned int flags)
{
	struct sk_buff *msg;
	struct genl_info *info = umi->info;
	void *hdr;
	int err;

	err = -ENOMEM;
	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg)
		goto out;

	hdr = genlmsg_put(msg, info->nlhdr->nlmsg_pid,
			  info->snd_seq, &usip_family, flags, cmd);
	if (!hdr) {
		nlmsg_free(msg);
		goto out;
	}

	err = 0;
	umi->msg = msg;
	umi->hdr = hdr;
out:
	return err;
}

int usip_send_status(struct usip_message_info *umi, int attr, s32 status)
{
	nla_put_s32(umi->msg, attr, status);
	genlmsg_end(umi->msg, umi->hdr);
	return genlmsg_unicast(genl_info_net(umi->info),
                               umi->msg, umi->info->snd_portid);
}

int usip_send_status_reply(struct genl_info *info, u8 action, s32 status)
{
	struct usip_message_info umi;
	int err;

	umi.info = info;

	err = usip_new_msg(&umi, action, 0);
	if (err)
		goto out;

	err = usip_send_status(&umi, USIP_ATTR_STATUS, status);
out:
	return err;
}

int usip_new_mc_msg(struct usip_message_info *umi,
		    u32 type, s32 group, unsigned int flags)
{
	struct sk_buff *msg;
	void *hdr;
	int err;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, flags);
	if (!msg) {
		pr_err("failed to create message\n");
		return -ENOMEM;
	}

	err = -EINVAL;
	hdr = genlmsg_put(msg, 0, 0, &usip_family, flags, USIP_CMD_NOOP);
	if (!hdr) {
		pr_err("failed to setup message header\n");
		goto out;
	}

	err = nla_put_u32(msg, USIP_EVENT_ATTR_TYPE, type);
	if (err) {
		pr_err("failed to put event type in message: error %d\n", err);
		goto out;
	}

	err = nla_put_s32(msg, USIP_EVENT_ATTR_GROUP, group);
	if (err) {
		pr_err("failed to put event group in message: error %d\n", err);
		goto out;
	}

	err = 0;
	umi->msg = msg;
	umi->hdr = hdr;
out:
	return err;
}

int usip_send_notification(struct notifier *notifier,
			   struct event_notify *notify)
{
	struct usip_message_info umi;
	unsigned int flags = GFP_KERNEL;
	int err;

	err = usip_new_mc_msg(&umi, notify->type, notify->group, flags);
	if (err)
		goto out;

	if (notifier->ops->put_reply_params) {
		err = notifier->ops->put_reply_params(umi.msg, notify);
		if (err) {
			pr_err("failed to put reply params\n");
			goto out;
		}
	}

	pr_info("send multicast message mc_group %d\n", notify->mc_group);
	genlmsg_end(umi.msg, umi.hdr);
	genlmsg_multicast(&usip_family, umi.msg, 0, notify->mc_group, flags);
	return 0;
out:
	genlmsg_cancel(umi.msg, umi.hdr);
	nlmsg_free(umi.msg);
	return err;
}

/* For testing */

/*
 * This all needs to be simplified and set_fs_root() is just
 * not allowed in a workqueue task due to shared current->fs.
 *
 * The root of the notifying task needs to be used to get the
 * mount point path so a variant of d_path() needs to be written
 * here and this needs to be built as part of the VFS in order
 * to access __d_path().
 *
 * This need is very similar to that of the usermodehelper
 * needing to execute a helper under a different fs root and,
 * years ago, code that used set_fs_root() to do this was
 * rejected.
 *
 * Anyway, I guess current->fs->lock could be taken while
 * getting the path but that seems like bad pratice too.
 *
 * The seq file abuse is poor as well but looks to be the only
 * way to get mount paths requiring a different fs root without
 * requiring file system modification (since a super block
 * operation that requires a seq file as a parameter might be
 * needed to get it).
 *
 * But this is still just a test environment atm.
 */
static void my_set_fs_root(struct fs_struct *fs, const struct path *path)
{
        struct path old_root;

        path_get(path);
        spin_lock(&fs->lock);
        write_seqcount_begin(&fs->seq);
        old_root = fs->root;
        fs->root = *path;
        write_seqcount_end(&fs->seq);
        spin_unlock(&fs->lock);
        if (old_root.dentry)
                path_put(&old_root);
}
#define set_fs_root my_set_fs_root

char *get_mp_path(struct path *path, struct path *root)
{
	struct path saved_root;
	struct path mp_path;
	char *buf, *tmp;
	char *mp;

	buf = (char *) __get_free_page(GFP_KERNEL);
	if (IS_ERR(buf))
		return buf;

	get_fs_root(current->fs, &saved_root);
	set_fs_root(current->fs, root);

	mp_path = *path;
	path_get(&mp_path);
	dput(mp_path.dentry);
	mp_path.dentry = dget(mp_path.mnt->mnt_root);

	tmp = d_path(&mp_path, buf, PAGE_SIZE);
	if (IS_ERR_OR_NULL(tmp)) {
		if (!tmp)
			tmp = ERR_PTR(-EINVAL);
		mp = tmp;
		goto out;
	}

	mp = kstrdup(tmp, GFP_KERNEL);
	if (!mp)
		mp = ERR_PTR(-ENOMEM);
out:
	path_put(&mp_path);
	set_fs_root(current->fs, &saved_root);
	path_put(&saved_root);
	free_page((unsigned long) buf);

	return mp;
}

static int show(struct seq_file *sf, void *dummy)
{
	return 0;
}

char *get_dev_path(struct path *path)
{
	struct vfsmount *mnt = path->mnt;
	struct mount *rm = real_mount(mnt);
	struct seq_file *sf;
	struct file f;
	char *dev;
	int err;

	f.private_data = NULL;
	err = single_open(&f, show, NULL);
	if (err)
		return ERR_PTR(err);

	sf = f.private_data;
	sf->size = PAGE_SIZE;
	sf->buf = kvmalloc(sf->size, GFP_KERNEL);
	if (!sf->buf) {
		dev = ERR_PTR(-ENOMEM);
		goto out;
	}
	memset(sf->buf, 0, sf->size);

	if (mnt->mnt_sb->s_op->show_devname) {
		err = mnt->mnt_sb->s_op->show_devname(sf, mnt->mnt_root);
		if (err) {
			dev = ERR_PTR(err);
			goto out;
		}
	} else {
		if (!rm->mnt_devname)
                        seq_puts(sf, "no device");
		else
                        seq_escape(sf, rm->mnt_devname, " \t\n\\");
	}

	dev = kstrdup(sf->buf, GFP_KERNEL);
	if (!dev) {
		dev = ERR_PTR(-ENOMEM);
		goto out;
	}
out:
	seq_release(NULL, &f);
	return dev;
}
