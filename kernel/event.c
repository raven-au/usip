/*
 * Copyright 2018 Red Hat, Inc. All rights reserved.
 * Copyright 2018 Ian Kent <raven@themaw.net>
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 */

#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/nsproxy.h>
#include <linux/wait.h>
#include <linux/idr.h>
#include <linux/interrupt.h>

#define INCLUDE_USIP_POLICY
#include "usip.h"
#include "internal.h"

static struct idr idr;

static struct kmem_cache *listeners_cache;
static struct kmem_cache *notifiers_cache;
static struct kmem_cache *event_notify_cache;

#define EVENT_HASH_SHIFT  6
#define EVENT_HASH_SIZE   1 << EVENT_HASH_SHIFT

static DEFINE_MUTEX(listeners_mutex);
static struct hlist_head listeners_hash[EVENT_HASH_SIZE];
static unsigned int listeners_list_empty = 0;

static void usip_event_signal(unsigned long);
static DECLARE_TASKLET(usip_signal, usip_event_signal, 0);

#define IDLE_TIMEOUT	500
#define WQ_NAME		"usip_events"
static struct workqueue_struct *usip_eventwq = NULL;
static DECLARE_COMPLETION(usip_wq_complete);

struct usip_events {
	bool done;
	unsigned int  waiting;
	struct list_head events;
};
static struct usip_events usip_events;

static void usip_event_handler(struct work_struct *);
static DECLARE_WORK(usip_worker, usip_event_handler);
static DEFINE_SPINLOCK(usip_event_lock);
static DECLARE_WAIT_QUEUE_HEAD(usip_event_wq);

static void *find_group_ptr(int group)
{
	void *ptr;

	if (!group)
		ptr = init_task.nsproxy->mnt_ns;
	else
		ptr = idr_find(&idr, group);
	return ptr;
}

static struct listener *usip_lookup_listener(s32 group, s32 id)
{
	struct listener *entry, *this;
	struct hlist_head *bucket;
	struct notifier *notifier;
	void *ptr;
	u32 hash;

	ptr = find_group_ptr(group);
	if (!ptr)
		return NULL;

	hash = hash_ptr(ptr, EVENT_HASH_SHIFT);
	bucket = &listeners_hash[hash];

	entry = NULL;
	notifier = NULL;
	hlist_for_each_entry(this, bucket, entry) {
		if (this->event.id == id &&
		    this->event.group == group) {
			entry = this;
			break;
		}
		continue;
	}

	return entry;
}

static void usip_add_listener(struct listener *listener)
{
	struct hlist_head *bucket;
	void *ptr;
	u32 hash;

	ptr = find_group_ptr(listener->event.group);
	if (!ptr)
		return;

	hash = hash_ptr(ptr, EVENT_HASH_SHIFT);
	bucket = &listeners_hash[hash];
	hlist_add_head(&listener->entry, bucket);
	listeners_list_empty++;
}

static void usip_del_notifiers(struct notifier *notifiers)
{
	struct notifier *this = notifiers;
	struct notifier *next;

	while (this) {
		next = this->next;
		if (this->ops && this->ops->release)
			this->ops->release(this);
		kmem_cache_free(notifiers_cache, this);

		this = next;
	}
}

static void usip_del_listener(struct listener *listener)
{
	void *ptr;

	if (!hlist_unhashed(&listener->entry))
		hlist_del(&listener->entry);

	ptr = find_group_ptr(listener->event.group);
	if (ptr) {
		struct listener *entry, *this;
		struct hlist_head *bucket;
		u32 hash;

		hash = hash_ptr(ptr, EVENT_HASH_SHIFT);
		bucket = &listeners_hash[hash];

		entry = NULL;
		hlist_for_each_entry(this, bucket, entry) {
			if (this->event.group == listener->event.group) {
				entry = this;
				break;
			}
		}
		if (!entry)
			idr_remove(&idr, listener->event.group);
	}
	usip_del_notifiers(listener->event.notifiers);
	idr_remove(&idr, listener->event.id);
	kmem_cache_free(listeners_cache, listener);
	listeners_list_empty--;
}

static s32 usip_new_id(void *ptr, unsigned int gfp_flag)
{
	return idr_alloc(&idr, ptr, 1, 0, gfp_flag);
}

static s32 usip_match_group(struct mnt_namespace *mnt_ns)
{
	struct listener *this;
	struct hlist_head *bucket;
	s32 group = -1;
	u32 hash;

	hash = hash_ptr(mnt_ns, EVENT_HASH_SHIFT);
	bucket = &listeners_hash[hash];

	hlist_for_each_entry(this, bucket, entry) {
		struct mnt_namespace *found;

		found = find_group_ptr(this->event.group);
		if (found == mnt_ns) {
			group = this->event.group;
			break;
		}
	}

	return group;
}

static int usip_get_group(struct mnt_namespace *mnt_ns,
			  u32 type, s32 *group, unsigned int gfp_flag)
{
	s32 new;
	int err;

	if (mnt_ns == init_task.nsproxy->mnt_ns) {
		new = 0;
		goto found;
	}

	mutex_lock(&listeners_mutex);
	new = usip_match_group(mnt_ns);
	if (new == -1) {
		idr_preload(gfp_flag);
		new = usip_new_id(mnt_ns, gfp_flag);
		idr_preload_end();
	}
	mutex_unlock(&listeners_mutex);

	if (new < 0) {
		err = new;
		goto out;
	}
found:
	*group = new;

	return 0;
out:
	return err;
}

static int usip_set_notifier(struct notifier *notifier,
			     u32 type, u32 action, u8 cmd, u32 flags)
{
	const struct usip_notifier_ops *ops;
	int err = 0;

	notifier->type = type;
	notifier->action = action;
	notifier->cmd = cmd;
	notifier->flags = flags;

	switch (type) {
	case USIP_EVENT_TYPE_MTAB:
		usip_mtab_set_ops(notifier);
		ops = notifier->ops;
		if (ops && ops->get_request_params)
			err = ops->get_request_params(NULL, notifier);
		break;
	case USIP_EVENT_TYPE_STORAGE:
		usip_storage_set_ops(notifier);
		ops = notifier->ops;
		if (ops && ops->get_request_params)
			err = ops->get_request_params(NULL, notifier);
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

struct notifier *usip_add_notifier(struct notifier *notifier,
				   u32 type, u32 action, u8 cmd, u32 flags)
{
	struct notifier *new;
	int err;

	new = kmem_cache_alloc(notifiers_cache, GFP_KERNEL);
	if (!new) {
		pr_err("failed to alloc notifier\n");
		new = ERR_PTR(-ENOMEM);
		goto out;
	}
	memset(new, 0, sizeof(struct notifier));

	err = usip_set_notifier(new, type, action, cmd, flags);
	if (err) {
		pr_err("failed to set notifier\n");
		kmem_cache_free(notifiers_cache, new);
		new = ERR_PTR(err);
		goto out;
	}

	if (notifier)
		new->next = notifier;
out:
	return new;
}

static int usip_add_notifiers(const struct nlattr *attr, struct event *event)
{
	struct notifier *notifier;
	struct nlattr *this;
	int remaining;
	int err = 0;

	err = nla_validate(attr, nla_len(attr),
			   USIP_ATTRS_MAX, usip_policy, NULL);
	if (err) {
		pr_err("failed to validate attribute stream\n");
		return err;
	}

	notifier = NULL;
	remaining = nla_len(attr);
	this = nla_data(attr);
	while (nla_ok(this, remaining)) {
		u32 type;
		u32 action;
		u8 cmd;
		u32 flags;

		type = nla_get_u32(this);

		this = nla_next(this, &remaining);
		if (!nla_ok(this, remaining)) {
			pr_err("premature end of attributes stream\n");
			err = -ENOENT;
			break;
		}

		action = nla_get_u32(this);

		this = nla_next(this, &remaining);
		if (!nla_ok(this, remaining)) {
			pr_err("premature end of attributes stream\n");
			err = -ENOENT;
			break;
		}

		cmd = nla_get_u8(this);

		this = nla_next(this, &remaining);
		if (!nla_ok(this, remaining)) {
			pr_err("premature end of attributes stream\n");
			err = -ENOENT;
			break;
		}

		flags = nla_get_u32(this);
		pr_info("flags 0x%x\n", flags);

		notifier = usip_add_notifier(notifier,
					     type, action, cmd, flags);
		if (IS_ERR(notifier)) {
			err = PTR_ERR(notifier);
			goto out;
		}

		this = nla_next(this, &remaining);
	}

	event->notifiers = notifier;

	return 0;

out:
	usip_del_notifiers(notifier);
	return err;
}

int usip_event_register(struct sk_buff *skb, struct genl_info *info)
{
	struct listener *listener;
	struct usip_message_info umi;
	struct pid *pid;
	u32 type;
	u32 flags;
	s32 group;
	s32 id;
	int err = 0;

	listener = kmem_cache_alloc(listeners_cache, GFP_KERNEL);
	if (!listener)
		return -ENOMEM;
	INIT_LIST_HEAD(&listener->notify_net.entry);
	INIT_HLIST_NODE(&listener->entry);

	err = -EINVAL;
	pid = get_task_pid(current, PIDTYPE_PID);
	if (!pid)
		goto out;

	id = usip_new_id((void *) pid, GFP_KERNEL);
	if (id < 0) {
		pr_err("failed to get new id\n");
		err = id;
		put_pid(pid);
		goto out;
	}
	put_pid(pid);

	flags = 0;
	if (info->attrs[USIP_EVENT_ATTR_FLAGS])
		flags = nla_get_u32(info->attrs[USIP_EVENT_ATTR_FLAGS]);

	group = 0;
	if (!(flags & USIP_FLAGS_LISTENER_GLOBAL)) {
		err = usip_get_group(current->nsproxy->mnt_ns,
				     type, &group, GFP_KERNEL);
		if (err < 0) {
			pr_err("failed to get group\n");
			err = group;
			mutex_lock(&listeners_mutex);
			idr_remove(&idr, id);
			mutex_unlock(&listeners_mutex);
			goto out;
		}
	}

	listener->event.group = group;
	listener->event.id = id;
	listener->notify_net.net = genl_info_net(info);
	listener->flags = flags;
	listener->event.notifiers = NULL;

	mutex_lock(&listeners_mutex);
	usip_add_listener(listener);
	mutex_unlock(&listeners_mutex);

	umi.info = info;
	err = usip_new_msg(&umi, USIP_EVENT_CMD_REGISTER, 0);
	if (err) {
		pr_err("failed to create new message\n");
		usip_del_listener(listener);
		listener = NULL;
		goto out;
	}

	nla_put_s32(umi.msg, USIP_EVENT_ATTR_ID, id);
	nla_put_s32(umi.msg, USIP_EVENT_ATTR_GROUP, group);

	if (!info->attrs[USIP_EVENT_ATTR_NOTIFIERS]) {
		pr_err("no notifiers present\n");
		err = -ENOENT;
		usip_del_listener(listener);
		listener = NULL;
		goto out_free_msg;
	}

	err = usip_add_notifiers(info->attrs[USIP_EVENT_ATTR_NOTIFIERS],
				 &listener->event);
	if (err) {
		pr_err("failed to add notifier\n");
		usip_del_listener(listener);
		listener = NULL;
		goto out_free_msg;
	}

	err = usip_send_status(&umi, USIP_ATTR_STATUS, 0);
	if (err < 0) {
		pr_err("failed to add send status\n");
		usip_del_listener(listener);
		listener = NULL;
		goto out_free_msg;
	}
	pr_info("registered listener\n");

	return 0;

out_free_msg:
	nlmsg_free(umi.msg);
out:
	kmem_cache_free(listeners_cache, listener);
	return usip_send_status_reply(info, USIP_EVENT_CMD_REGISTER, err);
}

int usip_event_unregister(struct sk_buff *skb, struct genl_info *info)
{
	struct listener *listener;
	s32 group;
	s32 id;
	int err;

	err = -EINVAL;

	if (!info->attrs[USIP_EVENT_ATTR_GROUP])
		goto out;
	group = nla_get_s32(info->attrs[USIP_EVENT_ATTR_GROUP]);

	if (!info->attrs[USIP_EVENT_ATTR_ID])
		goto out;
	id = nla_get_s32(info->attrs[USIP_EVENT_ATTR_ID]);

	mutex_lock(&listeners_mutex);
	listener = usip_lookup_listener(group, id);
	if (listener)
		usip_del_listener(listener);
	mutex_unlock(&listeners_mutex);
	pr_info("unregistered listener\n");

	return usip_send_status_reply(info, USIP_EVENT_CMD_UNREGISTER, 0);
out:
	return usip_send_status_reply(info, USIP_EVENT_CMD_UNREGISTER, err);
}

bool usip_have_listeners(void)
{
	return !!listeners_list_empty;
}

bool usip_event_handler_running(void)
{
	bool running = true;

	if (usip_events.done)
		running = false;
	return running;
}

void usip_event_queue(struct event_notify *event)
{
	unsigned long flags;

	spin_lock_irqsave(&usip_event_lock, flags);
	list_add_tail(&event->entry, &usip_events.events);
	usip_events.waiting++;
	spin_unlock_irqrestore(&usip_event_lock, flags);
	tasklet_schedule(&usip_signal);
	pr_info("queued notify event\n");
}

static void usip_event_signal(unsigned long unused)
{
	queue_work(usip_eventwq, &usip_worker);
	wake_up(&usip_event_wq);
	pr_info("sent wake up\n");
}

static struct event_notify *usip_event_wait(unsigned long idle)
{
	struct event_notify *notify;
	struct list_head *head;
	unsigned long flags;

	notify = NULL;

	wait_event_timeout(usip_event_wq, usip_events.waiting, idle);

	spin_lock_irqsave(&usip_event_lock, flags);
	head = &usip_events.events;
	if (usip_events.done)
		goto out;
	if (list_empty(&usip_events.events))
		goto out;
	notify = list_entry(head->next, struct event_notify, entry);
	list_del_init(&notify->entry);
	usip_events.waiting--;
out:
	spin_unlock_irqrestore(&usip_event_lock, flags);

	return notify;
}

static struct notifier *
match_notifier(struct listener *listener, struct event_notify *notify)
{
	struct notifier *notifier, *this;

	notifier = listener->event.notifiers;
	while (notifier) {
		pr_info("notifier->ops %p notifier->ops->match_notifier %p\n",
				notifier->ops, notifier->ops->match_notifier);
		if (!notifier->ops || !notifier->ops->match_notifier)
			goto next;
		this = notifier->ops->match_notifier(notifier, notify);
		if (this)
			break;
next:
		notifier = notifier->next;
	}

	return this;
}

static void add_notify_net(struct notify_net *n_net, struct list_head *head)
{
	struct notify_net *this;

	if (list_empty(head)) {
		list_add(&n_net->entry, head);
		return;
	}

	/* Number of net namespaces should be small.
	 * If not this will need to change to a hash list.
	 */
	list_for_each_entry(this, head, entry) {
		if (this->net == n_net->net)
			continue;
	}

	if (!this)
		list_add(&n_net->entry, head);
}

static void usip_event_handler(struct work_struct *work)
{
	struct listener *entry, *this;
	struct hlist_head *bucket;
	struct hlist_node *next;
	struct event_notify *notify;
	struct notifier *notifier;
	struct notify_net *nn, *nn_next;
	LIST_HEAD(notify_nets);
	u32 hash;
cont:
	notifier = NULL;

	notify = usip_event_wait(msecs_to_jiffies(IDLE_TIMEOUT));
	if (!notify) {
		pr_info("shutdown workqueue\n");
		complete(&usip_wq_complete);
		return;
	}
	pr_info("got event notify %p\n", notify);

	/*
	if (usip_events.done) {
		pr_info("events shutdown\n");
		usip_event_notify_free(notify);
		complete(&usip_wq_complete);
		return;
	}
	*/

	entry = NULL;
	hash = hash_ptr(notify->mnt_ns, EVENT_HASH_SHIFT);

	mutex_lock(&listeners_mutex);
	bucket = &listeners_hash[hash];

	if (hlist_empty(bucket)) {
		pr_info("empty bucket\n");
		goto done;
	}

	/* Send a multicast noticication if a match is found */
	hlist_for_each_entry_safe(this, next, bucket, entry) {
		struct notifier *matched;
		void *ptr;

		pr_info("this->event.group %d\n", this->event.group);
		if (!this->event.group) {
			pr_info("notify->mnt_ns %p init_task.nsproxy->mnt_ns %p\n",
				       notify->mnt_ns, init_task.nsproxy->mnt_ns);
			if (notify->mnt_ns == init_task.nsproxy->mnt_ns)
				goto match;
			continue;
		}
		ptr = idr_find(&idr, this->event.group);
		pr_info("ptr %p notify->mnt_ns %p\n", ptr, notify->mnt_ns);
		if (ptr != notify->mnt_ns)
			continue;
match:
		matched = match_notifier(this, notify);
		if (!matched || !matched->ops || !matched->ops->notify)
			continue;
		notifier = matched;
		add_notify_net(&this->notify_net, &notify_nets);
	}

	if (!notifier || list_empty(&notify_nets)) {
		pr_info("no notifier match\n");
		goto done;
	}

	list_for_each_entry_safe(nn, nn_next, &notify_nets, entry) {
		int err;

		list_del_init(&nn->entry);
		err = notifier->ops->notify(nn->net, notifier, notify);
		if (err)
			pr_err("failed to send notification: %d\n", err);
	}
done:
	mutex_unlock(&listeners_mutex);
	usip_event_notify_free(notify);
	goto cont;
}

static int usip_listeners_init(void)
{
	int i;

	listeners_cache = kmem_cache_create("listeners",
					    sizeof(struct listener),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!listeners_cache) {
		pr_info("failed to create listeners kmem cache\n");
		return -ENOMEM;
	}

	notifiers_cache = kmem_cache_create("notifiers",
					    sizeof(struct notifier),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!notifiers_cache) {
		kmem_cache_destroy(listeners_cache);
		pr_info("failed to create notifiers kmem cache\n");
		return -ENOMEM;
	}

	for (i = 0; i < EVENT_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&listeners_hash[i]);

	return 0;
}

static void usip_listeners_cleanup(void)
{
	int i;

	mutex_lock(&listeners_mutex);
	for (i = 0; i < EVENT_HASH_SIZE; i++) {
		struct hlist_head *bucket;
		struct hlist_node *pos, *next;

		bucket = &listeners_hash[i];
		hlist_for_each_safe(pos, next, bucket) {
			struct listener *entry;

			entry = hlist_entry(pos, struct listener, entry);
			usip_del_listener(entry);
		}
	}
	mutex_unlock(&listeners_mutex);

	kmem_cache_destroy(notifiers_cache);
	kmem_cache_destroy(listeners_cache);
}

struct event_notify *usip_event_notify_alloc(gfp_t flags)
{
	struct event_notify *notify;

	notify = kmem_cache_alloc(event_notify_cache, flags);
	memset(notify, 0, sizeof(struct event_notify));
	INIT_LIST_HEAD(&notify->entry);

	return notify;
}

void usip_event_notify_free(struct event_notify *notify)
{
	if (notify->ops && notify->ops->release)
		notify->ops->release(notify);
	if (!list_empty(&notify->entry))
		list_del(&notify->entry);
	kmem_cache_free(event_notify_cache, notify);
}

static int usip_event_notify_init(void)
{
	event_notify_cache = kmem_cache_create("event_notify",
					       sizeof(struct event_notify),
					       0, SLAB_HWCACHE_ALIGN, NULL);
	if (!event_notify_cache) {
		pr_info("failed to create notify kmem cache\n");
		return -ENOMEM;
	}

	return 0;
}

static void usip_event_notify_destroy(void)
{
	kmem_cache_destroy(event_notify_cache);
}

static int usip_events_workqueue_init(void)
{
	int err;

	usip_events.done = false;
	usip_events.waiting = 0;
	INIT_LIST_HEAD(&usip_events.events);

	err = -ENOENT;
	usip_eventwq = create_singlethread_workqueue(WQ_NAME);
	if (!usip_eventwq)
		return err;
	/* If no work is ever queued to a workqueue the system
	 * will hang when destroying the workqueue, so kick
	 * start it now.
	 */
	queue_work(usip_eventwq, &usip_worker);

	return 0;
}

static void usip_event_notify_signal_queue_free(void)
{
	struct event_notify *pos, *next;
	struct list_head *head;

	if (list_empty(&usip_events.events))
		return;

	spin_lock(&usip_event_lock);
	head = &usip_events.events;
	list_for_each_entry_safe(pos, next, head, entry) {
		list_del(&pos->entry);
		usip_event_notify_free(pos);
	}
	spin_unlock(&usip_event_lock);
}

static void usip_events_workqueue_shutdown(void)
{
	unsigned long flags;

	spin_lock_irqsave(&usip_event_lock, flags);
	usip_events.done = true;
	spin_unlock_irqrestore(&usip_event_lock, flags);
	wake_up(&usip_event_wq);
	wait_for_completion(&usip_wq_complete);
	destroy_workqueue(usip_eventwq);
	usip_event_notify_signal_queue_free();
}

int __init usip_event_init(void)
{
	int err;

	idr_init(&idr);
	err = usip_listeners_init();
	if (err)
		return err;
	err = usip_event_notify_init();
	if (err) {
		kmem_cache_destroy(notifiers_cache);
		kmem_cache_destroy(listeners_cache);
		return err;
	}
	err = usip_events_workqueue_init();
	if (err) {
		usip_event_notify_destroy();
		kmem_cache_destroy(notifiers_cache);
		kmem_cache_destroy(listeners_cache);
		pr_err("failed to create events workqueue\n");
		return err;
	}

	return 0;
}

void __exit usip_event_exit(void)
{
	usip_events_workqueue_shutdown();
	usip_event_notify_destroy();
	usip_listeners_cleanup();
}
