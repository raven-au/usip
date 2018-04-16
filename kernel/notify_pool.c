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
#include <linux/mempool.h>

#include "internal.h"

#define EVENT_NOTIFY_POOLSIZE	10

static struct kmem_cache *event_notify_cache;
static mempool_t 	 *event_notify_pool;

struct event_notify *usip_event_notify_alloc(gfp_t flags)
{
	struct event_notify *notify;

	notify = mempool_alloc(event_notify_pool, flags);
	memset(notify, 0, sizeof(struct event_notify));
	INIT_LIST_HEAD(&notify->entry);

	return notify;
}

struct event_notify *usip_event_notify_realloc(struct event_notify *notify)
{
	struct event_notify *new;

	new = mempool_alloc(event_notify_pool, GFP_KERNEL);
	if (new) {
		BUG_ON(!list_empty(&notify->entry));
		memcpy(new, notify, sizeof(struct event_notify));
		INIT_LIST_HEAD(&new->entry);
		/* Return requested GFP_ATOMIC alloc to mempool
		 * elements.
		 */
		mempool_free(notify, event_notify_pool);
	}

	return new;
}

void usip_event_notify_free(struct event_notify *notify)
{
	if (notify->ops && notify->ops->release)
		notify->ops->release(notify);
	if (!list_empty(&notify->entry))
		list_del_init(&notify->entry);
	mempool_free(notify, event_notify_pool);
}

static void *event_notify_alloc(gfp_t gfp_mask, void *pool)
{
	/* If reqesting GFP_ATOMIC allocation use a pre-allocated
	 * pool element, return it ASAP (to try and ensure there
	 * are elements available as often as possible) and
	 * transfer to a non-GFP_ATOMIC allocation.
	 */
	if (gfp_mask == GFP_ATOMIC) {
		pr_info("saw GFP_ATOMIC\n");
		return NULL;
	}
	return mempool_alloc_slab(gfp_mask, pool);
}

int usip_event_notify_pool_init(void)
{
	event_notify_cache = kmem_cache_create("event_notify",
					       sizeof(struct event_notify),
					       0, SLAB_HWCACHE_ALIGN, NULL);
	if (!event_notify_cache) {
		pr_info("failed to create kmem cache\n");
		return -ENOMEM;
	}

	event_notify_pool = mempool_create(EVENT_NOTIFY_POOLSIZE,
					   event_notify_alloc,
					   mempool_free_slab,
					   event_notify_cache);
	if (!event_notify_pool) {
		pr_info("failed to create mempool\n");
		kmem_cache_destroy(event_notify_cache);
		return -ENOMEM;
	}

	return 0;
}

void usip_event_notify_pool_destroy(void)
{
	mempool_destroy(event_notify_pool);
	kmem_cache_destroy(event_notify_cache);
}
