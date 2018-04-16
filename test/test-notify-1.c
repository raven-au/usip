#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>

#include "usip.h"

struct notify_params params;

void sig_handler(int signum)
{
	params.done = 1;
}

int mtab_handle_notify(unsigned int action, void *arg)
{
	struct mounts *mounts, *this;
	unsigned int *table = (unsigned int *) arg;
	int ret;

	mounts = NULL;

	printf("call usip_mtab_get_mtab()\n");
	ret = usip_mtab_get_mtab(action, *table, &mounts);
	if (ret)
		printf("get mtab error: %s (%d)\n", strerror(errno), ret);
	else
		printf("success\n");

	this = mounts;
	while (this) {
		printf("this->entry: %s\n", this->entry);
		this = this->next;
	}
	usip_mtab_free_mounts(mounts);

	return ret;
}

int main(int argc, char **argv)
{
	unsigned int table = USIP_MTAB_TABLE_MOUNTS;
	struct notifier notifier;
	struct event *event;
	int ret = 0;

	event = usip_event_alloc();
	if (!event) {
		printf("event allocation failed: %s (%d)\n", usip_perror(ret), ret);
		exit(1);
	}

	memset(&params, 0, sizeof(struct notify_params));

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	notifier.mc_grp_name = USIP_MC_MTAB_GROUP_NAME;
	notifier.type = USIP_EVENT_TYPE_MTAB;
	notifier.action = 0;
	notifier.cmd = USIP_MTAB_CMD_GET_MTAB;
	notifier.flags = USIP_FLAGS_NOTIFIER_NOTIFY;
	notifier.callback = mtab_handle_notify;
	notifier.arg = &table;
	ret = usip_add_notifier(event, &notifier);

	ret = usip_notify_register(event);
	if (ret) {
		printf("register failed: %s (%d)\n", usip_perror(ret), ret);
		exit(1);
	}
	printf("registered event id: %d, group %d\n", event->id, event->group);

	params.event = event;
	ret = usip_mc_notify(&params);
	if (ret)
		printf("usip_mc_notify failed: %s (%d)\n", usip_perror(ret), ret);

	ret = usip_notify_unregister(event);
	if (ret)
		printf("usip_notify_unregister: %s (%d)\n", usip_perror(ret), ret);
	else
		printf("usip_notify_unregister: done\n");

	usip_event_free(event);
}
