#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>

#include "usip.h"

struct notify_params params;

void sig_handler(int signum)
{
	params.done = 1;
}

int storage_handle_enospc_notify(unsigned int action, void *arg)
{
	struct storage_event *stg_event = (struct storage_event *) arg;
	struct tm tm, *ptm;

	printf("File system out of space event:\n");
	printf("\tMount point: %s\t\tDevice node:%s (ino: %lu)\n",
		stg_event->mp, stg_event->dev, stg_event->ino);
	if (!stg_event->vpid || stg_event->vpid == stg_event->pid)
		printf("\tProcess pid: %u\t\tProcess uid: %u\n",
		       stg_event->pid, stg_event->uid);
	else
		printf("\tProcess pid: %u (vpid: %u)\tProcess uid: %u\n",
		       stg_event->pid, stg_event->vpid, stg_event->uid);

	ptm = localtime_r((const time_t *) &stg_event->tv.tv_sec, &tm);
	if (ptm) {
		char buf[30], *pbuf;

		pbuf = asctime_r(ptm, buf);
		if (pbuf)
			printf("\tTime: %s", pbuf);
	}

	return 0;
}

int main(int argc, char **argv)
{
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

	event->flags = USIP_FLAGS_LISTENER_GLOBAL;
	notifier.mc_grp_name = USIP_MC_STORAGE_GROUP_NAME;
	notifier.type = USIP_EVENT_TYPE_STORAGE;
	notifier.action = USIP_NOTIFY_ENOSPC;
	notifier.flags = USIP_FLAGS_NOTIFIER_NOTIFY |
			 USIP_FLAGS_NOTIFIER_KERN_LOG;
	notifier.callback = storage_handle_enospc_notify;
	notifier.arg = &event->storage;
	ret = usip_add_notifier(event, &notifier);

	ret = usip_notify_register(event);
	if (ret) {
		printf("register failed: %s (%d)\n", usip_perror(ret), ret);
		usip_event_free(event);
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
