#include <linux/namei.h>

#include "usip.h"
#include "internal.h"

int usip_test_mtab(struct sk_buff *skb, struct genl_info *info)
{
	u64 now = get_jiffies_64();
	int err;

	err = usip_notify_mtab_event(0, USIP_MTAB_CMD_GET_MTAB, now + 10);
	return usip_send_status_reply(info, USIP_TEST_CMD_MTAB, err);
}

int usip_test_enospc(struct sk_buff *skb, struct genl_info *info)
{
	struct path path;
	char *s;
	int err;

	err = -EINVAL;
	if (!info->attrs[USIP_TEST_ATTR_PATH]) {
		pr_info("path attr not present\n");
		goto out;
	}

	s = nla_data(info->attrs[USIP_TEST_ATTR_PATH]);
	if (!s) {
		pr_info("failed to get path\n");
		goto out;
	}

	err = kern_path(s, LOOKUP_FOLLOW, &path);
	if (err) {
		pr_info("kern_path() error %d\n", err);
		goto out;
	}

	err = usip_notify_storage_event(USIP_NOTIFY_ENOSPC, 0, &path);
	path_put(&path);
out:
	return usip_send_status_reply(info, USIP_TEST_CMD_ENOSPC, err);
}

