#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include "usip.h"
#include "../kernel/usip.h"

int send_mtab_msg(void)
{
	struct usip_message_info umi;
	int fd, status;
	int ret = 0;

	ret = usip_init();
	if (ret) {
		printf("failed init\n");
		goto out;
	}

	ret = usip_new_msg(&umi, USIP_TEST_CMD_MTAB, NLM_F_REQUEST|NLM_F_ACK);
	if (ret < 0) {
		printf("couldn't make new msg\n");
		goto out;
	}

	ret = usip_send_msg_with_reply(umi.msg,
				       usip_parse_status_reply, &status);
	if (ret < 0) {
		printf("failed send msg with reply\n");
		goto out;
	}

	if (status)
		ret = std_err_to_nle_err(status);
out:
	usip_close();
	return ret;
}

int main(int argc, char **argv)
{
	int ret;

	ret = send_mtab_msg();
	if (ret)
		printf("send_mtab_msg: failed: %d: %s\n", ret, usip_perror(ret));
}
