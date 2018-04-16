#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "usip.h"
#include "../kernel/usip.h"

int main(int argc, char **argv)
{
	struct mounts *mounts, *this;
	int ret;

	mounts = NULL;

	ret = usip_mtab_get_mtab(USIP_MTAB_CMD_GET_MTAB,
				 USIP_MTAB_TABLE_MOUNTS, &mounts);
	if (ret)
		printf("get mtab error: %s (%d)\n", usip_perror(ret), ret);
	else
		printf("success\n");

	this = mounts;
	while (this) {
		printf("this->entry %s\n", this->entry);
		this = this->next;
	}
	usip_mtab_free_mounts(mounts);
}
