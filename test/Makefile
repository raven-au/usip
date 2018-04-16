#export LD_LIBRARY_PATH=/usr/local/lib

INCLUDES = -I/usr/local/include -L/usr/local/lib
INCLUDES += -I/work/autofs/work/usip/usip.git/lib/src
INCLUDES += -I/usr/include/libnl3

all: test test-notify-1 test-notify-2 test-mtab test-enospc

test: test.c
	gcc -g -o test $(INCLUDES) -lusip test.c

test-notify-1: test-notify-1.c
	gcc -g -o test-notify-1 $(INCLUDES) -lusip test-notify-1.c

.PHONY: notify-1
notify-1:
	export LD_LIBRARY_PATH=/usr/local/lib && \
	./test-notify-1

test-notify-2: test-notify-2.c
	gcc -g -o test-notify-2 $(INCLUDES) -lusip test-notify-2.c

.PHONY: notify-2
notify-2:
	export LD_LIBRARY_PATH=/usr/local/lib && \
	./test-notify-2

test-mtab: test-mtab.c
	gcc -g -o test-mtab $(INCLUDES) -lusip -lnl-genl-3 -lnl-3 test-mtab.c

test-enospc: test-enospc.c
	gcc -g -o test-enospc $(INCLUDES) -lusip -lnl-genl-3 -lnl-3 test-enospc.c

.PHONY: mtab
mtab:
	export LD_LIBRARY_PATH=/usr/local/lib && \
	./test-mtab

.PHONY: enospc
enospc:
	export LD_LIBRARY_PATH=/usr/local/lib && \
	./test-enospc

clean:
	rm test test-notify-1 test-notify-2 test-enospc test-mtab

