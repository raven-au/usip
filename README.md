Universal Storage Information Provider
======================================

This repository is a work in progress in it's initial stages of
development.

The goal of the system is to provide storage information from the
Linux kernel to user space for various storage devices and file
systems, and for mount table information.

The system uses the Linux kernel Netlink subsystem for kernel to
user space communication and a user space shared library will
provide functions to forward Netlink commands to get storage
information and for the registration and deregistration of event
listeners and their notifiers as well as providing functions for
listening for registered events.

The initial motivation was to provide a way to get incremental
mount table information. Providing this functionality has a long
way to go yet. The code here is "out-of-tree" at this stage but
the incremental update functionality will require changes to the
kernel proper and how that will be done has not yet been determined.

But there was also interest in providing a much more broad spectrum
of storage information to user space so the scope has been broadened.

At this stage work is being done to create an infrastructure for
communication of storage information to user space including event
notification. At some point development will need to move to the
kernel proper to implement notifications and to access the needed
information for events and requests.

However, there are a number of challenges to be overcome before
this, such as ensuring that notification code called from critical
places in storage device drivers does not hinder drivers. As well
as getting the needed information is acceptable ways (which turns
out to be more difficult that one would expect) when considering
that the "view" of storage can be different between mount name
spaces. 

A word about the mount table information problem
================================================

Mount table information available via the proc file system is provided
on an all or nothing basis and can lead to excessive overhead for
systems that need up-to-date mounts information. A system for obtaining
incremental changes and information about individual mounts is needed.

This isn't such a problem when the mount table is small (say less than
thousand or so entries) but becomes a serious problem for very large
mount tables (of the order of ten thousand or more).

For example, starting autofs with a direct mount map of 15,000 entries
several key processes CPU usage grows to consume all available CPU
(to name a few of these, systemd, udisksd, gvfs-udisks2-volume-monitor
and gvfs-trash). After the autofs startup has completed a couple of
process continue to consume excessive CPU purely because of the size
of the mount table (namely gvfs-udisks2-volume-monitor, packagekitd
and gnome-settings-daemon).

While such large autofs direct mount maps are not that common the
mount table can still become very large, such as when many containers
are in use so the problem is not confined to autofs.

What's in the repository
========================

The repository consists of three directories, kernel, lib and test.

The kernel directory contains the out-of-tree kernel implementation.

The kernel module is built with "make" and to use it for testing, it
must be inserted manually with "insmod usip.ko" and when finished
removed with "rmmod usip".

The lib directory contains the user space library (although less time
has been spent on that so far).

To use the library a "make" followed by a "make install" all that's
needed but see the code in the test directory for more information
about using the library.

Finally the test directory contains code to exercise the implementation
of Netlink commands (or will do as they are added) as well as code to
call Netlink commands that test event notifications (for the limited
functions that have been done).

NOTE: a configure, make and make install will install the library under
/usr/local and as you will see the make file targets which execute tests
will set "export LD_LIBRARY_PATH=/usr/local/lib" before running a test.

An example use of the kernel and user space library
===================================================

When registering what the user space library calls an event the kernel
allocates a listener. Listeners (user space struct event) hold a list
of notifiers what are checked for a match when a kernel event arrives.

For example you can see this in test/test-notify-2.c (params is declared
global):

        struct notifier notifier;
        struct event *event;
        int ret = 0;

	...

        memset(&params, 0, sizeof(struct notify_params));

	...

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
	...

        params.event = event;
        ret = usip_mc_notify(&params);
	...

        ret = usip_notify_unregister(event);
	...

        usip_event_free(event);

Here the event wide flags of USIP_FLAGS_LISTENER_GLOBAL declare this
event to be namespace independent (except for path calculations that
need to use a saved root).

Next fill in the fields of a notifier, first the multicast group is
USIP_MC_STORAGE_GROUP_NAME and the type is USIP_EVENT_TYPE_STORAGE
which is a generic name for storage events for now.

There are two notifier fields action and cmd, action is used to define
some type of notification while cmd is used to send an appropriate
Netlink command to be executed in the user space callback for the
notifier.

The flags fields defines what to do, USIP_FLAGS_NOTIFIER_NOTIFY says
send a notification to the multicast list and USIP_FLAGS_NOTIFIER_KERN_LOG
says log event information to the kernel log.

Lastly the user space callback function is defined, the callback argument
filled in and the notifier added to the event notifier list.

The next steps show registration, listening for events, and unregistering
the event.

To run this test the kernel module must be loaded and test/test-enospc
used to send a test event Netlink command (obviously added for testing).

Conclusion
==========

This is what I have so far.
There are a number of challenges to overcome, some of which are noted
in the source (eg. kernel/log.c).

Please have a look through this and offer feedback and suggestions.
Ian
