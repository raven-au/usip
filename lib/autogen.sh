#!/bin/sh -e

echo -n cleaning up .

CLEANFILES="config.guess config.status config.log config.sub ar-lib libtool"
CLEABFILES="$CLEANFILES compile depcomp install-sh ltmain.sh missing"

# Clean up the generated crud
(
	for FILE in $CLEANFILES; do
	    if test -f $FILE; then
		rm -f $FILE
	    fi
	    echo -n .
	done
)

for FILE in aclocal.m4 configure config.h.in; do
    if test -f $FILE; then
	rm -f $FILE
    fi
	echo -n .
done

for DIR in autom4te.cache; do
    if test -d $DIR; then
	rm -rf $DIR
    fi
	echo -n .
done

find . -type f -name 'Makefile.in' -print0 | xargs -r0  rm -f --
find . -type f -name 'Makefile' -print0 | xargs -r0 rm -f --

echo ' done'

if test x"${1}" = x"clean"; then
    exit
fi

aclocal
libtoolize --force --copy
autoheader
automake --add-missing --copy --gnu # -Wall
autoconf # -Wall
