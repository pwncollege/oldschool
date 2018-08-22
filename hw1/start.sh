#!/bin/bash -e

[ -f /start.sh ] && rm -f /start.sh

if [ -z "$BINARY_FILE" ]
then
	echo "[!!!] BINARY FILE NOT SPECIFIED. EXITING."
	exit 1
fi

if [ -z "$FLAG" ]
then
	echo "[!!!] FLAG NOT SPECIFIED. EXITING."
	exit 1
fi

if ! file $BINARY_FILE | grep -q ELF
then
	echo "[!!!] ERROR: $BINARY_FILE is NOT an ELF file."
	echo "[!!!]        this means that suid will not have any effect."
	echo "[!!!]        (see https://www.vidarholen.net/contents/blog/?p=30)"
	echo "[!!!]"
	echo "[!!!] You can see the type of the file yourself by running:"
	echo "[!!!]"
	echo "[!!!]     file $BINARY_FILE"
	echo "[!!!]"
	echo "[!!!] In this case, it is:"
	file $BINARY_FILE
	echo "[!!!] This session will now terminate. Please choose an ELF file next time."
	exit 1
fi

echo "$FLAG" > /flag
chmod 600 /flag
chmod u+s $BINARY_FILE
exec env -i su - hw1
