from ubuntu:18.04

env CACHE=2
run apt-get update
run apt-get install -y sudo

# some standard crap
run apt-get install -y ubuntu-standard build-essential apt-utils binutils bsdmainutils bsdutils debianutils diffutils elfutils findutils gnupg-utils keyutils pcaputils pcre2-utils psutils
run apt-get install -y openssh-client python-dev python3-dev netcat-openbsd socat vim nano emacs virtualenvwrapper python-virtualenv python-pip

# cleanup
run find / -type f -perm -4000 | xargs chmod u-s

copy start /start
copy get_flag /get_flag
run chown root.nogroup /get_flag
run chmod 2750 /get_flag

run adduser hw3
cmd "/start"
