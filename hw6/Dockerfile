from ubuntu:18.04

env CACHE=2
run apt-get update
run apt-get install -y sudo

# some standard crap
run apt-get install -y ubuntu-standard build-essential apt-utils binutils bsdmainutils bsdutils debianutils diffutils elfutils findutils gnupg-utils keyutils pcaputils pcre2-utils psutils
run apt-get install -y openssh-client python-dev python3-dev netcat-openbsd socat vim nano emacs virtualenvwrapper python-virtualenv python-pip
run apt-get install -y screen tmux git
run apt-get install -y openssh-server

run pip install ipython pwntools

run apt-get install -y gdb
run cd /tmp; git clone https://github.com/pwndbg/pwndbg; cd pwndbg; ./setup.sh

run apt-get install -y libcapstone-dev

# cleanup
run find / -type f -perm -4000 | xargs chmod u-s

copy start /start
run adduser hw6
cmd "/start"
