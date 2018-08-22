from ubuntu:18.04

env CACHE=1
run apt-get update
run apt-get install -y sudo

# some standard crap
run apt-get install -y ubuntu-standard build-essential apt-utils binutils bsdmainutils bsdutils debianutils diffutils elfutils findutils gnupg-utils keyutils pcaputils pcre2-utils psutils

# merry christmas
add install.sh /install.sh
run DEBIAN_FRONTEND=noninteractive /install.sh
run rm /install.sh

run adduser hw1

copy start.sh /start.sh
cmd "/start.sh"
