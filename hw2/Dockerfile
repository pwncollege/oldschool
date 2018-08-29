from ubuntu:bionic
#from hw1

run apt-get update
run apt-get -y install file
run rm -f /start.sh
copy start /start
copy get_flag /get_flag
run chown root.nogroup /get_flag
run chmod 2750 /get_flag
#run userdel -r hw1
run adduser hw2
cmd "/start"
