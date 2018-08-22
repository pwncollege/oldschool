#[ -f pkgs-all ] || ( grep-aptavail -s Package . | awk '{print $2}' | sort > pkgs-all )
#[ -f pkgs-cli ] || ( cat pkgs-all | parallel --progress --eta "apt-rdepends {} 2>/dev/null | grep -iq libx11 || echo {}" > pkgs-cli )
#[ -f pkgs-cli ] || ( cat pkgs-popular | head -n 4000 | parallel --progress --eta '\
#	apt-rdepends {} >/dev/shm/deps-{%} 2>/dev/null; [ $(wc -l /dev/shm/deps-{%} | awk "{print \$1}") -gt 2 ] && ( grep -Eq "(libx11|libway)" /dev/shm/deps-{%} || echo {} )\
#' > pkgs-cli )
#[ -f by_inst ] || wget https://popcon.debian.org/by_inst
[ -f pkgs-popular ] || ( cat by_inst || curl https://popcon.debian.org/by_inst 2>/dev/null ) | grep -E "^[0-9]" | awk '{print $2}' | grep -Ev "^lib" > pkgs-popular

echo "#!/bin/bash" > install.sh
chmod 755 install.sh
for pkg in $(cat pkgs-popular | head -n 5000)
do
	echo "apt-get install -y $pkg || echo ERROR INSTALLING $pkg" >> install.sh
done
