for solve in /home/hw1/*:*/solves/*
do
	log=${solve/solves/logs}
	if [ ! -f $log ]
	then
		echo "!!! LOG MISSING: $log"
		continue
	fi

	if ! grep -iqE "CSE.*466" $log
	then
		echo "??? No CSE466: $log"
		continue
	fi
done
