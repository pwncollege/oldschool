#!/bin/bash

while :;
do
	echo "[*] Cleanup at $(date)"
	docker ps
	docker ps | grep -E "(Up .. minutes)|(Up .* hour)" | awk '{print $1}' | xargs docker kill
	sleep 60
done
