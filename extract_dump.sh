#!/bin/bash

FILES="/home/ubuntu/sniff_captures/"
DUMP_DIR="/home/ubuntu/caps"

while true
do 
    
    # Check if any file changed within 5 minute window
    F_NAME=`find $FILES -mmin -5 -type f -print`
    
    if [ ! -z "$F_NAME" ]
    then 
        PCAP_FILE=`tar -zxvf $F_NAME -C $DUMP_DIR`
        echo $PCAP_FILE
        
        sudo python3 parse_dump.py $DUMP_DIR/$PCAP_FILE
    else 
        echo "empty"
    fi
    
    sleep 300
done
