#!/bin/bash
# YOU DON'T NEED TO EXECUTE THIS FILE 
# JUST KEEPING IT FOR BACKUP
FILES="/home/ubuntu/sniff_captures/"
DUMP_DIR="/home/ubuntu/caps"

while true
do 
    
    # Check if any file changed within 5 minute window
    F_NAME=`find $FILES -mmin -5 -type f -print`
    
    if [ ! -z "$F_NAME" ]
    then
        echo $F_NAME
        PCAP_FILE=`tar -zxvf $F_NAME -C $DUMP_DIR`
        echo $PCAP_FILE
        
        LAT_LONG=`echo $PCAP_FILE | awk -F '-PCAP' '{print $1}' | tr '_' '.' | tr ':' ','`

        echo $LAT_LONG
        sudo python3 parse_dump_v2.py $DUMP_DIR/$PCAP_FILE $LAT_LONG
    else 
        echo "empty"
    fi
    
    sleep 300
done
