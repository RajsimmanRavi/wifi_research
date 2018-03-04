#!/bin/bash

DIR_NAME="/tmp"
MONITOR_INTERFACE="wlan1"
MANAGED_INTERFACE="wlan0"
CHANNEL=6
PRIVATE_KEY="/root/.ssh/sniff"
MONITORING_TIME_DURATION=240 # secs 

# Get the Physical device. The "/dev/null" is used to suppress the 'tr' warning msg
#PHY=`iw dev | grep '#' | tr -d '\#\\' 2> /dev/null`
#echo $PHY

# This function will bring down the current interface and create another interface (either monitor or managed)
# Parameters: $1 --> Interface name
#             $2 --> "monitor" or "managed"
bring_interface_up(){
     
    # Get the current interface
    INTERFACE=`iw dev | grep 'Interface' | cut -d ' ' -f 2`
    echo $INTERFACE
    
    # Delete that interface, because we're going to create a new one 
    iw dev $INTERFACE del
    
    # STEP 2. Create a new interface based on the parameters
    iw phy $PHY interface add $1 type $2 
    
    if [ "$2" == "monitor" ]
    then

        # Change MAC Address of the monitoring interface (to hide your tracks, kinda)
        # First, bring interface down
        ifconfig $1 down
        # Change MAC address
        macchanger -r $1
        # Bring it back up
        ifconfig $1 up
        
        # STEP 4. Set it to listen to specific channel (TODO: make for loop later)
        # Using channel 6, since it is default on devices
        iwconfig $1 channel $CHANNEL
    else 
	ifconfig $1 up 
    fi
}    

# BRING MONITORING INTERFACE UP
#bring_interface_up $MONITOR_INTERFACE "monitor"	
    
ifconfig $MONITOR_INTERFACE down
# Change MAC address
macchanger -r $MONITOR_INTERFACE
# Bring it back up
ifconfig $MONITOR_INTERFACE up
        
# STEP 4. Set it to listen to specific channel (TODO: make for loop later)
# Using channel 6, since it is default on devices
iwconfig $MONITOR_INTERFACE channel $CHANNEL

# File name for the pcap
# Get IP Address of the sensor
IP=`/sbin/ifconfig $MANAGED_INTERFACE | grep -w 'inet' | awk '{print $2}' | sed 's/\./_/g'`
#LOC=`curl ipinfo.io/$(curl ipinfo.io/ip) | grep 'loc' | awk -F ':' '{print $2}' | tr '.' '_' | tr ',' '_' | tr -d '\"' | tr -d '[:space:]'`
LOC=`curl ipinfo.io/$(curl ipinfo.io/ip) | jq '.loc' | tr ',' ':' | tr '.' '_' | tr -d '\"' | tr -d '[:space:]'`
FILE_NAME="$LOC-PCAP-`date '+%Y-%m-%d_%H-%M-%S'`"

# TCPDUMP FOR AMOUNT OF TIME
/usr/sbin/tcpdump -tttt -nei $MONITOR_INTERFACE -G $MONITORING_TIME_DURATION -W 1 -v type mgt subtype probe-req -w "$DIR_NAME/$FILE_NAME.pcap"

# TAR THAT OUTPUT FILE
#tar czf $DIR_NAME/$FILE_NAME.tar.gz --directory=$DIR_NAME $FILE_NAME.pcap

# SCP THAT FILE 
scp -i $PRIVATE_KEY $DIR_NAME/$FILE_NAME.pcap ubuntu@10.2.1.24:~/sniff_captures/

# REMOVE THOSE FILES
rm $DIR_NAME/$FILE_NAME.pcap
#rm $DIR_NAME/$FILE_NAME.tar.gz

exit 0
