#!/bin/bash

DIR_NAME="/tmp"
MONITOR_INTERFACE="mon0"
MANAGED_INTERFACE="wlan0"
CHANNEL=6
PRIVATE_KEY="/root/.ssh/sniff"
MONITORING_TIME_DURATION=540 # secs 

# Get the Physical device. The "/dev/null" is used to suppress the 'tr' warning msg
PHY=`iw dev | grep '#' | tr -d '\#\\' 2> /dev/null`
echo $PHY

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
bring_interface_up $MONITOR_INTERFACE "monitor"	
    
# TCPDUMP FOR AMOUNT OF TIME
FILE_NAME="capture_`date '+%Y-%m-%d_%H-%M-%S'`"
/usr/sbin/tcpdump -tttt -nei $MONITOR_INTERFACE -G $MONITORING_TIME_DURATION -W 1 -v type mgt subtype probe-req -w "$DIR_NAME/$FILE_NAME.pcap"

# TAR THAT OUTPUT FILE
tar -cvzf "$DIR_NAME/$FILE_NAME.tar.gz" "$DIR_NAME/$FILE_NAME.pcap"

# BRING MANAGED INTERFACE BACK UP
bring_interface_up $MANAGED_INTERFACE "managed"

# SCP THAT FILE 
scp -i $PRIVATE_KEY "$DIR_NAME/$FILE_NAME.tar.gz" xxxx@client1.savitestbed.ca:~/sniff_captures/

# REMOVE THOSE FILES
rm "$DIR_NAME/$FILE_NAME.*"

exit 0
