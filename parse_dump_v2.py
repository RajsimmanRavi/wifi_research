import os
import sys
import time
import datetime
import pytz
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from elasticsearch import Elasticsearch

# Format for timestamp
fmt = "%Y/%m/%d %H:%M:%S"
elastic_ip = "10.2.1.12"
dir_name="/home/ubuntu/sniff_captures"

def send_to_elastic(elastic_IP, msg):
  print("sending: %s" %elastic_IP)
  try:
    es = Elasticsearch([{'host': str(elastic_IP), 'port': 9200}])
    es.index(index='snoop', doc_type='wifi_traffic', body=msg)
  except KeyboardInterrupt:
     print("\nCaught Ctrl+C! Exiting Gracefully...")
     sys.exit()
  except Exception as e:
    print(str(e))
    print("Could not send data rate to Elastic_search...")
  else:
    print("Successfully sent data to Elastic_search!")

def read_pcap(f_name):

    packets = rdpcap(f_name)

    for pkt in packets:
        epoch = pkt.time
        time = datetime.datetime.fromtimestamp(float(epoch))
        time_stamp = time.strftime(fmt)

        # Convert it into UTC (for Kibana)
        local = pytz.timezone ("US/Eastern")
        naive = datetime.datetime.strptime (time_stamp, fmt)
        local_dt = local.localize(naive, is_dst=None)
        utc_dt = local_dt.astimezone (pytz.utc)

        date = utc_dt.strftime(fmt)

        # Get Channel Frequency
        channel_freq = pkt[RadioTap].channel_freq

        # Get Antenna dBm
        dbm_ant = str(pkt[RadioTap].dbm_antsignal)

        # Get MAC Address
        src_mac = pkt[Dot11].addr2

        # Check for any SSID? Also Decode it
        ssid = (pkt[Dot11Elt].info).decode("utf-8")

        msg = {
          'date': date,
          'source_mac': src_mac,
          'signal_strength': dbm_ant,
          'ssid': ssid,
          'channel_frequency': channel_freq,
        }
        print(msg)
        send_to_elastic(elastic_ip, msg)
if __name__=="__main__":

    # Change directory
    os.chdir(dir_name)

    _dir = os.getcwd()

    while(1):
        for dirName, _, fileList in os.walk(_dir):
            for f_name in fileList:
               if((time.time() - os.stat(os.path.join(dirName, f_name)).st_mtime) < 300):
                   print("Found file change: %s " %(f_name))
                   read_pcap(f_name)
        time.sleep(300)
