from scapy.all import *
import datetime
from elasticsearch import Elasticsearch

# Format for timestamp
fmt = "%Y-%m-%d %H:%M:%S"
elastic_ip = "10.2.1.12"

def send_to_elastic(elastic_IP, msg):
  print("sending: %s" %elastic_IP)  
  try:
    es = Elasticsearch([{'host': str(elastic_IP), 'port': 9200}])  
    es.index(index='sniff', doc_type='wifi_traffic', body=msg)
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
    
        # Get Channel Frequency 
        channel_freq = pkt[RadioTap].channel_freq
    
        # Get Antenna dBm
        dbm_ant = str(pkt[RadioTap].dbm_antsignal)
    
        # Get MAC Address
        src_mac = pkt[Dot11].addr2
    
        # Check for any SSID? Also Decode it
        ssid = (pkt[Dot11Elt].info).decode("utf-8")
    
        msg = {
          'timestamp': time_stamp,
          'source_mac': src_mac,
          'signal_strength': dbm_ant,
          'ssid': ssid,
          'channel_frequency': channel_freq,
        }
        
        send_to_elastic(elastic_ip, msg)

if __name__=="__main__":
    read_pcap("captures/tmp/capture_2018-01-20_20-20-02.pcap")
