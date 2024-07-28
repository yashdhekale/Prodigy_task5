import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from scapy.all import sniff, IP, TCP, UDP, conf

# Ensure Npcap is being used
conf.use_pcap = True

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol}")

        if TCP in packet:
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}")
            print(f"Payload: {packet[TCP].payload}")
        
        elif UDP in packet:
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport} -> Destination Port: {packet[UDP].dport}")
            print(f"Payload: {packet[UDP].payload}")
        
        print("-" * 50)

# Sniff the network packets for 10 seconds or up to 50 packets, whichever comes first
sniff(prn=packet_callback, store=0, timeout=10, count=50)


