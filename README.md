# Prodigy_task5
Network Packet Analyzer
Overview
This project involves developing a packet sniffer tool that captures and analyzes network packets. The tool displays relevant information such as source and destination IP addresses, protocols, and payload data. It is intended for educational purposes to enhance understanding and improve network security practices.

Features
Capture Network Packets: Intercept and capture packets on the network.
Analyze Packet Data: Display source and destination IP addresses, protocols, and payload data.
Support for Multiple Protocols: Analyze TCP, UDP, and other protocols.
Ethical Use: Designed for educational purposes to promote ethical hacking and cybersecurity practices.
Prerequisites
Python 3.x
scapy library
npcap for Windows or libpcap for Linux
Installation
Clone the Repository:

bash
Copy code
git clone https://github.com/yourusername/network-packet-analyzer.git
cd network-packet-analyzer
Create a Virtual Environment (optional but recommended):

bash
Copy code
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
Install the Required Packages:

bash
Copy code
pip install -r requirements.txt
If scapy is not listed in the requirements.txt, you can install it directly:

bash
Copy code
pip install scapy
Install Npcap/Libpcap:

Windows: Download and install Npcap
Linux: Libpcap is usually pre-installed. If not, install it via your package manager (e.g., sudo apt-get install libpcap-dev).
Usage
Run the Packet Sniffer:

bash
Copy code
python prog4.py
Output:
The tool will display captured packet information such as source and destination IP addresses, protocols, and payload data.

Code Explanation
python
Copy code
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

# Sniff the network packets
sniff(prn=packet_callback, store=0)
