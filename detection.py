from scapy.all import sniff, ARP
from collections import defaultdict

# Store MAC to IP mappings
mac_ip_map = defaultdict(set)

# Threshold for suspicious MAC claiming too many IPs
THRESHOLD = 3

def process_packet(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        mac_ip_map[mac].add(ip)

        print(f"[+] ARP Reply: {ip} is at {mac}")
        
        if len(mac_ip_map[mac]) >= THRESHOLD:
            print("⚠️  Suspicious Activity Detected!")
            print(f"    >> MAC {mac} is claiming {len(mac_ip_map[mac])} different IPs:")
            for claimed_ip in mac_ip_map[mac]:
                print(f"       - {claimed_ip}")
            print("-" * 40)

print("📡 Listening for ARP replies... (Press Ctrl+C to stop)\n")
sniff(filter="arp", prn=process_packet, store=0)
