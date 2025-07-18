# 🛡️ YaCine DNS & ARP Spoofing Tool

A lightweight Python-based network tool for performing **ARP spoofing** and **DNS query sniffing** on a local network. Built using [Scapy].

---

## ✨ Features

- Intercepts and logs DNS queries made by devices on the network
- Performs ARP spoofing to redirect traffic between target and gateway
- Displays clean, color-coded output in terminal using `rich`

---

## How It Works

This script performs a **Man-in-the-Middle (MITM)** attack by:
1. ARP spoofing both the **target** and the **gateway**
2. Sniffing **DNS requests (UDP port 53)** from the intercepted traffic
3. Printing the source IP and the requested domain name

