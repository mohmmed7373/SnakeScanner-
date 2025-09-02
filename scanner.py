#!/usr/bin/env python3
import os, sys

# نحاول استدعاء مكتبة scapy، ولو مش موجودة نثبتها
try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    os.system(f"{sys.executable} -m pip install scapy")
    from scapy.all import ARP, Ether, srp

import argparse

def welcome_message():
    ascii_banner = r"""
 __  __       _                     _     _             
|  \/  |     | |                   | |   | |            
| \  / | ___ | |__   ___  _ __   __| | __| | ___  _ __  
| |\/| |/ _ \| '_ \ / _ \| '_ \ / _` |/ _` |/ _ \| '_ \ 
| |  | | (_) | | | | (_) | | | | (_| | (_| | (_) | | | |
|_|  |_|\___/|_| |_|\___/|_| |_|\__,_|\__,_|\___/|_| |_|

              🐍 print("🌟 محمد المشرع 🌟".center(60))  🐍
    """

    ascii_snake = r"""
          /^\/^\
        _|__|  O|
\/     /~     \_/ \
 \____|__________/  \
        \_______      \
                `\     \                 \
                  |     |                  \
                 /      /                    \
                /     /                       \
              /      /                         \ \
             /     /                            \  \
           /     /             _----_            \   \
          /     /           _-~      ~-_         |   |
         (      (        _-~    _--_    ~-_     _/   |
          \      ~-____-~    _-~    ~-_    ~-_-~    /
            ~-_           _-~          ~-_       _-~
               ~--______-~                ~-___-~
    """

    print("=" * 60)
    print(ascii_banner)
    print(ascii_snake)
    print("=" * 60)
    print("📡 الأداة ستساعدك على استعراض الأجهزة المتصلة بشبكتك.\n")


def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices


def main():
    parser = argparse.ArgumentParser(description="Network Scanner using Scapy")
    parser.add_argument("range", help="Target IP range (e.g. 192.168.1.1/24)")
    args = parser.parse_args()

    welcome_message()

    print(f"[+] Scanning network: {args.range}")
    devices = scan_network(args.range)

    print("\nAvailable devices in the network:")
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")


if __name__ == "__main__":
    main()
