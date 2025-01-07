import sys
import time
import os
from datetime import datetime
from scapy.all import Ether, sendp, sniff,  get_if_list, get_if_hwaddr

def sender(target_mac, interface):
    """Send Ethernet frames to a specific MAC address."""
    print(f"Sending packets to {target_mac} on interface {interface}. Press Ctrl+C to stop.")
    try:
        while True:
            packet = Ether(dst=target_mac, src=get_if_hwaddr(interface)) / b"Ethernet ping"
            sendp(packet, iface=interface, verbose=False)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping sender.")

def receiver(interface):
    """Listen for incoming Ethernet frames on a specified interface and display source MAC and timestamp."""
    print(f"Listening for packets on interface {interface}. Press Ctrl+C to stop.")
    try:
        def process_packet(packet):
            if Ether in packet:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] Packet received from {packet[Ether].src}")

        sniff(iface=interface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping receiver.")

def choose_interface():
    """Prompt the user to choose an Ethernet interface."""
    interfaces = get_if_list()
    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i + 1}. {iface}")

    choice = int(input("Select an interface (number): ").strip())
    if 1 <= choice <= len(interfaces):
        return interfaces[choice - 1]
    else:
        print("Invalid choice.")
        sys.exit(1)

#def get_mac():
    #"""Retrieve the MAC address of the first interface."""
    #from uuid import getnode
    #mac = getnode()
    #return ":".join(f"{(mac >> i) & 0xff:02x}" for i in range(40, -8, -8))

def main():
    print("Select mode:")
    print("1. Sending mode")
    print("2. Receiving mode")

    choice = input("Enter choice (1/2): ").strip()

    interface = choose_interface()

    if choice == "1":
        target_mac = input("Enter target MAC address (e.g., 00:11:22:33:44:55): ").strip()
        sender(target_mac, interface)
    elif choice == "2":
        receiver(interface)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges. Run as root or with sudo.")
        sys.exit(1)
    else:
        main()

