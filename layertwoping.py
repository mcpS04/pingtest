import sys
import time
import os
from datetime import datetime
from scapy.all import Ether, sendp, sniff

def sender(target_mac):
    """Send Ethernet frames to a specific MAC address."""
    print(f"Sending packets to {target_mac}. Press Ctrl+C to stop.")
    try:
        while True:
            packet = Ether(dst=target_mac, src=get_mac()) / b"Ethernet ping"
            sendp(packet, verbose=False)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping sender.")

def receiver():
    """Listen for incoming Ethernet frames and display source MAC and timestamp."""
    print("Listening for packets. Press Ctrl+C to stop.")
    try:
        def process_packet(packet):
            if Ether in packet:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] Packet received from {packet[Ether].src}")

        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping receiver.")

def get_mac():
    """Retrieve the MAC address of the first interface."""
    from uuid import getnode
    mac = getnode()
    return ":".join(f"{(mac >> i) & 0xff:02x}" for i in range(40, -8, -8))

def main():
    print("Select mode:")
    print("1. Sending mode")
    print("2. Receiving mode")

    choice = input("Enter choice (1/2): ").strip()

    if choice == "1":
        target_mac = input("Enter target MAC address (e.g., 00:11:22:33:44:55): ").strip()
        sender(target_mac)
    elif choice == "2":
        receiver()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(\"This script requires root privileges. Run as root or with sudo.\")
        sys.exit(1)
    else:
        main()

