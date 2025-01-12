from scapy.all import Ether, sendp, sniff, get_if_hwaddr, get_if_list
from datetime import datetime
import time
import os
import sys

FIXED_PAYLOAD_LENGTH = 64  # Define the fixed payload length

def client(target_mac, interface, num_requests=4, timeout=10):
    """Send Ethernet frames using the Ethernet Configuration Testing Protocol (ECTP) to a specific MAC address and print received answers."""
    print(f"Sending ECTP packets to {target_mac} on interface {interface}. Press Ctrl+C to stop.")
    
    sent_packets = 0
    received_responses = 0
    round_trip_times = []

    def process_packet(packet):
        print("Packet captured")  # Debugging statement
        nonlocal received_responses
        if Ether in packet:
            print(f"Ethernet type: {hex(packet.type)}")  # Debugging statement
            if packet.type == 0x9000:  # Check for ECTP packets
                print("ECTP packet detected") # Debugging statement
                # Strip trailing zeros from the payload
                payload = packet.load.rstrip(b'\x00')
                # Check if the packet is a response packet
                if payload[15:] != b"ECTP response":
                    print("Not a response packet")  # Debugging statement
                    return
            
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                src_mac = packet[Ether].src
            
                # Extract custom fields from the response
                loop_skipcnt = payload[0:2]
                loop_function_0 = payload[2:4]
                loop_forward_mac = payload[4:11]
                loop_function_1 = payload[11:13]
                loop_receipt_num = payload[13:15]
            
                rtt = (datetime.now() - start_time).total_seconds()
                round_trip_times.append(rtt)
                received_responses += 1
                print(f"[{timestamp}] ECTP response received from {src_mac} (RTT: {rtt:.4f} seconds)")
                #print(f"  Loop Skip Count: {int.from_bytes(loop_skipcnt, 'big')}")
                #print(f"  Loop Function 0: {int.from_bytes(loop_function_0, 'big')}")
                #print(f"  Loop Forward MAC: {':'.join(f'{b:02x}' for b in loop_forward_mac)}")
                #print(f"  Loop Function 1: {int.from_bytes(loop_function_1, 'big')}")
                #print(f"  Loop Receipt Number: {int.from_bytes(loop_receipt_num, 'big')}")
                #print payload message
                print(f"  Payload: {payload[15:].decode('utf-8')}")

    try:
        for _ in range(num_requests):
            # Define custom fields
            loop_skipcnt = b'\x00\x01'  # Skip count
            loop_function_0 = b'\x00\x02'  # Function 0
            loop_forward_mac = b'\x00\x11\x22\x33\x44\x55\x66'  # Forward MAC address
            loop_function_1 = b'\x00\x03'  # Function 1
            loop_receipt_num = b'\x00\x04'  # Receipt number

            # Construct an ECTP packet with custom fields
            payload = (loop_skipcnt +
                       loop_function_0 +
                       loop_forward_mac +
                       loop_function_1 +
                       loop_receipt_num +
                       b"ECTP ping")
            # Pad the payload to the fixed length
            payload = payload.ljust(FIXED_PAYLOAD_LENGTH, b'\x00')
            packet = Ether(dst=target_mac, src=get_if_hwaddr(interface), type=0x9000) / payload
            start_time = datetime.now()
            sendp(packet, iface=interface, verbose=False)
            sent_packets += 1
            
            # Sniff for response packets
            print("Starting sniffing...")  # Debugging statement
            sniff(iface=interface, prn=process_packet, timeout=timeout, store=False)
            print("Sniffing ended.")  # Debugging statement
            time.sleep(1)
        
        print(f"\nSent packets: {sent_packets}")
        print(f"Received responses: {received_responses}")
        if round_trip_times:
            print(f"Average RTT: {sum(round_trip_times) / len(round_trip_times):.4f} seconds")
    except KeyboardInterrupt:
        print("\nStopping client.")

def server(interface):
    """Listen for incoming Ethernet frames on a specified interface and send a response frame to the source."""
    print(f"Listening for packets on interface {interface}. Press Ctrl+C to stop.")
    
    def process_packet(packet):
        if Ether in packet and packet.type == 0x9000:  # Check for ECTP packets
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_mac = packet[Ether].src
            
            # Extract custom fields
            payload = packet.load.rstrip(b'\x00')
            loop_skipcnt = payload[0:2]
            loop_function_0 = payload[2:4]
            loop_forward_mac = payload[4:11]
            loop_function_1 = payload[11:13]
            loop_receipt_num = payload[13:15]
            
            # Check if the packet is a response packet to avoid infinite loop
            if payload[15:] != b"ECTP ping":
                return
            
            print(f"[{timestamp}] ECTP packet received from {src_mac}")
            print(f"  Loop Skip Count: {int.from_bytes(loop_skipcnt, 'big')}")
            print(f"  Loop Function 0: {int.from_bytes(loop_function_0, 'big')}")
            print(f"  Loop Forward MAC: {':'.join(f'{b:02x}' for b in loop_forward_mac)}")
            print(f"  Loop Function 1: {int.from_bytes(loop_function_1, 'big')}")
            print(f"  Loop Receipt Number: {int.from_bytes(loop_receipt_num, 'big')}")
            
            # Construct and send a response packet
            response_payload = (loop_skipcnt +
                                loop_function_0 +
                                loop_forward_mac +
                                loop_function_1 +
                                loop_receipt_num +
                                b"ECTP response")
            # Pad the payload to the fixed length
            response_payload = response_payload.ljust(FIXED_PAYLOAD_LENGTH, b'\x00')
            response_packet = Ether(dst=src_mac, src=get_if_hwaddr(interface), type=0x9000) / response_payload
            sendp(response_packet, iface=interface, verbose=False)
            print(f"Response sent to {src_mac}")

    try:
        sniff(iface=interface, prn=process_packet, filter="ether proto 0x9000", store=False)
    except KeyboardInterrupt:
        print("\nStopping server.")

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

def main():
    print("Select mode:")
    print("1. Client mode")
    print("2. Server mode")

    choice = input("Enter choice (1/2): ").strip()

    interface = choose_interface()

    if choice == "1":
        target_mac = input("Enter target MAC address (e.g., 00:11:22:33:44:55): ").strip()
        client(target_mac, interface)
    elif choice == "2":
        server(interface)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges. Run as root or with sudo.")
        sys.exit(1)
    else:
        main()
