from scapy.all import Ether, sendp, sniff, get_if_hwaddr, get_if_list
from datetime import datetime
import time
import os
import sys
import argparse  # Add argparse for argument parsing

FIXED_PAYLOAD_LENGTH = 50  # Define the fixed payload length
RESPONSE_DELAY = 0.05  # Define the response delay in seconds

def client(target_mac, interface, num_requests=4, timeout=1, continuous=False, srcaddr=False):
    """Send Ethernet frames using the Ethernet Configuration Testing Protocol (ECTP) to a specific MAC address and print received answers."""
    print(f"Sending ECTP packets to {target_mac} on interface {interface}. Press Ctrl+C to stop.")
    
    sent_packets = 0
    received_responses = 0
    round_trip_times = []
    if not srcaddr:
        srcaddr = get_if_hwaddr(interface)
    else:
        srcaddr = mac2str(srcaddr)

    def process_packet(packet):
        nonlocal received_responses
        if Ether in packet and packet.type == 0x9000:  # Check for ECTP packets
            # Strip trailing zeros from the payload
            payload = packet.load.rstrip(b'\x00')
            loop_function_0 = payload[2:4]
            # Check if the packet is a response packet
            if loop_function_0 != b'\x01\x00':
                return
        
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_mac = packet[Ether].src
        
            # Extract custom fields from the response
            loop_skipcnt = payload[0:2]
            loop_forward_mac = payload[4:11]
            loop_function_1 = payload[11:13]
            loop_receipt_num = payload[13:15]
        
            rtt = (datetime.now() - start_time).total_seconds() - RESPONSE_DELAY
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
        while continuous or sent_packets < num_requests:
            # Define custom fields
            loop_skipcnt = b'\x00\x00'  # Skip count
            loop_function_0 = b'\x02\x00'  # Function 0
            loop_forward_mac = b'\x00\x11\x22\x33\x44\x55'  # Forward MAC address
            loop_function_1 = b'\x01\x00'  # Function 1
            #loop_receipt_num = b'\x00\x00'  # Receipt number

            # Construct an ECTP packet with custom fields
            payload = (loop_skipcnt +
                       loop_function_0 +
                       loop_forward_mac +
                       loop_function_1 +
                       #loop_receipt_num +
                       b"ECTP ping")
            # Pad the payload to the fixed length
            payload = payload.ljust(FIXED_PAYLOAD_LENGTH, b'\x00')
            packet = Ether(dst=target_mac, src=srcaddr, type=0x9000) / payload
            start_time = datetime.now()
            sendp(packet, iface=interface, verbose=False)
            sent_packets += 1
            
            # Sniff for response packets
            sniff(iface=interface, prn=process_packet, filter="ether proto 0x9000", timeout=timeout, store=False)
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
            #loop_receipt_num = payload[13:15]
            
            # Check if the packet is a forwarding message to avoid infinite loop
            if loop_function_0 != b'\x02\x00':
                return
            
            print(f"[{timestamp}] ECTP packet received from {src_mac}")
            #print(f"  Loop Skip Count: {int.from_bytes(loop_skipcnt, 'big')}")
            #print(f"  Loop Function 0: {int.from_bytes(loop_function_0, 'big')}")
            #print(f"  Loop Forward MAC: {':'.join(f'{b:02x}' for b in loop_forward_mac)}")
            #print(f"  Loop Function 1: {int.from_bytes(loop_function_1, 'big')}")
            #print(f"  Loop Receipt Number: {int.from_bytes(loop_receipt_num, 'big')}")
            
            # Construct and send a response packet
            loop_skipcnt = b'\x08\x00'  # Skip count
            loop_function_0 = b'\x01\x00'  # Function 0
            #loop_forward_mac = b'\x00\x01\x22\x33\x44\x55'  # Forward MAC address
            #loop_function_1 = b'\x00\x00'  # Function 1
            loop_receipt_num = b'\x01\x00'  # Receipt number
            response_payload = (loop_skipcnt +
                                loop_function_0 +
                                #loop_forward_mac +
                                #loop_function_1 +
                                loop_receipt_num +
                                b"ECTP response")
            # Pad the payload to the fixed length
            response_payload = response_payload.ljust(FIXED_PAYLOAD_LENGTH, b'\x00')
            response_packet = Ether(dst=src_mac, src=get_if_hwaddr(interface), type=0x9000) / response_payload
            time.sleep(RESPONSE_DELAY)  # Delay the response for debugging purposes
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
    parser = argparse.ArgumentParser(description="Ethernet Configuration Testing Protocol (ECTP) tool")
    parser.add_argument('-s', '--server', action='store_true', help="Start in server mode")
    parser.add_argument('-c', '--client', metavar='TARGET_MAC', help="Start in client mode and specify target MAC address")
    parser.add_argument('-n', '--num_requests', type=int, default=4, help="Number of requests to send in client mode (default: 4)")
    parser.add_argument('-w', '--timeout', type=int, default=1, help="Timeout between requests in client mode (default: 1 second)")
    parser.add_argument('-t', '--continuous', action='store_true', help="Send requests continuously until stopped")
    parser.add_argument('-S', '--srcaddr', metavar='src_address', help="Source address to use for the client")
    
    args = parser.parse_args()

    if not args.server and not args.client:
        parser.print_help()
        sys.exit(1)

    interface = choose_interface()


    if args.server:
        server(interface)
    elif args.client:
        client(args.client, interface, num_requests=args.num_requests, timeout=args.timeout, continuous=args.continuous, srcaddr=args.srcaddr)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges. Run as root or with sudo.")
        sys.exit(1)
    else:
        main()
