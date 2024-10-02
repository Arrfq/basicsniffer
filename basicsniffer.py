import sys
from scapy.all import *
from functools import partial

#Interface name taken from arguments
int_name=sys.argv[1]

#Number of packets that will be sniffed taken from argument
maximum_packet = int(sys.argv[2]) if len(sys.argv) == 3 else None

#Counting the number of sniffed packet if not specified in argument
packet_count=0
def packet_counting():
    global packet_count
    packet_count+=1

#Function to log the sniffed packet
def logging(packet, log):
    #Check if the packet has an IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        #Check if the packet is using TCP or UDP
        if packet.haslayer(TCP):
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            #Log the packet
            log.write(f"TCP detected from {src_ip}:{tcp_src_port} to {dst_ip}:{tcp_dst_port}\n")
        elif packet.haslayer(UDP):
            udp_src_port = packet[UDP].sport
            udp_dst_port = packet[UDP].dport
            #Log the packet
            log.write(f"UDP detected from {src_ip}:{udp_src_port} to {dst_ip}:{udp_dst_port}\n")
        
        #Ensure packet is written immediately
        log.flush()

#Function to input sniffed packet to the logging function
def packet_handling(pkt, log):
    logging(pkt, log)
    packet_counting()

def main():
    logfile = f"{int_name}_sniffed.txt"

    # If the script is run without count parameters
    if maximum_packet is None:
        with open(logfile, 'w') as logging_data:
            try:
                print("Sniffing started")
                # Use partial to create a new function that binds logging_data
                packet_handler = partial(packet_handling, log=logging_data)
                sniff(iface=int_name, prn=packet_handler, store=0)
            except KeyboardInterrupt:
                print(f"Sniffing ended by user. Numbers of sniffed packet = {packet_count}")
                sys.exit(0)

    # If the script is run with count parameters
    else:
        with open(logfile, 'w') as logging_data:
            print("Sniffing started")
            # Use partial to create a new function that binds logging_data
            packet_handler = partial(packet_handling, log=logging_data)
            sniff(iface=int_name, prn=packet_handler, store=0, count=maximum_packet)
            print(f"Sniffing ended. Numbers of sniffed packet = {packet_count}")

# Check if the script is being run directly
if __name__ == "__main__":
    #Interface not found
    if int_name not in get_if_list():
        print(f"Error: Interface {int_name} not found.")
        sys.exit(1)
    
    #Wrong argument
    if len(sys.argv)<2 or len(sys.argv)>3:
        print("Usage: python basicsniffer.py <interface> <packet_count_in_integer>")
        sys.exit(1)

    main()
