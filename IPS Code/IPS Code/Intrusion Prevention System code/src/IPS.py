from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP, ICMP, TCP, UDP
from .flow_session import generate_session_class
from .Classifier import classify_flow
from .logging import Log_Traffic, get_whitelist, get_blacklist
import threading

# Global session instance to track flows
session_instance = None

# Function to process packets and decide whether to block or allow forwarding
def process_packet(scapy_pkt, packet):
    """Process packets based on traffic type (internal vs external)"""
    global session_instance
    
    # Check ICMP block
    if scapy_pkt.haslayer(ICMP):
        if get_blacklist():  # Global ICMP block check
            #print("ICMP Dropped")
            return packet.drop()

    # Check source IP blacklist
    if get_blacklist(ip=scapy_pkt.src):
        #print(f"Source IP {scapy_pkt.src} Dropped")
        return packet.drop()

    # Check destination IP blacklist
    if get_blacklist(ip=scapy_pkt.dst):
        #print(f"Destination IP {scapy_pkt.dst} Dropped")
        return packet.drop()

    # Check TCP port blacklist
    if scapy_pkt.haslayer(TCP):
        port = scapy_pkt[TCP].dport
        if get_blacklist(port=port):
            #print(f"TCP Port {port} Dropped")
            return packet.drop()

    # Check UDP port blacklist
    elif scapy_pkt.haslayer(UDP):
        port = scapy_pkt[UDP].dport
        if get_blacklist(port=port):
            #print(f"UDP Port {port} Dropped")
            return packet.drop()
    if session_instance:
        
        # Allow DNS servers through without inspection
        if scapy_pkt.dst in ["8.8.8.8", "8.8.4.4", "1.1.1.1"]:
            return packet.accept()
        
        # Internal traffic (192.168.x.x) - Process DPI
        if scapy_pkt.src.startswith("192.168"):
            # Perform Deep Packet Inspection (DPI) for internal traffic
            if scapy_pkt.haslayer(TCP) or scapy_pkt.haslayer(UDP):
                session_instance.on_packet_received(scapy_pkt)  # Process packet
                flows = session_instance.get_last_flow()  # Get processed flow data
                data = flows.get_data()

                # Machine Learning classification
                prediction = classify_flow(data)

                # Update data with classification results
                data["Label"] = prediction['Layer 1']
                data["Label_2"] = prediction['Layer 2']
                data["Label_3"] = prediction['Layer 3']

                # Log the traffic flow
                Log_Traffic(data)

                # Check if traffic is Darknet and apply whitelist filtering
                if prediction['Layer 1'] == "Darknet":
                    layer2_result = prediction.get('Layer 2')
                    if layer2_result in ["Tor", "VPN", "I2P", "Freenet", "Zeronet"]:
                        if get_whitelist(data["Src IP"]):
                            return packet.accept()
                        return packet.drop()  # Block the packet
                else:
                    return packet.accept()  # Forward non-Darknet traffic
            else:
                return packet.accept()  # Allow non-TCP/UDP packets to pass through
        else:
            # External traffic (Internet-bound) - No DPI
            return packet.accept()
    else:
        # No active session_instance, allow packet by default
        return packet.accept()

# Function to handle incoming packets via NetfilterQueue
def ips(packet):
    """Accept and process each packet"""
    scapy_pkt = IP(packet.get_payload())  # Convert raw packet to Scapy format
    process_packet(scapy_pkt, packet)

# Function to run a specific NetfilterQueue with the IPS handler
def run_queue(queue_num):
    """Run NetfilterQueue handler"""
    queue = NetfilterQueue()
    queue.bind(queue_num, ips)
    queue.run()

# Setup function for initializing multi-threaded NFQueue processing
def setup_nfqueue(verbose=True, to_csv=False, output_file=None):
    global session_instance
    # Generate a session instance for flow tracking
    session_cls = generate_session_class(verbose, to_csv, output_file)
    session_instance = session_cls()

    # Define number of NFQueues for parallel processing
    num_queues = 4

    # Launch threads for each queue
    threads = []
    for i in range(num_queues):
        thread = threading.Thread(target=run_queue, args=(i,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Keep main thread alive
    for thread in threads:
        thread.join()

