import datetime
import threading
from queue import Queue, Empty
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

def packet_generator():
    """
    Captures live packets on the default interface and yields them as dicts.
    Yields None periodically if no packets are captured to allow flushing.
    """
    q = Queue()
    
    def packet_handler(packet):
        if not packet.haslayer(IP):
            return
            
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size = len(packet)
        
        protocol = "other"
        src_port = 0
        dst_port = 0
        tcp_flags = ""
        
        if packet.haslayer(TCP):
            protocol = "tcp"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            protocol = "udp"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "icmp"

        doc = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol.lower(),
            "size": size,
            "tcp_flags": tcp_flags
        }
        q.put(doc)
        
    def start_sniffing():
        # Get default interface
        iface = conf.iface
        print(f"Sniffer listening on interface: {iface}")
        # store=False prevents memory leak over time
        sniff(prn=packet_handler, store=False)
        
    t = threading.Thread(target=start_sniffing, daemon=True)
    t.start()
    
    while True:
        try:
            # Timeout allows yielding control back to indexer to check the 5s timer
            yield q.get(timeout=1.0)
        except Empty:
            yield None
