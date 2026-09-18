#!/usr/bin/env python3
"""
Synthetic Port Scan Attack Simulator

NOTE: This must be run AFTER the sniffer has accumulated at least 30-60 minutes 
of baseline traffic. Otherwise, the RCF anomaly detector has no baseline to 
compare against and won't flag it as anomalous, even though the traffic pattern 
is correct.
"""

import sys
import socket
import argparse

def main():
    parser = argparse.ArgumentParser(description="Synthetic Port Scan Attack Simulator")
    parser.add_argument("target", nargs="?", default="127.0.0.1", 
                        help="Target IP address (default: 127.0.0.1)")
    
    args = parser.parse_args()
    target_ip = args.target
    
    # Range of 25 distinct ports to scan
    ports_to_scan = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 9200
    ]
    
    print(f"Starting synthetic port scan against {target_ip}...")
    
    connected = 0
    refused_or_timeout = 0
    
    for port in ports_to_scan:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        
        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"Port {port:4d}: OPEN")
                connected += 1
            else:
                refused_or_timeout += 1
        except Exception:
            refused_or_timeout += 1
        finally:
            sock.close()
            
    print("\n--- Port Scan Summary ---")
    print(f"Target: {target_ip}")
    print(f"Total Ports Attempted: {len(ports_to_scan)}")
    print(f"Successfully Connected (OPEN): {connected}")
    print(f"Refused/Timed Out/Error: {refused_or_timeout}")

if __name__ == "__main__":
    main()
