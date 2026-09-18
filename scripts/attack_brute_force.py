import socket
import argparse
import time

def brute_force_attack(target_ip, target_port, attempts=150):
    print(f"Starting simulated brute-force attack against {target_ip}:{target_port} ({attempts} attempts)...")
    successes = 0
    failures = 0
    
    for i in range(attempts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            result = s.connect_ex((target_ip, target_port))
            if result == 0:
                successes += 1
            else:
                failures += 1
            s.close()
        except Exception:
            failures += 1
        
        # Micro-sleep to avoid OS-level local socket exhaustion
        time.sleep(0.01)
            
    print("\n--- Attack Summary ---")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Total Attempts: {attempts}")
    print(f"Successful Connections: {successes}")
    print(f"Failed Connections: {failures}")
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate a brute-force attack (repeated TCP connections to a single port).")
    parser.add_argument("target_ip", type=str, help="Target IP address")
    parser.add_argument("--port", type=int, default=22, help="Target port (default: 22)")
    parser.add_argument("--attempts", type=int, default=150, help="Number of connection attempts")
    
    args = parser.parse_args()
    brute_force_attack(args.target_ip, args.port, args.attempts)
