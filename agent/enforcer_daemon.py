import os
import sys
import time
import signal
import subprocess
import json
import contextlib
import io

from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.fetch_anomaly import fetch_latest_anomaly
from agent.enforcer import process_anomaly_payload
from mcp_server import rule_manager

SHUTDOWN_FLAG = False

def handle_shutdown(signum, frame):
    global SHUTDOWN_FLAG
    print(f"\n[DAEMON] Received signal {signum}. Commencing graceful shutdown...")
    SHUTDOWN_FLAG = True

def force_cleanup_all_active_rules():
    """
    Called strictly on shutdown to leave the user's iptables perfectly clean.
    """
    print("[DAEMON] Cleaning up all active kernel rules before exit...")
    records = rule_manager._load_records()
    changed = False
    for r in records:
        if r.get("status") == "ACTIVE":
            target_ip = r["target_ip"]
            print(f"[DAEMON] Reverting ban for {target_ip}...")
            revert_cmd = ["iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"]
            try:
                subprocess.run(revert_cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                r["status"] = "REVERSED"
                changed = True
            except Exception as e:
                print(f"[DAEMON] Error reverting {target_ip}: {e}")
                
    if changed:
        rule_manager._save_records(records)
    print("[DAEMON] Cleanup complete.")

def main():
    if os.geteuid() != 0:
        print("ERROR: Daemon must be run as root (sudo) to modify iptables.")
        sys.exit(1)
        
    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)
    
    os.environ["DRY_RUN"] = "false"
    
    print("===================================================")
    print("  AGENTIC ZERO-TRUST FIREWALL DAEMON INITIALIZED   ")
    print("===================================================")
    print("[DAEMON] Starting polling loop (interval: 10s)")
    
    last_processed_payload = None
    
    while not SHUTDOWN_FLAG:
        # 1. Clean up expired rules
        try:
            expired = rule_manager.cleanup_expired_rules(dry_run=False)
            if expired:
                print(f"\n[DAEMON] TTL Expired. Reverted bans for: {expired}")
        except Exception as e:
            print(f"[DAEMON] Error during TTL cleanup: {e}")
            
        # 2. Poll OpenSearch securely, suppressing standard output to keep logs clean
        try:
            f = io.StringIO()
            with contextlib.redirect_stdout(f):
                anomaly = fetch_latest_anomaly()
                
            payload_str = json.dumps(anomaly, sort_keys=True)
            # Only process if this anomaly document hasn't been handled already
            if payload_str != last_processed_payload:
                print("\n[DAEMON] >> NEW Anomaly Payload Detected in OpenSearch!")
                res = process_anomaly_payload(anomaly, dry_run=False)
                print(f"[DAEMON] Execution Report: {json.dumps(res, indent=2)}")
                last_processed_payload = payload_str
                
        except SystemExit:
            # fetch_latest_anomaly calls sys.exit(1) when OpenSearch hits are empty
            pass
        except Exception as e:
            print(f"\n[DAEMON] Error polling OpenSearch: {e}")
            
        # 3. Micro-sleep to allow interrupt handling rapidly
        for _ in range(10):
            if SHUTDOWN_FLAG:
                break
            time.sleep(1)

    force_cleanup_all_active_rules()
    print("[DAEMON] Daemon exited gracefully.")

if __name__ == "__main__":
    main()
