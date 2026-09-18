import os
import sys
import json
import subprocess
from datetime import datetime, timedelta, timezone

# Add root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.enforcer import process_anomaly_payload
from mcp_server import rule_manager

def check_iptables_rule(target_ip):
    try:
        subprocess.run(["iptables", "-C", "INPUT", "-s", target_ip, "-j", "DROP"], 
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def main():
    if os.geteuid() != 0:
        print("ERROR: This live integration test must be run as root (with sudo) to modify iptables.")
        sys.exit(1)
        
    print("Testing Phase 5 Live E2E Integration...\n")
    
    # Clean logs
    if os.path.exists(rule_manager.LOG_FILE):
        os.remove(rule_manager.LOG_FILE)
        
    # Ensure DRY_RUN is explicitly false for the enforcer
    os.environ["DRY_RUN"] = "false"
    
    TEST_IP_1 = "198.51.100.55"
    
    # Cleanup any lingering iptables state before test just in case
    if check_iptables_rule(TEST_IP_1):
        subprocess.run(["iptables", "-D", "INPUT", "-s", TEST_IP_1, "-j", "DROP"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"--- Test 1: Real Attack & TTL ({TEST_IP_1}) ---")
    mock_payload = {
        "anomaly_grade": 1.0,
        "entity": [{"name": "src_ip", "value": TEST_IP_1}],
        "features": {"distinct_dst_ports": 25}
    }
    
    # 1. Apply Rule
    res1 = process_anomaly_payload(mock_payload, dry_run=False)
    print(f"Apply Result: {res1}")
    assert res1.get("status") == "APPLIED", f"Status should be APPLIED, got {res1.get('status')}"
    
    # 2. Check iptables Kernel State
    assert check_iptables_rule(TEST_IP_1) is True, f"Kernel iptables rule missing for {TEST_IP_1}"
    print(f"Kernel verification: PASS (Rule actively exists for {TEST_IP_1})")
    
    # 3. Fast-forward time to Mock TTL Expiration
    print("Mocking TTL expiration (fast-forwarding 5 minutes)...")
    records = rule_manager._load_records()
    for r in records:
        if r["target_ip"] == TEST_IP_1:
            r["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    rule_manager._save_records(records)
    
    # 4. Trigger Cleanup
    rule_manager.cleanup_expired_rules(dry_run=False)
    assert check_iptables_rule(TEST_IP_1) is False, f"Kernel iptables rule still exists for {TEST_IP_1} after cleanup!"
    print(f"TTL Cleanup verification: PASS (Rule successfully deleted from live kernel)")
    
    
    TEST_IP_2 = "198.51.100.56"
    print(f"\n--- Test 2: Benign Noise ({TEST_IP_2}) ---")
    benign_payload = {
        "anomaly_grade": 0.15,
        "entity": [{"name": "src_ip", "value": TEST_IP_2}],
        "features": {"distinct_dst_ports": 2}
    }
    res2 = process_anomaly_payload(benign_payload, dry_run=False)
    print(f"Apply Result: {res2}")
    assert res2.get("status") == "NOOP", "Status should be NOOP"
    assert check_iptables_rule(TEST_IP_2) is False, "Benign payload accidentally created an iptables rule!"
    print("Benign verification: PASS")
    
    
    TEST_IP_3 = "172.27.119.1"
    print(f"\n--- Test 3: Full-Stack Adversarial ({TEST_IP_3}) ---")
    adversarial_payload = {
        "anomaly_grade": 1.0,
        "entity": [{"name": "src_ip", "value": TEST_IP_3}],
        "features": {"distinct_dst_ports": 30}
    }
    res3 = process_anomaly_payload(adversarial_payload, dry_run=False)
    print(f"Apply Result: {res3}")
    assert res3.get("status") == "REJECTED", "Should reject protected infrastructure"
    assert check_iptables_rule(TEST_IP_3) is False, "Sandbox failed to protect critical infrastructure!"
    print("Adversarial verification: PASS (Kernel intact, protected IP not blocked)")
    
    print("\nALL LIVE E2E TESTS PASSED!")

if __name__ == "__main__":
    main()
