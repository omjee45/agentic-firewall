import sys
import os
import json
from datetime import datetime, timedelta, timezone

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp_server.server import apply_block_policy
from agent.enforcer import process_anomaly_payload
from mcp_server import rule_manager

def main():
    print("Testing Phase 4 Execution Layer...\n")
    
    # Ensure starting clean
    if os.path.exists(rule_manager.LOG_FILE):
        os.remove(rule_manager.LOG_FILE)
        
    os.environ["DRY_RUN"] = "true"

    # Test 1: Valid Attack in Dry Run
    print("--- Test 1: Valid Attack in Dry Run ---")
    mock_payload = {
        "anomaly_grade": 1.0,
        "entity": [{"name": "src_ip", "value": "10.0.0.51"}],
        "features": {"distinct_dst_ports": 25}
    }
    res1 = process_anomaly_payload(mock_payload, dry_run=True)
    print(f"Result: {res1}")
    assert res1.get("status") == "DRY_RUN", f"Status should be DRY_RUN, got {res1.get('status')}"
    assert res1.get("command") == "iptables -A INPUT -s 10.0.0.51 -j DROP", "Command mismatch"
    assert os.path.exists(rule_manager.LOG_FILE), "Log file was not created"
    print("PASS\n")

    # Test 2: Adversarial Policy Re-Validation
    print("--- Test 2: Adversarial Policy Re-Validation ---")
    bad_policy = 'forbid (principal == Host::"127.0.0.1", action == Action::"Connect", resource == Port::"Any");'
    res2 = apply_block_policy(bad_policy)
    print(f"Result: {res2}")
    assert res2.get("status") == "REJECTED", "Should reject 127.0.0.1"
    print("PASS\n")

    # Test 3: Benign Payload NOOP
    print("--- Test 3: Benign Payload NOOP ---")
    benign_payload = {
        "anomaly_grade": 0.15,
        "entity": [{"name": "src_ip", "value": "10.0.0.52"}],
        "features": {"distinct_dst_ports": 2}
    }
    res3 = process_anomaly_payload(benign_payload, dry_run=True)
    print(f"Result: {res3}")
    assert res3.get("status") == "NOOP", "Status should be NOOP"
    print("PASS\n")

    # Test 4: TTL Expiration Logic
    print("--- Test 4: TTL Expiration Logic ---")
    records = rule_manager._load_records()
    expired_time = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
    records.append({
        "rule_id": "mock-uuid-expired",
        "target_ip": "10.0.0.99",
        "anomaly_id": "mock",
        "applied_at": expired_time,
        "ttl_seconds": 300,
        "expires_at": expired_time,
        "command": "iptables mock",
        "status": "DRY_RUN"
    })
    rule_manager._save_records(records)
    
    expired_ips = rule_manager.cleanup_expired_rules(dry_run=True)
    print(f"Expired IPs cleaned: {expired_ips}")
    assert "10.0.0.99" in expired_ips, "Failed to clean up expired rule"
    
    updated_records = rule_manager._load_records()
    for r in updated_records:
        if r["target_ip"] == "10.0.0.99":
            assert r["status"] == "EXPIRED", "Status was not updated to EXPIRED"
    print("PASS\n")

    print("ALL TESTS PASSED: Execution Layer is ready.")

if __name__ == "__main__":
    main()
