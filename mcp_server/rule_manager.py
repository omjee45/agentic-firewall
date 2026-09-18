import os
import json
import uuid
import subprocess
from datetime import datetime, timedelta, timezone

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "applied_rules.json")

def _load_records():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

def _save_records(records):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "w") as f:
        json.dump(records, f, indent=2)

def record_rule(target_ip, anomaly_id, command, ttl_seconds, dry_run=False) -> dict:
    records = _load_records()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=ttl_seconds)
    
    record = {
        "rule_id": str(uuid.uuid4()),
        "target_ip": target_ip,
        "anomaly_id": anomaly_id,
        "applied_at": now.isoformat(),
        "ttl_seconds": ttl_seconds,
        "expires_at": expires.isoformat(),
        "command": command,
        "status": "DRY_RUN" if dry_run else "ACTIVE"
    }
    
    records.append(record)
    _save_records(records)
    return record

def get_active_rule(target_ip) -> dict | None:
    records = _load_records()
    now = datetime.now(timezone.utc)
    
    for r in records:
        if r.get("target_ip") == target_ip and r.get("status") in ["ACTIVE", "DRY_RUN"]:
            try:
                expires = datetime.fromisoformat(r["expires_at"])
                if now < expires:
                    return r
            except ValueError:
                pass
    return None

def cleanup_expired_rules(dry_run=False) -> list[str]:
    records = _load_records()
    now = datetime.now(timezone.utc)
    expired_ips = []
    
    changed = False
    for r in records:
        if r.get("status") in ["ACTIVE", "DRY_RUN"]:
            try:
                expires = datetime.fromisoformat(r["expires_at"])
            except ValueError:
                continue
                
            if now >= expires:
                changed = True
                expired_ips.append(r["target_ip"])
                
                # Execute revert command for real if it was ACTIVE
                if r.get("status") == "ACTIVE" and not dry_run:
                    try:
                        revert_cmd = ["iptables", "-D", "INPUT", "-s", r["target_ip"], "-j", "DROP"]
                        subprocess.run(revert_cmd, check=True)
                    except Exception as e:
                        print(f"Failed to revert iptables rule for {r['target_ip']}: {e}")
                
                # Always update state
                r["status"] = "EXPIRED"
                    
    if changed:
        _save_records(records)
        
    return expired_ips
