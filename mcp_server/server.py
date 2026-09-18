import os
import sys
import subprocess

# Add root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.validator import is_valid_cedar_syntax
from policy.translator import cedar_to_iptables
from mcp_server import rule_manager

def apply_block_policy(cedar_policy: str, anomaly_id: str = None, ttl_seconds: int = 300) -> dict:
    """
    MCP tool to apply a cedar policy as an iptables rule safely.
    """
    # Step A: Internal Re-Validation (Never trust the upstream prompt)
    if not is_valid_cedar_syntax(cedar_policy):
        return {"status": "REJECTED", "reason": "Failed internal Cedar sandbox validation"}
        
    # Step B: Translation
    try:
        translation = cedar_to_iptables(cedar_policy)
    except ValueError as e:
        return {"status": "REJECTED", "reason": str(e)}
        
    if translation.get("action") == "NONE":
        return {"status": "NOOP", "reason": "No policy to enforce"}
        
    target_ip = translation["target_ip"]
    apply_cmd = translation["apply_command"]
    cmd_str = " ".join(apply_cmd)
    
    # Step C: Idempotency Check
    active_rule = rule_manager.get_active_rule(target_ip)
    if active_rule:
        return {"status": "EXISTS", "ip": target_ip, "message": "Rule already active with unexpired TTL"}
        
    # Step D: Dry-Run Check
    dry_run_env = os.environ.get("DRY_RUN", "true").lower()
    is_dry_run = dry_run_env == "true"
    
    if is_dry_run:
        print(f"[DRY RUN] Would execute: {cmd_str} (TTL: {ttl_seconds}s)")
        rule_manager.record_rule(target_ip, anomaly_id, cmd_str, ttl_seconds, dry_run=True)
        return {"status": "DRY_RUN", "ip": target_ip, "command": cmd_str, "ttl_seconds": ttl_seconds}
    else:
        try:
            subprocess.run(apply_cmd, check=True)
            rule_manager.record_rule(target_ip, anomaly_id, cmd_str, ttl_seconds, dry_run=False)
            return {"status": "APPLIED", "ip": target_ip, "command": cmd_str, "ttl_seconds": ttl_seconds}
        except subprocess.CalledProcessError as e:
            return {"status": "ERROR", "reason": f"Failed to execute iptables: {e}"}
