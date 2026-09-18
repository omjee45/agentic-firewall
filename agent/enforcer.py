import os
import sys

# Add root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.agent import evaluate_anomaly
from mcp_server.server import apply_block_policy
from mcp_server.rule_manager import cleanup_expired_rules

def process_anomaly_payload(anomaly_dict: dict, dry_run: bool = True) -> dict:
    """
    End-to-end orchestrator mapping OpenSearch payloads directly to firewall enforcement.
    """
    # 1. Evaluate Anomaly to generate draft Cedar Policy
    agent_response = evaluate_anomaly(anomaly_dict)
    
    cedar_policy = agent_response.get("cedar_policy", "")
    anomaly_id = anomaly_dict.get("detector_id", "unknown_detector")
    
    # 2. Set environment correctly
    os.environ["DRY_RUN"] = "true" if dry_run else "false"
    
    # 3. Execute Policy via MCP Tool
    execution_report = apply_block_policy(cedar_policy, anomaly_id=anomaly_id)
    
    # 4. Trigger routine cleanup of expired rules
    expired_ips = cleanup_expired_rules(dry_run=dry_run)
    if expired_ips:
        execution_report["expired_ips_cleaned"] = expired_ips
        
    return execution_report
