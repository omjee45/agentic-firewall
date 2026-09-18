import re
import ipaddress

def cedar_to_iptables(cedar_policy: str) -> dict:
    if not cedar_policy or not cedar_policy.strip():
        return {"action": "NONE", "command": []}
        
    # Extract IP from Host::"IP"
    match = re.search(r'Host::"([^"]+)"', cedar_policy)
    if not match:
        raise ValueError("Failed to extract target IP from Cedar policy.")
        
    target_ip = match.group(1)
    
    # Validate IP format
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        raise ValueError(f"Extracted string '{target_ip}' is not a valid IP address.")
        
    apply_command = ["iptables", "-A", "INPUT", "-s", target_ip, "-j", "DROP"]
    revert_command = ["iptables", "-D", "INPUT", "-s", target_ip, "-j", "DROP"]
    
    return {
        "action": "BLOCK",
        "target_ip": target_ip,
        "apply_command": apply_command,
        "revert_command": revert_command
    }
