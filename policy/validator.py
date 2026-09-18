import cedarpy

PROTECTED_IPS = ["127.0.0.1", "172.27.119.1"]

def is_valid_cedar_syntax(policy_string: str) -> bool:
    """
    Validates AWS Cedar policy syntax AND performs semantic authorization 
    to ensure protected infrastructure is never blocked.
    Returns True if the policy is valid, safe, or empty (benign).
    Returns False if there are syntax errors or if the policy blocks protected IPs.
    """
    if not policy_string or not policy_string.strip():
        return True
        
    # 1. Syntax Verification
    try:
        cedarpy.format_policies(policy_string)
    except Exception as e:
        print(f"Cedar Syntax Validation Failed: {e}")
        return False

    eval_policy = f"permit(principal, action, resource);\n{policy_string}"
    
    for ip in PROTECTED_IPS:
        request = {
            "principal": {"type": "Host", "id": ip},
            "action": {"type": "Action", "id": "Connect"},
            "resource": {"type": "Port", "id": "Any"}
        }
        
        try:
            authz_result = cedarpy.is_authorized(request, eval_policy, entities=[])
            
            if "Deny" in str(authz_result.decision):
                print(f"SEVERE WARNING: Agent drafted a policy that blocks protected infrastructure ({ip})! Intercepting.")
                return False
                
        except Exception as e:
            print(f"Cedar Semantic Evaluation Failed: {e}")
            return False
            
    return True
