import sys
import os

# Add root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.validator import is_valid_cedar_syntax

def main():
    print("Testing Cedar Semantic Sandbox (Adversarial Testing)...\n")
    
    # Test 1: Valid Target
    test_1 = 'forbid (principal == Host::"10.0.0.51", action == Action::"Connect", resource == Port::"Any");'
    print("--- Test 1: Valid Target (10.0.0.51) ---")
    print(f"Policy: {test_1}")
    res1 = is_valid_cedar_syntax(test_1)
    if res1:
        print("RESULT: PASS (Policy Allowed)\n")
    else:
        print("RESULT: FAIL (Expected True)\n")
        
    # Test 2: Adversarial Localhost
    test_2 = 'forbid (principal == Host::"127.0.0.1", action == Action::"Connect", resource == Port::"Any");'
    print("--- Test 2: Adversarial Localhost (127.0.0.1) ---")
    print(f"Policy: {test_2}")
    res2 = is_valid_cedar_syntax(test_2)
    if not res2:
        print("RESULT: PASS (Successfully Intercepted)\n")
    else:
        print("RESULT: FAIL (Sandbox failed to block!)\n")
        
    # Test 3: Adversarial Gateway
    test_3 = 'forbid (principal == Host::"172.27.119.1", action == Action::"Connect", resource == Port::"Any");'
    print("--- Test 3: Adversarial Gateway (172.27.119.1) ---")
    print(f"Policy: {test_3}")
    res3 = is_valid_cedar_syntax(test_3)
    if not res3:
        print("RESULT: PASS (Successfully Intercepted)\n")
    else:
        print("RESULT: FAIL (Sandbox failed to block!)\n")
        
    if res1 and not res2 and not res3:
        print("\nSUCCESS: All semantic sandbox tests passed. Critical IPs are protected.")
    else:
        print("\nFAILURE: Sandbox failed to intercept malicious policies.")
        sys.exit(1)

if __name__ == "__main__":
    main()
