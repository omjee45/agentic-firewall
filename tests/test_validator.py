import sys
import os

# Add root to sys.path to import policy module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy.validator import is_valid_cedar_syntax

def main():
    print("Testing Cedar Policy Validator Sandbox...\n")
    
    # Test 1: Valid Cedar Syntax
    valid_str = 'forbid (principal == Host::"10.0.0.51", action == Action::"Connect", resource == Port::"Any");'
    print("--- Test 1: Valid Policy ---")
    print(f"Policy: {valid_str}")
    res1 = is_valid_cedar_syntax(valid_str)
    if res1:
        print("RESULT: PASS\n")
    else:
        print("RESULT: FAIL (Expected True)\n")
        
    # Test 2: Invalid Hallucinated Syntax
    invalid_str = 'deny ip 10.0.0.51 from accessing any port'
    print("--- Test 2: Invalid/Hallucinated Policy ---")
    print(f"Policy: {invalid_str}")
    res2 = is_valid_cedar_syntax(invalid_str)
    if not res2:
        print("RESULT: PASS\n")
    else:
        print("RESULT: FAIL (Expected False)\n")
        
    # Test 3: Empty String (Benign)
    empty_str = ""
    print("--- Test 3: Empty Policy (BENIGN) ---")
    print(f"Policy: '{empty_str}'")
    res3 = is_valid_cedar_syntax(empty_str)
    if res3:
        print("RESULT: PASS\n")
    else:
        print("RESULT: FAIL (Expected True)\n")
        
    if res1 and not res2 and res3:
        print("\nSUCCESS: All validator tests passed. Sandbox is ready.")
    else:
        print("\nFAILURE: One or more validator tests failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
