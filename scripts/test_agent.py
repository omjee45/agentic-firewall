import sys
import os
import json

# Add the root directory to sys.path so we can import the agent module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.agent import evaluate_anomaly, MODEL_NAME

def main():
    print("Initializing mock Anomaly Payload from OpenSearch...")
    
    mock_anomaly = {
        "detector_name": "port-scan-detector",
        "timestamp": "2026-09-18T19:30:00Z",
        "anomaly_grade": 0.95,
        "confidence": 0.99,
        "entity": [
            {"name": "src_ip", "value": "192.168.1.105"}
        ],
        "features": {
            "distinct_dst_ports": 25
        },
        "trigger": "Unusually high number of distinct destination ports accessed in 1-minute window."
    }
    
    print(f"\nSending payload to Local Agent ({MODEL_NAME} via Ollama)...")
    print("Please wait, this may take a few moments for local inference.\n")
    
    result = evaluate_anomaly(mock_anomaly)
    
    if not result:
        print("\nFAIL: Agent did not return a valid response.")
        print(f"Tip: Ensure Ollama is running and '{MODEL_NAME}' is pulled.")
        sys.exit(1)
        
    print("--- Agent JSON Response ---")
    print(json.dumps(result, indent=2))
    print("---------------------------\n")
    
    # Simple validation of required fields
    required_keys = ["threat_type", "offending_ip", "cedar_policy"]
    if all(k in result for k in required_keys):
        print("PASS: Agent successfully reasoned over the payload and returned valid structured output containing the Cedar policy.")
    else:
        print(f"FAIL: Agent response is missing required keys. Expected: {required_keys}")
        sys.exit(1)

if __name__ == "__main__":
    main()
