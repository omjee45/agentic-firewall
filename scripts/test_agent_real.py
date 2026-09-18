import sys
import os
import json

# Add the root directory to sys.path so we can import the agent module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.fetch_anomaly import fetch_latest_anomaly
from agent.agent import evaluate_anomaly, MODEL_NAME

def main():
    print("Fetching real anomaly payload from OpenSearch...")
    real_anomaly = fetch_latest_anomaly()
    
    print(f"Sending real payload to Local Agent ({MODEL_NAME} via Ollama)...")
    print("Running consistency check (3 classifications on the same payload).")
    print("Please wait...\n")
    
    results = []
    for i in range(3):
        print(f"--- Running classification pass {i+1}/3 ---")
        result = evaluate_anomaly(real_anomaly)
        results.append(result)
    
    print("\n\n===========================================")
    print("      CONSISTENCY CHECK RESULTS (3 RUNS)   ")
    print("===========================================")
    
    for i, res in enumerate(results):
        print(f"\n[RUN {i+1}]")
        if res:
            print(json.dumps(res, indent=2))
        else:
            print("FAIL: Agent did not return a valid response.")
        
    print("\n===========================================\n")
    print("Please review the outputs above for consistency.")
    
    # Assert acceptance criteria 
    offending_ip_matches = [res.get("offending_ip") for res in results if res]
    print(f"\nExtracted IPs across 3 runs: {offending_ip_matches}")

if __name__ == "__main__":
    main()
