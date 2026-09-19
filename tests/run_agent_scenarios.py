import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.agent import evaluate_anomaly, MODEL_NAME

def map_to_llm_payload(scenario):
    """
    Transforms the flat scenario dict into the 'llm_payload' shape expected by the agent,
    matching what we did in fetch_anomaly.py
    """
    payload = {
        "anomaly_grade": scenario.get("anomaly_grade"),
        "confidence": scenario.get("confidence"),
        "entity": [
            {"name": "src_ip", "value": scenario.get("entity_src_ip")}
        ],
        "features": {
            "distinct_dst_ports": scenario.get("feature_distinct_dst_ports")
        },
        "trigger": scenario.get("trigger", "Unknown")
    }
    
    # Map extra features if present
    if "connection_attempts_per_minute" in scenario:
        payload["features"]["connection_attempts_per_minute"] = scenario["connection_attempts_per_minute"]
    if "feature_distinct_dst_ips" in scenario:
        payload["features"]["distinct_dst_ips"] = scenario["feature_distinct_dst_ips"]
        
    return payload

def main():
    scenarios_path = os.path.join(os.path.dirname(__file__), "agent_test_scenarios.json")
    
    with open(scenarios_path, 'r') as f:
        scenarios = json.load(f)
        
    print(f"Loaded {len(scenarios)} test scenarios. Beginning classification using {MODEL_NAME}...\n")
    
    results_summary = []
    
    for sc in scenarios:
        name = sc["scenario_name"]
        notes = sc["scenario_notes"]
        
        print("="*70)
        print(f"SCENARIO: {name}")
        print(f"NOTES:    {notes}")
        print("="*70)
        
        # Prepare payload (exclude human notes)
        llm_payload = map_to_llm_payload(sc)
        
        print("Input Payload to Agent:")
        print(json.dumps(llm_payload, indent=2))
        print("\nAgent Raw JSON Response:")
        
        # Run agent
        agent_resp = evaluate_anomaly(llm_payload)
        
        if agent_resp:
            print(json.dumps(agent_resp, indent=2))
        else:
            print("FAIL: Agent returned empty or invalid response.")
            agent_resp = {}
            
        print("\n")
        
        # Save for summary table
        threat_type = agent_resp.get("threat_type", "ERROR")
        cedar = agent_resp.get("cedar_policy", "")
        has_cedar = "Yes" if cedar and len(cedar.strip()) > 0 else "No"
        
        results_summary.append({
            "name": name,
            "threat_type": threat_type,
            "has_cedar": has_cedar
        })

    # Summary Table
    print("="*85)
    print(f"{'SCENARIO NAME':<30} | {'THREAT_TYPE':<18} | {'CEDAR POLICY?':<14} | {'HUMAN JUDGMENT':<15}")
    print("-" * 85)
    for res in results_summary:
        print(f"{res['name']:<30} | {res['threat_type']:<18} | {res['has_cedar']:<14} | ")
    print("="*85)
    print("Run complete. Please review the responses for accuracy and fill in HUMAN JUDGMENT.")
    
if __name__ == "__main__":
    main()
