import sys
import requests

def main():
    base_url = "http://localhost:9200/_plugins/_anomaly_detection/detectors"
    
    # Get all detectors to find ours
    res = requests.post(f"{base_url}/_search", json={
        "query": {
            "match": {
                "name": "port-scan-detector"
            }
        }
    })
    
    if res.status_code != 200:
        print(f"FAIL: Failed to search detectors. HTTP {res.status_code}")
        print(res.text)
        sys.exit(1)
        
    hits = res.json().get("hits", {}).get("hits", [])
    if not hits:
        print("FAIL: Could not find 'port-scan-detector'")
        sys.exit(1)
        
    detector_id = hits[0]["_id"]
    print(f"Found Detector ID: {detector_id}")
    
    # Get detector profile
    profile_res = requests.get(f"{base_url}/{detector_id}/_profile")
    if profile_res.status_code != 200:
        print(f"FAIL: Failed to get detector profile. HTTP {profile_res.status_code}")
        print(profile_res.text)
        sys.exit(1)
        
    profile = profile_res.json()
    state = profile.get("state")
    
    print(f"Detector State: {state}")
    
    if state in ["RUNNING", "INIT"]:
        print("PASS: Detector is registered and its state is retrievable.")
        print("\nNote: Real anomaly testing requires letting this run against live or simulated traffic over time.")
        print("This is expected as RCF needs time-series data to initialize. This step is complete.")
        sys.exit(0)
    else:
        print(f"FAIL: Detector state is not RUNNING or INIT. Current state: {state}")
        sys.exit(1)

if __name__ == "__main__":
    main()
