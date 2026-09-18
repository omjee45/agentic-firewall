import sys
import json
from opensearchpy import OpenSearch

def fetch_latest_anomaly(detector_id="ZY7AtKABEHSa55H-Iqxw"):
    client = OpenSearch(
        hosts=[{"host": "localhost", "port": 9200}],
        use_ssl=False,
        verify_certs=False,
    )
    
    query = {
        "size": 1,
        "sort": [
            {"anomaly_grade": {"order": "desc"}}
        ],
        "query": {
            "bool": {
                "must": [
                    {"term": {"detector_id": detector_id}},
                    {"range": {"anomaly_grade": {"gt": 0}}}
                ]
            }
        }
    }
    
    index_pattern = ".opendistro-anomaly-results*"
    
    try:
        res = client.search(index=index_pattern, body=query)
    except Exception as e:
        print(f"Error querying OpenSearch: {e}")
        sys.exit(1)
        
    hits = res.get("hits", {}).get("hits", [])
    
    if not hits:
        print("No anomalies found yet — run scripts/attack_port_scan.py against 172.27.112.1 and wait ~2 minutes")
        sys.exit(1)
        
    raw_doc = hits[0]["_source"]
    
    # Extract entity src_ip
    entities = raw_doc.get("entity", [])
    src_ip = "UNKNOWN"
    for ent in entities:
        if ent.get("name") == "src_ip":
            src_ip = ent.get("value")
            break
            
    # Extract feature data
    feature_data = raw_doc.get("feature_data", [])
    distinct_dst_ports = 0
    for feat in feature_data:
        if feat.get("feature_id") == "distinct_dst_ports" or feat.get("feature_name") == "distinct_dst_ports":
            distinct_dst_ports = feat.get("data", 0)
            break
    
    # A clean representation to show the user
    clean_anomaly = {
        "detector_id": raw_doc.get("detector_id"),
        "entity_src_ip": src_ip,
        "anomaly_score": raw_doc.get("anomaly_score"),
        "anomaly_grade": raw_doc.get("anomaly_grade"),
        "confidence": raw_doc.get("confidence"),
        "data_start_time": raw_doc.get("data_start_time"),
        "data_end_time": raw_doc.get("data_end_time"),
        "feature_distinct_dst_ports": distinct_dst_ports,
    }
    
    print("--- Fetched Real Anomaly from OpenSearch ---")
    print(json.dumps(clean_anomaly, indent=2))
    print("--------------------------------------------\n")
    
    # Payload format modeled to map well to the prompt rules
    llm_payload = {
        "detector_id": raw_doc.get("detector_id"),
        "anomaly_grade": raw_doc.get("anomaly_grade"),
        "confidence": raw_doc.get("confidence"),
        "entity": [
            {"name": "src_ip", "value": src_ip}
        ],
        "features": {
            "distinct_dst_ports": distinct_dst_ports
        },
        "trigger": "Unusually high number of distinct destination ports accessed" if distinct_dst_ports > 10 else "Unknown anomaly"
    }
    
    return llm_payload
    
if __name__ == "__main__":
    fetch_latest_anomaly()
