import json
import requests
try:
    from agent.prompts import SYSTEM_PROMPT, RESPONSE_SCHEMA
except ImportError:
    from prompts import SYSTEM_PROMPT, RESPONSE_SCHEMA

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL_NAME = "llama3.2:1b"

def evaluate_anomaly(anomaly_json: dict) -> dict:
    """
    Passes the anomaly payload to the local Ollama agent and returns parsed JSON.
    Acts as a standard LLM library wrapper since AWS Strands Agents SDK may not be 
    locally installed or supported in this air-gapped WSL config.
    """
    
    actual_src_ip = None
    for ent in anomaly_json.get("entity", []):
        if ent.get("name") == "src_ip":
            actual_src_ip = ent.get("value")
            break
            
    anomaly_grade = anomaly_json.get("anomaly_grade", 0.0)
    if anomaly_grade < 0.5:
        return {
            "threat_type": "BENIGN",
            "offending_ip": actual_src_ip,
            "cedar_policy": ""
        }
            
    user_message = f"Analyze the following anomaly payload:\n{json.dumps(anomaly_json, indent=2)}"
    
    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message}
        ],
        "format": "json",  # Forces strict JSON output from Ollama
        "stream": False,
        "options": {
            "temperature": 0.1 # Low temp for deterministic logic output
        }
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=60)
        
        if response.status_code == 404:
            print(f"Error 404: Model '{MODEL_NAME}' might not be pulled in Ollama.")
            return {}
            
        response.raise_for_status()
        
        result = response.json()
        message_content = result.get("message", {}).get("content", "{}")
        
        structured_output = json.loads(message_content)
        
        # Code-level safety check for hallucinated IP
        agent_ip = structured_output.get("offending_ip")
        if actual_src_ip and agent_ip != actual_src_ip:
            print(f"WARNING: Agent hallucinated IP: expected {actual_src_ip}, got {agent_ip}. Overriding with correct value.")
            structured_output["offending_ip"] = actual_src_ip
            
            # Regenerate cedar policy with corrected IP if a policy was generated
            cedar = structured_output.get("cedar_policy", "")
            if cedar and agent_ip and agent_ip in cedar:
                structured_output["cedar_policy"] = cedar.replace(agent_ip, actual_src_ip)
            elif cedar and "<EXTRACTED_IP_HERE>" in cedar:
                structured_output["cedar_policy"] = cedar.replace("<EXTRACTED_IP_HERE>", actual_src_ip)
                
        if structured_output.get("threat_type") == "BENIGN" and structured_output.get("cedar_policy"):
            print("WARNING: Agent drafted a block policy for a BENIGN threat. Overriding cedar_policy to empty string.")
            structured_output["cedar_policy"] = ""
            
        return structured_output
        
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Ollama: {e}")
        return {}
    except json.JSONDecodeError as e:
        print(f"Agent failed to return valid JSON: {e}")
        print(f"Raw output was: {message_content}")
        return {}
