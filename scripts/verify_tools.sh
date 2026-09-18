#!/bin/bash
# Verification commands for standalone tools

echo "=== Verifying OpenSearch ==="
curl -s -X GET http://localhost:9200/ | grep -i '"cluster_name"\|"version"'

echo -e "\n=== Verifying Ollama ==="
curl -s -X GET http://localhost:11434/api/tags | grep -i '"models"'

echo -e "\n=== Verifying Python Dependencies ==="
python3 -c "import scapy, opensearchpy, cedarpy, mcp; print('Python dependencies loaded successfully.')"

echo -e "\n=== Verifying iptables (requires sudo) ==="
sudo iptables -L -n | head -n 3
