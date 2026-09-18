#!/bin/bash

cd "$(dirname "$0")"

echo "Re-creating index 'network-traffic'..."
curl -s -X DELETE "http://localhost:9200/network-traffic" > /dev/null

RESPONSE=$(curl -s -X PUT "http://localhost:9200/network-traffic" \
  -H "Content-Type: application/json" \
  -d @mapping.json)

echo "Raw response:"
echo "$RESPONSE"

if echo "$RESPONSE" | grep -qi '"acknowledged"[[:space:]]*:[[:space:]]*true'; then
  exit 0
else
  exit 1
fi
