#!/bin/bash
cd "$(dirname "$0")"

echo "Creating Anomaly Detector..."
CREATE_RES=$(curl -s -X POST "http://localhost:9200/_plugins/_anomaly_detection/detectors" \
  -H "Content-Type: application/json" \
  -d @rcf_detector.json)

echo "Raw Create Response:"
echo "$CREATE_RES"

DETECTOR_ID=$(python3 -c "import sys, json; print(json.loads(sys.argv[1]).get('_id', ''))" "$CREATE_RES")

if [ -z "$DETECTOR_ID" ]; then
    echo "Failed to get detector_id. Exiting."
    exit 1
fi

echo "Created Detector ID: $DETECTOR_ID"
echo "Starting Anomaly Detector..."

START_RES=$(curl -s -X POST "http://localhost:9200/_plugins/_anomaly_detection/detectors/$DETECTOR_ID/_start")

echo "Raw Start Response:"
echo "$START_RES"

HAS_ERROR=$(python3 -c "import sys, json; print('error' in json.loads(sys.argv[1]))" "$START_RES")

if [ "$HAS_ERROR" = "True" ]; then
    echo "Failed to start detector. Exiting."
    exit 1
fi

echo "Detector started successfully!"
exit 0
