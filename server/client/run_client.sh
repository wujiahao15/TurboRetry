#!/usr/bin/env bash

for arg in "$@"; do
    if [[ $arg == --tag=* ]]; then
        TAG="${arg#--tag=}"
    elif [[ $arg == --impl=* ]]; then
        IMP="${arg#--impl=}"
    else
        echo "Unknown args: $arg"
        exit 1
    fi
done

echo "${IMP}-${TAG}"

# Check if arguments are provided
if [[ -z "$TAG" ]]; then
    echo "Error: --tag argument is required"
    exit 1
fi
if [[ -z "$IMP" ]]; then
    echo "Error: --impl argument is required"
    exit 1
fi

# Set target URL
URL="<your domain name>:<your server port>"
REQ_SEQ=0

# Generate current time string, format YYYYMMDD-HHMMSS
START_TIME=$(date +"%Y%m%d-%H%M%S")
RESULT_DIR="results/${IMP}-${TAG}-${START_TIME}"

# Create directory
mkdir -p "$RESULT_DIR"
echo "Create results directory: $RESULT_DIR"

max_runs=60 # Maximum number of runs
run_count=0 # Current run count

while true; do
    # If run count reaches the limit, exit the loop
    if (( run_count >= max_runs )); then
        break
    fi

    # Run the script to send QUIC requests
    python benign_client_v2.py "$URL" --measurement-path "$RESULT_DIR/$REQ_SEQ.parquet" &

    # Increment sequence number after each request
    ((REQ_SEQ++))

    # Increment run count
    ((run_count++))

    sleep 1
done

sleep 3
echo "Maximum run count ($max_runs) reached, script exiting"
