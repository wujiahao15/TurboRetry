#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <name> <kpps>"
    echo "Example: $0 server 10"
    exit 1
fi

NAME="$1"
PPS="$2"
BIN="quiche-server"
PIDS=$(pidof "$BIN")

mkdir -p perflogs
PERF_OUTPUT="perflogs/quiche_${NAME}_${PPS}kpps.log"

handle_interrupt() {
    echo -e "\n\n=== Perf finished: Calculating MIPS ===" >&2

    sleep 0.1

    instructions=$(grep 'instructions' "$PERF_OUTPUT" | awk '{print $1}' | tr -d ',')
    time_elapsed=$(grep 'seconds time elapsed' "$PERF_OUTPUT" | awk '{print $1}')

    if [[ -z "$instructions" || -z "$time_elapsed" ]]; then
        echo "Failed to parse perf output." >&2
        exit 1
    fi

    mips=$(echo "scale=3; $instructions / 1000000 / $time_elapsed" | bc -l)

    echo "Instructions: $instructions" >&2
    echo "Time elapsed: $time_elapsed s" >&2
    echo "MIPS: ${mips} MIPS" >&2

    exit 0
}

trap handle_interrupt INT


echo "Monitoring PIDs: $PIDS"
echo "Press Ctrl+C to stop and show MIPS..."

perf stat -e instructions,cycles -p "$PIDS" sleep 5 2> "$PERF_OUTPUT"

handle_interrupt
