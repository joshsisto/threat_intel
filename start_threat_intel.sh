#!/bin/bash

PYTHON_SCRIPT="main.py"
LOG_FILE="threat_intel.log"

# Redirect stdout and stderr of the python script to the log file
python3 "$PYTHON_SCRIPT" > "$LOG_FILE" 2>&1 &

echo "Application started. Output is in $LOG_FILE. PID: $!"
