#!/bin/bash

# Configuration
LOG_FILE="my_app.log"
MAX_LOG_SIZE=$((1024 * 1024)) # 1MB (adjust as needed)
PYTHON_SCRIPT="main.py"
MONITOR_LOG="monitor.log" # Log for the monitoring script itself

# Redirect stdout and stderr of the python script to the log file
python3 "$PYTHON_SCRIPT" > "$LOG_FILE" 2>&1 &

PID=$!

# Redirect monitoring script's output to its own log
(
  while kill -0 $PID 2>/dev/null; do
    LOG_SIZE=$(stat -c%s "$LOG_FILE")

    if [ "$LOG_SIZE" -gt "$MAX_LOG_SIZE" ]; then
      truncate -s 0 "$LOG_FILE"
      echo "$(date) - Log truncated" >> "$LOG_FILE"
    fi

    sleep 60
  done

  echo "$(date) - Process finished" >> "$LOG_FILE"
) > "$MONITOR_LOG" 2>&1 &

echo "Monitoring script started. PID: $!"

