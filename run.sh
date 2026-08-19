#!/bin/bash

PID_FILE="/tmp/onecf_loop.pid"

if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    exit 0
fi

nohup bash -c '
while true
do
    python3 onecf.py >/dev/null 2>&1
    sleep 60
done
' >/dev/null 2>&1 &

echo $! > "$PID_FILE"