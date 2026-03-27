#!/usr/bin/env bash
# stop.sh — Stops Suricata + NDR Watcher

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$DIR/logs/pids"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

stopped=0

if [[ -f "$PID_DIR/watcher.pid" ]]; then
    PID=$(cat "$PID_DIR/watcher.pid")
    kill "$PID" 2>/dev/null && echo -e "${GREEN}[OK]${NC} Stopped NDR watcher (PID $PID)"
    rm -f "$PID_DIR/watcher.pid"
    stopped=$((stopped+1))
fi

if [[ -f "$PID_DIR/suricata.pid" ]]; then
    PID=$(cat "$PID_DIR/suricata.pid")
    sudo kill "$PID" 2>/dev/null && echo -e "${GREEN}[OK]${NC} Stopped Suricata (PID $PID)"
    rm -f "$PID_DIR/suricata.pid"
    stopped=$((stopped+1))
fi

if [[ $stopped -eq 0 ]]; then
    echo -e "${YELLOW}[WARN]${NC} No running processes found"
else
    echo -e "${GREEN}Done.${NC}"
fi
