#!/usr/bin/env bash
# status.sh — Show status of Suricata + NDR Watcher

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_DIR="$DIR/logs/pids"
LOGS="$DIR/logs"

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo -e "\n${CYAN}━━━ Suricata NDR Status ━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# Suricata
if [[ -f "$PID_DIR/suricata.pid" ]]; then
    PID=$(cat "$PID_DIR/suricata.pid")
    if kill -0 "$PID" 2>/dev/null; then
        echo -e "  Suricata:  ${GREEN}RUNNING${NC} (PID $PID)"
    else
        echo -e "  Suricata:  ${RED}DEAD${NC} (stale PID $PID)"
    fi
else
    echo -e "  Suricata:  ${RED}NOT RUNNING${NC}"
fi

# Watcher
if [[ -f "$PID_DIR/watcher.pid" ]]; then
    PID=$(cat "$PID_DIR/watcher.pid")
    if kill -0 "$PID" 2>/dev/null; then
        echo -e "  Watcher:   ${GREEN}RUNNING${NC} (PID $PID)"
    else
        echo -e "  Watcher:   ${RED}DEAD${NC} (stale PID $PID)"
    fi
else
    echo -e "  Watcher:   ${RED}NOT RUNNING${NC}"
fi

# Interface
IFACE=$(route get default 2>/dev/null | awk '/interface:/{print $2}')
echo -e "  Interface: ${CYAN}${IFACE:-unknown}${NC}"

# Eve log size
if [[ -f "$LOGS/eve.json" ]]; then
    LINES=$(wc -l < "$LOGS/eve.json")
    SIZE=$(du -sh "$LOGS/eve.json" | cut -f1)
    echo -e "  Eve log:   $SIZE ($LINES events)"
fi

# Last watcher activity
if [[ -f "$LOGS/watcher.log" ]]; then
    echo -e "\n  ${YELLOW}Last watcher log entries:${NC}"
    tail -5 "$LOGS/watcher.log" | sed 's/^/    /'
fi

echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
