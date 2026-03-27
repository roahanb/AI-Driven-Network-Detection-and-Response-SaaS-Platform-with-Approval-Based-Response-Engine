#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
# start.sh — Starts Suricata + NDR Watcher
# Usage: ./start.sh [NDR_API_URL] [JWT_TOKEN]
# ─────────────────────────────────────────────────────────

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="$DIR/logs"
PID_DIR="$LOGS/pids"
mkdir -p "$LOGS" "$PID_DIR"

NDR_API="${1:-http://localhost:8000}"
JWT_TOKEN="${2:-}"

# ── Colour output ──────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[NDR]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

# ── Detect active network interface ───────────────────
IFACE=$(route get default 2>/dev/null | awk '/interface:/{print $2}')
IFACE="${IFACE:-en0}"
info "Active interface: $IFACE"

# ── Check Suricata ─────────────────────────────────────
SURICATA_BIN=$(command -v suricata 2>/dev/null \
    || command -v /opt/homebrew/bin/suricata 2>/dev/null \
    || command -v /usr/local/bin/suricata 2>/dev/null \
    || echo "")
if [[ -z "$SURICATA_BIN" ]]; then
    err "Suricata not found. Install it first:\n\n  brew install suricata\n  suricata-update\n"
fi
ok "Suricata found: $SURICATA_BIN"

# ── Get JWT token if not provided ─────────────────────
if [[ -z "$JWT_TOKEN" ]]; then
    echo ""
    info "No JWT token provided. Fetching from NDR platform..."
    read -rp "  NDR email:    " NDR_EMAIL
    read -rsp "  NDR password: " NDR_PASS
    echo ""

    RESPONSE=$(curl -s -X POST "${NDR_API}/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"${NDR_EMAIL}\",\"password\":\"${NDR_PASS}\"}" 2>/dev/null)

    JWT_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null || echo "")

    if [[ -z "$JWT_TOKEN" ]]; then
        err "Login failed. Check credentials or start the NDR backend first."
    fi
    ok "Authenticated successfully"
fi

# Save token for watcher restarts
echo "$JWT_TOKEN" > "$PID_DIR/.token"

# ── Kill any existing processes ────────────────────────
if [[ -f "$PID_DIR/suricata.pid" ]]; then
    OLD_PID=$(cat "$PID_DIR/suricata.pid")
    kill "$OLD_PID" 2>/dev/null && warn "Stopped existing Suricata (PID $OLD_PID)"
    rm -f "$PID_DIR/suricata.pid"
fi
if [[ -f "$PID_DIR/watcher.pid" ]]; then
    OLD_PID=$(cat "$PID_DIR/watcher.pid")
    kill "$OLD_PID" 2>/dev/null && warn "Stopped existing watcher (PID $OLD_PID)"
    rm -f "$PID_DIR/watcher.pid"
fi

# ── Update Suricata rules ──────────────────────────────
info "Updating Suricata rules (ET Open)..."
SURICATA_UPDATE=$(command -v suricata-update 2>/dev/null || command -v /opt/homebrew/bin/suricata-update 2>/dev/null || echo "")
if [[ -n "$SURICATA_UPDATE" ]]; then
    "$SURICATA_UPDATE" --suricata-conf "$DIR/suricata-ndr.yaml" \
        --output "$DIR/rules" \
        --no-test 2>&1 | tail -5 || warn "Rule update failed, using existing rules"
else
    warn "suricata-update not found, skipping rule update"
fi

# ── Find classification/reference config ──────────────
SURICATA_SHARE=$(find /usr/local/share /opt/homebrew/share 2>/dev/null -name "classification.config" | head -1 | xargs dirname 2>/dev/null || echo "")
if [[ -n "$SURICATA_SHARE" ]]; then
    EXTRA_CONF="--set classification-file=$SURICATA_SHARE/classification.config \
                --set reference-config-file=$SURICATA_SHARE/reference.config"
else
    EXTRA_CONF=""
fi

# ── Start Suricata ─────────────────────────────────────
info "Starting Suricata on interface $IFACE..."
sudo "$SURICATA_BIN" \
    -c "$DIR/suricata-ndr.yaml" \
    -i "$IFACE" \
    --set "default-log-dir=$LOGS" \
    $EXTRA_CONF \
    -D --pidfile "$PID_DIR/suricata.pid" \
    2>>"$LOGS/suricata-start.log"

# Wait for Suricata to create the PID file
WAIT=0
while [[ ! -f "$PID_DIR/suricata.pid" && $WAIT -lt 10 ]]; do
    sleep 1; WAIT=$((WAIT+1))
done

if [[ ! -f "$PID_DIR/suricata.pid" ]]; then
    err "Suricata failed to start. Check $LOGS/suricata.log"
fi

SURICATA_PID=$(cat "$PID_DIR/suricata.pid")
ok "Suricata running (PID $SURICATA_PID) | Logs: $LOGS/eve.json"

# Wait for eve.json to appear
info "Waiting for Suricata to initialise..."
WAIT=0
while [[ ! -f "$LOGS/eve.json" && $WAIT -lt 20 ]]; do
    sleep 1; WAIT=$((WAIT+1))
    echo -n "."
done
echo ""

# ── Start NDR watcher ──────────────────────────────────
info "Starting NDR watcher → $NDR_API"
nohup python3 "$DIR/ndr_watcher.py" \
    --api "$NDR_API" \
    --token "$JWT_TOKEN" \
    >> "$LOGS/watcher.log" 2>&1 &
WATCHER_PID=$!
echo "$WATCHER_PID" > "$PID_DIR/watcher.pid"
ok "NDR watcher running (PID $WATCHER_PID)"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Suricata + NDR Watcher ACTIVE${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Interface:  ${CYAN}$IFACE${NC}"
echo -e "  NDR API:    ${CYAN}$NDR_API${NC}"
echo -e "  Eve log:    $LOGS/eve.json"
echo -e "  Watcher:    $LOGS/watcher.log"
echo -e ""
echo -e "  To stop:    ${YELLOW}./stop.sh${NC}"
echo -e "  Live logs:  ${YELLOW}tail -f $LOGS/watcher.log${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
