#!/usr/bin/env bash
# vds.sh — manage onion relay nodes on VDS (80.93.52.15)
#
# Usage:
#   ./scripts/vds.sh deploy          -- sync code + restart all relays
#   ./scripts/vds.sh start           -- start relays (Guard/Middle/Exit)
#   ./scripts/vds.sh stop            -- kill all relay processes
#   ./scripts/vds.sh status          -- show process list + API status
#   ./scripts/vds.sh logs [name]     -- tail logs (Guard/Middle/Exit/VpnExit, or all)
#   ./scripts/vds.sh vpn-start       -- start VPN exit node on port 9010
#   ./scripts/vds.sh vpn-stop        -- kill VPN exit node
#   ./scripts/vds.sh vpn-deploy      -- deploy vpn_onion.py + (re)start VPN exit
#   ./scripts/vds.sh ssh             -- open interactive shell on VDS

set -euo pipefail

VDS_HOST="80.93.52.15"
VDS_USER="root"
VDS_KEY="${VDS_KEY:-D:/kai/02_System/vds_key}"
REMOTE_DIR="/opt/murnet"
LOG_DIR="/var/log/murnet"

SSH="ssh -i $VDS_KEY -o StrictHostKeyChecking=no $VDS_USER@$VDS_HOST"
SCP="scp -i $VDS_KEY -o StrictHostKeyChecking=no"

# Relay definitions: name bind_port api_port
RELAYS=(
    "Guard  9001 8081"
    "Middle 9002 8082"
    "Exit   9003 8083"
)

# ── helpers ───────────────────────────────────────────────────────────────────

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "  >> $*"; }

remote() { $SSH "$@"; }

relay_start_cmd() {
    local name=$1 port=$2 api_port=$3
    echo "cd $REMOTE_DIR && setsid python demos/onion_node.py" \
         "--bind 0.0.0.0:${port} --name ${name}" \
         "--api-port ${api_port} --log WARNING" \
         "> $LOG_DIR/${name}.log 2>&1 </dev/null &"
}

# ── commands ──────────────────────────────────────────────────────────────────

cmd_deploy() {
    info "Syncing code to $VDS_USER@$VDS_HOST:$REMOTE_DIR ..."

    # Ensure remote dirs exist
    remote "mkdir -p $REMOTE_DIR/core/onion $REMOTE_DIR/api $REMOTE_DIR/demos $LOG_DIR"

    # Sync core onion files
    $SCP core/onion/*.py    "$VDS_USER@$VDS_HOST:$REMOTE_DIR/core/onion/"
    $SCP core/__init__.py   "$VDS_USER@$VDS_HOST:$REMOTE_DIR/core/"  2>/dev/null || true
    $SCP core/onion/__init__.py "$VDS_USER@$VDS_HOST:$REMOTE_DIR/core/onion/" 2>/dev/null || true

    # Sync API (onion_api only — no full node dependency)
    $SCP api/onion_api.py   "$VDS_USER@$VDS_HOST:$REMOTE_DIR/api/"
    remote "touch $REMOTE_DIR/api/__init__.py"

    # Sync demos
    $SCP demos/onion_node.py "$VDS_USER@$VDS_HOST:$REMOTE_DIR/demos/"

    info "Code synced. Restarting relays..."
    cmd_stop  2>/dev/null || true
    sleep 1
    cmd_start
}

cmd_start() {
    info "Starting relay nodes on VDS..."
    for relay in "${RELAYS[@]}"; do
        read -r name port api_port <<< "$relay"
        cmd=$(relay_start_cmd "$name" "$port" "$api_port")
        remote "bash -c '$cmd'"
        info "  $name  onion=:$port  api=:$api_port"
    done
    sleep 1
    cmd_status
}

cmd_stop() {
    info "Stopping relay nodes..."
    remote "pkill -f 'onion_node.py' 2>/dev/null; echo stopped" || true
}

cmd_status() {
    echo ""
    echo "=== Processes ==="
    remote "pgrep -a -f onion_node.py 2>/dev/null || echo '  (none running)'"

    echo ""
    echo "=== Relay API health ==="
    for relay in "${RELAYS[@]}"; do
        read -r name _port api_port <<< "$relay"
        url="http://$VDS_HOST:$api_port/api/status"
        result=$(curl -sf --max-time 3 "$url" 2>/dev/null || echo '{"error":"unreachable"}')
        echo "  $name ($url)"
        echo "    $result"
    done
}

cmd_logs() {
    local name="${1:-}"
    if [[ -n "$name" ]]; then
        remote "tail -f $LOG_DIR/${name}.log"
    else
        remote "tail -f $LOG_DIR/Guard.log $LOG_DIR/Middle.log $LOG_DIR/Exit.log $LOG_DIR/VpnExit.log 2>/dev/null"
    fi
}

cmd_ssh() {
    $SSH
}

cmd_vpn_start() {
    info "Starting VPN exit node on :9010 ..."
    remote "bash -c 'cd $REMOTE_DIR && setsid python demos/vpn_onion.py \
        --mode exit --bind 0.0.0.0:9010 --name VpnExit --log WARNING \
        > $LOG_DIR/VpnExit.log 2>&1 </dev/null &'"
    sleep 1
    info "VPN exit started."
    remote "pgrep -a -f vpn_onion.py 2>/dev/null || echo '  (not found)'"
}

cmd_vpn_stop() {
    info "Stopping VPN exit node..."
    remote "pkill -f 'vpn_onion.py' 2>/dev/null; echo stopped" || true
}

cmd_vpn_deploy() {
    info "Deploying vpn_onion.py to VDS..."
    $SCP demos/vpn_onion.py "$VDS_USER@$VDS_HOST:$REMOTE_DIR/demos/"
    cmd_vpn_stop 2>/dev/null || true
    sleep 1
    cmd_vpn_start
    echo ""
    echo "VPN exit running on $VDS_HOST:9010"
    echo ""
    echo "Connect locally:"
    echo "  python demos/vpn_onion.py --mode client \\"
    echo "      --peer Guard=$VDS_HOST:9001 \\"
    echo "      --peer Middle=$VDS_HOST:9002 \\"
    echo "      --peer VpnExit=$VDS_HOST:9010 \\"
    echo "      --circuit Guard,Middle,VpnExit \\"
    echo "      --socks 127.0.0.1:1080"
}

# ── dispatch ──────────────────────────────────────────────────────────────────

CMD="${1:-help}"
shift || true

case "$CMD" in
    deploy)     cmd_deploy ;;
    start)      cmd_start  ;;
    stop)       cmd_stop   ;;
    status)     cmd_status ;;
    logs)       cmd_logs "${1:-}" ;;
    vpn-start)  cmd_vpn_start ;;
    vpn-stop)   cmd_vpn_stop  ;;
    vpn-deploy) cmd_vpn_deploy ;;
    ssh)        cmd_ssh    ;;
    help|--help|-h)
        grep '^#' "$0" | head -15 | sed 's/^# //'
        ;;
    *)
        die "Unknown command: $CMD. Use deploy|start|stop|status|logs|vpn-start|vpn-stop|vpn-deploy|ssh"
        ;;
esac
