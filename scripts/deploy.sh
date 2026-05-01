#!/usr/bin/env bash
# Murnet VDS Deployment Script
# Usage: sudo ./deploy.sh [--repo <url>] [--branch <name>] [--dir <path>]
set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
REPO_URL="${MURNET_REPO:-https://github.com/your-org/murnet.git}"
BRANCH="${MURNET_BRANCH:-main}"
INSTALL_DIR="${MURNET_DIR:-/opt/murnet}"
DATA_DIR="${MURNET_DATA:-/var/lib/murnet}"
LOG_DIR="/var/log/murnet"
VENV_DIR="$INSTALL_DIR/venv"
SERVICE_NAME="murnet"
MURNET_USER="murnet"

# ── Colour helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── CLI argument parsing ─────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo)   REPO_URL="$2"; shift 2 ;;
        --branch) BRANCH="$2";   shift 2 ;;
        --dir)    INSTALL_DIR="$2"; VENV_DIR="$INSTALL_DIR/venv"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--repo URL] [--branch NAME] [--dir PATH]"
            exit 0 ;;
        *) error "Unknown option: $1" ;;
    esac
done

# ── Step 1: Requirement checks ───────────────────────────────────────────────
info "Checking requirements..."

check_python() {
    local py_bin
    for bin in python3.12 python3.11 python3; do
        py_bin=$(command -v "$bin" 2>/dev/null) && break
    done
    [[ -z "${py_bin:-}" ]] && error "Python 3.11+ not found. Install it first."

    local version
    version=$("$py_bin" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)
    if [[ "$major" -lt 3 || ( "$major" -eq 3 && "$minor" -lt 11 ) ]]; then
        error "Python 3.11+ required (found $version). Install a newer version."
    fi
    success "Python $version found at $py_bin"
    PYTHON_BIN="$py_bin"
}

check_python

command -v pip3 &>/dev/null || error "pip3 not found. Install python3-pip."
success "pip3 found"

command -v git &>/dev/null || error "git not found. Install git."
success "git found"

# ── Step 2: Create system user ───────────────────────────────────────────────
info "Setting up system user '$MURNET_USER'..."
if ! id "$MURNET_USER" &>/dev/null; then
    useradd --system --shell /usr/sbin/nologin --home-dir "$INSTALL_DIR" \
            --create-home "$MURNET_USER"
    success "Created user '$MURNET_USER'"
else
    success "User '$MURNET_USER' already exists"
fi

# ── Step 3: Create directories ───────────────────────────────────────────────
info "Creating directories..."
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
chown -R "$MURNET_USER:$MURNET_USER" "$DATA_DIR" "$LOG_DIR"
success "Directories ready"

# ── Step 4: Clone or pull latest code ────────────────────────────────────────
info "Syncing source code (branch: $BRANCH)..."
if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Existing repo found — pulling latest..."
    git -C "$INSTALL_DIR" fetch origin
    git -C "$INSTALL_DIR" checkout "$BRANCH"
    git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
    success "Pulled latest code"
else
    info "Cloning from $REPO_URL..."
    # If INSTALL_DIR already has files (e.g. local dev), copy instead of clone
    if [[ -f "$INSTALL_DIR/requirements.txt" && ! -d "$INSTALL_DIR/.git" ]]; then
        warn "Directory exists without .git — skipping clone, using existing files"
    else
        git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$INSTALL_DIR"
        success "Cloned repository"
    fi
fi

chown -R "$MURNET_USER:$MURNET_USER" "$INSTALL_DIR"

# ── Step 5: Virtualenv ───────────────────────────────────────────────────────
info "Setting up Python virtualenv at $VENV_DIR..."
if [[ ! -d "$VENV_DIR" ]]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    success "Virtualenv created"
else
    success "Virtualenv already exists"
fi

# ── Step 6: Install dependencies ─────────────────────────────────────────────
info "Installing Python requirements..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
success "Requirements installed"

# ── Step 7: Database migrations ──────────────────────────────────────────────
info "Running database migrations..."
PYTHONPATH="$INSTALL_DIR" "$VENV_DIR/bin/python" - <<'PYEOF'
import sqlite3, os, sys
sys.path.insert(0, os.environ.get("PYTHONPATH", "."))
from core.migrations import migrate

data_dir = os.environ.get("MURNET_DATA", "/var/lib/murnet")
db_path  = os.path.join(data_dir, "murnet.db")
os.makedirs(data_dir, exist_ok=True)

conn = sqlite3.connect(db_path, isolation_level=None)
try:
    new_ver = migrate(conn)
    print(f"  Migrations complete — schema version {new_ver}")
finally:
    conn.close()
PYEOF
success "Migrations complete"

# ── Step 8: Systemd service ───────────────────────────────────────────────────
info "Installing systemd service..."

# Generate service file from vds/systemd.py if not already on disk
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
if [[ ! -f "$SERVICE_FILE" ]]; then
    PYTHONPATH="$INSTALL_DIR" "$PYTHON_BIN" -c "
from vds.systemd import SYSTEMD_SERVICE
with open('$SERVICE_FILE', 'w') as f:
    f.write(SYSTEMD_SERVICE.strip())
print('Service file written to $SERVICE_FILE')
"
    success "Service file installed at $SERVICE_FILE"
else
    # Refresh in case it changed
    PYTHONPATH="$INSTALL_DIR" "$PYTHON_BIN" -c "
from vds.systemd import SYSTEMD_SERVICE
with open('$SERVICE_FILE', 'w') as f:
    f.write(SYSTEMD_SERVICE.strip())
" 2>/dev/null && success "Service file refreshed" || warn "Could not refresh service file"
fi

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
success "Service enabled"

# ── Step 9: Start / restart service ──────────────────────────────────────────
info "Starting $SERVICE_NAME service..."
if systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl restart "$SERVICE_NAME"
    success "Service restarted"
else
    systemctl start "$SERVICE_NAME"
    success "Service started"
fi

# ── Step 10: Final status ─────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────"
success "Murnet deployment complete!"
echo ""
systemctl status "$SERVICE_NAME" --no-pager --lines=5 || true
echo ""
echo "  Logs:    journalctl -u $SERVICE_NAME -f"
echo "  API:     http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1):8080"
echo "  Data:    $DATA_DIR"
echo "────────────────────────────────────────────"
