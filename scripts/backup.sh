#!/usr/bin/env bash
# Murnet Data Backup Script
# Usage: ./backup.sh [--data-dir PATH] [--backup-dir PATH] [--keep N]
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
DATA_DIR="${MURNET_DATA:-}"            # will probe below if empty
BACKUP_DIR="${MURNET_BACKUP_DIR:-/var/backups/murnet}"
KEEP="${MURNET_BACKUP_KEEP:-7}"        # number of backups to retain

# ── Helpers ───────────────────────────────────────────────────────────────────
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
die() { log "ERROR: $*" >&2; exit 1; }

# ── CLI argument parsing ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --data-dir)   DATA_DIR="$2";   shift 2 ;;
        --backup-dir) BACKUP_DIR="$2"; shift 2 ;;
        --keep)       KEEP="$2";       shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--data-dir PATH] [--backup-dir PATH] [--keep N]"
            echo ""
            echo "  --data-dir   Source data directory  (default: /var/lib/murnet or ./data)"
            echo "  --backup-dir Backup destination     (default: /var/backups/murnet)"
            echo "  --keep       Backups to retain      (default: 7)"
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

# ── Resolve data directory ────────────────────────────────────────────────────
if [[ -z "$DATA_DIR" ]]; then
    if [[ -d "/var/lib/murnet" ]]; then
        DATA_DIR="/var/lib/murnet"
    elif [[ -d "./data" ]]; then
        DATA_DIR="./data"
    else
        die "Cannot find data directory. Use --data-dir to specify one."
    fi
fi

# ── Validate ──────────────────────────────────────────────────────────────────
[[ -d "$DATA_DIR" ]] || die "Data directory '$DATA_DIR' does not exist."
[[ "$KEEP" =~ ^[0-9]+$ && "$KEEP" -ge 1 ]] || die "--keep must be a positive integer."

# ── Create backup directory ───────────────────────────────────────────────────
mkdir -p "$BACKUP_DIR"

# ── Build archive ─────────────────────────────────────────────────────────────
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
ARCHIVE="$BACKUP_DIR/murnet_${TIMESTAMP}.tar.gz"

log "Starting backup..."
log "  Source : $DATA_DIR"
log "  Archive: $ARCHIVE"
log "  Keep   : last $KEEP backups"

# Count files/size for reporting
SRC_SIZE=$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1 || echo "?")
log "  Source size: $SRC_SIZE"

tar --create \
    --gzip \
    --file="$ARCHIVE" \
    --directory="$(dirname "$DATA_DIR")" \
    "$(basename "$DATA_DIR")"

ARCHIVE_SIZE=$(du -sh "$ARCHIVE" 2>/dev/null | cut -f1 || echo "?")
log "Backup created: $ARCHIVE ($ARCHIVE_SIZE compressed)"

# ── Rotate old backups ────────────────────────────────────────────────────────
log "Rotating old backups (keeping last $KEEP)..."

# List backups sorted oldest-first, delete those beyond KEEP
mapfile -t OLD_BACKUPS < <(
    ls -1t "$BACKUP_DIR"/murnet_*.tar.gz 2>/dev/null | tail -n +"$((KEEP + 1))"
)

if [[ ${#OLD_BACKUPS[@]} -eq 0 ]]; then
    log "No old backups to remove."
else
    for old in "${OLD_BACKUPS[@]}"; do
        rm -f "$old"
        log "Removed old backup: $(basename "$old")"
    done
fi

# ── Summary ───────────────────────────────────────────────────────────────────
TOTAL=$(ls -1 "$BACKUP_DIR"/murnet_*.tar.gz 2>/dev/null | wc -l || echo 0)
log "Done. $TOTAL backup(s) retained in $BACKUP_DIR."
