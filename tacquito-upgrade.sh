#!/usr/bin/env bash
#
# Tacquito TACACS+ Server — Upgrade Script
#
# Pulls the latest tacquito source, rebuilds the binaries, updates all managed
# scripts, and restarts the service. Configuration is preserved.
#
# Usage:
#   sudo ./tacquito-upgrade.sh
#
set -euo pipefail

TACQUITO_SRC="/opt/tacquito-src"
TACQUITO_BIN="/usr/local/bin/tacquito"
HASHGEN_BIN="/usr/local/bin/tacquito-hashgen"
MANAGE_BIN="/usr/local/bin/tacquito-manage"
UPGRADE_BIN="/usr/local/bin/tacquito-upgrade"
CONFIG_DIR="/etc/tacquito"
SERVICE_FILE="/etc/systemd/system/tacquito.service"
GO_BIN="/usr/local/go/bin/go"
# Look for deploy files: first try the directory this script lives in,
# then fall back to the canonical deploy location.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "${SCRIPT_DIR}/tacquito-manage.sh" ]]; then
    DEPLOY_DIR="$SCRIPT_DIR"
elif [[ -d "/opt/tacquito-manage" ]]; then
    DEPLOY_DIR="/opt/tacquito-manage"
else
    DEPLOY_DIR=""
fi

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Pre-flight checks ---
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo ./tacquito-upgrade.sh)"
    exit 1
fi

if [[ ! -d "$TACQUITO_SRC" ]]; then
    error "Tacquito source not found at ${TACQUITO_SRC}. Run tacquito-install.sh first."
    exit 1
fi

if [[ ! -x "$GO_BIN" ]]; then
    error "Go not found at ${GO_BIN}. Install Go first."
    exit 1
fi

export PATH=$PATH:/usr/local/go/bin

echo ""
echo "============================================"
echo "  Tacquito Upgrade"
echo "============================================"
echo ""

# --- Record current version ---
CURRENT_COMMIT=$(cd "$TACQUITO_SRC" && git rev-parse --short HEAD)
info "Current commit: ${CURRENT_COMMIT}"

# --- Pull latest source ---
info "Pulling latest source..."
cd "$TACQUITO_SRC"
git fetch --quiet
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse @{u})

if [[ "$LOCAL" == "$REMOTE" ]]; then
    info "Tacquito source already up to date (${CURRENT_COMMIT})."
    SKIP_BUILD=true
else
    SKIP_BUILD=false
    # Back up current binary before rebuilding
    if [[ -f "$TACQUITO_BIN" ]]; then
        cp "$TACQUITO_BIN" "${TACQUITO_BIN}.bak"
        info "Backed up current binary to ${TACQUITO_BIN}.bak"
    fi
fi

if [[ "$SKIP_BUILD" == "false" ]]; then
    git pull --quiet
    NEW_COMMIT=$(git rev-parse --short HEAD)
    info "Updated: ${CURRENT_COMMIT} -> ${NEW_COMMIT}"

    # --- Show what changed ---
    echo ""
    info "Changes:"
    git log --oneline "${CURRENT_COMMIT}..${NEW_COMMIT}" | head -20
    echo ""

    # --- Rebuild binaries ---
    info "Building tacquito server..."
    cd "${TACQUITO_SRC}/cmds/server"
    if ! go build -o "$TACQUITO_BIN" . ; then
        error "Build failed. Restoring previous binary."
        mv "${TACQUITO_BIN}.bak" "$TACQUITO_BIN"
        exit 1
    fi

    info "Building password hash generator..."
    cd "${TACQUITO_SRC}/cmds/server/config/authenticators/bcrypt/generator"
    go build -o "$HASHGEN_BIN" . || warn "Hashgen build failed (non-critical)."
fi

# --- Update managed scripts ---
info "Updating managed scripts..."
SCRIPTS_UPDATED=0

if [[ -z "$DEPLOY_DIR" ]]; then
    warn "Deploy directory not found. Skipping script updates."
    warn "To fix: copy the tacquito-manage folder to /opt/tacquito-manage"
fi

update_if_changed() {
    local src="$1" dest="$2" label="$3"
    if [[ ! -f "$src" ]]; then return; fi
    if diff -q "$src" "$dest" &>/dev/null; then
        info "  Unchanged: ${label}"
    else
        cp "$src" "$dest"
        info "  Updated: ${label}"
        SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
    fi
}

update_if_changed "${DEPLOY_DIR}/tacquito-manage.sh" "$MANAGE_BIN" "tacquito-manage"
chmod +x "$MANAGE_BIN" 2>/dev/null || true

update_if_changed "${DEPLOY_DIR}/tacquito-upgrade.sh" "$UPGRADE_BIN" "tacquito-upgrade"
chmod +x "$UPGRADE_BIN" 2>/dev/null || true

if [[ -f "${DEPLOY_DIR}/tacquito.service" ]]; then
    if ! diff -q "${DEPLOY_DIR}/tacquito.service" "$SERVICE_FILE" &>/dev/null; then
        cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"
        cp "${DEPLOY_DIR}/tacquito.service" "$SERVICE_FILE"
        systemctl daemon-reload
        info "  Updated: tacquito.service (previous backed up to ${SERVICE_FILE}.bak)"
        SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
    else
        info "  Unchanged: tacquito.service"
    fi
fi

update_if_changed "${DEPLOY_DIR}/README.md" "${CONFIG_DIR}/README.md" "README.md"
update_if_changed "${DEPLOY_DIR}/tacquito.logrotate" "/etc/logrotate.d/tacquito" "logrotate config"

info "${SCRIPTS_UPDATED} script(s) updated."

# --- Restart service (if binaries or service file changed) ---
if [[ "$SKIP_BUILD" == "false" ]] || [[ "$SCRIPTS_UPDATED" -gt 0 ]]; then
    info "Restarting tacquito service..."
    systemctl restart tacquito.service
    sleep 2

    if systemctl is-active --quiet tacquito.service; then
        info "Tacquito is running."
        rm -f "${TACQUITO_BIN}.bak"
    else
        if [[ "$SKIP_BUILD" == "false" ]]; then
            error "Tacquito failed to start after upgrade. Rolling back binary..."
            mv "${TACQUITO_BIN}.bak" "$TACQUITO_BIN"
            systemctl restart tacquito.service
            sleep 2
            if systemctl is-active --quiet tacquito.service; then
                warn "Rolled back to previous binary. Service is running."
            else
                error "Rollback failed. Check: journalctl -u tacquito"
            fi
            exit 1
        else
            error "Tacquito failed to start. Check: journalctl -u tacquito"
            exit 1
        fi
    fi

    # --- Verify ---
    LISTEN_CHECK=$(ss -tlnp | grep ":49 " || true)
    if [[ -n "$LISTEN_CHECK" ]]; then
        info "Listening on port 49/tcp"
    else
        warn "Port 49 not detected — check logs."
    fi
fi

echo ""
echo "============================================"
if [[ "$SKIP_BUILD" == "false" ]]; then
    echo "  Upgrade Complete: ${CURRENT_COMMIT} -> ${NEW_COMMIT}"
else
    echo "  Scripts Updated (source unchanged at ${CURRENT_COMMIT})"
fi
echo "  Managed scripts: ${SCRIPTS_UPDATED} updated"
echo "============================================"
echo ""
