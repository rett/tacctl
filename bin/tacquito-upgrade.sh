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
MANAGE_BIN="/usr/local/bin/tacctl"
UPGRADE_BIN="/usr/local/bin/tacquito-upgrade"
CONFIG_DIR="/etc/tacquito"
SERVICE_FILE="/etc/systemd/system/tacquito.service"
GO_BIN="/usr/local/go/bin/go"
MANAGE_REPO="https://github.com/rett/tacctl.git"
MANAGE_DIR="/opt/tacctl"
# Look for project root: first try parent of this script's directory (bin/),
# then fall back to the canonical deploy location.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." 2>/dev/null && pwd)"
if [[ -f "${SCRIPT_DIR}/tacctl.sh" ]]; then
    DEPLOY_DIR="$PROJECT_DIR"
elif [[ -d "$MANAGE_DIR" ]]; then
    DEPLOY_DIR="$MANAGE_DIR"
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

# --- Update management repo ---
if [[ -d "${MANAGE_DIR}/.git" ]]; then
    info "Pulling latest management scripts..."
    cd "$MANAGE_DIR"
    git fetch --quiet 2>/dev/null || true
    LOCAL_MANAGE=$(git rev-parse HEAD 2>/dev/null)
    REMOTE_MANAGE=$(git rev-parse @{u} 2>/dev/null || echo "")
    if [[ -n "$REMOTE_MANAGE" && "$LOCAL_MANAGE" != "$REMOTE_MANAGE" ]]; then
        # Copy self to temp before pull (git pull will overwrite the running script)
        SELF_TMP=$(mktemp)
        cp "${MANAGE_DIR}/bin/tacquito-upgrade.sh" "$SELF_TMP"

        git pull --quiet 2>/dev/null
        info "Management scripts updated: $(git rev-parse --short HEAD)"

        # If upgrade script changed, re-run the new version from the start
        if ! diff -q "$SELF_TMP" "${MANAGE_DIR}/bin/tacquito-upgrade.sh" &>/dev/null; then
            rm -f "$SELF_TMP"
            info "Upgrade script changed — restarting with new version..."
            exec "${MANAGE_DIR}/bin/tacquito-upgrade.sh"
        fi
        rm -f "$SELF_TMP"
    else
        info "Management scripts already up to date."
    fi
    DEPLOY_DIR="$MANAGE_DIR"
elif [[ -z "$DEPLOY_DIR" ]]; then
    info "Cloning management repo..."
    git clone --quiet "$MANAGE_REPO" "$MANAGE_DIR" 2>/dev/null && DEPLOY_DIR="$MANAGE_DIR" || warn "Failed to clone management repo."
fi

# --- Ensure symlinks exist ---
if [[ -d "$DEPLOY_DIR" ]]; then
    ln -sf "${DEPLOY_DIR}/bin/tacctl.sh" "$MANAGE_BIN"
    ln -sf "${DEPLOY_DIR}/bin/tacquito-upgrade.sh" "$UPGRADE_BIN"
fi

# --- Update system config files ---
info "Updating system files..."
SCRIPTS_UPDATED=0

if [[ -z "$DEPLOY_DIR" ]]; then
    warn "Deploy directory not found. Skipping updates."
    warn "To fix: clone the repo to /opt/tacctl"
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

if [[ -f "${DEPLOY_DIR}/config/tacquito.service" ]]; then
    if ! diff -q "${DEPLOY_DIR}/config/tacquito.service" "$SERVICE_FILE" &>/dev/null; then
        cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"
        cp "${DEPLOY_DIR}/config/tacquito.service" "$SERVICE_FILE"
        systemctl daemon-reload
        info "  Updated: tacquito.service (previous backed up to ${SERVICE_FILE}.bak)"
        SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
    else
        info "  Unchanged: tacquito.service"
    fi
fi

update_if_changed "${DEPLOY_DIR}/README.md" "${CONFIG_DIR}/README.md" "README.md"
update_if_changed "${DEPLOY_DIR}/config/tacquito.logrotate" "/etc/logrotate.d/tacquito" "logrotate config"

# Update default config templates (only if user hasn't customized them)
if [[ -d "${DEPLOY_DIR}/config/templates" ]]; then
    mkdir -p "${CONFIG_DIR}/templates"
    for tmpl in "${DEPLOY_DIR}/config/templates/"*.template; do
        [[ -f "$tmpl" ]] || continue
        tmpl_name=$(basename "$tmpl")
        dest="${CONFIG_DIR}/templates/${tmpl_name}"
        if [[ ! -f "$dest" ]]; then
            cp "$tmpl" "$dest"
            info "  Installed: ${tmpl_name}"
            SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
        else
            # Only update if the installed copy matches the previous repo version (not user-modified)
            update_if_changed "$tmpl" "$dest" "template: ${tmpl_name}"
        fi
    done
fi

info "${SCRIPTS_UPDATED} file(s) updated."

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
