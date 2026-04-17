#!/usr/bin/env bash
#
# Tacquito TACACS+ Server — Automated Install Script
#
# Installs Go, builds tacquito from source, configures the service,
# and generates passwords for all users interactively.
#
# Usage:
#   sudo ./tacquito-install.sh
#
# Requires: git, wget, python3, internet access
#
set -euo pipefail

# --- Configuration ---
GO_VERSION="1.26.2"
TACQUITO_REPO="https://github.com/facebookincubator/tacquito.git"
TACQUITO_SRC="/opt/tacquito-src"
TACQUITO_BIN="/usr/local/bin/tacquito"
HASHGEN_BIN="/usr/local/bin/tacquito-hashgen"
CONFIG_DIR="/etc/tacquito"
CONFIG_FILE="${CONFIG_DIR}/tacquito.yaml"
LOG_DIR="/var/log/tacquito"
SERVICE_FILE="/etc/systemd/system/tacquito.service"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

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
    error "This script must be run as root (sudo ./tacquito-install.sh)"
    exit 1
fi

for cmd in git wget python3; do
    if ! command -v "$cmd" &>/dev/null; then
        error "Required command '$cmd' not found. Install it first."
        exit 1
    fi
done

echo ""
echo "============================================"
echo "  Tacquito TACACS+ Server Installer"
echo "============================================"
echo ""

# --- Step 1: Install Go ---
if command -v /usr/local/go/bin/go &>/dev/null; then
    CURRENT_GO=$(/usr/local/go/bin/go version | awk '{print $3}')
    if [[ "$CURRENT_GO" == "go${GO_VERSION}" ]]; then
        info "Go ${GO_VERSION} already installed, skipping."
    else
        warn "Go ${CURRENT_GO} found, upgrading to ${GO_VERSION}..."
        rm -rf /usr/local/go
    fi
fi

if ! command -v /usr/local/go/bin/go &>/dev/null; then
    info "Installing Go ${GO_VERSION}..."
    cd /tmp
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
    info "Go ${GO_VERSION} installed."
fi

export PATH=$PATH:/usr/local/go/bin

# --- Step 2: Clone and build tacquito ---
if [[ -d "$TACQUITO_SRC" ]]; then
    info "Tacquito source already exists at ${TACQUITO_SRC}, pulling latest..."
    cd "$TACQUITO_SRC" && git pull --quiet
else
    info "Cloning tacquito..."
    git clone --quiet "$TACQUITO_REPO" "$TACQUITO_SRC"
fi

info "Building tacquito server..."
cd "${TACQUITO_SRC}/cmds/server"
go build -o "$TACQUITO_BIN" .

info "Building password hash generator..."
cd "${TACQUITO_SRC}/cmds/server/config/authenticators/bcrypt/generator"
go build -o "$HASHGEN_BIN" .

info "Binaries installed:"
info "  Server:  ${TACQUITO_BIN}"
info "  Hashgen: ${HASHGEN_BIN}"

# Copy deploy package to canonical location for upgrades
DEPLOY_DEST="/opt/tacquito-manage"
mkdir -p "$DEPLOY_DEST"
cp "${SCRIPT_DIR}/tacquito-manage.sh" "$DEPLOY_DEST/"
cp "${SCRIPT_DIR}/tacquito-upgrade.sh" "$DEPLOY_DEST/"
cp "${SCRIPT_DIR}/tacquito.service" "$DEPLOY_DEST/"
cp "${SCRIPT_DIR}/tacquito.yaml" "$DEPLOY_DEST/"
cp "${SCRIPT_DIR}/tacquito-install.sh" "$DEPLOY_DEST/"
cp "${SCRIPT_DIR}/README.md" "$DEPLOY_DEST/" 2>/dev/null || true
cp "${SCRIPT_DIR}/tacquito.logrotate" "$DEPLOY_DEST/" 2>/dev/null || true

# Install management scripts
cp "${SCRIPT_DIR}/tacquito-manage.sh" /usr/local/bin/tacquito-manage
chmod +x /usr/local/bin/tacquito-manage
cp "${SCRIPT_DIR}/tacquito-upgrade.sh" /usr/local/bin/tacquito-upgrade
chmod +x /usr/local/bin/tacquito-upgrade
cp "${SCRIPT_DIR}/README.md" "${CONFIG_DIR}/README.md" 2>/dev/null || true
# Install logrotate config
if [[ -f "${SCRIPT_DIR}/tacquito.logrotate" ]]; then
    cp "${SCRIPT_DIR}/tacquito.logrotate" /etc/logrotate.d/tacquito
    info "Log rotation installed: /etc/logrotate.d/tacquito"
fi

info "Management scripts installed:"
info "  tacquito-manage   — user & config management"
info "  tacquito-upgrade  — pull latest source, rebuild & update scripts"
info "  Deploy source:      ${DEPLOY_DEST}"

# --- Step 3: Install python3-bcrypt ---
if ! python3 -c "import bcrypt" 2>/dev/null; then
    info "Installing python3-bcrypt..."
    if command -v apt-get &>/dev/null; then
        apt-get install -y -qq python3-bcrypt
    elif command -v dnf &>/dev/null; then
        dnf install -y -q python3-bcrypt
    elif command -v yum &>/dev/null; then
        yum install -y -q python3-bcrypt
    else
        error "Cannot install python3-bcrypt automatically. Install it manually."
        exit 1
    fi
fi

# --- Step 4: Create service user and directories ---
if ! id tacquito &>/dev/null; then
    info "Creating tacquito service user..."
    useradd --system --no-create-home --shell /usr/sbin/nologin tacquito
else
    info "Service user 'tacquito' already exists."
fi

mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chown tacquito:tacquito "$CONFIG_DIR" "$LOG_DIR"
chmod 750 "$CONFIG_DIR" "$LOG_DIR"

# --- Step 5: Generate shared secret ---
echo ""
echo "--------------------------------------------"
echo "  Shared Secret Configuration"
echo "--------------------------------------------"
SHARED_SECRET=""
read -rp "Enter shared secret (leave blank to auto-generate): " SHARED_SECRET
if [[ -z "$SHARED_SECRET" ]]; then
    SHARED_SECRET=$(openssl rand -hex 16)
    info "Generated shared secret: ${SHARED_SECRET}"
else
    info "Using provided shared secret."
fi

# --- Step 6: Generate user passwords and hashes ---
echo ""
echo "--------------------------------------------"
echo "  User Password Configuration"
echo "--------------------------------------------"

generate_hash() {
    local password="$1"
    python3 -c "
import bcrypt, binascii
h = bcrypt.hashpw(b'''${password}''', bcrypt.gensalt(rounds=10))
print(binascii.hexlify(h).decode())
"
}

prompt_password() {
    local username="$1"
    local access="$2"
    local password=""

    echo ""
    echo "  User: ${username} (${access})"
    read -rp "  Enter password (leave blank to auto-generate): " password
    if [[ -z "$password" ]]; then
        password=$(openssl rand -base64 18)
        echo "  Generated password: ${password}"
    fi

    # Generate bcrypt hash
    local hash
    hash=$(python3 -c "
import bcrypt, binascii, sys
h = bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(rounds=10))
print(binascii.hexlify(h).decode())
" "$password")

    # Return hash via global variable (bash limitation)
    LAST_HASH="$hash"
    LAST_PASSWORD="$password"
}

prompt_password "user" "read-only"
HASH_USER="$LAST_HASH"
PW_USER="$LAST_PASSWORD"

prompt_password "operations" "operator, Operations"
HASH_OPERATIONS="$LAST_HASH"
PW_OPERATIONS="$LAST_PASSWORD"

prompt_password "engineering" "super-user"
HASH_ENGINEERING="$LAST_HASH"
PW_ENGINEERING="$LAST_PASSWORD"

# --- Step 7: Write configuration ---
info "Writing configuration to ${CONFIG_FILE}..."

# Use the template config and substitute placeholders
cp "${SCRIPT_DIR}/tacquito.yaml" "$CONFIG_FILE"

sed -i "s|hash: REPLACE_ME|hash: ${HASH_USER}|" "$CONFIG_FILE"
# Second occurrence for operations
sed -i "0,/hash: REPLACE_ME/{s|hash: REPLACE_ME|hash: ${HASH_OPERATIONS}|}" "$CONFIG_FILE"
# Third occurrence for engineering
sed -i "0,/hash: REPLACE_ME/{s|hash: REPLACE_ME|hash: ${HASH_ENGINEERING}|}" "$CONFIG_FILE"
# Shared secret
sed -i "s|REPLACE_WITH_SHARED_SECRET|${SHARED_SECRET}|" "$CONFIG_FILE"

chown tacquito:tacquito "$CONFIG_FILE"
chmod 640 "$CONFIG_FILE"

# --- Step 8: Install systemd service ---
info "Installing systemd service..."
cp "${SCRIPT_DIR}/tacquito.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable tacquito.service

# --- Step 9: Start the service ---
info "Starting tacquito..."
systemctl start tacquito.service
sleep 2

if systemctl is-active --quiet tacquito.service; then
    info "Tacquito is running!"
else
    error "Tacquito failed to start. Check: journalctl -u tacquito"
    exit 1
fi

# --- Step 10: Verify ---
LISTEN_CHECK=$(ss -tlnp | grep ":49 " || true)
if [[ -n "$LISTEN_CHECK" ]]; then
    info "Listening on port 49/tcp"
else
    warn "Port 49 not detected — check logs."
fi

# --- Summary ---
echo ""
echo "============================================"
echo "  Installation Complete"
echo "============================================"
echo ""
echo "  Service:        tacquito.service (enabled, running)"
echo "  Config:         ${CONFIG_FILE}"
echo "  Accounting log: ${LOG_DIR}/accounting.log"
echo "  Metrics:        http://localhost:8080/metrics"
echo ""
echo "  Shared Secret:  ${SHARED_SECRET}"
echo ""
echo "  Users:"
echo "    user         (read-only)   password: ${PW_USER}"
echo "    operations   (operator)    password: ${PW_OPERATIONS}"
echo "    engineering  (super-user)  password: ${PW_ENGINEERING}"
echo ""
echo "  SAVE THESE CREDENTIALS — they are not stored in plaintext."
echo ""
echo "  Next steps:"
echo "    1. Configure your Cisco/Juniper devices (see README.md)"
echo "    2. Restrict prefixes in ${CONFIG_FILE} to your management subnets"
echo "    3. Open port 49/tcp in your firewall if needed"
echo "    4. See README.md for user management and troubleshooting"
echo ""
