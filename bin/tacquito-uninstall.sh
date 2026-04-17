#!/usr/bin/env bash
#
# Tacquito TACACS+ Server — Uninstaller
#
# Removes tacquito server, management scripts, configuration, and all data.
# Optionally preserves config backups and accounting logs.
#
# Usage:
#   sudo ./tacquito-uninstall.sh
#
set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Pre-flight ---
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo ./tacquito-uninstall.sh)"
    exit 1
fi

echo ""
echo "============================================"
echo -e "  ${RED}Tacquito Uninstaller${NC}"
echo "============================================"
echo ""
echo "This will remove:"
echo "  - Tacquito service and binary"
echo "  - Management scripts (tacquito-manage, tacquito-upgrade)"
echo "  - Password hash generator (tacquito-hashgen)"
echo "  - Configuration directory (/etc/tacquito)"
echo "  - Log directory (/var/log/tacquito)"
echo "  - Logrotate config"
echo "  - Service user (tacquito)"
echo "  - Management repo (/opt/tacquito-manage)"
echo ""
echo -e "${YELLOW}The tacquito source (/opt/tacquito-src) and Go installation"
echo -e "(/usr/local/go) will NOT be removed.${NC}"
echo ""

read -rp "Are you sure you want to uninstall tacquito? [y/N]: " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    info "Cancelled."
    exit 0
fi

echo ""

# --- Stop and disable service ---
if systemctl is-active --quiet tacquito 2>/dev/null; then
    info "Stopping tacquito service..."
    systemctl stop tacquito
fi
if systemctl is-enabled --quiet tacquito 2>/dev/null; then
    systemctl disable tacquito 2>/dev/null || true
fi

# --- Ask about preserving data ---
PRESERVE_BACKUPS=false
PRESERVE_LOGS=false

echo ""
read -rp "Preserve config backups (/etc/tacquito/backups)? [y/N]: " keep_backups
if [[ "$keep_backups" == "y" || "$keep_backups" == "Y" ]]; then
    PRESERVE_BACKUPS=true
fi

read -rp "Preserve accounting logs (/var/log/tacquito)? [y/N]: " keep_logs
if [[ "$keep_logs" == "y" || "$keep_logs" == "Y" ]]; then
    PRESERVE_LOGS=true
fi

echo ""

# --- Remove symlinks and binaries ---
info "Removing binaries and symlinks..."
rm -f /usr/local/bin/tacquito-manage
rm -f /usr/local/bin/tacquito-upgrade
rm -f /usr/local/bin/tacquito
rm -f /usr/local/bin/tacquito.bak
rm -f /usr/local/bin/tacquito-hashgen

# --- Remove systemd unit ---
info "Removing systemd unit..."
rm -f /etc/systemd/system/tacquito.service
rm -f /etc/systemd/system/tacquito.service.bak
systemctl daemon-reload

# --- Remove logrotate config ---
info "Removing logrotate config..."
rm -f /etc/logrotate.d/tacquito

# --- Remove configuration ---
if [[ "$PRESERVE_BACKUPS" == "true" ]]; then
    if [[ -d /etc/tacquito/backups ]]; then
        BACKUP_ARCHIVE="/root/tacquito-backups-$(date +%Y%m%d_%H%M%S).tar.gz"
        tar czf "$BACKUP_ARCHIVE" -C /etc/tacquito backups/ 2>/dev/null || true
        info "Config backups saved to ${BACKUP_ARCHIVE}"
    fi
fi
info "Removing configuration directory..."
rm -rf /etc/tacquito

# --- Remove logs ---
if [[ "$PRESERVE_LOGS" == "true" ]]; then
    if [[ -d /var/log/tacquito ]]; then
        LOG_ARCHIVE="/root/tacquito-logs-$(date +%Y%m%d_%H%M%S).tar.gz"
        tar czf "$LOG_ARCHIVE" -C /var/log tacquito/ 2>/dev/null || true
        info "Accounting logs saved to ${LOG_ARCHIVE}"
    fi
fi
info "Removing log directory..."
rm -rf /var/log/tacquito

# --- Remove password max age file ---
rm -f /etc/tacquito/password-max-age

# --- Remove management repo ---
info "Removing management repo..."
rm -rf /opt/tacquito-manage

# --- Remove service user ---
if id tacquito &>/dev/null; then
    info "Removing tacquito service user..."
    userdel tacquito 2>/dev/null || true
fi

echo ""
echo "============================================"
echo "  Uninstall Complete"
echo "============================================"
echo ""
echo "  Removed:"
echo "    - Tacquito service and binary"
echo "    - Management scripts and symlinks"
echo "    - Configuration and systemd unit"
echo "    - Logrotate config"
echo "    - Service user"
if [[ "$PRESERVE_BACKUPS" == "true" ]]; then
    echo "    - Config backups saved to: ${BACKUP_ARCHIVE}"
fi
if [[ "$PRESERVE_LOGS" == "true" ]]; then
    echo "    - Accounting logs saved to: ${LOG_ARCHIVE}"
fi
echo ""
echo "  Not removed:"
echo "    - Go installation (/usr/local/go)"
echo "    - Tacquito source (/opt/tacquito-src)"
echo "    - python3-bcrypt package"
echo ""
