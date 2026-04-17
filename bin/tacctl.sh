#!/usr/bin/env bash
#
# Tacquito TACACS+ Server — Management Script
#
# Manage local TACACS+ users and server configuration.
# Changes are applied to /etc/tacquito/tacquito.yaml and hot-reloaded automatically.
#
# Usage:
#   sudo ./tacctl.sh list
#   sudo ./tacctl.sh add <username> <readonly|superuser>
#   sudo ./tacctl.sh remove <username>
#   sudo ./tacctl.sh passwd <username>
#   sudo ./tacctl.sh disable <username>
#   sudo ./tacctl.sh enable <username>
#   sudo ./tacctl.sh verify <username>
#   sudo ./tacctl.sh config show
#   sudo ./tacctl.sh config secret [new-secret]
#   sudo ./tacctl.sh config juniper-ro [class-name]
#   sudo ./tacctl.sh config juniper-rw [class-name]
#   sudo ./tacctl.sh config prefixes [cidr,cidr,...]
#
set -euo pipefail

CONFIG="/etc/tacquito/tacquito.yaml"
BACKUP_DIR="/etc/tacquito/backups"
PASSWORD_DATES_DIR="/etc/tacquito/backups/password-dates"
ACCT_LOG="/var/log/tacquito/accounting.log"
PASSWORD_MAX_AGE_DAYS=90
PASSWORD_MAX_AGE_FILE="/etc/tacquito/password-max-age"
CONFIG_DIR="/etc/tacquito"
LOG_DIR="/var/log/tacquito"
SERVICE_FILE="/etc/systemd/system/tacquito.service"

# --- System lifecycle constants ---
GO_VERSION="1.26.2"
TACQUITO_REPO="https://github.com/facebookincubator/tacquito.git"
TACQUITO_SRC="/opt/tacquito-src"
TACQUITO_BIN="/usr/local/bin/tacquito"
HASHGEN_BIN="/usr/local/bin/tacquito-hashgen"
DEPLOY_DIR="/opt/tacctl"
MANAGE_REPO="https://github.com/rett/tacctl.git"
GO_BIN="/usr/local/go/bin/go"

# Load custom password max age if set
if [[ -f "$PASSWORD_MAX_AGE_FILE" ]]; then
    PASSWORD_MAX_AGE_DAYS=$(cat "$PASSWORD_MAX_AGE_FILE")
fi

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Pre-flight ---
preflight() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (sudo ./tacctl.sh ...)"
        exit 1
    fi
    if [[ ! -f "$CONFIG" ]]; then
        error "Config not found at ${CONFIG}. Is tacquito installed?"
        exit 1
    fi
    if ! python3 -c "import bcrypt" 2>/dev/null; then
        error "python3-bcrypt not installed. Install it first."
        exit 1
    fi
}

# --- Resolve template file (user override → repo default) ---
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
TEMPLATE_DIR_LOCAL="/etc/tacquito/templates"
TEMPLATE_DIR_REPO="$(cd "${SCRIPT_DIR}/../config/templates" 2>/dev/null && pwd)"

resolve_template() {
    local name="$1"
    if [[ -f "${TEMPLATE_DIR_LOCAL}/${name}.template" ]]; then
        echo "${TEMPLATE_DIR_LOCAL}/${name}.template"
    elif [[ -n "$TEMPLATE_DIR_REPO" && -f "${TEMPLATE_DIR_REPO}/${name}.template" ]]; then
        echo "${TEMPLATE_DIR_REPO}/${name}.template"
    fi
}

# --- Restart service after config changes ---
# sed -i and python rewrites change the file inode, breaking fsnotify hot-reload.
restart_service() {
    systemctl restart tacquito 2>/dev/null && info "Service restarted." || warn "Service restart failed — run: sudo systemctl restart tacquito"
}

# --- Track password change date ---
record_password_date() {
    local username="$1"
    mkdir -p "$PASSWORD_DATES_DIR"
    date +%Y-%m-%d > "${PASSWORD_DATES_DIR}/${username}.date"
}

get_password_date() {
    local username="$1"
    local datefile="${PASSWORD_DATES_DIR}/${username}.date"
    if [[ -f "$datefile" ]]; then
        cat "$datefile"
    else
        echo "unknown"
    fi
}

# --- Backup config before changes ---
BACKUP_RETENTION=30

backup_config() {
    mkdir -p "$BACKUP_DIR"
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    cp "$CONFIG" "${BACKUP_DIR}/tacquito.yaml.${ts}"
    info "Config backed up to ${BACKUP_DIR}/tacquito.yaml.${ts}"

    # Prune old backups, keep last $BACKUP_RETENTION
    local count
    count=$(ls -1 "${BACKUP_DIR}"/tacquito.yaml.* 2>/dev/null | wc -l)
    if [[ "$count" -gt "$BACKUP_RETENTION" ]]; then
        ls -1t "${BACKUP_DIR}"/tacquito.yaml.* | tail -n +$((BACKUP_RETENTION + 1)) | xargs rm -f
    fi
}

# --- Generate bcrypt hex hash from password ---
generate_hash() {
    local password="$1"
    python3 -c "
import bcrypt, binascii, sys
h = bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(rounds=10))
print(binascii.hexlify(h).decode())
" "$password"
}

# --- Verify a password against a stored hash ---
verify_hash() {
    local password="$1"
    local hexhash="$2"
    python3 -c "
import bcrypt, binascii, sys
h = binascii.unhexlify(sys.argv[2])
try:
    bcrypt.checkpw(sys.argv[1].encode(), h)
    print('MATCH')
except ValueError:
    print('INVALID_HASH')
" "$password" "$hexhash" 2>/dev/null || echo "FAIL"
}

# --- Check if user exists ---
user_exists() {
    local username="$1"
    grep -qP "^bcrypt_${username}:" "$CONFIG"
}

# --- Get user's hash ---
get_user_hash() {
    local username="$1"
    # Find the bcrypt anchor for this user and extract the hash value
    grep -A4 "^bcrypt_${username}:" "$CONFIG" | grep "hash:" | awk '{print $2}'
}

# --- Get user's group ---
get_user_group() {
    local username="$1"
    python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'- name: ' + re.escape(sys.argv[2]) + r'\n.*?groups: \[\*(\w+)\]', config, re.DOTALL)
print(m.group(1) if m else 'unknown')
" "$CONFIG" "$username"
}

# --- Read password with asterisk masking ---
read_password_masked() {
    local prompt="${1:-Password: }"
    local password="" char=""
    printf "%s" "$prompt" >&2
    while IFS= read -rsn1 char; do
        # Enter pressed
        if [[ -z "$char" ]]; then
            break
        fi
        # Backspace / delete
        if [[ "$char" == $'\x7f' || "$char" == $'\b' ]]; then
            if [[ -n "$password" ]]; then
                password="${password%?}"
                printf '\b \b' >&2
            fi
        else
            password+="$char"
            printf '*' >&2
        fi
    done
    echo "" >&2
    echo "$password"
}

# --- Prompt for password ---
prompt_password() {
    local password=""
    password=$(read_password_masked "  Enter password (leave blank to auto-generate): ")
    if [[ -z "$password" ]]; then
        password=$(openssl rand -base64 18)
        echo -e "  Generated password: ${BOLD}${password}${NC}" >&2
    else
        local confirm=""
        confirm=$(read_password_masked "  Confirm password: ")
        if [[ "$password" != "$confirm" ]]; then
            echo -e "  ${RED}Passwords do not match.${NC}" >&2
            exit 1
        fi
    fi
    echo "$password"
}

# =====================================================================
#  COMMANDS
# =====================================================================

# --- LIST ---
cmd_list() {
    echo ""
    echo -e "${BOLD}Tacquito Users${NC}"
    echo "--------------------------------------------"
    printf "  ${BOLD}%-20s %-15s %-10s %-12s${NC}\n" "USERNAME" "GROUP" "STATUS" "PW CHANGED"
    echo "  -----------------------------------------------------------------"

    # Use Python for reliable YAML-ish parsing
    python3 -c "
import re, sys

config = open(sys.argv[1]).read()

# Extract only the users: section
users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
if not users_match:
    sys.exit(0)
users_section = users_match.group(1)

# Find all user entries within the users section
for m in re.finditer(r'- name: (\S+)\n.*?groups: \[\*(\w+)\]', users_section, re.DOTALL):
    username = m.group(1)
    group = m.group(2)

    # Find the hash for this user in the full config
    auth_match = re.search(r'^bcrypt_' + re.escape(username) + r':.*?hash:\s*(\S+)', config, re.MULTILINE | re.DOTALL)
    if auth_match:
        h = auth_match.group(1)
        status = 'disabled' if h == 'DISABLED' else 'active'
    else:
        status = 'unknown'

    print(f'{username}|{group}|{status}')
" "$CONFIG" | sort | while IFS='|' read -r username group status; do
        local color="$GREEN"
        [[ "$status" == "disabled" ]] && color="$RED"
        [[ "$status" == "unknown" ]] && color="$YELLOW"
        local pw_date
        pw_date=$(get_password_date "$username")
        printf "  %-20s %-15s ${color}%-10s${NC} %-12s\n" "$username" "$group" "$status" "$pw_date"
    done

    echo ""
}

# --- ADD ---
cmd_add() {
    local username="${1:-}"
    local group="${2:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl.sh add <username> <readonly|operator|superuser>"
        exit 1
    fi
    # Validate group exists in config
    if ! grep -q "^${group}: &${group}$" "$CONFIG"; then
        local available
        available=$(grep -oP '^\w+(?=: &\w)' "$CONFIG" | grep -v "^bcrypt_\|^exec_\|^junos_\|^file_\|^authenticator\|^action\|^accounter\|^handler\|^provider" | tr '\n' '|' | sed 's/|$//')
        error "Group '${group}' does not exist. Available: ${available}"
        error "Usage: tacctl.sh add <username> <group>"
        exit 1
    fi
    if user_exists "$username"; then
        error "User '${username}' already exists."
        exit 1
    fi
    # Validate username (alphanumeric, underscore, hyphen)
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        error "Username must contain only letters, numbers, underscores, and hyphens."
        exit 1
    fi

    echo ""
    echo -e "  Adding user: ${BOLD}${username}${NC} (${group})"
    local password
    password=$(prompt_password)

    local hash
    hash=$(generate_hash "$password")

    backup_config

    # Insert authenticator anchor before the "# --- Services ---" line
    local auth_block
    auth_block=$(cat <<EOF

bcrypt_${username}: &bcrypt_${username}
  type: *authenticator_type_bcrypt
  options:
    hash: ${hash}
EOF
)
    # Find the line number of "# --- Services ---" and insert before it
    local insert_line
    insert_line=$(grep -n "^# --- Services ---" "$CONFIG" | head -1 | cut -d: -f1)
    if [[ -z "$insert_line" ]]; then
        error "Cannot find insertion point in config. Is the config format correct?"
        exit 1
    fi

    # Insert the authenticator block
    sed -i "$((insert_line - 1))a\\
\\
bcrypt_${username}: \&bcrypt_${username}\\
  type: *authenticator_type_bcrypt\\
  options:\\
    hash: ${hash}" "$CONFIG"

    # Append user entry at the end of the users section (before "# --- Secret Providers ---")
    local secrets_line
    secrets_line=$(grep -n "^# --- Secret Providers ---" "$CONFIG" | head -1 | cut -d: -f1)
    if [[ -z "$secrets_line" ]]; then
        error "Cannot find secrets section in config."
        exit 1
    fi

    sed -i "$((secrets_line - 1))i\\
\\
  # ${username}\\
  - name: ${username}\\
    scopes: [\"network_devices\"]\\
    groups: [*${group}]\\
    authenticator: *bcrypt_${username}\\
    accounter: *file_accounter" "$CONFIG"

    # Fix ownership
    chown tacquito:tacquito "$CONFIG"

    restart_service
    record_password_date "$username"
    info "User '${username}' added (${group})."
    echo ""
}

# --- REMOVE ---
cmd_remove() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl.sh remove <username>"
        exit 1
    fi
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    echo ""
    read -rp "  Remove user '${username}'? This cannot be undone. [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    backup_config

    # Remove the authenticator anchor block (bcrypt_<username> through next blank line or next anchor)
    sed -i "/^bcrypt_${username}:/,/^$/d" "$CONFIG"

    # Remove the user entry block (from "# <username>" or "- name: <username>" to next "- name:" or section)
    # First try removing a comment line above the user entry
    sed -i "/^  # ${username}$/d" "$CONFIG"
    # Remove the user entry itself (multi-line block)
    python3 -c "
import sys
lines = open(sys.argv[1]).readlines()
out = []
skip = False
for i, line in enumerate(lines):
    if line.strip() == '- name: ${username}':
        skip = True
        continue
    if skip:
        if line.startswith('  - name:') or not line.startswith('    '):
            skip = False
        else:
            continue
    out.append(line)
open(sys.argv[1], 'w').writelines(out)
" "$CONFIG"

    # Clean up double blank lines
    sed -i '/^$/N;/^\n$/d' "$CONFIG"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "User '${username}' removed."
    echo ""
}

# --- PASSWD (change password) ---
cmd_passwd() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl.sh passwd <username>"
        exit 1
    fi
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    echo ""
    echo -e "  Changing password for: ${BOLD}${username}${NC}"
    local password
    password=$(prompt_password)

    local hash
    hash=$(generate_hash "$password")

    backup_config

    # Replace the hash in the user's authenticator anchor
    local old_hash
    old_hash=$(get_user_hash "$username")
    sed -i "s|hash: ${old_hash}|hash: ${hash}|" "$CONFIG"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    record_password_date "$username"
    info "Password changed for '${username}'."
    echo ""
}

# --- DISABLE ---
cmd_disable() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl.sh disable <username>"
        exit 1
    fi
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local current_hash
    current_hash=$(get_user_hash "$username")
    if [[ "$current_hash" == "DISABLED" ]]; then
        warn "User '${username}' is already disabled."
        exit 0
    fi

    backup_config

    # Save the real hash to a sidecar file for re-enabling
    mkdir -p "${BACKUP_DIR}/disabled"
    echo "$current_hash" > "${BACKUP_DIR}/disabled/${username}.hash"
    chmod 600 "${BACKUP_DIR}/disabled/${username}.hash"

    # Replace hash with DISABLED
    sed -i "s|hash: ${current_hash}|hash: DISABLED|" "$CONFIG"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "User '${username}' disabled. Use 'enable' to restore access."
    echo ""
}

# --- ENABLE ---
cmd_enable() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl.sh enable <username>"
        exit 1
    fi
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local current_hash
    current_hash=$(get_user_hash "$username")
    if [[ "$current_hash" != "DISABLED" ]]; then
        warn "User '${username}' is not disabled."
        exit 0
    fi

    local saved_hash_file="${BACKUP_DIR}/disabled/${username}.hash"
    if [[ ! -f "$saved_hash_file" ]]; then
        error "No saved hash found for '${username}'. Set a new password instead:"
        error "  sudo ./tacctl.sh passwd ${username}"
        exit 1
    fi

    local saved_hash
    saved_hash=$(cat "$saved_hash_file")

    backup_config

    sed -i "s|hash: DISABLED|hash: ${saved_hash}|" "$CONFIG"
    rm -f "$saved_hash_file"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "User '${username}' re-enabled with previous password."
    echo ""
}

# --- VERIFY (test a password against stored hash) ---
cmd_verify() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl.sh verify <username>"
        exit 1
    fi
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    # Show user details
    local group
    group=$(get_user_group "$username")
    local stored_hash
    stored_hash=$(get_user_hash "$username")
    local status="active"
    [[ "$stored_hash" == "DISABLED" ]] && status="disabled"
    local pw_date
    pw_date=$(get_password_date "$username")

    echo ""
    echo -e "  ${BOLD}User:${NC}           ${username}"
    echo -e "  ${BOLD}Group:${NC}          ${group}"
    if [[ "$status" == "disabled" ]]; then
        echo -e "  ${BOLD}Status:${NC}         ${RED}disabled${NC}"
        echo -e "  ${BOLD}PW changed:${NC}     ${pw_date}"
        echo ""
        error "User is disabled — cannot verify password."
        exit 1
    fi
    echo -e "  ${BOLD}Status:${NC}         ${GREEN}active${NC}"
    echo -e "  ${BOLD}PW changed:${NC}     ${pw_date}"
    echo ""

    local password
    password=$(read_password_masked "  Enter password to verify: ")

    local result
    result=$(verify_hash "$password" "$stored_hash")
    if [[ "$result" == "MATCH" ]]; then
        info "Password is correct."
    else
        error "Password does not match."
    fi
    echo ""
}

# --- RENAME ---
cmd_rename() {
    local oldname="${1:-}"
    local newname="${2:-}"

    if [[ -z "$oldname" || -z "$newname" ]]; then
        error "Usage: tacctl.sh rename <old-username> <new-username>"
        exit 1
    fi
    if ! user_exists "$oldname"; then
        error "User '${oldname}' does not exist."
        exit 1
    fi
    if user_exists "$newname"; then
        error "User '${newname}' already exists."
        exit 1
    fi
    if [[ ! "$newname" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        error "Username must contain only letters, numbers, underscores, and hyphens."
        exit 1
    fi

    backup_config

    # Use Python for reliable multi-reference rename
    python3 -c "
import re, sys

oldname = sys.argv[2]
newname = sys.argv[3]

config = open(sys.argv[1]).read()

# Rename bcrypt anchor: 'bcrypt_old: &bcrypt_old' -> 'bcrypt_new: &bcrypt_new'
config = config.replace(f'bcrypt_{oldname}: &bcrypt_{oldname}', f'bcrypt_{newname}: &bcrypt_{newname}')

# Rename authenticator reference: '*bcrypt_old' -> '*bcrypt_new'
config = config.replace(f'*bcrypt_{oldname}', f'*bcrypt_{newname}')

# Rename user entry: '- name: old' -> '- name: new'
config = re.sub(rf'^(\s+- name: ){re.escape(oldname)}$', rf'\g<1>{newname}', config, flags=re.MULTILINE)

# Rename comment if present: '# old' -> '# new'
config = re.sub(rf'^(\s+# ){re.escape(oldname)}$', rf'\g<1>{newname}', config, flags=re.MULTILINE)

open(sys.argv[1], 'w').write(config)
" "$CONFIG" "$oldname" "$newname"

    chown tacquito:tacquito "$CONFIG"

    # Rename password date file
    if [[ -f "${PASSWORD_DATES_DIR}/${oldname}.date" ]]; then
        mv "${PASSWORD_DATES_DIR}/${oldname}.date" "${PASSWORD_DATES_DIR}/${newname}.date"
    fi

    restart_service
    info "User renamed: ${oldname} -> ${newname}"
    echo ""
}

# --- MOVE (change user's group) ---
cmd_move() {
    local username="${1:-}"
    local newgroup="${2:-}"

    if [[ -z "$username" || -z "$newgroup" ]]; then
        error "Usage: tacctl move <username> <new-group>"
        exit 1
    fi
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi
    if ! grep -q "^${newgroup}: &${newgroup}$" "$CONFIG"; then
        local available
        available=$(grep -oP '^\w+(?=: &\w)' "$CONFIG" | grep -v "^bcrypt_\|^exec_\|^junos_\|^file_\|^authenticator\|^action\|^accounter\|^handler\|^provider" | tr '\n' '|' | sed 's/|$//' || true)
        error "Group '${newgroup}' does not exist. Available: ${available}"
        exit 1
    fi

    local oldgroup
    oldgroup=$(get_user_group "$username")
    if [[ "$oldgroup" == "$newgroup" ]]; then
        info "User '${username}' is already in group '${newgroup}'."
        return
    fi

    backup_config

    # Replace the group reference in the user entry
    python3 -c "
import re, sys
config = open(sys.argv[1]).read()
username = sys.argv[2]
oldgroup = sys.argv[3]
newgroup = sys.argv[4]

# Find the user block and replace the group
pattern = r'(- name: ' + re.escape(username) + r'\n.*?groups: \[\*)' + re.escape(oldgroup) + r'(\])'
config = re.sub(pattern, r'\g<1>' + newgroup + r'\2', config, flags=re.DOTALL)

open(sys.argv[1], 'w').write(config)
" "$CONFIG" "$username" "$oldgroup" "$newgroup"

    chown tacquito:tacquito "$CONFIG"
    restart_service
    info "User '${username}' moved: ${oldgroup} -> ${newgroup}"
    echo ""
}

# =====================================================================
#  CONFIG COMMANDS
# =====================================================================

# --- Helper: get current value from config using Python ---
get_config_value() {
    local key="$1"
    python3 -c "
import re, sys

config = open(sys.argv[1]).read()
key = sys.argv[2]

if key == 'secret':
    m = re.search(r'^\s+key:\s+\"?([^\"\n]+)\"?', config, re.MULTILINE)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'juniper-ro':
    m = re.search(r'junos_exec_readonly:.*?values:\s*\[\"?([^\"\]\n]+)', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'juniper-rw':
    m = re.search(r'junos_exec_superuser:.*?values:\s*\[\"?([^\"\]\n]+)', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'cisco-ro':
    m = re.search(r'exec_readonly:.*?values:\s*\[(\d+)\]', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'cisco-op':
    m = re.search(r'exec_operator:.*?values:\s*\[(\d+)\]', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'cisco-rw':
    m = re.search(r'exec_superuser:.*?values:\s*\[(\d+)\]', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'juniper-op':
    m = re.search(r'junos_exec_operator:.*?values:\s*\[\"?([^\"\]\n]+)', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'prefixes':
    m = re.search(r'prefixes:\s*\|\s*\n\s*\[\s*\n(.*?)\s*\]', config, re.DOTALL)
    if m:
        cidrs = re.findall(r'\"([^\"]+)\"', m.group(1))
        print(','.join(cidrs))
    else:
        print('NOT FOUND')
elif key == 'address':
    # read from systemd unit
    import subprocess
    r = subprocess.run(['systemctl', 'show', 'tacquito', '--property=ExecStart'], capture_output=True, text=True)
    m2 = re.search(r'-address\s+(\S+)', r.stdout)
    print(m2.group(1) if m2 else ':49')
" "$CONFIG" "$key"
}

# --- CONFIG SHOW ---
cmd_config_show() {
    echo ""
    echo -e "${BOLD}Tacquito Configuration${NC}"
    echo "--------------------------------------------"

    local secret juniper_ro juniper_op juniper_rw cisco_ro cisco_op cisco_rw prefixes
    secret=$(get_config_value "secret")
    juniper_ro=$(get_config_value "juniper-ro")
    juniper_op=$(get_config_value "juniper-op")
    juniper_rw=$(get_config_value "juniper-rw")
    cisco_ro=$(get_config_value "cisco-ro")
    cisco_op=$(get_config_value "cisco-op")
    cisco_rw=$(get_config_value "cisco-rw")
    prefixes=$(get_config_value "prefixes")

    echo ""
    echo -e "  ${BOLD}Shared Secret:${NC}        ${secret}"
    echo ""
    echo -e "  ${BOLD}Cisco (priv-lvl):${NC}"
    echo -e "    Read-only:          ${cisco_ro}"
    echo -e "    Operator:           ${cisco_op}"
    echo -e "    Super-user:         ${cisco_rw}"
    echo ""
    echo -e "  ${BOLD}Juniper (local-user-name):${NC}"
    echo -e "    Read-only class:    ${juniper_ro}"
    echo -e "    Operator class:     ${juniper_op}"
    echo -e "    Super-user class:   ${juniper_rw}"
    echo ""
    echo -e "  ${BOLD}Allowed Prefixes:${NC}"
    IFS=',' read -ra CIDRS <<< "$prefixes"
    for cidr in "${CIDRS[@]}"; do
        echo "    - ${cidr}"
    done

    # Show allow/deny lists
    local allow_list deny_list
    allow_list=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^prefix_allow:\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    print(', '.join(re.findall(r'\"([^\"]+)\"', m.group(1))))
else:
    print('')
" "$CONFIG" || true)
    deny_list=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^prefix_deny:\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    print(', '.join(re.findall(r'\"([^\"]+)\"', m.group(1))))
else:
    print('')
" "$CONFIG" || true)

    echo ""
    echo -e "  ${BOLD}Connection Filters:${NC} ${CYAN}(deny takes precedence over allow)${NC}"
    if [[ -n "$allow_list" ]]; then
        echo -e "    Allow:              ${allow_list}"
    else
        echo -e "    Allow:              ${CYAN}(all)${NC}"
    fi
    if [[ -n "$deny_list" ]]; then
        echo -e "    Deny:               ${deny_list}"
    else
        echo -e "    Deny:               ${CYAN}(none)${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}Config file:${NC}          ${CONFIG}"
    echo -e "  ${BOLD}Service status:${NC}       $(systemctl is-active tacquito 2>/dev/null || echo 'unknown')"

    # Show listening port (TACACS+ = port 49)
    local listen
    listen=$(ss -tlnp 2>/dev/null | grep ":49 " | awk '{print $4}' | head -1)
    if [[ -n "$listen" ]]; then
        echo -e "  ${BOLD}Listening on:${NC}         ${listen}"
    else
        echo -e "  ${BOLD}Listening on:${NC}         ${RED}port 49 not detected${NC}"
    fi
    echo ""
}

# --- CONFIG SECRET ---
cmd_config_secret() {
    local new_secret="${1:-}"

    if [[ -z "$new_secret" ]]; then
        read -rp "  Enter new shared secret (leave blank to auto-generate): " new_secret
        if [[ -z "$new_secret" ]]; then
            new_secret=$(openssl rand -base64 24)
            echo -e "  Generated: ${BOLD}${new_secret}${NC}"
        fi
    fi

    local old_secret
    old_secret=$(get_config_value "secret")

    backup_config

    sed -i "s|key: \"${old_secret}\"|key: \"${new_secret}\"|" "$CONFIG"
    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "Shared secret updated."
    warn "Update ALL network devices with the new secret: ${new_secret}"
    echo ""
}

# --- CONFIG JUNIPER-RO ---
cmd_config_juniper_ro() {
    local new_class="${1:-}"

    if [[ -z "$new_class" ]]; then
        local current
        current=$(get_config_value "juniper-ro")
        read -rp "  Enter new Juniper read-only class name [current: ${current}]: " new_class
        if [[ -z "$new_class" ]]; then
            info "No change."
            return
        fi
    fi

    local old_class
    old_class=$(get_config_value "juniper-ro")

    backup_config

    # Update the junos_exec_readonly service value
    sed -i "/junos_exec_readonly:/,/values:/{s|values: \[\"${old_class}\"\]|values: [\"${new_class}\"]|}" "$CONFIG"

    # Update the comment above it
    sed -i "s|\"${old_class}\" must match a local template user|\"${new_class}\" must match a local template user|" "$CONFIG"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "Juniper read-only class changed: ${old_class} -> ${new_class}"
    warn "Update Juniper devices: set system login user ${new_class} class read-only"
    echo ""
}

# --- CONFIG JUNIPER-RW ---
cmd_config_juniper_rw() {
    local new_class="${1:-}"

    if [[ -z "$new_class" ]]; then
        local current
        current=$(get_config_value "juniper-rw")
        read -rp "  Enter new Juniper super-user class name [current: ${current}]: " new_class
        if [[ -z "$new_class" ]]; then
            info "No change."
            return
        fi
    fi

    local old_class
    old_class=$(get_config_value "juniper-rw")

    backup_config

    # Update the junos_exec_superuser service value
    sed -i "/junos_exec_superuser:/,/values:/{s|values: \[\"${old_class}\"\]|values: [\"${new_class}\"]|}" "$CONFIG"

    # Update the comment above it
    sed -i "s|\"${old_class}\" must match a local template user|\"${new_class}\" must match a local template user|" "$CONFIG"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "Juniper super-user class changed: ${old_class} -> ${new_class}"
    warn "Update Juniper devices: set system login user ${new_class} class super-user"
    echo ""
}

# --- CONFIG PREFIXES ---
cmd_config_prefixes() {
    local new_prefixes="${1:-}"

    local current
    current=$(get_config_value "prefixes")

    if [[ -z "$new_prefixes" ]]; then
        echo ""
        echo "  Current prefixes: ${current}"
        echo ""
        read -rp "  Enter new prefixes (comma-separated CIDRs, e.g. 10.1.0.0/16,172.16.0.0/12): " new_prefixes
        if [[ -z "$new_prefixes" ]]; then
            info "No change."
            return
        fi
    fi

    backup_config

    # Build the new prefixes YAML block
    local prefix_lines=""
    IFS=',' read -ra CIDRS <<< "$new_prefixes"
    for cidr in "${CIDRS[@]}"; do
        cidr=$(echo "$cidr" | xargs)  # trim whitespace
        if [[ -n "$prefix_lines" ]]; then
            prefix_lines="${prefix_lines},"$'\n'"          \"${cidr}\""
        else
            prefix_lines="\"${cidr}\""
        fi
    done

    # Use Python for reliable multi-line replacement
    python3 -c "
import re, sys

config = open(sys.argv[1]).read()
new_cidrs = sys.argv[2].split(',')

# Build new prefix block
lines = []
for c in new_cidrs:
    c = c.strip()
    if c:
        lines.append(f'          \"{c}\"')
new_block = 'prefixes: |\n        [\n' + ',\n'.join(lines) + '\n        ]'

# Replace existing prefix block
config = re.sub(
    r'prefixes:\s*\|\s*\n\s*\[.*?\]',
    new_block,
    config,
    flags=re.DOTALL
)

open(sys.argv[1], 'w').write(config)
" "$CONFIG" "$new_prefixes"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "Allowed prefixes updated."
    echo "  New prefixes:"
    IFS=',' read -ra CIDRS <<< "$new_prefixes"
    for cidr in "${CIDRS[@]}"; do
        echo "    - $(echo "$cidr" | xargs)"
    done
    echo ""
}

# --- CONFIG CISCO (show working device config) ---
cmd_config_cisco() {
    local secret server_ip
    secret=$(get_config_value "secret")
    server_ip=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [[ -z "$server_ip" ]]; then
        server_ip="<TACQUITO_SERVER_IP>"
    fi

    # Collect all groups with their priv-lvl
    local group_info
    group_info=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
groups_match = re.search(r'^# --- Groups ---\s*\n(.*?)(?=^# --- Users|\Z)', config, re.MULTILINE | re.DOTALL)
if not groups_match:
    sys.exit(0)
for m in re.finditer(r'^(\w+): &\1\n  name: \1\n  services:\n(.*?)  accounter:', groups_match.group(1), re.MULTILINE | re.DOTALL):
    name = m.group(1)
    pm = re.search(r'\*exec_(\w+)', m.group(2))
    if pm:
        svc = pm.group(1)
        sm = re.search(r'exec_' + svc + r':.*?values:\s*\[(\d+)\]', config, re.DOTALL)
        if sm:
            print(f'{name}|{sm.group(1)}')
" "$CONFIG")

    # Build dynamic sections
    local PRIVILEGE_COMMANDS=""
    while IFS='|' read -r gname privlvl; do
        [[ -z "$gname" ]] && continue
        [[ "$privlvl" == "1" || "$privlvl" == "15" ]] && continue
        PRIVILEGE_COMMANDS+="! --- ${gname} — Privilege Level ${privlvl} Commands ---
privilege exec level ${privlvl} show running-config
privilege exec level ${privlvl} show startup-config
privilege exec level ${privlvl} ping
privilege exec level ${privlvl} traceroute
privilege exec level ${privlvl} terminal monitor
privilege exec level ${privlvl} terminal no monitor
!
"
    done <<< "$group_info"

    local GROUP_SUMMARY=""
    while IFS='|' read -r gname privlvl; do
        [[ -z "$gname" ]] && continue
        GROUP_SUMMARY+="  ${gname}: priv-lvl ${privlvl}"$'\n'
    done <<< "$group_info"

    echo ""
    echo -e "${BOLD}Cisco IOS / IOS-XE Configuration${NC}"
    echo -e "${YELLOW}Copy and paste into the device:${NC}"
    echo "--------------------------------------------"
    echo ""

    local template_file
    template_file=$(resolve_template "cisco")
    if [[ -n "$template_file" ]]; then
        export SERVER_IP="$server_ip" SECRET="$secret" PRIVILEGE_COMMANDS GROUP_SUMMARY
        envsubst '${SERVER_IP} ${SECRET} ${PRIVILEGE_COMMANDS} ${GROUP_SUMMARY}' < "$template_file"
    else
        cat <<EOF
! --- TACACS+ Server & AAA ---
aaa new-model
!
tacacs server TACACS
  address ipv4 ${server_ip}
  key ${secret}
  single-connection
!
aaa group server tacacs+ TACACS-GROUP
  server name TACACS
!
aaa authentication login default group TACACS-GROUP local
aaa authorization exec default group TACACS-GROUP local if-authenticated
aaa accounting exec default start-stop group TACACS-GROUP
aaa accounting commands 15 default start-stop group TACACS-GROUP
!
${PRIVILEGE_COMMANDS}
line vty 0 15
  login authentication default
EOF
    fi

    echo ""
    echo "--------------------------------------------"
    echo -e "${YELLOW}Group → Privilege Level Mapping:${NC}"
    echo -n "$GROUP_SUMMARY"
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - The 'local' fallback ensures access if TACACS+ is unreachable"
    echo "  - Ensure a local admin account exists as a backup"
    echo "  - Custom privilege levels (2-14) require the 'privilege exec level' mappings above"
    echo "  - Adjust mapped commands to suit your operational needs"
    if [[ -n "$template_file" ]]; then
        echo "  - Using template: ${template_file}"
    fi
    echo ""
}

# --- CONFIG JUNIPER (show working device config) ---
cmd_config_juniper() {
    local secret server_ip
    secret=$(get_config_value "secret")
    server_ip=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [[ -z "$server_ip" ]]; then
        server_ip="<TACQUITO_SERVER_IP>"
    fi

    # Collect all groups with their Juniper class and suggested Junos login class
    local group_juniper
    group_juniper=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
groups_match = re.search(r'^# --- Groups ---\s*\n(.*?)(?=^# --- Users|\Z)', config, re.MULTILINE | re.DOTALL)
if not groups_match:
    sys.exit(0)
for m in re.finditer(r'^(\w+): &\1\n  name: \1\n  services:\n(.*?)  accounter:', groups_match.group(1), re.MULTILINE | re.DOTALL):
    name = m.group(1)
    jm = re.search(r'\*junos_exec_(\w+)', m.group(2))
    if jm:
        svc = jm.group(1)
        jcm = re.search(r'junos_exec_' + svc + r':.*?values:\s*\[\"([^\"]+)\"\]', config, re.DOTALL)
        if jcm:
            jclass = jcm.group(1)
            # Suggest a Junos login class based on group name
            if 'super' in name or 'admin' in name:
                junos_class = 'super-user'
            elif 'readonly' in name or 'read' in name:
                junos_class = 'read-only'
            else:
                junos_class = 'operator'
            print(f'{name}|{jclass}|{junos_class}')
" "$CONFIG")

    # Build dynamic sections
    local TEMPLATE_USERS=""
    while IFS='|' read -r gname jclass junos_class; do
        [[ -z "$gname" ]] && continue
        TEMPLATE_USERS+="set system login user ${jclass} class ${junos_class}"$'\n'
    done <<< "$group_juniper"
    TEMPLATE_USERS="${TEMPLATE_USERS%$'\n'}"

    local TACPLUS_CONFIG
    TACPLUS_CONFIG="set system authentication-order [tacplus password]
set system tacplus-server ${server_ip} secret ${secret}
set system tacplus-server ${server_ip} single-connection
set system accounting events [ login change-log interactive-commands ]
set system accounting destination tacplus"

    local VERIFY_COMMANDS
    VERIFY_COMMANDS="  show configuration system tacplus-server
  show configuration system authentication-order"
    while IFS='|' read -r gname jclass junos_class; do
        [[ -z "$gname" ]] && continue
        VERIFY_COMMANDS+=$'\n'"  show configuration system login user ${jclass}"
    done <<< "$group_juniper"

    local GROUP_SUMMARY=""
    while IFS='|' read -r gname jclass junos_class; do
        [[ -z "$gname" ]] && continue
        GROUP_SUMMARY+="  ${gname}: ${jclass} (${junos_class})"$'\n'
    done <<< "$group_juniper"

    echo ""
    echo -e "${BOLD}Juniper Junos Configuration${NC}"
    echo -e "${YELLOW}Copy and paste into the device (configure mode):${NC}"
    echo "--------------------------------------------"
    echo ""

    local template_file
    template_file=$(resolve_template "juniper")
    if [[ -n "$template_file" ]]; then
        export SERVER_IP="$server_ip" SECRET="$secret" TEMPLATE_USERS TACPLUS_CONFIG VERIFY_COMMANDS GROUP_SUMMARY
        envsubst '${SERVER_IP} ${SECRET} ${TEMPLATE_USERS} ${TACPLUS_CONFIG} ${VERIFY_COMMANDS} ${GROUP_SUMMARY}' < "$template_file"
    else
        echo "# Step 1: Create template users (REQUIRED)"
        echo "$TEMPLATE_USERS"
        echo ""
        echo "# Step 2: Configure TACACS+"
        echo "$TACPLUS_CONFIG"
        echo ""
        echo "# Step 3: Commit"
        echo "commit"
    fi

    echo ""
    echo "--------------------------------------------"
    echo -e "${YELLOW}Group → Juniper Class Mapping:${NC}"
    echo -n "$GROUP_SUMMARY"
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - Template users MUST exist before TACACS+ logins will work"
    echo "  - The 'password' fallback in authentication-order ensures local access"
    echo "  - If a login fails silently, the template user is likely missing"
    echo "  - Adjust the Junos class (read-only/operator/super-user) as needed"
    if [[ -n "$template_file" ]]; then
        echo "  - Using template: ${template_file}"
    fi
    echo ""
    echo -e "${BOLD}Verify after commit:${NC}"
    echo "$VERIFY_COMMANDS"
    echo ""
}

# --- CONFIG ALLOW/DENY PREFIX FILTERS ---
cmd_config_prefix_filter() {
    local key="$1"
    local subcmd="${2:-list}"
    local cidr="${3:-}"
    local label
    [[ "$key" == "prefix_allow" ]] && label="allow" || label="deny"

    case "$subcmd" in
        list)
            echo ""
            echo -e "${BOLD}Connection ${label} list${NC}"
            echo "--------------------------------------------"
            local entries
            entries=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^' + sys.argv[2] + r':\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    for c in re.findall(r'\"([^\"]+)\"', m.group(1)):
        print(c)
else:
    print('EMPTY')
" "$CONFIG" "$key" || true)
            if [[ "$entries" == "EMPTY" ]]; then
                if [[ "$label" == "allow" ]]; then
                    echo "  (empty — all connections allowed)"
                else
                    echo "  (empty — no connections denied)"
                fi
            else
                echo "$entries" | while IFS= read -r entry; do
                    echo "  - ${entry}"
                done
            fi
            echo ""
            echo -e "  ${CYAN}Note: deny takes precedence over allow.${NC}"
            echo ""
            ;;
        add)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config ${label} add <cidr>"
                exit 1
            fi
            backup_config
            python3 -c "
import re, sys
config = open(sys.argv[1]).read()
key = sys.argv[2]
cidr = sys.argv[3]

m = re.search(r'^' + key + r':\s*\[(.*?)\]', config, re.MULTILINE)
if m:
    existing = m.group(1).strip()
    if existing:
        new_val = existing.rstrip() + ', \"' + cidr + '\"'
    else:
        new_val = '\"' + cidr + '\"'
    config = config.replace(m.group(0), key + ': [' + new_val + ']')
else:
    # Key doesn't exist yet — add it at the end of the file
    config = config.rstrip() + '\n\n' + key + ': [\"' + cidr + '\"]\n'

open(sys.argv[1], 'w').write(config)
" "$CONFIG" "$key" "$cidr"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Added '${cidr}' to ${label} list."
            echo ""
            ;;
        remove)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config ${label} remove <cidr>"
                exit 1
            fi
            backup_config
            python3 -c "
import re, sys
config = open(sys.argv[1]).read()
key = sys.argv[2]
cidr = sys.argv[3]

m = re.search(r'^' + key + r':\s*\[(.*?)\]', config, re.MULTILINE)
if m:
    entries = re.findall(r'\"([^\"]+)\"', m.group(1))
    entries = [e for e in entries if e != cidr]
    if entries:
        new_val = ', '.join('\"' + e + '\"' for e in entries)
        config = config.replace(m.group(0), key + ': [' + new_val + ']')
    else:
        # Remove the entire line if empty
        config = config.replace(m.group(0) + '\n', '')

open(sys.argv[1], 'w').write(config)
" "$CONFIG" "$key" "$cidr"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Removed '${cidr}' from ${label} list."
            echo ""
            ;;
        *)
            echo ""
            echo "Usage: sudo tacctl config ${label} <list|add|remove> [cidr]"
            echo ""
            exit 1
            ;;
    esac
}

# --- CONFIG dispatcher ---
cmd_config() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        show)
            cmd_config_show
            ;;
        secret)
            cmd_config_secret "$@"
            ;;
        juniper-ro)
            cmd_config_juniper_ro "$@"
            ;;
        juniper-rw)
            cmd_config_juniper_rw "$@"
            ;;
        prefixes)
            cmd_config_prefixes "$@"
            ;;
        cisco)
            cmd_config_cisco
            ;;
        juniper)
            cmd_config_juniper
            ;;
        validate)
            cmd_config_validate
            ;;
        loglevel)
            cmd_config_loglevel "$@"
            ;;
        password-age)
            cmd_config_password_age "$@"
            ;;
        diff)
            cmd_backup diff "$@"
            ;;
        allow)
            cmd_config_prefix_filter "prefix_allow" "$@"
            ;;
        deny)
            cmd_config_prefix_filter "prefix_deny" "$@"
            ;;
        *)
            echo ""
            echo -e "${BOLD}Config Commands${NC}"
            echo ""
            echo "Usage: sudo tacctl config <subcommand> [value]"
            echo ""
            echo "Subcommands:"
            echo "  show                          Show current configuration"
            echo "  validate                      Validate config syntax and structure"
            echo "  diff [timestamp]              Diff current config vs last backup"
            echo "  loglevel [debug|info|error]    Show or change log level"
            echo "  password-age [days]           Show or set password age warning threshold"
            echo "  secret [new-secret]           Change shared secret"
            echo "  juniper-ro [class-name]       Change Juniper read-only class name"
            echo "  juniper-rw [class-name]       Change Juniper super-user class name"
            echo "  prefixes [cidr,cidr,...]       Change allowed device subnets"
            echo "  allow list|add|remove          Manage connection allow list (IP ACL)"
            echo "  deny list|add|remove           Manage connection deny list (IP ACL)"
            echo "  cisco                         Show working Cisco device configuration"
            echo "  juniper                       Show working Juniper device configuration"
            echo ""
            echo "Examples:"
            echo "  sudo tacctl config show"
            echo "  sudo tacctl config validate"
            echo "  sudo tacctl config loglevel debug"
            echo "  sudo tacctl config cisco"
            echo "  sudo tacctl config prefixes 10.1.0.0/16,10.2.0.0/16"
            echo ""
            exit 1
            ;;
    esac
}

# =====================================================================
#  GROUP COMMANDS
# =====================================================================

# --- GROUP LIST ---
cmd_group_list() {
    echo ""
    echo -e "${BOLD}Tacquito Groups${NC}"
    echo "--------------------------------------------"
    printf "  ${BOLD}%-20s %-15s %-20s %-10s${NC}\n" "GROUP" "CISCO PRIV-LVL" "JUNIPER CLASS" "USERS"
    echo "  -------------------------------------------------------------------"

    python3 -c "
import re, sys

config = open(sys.argv[1]).read()

# Find groups section
groups_match = re.search(r'^# --- Groups ---\s*\n(.*?)(?=^# --- Users|\Z)', config, re.MULTILINE | re.DOTALL)
if not groups_match:
    sys.exit(0)

groups_section = groups_match.group(1)

# Find all group definitions
for m in re.finditer(r'^(\w+): &\1\n  name: \1\n  services:\n(.*?)  accounter:', groups_section, re.MULTILINE | re.DOTALL):
    name = m.group(1)
    services = m.group(2)

    # Extract Cisco priv-lvl
    priv = 'n/a'
    pm = re.search(r'\*exec_(\w+)', services)
    if pm:
        svc_name = pm.group(1)
        sm = re.search(r'exec_' + svc_name + r':.*?values:\s*\[(\d+)\]', config, re.DOTALL)
        if sm:
            priv = sm.group(1)

    # Extract Juniper class
    jclass = 'n/a'
    jm = re.search(r'\*junos_exec_(\w+)', services)
    if jm:
        svc_name = jm.group(1)
        jcm = re.search(r'junos_exec_' + svc_name + r':.*?values:\s*\[\"([^\"]+)\"\]', config, re.DOTALL)
        if jcm:
            jclass = jcm.group(1)

    # Count users in this group
    users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
    user_count = 0
    if users_match:
        user_count = len(re.findall(r'groups: \[\*' + re.escape(name) + r'\]', users_match.group(1)))

    print(f'{name}|{priv}|{jclass}|{user_count}')
" "$CONFIG" | while IFS='|' read -r name priv jclass user_count; do
        printf "  %-20s %-15s %-20s %-10s\n" "$name" "$priv" "$jclass" "$user_count"
    done

    echo ""
}

# --- GROUP ADD ---
cmd_group_add() {
    local groupname="${1:-}"
    local privlvl="${2:-}"
    local jclass="${3:-}"

    if [[ -z "$groupname" || -z "$privlvl" || -z "$jclass" ]]; then
        error "Usage: tacctl group add <name> <cisco-priv-lvl> <juniper-class>"
        echo "  Example: tacctl group add helpdesk 5 HELPDESK-CLASS" >&2
        exit 1
    fi

    # Validate group name
    if [[ ! "$groupname" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        error "Group name must be lowercase, starting with a letter."
        exit 1
    fi

    # Check if group already exists
    if grep -q "^${groupname}: &${groupname}$" "$CONFIG"; then
        error "Group '${groupname}' already exists."
        exit 1
    fi

    # Validate priv-lvl
    if ! [[ "$privlvl" =~ ^[0-9]+$ ]] || [[ "$privlvl" -lt 0 || "$privlvl" -gt 15 ]]; then
        error "Cisco privilege level must be 0-15."
        exit 1
    fi

    backup_config

    # Insert the new exec service, junos-exec service, and group before "# --- Groups ---"
    local groups_line
    groups_line=$(grep -n "^# --- Groups ---" "$CONFIG" | head -1 | cut -d: -f1)
    if [[ -z "$groups_line" ]]; then
        error "Cannot find groups section in config."
        exit 1
    fi

    # Build the new service + group block
    local block
    block=$(cat <<BLOCK

# Cisco exec - ${groupname} (priv-lvl ${privlvl})
exec_${groupname}: &exec_${groupname}
  name: exec
  set_values:
    - name: priv-lvl
      values: [${privlvl}]

# Juniper junos-exec - ${groupname}
# "${jclass}" must match a local template user on Juniper devices
junos_exec_${groupname}: &junos_exec_${groupname}
  name: junos-exec
  set_values:
    - name: local-user-name
      values: ["${jclass}"]

BLOCK
)

    # Insert services before "# --- Groups ---"
    python3 -c "
import sys
config = open(sys.argv[1]).read()
marker = '# --- Groups ---'
idx = config.index(marker)
new_block = sys.argv[2] + '\n'
config = config[:idx] + new_block + config[idx:]
open(sys.argv[1], 'w').write(config)
" "$CONFIG" "$block"

    # Insert group definition after the last existing group (before "# --- Users ---")
    local users_line
    users_line=$(grep -n "^# --- Users ---" "$CONFIG" | head -1 | cut -d: -f1)

    python3 -c "
import sys
lines = open(sys.argv[1]).readlines()
insert_at = int(sys.argv[2]) - 1
group_block = [
    '\n',
    sys.argv[3] + ': &' + sys.argv[3] + '\n',
    '  name: ' + sys.argv[3] + '\n',
    '  services:\n',
    '    - *exec_' + sys.argv[3] + '\n',
    '    - *junos_exec_' + sys.argv[3] + '\n',
    '  authenticator: *bcrypt_user\n',
    '  accounter: *file_accounter\n',
]
lines = lines[:insert_at] + group_block + lines[insert_at:]
open(sys.argv[1], 'w').writelines(lines)
" "$CONFIG" "$users_line" "$groupname"

    chown tacquito:tacquito "$CONFIG"
    restart_service

    info "Group '${groupname}' added (Cisco priv-lvl ${privlvl}, Juniper ${jclass})."
    warn "On Juniper devices, create the template user: set system login user ${jclass} class <junos-class>"
    echo ""
}

# --- GROUP REMOVE ---
cmd_group_remove() {
    local groupname="${1:-}"

    if [[ -z "$groupname" ]]; then
        error "Usage: tacctl group remove <name>"
        exit 1
    fi

    # Protect built-in groups
    if [[ "$groupname" == "readonly" || "$groupname" == "operator" || "$groupname" == "superuser" ]]; then
        error "Cannot remove built-in group '${groupname}'."
        exit 1
    fi

    # Check if group exists
    if ! grep -q "^${groupname}: &${groupname}$" "$CONFIG"; then
        error "Group '${groupname}' does not exist."
        exit 1
    fi

    # Check if any users are assigned to this group
    local user_count
    user_count=$(grep -c "groups: \[\*${groupname}\]" "$CONFIG" || true)
    if [[ "$user_count" -gt 0 ]]; then
        error "Cannot remove group '${groupname}' — ${user_count} user(s) are assigned to it."
        error "Reassign those users first."
        exit 1
    fi

    echo ""
    read -rp "  Remove group '${groupname}'? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    backup_config

    # Remove the exec service, junos-exec service, and group definition
    python3 -c "
import re, sys

groupname = sys.argv[2]
config = open(sys.argv[1]).read()

# Remove exec service block
config = re.sub(
    r'\n# Cisco exec - ' + re.escape(groupname) + r'.*?exec_' + re.escape(groupname) + r':.*?values: \[\d+\]\n',
    '\n', config, flags=re.DOTALL)

# Remove junos-exec service block
config = re.sub(
    r'\n# Juniper junos-exec - ' + re.escape(groupname) + r'.*?junos_exec_' + re.escape(groupname) + r':.*?values: \[\"[^\"]+\"\]\n',
    '\n', config, flags=re.DOTALL)

# Remove group definition block
config = re.sub(
    r'\n' + re.escape(groupname) + r': &' + re.escape(groupname) + r'\n  name: ' + re.escape(groupname) + r'\n.*?accounter: \*file_accounter\n',
    '\n', config, flags=re.DOTALL)

# Clean up double blank lines
config = re.sub(r'\n{3,}', '\n\n', config)

open(sys.argv[1], 'w').write(config)
" "$CONFIG" "$groupname"

    chown tacquito:tacquito "$CONFIG"
    restart_service

    info "Group '${groupname}' removed."
    echo ""
}

# --- GROUP EDIT ---
cmd_group_edit() {
    local groupname="${1:-}"
    local field="${2:-}"
    local value="${3:-}"

    if [[ -z "$groupname" || -z "$field" || -z "$value" ]]; then
        error "Usage: tacctl group edit <name> <priv-lvl|juniper-class> <value>"
        echo "  Example: tacctl group edit operator priv-lvl 10" >&2
        echo "  Example: tacctl group edit operator juniper-class NEW-CLASS" >&2
        exit 1
    fi

    # Check if group exists
    if ! grep -q "^${groupname}: &${groupname}$" "$CONFIG"; then
        error "Group '${groupname}' does not exist."
        exit 1
    fi

    backup_config

    case "$field" in
        priv-lvl)
            if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 0 || "$value" -gt 15 ]]; then
                error "Cisco privilege level must be 0-15."
                exit 1
            fi

            # Find the exec service for this group and update its priv-lvl
            python3 -c "
import re, sys
config = open(sys.argv[1]).read()
group = sys.argv[2]
new_val = sys.argv[3]

# Find the group block and extract the exec service reference
gm = re.search(r'^' + re.escape(group) + r': &' + re.escape(group) + r'\n  name:.*?\n  services:\n(.*?)  accounter:', config, re.MULTILINE | re.DOTALL)
if not gm:
    print('ERROR:Could not find group block')
    sys.exit(1)
sm = re.search(r'\*exec_(\w+)', gm.group(1))
if not sm:
    print('ERROR:Could not find exec service for group')
    sys.exit(1)
svc = sm.group(1)

# Find the exact service block and replace only its priv-lvl value
pattern = r'(exec_' + re.escape(svc) + r': &exec_' + re.escape(svc) + r'\n  name: exec\n  set_values:\n    - name: priv-lvl\n      values: \[)\d+(\])'
config = re.sub(pattern, r'\g<1>' + new_val + r'\2', config)

open(sys.argv[1], 'w').write(config)
print('OK')
" "$CONFIG" "$groupname" "$value"

            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Group '${groupname}' Cisco priv-lvl changed to ${value}."
            ;;

        juniper-class)
            # Find the junos-exec service for this group and update its local-user-name
            python3 -c "
import re, sys
config = open(sys.argv[1]).read()
group = sys.argv[2]
new_class = sys.argv[3]

# Find the group block and extract the junos-exec service reference
gm = re.search(r'^' + re.escape(group) + r': &' + re.escape(group) + r'\n  name:.*?\n  services:\n(.*?)  accounter:', config, re.MULTILINE | re.DOTALL)
if not gm:
    print('ERROR:Could not find group block')
    sys.exit(1)
sm = re.search(r'\*junos_exec_(\w+)', gm.group(1))
if not sm:
    print('ERROR:Could not find junos-exec service for group')
    sys.exit(1)
svc = sm.group(1)

# Find the exact service block and replace only its local-user-name value
pattern = r'(junos_exec_' + re.escape(svc) + r': &junos_exec_' + re.escape(svc) + r'\n  name: junos-exec\n  set_values:\n    - name: local-user-name\n      values: \[\")([^\"]+)(\"\])'
old_match = re.search(pattern, config)
if old_match:
    old_class = old_match.group(2)
    config = re.sub(pattern, r'\g<1>' + new_class + r'\3', config)
    # Update comment if present
    config = config.replace(
        '\"' + old_class + '\" must match',
        '\"' + new_class + '\" must match'
    )

open(sys.argv[1], 'w').write(config)
print('OK')
" "$CONFIG" "$groupname" "$value"

            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Group '${groupname}' Juniper class changed to ${value}."
            warn "On Juniper devices: set system login user ${value} class <junos-class>"
            ;;

        *)
            error "Unknown field '${field}'. Use: priv-lvl or juniper-class"
            exit 1
            ;;
    esac
    echo ""
}

# --- GROUP dispatcher ---
cmd_group() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        list)
            cmd_group_list
            ;;
        add)
            cmd_group_add "$@"
            ;;
        edit)
            cmd_group_edit "$@"
            ;;
        remove)
            cmd_group_remove "$@"
            ;;
        *)
            echo ""
            echo -e "${BOLD}Group Commands${NC}"
            echo ""
            echo "Usage: sudo tacctl group <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                                       List all groups"
            echo "  add <name> <priv-lvl> <juniper-class>      Add a new group"
            echo "  edit <name> priv-lvl <0-15>                Change Cisco privilege level"
            echo "  edit <name> juniper-class <CLASS>           Change Juniper class name"
            echo "  remove <name>                              Remove a custom group"
            echo ""
            echo "Examples:"
            echo "  sudo tacctl group list"
            echo "  sudo tacctl group add helpdesk 5 HELPDESK-CLASS"
            echo "  sudo tacctl group edit operator priv-lvl 10"
            echo "  sudo tacctl group edit operator juniper-class NEW-CLASS"
            echo "  sudo tacctl group remove helpdesk"
            echo ""
            exit 1
            ;;
    esac
}

# =====================================================================
#  STATUS & VALIDATION COMMANDS
# =====================================================================

# --- STATUS ---
cmd_status() {
    echo ""
    echo -e "${BOLD}Tacquito Service Status${NC}"
    echo "--------------------------------------------"

    # Service state
    local state
    state=$(systemctl is-active tacquito 2>/dev/null || echo "unknown")
    local state_color="$GREEN"
    [[ "$state" != "active" ]] && state_color="$RED"
    echo -e "  ${BOLD}Service:${NC}              ${state_color}${state}${NC}"

    # Uptime
    if [[ "$state" == "active" ]]; then
        local since
        since=$(systemctl show tacquito --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2)
        echo -e "  ${BOLD}Since:${NC}                ${since}"
    fi

    # PID
    local pid
    pid=$(systemctl show tacquito --property=MainPID 2>/dev/null | cut -d= -f2)
    if [[ -n "$pid" && "$pid" != "0" ]]; then
        echo -e "  ${BOLD}PID:${NC}                  ${pid}"
        # Memory usage
        local mem
        mem=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
        echo -e "  ${BOLD}Memory:${NC}               ${mem}"
    fi

    # Listening port
    local listen
    listen=$(ss -tlnp 2>/dev/null | grep ":49 " | awk '{print $4}' | head -1)
    if [[ -n "$listen" ]]; then
        echo -e "  ${BOLD}Listening:${NC}            ${GREEN}${listen}${NC}"
    else
        echo -e "  ${BOLD}Listening:${NC}            ${RED}port 49 not detected${NC}"
    fi

    # Log level
    local loglevel
    loglevel=$(systemctl show tacquito --property=ExecStart 2>/dev/null | grep -oP '\-level \K\d+')
    local level_name="unknown"
    case "$loglevel" in
        10) level_name="error" ;;
        20) level_name="info" ;;
        30) level_name="debug" ;;
    esac
    echo -e "  ${BOLD}Log level:${NC}            ${level_name} (${loglevel})"

    # User count
    local user_count
    user_count=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
if users_match:
    print(len(re.findall(r'- name:', users_match.group(1))))
else:
    print(0)
" "$CONFIG")
    echo -e "  ${BOLD}Users:${NC}                ${user_count}"

    # Config file
    echo -e "  ${BOLD}Config:${NC}               ${CONFIG}"

    # Accounting log size
    local acct_log="/var/log/tacquito/accounting.log"
    if [[ -f "$acct_log" ]]; then
        local log_size
        log_size=$(du -sh "$acct_log" 2>/dev/null | awk '{print $1}')
        local log_lines
        log_lines=$(wc -l < "$acct_log" 2>/dev/null)
        echo -e "  ${BOLD}Accounting log:${NC}       ${log_size} (${log_lines} entries)"
    fi

    # Backup count
    local backup_count
    backup_count=$(ls -1 "${BACKUP_DIR}"/tacquito.yaml.* 2>/dev/null | wc -l)
    echo -e "  ${BOLD}Config backups:${NC}       ${backup_count}"

    # Prometheus metrics — auth stats
    echo ""
    echo -e "  ${BOLD}Authentication Stats (since last restart):${NC}"
    local metrics
    metrics=$(curl -s http://localhost:8080/metrics 2>/dev/null || true)
    if [[ -n "$metrics" ]]; then
        local auth_pass auth_fail authz_pass authz_fail
        auth_pass=$(echo "$metrics" | grep -P '^tacquito_authenstart_handle_pap ' | awk '{print $2}' | head -1 || true)
        auth_fail=$(echo "$metrics" | grep -P '^tacquito_authenpap_handle_error ' | awk '{print $2}' | head -1 || true)
        authz_pass=$(echo "$metrics" | grep -P '^tacquito_stringy_handle_authorize_accept_pass_add ' | awk '{print $2}' | head -1 || true)
        authz_fail=$(echo "$metrics" | grep -P '^tacquito_stringy_handle_authorize_fail ' | awk '{print $2}' | head -1 || true)

        echo -e "    Auth attempts:      ${auth_pass:-0}"
        echo -e "    Auth errors:        ${auth_fail:-0}"
        echo -e "    Authz granted:      ${authz_pass:-0}"
        echo -e "    Authz denied:       ${authz_fail:-0}"
    else
        echo -e "    ${YELLOW}Metrics unavailable (http://localhost:8080/metrics)${NC}"
    fi

    # Recent errors
    echo ""
    echo -e "  ${BOLD}Recent Errors (last 5):${NC}"
    local errors
    errors=$(journalctl -u tacquito --no-pager -n 100 --since "24 hours ago" 2>/dev/null | grep "ERROR:" | tail -5 || true)
    if [[ -n "$errors" ]]; then
        echo "$errors" | while IFS= read -r line; do
            echo -e "    ${RED}${line}${NC}"
        done
    else
        echo -e "    ${GREEN}No errors in the last 24 hours${NC}"
    fi

    # Password age warnings
    echo ""
    echo -e "  ${BOLD}Password Age Warnings:${NC}"
    local pw_warnings=0
    local today
    today=$(date +%s)
    if [[ -d "$PASSWORD_DATES_DIR" ]]; then
        for datefile in "${PASSWORD_DATES_DIR}"/*.date; do
            [[ -f "$datefile" ]] || continue
            local uname pw_date pw_epoch age_days
            uname=$(basename "$datefile" .date)
            pw_date=$(cat "$datefile")
            pw_epoch=$(date -d "$pw_date" +%s 2>/dev/null || echo 0)
            if [[ "$pw_epoch" -gt 0 ]]; then
                age_days=$(( (today - pw_epoch) / 86400 ))
                if [[ "$age_days" -gt "$PASSWORD_MAX_AGE_DAYS" ]]; then
                    echo -e "    ${YELLOW}${uname}: password is ${age_days} days old (changed ${pw_date})${NC}"
                    pw_warnings=$((pw_warnings + 1))
                fi
            fi
        done
    fi
    if [[ "$pw_warnings" -eq 0 ]]; then
        echo -e "    ${GREEN}No passwords older than ${PASSWORD_MAX_AGE_DAYS} days${NC}"
    fi

    echo ""
}

# --- CONFIG VALIDATE ---
cmd_config_validate() {
    echo ""
    echo -e "${BOLD}Validating ${CONFIG}...${NC}"
    echo ""

    local errors=0

    # Check YAML syntax
    if python3 -c "import yaml; yaml.safe_load(open('$CONFIG'))" 2>/dev/null; then
        echo -e "  ${GREEN}YAML syntax:${NC}          valid"
    else
        echo -e "  ${RED}YAML syntax:${NC}          INVALID"
        python3 -c "import yaml; yaml.safe_load(open('$CONFIG'))" 2>&1 | head -3
        errors=$((errors + 1))
    fi

    # Check required sections exist
    local result
    result=$(python3 -c "
import re, sys

config = open(sys.argv[1]).read()
errors = []

# Check for users section
if not re.search(r'^users:', config, re.MULTILINE):
    errors.append('Missing users: section')

# Check for secrets section
if not re.search(r'^secrets:', config, re.MULTILINE):
    errors.append('Missing secrets: section')

# Check for at least one user
users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
if users_match:
    users = re.findall(r'- name: (\S+)', users_match.group(1))
    if len(users) == 0:
        errors.append('No users defined')
    else:
        # Check each user has a bcrypt anchor
        for u in users:
            if not re.search(r'^bcrypt_' + re.escape(u) + r':', config, re.MULTILINE):
                errors.append(f'User \"{u}\" has no bcrypt authenticator anchor')

        # Check for DISABLED or empty hashes
        for m in re.finditer(r'^bcrypt_(\w+):.*?hash:\s*(\S+)', config, re.MULTILINE | re.DOTALL):
            username = m.group(1)
            h = m.group(2)
            if h == 'REPLACE_ME':
                errors.append(f'User \"{username}\" has placeholder hash (REPLACE_ME)')
            elif h == 'DISABLED':
                pass  # valid state
            elif len(h) < 20:
                errors.append(f'User \"{username}\" has suspiciously short hash')

# Check shared secret
secret_match = re.search(r'key:\s*\"?([^\"\n]+)\"?', config)
if not secret_match:
    errors.append('No shared secret (key:) found in secrets section')
elif 'REPLACE' in secret_match.group(1):
    errors.append('Shared secret contains placeholder value')

# Check prefixes
prefix_match = re.search(r'prefixes:', config)
if not prefix_match:
    errors.append('No prefixes defined in secrets section')

if errors:
    for e in errors:
        print(f'ERROR:{e}')
else:
    print('OK')
" "$CONFIG")

    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}Config structure:${NC}      valid"
    else
        echo "$result" | while IFS= read -r line; do
            local msg="${line#ERROR:}"
            echo -e "  ${RED}Error:${NC}                ${msg}"
            errors=$((errors + 1))
        done
    fi

    # Check services
    local svc_count
    svc_count=$(grep -c "name: exec\|name: junos-exec" "$CONFIG" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}Services defined:${NC}     ${svc_count}"

    # Check groups
    local grp_count
    grp_count=$(grep -c "^[a-z].*: &" "$CONFIG" 2>/dev/null | head -1)
    echo -e "  ${GREEN}Groups/anchors:${NC}       ${grp_count}"

    # User count
    local user_count
    user_count=$(python3 -c "
import re
config = open('$CONFIG').read()
m = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
print(len(re.findall(r'- name:', m.group(1))) if m else 0)
")
    echo -e "  ${GREEN}Users defined:${NC}        ${user_count}"

    echo ""
    if [[ "$errors" -gt 0 ]]; then
        error "Validation failed with ${errors} error(s)."
        return 1
    else
        info "Configuration is valid."
    fi
    echo ""
}

# --- CONFIG LOGLEVEL ---
cmd_config_loglevel() {
    local new_level="${1:-}"
    local SERVICE_FILE="/etc/systemd/system/tacquito.service"

    if [[ -z "$new_level" ]]; then
        # Show current level
        local current
        current=$(grep -oP '\-level \K\d+' "$SERVICE_FILE" 2>/dev/null)
        local level_name="unknown"
        case "$current" in
            10) level_name="error" ;;
            20) level_name="info" ;;
            30) level_name="debug" ;;
        esac
        echo ""
        echo "  Current log level: ${level_name} (${current})"
        echo ""
        echo "  Usage: tacctl config loglevel <debug|info|error>"
        echo ""
        return
    fi

    local level_num
    case "$new_level" in
        debug)  level_num=30 ;;
        info)   level_num=20 ;;
        error)  level_num=10 ;;
        *)
            error "Invalid level: ${new_level}. Use: debug, info, or error"
            return 1
            ;;
    esac

    local current_num
    current_num=$(grep -oP '\-level \K\d+' "$SERVICE_FILE" 2>/dev/null)
    if [[ "$current_num" == "$level_num" ]]; then
        info "Already at ${new_level} (${level_num})."
        return
    fi

    sed -i "s/-level ${current_num}/-level ${level_num}/" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl restart tacquito

    info "Log level changed to ${new_level} (${level_num}). Service restarted."
    echo ""
}

# --- CONFIG PASSWORD-AGE ---
cmd_config_password_age() {
    local new_days="${1:-}"

    if [[ -z "$new_days" ]]; then
        echo ""
        echo "  Password age warning threshold: ${PASSWORD_MAX_AGE_DAYS} days"
        echo ""
        echo "  Usage: tacctl config password-age <days>"
        echo ""
        return
    fi

    if ! [[ "$new_days" =~ ^[0-9]+$ ]] || [[ "$new_days" -lt 1 ]]; then
        error "Days must be a positive number."
        exit 1
    fi

    echo "$new_days" > "$PASSWORD_MAX_AGE_FILE"
    PASSWORD_MAX_AGE_DAYS="$new_days"
    info "Password age warning threshold set to ${new_days} days."
    echo ""
}

# =====================================================================
#  LOG COMMANDS
# =====================================================================

cmd_log() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        tail)
            local count="${1:-20}"
            echo ""
            echo -e "${BOLD}Recent TACACS+ Log Entries${NC}"
            echo "--------------------------------------------"
            journalctl -u tacquito --no-pager -n "$count" 2>/dev/null || echo "  No log entries found."
            echo ""
            ;;
        search)
            local term="${1:-}"
            if [[ -z "$term" ]]; then
                error "Usage: tacctl log search <username>"
                exit 1
            fi
            echo ""
            echo -e "${BOLD}Log entries matching '${term}'${NC}"
            echo "--------------------------------------------"
            journalctl -u tacquito --no-pager --since "7 days ago" 2>/dev/null | grep -i "$term" || echo "  No matches found."
            echo ""
            ;;
        failures)
            echo ""
            echo -e "${BOLD}Authentication Failures (last 24 hours)${NC}"
            echo "--------------------------------------------"
            local failures
            failures=$(journalctl -u tacquito --no-pager --since "24 hours ago" 2>/dev/null | grep -i "ERROR\|fail\|bad secret" || true)
            if [[ -n "$failures" ]]; then
                echo "$failures"
            else
                echo -e "  ${GREEN}No failures in the last 24 hours${NC}"
            fi
            echo ""
            ;;
        accounting)
            local count="${1:-20}"
            echo ""
            echo -e "${BOLD}Recent Accounting Entries${NC}"
            echo "--------------------------------------------"
            if [[ -f "$ACCT_LOG" ]]; then
                tail -n "$count" "$ACCT_LOG"
            else
                echo "  No accounting log found at ${ACCT_LOG}"
            fi
            echo ""
            ;;
        *)
            echo ""
            echo -e "${BOLD}Log Commands${NC}"
            echo ""
            echo "Usage: sudo tacctl log <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  tail [n]              Show last N journal entries (default 20)"
            echo "  search <term>         Search journal for a username or keyword"
            echo "  failures              Show auth failures from the last 24 hours"
            echo "  accounting [n]        Show last N accounting log entries"
            echo ""
            exit 1
            ;;
    esac
}

# =====================================================================
#  BACKUP COMMANDS
# =====================================================================

cmd_backup() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        list)
            echo ""
            echo -e "${BOLD}Config Backups${NC}"
            echo "--------------------------------------------"
            if ls "${BACKUP_DIR}"/tacquito.yaml.* &>/dev/null; then
                printf "  ${BOLD}%-25s %-10s${NC}\n" "TIMESTAMP" "SIZE"
                echo "  -----------------------------------"
                ls -1t "${BACKUP_DIR}"/tacquito.yaml.* | while IFS= read -r f; do
                    local ts size
                    ts=$(basename "$f" | sed 's/tacquito\.yaml\.//')
                    size=$(du -sh "$f" 2>/dev/null | awk '{print $1}')
                    printf "  %-25s %-10s\n" "$ts" "$size"
                done
            else
                echo "  No backups found."
            fi
            echo ""
            ;;
        diff)
            local timestamp="${1:-}"
            local backup_file=""

            if [[ -z "$timestamp" ]]; then
                # Use most recent backup
                backup_file=$(ls -1t "${BACKUP_DIR}"/tacquito.yaml.* 2>/dev/null | head -1)
                if [[ -z "$backup_file" ]]; then
                    error "No backups found."
                    exit 1
                fi
            else
                backup_file="${BACKUP_DIR}/tacquito.yaml.${timestamp}"
                if [[ ! -f "$backup_file" ]]; then
                    error "Backup not found: ${timestamp}"
                    error "Run 'tacctl backup list' to see available backups."
                    exit 1
                fi
            fi

            local ts
            ts=$(basename "$backup_file" | sed 's/tacquito\.yaml\.//')
            echo ""
            echo -e "${BOLD}Diff: current config vs backup ${ts}${NC}"
            echo "--------------------------------------------"
            diff --color=always "$backup_file" "$CONFIG" || true
            echo ""
            ;;
        restore)
            local timestamp="${1:-}"
            if [[ -z "$timestamp" ]]; then
                error "Usage: tacctl backup restore <timestamp>"
                error "Run 'tacctl backup list' to see available backups."
                exit 1
            fi

            local backup_file="${BACKUP_DIR}/tacquito.yaml.${timestamp}"
            if [[ ! -f "$backup_file" ]]; then
                error "Backup not found: ${timestamp}"
                exit 1
            fi

            echo ""
            echo "  Restoring config from: ${timestamp}"
            echo ""
            echo -e "  ${BOLD}Changes that will be applied:${NC}"
            diff --color=always "$CONFIG" "$backup_file" || true
            echo ""

            read -rp "  Restore this backup? [y/N]: " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                info "Cancelled."
                exit 0
            fi

            # Back up current config before restoring (safety net)
            backup_config

            cp "$backup_file" "$CONFIG"
            chown tacquito:tacquito "$CONFIG"
            chmod 640 "$CONFIG"
            restart_service
            info "Config restored from backup ${timestamp}."
            echo ""
            ;;
        *)
            echo ""
            echo -e "${BOLD}Backup Commands${NC}"
            echo ""
            echo "Usage: sudo tacctl backup <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                  Show available backups"
            echo "  diff [timestamp]      Diff current config vs a backup (default: most recent)"
            echo "  restore <timestamp>   Restore a backup (with confirmation)"
            echo ""
            exit 1
            ;;
    esac
}

# =====================================================================
#  SYSTEM LIFECYCLE COMMANDS
# =====================================================================

# --- INSTALL ---
cmd_install() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (sudo tacctl install)"
        exit 1
    fi

    for cmd in git wget python3; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command '$cmd' not found. Install it first."
            exit 1
        fi
    done

    local PROJECT_DIR
    PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

    echo ""
    echo "============================================"
    echo "  Tacquito TACACS+ Server Installer"
    echo "============================================"
    echo ""
    echo "This will:"
    echo "  - Install Go ${GO_VERSION} (if not present)"
    echo "  - Clone and build tacquito from source"
    echo "  - Create a 'tacquito' service user"
    echo "  - Configure and start the TACACS+ service on port 49"
    echo "  - Prompt for shared secret and user passwords"
    echo ""

    read -rp "Continue with installation? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    echo ""

    # --- Step 1: Install Go ---
    if command -v /usr/local/go/bin/go &>/dev/null; then
        local CURRENT_GO
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

    # Clone management repo for future upgrades
    if [[ -d "${DEPLOY_DIR}/.git" ]]; then
        info "Management repo already cloned at ${DEPLOY_DIR}, pulling latest..."
        cd "$DEPLOY_DIR" && git pull --quiet 2>/dev/null || true
    elif [[ -d "$DEPLOY_DIR" ]]; then
        rm -rf "$DEPLOY_DIR"
        git clone --quiet "$MANAGE_REPO" "$DEPLOY_DIR"
        info "Management repo cloned to ${DEPLOY_DIR}"
    else
        git clone --quiet "$MANAGE_REPO" "$DEPLOY_DIR"
        info "Management repo cloned to ${DEPLOY_DIR}"
    fi

    # Symlink management CLI
    ln -sf "${DEPLOY_DIR}/bin/tacctl.sh" /usr/local/bin/tacctl
    cp "${PROJECT_DIR}/README.md" "${CONFIG_DIR}/README.md" 2>/dev/null || true
    # Install default config templates
    if [[ -d "${PROJECT_DIR}/config/templates" ]]; then
        mkdir -p "${CONFIG_DIR}/templates"
        cp -n "${PROJECT_DIR}/config/templates/"*.template "${CONFIG_DIR}/templates/" 2>/dev/null || true
        info "Config templates installed: ${CONFIG_DIR}/templates/"
    fi
    # Install logrotate config
    if [[ -f "${PROJECT_DIR}/config/tacquito.logrotate" ]]; then
        cp "${PROJECT_DIR}/config/tacquito.logrotate" /etc/logrotate.d/tacquito
        info "Log rotation installed: /etc/logrotate.d/tacquito"
    fi

    info "Management CLI installed:"
    info "  tacctl — user, config, and system management"
    info "  Deploy source: ${DEPLOY_DIR}"

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
    local SHARED_SECRET=""
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

    local install_prompt_password
    install_prompt_password() {
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

        local hash
        hash=$(generate_hash "$password")

        LAST_HASH="$hash"
        LAST_PASSWORD="$password"
    }

    local LAST_HASH="" LAST_PASSWORD=""

    install_prompt_password "user" "read-only"
    local HASH_USER="$LAST_HASH" PW_USER="$LAST_PASSWORD"

    install_prompt_password "operations" "operator, Operations"
    local HASH_OPERATIONS="$LAST_HASH" PW_OPERATIONS="$LAST_PASSWORD"

    install_prompt_password "engineering" "super-user"
    local HASH_ENGINEERING="$LAST_HASH" PW_ENGINEERING="$LAST_PASSWORD"

    # --- Step 7: Write configuration ---
    local CONFIG_FILE="${CONFIG_DIR}/tacquito.yaml"
    info "Writing configuration to ${CONFIG_FILE}..."

    cp "${PROJECT_DIR}/config/tacquito.yaml" "$CONFIG_FILE"

    sed -i "s|hash: REPLACE_ME|hash: ${HASH_USER}|" "$CONFIG_FILE"
    sed -i "0,/hash: REPLACE_ME/{s|hash: REPLACE_ME|hash: ${HASH_OPERATIONS}|}" "$CONFIG_FILE"
    sed -i "0,/hash: REPLACE_ME/{s|hash: REPLACE_ME|hash: ${HASH_ENGINEERING}|}" "$CONFIG_FILE"
    sed -i "s|REPLACE_WITH_SHARED_SECRET|${SHARED_SECRET}|" "$CONFIG_FILE"

    chown tacquito:tacquito "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"

    mkdir -p "$PASSWORD_DATES_DIR"
    for u in user operations engineering; do
        date +%Y-%m-%d > "${PASSWORD_DATES_DIR}/${u}.date"
    done
    info "Password dates recorded."

    # --- Step 8: Install systemd service ---
    info "Installing systemd service..."
    cp "${PROJECT_DIR}/config/tacquito.service" "$SERVICE_FILE"
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
    local LISTEN_CHECK
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
}

# --- UPGRADE ---
cmd_upgrade() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (sudo tacctl upgrade)"
        exit 1
    fi

    if [[ ! -d "$TACQUITO_SRC" ]]; then
        error "Tacquito source not found at ${TACQUITO_SRC}. Run 'tacctl install' first."
        exit 1
    fi

    if [[ ! -x "$GO_BIN" ]]; then
        error "Go not found at ${GO_BIN}. Install Go first."
        exit 1
    fi

    export PATH=$PATH:/usr/local/go/bin

    local PROJECT_DIR
    PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

    echo ""
    echo "============================================"
    echo "  Tacquito Upgrade"
    echo "============================================"
    echo ""

    # --- Record current version ---
    local CURRENT_COMMIT
    CURRENT_COMMIT=$(cd "$TACQUITO_SRC" && git rev-parse --short HEAD)
    info "Current commit: ${CURRENT_COMMIT}"

    # --- Pull latest source ---
    info "Pulling latest source..."
    cd "$TACQUITO_SRC"
    git fetch --quiet
    local LOCAL REMOTE SKIP_BUILD NEW_COMMIT
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse @{u})

    if [[ "$LOCAL" == "$REMOTE" ]]; then
        info "Tacquito source already up to date (${CURRENT_COMMIT})."
        SKIP_BUILD=true
    else
        SKIP_BUILD=false
        if [[ -f "$TACQUITO_BIN" ]]; then
            cp "$TACQUITO_BIN" "${TACQUITO_BIN}.bak"
            info "Backed up current binary to ${TACQUITO_BIN}.bak"
        fi
    fi

    if [[ "$SKIP_BUILD" == "false" ]]; then
        git pull --quiet
        NEW_COMMIT=$(git rev-parse --short HEAD)
        info "Updated: ${CURRENT_COMMIT} -> ${NEW_COMMIT}"

        echo ""
        info "Changes:"
        git log --oneline "${CURRENT_COMMIT}..${NEW_COMMIT}" | head -20
        echo ""

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
    if [[ -d "${DEPLOY_DIR}/.git" ]]; then
        info "Pulling latest management scripts..."
        cd "$DEPLOY_DIR"
        git fetch --quiet 2>/dev/null || true
        local LOCAL_MANAGE REMOTE_MANAGE
        LOCAL_MANAGE=$(git rev-parse HEAD 2>/dev/null)
        REMOTE_MANAGE=$(git rev-parse @{u} 2>/dev/null || echo "")
        if [[ -n "$REMOTE_MANAGE" && "$LOCAL_MANAGE" != "$REMOTE_MANAGE" ]]; then
            # Copy self to temp before pull (git pull will overwrite the running script)
            local SELF_TMP
            SELF_TMP=$(mktemp)
            cp "${DEPLOY_DIR}/bin/tacctl.sh" "$SELF_TMP"

            git pull --quiet 2>/dev/null
            info "Management scripts updated: $(git rev-parse --short HEAD)"

            # If tacctl changed, re-run the new version
            if ! diff -q "$SELF_TMP" "${DEPLOY_DIR}/bin/tacctl.sh" &>/dev/null; then
                rm -f "$SELF_TMP"
                info "tacctl updated — restarting upgrade with new version..."
                exec "${DEPLOY_DIR}/bin/tacctl.sh" upgrade
            fi
            rm -f "$SELF_TMP"
        else
            info "Management scripts already up to date."
        fi
    elif [[ ! -d "$DEPLOY_DIR" ]]; then
        info "Cloning management repo..."
        git clone --quiet "$MANAGE_REPO" "$DEPLOY_DIR" 2>/dev/null || warn "Failed to clone management repo."
    fi

    # --- Ensure symlink exists ---
    if [[ -d "$DEPLOY_DIR" ]]; then
        ln -sf "${DEPLOY_DIR}/bin/tacctl.sh" /usr/local/bin/tacctl
    fi

    # --- Update system config files ---
    info "Updating system files..."
    local SCRIPTS_UPDATED=0
    local ACTIVE_DEPLOY_DIR="$DEPLOY_DIR"

    if [[ ! -d "$ACTIVE_DEPLOY_DIR" ]]; then
        # Fall back to script's own project dir
        ACTIVE_DEPLOY_DIR="$PROJECT_DIR"
    fi

    if [[ -z "$ACTIVE_DEPLOY_DIR" ]]; then
        warn "Deploy directory not found. Skipping updates."
        warn "To fix: clone the repo to ${DEPLOY_DIR}"
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

    if [[ -f "${ACTIVE_DEPLOY_DIR}/config/tacquito.service" ]]; then
        if ! diff -q "${ACTIVE_DEPLOY_DIR}/config/tacquito.service" "$SERVICE_FILE" &>/dev/null; then
            cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"
            cp "${ACTIVE_DEPLOY_DIR}/config/tacquito.service" "$SERVICE_FILE"
            systemctl daemon-reload
            info "  Updated: tacquito.service (previous backed up to ${SERVICE_FILE}.bak)"
            SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
        else
            info "  Unchanged: tacquito.service"
        fi
    fi

    update_if_changed "${ACTIVE_DEPLOY_DIR}/README.md" "${CONFIG_DIR}/README.md" "README.md"
    update_if_changed "${ACTIVE_DEPLOY_DIR}/config/tacquito.logrotate" "/etc/logrotate.d/tacquito" "logrotate config"

    # Update default config templates (only if user hasn't customized them)
    if [[ -d "${ACTIVE_DEPLOY_DIR}/config/templates" ]]; then
        mkdir -p "${CONFIG_DIR}/templates"
        for tmpl in "${ACTIVE_DEPLOY_DIR}/config/templates/"*.template; do
            [[ -f "$tmpl" ]] || continue
            local tmpl_name dest
            tmpl_name=$(basename "$tmpl")
            dest="${CONFIG_DIR}/templates/${tmpl_name}"
            if [[ ! -f "$dest" ]]; then
                cp "$tmpl" "$dest"
                info "  Installed: ${tmpl_name}"
                SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
            else
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

        local LISTEN_CHECK
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
}

# --- UNINSTALL ---
cmd_uninstall() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (sudo tacctl uninstall)"
        exit 1
    fi

    echo ""
    echo "============================================"
    echo -e "  ${RED}Tacquito Uninstaller${NC}"
    echo "============================================"
    echo ""
    echo "This will remove:"
    echo "  - Tacquito service and binary"
    echo "  - Management CLI (tacctl)"
    echo "  - Password hash generator (tacquito-hashgen)"
    echo "  - Configuration directory (/etc/tacquito)"
    echo "  - Log directory (/var/log/tacquito)"
    echo "  - Logrotate config"
    echo "  - Service user (tacquito)"
    echo "  - Management repo (${DEPLOY_DIR})"
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
    local PRESERVE_BACKUPS=false PRESERVE_LOGS=false

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
    rm -f /usr/local/bin/tacctl
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
    local BACKUP_ARCHIVE="" LOG_ARCHIVE=""
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
    rm -rf "$DEPLOY_DIR"

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
    echo "    - Management CLI and symlinks"
    echo "    - Configuration and systemd unit"
    echo "    - Logrotate config"
    echo "    - Service user"
    if [[ "$PRESERVE_BACKUPS" == "true" && -n "$BACKUP_ARCHIVE" ]]; then
        echo "    - Config backups saved to: ${BACKUP_ARCHIVE}"
    fi
    if [[ "$PRESERVE_LOGS" == "true" && -n "$LOG_ARCHIVE" ]]; then
        echo "    - Accounting logs saved to: ${LOG_ARCHIVE}"
    fi
    echo ""
    echo "  Not removed:"
    echo "    - Go installation (/usr/local/go)"
    echo "    - Tacquito source (/opt/tacquito-src)"
    echo "    - python3-bcrypt package"
    echo ""
}

# =====================================================================
#  MAIN
# =====================================================================

usage() {
    echo ""
    echo -e "${BOLD}Tacquito Management${NC}"
    echo ""
    echo "Usage: sudo tacctl <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  install                       Install tacquito server and configure from scratch"
    echo "  upgrade                       Pull latest source, rebuild, and update scripts"
    echo "  uninstall                     Remove tacquito and all associated files"
    echo "  status                        Show service health, stats, and recent errors"
    echo "  user <subcommand>             User management (list, add, remove, passwd, ...)"
    echo "  group <subcommand>            Group management (list, add, edit, remove)"
    echo "  config <subcommand>           Configuration (show, cisco, juniper, secret, ...)"
    echo "  log <subcommand>              Log viewer (tail, search, failures, accounting)"
    echo "  backup <subcommand>           Backup management (list, diff, restore)"
    echo ""
    echo "Run any command without arguments for detailed help, e.g.:"
    echo "  sudo tacctl user"
    echo "  sudo tacctl config"
    echo ""
    echo "Examples:"
    echo "  sudo tacctl install"
    echo "  sudo tacctl upgrade"
    echo "  sudo tacctl user add jsmith superuser"
    echo "  sudo tacctl user move jsmith operator"
    echo "  sudo tacctl config cisco"
    echo ""
}

COMMAND="${1:-}"
shift || true

# --- USER dispatcher ---
cmd_user() {
    local subcmd="${1:-help}"
    shift || true

    case "$subcmd" in
        list)       cmd_list ;;
        add)        cmd_add "$@" ;;
        remove)     cmd_remove "$@" ;;
        passwd)     cmd_passwd "$@" ;;
        disable)    cmd_disable "$@" ;;
        enable)     cmd_enable "$@" ;;
        rename)     cmd_rename "$@" ;;
        move)       cmd_move "$@" ;;
        verify)     cmd_verify "$@" ;;
        *)
            echo ""
            echo -e "${BOLD}User Commands${NC}"
            echo ""
            echo "Usage: sudo tacctl user <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                          List all users and their status"
            echo "  add <username> <group>        Add a new user"
            echo "  remove <username>             Remove a user"
            echo "  passwd <username>             Change a user's password"
            echo "  disable <username>            Disable a user (preserves hash)"
            echo "  enable <username>             Re-enable a disabled user"
            echo "  rename <old> <new>            Rename a user"
            echo "  move <user> <group>           Move user to a different group"
            echo "  verify <username>             Verify password and show user details"
            echo ""
            echo "Examples:"
            echo "  sudo tacctl user list"
            echo "  sudo tacctl user add jsmith superuser"
            echo "  sudo tacctl user move jsmith operator"
            echo "  sudo tacctl user verify jsmith"
            echo ""
            exit 1
            ;;
    esac
}

case "$COMMAND" in
    install)
        cmd_install "$@"
        ;;
    upgrade)
        cmd_upgrade "$@"
        ;;
    uninstall)
        cmd_uninstall "$@"
        ;;
    status)
        preflight
        cmd_status
        ;;
    user)
        preflight
        cmd_user "$@"
        ;;
    group)
        preflight
        cmd_group "$@"
        ;;
    config)
        preflight
        cmd_config "$@"
        ;;
    log)
        preflight
        cmd_log "$@"
        ;;
    backup)
        preflight
        cmd_backup "$@"
        ;;
    *)
        usage
        exit 1
        ;;
esac
