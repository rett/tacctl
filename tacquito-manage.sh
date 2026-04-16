#!/usr/bin/env bash
#
# Tacquito TACACS+ Server — Management Script
#
# Manage local TACACS+ users and server configuration.
# Changes are applied to /etc/tacquito/tacquito.yaml and hot-reloaded automatically.
#
# Usage:
#   sudo ./tacquito-manage.sh list
#   sudo ./tacquito-manage.sh add <username> <readonly|superuser>
#   sudo ./tacquito-manage.sh remove <username>
#   sudo ./tacquito-manage.sh passwd <username>
#   sudo ./tacquito-manage.sh disable <username>
#   sudo ./tacquito-manage.sh enable <username>
#   sudo ./tacquito-manage.sh verify <username>
#   sudo ./tacquito-manage.sh config show
#   sudo ./tacquito-manage.sh config secret [new-secret]
#   sudo ./tacquito-manage.sh config juniper-ro [class-name]
#   sudo ./tacquito-manage.sh config juniper-rw [class-name]
#   sudo ./tacquito-manage.sh config prefixes [cidr,cidr,...]
#
set -euo pipefail

CONFIG="/etc/tacquito/tacquito.yaml"
BACKUP_DIR="/etc/tacquito/backups"

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
        error "This script must be run as root (sudo ./tacquito-manage.sh ...)"
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

# --- Restart service after config changes ---
# sed -i and python rewrites change the file inode, breaking fsnotify hot-reload.
restart_service() {
    systemctl restart tacquito 2>/dev/null && info "Service restarted." || warn "Service restart failed — run: sudo systemctl restart tacquito"
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
    # Look at the user entry and find the group reference
    awk "/^  - name: ${username}$/,/^  - name:/" "$CONFIG" | grep "groups:" | head -1 | \
        sed 's/.*\[\*\(.*\)\]/\1/'
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
    printf "  ${BOLD}%-20s %-15s %-10s${NC}\n" "USERNAME" "GROUP" "STATUS"
    echo "  ---------------------------------------------------"

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
        printf "  %-20s %-15s ${color}%-10s${NC}\n" "$username" "$group" "$status"
    done

    echo ""
}

# --- ADD ---
cmd_add() {
    local username="${1:-}"
    local group="${2:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacquito-manage.sh add <username> <readonly|operator|superuser>"
        exit 1
    fi
    # Validate group exists in config
    if ! grep -q "^${group}: &${group}$" "$CONFIG"; then
        local available
        available=$(grep -oP '^\w+(?=: &\w)' "$CONFIG" | grep -v "^bcrypt_\|^exec_\|^junos_\|^file_\|^authenticator\|^action\|^accounter\|^handler\|^provider" | tr '\n' '|' | sed 's/|$//')
        error "Group '${group}' does not exist. Available: ${available}"
        error "Usage: tacquito-manage.sh add <username> <group>"
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
    info "User '${username}' added (${group})."
    echo ""
}

# --- REMOVE ---
cmd_remove() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacquito-manage.sh remove <username>"
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
        error "Usage: tacquito-manage.sh passwd <username>"
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
    info "Password changed for '${username}'."
    echo ""
}

# --- DISABLE ---
cmd_disable() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacquito-manage.sh disable <username>"
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
        error "Usage: tacquito-manage.sh enable <username>"
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
        error "  sudo ./tacquito-manage.sh passwd ${username}"
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
        error "Usage: tacquito-manage.sh verify <username>"
        exit 1
    fi
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local stored_hash
    stored_hash=$(get_user_hash "$username")
    if [[ "$stored_hash" == "DISABLED" ]]; then
        error "User '${username}' is disabled."
        exit 1
    fi

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
        error "Usage: tacquito-manage.sh rename <old-username> <new-username>"
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

    restart_service
    info "User renamed: ${oldname} -> ${newname}"
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

    echo ""
    echo -e "${BOLD}Cisco IOS / IOS-XE Configuration${NC}"
    echo -e "${YELLOW}Copy and paste into the device:${NC}"
    echo "--------------------------------------------"
    echo ""
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
EOF

    # Generate privilege level command mappings for each non-standard group
    echo "$group_info" | while IFS='|' read -r gname privlvl; do
        [[ "$privlvl" == "1" || "$privlvl" == "15" ]] && continue
        cat <<EOF
! --- ${gname} — Privilege Level ${privlvl} Commands ---
privilege exec level ${privlvl} clear counters
privilege exec level ${privlvl} clear ip bgp
privilege exec level ${privlvl} clear ip ospf
privilege exec level ${privlvl} clear ip route
privilege exec level ${privlvl} clear logging
privilege exec level ${privlvl} clear arp-cache
privilege exec level ${privlvl} debug
privilege exec level ${privlvl} undebug all
privilege exec level ${privlvl} show running-config
privilege exec level ${privlvl} show startup-config
privilege exec level ${privlvl} ping
privilege exec level ${privlvl} traceroute
privilege exec level ${privlvl} terminal monitor
privilege exec level ${privlvl} terminal no monitor
!
EOF
    done

    cat <<EOF
line vty 0 15
  login authentication default
EOF
    echo ""
    echo "--------------------------------------------"
    echo -e "${YELLOW}Group → Privilege Level Mapping:${NC}"
    echo "$group_info" | while IFS='|' read -r gname privlvl; do
        echo "  ${gname}: priv-lvl ${privlvl}"
    done
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - The 'local' fallback ensures access if TACACS+ is unreachable"
    echo "  - Ensure a local admin account exists as a backup"
    echo "  - Custom privilege levels (2-14) require the 'privilege exec level' mappings above"
    echo "  - Adjust mapped commands to suit your operational needs"
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

    echo ""
    echo -e "${BOLD}Juniper Junos Configuration${NC}"
    echo -e "${YELLOW}Copy and paste into the device (configure mode):${NC}"
    echo "--------------------------------------------"
    echo ""
    echo "# Step 1: Create template users (REQUIRED)"
    echo "$group_juniper" | while IFS='|' read -r gname jclass junos_class; do
        echo "set system login user ${jclass} class ${junos_class}"
    done
    echo ""
    echo "# Step 2: Configure TACACS+"
    cat <<EOF
set system authentication-order [tacplus password]
set system tacplus-server ${server_ip} secret ${secret}
set system tacplus-server ${server_ip} single-connection
set system accounting events [ login change-log interactive-commands ]
set system accounting destination tacplus
EOF
    echo ""
    echo "# Step 3: Commit"
    echo "commit"
    echo ""
    echo "--------------------------------------------"
    echo -e "${YELLOW}Group → Juniper Class Mapping:${NC}"
    echo "$group_juniper" | while IFS='|' read -r gname jclass junos_class; do
        echo "  ${gname}: ${jclass} (${junos_class})"
    done
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - Template users MUST exist before TACACS+ logins will work"
    echo "  - The 'password' fallback in authentication-order ensures local access"
    echo "  - If a login fails silently, the template user is likely missing"
    echo "  - Adjust the Junos class (read-only/operator/super-user) as needed"
    echo ""
    echo -e "${BOLD}Verify after commit:${NC}"
    echo "  show configuration system tacplus-server"
    echo "  show configuration system authentication-order"
    echo "$group_juniper" | while IFS='|' read -r gname jclass junos_class; do
        echo "  show configuration system login user ${jclass}"
    done
    echo ""
}

# --- CONFIG dispatcher ---
cmd_config() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        show|"")
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
        *)
            echo ""
            echo -e "${BOLD}Config Commands${NC}"
            echo ""
            echo "Usage: sudo tacquito-manage config <subcommand> [value]"
            echo ""
            echo "Subcommands:"
            echo "  show                          Show current configuration"
            echo "  validate                      Validate config syntax and structure"
            echo "  loglevel [debug|info|error]    Show or change log level"
            echo "  secret [new-secret]           Change shared secret"
            echo "  juniper-ro [class-name]       Change Juniper read-only class name"
            echo "  juniper-rw [class-name]       Change Juniper super-user class name"
            echo "  prefixes [cidr,cidr,...]       Change allowed device subnets"
            echo "  cisco                         Show working Cisco device configuration"
            echo "  juniper                       Show working Juniper device configuration"
            echo ""
            echo "Examples:"
            echo "  sudo tacquito-manage config show"
            echo "  sudo tacquito-manage config validate"
            echo "  sudo tacquito-manage config loglevel debug"
            echo "  sudo tacquito-manage config cisco"
            echo "  sudo tacquito-manage config prefixes 10.1.0.0/16,10.2.0.0/16"
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
        error "Usage: tacquito-manage group add <name> <cisco-priv-lvl> <juniper-class>"
        echo "  Example: tacquito-manage group add helpdesk 5 HELPDESK-CLASS" >&2
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
        error "Usage: tacquito-manage group remove <name>"
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
        error "Usage: tacquito-manage group edit <name> <priv-lvl|juniper-class> <value>"
        echo "  Example: tacquito-manage group edit operator priv-lvl 10" >&2
        echo "  Example: tacquito-manage group edit operator juniper-class NEW-CLASS" >&2
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
        list|"")
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
            echo "Usage: sudo tacquito-manage group <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                                       List all groups"
            echo "  add <name> <priv-lvl> <juniper-class>      Add a new group"
            echo "  edit <name> priv-lvl <0-15>                Change Cisco privilege level"
            echo "  edit <name> juniper-class <CLASS>           Change Juniper class name"
            echo "  remove <name>                              Remove a custom group"
            echo ""
            echo "Examples:"
            echo "  sudo tacquito-manage group list"
            echo "  sudo tacquito-manage group add helpdesk 5 HELPDESK-CLASS"
            echo "  sudo tacquito-manage group edit operator priv-lvl 10"
            echo "  sudo tacquito-manage group edit operator juniper-class NEW-CLASS"
            echo "  sudo tacquito-manage group remove helpdesk"
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
        echo "  Usage: tacquito-manage config loglevel <debug|info|error>"
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

# =====================================================================
#  MAIN
# =====================================================================

usage() {
    echo ""
    echo -e "${BOLD}Tacquito Management${NC}"
    echo ""
    echo "Usage: sudo tacquito-manage <command> [arguments]"
    echo ""
    echo "General:"
    echo "  status                        Show service health, stats, and recent errors"
    echo ""
    echo "User Commands:"
    echo "  list                          List all users and their status"
    echo "  add <username> <group>        Add a new user (group: readonly|operator|superuser)"
    echo "  remove <username>             Remove a user"
    echo "  passwd <username>             Change a user's password"
    echo "  disable <username>            Disable a user (preserves hash for re-enable)"
    echo "  enable <username>             Re-enable a disabled user"
    echo "  rename <old> <new>            Rename a user"
    echo "  verify <username>             Test a password against stored hash"
    echo ""
    echo "Group Commands:"
    echo "  group list                    List all groups with details"
    echo "  group add <n> <pl> <jc>       Add group (name, priv-lvl, juniper-class)"
    echo "  group edit <n> <field> <val>  Edit group (priv-lvl or juniper-class)"
    echo "  group remove <name>           Remove a custom group"
    echo ""
    echo "Config Commands:"
    echo "  config show                   Show current configuration"
    echo "  config cisco                  Show working Cisco device configuration"
    echo "  config juniper                Show working Juniper device configuration"
    echo "  config secret [value]         Change shared secret"
    echo "  config juniper-ro [class]     Change Juniper read-only class name"
    echo "  config juniper-rw [class]     Change Juniper super-user class name"
    echo "  config prefixes [cidr,...]    Change allowed device subnets"
    echo "  config validate              Validate config syntax and structure"
    echo "  config loglevel [level]      Show or change log level (debug|info|error)"
    echo ""
    echo "Examples:"
    echo "  sudo tacquito-manage add jsmith superuser"
    echo "  sudo tacquito-manage passwd user"
    echo "  sudo tacquito-manage config show"
    echo "  sudo tacquito-manage config juniper-ro RO-CLASS"
    echo "  sudo tacquito-manage config prefixes 10.1.0.0/16,10.2.0.0/16"
    echo ""
}

COMMAND="${1:-}"
shift || true

case "$COMMAND" in
    status)
        preflight
        cmd_status
        ;;
    list)
        preflight
        cmd_list
        ;;
    add)
        preflight
        cmd_add "$@"
        ;;
    remove)
        preflight
        cmd_remove "$@"
        ;;
    passwd)
        preflight
        cmd_passwd "$@"
        ;;
    disable)
        preflight
        cmd_disable "$@"
        ;;
    enable)
        preflight
        cmd_enable "$@"
        ;;
    verify)
        preflight
        cmd_verify "$@"
        ;;
    rename)
        preflight
        cmd_rename "$@"
        ;;
    group)
        preflight
        cmd_group "$@"
        ;;
    config)
        preflight
        cmd_config "$@"
        ;;
    *)
        usage
        exit 1
        ;;
esac
