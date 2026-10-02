# shellcheck shell=bash
# tacctl lib/users.sh -- user data-model helpers, password/hash helpers, user and hash commands
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# --- Disabled-user hash marker ---
# Well-formed but unverifiable bcrypt hash: '$2b$12$' + 53 '.' chars
# (all-zero salt + all-zero digest). Valid bcrypt structure so tacquito
# parses it, but no real password can match. Stored hex-encoded.
# Hex of "$2b$12$" + "." × 53:
DISABLED_MARKER_HEX="24326224313224"
DISABLED_MARKER_HEX+="2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"
DISABLED_MARKER_HEX+="2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"

is_disabled_hash() {
    [[ "$1" == "$DISABLED_MARKER_HEX" ]]
}

# --- Track password change date ---
record_password_date() {
    local username="$1"
    mkdir -p "$PASSWORD_DATES_DIR"
    chmod 750 "$PASSWORD_DATES_DIR"
    chown tacquito:tacquito "$PASSWORD_DATES_DIR" 2>/dev/null || true
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

# --- Generate bcrypt hex hash from password ---
# Password is passed via stdin (not argv) so it never lands in
# /proc/<pid>/cmdline, which is world-readable on Linux by default.
generate_hash() {
    local password="$1"
    printf '%s' "$password" | python3 -c '
import bcrypt, binascii, sys
pw = sys.stdin.buffer.read()
rounds = int(sys.argv[1])
h = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=rounds))
print(binascii.hexlify(h).decode())
' "$BCRYPT_COST"
}

# --- Normalize a bcrypt hash to the hex-encoded form tacquito reads ---
# Accepts either:
#   - raw form ('$2b$...', '$2a$...', '$2y$...') — hex-encoded on emit
#   - already hex-encoded (e.g. `tacctl hash` output) — lower-cased on emit
# Prints the hex-encoded result on stdout, or nothing if the input is
# not a recognizable bcrypt hash. Caller treats empty output as rejection.
normalize_bcrypt_hash() {
    local input="$1"
    # Route the candidate hash through stdin so it does not appear on argv
    # (/proc/<pid>/cmdline). The raw `$2b$...` form is a credential-equivalent
    # offline-crack target; the hex form is also stored in the YAML but we
    # keep the subprocess boundary tight regardless.
    # shellcheck disable=SC2016  # python source; the $2b$ prefixes are literal
    printf '%s' "$input" | python3 -c '
import binascii, re, sys
s = sys.stdin.read()
# Raw form: "$2a$..", "$2b$..", "$2y$..". Hex-encode for storage.
if re.match(r"^\$2[aby]\$", s):
    print(binascii.hexlify(s.encode()).decode())
    sys.exit(0)
# Hex form must hex-decode to the raw prefix.
try:
    decoded = binascii.unhexlify(s).decode("ascii")
    if re.match(r"^\$2[aby]\$", decoded):
        print(s.lower())
        sys.exit(0)
except (binascii.Error, ValueError, UnicodeDecodeError):
    pass
'
}

# --- Verify a password against a stored hash ---
# Password via stdin (see generate_hash rationale). Hash travels via argv
# because it is already on-disk in the config; not additionally sensitive.
# checkpw returns bool; we must honor it (previous code printed MATCH for
# any input as long as the hash parsed).
verify_hash() {
    local password="$1"
    local hexhash="$2"
    # Password goes through stdin; the stored hash goes through /dev/fd
    # process substitution so neither shows up on argv. The hash already
    # lives in tacquito.yaml (mode 0640) so leaking to /proc/cmdline is a
    # low-severity issue, but the pattern is uniform across secret handling.
    #
    # Script is passed via `-c`: an earlier heredoc-on-stdin form (`python3 -`
    # + `<<'PY'`) let the heredoc shadow the password pipe, so stdin.read()
    # always returned b'' and every verify returned NO_MATCH.
    printf '%s' "$password" | python3 -c '
import bcrypt, binascii, sys
pw = sys.stdin.buffer.read()
with open(sys.argv[1]) as f:
    hexhash = f.read()
try:
    h = binascii.unhexlify(hexhash)
except (binascii.Error, ValueError):
    print("INVALID_HASH")
    sys.exit(0)
try:
    if bcrypt.checkpw(pw, h):
        print("MATCH")
    else:
        print("NO_MATCH")
except ValueError:
    print("INVALID_HASH")
' <(printf '%s' "$hexhash") 2>/dev/null || echo "FAIL"
}

# --- Replace a user's hash in config (safe from sed injection) ---
# Hash travels via argv (already stored in readable config on disk).
replace_user_hash() {
    local username="$1"
    local new_hash="$2"
    # bcrypt hash is a one-way digest, but keeping it off argv matches the
    # same process-substitution pattern used for raw secrets — a leaked
    # hash is an offline-crack target and the /proc/<pid>/cmdline exposure
    # is free to close.
    python3 - "$CONFIG" "$username" <(printf '%s' "$new_hash") <<'PY'
import re, sys, tempfile, os
config_path, username, hash_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(hash_path) as f:
    new_hash = f.read()
config = open(config_path).read()
pattern = r'(bcrypt_' + re.escape(username) + r':.*?hash:\s*)\S+'
config = re.sub(pattern, r'\g<1>' + new_hash, config, count=1, flags=re.DOTALL)
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(config_path), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, config_path)
PY
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

# --- Validate password strength for a user-chosen password ---
# Auto-generated passwords bypass this (they're always long + mixed).
# Returns 0 on accept, 1 on reject (with error printed).
validate_password_strength() {
    local password="$1"
    local username="${2:-}"

    if [[ "${#password}" -lt "$PASSWORD_MIN_LENGTH" ]]; then
        error "Password is ${#password} characters; minimum is ${PASSWORD_MIN_LENGTH}."
        return 1
    fi

    local lower="${password,,}"
    # Reject the usual suspects. Lowercase-fold first so variants ("Admin",
    # "ADMIN") all match. Not a dictionary check — just the handful that
    # dominate breach corpora.
    case "$lower" in
        admin|administrator|root|password|password1|passw0rd|\
        tacacs|tacacs+|tacplus|tacquito|\
        cisco|cisco123|juniper|juniper1|\
        changeme|welcome|welcome1|letmein|qwerty*|abc123*|\
        12345*|00000*|aaaaaa*)
            error "Password is on the common-weak list. Choose another."
            return 1
            ;;
    esac

    if [[ -n "$username" && "$lower" == "${username,,}" ]]; then
        error "Password must not equal the username."
        return 1
    fi

    return 0
}

# --- Prompt for password ---
# If $1 is given, it's the username — used for password-equals-username checks.
prompt_password() {
    local username="${1:-}"
    local password=""
    password=$(read_password_masked "  Enter password (leave blank to auto-generate): ")
    if [[ -z "$password" ]]; then
        password=$(openssl rand -base64 18)
        echo -e "  Generated password: ${BOLD}${password}${NC}" >&2
    else
        if ! validate_password_strength "$password" "$username"; then
            exit 1
        fi
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
    printf "  ${BOLD}%-20s %-15s %-10s %-12s %-30s${NC}\n" "USERNAME" "GROUP" "STATUS" "PW CHANGED" "SCOPES"
    echo "  -----------------------------------------------------------------------------------------------"

    # Use Python for reliable YAML-ish parsing. Pull scopes via yaml.safe_load
    # since that field can span multiple forms ([\"a\",\"b\"] or block list);
    # the other fields stay on the regex path for consistency with prior output.
    python3 -c "
import re, sys, yaml

config_path = sys.argv[1]
config = open(config_path).read()

# Extract only the users: section for the regex pass.
users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
if not users_match:
    sys.exit(0)
users_section = users_match.group(1)

# Build a scopes map via safe_load so we don't have to teach the regex about
# every YAML list form.
scopes_map = {}
try:
    with open(config_path) as f:
        d = yaml.safe_load(f) or {}
    for u in (d.get('users') or []):
        name = u.get('name')
        if name:
            scopes_map[name] = u.get('scopes') or []
except Exception:
    pass

DISABLED_MARKER = sys.argv[2]
# Built-in accounting sinks are hidden from the user-list output:
# they are not manageable identities, they exist so tacquito does
# not error on accounting packets generated by device-built-in
# accounts like Junos root that run non-tty CLI as internal daemons.
HIDDEN_SINKS = {'root'}
for m in re.finditer(r'- name: (\S+)\n.*?groups: \[\*(\w+)\]', users_section, re.DOTALL):
    username = m.group(1)
    if username in HIDDEN_SINKS:
        continue
    group = m.group(2)

    auth_match = re.search(r'^bcrypt_' + re.escape(username) + r':.*?hash:\s*(\S+)', config, re.MULTILINE | re.DOTALL)
    if auth_match:
        h = auth_match.group(1)
        status = 'disabled' if h == 'DISABLED' or h == DISABLED_MARKER else 'active'
    else:
        status = 'unknown'

    scopes = scopes_map.get(username, [])
    print(f'{username}|{group}|{status}|' + ','.join(scopes))
" "$CONFIG" "$DISABLED_MARKER_HEX" | sort | while IFS='|' read -r username group status scopes_csv; do
        local color="$GREEN"
        [[ "$status" == "disabled" ]] && color="$RED"
        [[ "$status" == "unknown" ]] && color="$YELLOW"
        local pw_date
        pw_date=$(get_password_date "$username")
        local scopes_display=""
        if [[ -z "$scopes_csv" ]]; then
            scopes_display="(none)"
        else
            # Truncate >3 scopes with "(…+N)" suffix.
            local IFS_old="$IFS"
            IFS=',' read -ra _SC <<< "$scopes_csv"
            IFS="$IFS_old"
            if (( ${#_SC[@]} > 3 )); then
                scopes_display="${_SC[0]},${_SC[1]},${_SC[2]} (…+$(( ${#_SC[@]} - 3 )))"
            else
                scopes_display="$scopes_csv"
            fi
        fi
        printf "  %-20s %-15s ${color}%-10s${NC} %-12s %-30s\n" "$username" "$group" "$status" "$pw_date" "$scopes_display"
    done

    echo ""
}

# --- ADD ---
cmd_add() {
    local username="${1:-}"
    local group="${2:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user add <username> <group> [--hash <bcrypt-hash>] [--scopes <name>[,<name>...]]"
        exit 1
    fi
    validate_username "$username"
    reject_reserved_username "$username"
    # Validate group exists in config
    if ! grep -q "^${group}: &${group}$" "$CONFIG"; then
        local available
        available=$(grep -oP '^\w+(?=: &\w)' "$CONFIG" | grep -v "^bcrypt_\|^exec_\|^junos_\|^file_\|^authenticator\|^action\|^accounter\|^handler\|^provider" | tr '\n' '|' | sed 's/|$//')
        error "Group '${group}' does not exist. Available: ${available}"
        error "Usage: tacctl user add <username> <group>"
        exit 1
    fi
    if user_exists "$username"; then
        error "User '${username}' already exists."
        exit 1
    fi

    # Parse optional flags: --hash <value>, --scopes <csv>
    local hash=""
    local scopes_csv=""
    shift 2 || true
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hash)
                hash="${2:-}"
                if [[ -z "$hash" ]]; then
                    error "Usage: tacctl user add <username> <group> --hash <bcrypt-hash>"
                    exit 1
                fi
                local normalized
                normalized=$(normalize_bcrypt_hash "$hash")
                if [[ -z "$normalized" ]]; then
                    error "Invalid bcrypt hash."
                    error "Accepted forms:"
                    error "  - hex-encoded (from 'tacctl hash'): 24326224313224..."
                    error "  - raw (from bcrypt libs):           \$2b\$12\$..."
                    exit 1
                fi
                hash="$normalized"
                shift 2
                ;;
            --scopes)
                scopes_csv="${2:-}"
                if [[ -z "$scopes_csv" ]]; then
                    error "Usage: tacctl user add <username> <group> --scopes <name>[,<name>...]"
                    exit 1
                fi
                shift 2
                ;;
            *)
                error "Unknown argument: '$1'"
                error "Usage: tacctl user add <username> <group> [--hash <bcrypt-hash>] [--scopes <name>[,<name>...]]"
                exit 1
                ;;
        esac
    done

    # Determine scopes list. If --scopes given, validate each name exists; else
    # fall back to scope.default from tacctl.yaml (or the sole secrets[]
    # entry if only one scope exists; or the shipped default 'lab').
    local scope_names=""
    if [[ -n "$scopes_csv" ]]; then
        local s
        IFS=',' read -ra _REQ <<< "$scopes_csv"
        for s in "${_REQ[@]}"; do
            s=$(echo "$s" | xargs)
            [[ -z "$s" ]] && continue
            if ! scope_exists "$s"; then
                error "Scope '${s}' does not exist. Available: $(list_scopes | paste -sd' ')"
                exit 1
            fi
            # within-input dedupe
            if ! printf '%s\n' "$scope_names" | grep -qxF "$s" 2>/dev/null; then
                scope_names+="${scope_names:+$'\n'}${s}"
            fi
        done
        [[ -z "$scope_names" ]] && { error "No valid scope names provided."; exit 1; }
    else
        scope_names=$(read_default_scope)
        if [[ -z "$scope_names" ]]; then
            error "No scopes exist and no default scope is set."
            error "Create one first: tacctl scope add <name> --prefixes <cidrs>"
            exit 1
        fi
    fi
    # Build JSON array form for the YAML writer (safe strings — scope names
    # already validated via scope_exists, which only allows existing YAML names).
    local scopes_json
    scopes_json=$(printf '%s\n' "$scope_names" | awk 'NF' | awk 'BEGIN{printf "["} NR>1{printf ", "} {printf "\"%s\"", $0} END{printf "]"}')

    echo ""
    echo -e "  Adding user: ${BOLD}${username}${NC} (${group})"

    if [[ -z "$hash" ]]; then
        local password
        password=$(prompt_password "$username")
        hash=$(generate_hash "$password")
        unset password
    else
        info "Using pre-generated bcrypt hash."
    fi

    backup_config

    # Insert authenticator anchor and user entry using Python. The bcrypt
    # hash goes through a /dev/fd pipe so it never appears in
    # /proc/<pid>/cmdline; the other args (username, group, scopes_json)
    # are non-secret and stay on argv for readability.
    python3 - "$CONFIG" "$username" <(printf '%s' "$hash") "$group" "$scopes_json" <<'PY'
import sys, tempfile, os, re

config_path = sys.argv[1]
username = sys.argv[2]
hash_path = sys.argv[3]
group = sys.argv[4]
scopes_json = sys.argv[5]
with open(hash_path) as f:
    hash_val = f.read()
config = open(config_path).read()

# Insert authenticator block before '# --- Services ---'. Normalize the
# whitespace at the seam: strip trailing newlines from what's already
# there, then apply a deterministic '\n\n' (= one blank line) before
# and after the new block so spacing stays consistent regardless of
# whatever the prior insert (or original template) left behind.
auth_block = (
    f'bcrypt_{username}: &bcrypt_{username}\n'
    f'  type: *authenticator_type_bcrypt\n'
    f'  options:\n'
    f'    hash: {hash_val}\n'
)
marker = '# --- Services ---'
idx = config.index(marker)
prefix = config[:idx].rstrip('\n')
config = prefix + '\n\n' + auth_block.rstrip('\n') + '\n\n' + config[idx:]

# Insert user entry before the Secret Providers section. Prefix match
# accommodates both header variants: '# --- Secret Providers ---' and
# '# --- Secret Providers (Scopes) ---' (the template gained the suffix
# at one point and old installs may carry either form).
user_block = (
    f'  # {username}\n'
    f'  - name: {username}\n'
    f'    scopes: {scopes_json}\n'
    f'    groups: [*{group}]\n'
    f'    authenticator: *bcrypt_{username}\n'
    f'    accounter: *file_accounter\n'
)
m2 = re.search(r'^# --- Secret Providers\b', config, re.M)
if not m2:
    raise SystemExit("could not locate '# --- Secret Providers' section header")
idx2 = m2.start()
prefix2 = config[:idx2].rstrip('\n')
config = prefix2 + '\n\n' + user_block.rstrip('\n') + '\n\n' + config[idx2:]

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(config_path), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, config_path)
PY

    # Fix ownership
    chown tacquito:tacquito "$CONFIG"

    restart_service
    record_password_date "$username"
    local scopes_display
    scopes_display=$(printf '%s\n' "$scope_names" | awk 'NF' | paste -sd,)
    info "User '${username}' added (${group}) with scopes: ${scopes_display}"
    echo ""
}

# --- REMOVE ---
cmd_remove() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user remove <username>"
        exit 1
    fi
    validate_username "$username"
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
import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.writelines(out)
tmp.close()
os.rename(tmp.name, sys.argv[1])
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
        error "Usage: tacctl user passwd <username> [--hash <bcrypt-hash>]"
        exit 1
    fi
    validate_username "$username"
    reject_reserved_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    # Check for --hash flag (pre-generated bcrypt hash)
    local hash=""
    if [[ "${2:-}" == "--hash" ]]; then
        hash="${3:-}"
        if [[ -z "$hash" ]]; then
            error "Usage: tacctl user passwd <username> --hash <bcrypt-hash>"
            exit 1
        fi
        local normalized
        normalized=$(normalize_bcrypt_hash "$hash")
        if [[ -z "$normalized" ]]; then
            error "Invalid bcrypt hash."
            error "Accepted forms:"
            error "  - hex-encoded (from 'tacctl hash'): 24326224313224..."
            error "  - raw (from bcrypt libs):           \$2b\$12\$..."
            exit 1
        fi
        hash="$normalized"
    fi

    echo ""
    echo -e "  Changing password for: ${BOLD}${username}${NC}"

    if [[ -z "$hash" ]]; then
        local password
        password=$(prompt_password "$username")
        hash=$(generate_hash "$password")
        unset password
    else
        info "Using pre-generated bcrypt hash."
    fi

    backup_config

    replace_user_hash "$username" "$hash"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    record_password_date "$username"
    info "Password changed for '${username}'."
    echo ""
}

# --- PASSWD (self-service) ---
# 'tacctl passwd' with no arguments: the caller changes the password of the
# tacctl user that matches their own login. The target is taken from
# SUDO_USER only -- there is deliberately no username argument, so the
# sudoers rule for the lower tiers can allow this exact command without
# letting anyone reset somebody else's password. The current password must
# verify first.
cmd_passwd_self() {
    if [[ $# -gt 0 ]]; then
        error "Usage: tacctl passwd   (changes your own password; takes no arguments)"
        error "To set another user's password: tacctl user passwd <username>"
        exit 1
    fi
    local username="${SUDO_USER:-}"
    if [[ -z "$username" || "$username" == "root" ]]; then
        error "'tacctl passwd' changes the password of the user who invoked sudo."
        error "As root, use: tacctl user passwd <username>"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "No tacctl user named '${username}'."
        exit 1
    fi
    local stored_hash
    stored_hash=$(get_user_hash "$username")
    if is_disabled_hash "$stored_hash"; then
        error "User '${username}' is disabled. Ask a superuser to re-enable it."
        exit 1
    fi

    echo ""
    echo -e "  Changing password for: ${BOLD}${username}${NC}"

    local current
    current=$(read_password_masked "  Current password: ")
    if [[ "$(verify_hash "$current" "$stored_hash")" != "MATCH" ]]; then
        unset current
        # Same rate limit as 'user verify': not a local bcrypt oracle.
        sleep 0.5
        logger -t tacctl -p auth.warning \
            "passwd FAIL user=${username} reason=bad-current-password" 2>/dev/null || true
        error "Current password does not match."
        exit 1
    fi

    local password
    password=$(prompt_password "$username")
    if [[ "$password" == "$current" ]]; then
        unset current password
        error "New password must differ from the current one."
        exit 1
    fi
    unset current
    local hash
    hash=$(generate_hash "$password")
    unset password

    backup_config
    replace_user_hash "$username" "$hash"
    chown tacquito:tacquito "$CONFIG"
    restart_service
    record_password_date "$username"
    logger -t tacctl -p auth.info "passwd OK user=${username} (self-service)" 2>/dev/null || true
    info "Password changed for '${username}'."
    echo ""
}

# --- DISABLE ---
cmd_disable() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user disable <username>"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local current_hash
    current_hash=$(get_user_hash "$username")
    if is_disabled_hash "$current_hash"; then
        warn "User '${username}' is already disabled."
        exit 0
    fi

    backup_config

    # Save the real hash to a sidecar file for re-enabling
    mkdir -p "${BACKUP_DIR}/disabled"
    chmod 700 "${BACKUP_DIR}/disabled"
    echo "$current_hash" > "${BACKUP_DIR}/disabled/${username}.hash"
    chmod 600 "${BACKUP_DIR}/disabled/${username}.hash"

    replace_user_hash "$username" "$DISABLED_MARKER_HEX"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "User '${username}' disabled. Use 'enable' to restore access."
    echo ""
}

# --- ENABLE ---
cmd_enable() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user enable <username>"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local current_hash
    current_hash=$(get_user_hash "$username")
    if ! is_disabled_hash "$current_hash"; then
        warn "User '${username}' is not disabled."
        exit 0
    fi

    local saved_hash_file="${BACKUP_DIR}/disabled/${username}.hash"
    if [[ ! -f "$saved_hash_file" ]]; then
        error "No saved hash found for '${username}'. Set a new password instead:"
        error "  tacctl user passwd ${username}"
        exit 1
    fi

    local saved_hash
    saved_hash=$(cat "$saved_hash_file")

    backup_config

    replace_user_hash "$username" "$saved_hash"
    rm -f "$saved_hash_file"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "User '${username}' re-enabled with previous password."
    echo ""
}

# --- SHOW (read-only detail view; no password prompt) ---
cmd_show() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user show <username>"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local group stored_hash status pw_date last_login
    local pw_age=""
    group=$(get_user_group "$username")
    stored_hash=$(get_user_hash "$username")
    if is_disabled_hash "$stored_hash"; then
        status="disabled"
    else
        status="active"
    fi
    pw_date=$(get_password_date "$username")
    if [[ "$pw_date" != "unknown" ]]; then
        pw_age=$(( ( $(date +%s) - $(date -d "$pw_date" +%s) ) / 86400 ))
    fi
    last_login=$(get_last_login "$username")

    # Resolve Cisco priv-lvl and Juniper class for the user's group by
    # walking the YAML services chain. Falls back to empty on any error.
    local yaml_info priv_lvl juniper_class
    yaml_info=$(python3 - "$CONFIG" "$group" <<'PY' 2>/dev/null || echo '|'
import yaml, sys
try:
    with open(sys.argv[1]) as f:
        c = yaml.safe_load(f)
    g = c.get(sys.argv[2], {}) or {}
    priv = ''
    jclass = ''
    for s in g.get('services', []) or []:
        # 'shell' is the on-wire Cisco exec service name; 'exec' is the
        # legacy spelling healed by conf_migrate_exec_service_name().
        if s.get('name') in ('shell', 'exec'):
            for sv in s.get('set_values', []) or []:
                if sv.get('name') == 'priv-lvl':
                    v = sv.get('values') or []
                    if v:
                        priv = v[0]
        elif s.get('name') == 'junos-exec':
            for sv in s.get('set_values', []) or []:
                if sv.get('name') == 'local-user-name':
                    v = sv.get('values') or []
                    if v:
                        jclass = v[0]
    print(f'{priv}|{jclass}')
except Exception:
    print('|')
PY
)
    IFS='|' read -r priv_lvl juniper_class <<< "$yaml_info"

    # Hash fingerprint: the hash is stored hex-encoded in the YAML ("24326224313024..." = "$2b$10$..."). Decode the first 7 bcrypt chars (14 hex chars) to surface algorithm + cost without disclosing salt or digest.
    local hash_prefix=""
    if [[ -n "$stored_hash" ]] && ! is_disabled_hash "$stored_hash"; then
        hash_prefix=$(echo "${stored_hash:0:14}" | xxd -r -p 2>/dev/null)
    fi

    echo ""
    echo -e "  ${BOLD}User:${NC}             ${username}"
    echo -e "  ${BOLD}Group:${NC}            ${group}"
    if [[ "$status" == "disabled" ]]; then
        echo -e "  ${BOLD}Status:${NC}           ${RED}disabled${NC}"
    else
        echo -e "  ${BOLD}Status:${NC}           ${GREEN}active${NC}"
    fi
    if [[ -n "$pw_age" ]]; then
        echo -e "  ${BOLD}Password changed:${NC} ${pw_date} (${pw_age} days ago)"
    else
        echo -e "  ${BOLD}Password changed:${NC} ${pw_date}"
    fi
    echo -e "  ${BOLD}Last login:${NC}       ${last_login}"
    [[ -n "$priv_lvl" ]]      && echo -e "  ${BOLD}Cisco priv-lvl:${NC}   ${priv_lvl}"
    [[ -n "$juniper_class" ]] && echo -e "  ${BOLD}Juniper class:${NC}    ${juniper_class}"
    echo -e "  ${BOLD}Hash type:${NC}        ${hash_prefix}"
    local user_scopes
    user_scopes=$(read_user_scopes "$username")
    if [[ -z "$user_scopes" ]]; then
        echo -e "  ${BOLD}Scopes:${NC}           ${RED}(none — cannot authenticate on any device)${NC}"
    else
        local first=1
        while IFS= read -r s; do
            [[ -z "$s" ]] && continue
            local label=""
            if scope_exists "$s"; then
                label="$s"
            else
                label="${RED}${s} (ORPHAN)${NC}"
            fi
            if (( first )); then
                echo -e "  ${BOLD}Scopes:${NC}           ${label}"
                first=0
            else
                echo -e "                    ${label}"
            fi
        done <<< "$user_scopes"
    fi
    echo ""
}

# --- VERIFY (test a password against stored hash) ---
cmd_verify() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user verify <username>"
        exit 1
    fi
    validate_username "$username"
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
    is_disabled_hash "$stored_hash" && status="disabled"
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
    unset password

    # SUDO_UID is the invoking user's uid when run via sudo; falls back to
    # the current EUID (root/0) for direct-as-root invocations.
    local caller_uid="${SUDO_UID:-$EUID}"
    local caller_name="${SUDO_USER:-root}"

    if [[ "$result" == "MATCH" ]]; then
        logger -t tacctl -p auth.info \
            "verify OK user=${username} by=${caller_name}(uid=${caller_uid})" 2>/dev/null || true
        info "Password is correct."
    else
        # Rate-limit failures so the CLI isn't usable as a local bcrypt
        # oracle. 500ms is cheap for humans, expensive for scripted guessing.
        sleep 0.5
        logger -t tacctl -p auth.warning \
            "verify FAIL user=${username} result=${result} by=${caller_name}(uid=${caller_uid})" 2>/dev/null || true
        error "Password does not match."
    fi
    echo ""
}

# --- RENAME ---
cmd_rename() {
    local oldname="${1:-}"
    local newname="${2:-}"

    if [[ -z "$oldname" || -z "$newname" ]]; then
        error "Usage: tacctl user rename <old-username> <new-username>"
        exit 1
    fi
    validate_username "$oldname"
    validate_username "$newname"
    if ! user_exists "$oldname"; then
        error "User '${oldname}' does not exist."
        exit 1
    fi
    if user_exists "$newname"; then
        error "User '${newname}' already exists."
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

import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
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
    validate_username "$username"
    validate_class_name "$newgroup"
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

import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
" "$CONFIG" "$username" "$oldgroup" "$newgroup"

    chown tacquito:tacquito "$CONFIG"
    restart_service
    info "User '${username}' moved: ${oldgroup} -> ${newgroup}"
    echo ""
}

# --- USER SCOPES: tacctl user scope <user> list|add|remove|set|clear ---
cmd_user_scope() {
    local username="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user scope <user> {list|add|remove|set|clear} [<scope>[,<scope>...]]"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    case "$sub" in
        ""|list|-h|--help|help)
            echo ""
            echo -e "${BOLD}Scopes for user '${username}'${NC}"
            echo "--------------------------------------------"
            local cur
            cur=$(read_user_scopes "$username")
            if [[ -z "$cur" ]]; then
                echo -e "  ${RED}(none — user cannot authenticate on any device)${NC}"
            else
                echo "$cur" | while IFS= read -r s; do
                    [[ -z "$s" ]] && continue
                    if scope_exists "$s"; then
                        echo "  - ${s}"
                    else
                        echo -e "  ${RED}- ${s}  (ORPHAN: scope does not exist)${NC}"
                    fi
                done
            fi
            echo ""
            if [[ -z "$sub" || "$sub" == "list" ]]; then
                return
            fi
            echo "Usage:"
            echo "  tacctl user scope ${username} list                              Show current (default)"
            echo "  tacctl user scope ${username} add    <scope>[,<scope>...]      Grant scope access"
            echo "  tacctl user scope ${username} remove <scope>[,<scope>...]      Revoke scope access"
            echo "  tacctl user scope ${username} set    <scope>[,<scope>...]      Replace full list"
            echo "  tacctl user scope ${username} clear                             Wipe all (confirms)"
            echo ""
            return
            ;;
        add|remove|set)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl user scope ${username} ${sub} <scope>[,<scope>...]"
                exit 1
            fi
            # Parse + validate scope names
            local requested=""
            local s
            IFS=',' read -ra SCOPES <<< "$arg"
            for s in "${SCOPES[@]}"; do
                s=$(echo "$s" | xargs)
                [[ -z "$s" ]] && continue
                if ! scope_exists "$s"; then
                    error "Scope '${s}' does not exist. Available: $(list_scopes | paste -sd' ')"
                    exit 1
                fi
                # within-input dedupe
                if ! printf '%s\n' "$requested" | grep -qxF "$s"; then
                    requested+="${requested:+$'\n'}${s}"
                fi
            done
            [[ -z "$requested" ]] && { error "No valid scope names provided."; exit 1; }

            local current new_list
            current=$(read_user_scopes "$username")
            local changed="" noop=""
            if [[ "$sub" == "set" ]]; then
                new_list=$(printf '%s\n' "$requested" | paste -sd,)
                changed="$requested"
            elif [[ "$sub" == "add" ]]; then
                new_list="$current"
                while IFS= read -r s; do
                    [[ -z "$s" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF "$s"; then
                        noop+="${noop:+ }${s}"
                    else
                        changed+="${changed:+$'\n'}${s}"
                        new_list=$(printf '%s\n%s\n' "$new_list" "$s")
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { info "No new scopes (already present: ${noop})."; echo ""; return; }
                new_list=$(printf '%s\n' "$new_list" | awk 'NF' | paste -sd,)
            else  # remove
                new_list="$current"
                while IFS= read -r s; do
                    [[ -z "$s" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF "$s"; then
                        changed+="${changed:+$'\n'}${s}"
                        new_list=$(printf '%s\n' "$new_list" | grep -vxF "$s" || true)
                    else
                        noop+="${noop:+ }${s}"
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { warn "Nothing to remove (not present: ${noop})."; exit 0; }
                new_list=$(printf '%s\n' "$new_list" | awk 'NF' | paste -sd,)
            fi

            backup_config
            set_user_scopes "$username" "$new_list"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            local n
            n=$(printf '%s\n' "$changed" | wc -l)
            local verb
            case "$sub" in
                add)    verb="Granted ${n} scope(s) to" ;;
                remove) verb="Revoked ${n} scope(s) from" ;;
                set)    verb="Replaced scopes on" ;;
            esac
            info "${verb} user '${username}': $(printf '%s\n' "$changed" | paste -sd' ')"
            [[ -n "$noop" ]] && info "(Skipped: ${noop})"
            if [[ -z "$new_list" ]]; then
                warn "User '${username}' now has NO scopes — they cannot auth on any device"
                warn "until you run: tacctl user scope ${username} add <scope>"
            fi
            echo ""
            ;;
        clear)
            local current
            current=$(read_user_scopes "$username")
            if [[ -z "$current" ]]; then
                info "User '${username}' already has no scopes."
                return
            fi
            warn "WARNING: ${username} will be unable to authenticate on any device"
            warn "until you grant at least one scope with 'tacctl user scope ${username} add <name>'"
            warn "(Distinct from 'tacctl user disable' — the password hash is preserved.)"
            read -rp "  Clear all scopes for '${username}'? [y/N]: " confirm
            [[ ! "$confirm" =~ ^[Yy] ]] && { info "Aborted."; return; }
            backup_config
            set_user_scopes "$username" ""
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Cleared scopes for user '${username}'."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl user scope ${username}' for usage."
            exit 1
            ;;
    esac
}

# --- HASH (bcrypt hash helper — does not require root) ---
cmd_hash() {
    local subcmd="${1:-}"
    case "$subcmd" in
        ""|-h|--help|help)
            cmd_hash_usage
            ;;
        generate)
            cmd_hash_generate
            ;;
        commands)
            cmd_hash_commands
            ;;
        *)
            error "Unknown subcommand: '$subcmd'"
            cmd_hash_usage
            exit 1
            ;;
    esac
}

cmd_hash_usage() {
    echo ""
    echo -e "${BOLD}tacctl hash${NC} — bcrypt hash helper (non-root)"
    echo ""
    echo "Usage:"
    echo "  tacctl hash generate                Prompt for a password and print its bcrypt hash"
    echo "  tacctl hash commands                Show OS-specific one-liners for offline generation"
    echo ""
    echo "Use 'generate' when you can shell in to this server."
    echo "Use 'commands' to hand an operator a command they can run on their own machine,"
    echo "so the plaintext password never leaves their laptop."
    echo ""
    echo "Either output plugs into:"
    echo "  tacctl user add <username> <group> --hash '<hash>'"
    echo "  tacctl user passwd <username> --hash '<hash>'"
    echo ""
    echo "Both accept either form — hex ('24326224...') or raw ('\$2b\$12\$...')."
    echo ""
}

cmd_hash_generate() {
    if ! python3 -c "import bcrypt" 2>/dev/null; then
        error "python3-bcrypt not installed. Run 'tacctl hash commands' for client-side alternatives."
        exit 1
    fi
    local password
    password=$(prompt_password)
    local hash
    hash=$(generate_hash "$password")
    unset password
    echo ""
    echo "  Bcrypt hash (provide this to your admin):"
    echo ""
    echo "  ${hash}"
    echo ""
    echo "  Admin command:"
    echo "    tacctl user add <username> <group> --hash '${hash}'"
    echo ""
}

# Client-side bcrypt generation recipes. Intentionally verbose — this is
# the page an operator will paste from when the server isn't reachable,
# so brevity costs more than paper. Each recipe prints BOTH the raw
# '$2b$...' form and the hex form; 'tacctl user add --hash' accepts either.
cmd_hash_commands() {
    cat <<'EOF'

  Bcrypt hash generation — client-side recipes
  (run on the operator's machine; plaintext password never leaves it)

  =================================================================
  Any OS — Python 3 with the 'bcrypt' module
  =================================================================
    # install once:  python3 -m pip install --user bcrypt
    #                (use 'py' instead of 'python3' on Windows)
    python3 -c "import bcrypt,binascii,getpass; p=getpass.getpass('Password: ').encode(); r=bcrypt.hashpw(p,bcrypt.gensalt(12)); print('raw:',r.decode()); print('hex:',binascii.hexlify(r).decode())"

  =================================================================
  Linux / macOS — htpasswd (no Python needed)
  =================================================================
    # install once:  apt install apache2-utils  OR  brew install httpd
    htpasswd -nBC 12 "" | cut -d: -f2

  =================================================================
  Handing the hash to your admin
  =================================================================
  'tacctl user passwd --hash' accepts either form; the server
  normalizes to hex internally. So either line works:
      tacctl user passwd <user> --hash '$2b$12$...'          # raw
      tacctl user passwd <user> --hash '24326224313224...'   # hex

EOF
}

# --- USER dispatcher ---
cmd_user() {
    local subcmd="${1:-help}"
    shift || true

    case "$subcmd" in
        list)       cmd_list ;;
        show)       cmd_show "$@" ;;
        add)        cmd_add "$@" ;;
        remove)     cmd_remove "$@" ;;
        passwd)     cmd_passwd "$@" ;;
        disable)    cmd_disable "$@" ;;
        enable)     cmd_enable "$@" ;;
        rename)     cmd_rename "$@" ;;
        move)       cmd_move "$@" ;;
        verify)     cmd_verify "$@" ;;
        scope)      cmd_user_scope "$@" ;;
        *)
            echo ""
            echo -e "${BOLD}User Commands${NC}"
            echo ""
            echo "Usage: tacctl user <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                                        List all users (name, group, status, pw age, scopes)"
            echo "  show <username>                             Show user details incl. scope membership"
            echo "  add <username> <group>                      Add a new user; lands in default scope"
            echo "  add <username> <group> --scopes <s>[,s...]  Grant specific scopes at creation"
            echo "  add <username> <group> --hash <hash>        Add with pre-generated bcrypt hash"
            echo "  remove <username>                           Remove a user"
            echo "  passwd <username>                           Change a user's password"
            echo "  passwd <username> --hash <hash>             Change with pre-generated bcrypt hash"
            echo "  disable <username>                          Disable a user (preserves hash)"
            echo "  enable <username>                           Re-enable a disabled user"
            echo "  rename <old> <new>                          Rename a user"
            echo "  move <user> <group>                         Move user to a different group"
            echo "  verify <username>                           Verify password and show user details"
            echo "  scope <user> list|add|remove|set|clear      Manage which scopes the user can auth from"
            echo ""
            echo "Examples:"
            echo "  tacctl user list"
            echo "  tacctl user add jsmith superuser"
            echo "  tacctl user add jsmith superuser --scopes prod,lab"
            echo "  tacctl user scope jsmith add prod"
            echo "  tacctl user verify jsmith"
            echo ""
            exit 1
            ;;
    esac
}

