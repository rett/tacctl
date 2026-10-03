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
#
# Users live in the store (lib/store.sh); every command here reads them
# through the model (lib/model.sh) and writes them with store_apply
# (lib/backend.sh), which also re-renders tacquito.yaml. A disabled
# user keeps its real hash in the store with 'disabled: true', and the date
# of the last password change is the user's 'password_changed' field.

# _user_info <username>: fill the caller's associative array 'ui' (declare it
# with 'local -A ui=()') from model_user_info, plus ui[scopes] (one name per
# line) and ui[orphans] (the scopes among them that do not exist). Returns 1
# when the user does not exist.
_user_info() {
    local out key value
    out=$(model_user_info "$1") || return 1
    ui[scopes]=""
    ui[orphans]=""
    while IFS='=' read -r key value; do
        case "$key" in
            "") ;;
            scope)
                ui[scopes]+="${ui[scopes]:+$'\n'}${value%%|*}"
                if [[ "${value##*|}" != "1" ]]; then
                    ui[orphans]+="${ui[orphans]:+$'\n'}${value%%|*}"
                fi
                ;;
            *) ui[$key]="$value" ;;
        esac
    done <<< "$out"
}

# Parse a --hash argument into canonical hex on stdout; exits on a bad one.
_user_hash_arg() {
    local normalized
    normalized=$(normalize_bcrypt_hash "$1")
    if [[ -z "$normalized" ]]; then
        error "Invalid bcrypt hash."
        error "Accepted forms:"
        error "  - hex-encoded (from 'tacctl hash'): 24326224313224..."
        error "  - raw (from bcrypt libs):           \$2b\$12\$..."
        exit 1
    fi
    printf '%s\n' "$normalized"
}

# --- LIST ---
cmd_list() {
    echo ""
    echo -e "${BOLD}Users${NC}"
    echo "--------------------------------------------"
    printf "  ${BOLD}%-20s %-15s %-10s %-12s %-30s${NC}\n" "USERNAME" "GROUP" "STATUS" "PW CHANGED" "SCOPES"
    echo "  -----------------------------------------------------------------------------------------------"

    # The accounting sink ('root') is not a manageable identity and is left
    # out: it exists so tacquito does not error on accounting packets from
    # device-built-in accounts such as Junos root.
    local rows
    rows=$(model_user_rows) || exit 1
    local username group status pw_date scopes_csv
    while IFS='|' read -r username group status pw_date scopes_csv; do
        [[ -z "$username" ]] && continue
        local color="$GREEN"
        [[ "$status" == "disabled" ]] && color="$RED"
        local scopes_display=""
        if [[ -z "$scopes_csv" ]]; then
            scopes_display="(none)"
        else
            # Truncate >3 scopes with "(…+N)" suffix.
            local -a _SC
            IFS=',' read -ra _SC <<< "$scopes_csv"
            if (( ${#_SC[@]} > 3 )); then
                scopes_display="${_SC[0]},${_SC[1]},${_SC[2]} (…+$(( ${#_SC[@]} - 3 )))"
            else
                scopes_display="$scopes_csv"
            fi
        fi
        printf "  %-20s %-15s ${color}%-10s${NC} %-12s %-30s\n" "$username" "$group" "$status" "$pw_date" "$scopes_display"
    done <<< "$rows"

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
    store_require || exit 1
    validate_username "$username"
    reject_reserved_username "$username"
    if ! model_group_exists "$group"; then
        local available
        available=$(model_group_info | cut -d'|' -f1 | paste -sd'|' || true)
        error "Group '${group}' does not exist. Available: ${available}"
        error "Usage: tacctl user add <username> <group>"
        exit 1
    fi
    if model_user_exists "$username"; then
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
                hash=$(_user_hash_arg "$hash") || exit 1
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
    # fall back to scope.default from tacctl.yaml (or the sole scope if only
    # one exists; or the shipped default 'lab').
    local scope_names=""
    if [[ -n "$scopes_csv" ]]; then
        local s all_scopes
        all_scopes=$(model_scopes_by_routing) || exit 1
        local -a _REQ
        IFS=',' read -ra _REQ <<< "$scopes_csv"
        for s in "${_REQ[@]}"; do
            s=$(echo "$s" | xargs)
            [[ -z "$s" ]] && continue
            if ! grep -qxF -- "$s" <<< "$all_scopes"; then
                error "Scope '${s}' does not exist. Available: $(paste -sd' ' <<< "$all_scopes")"
                exit 1
            fi
            # within-input dedupe
            if ! printf '%s\n' "$scope_names" | grep -qxF -- "$s" 2>/dev/null; then
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
    local scopes_display
    scopes_display=$(printf '%s\n' "$scope_names" | awk 'NF' | paste -sd,)

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

    # The hash reaches the store writer on stdin (see store_mutate).
    store_apply store_user_set "$username" "group=${group}" "scopes=${scopes_display}" \
        "hash=${hash}" disabled=false password_changed=today || exit $?

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
    store_require || exit 1
    validate_username "$username"
    if ! model_user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    echo ""
    read -rp "  Remove user '${username}'? This cannot be undone. [y/N]: " confirm || true
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    store_apply store_user_del "$username" || exit $?

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
    store_require || exit 1
    validate_username "$username"
    reject_reserved_username "$username"
    if ! model_user_exists "$username"; then
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
        hash=$(_user_hash_arg "$hash") || exit 1
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

    # Setting a password also enables the account, as it always has: this is
    # how the seeded placeholder users are activated.
    store_apply store_user_set "$username" "hash=${hash}" disabled=false password_changed=today || exit $?

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
    store_require || exit 1
    validate_username "$username"
    local -A ui=()
    if ! _user_info "$username"; then
        error "No tacctl user named '${username}'."
        exit 1
    fi
    if [[ "${ui[status]}" == "disabled" ]]; then
        error "User '${username}' is disabled. Ask a superuser to re-enable it."
        exit 1
    fi
    local stored_hash
    stored_hash=$(model_user "$username" hash) || exit 1

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

    store_apply store_user_set "$username" "hash=${hash}" password_changed=today || exit $?
    logger -t tacctl -p auth.info "passwd OK user=${username} (self-service)" 2>/dev/null || true
    info "Password changed for '${username}'."
    echo ""
}

# --- DISABLE ---
# The user keeps its password hash in the store; 'disabled: true' makes the
# renderer emit a hash nothing matches.
cmd_disable() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user disable <username>"
        exit 1
    fi
    store_require || exit 1
    validate_username "$username"
    local -A ui=()
    if ! _user_info "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    if [[ "${ui[status]}" == "disabled" ]]; then
        warn "User '${username}' is already disabled."
        exit 0
    fi

    store_apply store_user_set "$username" disabled=true || exit $?

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
    store_require || exit 1
    validate_username "$username"
    local -A ui=()
    if ! _user_info "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    if [[ "${ui[status]}" != "disabled" ]]; then
        warn "User '${username}' is not disabled."
        exit 0
    fi

    # Nothing to restore: a seeded placeholder, the accounting sink, or a
    # user whose saved hash did not survive the import.
    if [[ "${ui[has_hash]}" != "1" ]]; then
        error "No saved hash found for '${username}'. Set a new password instead:"
        error "  tacctl user passwd ${username}"
        exit 1
    fi

    store_apply store_user_set "$username" disabled=false || exit $?

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
    local -A ui=()
    if ! _user_info "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local pw_date="${ui[password_changed]}" pw_age="" last_login
    if [[ "$pw_date" != "unknown" ]]; then
        pw_age=$(( ( $(date +%s) - $(date -d "$pw_date" +%s) ) / 86400 ))
    fi
    last_login=$(backends_last_login "$username")

    echo ""
    echo -e "  ${BOLD}User:${NC}             ${username}"
    echo -e "  ${BOLD}Group:${NC}            ${ui[group]}"
    if [[ "${ui[status]}" == "disabled" ]]; then
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
    [[ -n "${ui[priv_lvl]}" ]]      && echo -e "  ${BOLD}Cisco priv-lvl:${NC}   ${ui[priv_lvl]}"
    [[ -n "${ui[juniper_class]}" ]] && echo -e "  ${BOLD}Juniper class:${NC}    ${ui[juniper_class]}"
    # Algorithm and cost only ('$2b$12$'); never the salt or digest.
    echo -e "  ${BOLD}Hash type:${NC}        ${ui[hash_type]}"
    if [[ -z "${ui[scopes]}" ]]; then
        echo -e "  ${BOLD}Scopes:${NC}           ${RED}(none — cannot authenticate on any device)${NC}"
    else
        local first=1 s label
        while IFS= read -r s; do
            [[ -z "$s" ]] && continue
            if grep -qxF -- "$s" <<< "${ui[orphans]}"; then
                label="${RED}${s} (ORPHAN)${NC}"
            else
                label="$s"
            fi
            if (( first )); then
                echo -e "  ${BOLD}Scopes:${NC}           ${label}"
                first=0
            else
                echo -e "                    ${label}"
            fi
        done <<< "${ui[scopes]}"
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
    local -A ui=()
    if ! _user_info "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    # Show user details
    echo ""
    echo -e "  ${BOLD}User:${NC}           ${username}"
    echo -e "  ${BOLD}Group:${NC}          ${ui[group]}"
    if [[ "${ui[status]}" == "disabled" ]]; then
        echo -e "  ${BOLD}Status:${NC}         ${RED}disabled${NC}"
        echo -e "  ${BOLD}PW changed:${NC}     ${ui[password_changed]}"
        echo ""
        error "User is disabled — cannot verify password."
        exit 1
    fi
    echo -e "  ${BOLD}Status:${NC}         ${GREEN}active${NC}"
    echo -e "  ${BOLD}PW changed:${NC}     ${ui[password_changed]}"
    echo ""

    local stored_hash
    stored_hash=$(model_user "$username" hash) || exit 1

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
# The store keeps everything about a user under its name, so the hash, the
# disabled flag and the password date all move with it.
cmd_rename() {
    local oldname="${1:-}"
    local newname="${2:-}"

    if [[ -z "$oldname" || -z "$newname" ]]; then
        error "Usage: tacctl user rename <old-username> <new-username>"
        exit 1
    fi
    store_require || exit 1
    validate_username "$oldname"
    validate_username "$newname"
    reject_reserved_username "$newname"
    if ! model_user_exists "$oldname"; then
        error "User '${oldname}' does not exist."
        exit 1
    fi
    if model_user_exists "$newname"; then
        error "User '${newname}' already exists."
        exit 1
    fi

    store_apply store_user_rename "$oldname" "$newname" || exit $?

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
    store_require || exit 1
    validate_username "$username"
    validate_class_name "$newgroup"
    local oldgroup
    if ! oldgroup=$(model_user "$username" group); then
        error "User '${username}' does not exist."
        exit 1
    fi
    if ! model_group_exists "$newgroup"; then
        local available
        available=$(model_group_info | cut -d'|' -f1 | paste -sd'|' || true)
        error "Group '${newgroup}' does not exist. Available: ${available}"
        exit 1
    fi

    if [[ "$oldgroup" == "$newgroup" ]]; then
        info "User '${username}' is already in group '${newgroup}'."
        return
    fi

    store_apply store_user_set "$username" "group=${newgroup}" || exit $?

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
    case "$sub" in
        add|remove|set|clear) store_require || exit 1 ;;
    esac
    validate_username "$username"
    local -A ui=()
    if ! _user_info "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi
    local current="${ui[scopes]}"

    case "$sub" in
        ""|list|-h|--help|help)
            echo ""
            echo -e "${BOLD}Scopes for user '${username}'${NC}"
            echo "--------------------------------------------"
            if [[ -z "$current" ]]; then
                echo -e "  ${RED}(none — user cannot authenticate on any device)${NC}"
            else
                local s
                while IFS= read -r s; do
                    [[ -z "$s" ]] && continue
                    if grep -qxF -- "$s" <<< "${ui[orphans]}"; then
                        echo -e "  ${RED}- ${s}  (ORPHAN: scope does not exist)${NC}"
                    else
                        echo "  - ${s}"
                    fi
                done <<< "$current"
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
            local s all_scopes
            all_scopes=$(model_scopes_by_routing) || exit 1
            local -a SCOPES
            IFS=',' read -ra SCOPES <<< "$arg"
            for s in "${SCOPES[@]}"; do
                s=$(echo "$s" | xargs)
                [[ -z "$s" ]] && continue
                if ! grep -qxF -- "$s" <<< "$all_scopes"; then
                    error "Scope '${s}' does not exist. Available: $(paste -sd' ' <<< "$all_scopes")"
                    exit 1
                fi
                # within-input dedupe
                if ! printf '%s\n' "$requested" | grep -qxF -- "$s"; then
                    requested+="${requested:+$'\n'}${s}"
                fi
            done
            [[ -z "$requested" ]] && { error "No valid scope names provided."; exit 1; }

            local new_list
            local changed="" noop=""
            if [[ "$sub" == "set" ]]; then
                new_list=$(printf '%s\n' "$requested" | paste -sd,)
                changed="$requested"
            elif [[ "$sub" == "add" ]]; then
                new_list="$current"
                while IFS= read -r s; do
                    [[ -z "$s" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF -- "$s"; then
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
                    if printf '%s\n' "$current" | grep -qxF -- "$s"; then
                        changed+="${changed:+$'\n'}${s}"
                        new_list=$(printf '%s\n' "$new_list" | grep -vxF -- "$s" || true)
                    else
                        noop+="${noop:+ }${s}"
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { warn "Nothing to remove (not present: ${noop})."; exit 0; }
                new_list=$(printf '%s\n' "$new_list" | awk 'NF' | paste -sd,)
            fi

            store_apply store_user_set "$username" "scopes=${new_list}" || exit $?
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
            if [[ -z "$current" ]]; then
                info "User '${username}' already has no scopes."
                return
            fi
            warn "WARNING: ${username} will be unable to authenticate on any device"
            warn "until you grant at least one scope with 'tacctl user scope ${username} add <name>'"
            warn "(Distinct from 'tacctl user disable' — the password hash is preserved.)"
            read -rp "  Clear all scopes for '${username}'? [y/N]: " confirm || true
            [[ ! "$confirm" =~ ^[Yy] ]] && { info "Aborted."; return; }
            store_apply store_user_set "$username" "scopes=" || exit $?
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

