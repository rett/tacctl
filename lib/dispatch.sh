# shellcheck shell=bash
# tacctl lib/dispatch.sh -- caller tiers, sudoers drop-ins, config dispatcher, usage
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# =====================================================================
#  CALLER TIERS (read-only / operator / superuser)
# =====================================================================
#
# tacctl always runs as root, so the tier of the person behind sudo is
# enforced here as well as in the sudoers drop-in ('tacctl config sudoers
# tiers'): sudoers argument globs are loose, this gate is not.
#
# Only callers in the local group $TIER_USERS_GROUP are tier-managed --
# those are the accounts tacctl provisions for TACACS+ users. Everyone
# else who reaches this point (root, a local admin with sudo) keeps the
# full access they always had. For a managed caller the tier comes from
# the model (the user's group and its priv-lvl), never from local group
# membership, so a stale local group cannot grant more than the user's
# TACACS+ group does.
TIER_USERS_GROUP="tac-users"
TIER_GROUP_READONLY="tac-readonly"
TIER_GROUP_OPERATOR="tac-operator"
TIER_GROUP_SUPERUSER="tac-superuser"

# priv-lvl -> tier. 15 is superuser; the shipped operator group is 7.
tier_for_privlvl() {
    local privlvl="${1:-}"
    [[ "$privlvl" =~ ^[0-9]+$ ]] || { echo "none"; return; }
    if   (( privlvl >= 15 )); then echo "superuser"
    elif (( privlvl >= 7  )); then echo "operator"
    else                           echo "readonly"
    fi
}

# Prints: unrestricted | superuser | operator | readonly | none
# 'none' = tier-managed caller with no usable tacctl user (unknown or
# disabled), which is denied everything.
caller_tier() {
    local caller="${SUDO_USER:-}"
    if [[ -z "$caller" || "$caller" == "root" ]]; then
        echo "unrestricted"
        return
    fi
    # No pipeline here: under pipefail a SIGPIPE would read as "not a
    # member" and fail open.
    local caller_groups
    caller_groups=$(id -nG -- "$caller" 2>/dev/null) || caller_groups=""
    if [[ " ${caller_groups} " != *" ${TIER_USERS_GROUP} "* ]]; then
        echo "unrestricted"
        return
    fi
    if [[ ! "$caller" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "none"
        return
    fi
    # Empty for an unknown or disabled user, and when the model cannot be
    # read at all: every one of those is denied.
    local privlvl
    privlvl=$(model_user_privlvl "$caller" 2>/dev/null) || privlvl=""
    tier_for_privlvl "$privlvl"
}

# tier_permits <tier> <command> [subcommand] -> 0 if allowed.
# Keep in step with emit_tier_sudoers(). Anything that prints a shared
# secret or a password hash (config cisco|juniper|wti, scope show|secret,
# backup diff, config dump) is superuser-only.
tier_permits() {
    local tier="$1" cmd="${2:-}" sub="${3:-}"
    case "$tier" in
        unrestricted|superuser) return 0 ;;
        readonly|operator) ;;
        *) return 1 ;;
    esac
    case "$cmd" in
        ""|passwd|status|version|--version|-v|hash|_completion-names) return 0 ;;
    esac
    case "$cmd $sub" in
        "user list"|"user show"|"group list"|"scope list") return 0 ;;
    esac
    [[ "$tier" == "operator" ]] || return 1
    case "$cmd $sub" in
        "log tail"|"log search"|"log failures"|"log accounting") return 0 ;;
        "config validate"|"backup list") return 0 ;;
    esac
    return 1
}

enforce_tier() {
    local tier
    tier=$(caller_tier)
    if tier_permits "$tier" "$@"; then
        return 0
    fi
    logger -t tacctl -p auth.warning \
        "tier DENY user=${SUDO_USER:-root} tier=${tier} cmd=${1:-} ${2:-}" 2>/dev/null || true
    if [[ "$tier" == "none" ]]; then
        error "'${SUDO_USER}' has no active tacctl user, so tacctl access is denied."
    else
        error "'tacctl ${1:-} ${2:-}' is not permitted for the ${tier} tier."
    fi
    exit 1
}

# --- CONFIG dispatcher ---
cmd_config() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        show)
            cmd_config_show
            ;;
        cisco)
            cmd_config_cisco "$@"
            ;;
        juniper)
            cmd_config_juniper "$@"
            ;;
        wti)
            cmd_config_wti "$@"
            ;;
        linux)
            cmd_config_linux "$@"
            ;;
        validate)
            cmd_config_validate
            ;;
        render)
            cmd_config_render "$@"
            ;;
        dump)
            cmd_config_dump
            ;;
        defaults)
            conf_emit_defaults
            ;;
        get)
            if [[ -z "${1:-}" ]]; then
                error "Usage: tacctl config get <dotted.path> [fallback]"
                exit 1
            fi
            conf_get "$@"
            ;;
        get-list)
            if [[ -z "${1:-}" ]]; then
                error "Usage: tacctl config get-list <dotted.path>"
                exit 1
            fi
            conf_get_list "$@"
            ;;
        loglevel)
            cmd_config_loglevel "$@"
            ;;
        listen)
            cmd_config_listen "$@"
            ;;
        metrics)
            cmd_config_metrics "$@"
            ;;
        sudoers)
            cmd_config_sudoers "$@"
            ;;
        password-age)
            cmd_config_password_age "$@"
            ;;
        bcrypt-cost)
            cmd_config_bcrypt_cost "$@"
            ;;
        password-min-length)
            cmd_config_password_min_length "$@"
            ;;
        secret-min-length)
            cmd_config_secret_min_length "$@"
            ;;
        diff)
            cmd_backup diff "$@"
            ;;
        restore)
            cmd_backup restore "$@"
            ;;
        allow)
            cmd_config_prefix_filter "prefix_allow" "$@"
            ;;
        deny)
            cmd_config_prefix_filter "prefix_deny" "$@"
            ;;
        mgmt-acl)
            cmd_config_mgmt_acl "$@"
            ;;
        branch)
            cmd_config_branch "$@"
            ;;
        *)
            echo ""
            echo -e "${BOLD}Config Commands${NC}"
            echo ""
            echo "Usage: tacctl config <subcommand> [value]"
            echo ""
            echo "Subcommands:"
            echo "  show                                 Show current configuration"
            echo "  dump                                 Show tacctl defaults + overrides + merged view"
            echo "  defaults                             Print canonical tacctl defaults (shipped)"
            echo "  get <path> [fallback]                Read a dotted-path value from the merged config"
            echo "  get-list <path>                      Read a list value (one item per line)"
            echo "  validate                             Validate config syntax and structure"
            echo "  render [--force]                     Regenerate tacquito.yaml from the store (--force overwrites hand edits)"
            echo "  diff [timestamp]                     Diff current config vs last backup (or named one)"
            echo "  restore <timestamp>                  Restore a prior backup (prompts for confirmation)"
            echo "  loglevel [debug|info|error]          Show or change log level"
            echo "  listen [show|tcp|tcp6|reset] [addr]  Show, change, or reset TCP listen address"
            echo "  metrics <show|enable|disable|address <host:port>|reset>  Prometheus exporter control"
            echo "  sudoers [show|install|remove] [grp]  Manage NOPASSWD sudoers drop-in for tacctl"
            echo "  sudoers tiers [show|install|remove]  Manage per-tier (RO/OP/SU) sudoers rules for TACACS+ users"
            echo "  password-age [days]                  Show or set password age warning threshold"
            echo "  bcrypt-cost [10-14]                  Show or set bcrypt cost factor (default 12)"
            echo "  password-min-length [8-64]           Show or set minimum interactive password length (default 12)"
            echo "  secret-min-length [16-128]           Show or set minimum shared-secret length (default 16)"
            echo "  allow list|add|remove|clear          Manage connection allow list (IP ACL; add/remove accept comma-lists)"
            echo "  deny list|add|remove|clear           Manage connection deny list (IP ACL; add/remove accept comma-lists)"
            echo "  mgmt-acl list|add|remove|clear       Manage Cisco VTY-ACL + Juniper lo0-filter permits"
            echo "  cisco   [--scope <name>] [--legacy]  Show working Cisco device configuration for a scope (--legacy = IOS 12.x syntax)"
            echo "  juniper [--scope <name>]             Show working Juniper device configuration for a scope"
            echo "  wti     [--scope <name>]             Show step-by-step WTI console-server (v8.x serial menu) setup for a scope"
            echo "  linux   build|script|remove-script   TACACS+ login for Linux hosts (pam_tacplus install/removal scripts)"
            echo "  branch [name]                        Show or change the tacctl repo branch"
            echo ""
            echo "Examples:"
            echo "  tacctl config show"
            echo "  tacctl config validate"
            echo "  tacctl config loglevel debug"
            echo "  tacctl config listen tcp6 [::]:49"
            echo "  tacctl config sudoers install adm"
            echo "  tacctl config cisco --scope prod"
            echo "  tacctl config cisco --scope prod --legacy   # legacy IOS 12.x syntax"
            echo "  tacctl config wti --scope prod"
            echo ""
            exit 1
            ;;
    esac
}

# --- CONFIG SUDOERS ---
# Manages an optional /etc/sudoers.d/tacctl drop-in that grants NOPASSWD
# on /usr/local/bin/tacctl to a given group. Not installed by default --
# operators opt in explicitly.
SUDOERS_FILE="${TACCTL_SUDOERS_FILE:-/etc/sudoers.d/tacctl}"

TIER_SUDOERS_FILE="${TACCTL_TIER_SUDOERS_FILE:-/etc/sudoers.d/tacctl-tiers}"

# Sudoers body for the tier groups. Keep in step with tier_permits(), which
# re-checks every call inside tacctl (the globs below only narrow what sudo
# will start). The lower tiers are NOPASSWD because every command listed is
# either read-only or, for 'passwd', asks for the current password itself.
emit_tier_sudoers() {
    local t="/usr/local/bin/tacctl"
    cat <<EOF
# Managed by tacctl. Per-tier access for TACACS+ users with local accounts.
# Remove with: tacctl config sudoers tiers remove
Cmnd_Alias TACCTL_RO = ${t} "", ${t} passwd, ${t} status, ${t} version, \\
    ${t} user list, ${t} user show *, ${t} group list, ${t} scope list, \\
    ${t} _completion-names *
Cmnd_Alias TACCTL_OP = ${t} log tail, ${t} log tail *, ${t} log search *, \\
    ${t} log failures, ${t} log accounting, ${t} log accounting *, \\
    ${t} config validate, ${t} backup list

%${TIER_GROUP_SUPERUSER} ALL=(ALL:ALL) ALL
%${TIER_GROUP_SUPERUSER} ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP
%${TIER_GROUP_OPERATOR} ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP
%${TIER_GROUP_READONLY} ALL=(root) NOPASSWD: TACCTL_RO
EOF
}

cmd_config_sudoers_tiers() {
    local sub="${1:-show}"
    case "$sub" in
        show)
            echo ""
            if [[ -f "$TIER_SUDOERS_FILE" ]]; then
                echo "  Status: installed at ${TIER_SUDOERS_FILE}"
            else
                echo "  Status: not installed. 'tacctl config sudoers tiers install' would write:"
            fi
            echo ""
            if [[ -f "$TIER_SUDOERS_FILE" ]]; then
                sed 's/^/    /' "$TIER_SUDOERS_FILE"
            else
                emit_tier_sudoers | sed 's/^/    /'
            fi
            echo ""
            ;;
        install)
            local tmp
            tmp=$(mktemp)
            emit_tier_sudoers > "$tmp"
            if ! visudo -cf "$tmp" >/dev/null; then
                error "visudo validation failed. Not installed."
                rm -f "$tmp"
                return 1
            fi
            install -m 0440 -o root -g root "$tmp" "$TIER_SUDOERS_FILE"
            rm -f "$tmp"
            info "Installed ${TIER_SUDOERS_FILE}."
            info "Tiers apply to members of ${TIER_GROUP_READONLY}, ${TIER_GROUP_OPERATOR} and ${TIER_GROUP_SUPERUSER}."
            echo ""
            ;;
        remove)
            if [[ ! -f "$TIER_SUDOERS_FILE" ]]; then
                info "Not installed. Nothing to remove."
                return
            fi
            rm -f "$TIER_SUDOERS_FILE"
            info "Removed ${TIER_SUDOERS_FILE}."
            ;;
        *)
            error "Invalid subcommand: '${sub}'. Use: tiers show, tiers install, or tiers remove"
            return 1
            ;;
    esac
}

cmd_config_sudoers() {
    local sub="${1:-}"
    local group="${2:-adm}"

    if [[ "$sub" == "tiers" ]]; then
        shift
        cmd_config_sudoers_tiers "$@"
        return
    fi

    # Accept "%adm" or "adm" -- normalize to the bare group name.
    group="${group#%}"

    case "$sub" in
        ""|show)
            echo ""
            if [[ -f "$SUDOERS_FILE" ]]; then
                echo "  Status: installed at ${SUDOERS_FILE}"
                echo ""
                echo "  Contents:"
                sed 's/^/    /' "$SUDOERS_FILE"
            else
                echo "  Status: not installed"
            fi
            echo ""
            echo "  Usage: tacctl config sudoers <show|install|remove> [group]"
            echo "  Examples:"
            echo "    tacctl config sudoers install          # grant to group 'adm'"
            echo "    tacctl config sudoers install wheel    # grant to group 'wheel'"
            echo "    tacctl config sudoers remove"
            echo "    tacctl config sudoers tiers [show|install|remove]   # RO/OP/SU rules for TACACS+ users"
            echo ""
            return
            ;;
        install) ;;
        remove)
            if [[ ! -f "$SUDOERS_FILE" ]]; then
                info "Not installed. Nothing to remove."
                return
            fi
            rm -f "$SUDOERS_FILE"
            info "Removed ${SUDOERS_FILE}."
            return
            ;;
        *)
            error "Invalid subcommand: '${sub}'. Use: show, install, or remove"
            return 1
            ;;
    esac

    if ! [[ "$group" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]]; then
        error "Invalid group name: '${group}'"
        return 1
    fi

    # Confirm -- this grants the group passwordless root via tacctl.
    echo ""
    warn "This grants members of group '%${group}' passwordless sudo on"
    warn "/usr/local/bin/tacctl, which can modify system config and restart"
    warn "services. Effectively passwordless root for that group."
    echo ""
    read -rp "  Install ${SUDOERS_FILE} for group '%${group}'? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        info "Aborted."
        return
    fi

    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<EOF
# Managed by tacctl. Grants passwordless sudo on /usr/local/bin/tacctl
# to members of group '${group}'. Remove with: tacctl config sudoers remove
%${group} ALL=(ALL) NOPASSWD: /usr/local/bin/tacctl
EOF

    if ! visudo -cf "$tmp" >/dev/null; then
        error "visudo validation failed. Not installed."
        rm -f "$tmp"
        return 1
    fi

    install -m 0440 -o root -g root "$tmp" "$SUDOERS_FILE"
    rm -f "$tmp"
    info "Installed ${SUDOERS_FILE} for group '%${group}'."
    echo ""
}

# =====================================================================
#  MAIN
# =====================================================================

usage() {
    echo ""
    echo -e "${BOLD}Tacquito Control${NC} ($(get_version))"
    echo ""
    echo "Usage: tacctl <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  install [--branch <name>]     Install tacquito server and configure from scratch"
    echo "  upgrade [--branch <name>]     Pull latest source, rebuild, and update scripts"
    echo "  uninstall                     Remove tacquito and all associated files"
    echo "  status                        Show service health, stats, and recent errors"
    echo "  passwd                        Change your own password (asks for the current one)"
    echo "  user <subcommand>             User management (list, add, remove, passwd, scope, ...)"
    echo "  group <subcommand>            Group management (list, add, edit, remove)"
    echo "  scope <subcommand>            Scope management (named CIDR + shared-secret bundles)"
    echo "  host <subcommand>             Linux hosts: enroll, sync, unenroll TACACS+ login over SSH"
    echo "  config <subcommand>           Configuration (show, cisco, juniper, wti, validate, ...)"
    echo "  log <subcommand>              Log viewer (tail, search, failures, accounting)"
    echo "  backup <subcommand>           Backup management (list, diff, restore)"
    echo "  hash <subcommand>             Bcrypt helper (generate, commands — runs as invoking user, no sudo)"
    echo "  version                       Print tacctl version"
    echo ""
    echo "Run any command without arguments for detailed help, e.g.:"
    echo "  tacctl user"
    echo "  tacctl config"
    echo ""
    echo "Examples:"
    echo "  tacctl install"
    echo "  tacctl upgrade"
    echo "  tacctl user add jsmith superuser"
    echo "  tacctl user scope jsmith add prod"
    echo "  tacctl scope add prod --prefixes 10.10.0.0/16 --secret generate"
    echo "  tacctl config cisco --scope prod"
    echo ""
}

