# shellcheck shell=bash
# tacctl lib/render_devices.sh -- device templates, mgmt-ACL data, Cisco/Juniper/WTI renderers
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# --- Resolve template file (user override → repo default) ---
TEMPLATE_DIR_LOCAL="${TACCTL_ETC}/templates"
TEMPLATE_DIR_REPO="$(if cd "${SCRIPT_DIR}/../config/templates" 2>/dev/null; then pwd; fi)"

resolve_template() {
    local name="$1"
    if [[ -f "${TEMPLATE_DIR_LOCAL}/${name}.template" ]]; then
        echo "${TEMPLATE_DIR_LOCAL}/${name}.template"
    elif [[ -n "$TEMPLATE_DIR_REPO" && -f "${TEMPLATE_DIR_REPO}/${name}.template" ]]; then
        echo "${TEMPLATE_DIR_REPO}/${name}.template"
    fi
}

# --- Convert an IPv4 CIDR to Cisco wildcard-mask form (10.1.0.0/16 -> "10.1.0.0 0.0.255.255") ---
# IPv6 inputs return empty — callers decide whether to skip or warn.
cidr_to_cisco_wildcard() {
    local value="$1"
    python3 -c "
import ipaddress, sys
n = ipaddress.ip_network(sys.argv[1], strict=False)
if n.version != 4:
    sys.exit(0)
print(f'{n.network_address} {n.hostmask}')
" "$value" 2>/dev/null
}

# --- Read the mgmt-ACL permit list ---
# Optional second argument is the scope name. When supplied, the
# resolution chain is: per-scope override (mgmt_acl.permits.<scope>)
# if non-empty -> global (mgmt_acl.permits) -> shipped default ([]).
# Callers that don't care about per-scope overrides (the global
# setter/viewer under `tacctl config mgmt-acl`) omit the scope arg.
# One CIDR per stdout line; input is expected to already be canonical
# (writers canonicalize before storing). Empty list = no output.
read_mgmt_acl_cidrs() {
    local scope="${1:-}" list=""
    if [[ -n "$scope" ]]; then
        list=$(conf_get_list "scope_mgmt_acl.permits.${scope}")
    fi
    if [[ -z "$list" ]]; then
        list=$(conf_get_list mgmt_acl.permits)
    fi
    printf '%s\n' "$list" | python3 -c "
import ipaddress, sys
for line in sys.stdin:
    s = line.strip()
    if not s:
        continue
    try:
        print(ipaddress.ip_network(s, strict=False))
    except ValueError:
        print(s)
"
}

# --- Write the mgmt-ACL permit list ---
# Replaces mgmt_acl.permits (or per-scope mgmt_acl.permits.<scope>
# when the second arg is set) with the given newline-separated CIDR
# list (canonicalized, deduped, specificity-sorted). Empty input
# unsets the key (revert to default []). Writers are expected to pass
# validated CIDRs; malformed entries are dropped silently.
write_mgmt_acl_cidrs() {
    local list="$1" scope="${2:-}"
    local path="mgmt_acl.permits"
    [[ -n "$scope" ]] && path="scope_mgmt_acl.permits.${scope}"
    printf '%s\n' "$list" | python3 -c "
import ipaddress, sys
def key_fn(c):
    n = ipaddress.ip_network(c, strict=False)
    # Primary: version (v4 before v6). Secondary: broadcast address
    # ascending — disjoint ranges sort by end-of-range, and overlapping
    # subnets naturally fall just above their supernet (the subnet
    # ends earlier than the range containing it). Tertiary: network
    # address, for determinism across same-end-address edge cases.
    return (n.version, int(n.broadcast_address), int(n.network_address))
cidrs = []
for line in sys.stdin:
    s = line.strip()
    if not s:
        continue
    try:
        cidrs.append(str(ipaddress.ip_network(s, strict=False)))
    except ValueError:
        continue
for c in sorted(set(cidrs), key=key_fn):
    print(c)
" | conf_set_list "$path"
}

# --- Read an mgmt-ACL name override (cisco|juniper) with default fallback ---
# Backed by mgmt_acl.names.{cisco,juniper} in the unified config.
# conf_emit_defaults() ships VTY-ACL / MGMT-ACL; overrides in
# tacctl.yaml win.
#
# Optional second argument is the scope name. When supplied, the
# resolution chain is:
#   1. per-scope override  (mgmt_acl.names.<vendor>.<scope>)
#   2. global override     (mgmt_acl.names.<vendor>)
#   3. shipped default     (VTY-ACL / MGMT-ACL)
# Callers that don't care about per-scope overrides (the global
# setter/viewer under `tacctl config mgmt-acl`) omit the scope arg.
read_mgmt_acl_name() {
    local vendor="$1" scope="${2:-}" global=""
    case "$vendor" in
        cisco)   global=$(conf_get mgmt_acl.names.cisco   "$CISCO_ACL_NAME_DEFAULT") ;;
        juniper) global=$(conf_get mgmt_acl.names.juniper "$JUNIPER_ACL_NAME_DEFAULT") ;;
        *)       echo ""; return ;;
    esac
    if [[ -n "$scope" ]]; then
        conf_get "scope_mgmt_acl.names.${vendor}.${scope}" "$global"
    else
        echo "$global"
    fi
}

# --- Validate an ACL name for Cisco / Juniper use ---
# Both vendors accept letters, digits, `_`, `-`; names must start with a
# letter; keep length <= 63 to match common IOS / Junos limits.
validate_acl_name() {
    local name="$1"
    if [[ -z "$name" ]]; then
        error "ACL name must not be empty."
        exit 1
    fi
    if [[ ${#name} -gt 63 ]]; then
        error "ACL name too long (${#name} chars; max 63)."
        exit 1
    fi
    if [[ ! "$name" =~ ^[A-Za-z][A-Za-z0-9_-]*$ ]]; then
        error "Invalid ACL name '${name}'. Must start with a letter and contain only letters, digits, '_', '-'."
        exit 1
    fi
}

# --- Write an mgmt-ACL name override (cisco|juniper) ---
# Sets mgmt_acl.names.<which> in tacctl.yaml. Setting to the default value
# reverts (via the revert-to-default logic in conf_set).
write_mgmt_acl_name() {
    local which="$1" name="$2"
    case "$which" in
        cisco|juniper) ;;
        *) error "write_mgmt_acl_name: unknown target '${which}'"; return 1 ;;
    esac
    conf_set "mgmt_acl.names.${which}" "$name"
    info "Set ${which}-name = '${name}'."
}

# --- CONFIG CISCO (show working device config) ---
# The *_BLOCK / *_CONFIG / *_RULES values built here are device-config text
# handed to envsubst via the environment, never re-parsed as shell words, so
# the quotes embedded in them are meant literally.
# shellcheck disable=SC2089,SC2090
cmd_config_cisco() {
    # Parse --scope <name> and --legacy
    local scope="" legacy=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scope)
                scope="${2:-}"
                [[ -z "$scope" ]] && { error "Usage: tacctl config cisco [--scope <name>] [--legacy]"; exit 1; }
                shift 2
                ;;
            --legacy)
                legacy=1
                shift
                ;;
            *)
                error "Unknown argument: '$1'"
                error "Usage: tacctl config cisco [--scope <name>] [--legacy]"
                exit 1
                ;;
        esac
    done
    if [[ -z "$scope" ]]; then
        scope=$(read_default_scope)
        if [[ -z "$scope" ]]; then
            error "No default scope set and no --scope provided."
            error "Run 'tacctl scope default <name>' or pass --scope <name>."
            exit 1
        fi
    elif ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist. Available: $(list_scopes | paste -sd' ')"
        exit 1
    fi
    local secret server_ip
    secret=$(read_scope_secret "$scope")
    server_ip=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [[ -z "$server_ip" ]]; then
        server_ip="<TACQUITO_SERVER_IP>"
    fi

    # Compute "other scopes" list for the header.
    local other_scopes
    # `grep -vxF` exits 1 when no lines survive (e.g. only the one named scope
    # exists). Under `set -o pipefail` that kills the subshell and, via
    # `set -e`, the whole script. Append `|| true` to the grep so the pipeline
    # stays zero-exit when the "other scopes" set is empty.
    other_scopes=$(list_scopes | { grep -vxF "$scope" || true; } | paste -sd,)

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

    # Build the privilege-exec block from per-group mappings
    # (managed via 'tacctl group privilege'). For each group with priv-lvl
    # in 2-14, emit either its explicit mappings or a conservative built-in
    # default (move-DOWN commands only). De-dupe across multiple groups
    # sharing the same priv-lvl: IOS only needs one line per (level, cmd).
    local PRIVILEGE_COMMANDS=""
    local seen_pairs=""
    while IFS='|' read -r gname privlvl; do
        [[ -z "$gname" ]] && continue
        [[ "$privlvl" == "1" || "$privlvl" == "15" ]] && continue
        local cmds explicit
        explicit=$(read_group_privileges "$gname")
        if [[ -n "$explicit" ]]; then
            cmds="$explicit"
        else
            cmds=$(default_privileges_for_group "$gname")
        fi
        [[ -z "$cmds" ]] && continue
        local block_for_group="! --- ${gname} — Privilege Level ${privlvl} Commands ---"$'\n'
        local emitted_any="false"
        while IFS= read -r cmd; do
            [[ -z "$cmd" ]] && continue
            local pair="${privlvl}|${cmd}"
            # Dedup across groups sharing the same priv-lvl.
            if printf '%s\n' "$seen_pairs" | grep -qxF "$pair"; then
                continue
            fi
            seen_pairs+="${pair}"$'\n'
            block_for_group+="privilege exec level ${privlvl} ${cmd}"$'\n'
            emitted_any="true"
        done <<< "$cmds"
        if [[ "$emitted_any" == "true" ]]; then
            PRIVILEGE_COMMANDS+="${block_for_group}!"$'\n'
        fi
    done <<< "$group_info"

    local GROUP_SUMMARY=""
    while IFS='|' read -r gname privlvl; do
        [[ -z "$gname" ]] && continue
        GROUP_SUMMARY+="  ${gname}: priv-lvl ${privlvl}"$'\n'
    done <<< "$group_info"

    # Build the VTY-ACL block from the shared mgmt-acl list. IPv6 CIDRs
    # (if any) are skipped here — v6 would need an `ipv6 access-list`
    # and is not yet supported.
    #
    # Empty-list intentionally emits NO access-list (and a commented-out
    # access-class below). Emitting a placeholder permit was misleading:
    # pasting the output silently installed a bogus permit the operator
    # didn't configure. Comments are no-ops on IOS, so the empty-state
    # output is still safe to paste — it simply leaves the vty lines
    # unchanged until mgmt-acl is populated.
    local cisco_acl_name
    cisco_acl_name=$(read_mgmt_acl_name cisco "$scope")

    # Per-scope aaa-group-server label. Every AAA line references this
    # name — overriding per-scope lets operators match site naming
    # conventions (e.g. TACACS_PROD, ISE-GROUP). Default matches the
    # historical template value.
    local TACACS_GROUP
    TACACS_GROUP=$(conf_get "tacacs_group.${scope}" TACACS-GROUP)

    # AAA method-list order is per-scope. tacctl.yaml's aaa.order.<scope>
    # key flips every generated `aaa authentication login` /
    # `aaa authorization` line between tacacs-first (default — TACACS+
    # authoritative; local only kicks in on server outage) and
    # local-first (local break-glass credentials usable while TACACS+
    # is reachable; any local name that collides with a TACACS+ user
    # wins locally). Accounting method-lists are unaffected — they
    # always point at the TACACS group regardless of this setting.
    local aaa_order AUTHN_METHODS AUTHZ_EXEC_METHODS AUTHZ_CMD_METHODS
    aaa_order=$(conf_get "aaa.order.${scope}" tacacs-first)
    if [[ "$aaa_order" == "local-first" ]]; then
        AUTHN_METHODS="local group ${TACACS_GROUP}"
        AUTHZ_EXEC_METHODS="local group ${TACACS_GROUP} if-authenticated"
        AUTHZ_CMD_METHODS="local group ${TACACS_GROUP}"
    else
        AUTHN_METHODS="group ${TACACS_GROUP} local"
        AUTHZ_EXEC_METHODS="group ${TACACS_GROUP} local if-authenticated"
        AUTHZ_CMD_METHODS="group ${TACACS_GROUP} local"
    fi

    # Per-scope idle-session timeout. Default 60 minutes matches the
    # historical template; 0 means never expire.
    local EXEC_TIMEOUT
    EXEC_TIMEOUT=$(conf_get "exec_timeout.${scope}" 60)

    # Per-command authorization: emit `aaa authorization commands N`
    # only when at least one group has a commands: section in the YAML.
    # Without that gate, devices would still log normally; with it, IOS
    # asks tacquito for every command at each priv-lvl.
    local AUTHZ_COMMANDS_BLOCK=""
    if any_group_has_commands; then
        AUTHZ_COMMANDS_BLOCK="! Per-command authorization (managed by 'tacctl group commands').
aaa authorization commands 1 default ${AUTHZ_CMD_METHODS}
aaa authorization commands 7 default ${AUTHZ_CMD_METHODS}
aaa authorization commands 15 default ${AUTHZ_CMD_METHODS}"
    else
        AUTHZ_COMMANDS_BLOCK="! Per-command authorization not enabled.
! To restrict commands per group, use 'tacctl group commands'."
    fi

    local VTY_ACL_BLOCK VTY_ACCESS_CLASS mgmt_entries=""
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        local wildcard
        wildcard=$(cidr_to_cisco_wildcard "$entry")
        if [[ -n "$wildcard" ]]; then
            mgmt_entries+="  permit ${wildcard}"$'\n'
        fi
    done < <(read_mgmt_acl_cidrs "$scope")
    if [[ -n "$mgmt_entries" ]]; then
        VTY_ACL_BLOCK="ip access-list standard ${cisco_acl_name}
  remark Managed by tacctl — edit with 'tacctl config mgmt-acl'
${mgmt_entries}  deny   any log"
        VTY_ACCESS_CLASS="  access-class ${cisco_acl_name} in"
    else
        VTY_ACL_BLOCK="! ${cisco_acl_name} not emitted — mgmt-acl list is empty.
! Populate it on the tacquito server with
!   tacctl config mgmt-acl add <cidr>
! then re-run 'tacctl config cisco' to get the access-list block."
        VTY_ACCESS_CLASS="! access-class ${cisco_acl_name} in   ! uncomment after populating mgmt-acl"
    fi

    echo ""
    echo -e "${BOLD}Cisco IOS / IOS-XE Configuration${NC}  (scope: ${scope})"
    if [[ -n "$other_scopes" ]]; then
        echo -e "${YELLOW}(other scopes: ${other_scopes} — use --scope <name> to emit those)${NC}"
    fi
    echo -e "${YELLOW}Copy and paste into the device:${NC}"
    echo "--------------------------------------------"
    echo ""

    # TACACS+ server-definition block differs by IOS generation: legacy 12.x
    # global syntax vs the structured 'tacacs server <name>' block (15.0+).
    # Used only by the inline fallback below; the templates embed their own.
    local tacacs_server_block
    if [[ "$legacy" == 1 ]]; then
        tacacs_server_block="tacacs-server host ${server_ip} single-connection timeout 5 key ${secret}
!
aaa group server tacacs+ ${TACACS_GROUP}
  server ${server_ip}"
    else
        tacacs_server_block="tacacs server TACACS
  address ipv4 ${server_ip}
  key ${secret}
  single-connection
  timeout 5
!
aaa group server tacacs+ ${TACACS_GROUP}
  server name TACACS"
    fi

    local template_file template_name="cisco"
    [[ "$legacy" == 1 ]] && template_name="cisco-legacy"
    template_file=$(resolve_template "$template_name")
    # Filter the device-config emission through `awk 'NF'` so blank
    # lines introduced by multi-line `${VAR}` substitution don't reach
    # the operator. `!` separator lines have NF=1 so they survive.
    {
        if [[ -n "$template_file" ]]; then
            # The exports only need to reach envsubst in this same pipeline subshell.
            # shellcheck disable=SC2030
            export SERVER_IP="$server_ip" SECRET="$secret" PRIVILEGE_COMMANDS GROUP_SUMMARY VTY_ACL_BLOCK VTY_ACCESS_CLASS AUTHZ_COMMANDS_BLOCK AUTHN_METHODS AUTHZ_EXEC_METHODS EXEC_TIMEOUT TACACS_GROUP
            # shellcheck disable=SC2016  # envsubst takes the literal ${VAR} names
            envsubst '${SERVER_IP} ${SECRET} ${PRIVILEGE_COMMANDS} ${GROUP_SUMMARY} ${VTY_ACL_BLOCK} ${VTY_ACCESS_CLASS} ${AUTHZ_COMMANDS_BLOCK} ${AUTHN_METHODS} ${AUTHZ_EXEC_METHODS} ${EXEC_TIMEOUT} ${TACACS_GROUP}' < "$template_file"
        else
            cat <<EOF
! --- TACACS+ Server & AAA ---
service password-encryption
!
aaa new-model
!
! Optional: pin TACACS+ client to a known source interface.
! Uncomment and replace with your management interface, e.g.:
! ip tacacs source-interface Loopback0
!
${tacacs_server_block}
!
aaa authentication login default ${AUTHN_METHODS}
aaa authorization exec default ${AUTHZ_EXEC_METHODS}
aaa accounting exec default start-stop group ${TACACS_GROUP}
aaa accounting commands 1 default start-stop group ${TACACS_GROUP}
aaa accounting commands 7 default start-stop group ${TACACS_GROUP}
aaa accounting commands 15 default start-stop group ${TACACS_GROUP}
!
${AUTHZ_COMMANDS_BLOCK}
!
${PRIVILEGE_COMMANDS}
${VTY_ACL_BLOCK}
!
line con 0
  login authentication default
  exec-timeout ${EXEC_TIMEOUT} 0
!
line vty 0 15
  login authentication default
  transport input ssh
${VTY_ACCESS_CLASS}
  exec-timeout ${EXEC_TIMEOUT} 0
EOF
        fi
    } | awk 'NF'

    echo ""
    echo "--------------------------------------------"
    echo -e "${YELLOW}Group → Privilege Level Mapping:${NC}"
    echo -n "$GROUP_SUMMARY"
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - The 'local' fallback ensures access if TACACS+ is unreachable"
    echo "  - Ensure a local admin account exists as a backup"
    echo "  - Uncomment 'ip tacacs source-interface ...' to pin the TACACS+ client source"
    echo "  - ${cisco_acl_name} permits are managed with 'tacctl config mgmt-acl add <cidr>'"
    if [[ "$legacy" == 1 ]]; then
        echo "  - Type 6 (AES) key encryption is NOT available on IOS 12.x;"
        echo "    'service password-encryption' stores the key as Type 7."
    else
        echo "  - For Type 6 (AES) key encryption, run on the device first:"
        echo "      conf t ; key config-key password-encrypt <master-key>"
        echo "      password encryption aes"
        echo "    then re-enter the tacacs key. (Type 7 is trivially reversible.)"
    fi
    echo "  - Manage 'privilege exec level' mappings with 'tacctl group privilege add ...'"
    echo "    (defaults move only the verified priv-15 commands DOWN; nothing is moved UP)"
    if [[ -n "$template_file" ]]; then
        echo "  - Using template: ${template_file}"
    fi
    echo ""
}

# --- CONFIG JUNIPER (show working device config) ---
# The *_BLOCK / *_CONFIG / *_RULES values built here are device-config text
# handed to envsubst via the environment, never re-parsed as shell words, so
# the quotes embedded in them are meant literally.
# shellcheck disable=SC2089,SC2090
cmd_config_juniper() {
    # Parse --scope <name>
    local scope=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scope)
                scope="${2:-}"
                [[ -z "$scope" ]] && { error "Usage: tacctl config juniper [--scope <name>]"; exit 1; }
                shift 2
                ;;
            *)
                error "Unknown argument: '$1'"
                error "Usage: tacctl config juniper [--scope <name>]"
                exit 1
                ;;
        esac
    done
    if [[ -z "$scope" ]]; then
        scope=$(read_default_scope)
        if [[ -z "$scope" ]]; then
            error "No default scope set and no --scope provided."
            error "Run 'tacctl scope default <name>' or pass --scope <name>."
            exit 1
        fi
    elif ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist. Available: $(list_scopes | paste -sd' ')"
        exit 1
    fi
    local secret server_ip
    secret=$(read_scope_secret "$scope")
    server_ip=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [[ -z "$server_ip" ]]; then
        server_ip="<TACQUITO_SERVER_IP>"
    fi

    # Compute "other scopes" list for the header.
    local other_scopes
    # `grep -vxF` exits 1 when no lines survive (e.g. only the one named scope
    # exists). Under `set -o pipefail` that kills the subshell and, via
    # `set -e`, the whole script. Append `|| true` to the grep so the pipeline
    # stays zero-exit when the "other scopes" set is empty.
    other_scopes=$(list_scopes | { grep -vxF "$scope" || true; } | paste -sd,)

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
    # Define each template-user's class as a LOCAL class (reusing the
    # template-user name) instead of binding to a Junos predefined class.
    # Junos refuses to set permissions on predefined names (renames
    # `read-only` → `read-only-local` on commit), so granting
    # `view-configuration` — needed for monitoring tools like SolarWinds
    # to read the config tree — requires a non-predefined class.
    #   RO: view, view-configuration         (operational state + config tree)
    #   OP: operator-equivalent set + view-configuration
    #   RW: all
    local TEMPLATE_USERS=""
    while IFS='|' read -r gname jclass junos_class; do
        [[ -z "$gname" ]] && continue
        case "$junos_class" in
            read-only)
                TEMPLATE_USERS+="set system login class ${jclass} permissions view"$'\n'
                TEMPLATE_USERS+="set system login class ${jclass} permissions view-configuration"$'\n'
                TEMPLATE_USERS+="set system login user ${jclass} class ${jclass}"$'\n'
                ;;
            operator)
                TEMPLATE_USERS+="set system login class ${jclass} permissions clear"$'\n'
                TEMPLATE_USERS+="set system login class ${jclass} permissions network"$'\n'
                TEMPLATE_USERS+="set system login class ${jclass} permissions reset"$'\n'
                TEMPLATE_USERS+="set system login class ${jclass} permissions trace"$'\n'
                TEMPLATE_USERS+="set system login class ${jclass} permissions view"$'\n'
                TEMPLATE_USERS+="set system login class ${jclass} permissions view-configuration"$'\n'
                TEMPLATE_USERS+="set system login user ${jclass} class ${jclass}"$'\n'
                ;;
            super-user)
                TEMPLATE_USERS+="set system login class ${jclass} permissions all"$'\n'
                TEMPLATE_USERS+="set system login user ${jclass} class ${jclass}"$'\n'
                ;;
            *)
                TEMPLATE_USERS+="set system login user ${jclass} class ${junos_class}"$'\n'
                ;;
        esac
    done <<< "$group_juniper"
    TEMPLATE_USERS="${TEMPLATE_USERS%$'\n'}"

    # AAA method-list order is per-scope (aaa.order.<scope>). Junos has
    # a single authentication-order statement (no separate authz
    # method-list — permissions come from the user's login class).
    # Default tacacs-first emits `tacplus` alone — Junos falls back to
    # local password automatically when the server is unreachable, which
    # is exactly the desired breakglass behavior and avoids local-password
    # acceptance when tacplus is up but rejects the credential.
    # local-first keeps `[ password tacplus ]` so local users log in
    # ahead of tacplus while it's up.
    local junos_authn_order
    if [[ "$(conf_get "aaa.order.${scope}" tacacs-first)" == "local-first" ]]; then
        junos_authn_order="[ password tacplus ]"
    else
        junos_authn_order="tacplus"
    fi

    # Per-scope idle-session timeout (exec_timeout.<scope>). Junos
    # `idle-timeout` max is 60 minutes — schema already caps. 0 means
    # never expire (Junos and Cisco both honor it).
    local junos_idle_timeout
    junos_idle_timeout=$(conf_get "exec_timeout.${scope}" 60)

    local TACPLUS_CONFIG
    # `delete` first because Junos `set ... authentication-order` is
    # additive against an existing ordered list.
    # source-address pins the client source IP so prefix-based ACLs on
    # tacquito have a stable match. Emitted as a commented example —
    # pasting <MGMT_IP> literally fails; the operator must substitute
    # the device's management interface address (e.g. lo0 or fxp0).
    TACPLUS_CONFIG="delete system authentication-order
set system authentication-order ${junos_authn_order}
set system login idle-timeout ${junos_idle_timeout}
set system tacplus-server ${server_ip} secret ${secret}
set system tacplus-server ${server_ip} single-connection
# Optional: pin client source IP for prefix-ACL matching on tacquito.
# Replace 10.0.0.1 with the device's management interface address, e.g.:
#   set system tacplus-server ${server_ip} source-address 10.0.0.1
# Accounting events: login + change-log only. 'interactive-commands' is
# intentionally excluded because Junos internal daemons (mgd, jsd,
# health-probe op scripts, etc.) run non-tty CLI commands as root and
# generate a continuous stream of per-command accounting that is pure
# noise on the tacquito side. The login + change-log events still
# capture who logged in and who changed config.
set system accounting events [ login change-log ]
set system accounting destination tacplus"

    # Build the Juniper mgmt-acl block from the shared permit list.
    # When populated, emit live `set firewall …` commands so the filter
    # gets created in the candidate config on paste. The `set interfaces
    # lo0 … filter input` APPLY line stays commented, because that is
    # where the blackhole risk lives — an unreviewed lo0 filter can drop
    # BGP / OSPF / IS-IS to the RE. Defining the filter without applying
    # it is safe; the operator uncomments the apply line after review.
    # IPv6 CIDRs are skipped for now (filter would need family inet6).
    local juniper_acl_name
    juniper_acl_name=$(read_mgmt_acl_name juniper "$scope")
    local MGMT_ACL_BLOCK mgmt_terms=""
    local mgmt_has_any="false"
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        # Skip v6 — family inet filter only accepts v4 source-addresses.
        [[ "$entry" == *:* ]] && continue
        mgmt_has_any="true"
        mgmt_terms+="set firewall family inet filter ${juniper_acl_name} term permit-mgmt from source-address ${entry}"$'\n'
    done < <(read_mgmt_acl_cidrs "$scope")
    if [[ "$mgmt_has_any" == "true" ]]; then
        MGMT_ACL_BLOCK="# Restrict SSH / NETCONF to the configured mgmt subnets.
# These 'set firewall' lines define the filter in the candidate config.
# Activate it by uncommenting the 'set interfaces lo0 …' line below
# after reviewing — a misapplied lo0 filter can blackhole BGP / OSPF /
# IS-IS to the RE.
${mgmt_terms}set firewall family inet filter ${juniper_acl_name} term permit-mgmt from protocol tcp
set firewall family inet filter ${juniper_acl_name} term permit-mgmt from destination-port [ ssh 830 ]
set firewall family inet filter ${juniper_acl_name} term permit-mgmt then accept
set firewall family inet filter ${juniper_acl_name} term deny-mgmt from protocol tcp
set firewall family inet filter ${juniper_acl_name} term deny-mgmt from destination-port [ ssh 830 ]
set firewall family inet filter ${juniper_acl_name} term deny-mgmt then { log; discard; }
set firewall family inet filter ${juniper_acl_name} term default-accept then accept
#
# Apply (review first):
# set interfaces lo0 unit 0 family inet filter input ${juniper_acl_name}"
    else
        MGMT_ACL_BLOCK="# mgmt-acl empty — configure with 'tacctl config mgmt-acl add <cidr>' on the tacquito server
# to emit a source-restricted lo0 firewall filter here."
    fi

    local VERIFY_COMMANDS
    VERIFY_COMMANDS="  show configuration system tacplus-server
  show configuration system authentication-order"
    while IFS='|' read -r gname jclass junos_class; do
        [[ -z "$gname" ]] && continue
        VERIFY_COMMANDS+=$'\n'"  show configuration system login user ${jclass}"
    done <<< "$group_juniper"

    local GROUP_SUMMARY=""
    local class_desc
    while IFS='|' read -r gname jclass junos_class; do
        [[ -z "$gname" ]] && continue
        case "$junos_class" in
            read-only)  class_desc="local: view + view-configuration" ;;
            operator)   class_desc="local: clear/network/reset/trace/view + view-configuration" ;;
            super-user) class_desc="local: all" ;;
            *)          class_desc="$junos_class" ;;
        esac
        GROUP_SUMMARY+="  ${gname}: ${jclass} (${class_desc})"$'\n'
    done <<< "$group_juniper"

    # Build the per-class allow-commands / deny-commands block from
    # group commands rules (managed via 'tacctl group commands').
    # Junos enforces these patterns LOCALLY on each device, not via
    # TACACS+ — a config push is required after every change.
    #
    # v1 simplification: per-rule `match` regexes are dropped. Each
    # rule's `name` becomes part of an aggregated regex. Operators
    # needing finer control should hand-edit the Junos class
    # afterwards.
    local CLASS_COMMAND_RULES=""
    if any_group_has_commands; then
        CLASS_COMMAND_RULES="# Per-command authorization (enforced LOCALLY by Junos, not via TACACS+).
# Push these on every device after 'tacctl group commands' changes.
"
        while IFS='|' read -r gname jclass junos_class; do
            [[ -z "$gname" ]] && continue
            local rules
            rules=$(read_group_commands "$gname")
            [[ -z "$rules" ]] && continue
            local permit_names="" deny_names="" rule_default
            rule_default=$(read_group_default_action "$gname")
            while IFS='|' read -r rname raction _; do
                [[ -z "$rname" || "$rname" == "*" ]] && continue
                if [[ "$raction" == "permit" ]]; then
                    permit_names+="${permit_names:+|}${rname}"
                else
                    deny_names+="${deny_names:+|}${rname}"
                fi
            done <<< "$rules"
            CLASS_COMMAND_RULES+="# class '${jclass}' (group '${gname}', default ${rule_default})"$'\n'
            if [[ -n "$permit_names" ]]; then
                CLASS_COMMAND_RULES+="set system login class ${jclass} allow-commands \"^(${permit_names})( .*)?\$\""$'\n'
            fi
            if [[ -n "$deny_names" ]]; then
                CLASS_COMMAND_RULES+="set system login class ${jclass} deny-commands \"^(${deny_names})( .*)?\$\""$'\n'
            fi
            if [[ "$rule_default" == "deny" && -z "$permit_names" ]]; then
                CLASS_COMMAND_RULES+="# Default action is 'deny' but no allow-commands set —"$'\n'
                CLASS_COMMAND_RULES+="# this class will be unable to run anything. Add explicit"$'\n'
                CLASS_COMMAND_RULES+="# permits with 'tacctl group commands add ${gname} <name> --action permit'."$'\n'
            fi
        done <<< "$group_juniper"
        # Trim trailing newline so envsubst doesn't double-blank.
        CLASS_COMMAND_RULES="${CLASS_COMMAND_RULES%$'\n'}"
    else
        CLASS_COMMAND_RULES="# Per-command authorization not configured.
# To restrict commands per group, use 'tacctl group commands' on the tacquito server."
    fi

    echo ""
    echo -e "${BOLD}Juniper Junos Configuration${NC}  (scope: ${scope})"
    if [[ -n "$other_scopes" ]]; then
        echo -e "${YELLOW}(other scopes: ${other_scopes} — use --scope <name> to emit those)${NC}"
    fi
    echo -e "${YELLOW}Copy and paste into the device (configure mode):${NC}"
    echo "--------------------------------------------"
    echo ""

    local template_file
    template_file=$(resolve_template "juniper")
    if [[ -n "$template_file" ]]; then
        # Assigned and exported right here; the warning is cross-talk from
        # the cisco renderer's pipeline subshell.
        # shellcheck disable=SC2031
        export SERVER_IP="$server_ip" SECRET="$secret" TEMPLATE_USERS TACPLUS_CONFIG MGMT_ACL_BLOCK CLASS_COMMAND_RULES VERIFY_COMMANDS GROUP_SUMMARY
        # shellcheck disable=SC2016  # envsubst takes the literal ${VAR} names
        envsubst '${SERVER_IP} ${SECRET} ${TEMPLATE_USERS} ${TACPLUS_CONFIG} ${MGMT_ACL_BLOCK} ${CLASS_COMMAND_RULES} ${VERIFY_COMMANDS} ${GROUP_SUMMARY}' < "$template_file"
    else
        echo "# Step 1: Create template users (REQUIRED)"
        echo "$TEMPLATE_USERS"
        echo ""
        echo "# Step 2: Configure TACACS+"
        echo "$TACPLUS_CONFIG"
        echo ""
        echo "# Step 3: (optional) Per-class command rules"
        echo "$CLASS_COMMAND_RULES"
        echo ""
        echo "# Step 4: (optional) Management ACL"
        echo "$MGMT_ACL_BLOCK"
        echo ""
        echo "# Step 5: Commit"
        echo "commit"
    fi

    echo ""
    echo "--------------------------------------------"
    echo -e "${YELLOW}Group → Juniper Class Mapping:${NC}"
    echo -n "$GROUP_SUMMARY"
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - Template users MUST exist before TACACS+ logins will work"
    echo "  - With authentication-order 'tacplus', Junos auto-falls-back to"
    echo "    local password ONLY when the tacplus server is unreachable —"
    echo "    a tacplus reject does not fall through to local"
    echo "  - If a login fails silently, the template user is likely missing"
    echo "  - Each template-user is bound to a LOCAL class of the same name;"
    echo "    edit its 'permissions' to fit your policy (Junos refuses to set"
    echo "    permissions on the predefined read-only/operator/super-user names)"
    echo "  - Uncomment and edit the source-address line to pin the client"
    echo "    source IP for prefix-ACL matching on tacquito"
    echo "  - Junos replaces the plaintext 'secret' with '\$9\$...' on commit,"
    echo "    but it sits in the candidate config until then — commit promptly"
    echo "    and protect the commit archive (/config/rescue.conf, juniper.conf.*)."
    if [[ -n "$template_file" ]]; then
        echo "  - Using template: ${template_file}"
    fi
    echo ""
    echo -e "${BOLD}Verify after commit:${NC}"
    echo "$VERIFY_COMMANDS"
    echo ""
}

# --- WTI access level for a Cisco priv-lvl ---
# WTI console servers (DSM/CPM/REM/TSM/RSM, firmware v8.x) take the access
# level of a TACACS+ user from the standard `priv-lvl` attribute returned
# on exec authorization. The band → level mapping is WTI's own (from the
# WTI "TACACS with Cisco ISE" application note):
#   0-4 ViewOnly, 5-9 User, 10-14 SuperUser, 15 Administrator.
# The shipped groups therefore land as readonly(1)→ViewOnly,
# operator(7)→User, superuser(15)→Administrator; a custom group at
# priv-lvl 10-14 is the only way to hand out SuperUser.
wti_access_level_for_privlvl() {
    local privlvl="$1"
    if   (( privlvl >= 15 )); then echo "Administrator"
    elif (( privlvl >= 10 )); then echo "SuperUser"
    elif (( privlvl >= 5  )); then echo "User"
    else                            echo "ViewOnly"
    fi
}

# --- CONFIG WTI (step-by-step serial-CLI procedure) ---
# WTI units are configured through numbered text menus, not a pasteable
# config, so this emits an operator walkthrough with the scope's values
# filled in. No WTI-specific service block is needed in tacquito.yaml: the
# unit takes a login's level from the `priv-lvl` attribute returned on exec
# authorization (documented), so it reads the same `exec_<group>`
# (`name: shell`) services Cisco does. Its authorization service name is
# operator-settable (factory default `wti`); the walkthrough sets it to
# `shell` so the request matches tacquito's configured service directly.
# Should the unit send something else anyway, the default-service-permit
# patch in patches/ still answers with the same shell priv-lvl, so either
# way the operator gets the mapping printed below.
#
# Verified against a v8.10 unit: PAP authen → author service=shell
# protocol=tcp → priv-lvl=15 (Administrator) → acct start/stop. Three
# unit-side settings are load-bearing and easy to get wrong, so the
# walkthrough calls each out: Default User Access must be On (with it Off
# the unit's OpenSSH treats TACACS-only users as invalid and sends a junk
# password), IP Tables must accept ESTABLISHED,RELATED (or tacquito's
# SYN-ACK is dropped), and Session Management needs patch 0002 (the unit
# drops the session on a non-empty accounting server_msg).
cmd_config_wti() {
    # Parse --scope <name>
    local scope=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scope)
                scope="${2:-}"
                [[ -z "$scope" ]] && { error "Usage: tacctl config wti [--scope <name>]"; exit 1; }
                shift 2
                ;;
            *)
                error "Unknown argument: '$1'"
                error "Usage: tacctl config wti [--scope <name>]"
                exit 1
                ;;
        esac
    done
    if [[ -z "$scope" ]]; then
        scope=$(read_default_scope)
        if [[ -z "$scope" ]]; then
            error "No default scope set and no --scope provided."
            error "Run 'tacctl scope default <name>' or pass --scope <name>."
            exit 1
        fi
    elif ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist. Available: $(list_scopes | paste -sd' ')"
        exit 1
    fi
    local secret server_ip
    secret=$(read_scope_secret "$scope")
    server_ip=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [[ -z "$server_ip" ]]; then
        server_ip="<TACQUITO_SERVER_IP>"
    fi

    # Compute "other scopes" list for the header.
    local other_scopes
    # `grep -vxF` exits 1 when no lines survive (e.g. only the one named scope
    # exists). Under `set -o pipefail` that kills the subshell and, via
    # `set -e`, the whole script. Append `|| true` to the grep so the pipeline
    # stays zero-exit when the "other scopes" set is empty.
    other_scopes=$(list_scopes | { grep -vxF "$scope" || true; } | paste -sd,)

    # Collect all groups with their priv-lvl (same walk as config cisco —
    # WTI consumes the identical `shell` service).
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

    local GROUP_SUMMARY="" has_superuser_band="false"
    while IFS='|' read -r gname privlvl; do
        [[ -z "$gname" ]] && continue
        local wlevel
        wlevel=$(wti_access_level_for_privlvl "$privlvl")
        [[ "$wlevel" == "SuperUser" ]] && has_superuser_band="true"
        GROUP_SUMMARY+="  ${gname}: priv-lvl ${privlvl} → ${wlevel}"$'\n'
    done <<< "$group_info"

    # Fallback Local follows the scope's aaa-order. WTI always asks the
    # server first; the setting only picks when its own user directory is
    # consulted. "On (Transport Failure)" = only when the server cannot be
    # reached, which is what Cisco's `group TACACS local` (tacacs-first)
    # does. "On (All Failures)" = also after a server reject (bad password,
    # unknown user), the nearest WTI has to local-first. Plain "Off" is never
    # emitted: it would lock the operator out the moment tacquito is down.
    local FALLBACK_LOCAL
    if [[ "$(conf_get "aaa.order.${scope}" tacacs-first)" == "local-first" ]]; then
        FALLBACK_LOCAL="On (All Failures)"
    else
        FALLBACK_LOCAL="On (Transport Failure)"
    fi

    # Authorization service name the unit should send. tacquito's session
    # authorizer only returns AVPs for a service whose name matches the
    # inbound `service=` value; `shell` is what every exec_<group> block
    # is named.
    local SERVICE_NAME="shell"

    # WTI field constraints. The unit documents no Secret Word limit, but
    # every credential field it does document (username ≤ 32 chars,
    # password 5-16) rejects spaces and non-printable characters, and the
    # value is keyed in by hand at a menu prompt. Flag anything that is
    # likely to be mangled on entry so the operator can regenerate a
    # hex-only key before touching the device.
    local secret_warnings=""
    if [[ "$secret" =~ [[:space:]] ]] || [[ "$secret" =~ [^[:print:]] ]]; then
        secret_warnings+="  - ${RED}Secret contains whitespace or non-printable characters — WTI rejects${NC}"$'\n'
        secret_warnings+="    ${RED}those in credential fields. Regenerate a hex key:${NC}"$'\n'
        secret_warnings+="      tacctl scope secret ${scope} set \$(openssl rand -hex 16)"$'\n'
    elif [[ ! "$secret" =~ ^[A-Za-z0-9_-]+$ ]]; then
        secret_warnings+="  - Secret contains punctuation (e.g. + / =); the WTI menu prompt is untested"$'\n'
        secret_warnings+="    with those. If tacquito logs 'bad secret detected' after saving, switch"$'\n'
        secret_warnings+="    to a hex-only key: tacctl scope secret ${scope} set \$(openssl rand -hex 16)"$'\n'
    fi
    if [[ "${#secret}" -gt 32 ]]; then
        secret_warnings+="  - Secret is ${#secret} chars. WTI documents no Secret Word maximum, but its other"$'\n'
        secret_warnings+="    credential fields cap at 16-32 chars; a silent truncation shows up on the"$'\n'
        secret_warnings+="    tacquito side as 'bad secret detected'. A 32-char hex key is the safe choice."$'\n'
    fi
    # WTI usernames are capped at 32 characters (Add User menu); a longer
    # tacquito user can authenticate but cannot be represented on the unit.
    local user_warnings=""
    while IFS= read -r uname; do
        [[ -z "$uname" ]] && continue
        if [[ "${#uname}" -gt 32 ]]; then
            user_warnings+="  - User '${uname}' is ${#uname} chars; WTI usernames max out at 32"$'\n'
        fi
    done < <(list_users_in_scope "$scope")

    echo ""
    echo -e "${BOLD}WTI Console Server Configuration${NC}  (scope: ${scope}, firmware v8.x text interface)"
    if [[ -n "$other_scopes" ]]; then
        echo -e "${YELLOW}(other scopes: ${other_scopes} — use --scope <name> to emit those)${NC}"
    fi
    echo -e "${YELLOW}Follow these steps on the WTI serial (SetUp) console:${NC}"
    echo "--------------------------------------------"
    echo ""

    local template_file
    template_file=$(resolve_template "wti")
    if [[ -n "$template_file" ]]; then
        export SERVER_IP="$server_ip" SECRET="$secret" SCOPE="$scope" FALLBACK_LOCAL SERVICE_NAME GROUP_SUMMARY
        # shellcheck disable=SC2016
        envsubst '${SERVER_IP} ${SECRET} ${SCOPE} ${FALLBACK_LOCAL} ${SERVICE_NAME} ${GROUP_SUMMARY}' < "$template_file"
    else
        cat <<EOF
Step 1: Log in on the serial SetUp port as an Administrator-level account
        (factory default: super / super). Keep this session open until Step 7 succeeds.

Step 2: /N [Enter] -> Network Parameters; 28 [Enter] -> TACACS Parameters.

Step 3: Set each item:
         1. Enable                     : On
         2. Primary Host/Address       : ${server_ip}
         3. Secondary Host/Address     : (leave Undefined)
         4. Secret Word                : ${secret}
         5. Fallback Timer             : 15
         6. Fallback Local             : ${FALLBACK_LOCAL}
         7. Authentication Port        : 49
         8. Default User Access        : Enable On, Access Level ViewOnly (REQUIRED)
         9. Account Management Module  : Enabled   (authorization -- carries priv-lvl)
        10. Session Management Module  : Enabled   (accounting -- needs tacquito patch 0002)
        11. Service Name               : ${SERVICE_NAME}
        12. Debug                      : Off

Step 4: 13. Ping TACACS Servers -- confirms ${server_ip} answers ICMP (not TCP/49).

Step 5: If the unit's IP Tables (/N) end in DROP, accept these before the DROP:
          iptables -A INPUT -i lo -j ACCEPT
          iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

Step 6: Press [Esc] repeatedly until "Saving Configuration" is printed.

Step 7: From a SECOND session, log in as a tacquito user in scope '${scope}'
        with 'ssh -o PreferredAuthentications=password <user>@<wti-ip>', type /H
        to see the commands allowed at the assigned access level, and /X to exit.

Step 8: Only if Step 7 fails: set 12. Debug: On, retry the login, and read the
        exchange the unit prints on this serial session next to tacquito's debug
        log (see below). Set Debug back to Off afterwards.
EOF
    fi

    echo ""
    echo "--------------------------------------------"
    echo -e "${YELLOW}Group → WTI Access Level Mapping (from priv-lvl):${NC}"
    echo -n "$GROUP_SUMMARY"
    echo "  (WTI bands: 0-4 ViewOnly, 5-9 User, 10-14 SuperUser, 15 Administrator)"
    if [[ "$has_superuser_band" == "false" ]]; then
        echo "  No group lands in the SuperUser band; to grant it, add a group at"
        echo "  priv-lvl 10-14, e.g. 'tacctl group add wtisuper 12 OP-CLASS'."
    fi
    echo ""
    if [[ -n "$secret_warnings" || -n "$user_warnings" ]]; then
        echo -e "${YELLOW}Warnings:${NC}"
        echo -en "$secret_warnings"
        echo -n "$user_warnings"
        echo ""
    fi
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - WTI authenticates with PAP (password travels inside the TACACS+ body,"
    echo "    obfuscated with the shared secret) — tacquito's bcrypt authenticator"
    echo "    handles PAP, no server-side change needed"
    echo "  - The Account/Session Management Module items are PAM terms (the unit's"
    echo "    client is pam_tacplus-style): 'Account' is the TACACS+ authorization"
    echo "    request that carries priv-lvl back — without it every login gets the"
    echo "    'Default User Access' level; 'Session' is accounting start/stop"
    echo "  - Service Name '${SERVICE_NAME}' makes the unit's authorization request match"
    echo "    tacquito's configured service directly. Leaving the factory 'wti' also"
    echo "    works, but only via the default-service-permit patch (patches/0001),"
    echo "    which answers an unmatched service with the group's shell priv-lvl"
    echo "  - Default User Access must be On (Access Level ViewOnly is only the floor;"
    echo "    the priv-lvl tacquito returns sets the effective level). SSH logins go"
    echo "    through the unit's OpenSSH, which must resolve the account locally: with"
    echo "    it Off, a TACACS-only user is invalid to sshd, which sends a junk password"
    echo "    (OpenSSH's 'INCORRECT' filler) — tacquito then logs 'failed to validate"
    echo "    the user' on every attempt whatever was typed, and a plain ssh is closed"
    echo "    unprompted"
    echo "  - Session Management (accounting) needs tacquito built with tacctl's patch"
    echo "    0002 (patches/): upstream answers accounting with a non-empty server_msg,"
    echo "    and the unit drops the SSH session right after login when it gets one."
    echo "    'tacctl upgrade' applies the patch overlay and rebuilds"
    echo "  - Port and service access for User/ViewOnly-level logins (priv-lvl 0-9) is"
    echo "    defined only under 8. Default TACACS User Access → Configure Port Access /"
    echo "    Service Access (factory: Administrator+SuperUser all ports, User+ViewOnly"
    echo "    none). If such a login lands at the right level but reaches no ports,"
    echo "    grant them there. A same-named LOCAL account on the unit overrides the"
    echo "    server-assigned level — keep the two directories disjoint"
    echo "  - Fallback Local '${FALLBACK_LOCAL}' mirrors this scope's aaa-order;"
    echo "    keep a local Administrator account on the unit as break-glass. It acts"
    echo "    only after the TACACS+ transport fails (Fallback Timer expiry), not on an"
    echo "    immediate 'Connection closed' or 'Permission denied'"
    echo "  - A firewall that drops tacquito's replies (the unit's own IP Tables"
    echo "    without ESTABLISHED,RELATED — Step 5) shows up on the server only as"
    echo "    SYNs in tcpdump and half-open (SYN-RECV) sockets; tacquito logs nothing"
    echo "  - The unit's source IP must fall inside a prefix of scope '${scope}'"
    echo "    ('tacctl scope lookup <wti-ip>' to check)"
    if [[ -n "$template_file" ]]; then
        echo "  - Using template: ${template_file}"
    fi
    echo ""
    echo -e "${BOLD}Verify on the tacquito side:${NC}"
    echo "  tacctl config loglevel debug          # then log in on the WTI (Step 7) and watch:"
    echo "  tacctl log tail 50                    # 1. 'accepting user [x] using a bcrypt password'  (PAP authen)"
    echo "                                        # 2. 'session authz user [x]: client args [service=${SERVICE_NAME} ...]'"
    echo "                                        # 3. 'authorized user [x] as session based; args [priv-lvl=N]'"
    echo "  tacctl log accounting                 # start record at login, stop record after /X"
    echo "  tacctl log failures                   # 'bad secret detected' = Secret Word mismatch;"
    echo "                                        # 'failed to validate the user [x] using a bcrypt"
    echo "                                        # password' on EVERY attempt = Default User Access Off;"
    echo "                                        # 'unknown authenticate start packet type' = unit did not"
    echo "                                        # send PAP with TACACS+ minor version 1 (open an issue)"
    echo "  tacctl config loglevel info           # restore when done"
    echo "  On the WTI (Step 8): with 12. Debug: On the unit echoes each TACACS+ exchange on"
    echo "  the serial session; line up the authen/author/acct replies with the entries above"
    echo ""
}

# --- CONFIG MGMT-ACL (permit list for Cisco VTY-ACL + Juniper lo0 filter) ---
# Stored as mgmt_acl.permits (list) + mgmt_acl.names.{cisco,juniper} in
# tacctl.yaml. Tacctl-internal — never read by tacquito — so no service
# restart is needed when the list changes.
cmd_config_mgmt_acl() {
    local subcmd="${1:-}"
    # $2 is either a CIDR (add/remove) or an ACL name (cisco-name/juniper-name).
    # Keep the legacy name `cidr` since most branches use it that way.
    local cidr="${2:-}"

    case "$subcmd" in
        ""|-h|--help|help)
            local n
            n=$(read_mgmt_acl_cidrs | awk 'NF' | wc -l)
            local cisco_name juniper_name
            cisco_name=$(read_mgmt_acl_name cisco)
            juniper_name=$(read_mgmt_acl_name juniper)
            echo ""
            echo -e "${BOLD}tacctl config mgmt-acl${NC} — shared Cisco VTY-ACL + Juniper lo0-filter permits"
            echo ""
            echo "Usage:"
            echo "  tacctl config mgmt-acl list                          Show current permits"
            echo "  tacctl config mgmt-acl add    <cidr>[,<cidr>...]     Add one or more CIDRs"
            echo "  tacctl config mgmt-acl remove <cidr>[,<cidr>...]     Remove one or more CIDRs"
            echo "  tacctl config mgmt-acl clear                         Wipe all permits (confirms)"
            echo "  tacctl config mgmt-acl cisco-name [name]             Show or set the Cisco ACL name (default ${CISCO_ACL_NAME_DEFAULT})"
            echo "  tacctl config mgmt-acl juniper-name [name]           Show or set the Juniper filter name (default ${JUNIPER_ACL_NAME_DEFAULT})"
            echo ""
            echo "Storage: tacctl.yaml (mgmt_acl.permits + mgmt_acl.names)."
            echo "         cisco=${cisco_name}  juniper=${juniper_name}"
            echo "Current entries: ${n}"
            echo ""
            return
            ;;
        list)
            echo ""
            echo -e "${BOLD}Management ACL (shared Cisco VTY-ACL + Juniper lo0 filter source)${NC}"
            echo "--------------------------------------------"
            local entries
            entries=$(read_mgmt_acl_cidrs)
            if [[ -z "$entries" ]]; then
                echo "  (empty)"
                echo ""
                echo "  Add with: tacctl config mgmt-acl add <cidr>"
                echo "  Cisco/Juniper output uses a scaffold/comment until populated."
            else
                echo "$entries" | while IFS= read -r entry; do
                    echo "  - ${entry}"
                done
            fi
            echo ""
            ;;
        add)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config mgmt-acl add <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested added="" skipped=""
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(read_mgmt_acl_cidrs)
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    skipped+="${skipped:+ }${c}"
                else
                    added+="${added:+$'\n'}${c}"
                    current=$(printf '%s\n%s\n' "$current" "$c")
                fi
            done <<< "$requested"
            if [[ -z "$added" ]]; then
                info "No new CIDRs to add (already present: ${skipped})."
                echo ""
                return
            fi
            # Rewrite the whole file — canonical + sorted, with header.
            write_mgmt_acl_cidrs "$current"
            local n
            n=$(printf '%s\n' "$added" | wc -l)
            info "Added ${n} to mgmt-acl: $(printf '%s\n' "$added" | paste -sd' ')"
            [[ -n "$skipped" ]] && info "(Already present, unchanged: ${skipped})"
            info "Re-run 'tacctl config cisco' / 'tacctl config juniper' to see the new output."
            echo ""
            ;;
        remove)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config mgmt-acl remove <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested removed="" missing=""
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(read_mgmt_acl_cidrs)
            if [[ -z "$current" ]]; then
                warn "Nothing to remove — mgmt-acl permit list is empty."
                exit 0
            fi
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    removed+="${removed:+$'\n'}${c}"
                    current=$(printf '%s\n' "$current" | grep -vxF "$c" || true)
                else
                    missing+="${missing:+ }${c}"
                fi
            done <<< "$requested"
            if [[ -z "$removed" ]]; then
                warn "Nothing to remove (not present: ${missing})."
                exit 0
            fi
            write_mgmt_acl_cidrs "$current"
            local n
            n=$(printf '%s\n' "$removed" | wc -l)
            info "Removed ${n} from mgmt-acl: $(printf '%s\n' "$removed" | paste -sd' ')"
            [[ -n "$missing" ]] && info "(Not present, skipped: ${missing})"
            echo ""
            ;;
        clear)
            local current
            current=$(read_mgmt_acl_cidrs)
            if [[ -z "$current" ]]; then
                info "Already empty."
                echo ""
                return
            fi
            read -rp "  Clear all mgmt-acl entries? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            conf_unset mgmt_acl.permits
            info "mgmt-acl cleared."
            echo ""
            ;;
        cisco-name|juniper-name)
            local which="${subcmd%-name}"
            local default_val current_val
            if [[ "$which" == "cisco" ]]; then
                default_val="$CISCO_ACL_NAME_DEFAULT"
            else
                default_val="$JUNIPER_ACL_NAME_DEFAULT"
            fi
            current_val=$(read_mgmt_acl_name "$which")
            if [[ -z "$cidr" ]]; then
                echo ""
                echo "  ${which}-name: ${current_val}"
                if [[ "$current_val" == "$default_val" ]]; then
                    echo "  (default — override with 'tacctl config mgmt-acl ${subcmd} <name>')"
                else
                    echo "  (override in tacctl.yaml: mgmt_acl.names.${which})"
                fi
                echo ""
                return
            fi
            # Second positional arg = new name
            local new_name="$cidr"
            validate_acl_name "$new_name"
            if [[ "$new_name" == "$current_val" ]]; then
                info "${which}-name already '${new_name}'; no change."
                echo ""
                return
            fi
            write_mgmt_acl_name "$which" "$new_name"
            info "Re-run 'tacctl config ${which}' to see the new name in the output."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${subcmd}'"
            error "Run 'tacctl config mgmt-acl' with no arguments for help."
            exit 1
            ;;
    esac
}

