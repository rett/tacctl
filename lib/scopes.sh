# shellcheck shell=bash
# tacctl lib/scopes.sh -- default-scope helpers, allow/deny prefix filters, scope commands
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.
#
# A scope is a named (prefixes, shared secret) bundle in the store, with an
# optional 'protocols' filter naming the backends that serve it and, for
# RADIUS, the vendor attributes it opts into ('vendor-attrs', 'devices').
# Users carry
# a list of scope names and can authenticate only from devices matching a
# scope they are a member of. Reads go through the model (lib/model.sh);
# writes go through store_apply (lib/backend.sh), which re-renders
# tacquito.yaml -- one secrets[] entry per (scope, prefix), most specific
# first -- so nothing here touches that file.

# Protocols a scope's 'protocols' filter may name. Must equal KNOWN_PROTOCOLS
# in lib/store.sh (a unit test pins the two together).
SCOPE_PROTOCOLS="tacacs radius"

# Vendors a scope can enable a RADIUS privilege attribute for, or tag an
# address with. Must equal KNOWN_VENDORS in lib/store.sh (a unit test pins
# the two together).
SCOPE_VENDORS="cisco juniper wti"

# Every tacctl.yaml key that is stored under a scope's name: <key>.<scope>.
# 'scope rename' moves them and 'scope remove' drops them
# (_scope_conf_keys_move); a per-scope key added to the schema in lib/conf.sh
# belongs here too. scope.default names a scope by value and is handled by
# the commands themselves.
SCOPE_CONF_KEYS=(aaa.order exec_timeout tacacs_group radius_group scope_auth_method
                 scope_mgmt_acl.names.cisco scope_mgmt_acl.names.juniper scope_mgmt_acl.permits)

# --- Read scope.default from the merged tacctl config ---
# Returns the configured default scope name (tacctl.yaml's scope.default,
# layered over the shipped 'lab' default). Falls back to the name of the
# sole scope if the merged value doesn't name an existing scope and there
# is exactly one. Empty output if no scopes exist yet.
read_default_scope() {
    local v names
    v=$(conf_get scope.default)
    names=$(model_scopes) || return 0
    if [[ -n "$v" ]] && grep -qxF -- "$v" <<< "$names"; then
        echo "$v"
        return
    fi
    # Fallback: if there's exactly one scope, it's the implicit default.
    if [[ -n "$names" && $(printf '%s\n' "$names" | wc -l) -eq 1 ]]; then
        echo "$names"
    fi
}

# --- Write scope.default to tacctl.yaml ---
# Sets the scope.default override; reverts to the shipped default when the
# value equals 'lab' (conf_set's revert-to-default semantics). Caller is
# responsible for verifying the name exists as a scope first.
write_default_scope() {
    conf_set scope.default "$1"
}

# Print "Scope '<name>' does not exist. Available: ..." and return 1 when
# the scope is missing.
_scope_require() {
    model_scope_exists "$1" && return 0
    error "Scope '$1' does not exist. Available: $(model_scopes_by_routing | paste -sd' ' || true)"
    return 1
}

# scope_auth_method <scope>: the scope's default authentication method as set
# with 'tacctl scope auth-method' (tacacs|radius), empty when it has none. A
# value the schema does not know (a hand edit of tacctl.yaml) reads as none.
scope_auth_method() {
    local v
    v=$(conf_get "scope_auth_method.${1}")
    case "$v" in
        tacacs|radius) echo "$v" ;;
    esac
    return 0
}

# scope_protocol_choice <scope>: what the scope itself says about the protocol
# to use when a command names none. Sets SCOPE_CHOICE (tacacs|radius, or empty
# when the scope does not decide) and SCOPE_CHOICE_SOURCE:
#   auth-method   'tacctl scope auth-method' is set
#   protocols     it is not, and the scope's protocols filter names exactly
#                 one protocol: nothing else serves the scope
# The callers put this between what the command line (or a registered host)
# says and the global default (config_protocol_resolve, cmd_host_enroll,
# cmd_config_linux_script).
scope_protocol_choice() {
    local protocols
    SCOPE_CHOICE=$(scope_auth_method "$1") SCOPE_CHOICE_SOURCE="auth-method"
    [[ -n "$SCOPE_CHOICE" ]] && return 0
    SCOPE_CHOICE_SOURCE=""
    protocols=$(model_scope "$1" protocols 2> /dev/null | awk 'NF') || protocols=""
    if [[ -n "$protocols" && "$protocols" != *$'\n'* ]]; then
        SCOPE_CHOICE="$protocols" SCOPE_CHOICE_SOURCE="protocols"
    fi
    return 0
}

# What is in effect for a scope without an auth-method, for 'scope show' and
# 'scope auth-method': the scope's only protocol, else the global defaults
# (device configs are TACACS+; hosts take 'host default-method', named here
# by its protocol).
_scope_protocol_in_effect() {
    scope_protocol_choice "$1"
    if [[ "$SCOPE_CHOICE_SOURCE" == "protocols" ]]; then
        echo "${SCOPE_CHOICE}: the scope's only protocol"
    else
        echo "devices: tacacs; hosts: $(linux_method_backend "$(linux_default_method)")"
    fi
}

# _scope_conf_keys_move <old> [<new>]: every per-scope key of tacctl.yaml
# (SCOPE_CONF_KEYS) stored under <old> goes to <new>; without <new> it is
# dropped (the scope is going away, and a scope created later under the same
# name must not inherit it). tacctl.yaml is left alone when it holds nothing
# under that name: a write re-dumps the whole file. A value the schema does
# not take (a hand edit) is not carried over.
_scope_conf_keys_move() {
    local old="$1" new="${2:-}" key value
    grep -qsF -- "$old" "$TACCTL_OVERRIDES_FILE" || return 0
    for key in "${SCOPE_CONF_KEYS[@]}"; do
        conf_has_override "${key}.${old}" || continue
        value=$(conf_get_json "${key}.${old}")
        conf_unset "${key}.${old}" || return 1
        if [[ -n "$new" ]] && ! conf_set_json "${key}.${new}" "$value" 2> /dev/null; then
            warn "${key}.${old} holds a value tacctl.yaml does not take; it was not carried over to '${new}'." >&2
        fi
    done
    return 0
}

# Writer for store_apply: delete the scope (off every user that still has it)
# and every tacctl.yaml key stored under its name. Its vendor attributes and
# tagged addresses are part of its store entry and go with it.
_scope_remove_write() {
    store_scope_del "$1" --strip-users || return 1
    _scope_conf_keys_move "$1"
}

# --- CONFIG ALLOW/DENY PREFIX FILTERS ---
cmd_config_prefix_filter() {
    local key="$1"
    local subcmd="${2:-}"
    local cidr="${3:-}"
    local label
    [[ "$key" == "prefix_allow" ]] && label="allow" || label="deny"

    case "$subcmd" in
        add|remove|clear) store_require || exit 1 ;;
    esac
    # Canonical CIDRs, one per line, most specific first.
    local current
    current=$(model_filters "$label") || exit 1

    case "$subcmd" in
        ""|-h|--help|help)
            local entries
            entries=$(printf '%s\n' "$current" | awk 'NF' | wc -l)
            echo ""
            echo -e "${BOLD}tacctl config ${label}${NC} — connection IP ACL (${label} list)"
            echo ""
            echo "Usage:"
            echo "  tacctl config ${label} list                          Show current ${label} list"
            echo "  tacctl config ${label} add    <cidr>[,<cidr>...]     Add one or more CIDRs"
            echo "  tacctl config ${label} remove <cidr>[,<cidr>...]     Remove one or more CIDRs"
            echo "  tacctl config ${label} clear                         Wipe all (confirms)"
            echo ""
            echo "Current entries: ${entries}"
            echo "Note: 'deny' takes precedence over 'allow'. Both empty = all connections accepted."
            echo ""
            return
            ;;
        list)
            echo ""
            echo -e "${BOLD}Connection ${label} list${NC}"
            echo "--------------------------------------------"
            if [[ -z "$current" ]]; then
                if [[ "$label" == "allow" ]]; then
                    echo "  (empty — all connections allowed)"
                else
                    echo "  (empty — no connections denied)"
                fi
            else
                local entry
                while IFS= read -r entry; do
                    echo "  - ${entry}"
                done <<< "$current"
            fi
            echo ""
            echo -e "  ${CYAN}Note: deny takes precedence over allow.${NC}"
            echo ""
            ;;
        add)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config ${label} add <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested added="" skipped="" c
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF -- "$c"; then
                    skipped+="${skipped:+ }${c}"
                else
                    added+="${added:+$'\n'}${c}"
                    current=$(printf '%s\n%s\n' "$current" "$c")
                fi
            done <<< "$requested"
            if [[ -z "$added" ]]; then
                info "No new CIDRs to add to ${label} list (already present: ${skipped})."
                echo ""
                return
            fi
            store_apply store_filters_set "$label" "$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)" || exit $?
            local n
            n=$(printf '%s\n' "$added" | wc -l)
            info "Added ${n} to ${label} list: $(printf '%s\n' "$added" | paste -sd' ')"
            [[ -n "$skipped" ]] && info "(Already present, unchanged: ${skipped})"
            echo ""
            ;;
        remove)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config ${label} remove <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested removed="" missing="" c
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF -- "$c"; then
                    removed+="${removed:+$'\n'}${c}"
                    current=$(printf '%s\n' "$current" | grep -vxF -- "$c" || true)
                else
                    missing+="${missing:+ }${c}"
                fi
            done <<< "$requested"
            if [[ -z "$removed" ]]; then
                warn "Nothing to remove from ${label} list (not present: ${missing})."
                exit 0
            fi
            store_apply store_filters_set "$label" "$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)" || exit $?
            local n
            n=$(printf '%s\n' "$removed" | wc -l)
            info "Removed ${n} from ${label} list: $(printf '%s\n' "$removed" | paste -sd' ')"
            [[ -n "$missing" ]] && info "(Not present, skipped: ${missing})"
            echo ""
            ;;
        clear)
            local n
            if [[ -z "$current" ]]; then
                info "${label} list is already empty."
                return
            fi
            n=$(printf '%s\n' "$current" | wc -l)
            # Clearing either list removes a restriction — be explicit
            # about what the resulting posture is.
            if [[ "$label" == "allow" ]]; then
                warn "Clearing the allow list fails open: all source IPs become eligible"
                warn "to connect (subject to 'deny' and the secret-provider prefixes)."
            else
                warn "Clearing the deny list removes all per-IP deny overrides;"
                warn "any source matching 'allow' (or all, if allow is empty) can connect."
            fi
            read -rp "  Clear all ${n} ${label}-list entr$( [[ $n -eq 1 ]] && echo "y" || echo "ies" )? [y/N]: " confirm || true
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            store_apply store_filters_set "$label" "" || exit $?
            info "Cleared ${label} list (${n} entr$( [[ $n -eq 1 ]] && echo "y" || echo "ies" ) removed)."
            echo ""
            ;;
        *)
            echo ""
            echo "Usage: tacctl config ${label} <list|add|remove|clear> [cidr[,cidr...]]"
            echo ""
            exit 1
            ;;
    esac
}

# =====================================================================
#  SCOPE COMMANDS (tacctl scope ...)
# =====================================================================

cmd_scope() {
    local subcmd="${1:-}"
    shift 2>/dev/null || true
    case "$subcmd" in
        ""|-h|--help|help) cmd_scope_usage ;;
        list)              cmd_scope_list ;;
        routing)           cmd_scope_routing ;;
        show)              cmd_scope_show "$@" ;;
        add)               cmd_scope_add "$@" ;;
        remove)            cmd_scope_remove "$@" ;;
        rename)            cmd_scope_rename "$@" ;;
        default)           cmd_scope_default "$@" ;;
        lookup)            cmd_scope_lookup "$@" ;;
        prefixes)          cmd_scope_prefixes_dispatch "$@" ;;
        secret)            cmd_scope_secret_dispatch "$@" ;;
        protocols)         cmd_scope_protocols "$@" ;;
        vendor-attrs)      cmd_scope_vendor_attrs "$@" ;;
        devices)           cmd_scope_devices "$@" ;;
        aaa-order)         cmd_scope_aaa_order "$@" ;;
        exec-timeout)      cmd_scope_exec_timeout "$@" ;;
        tacacs-group)      cmd_scope_tacacs_group "$@" ;;
        radius-group)      cmd_scope_radius_group "$@" ;;
        auth-method)       cmd_scope_auth_method "$@" ;;
        mgmt-acl)          cmd_scope_mgmt_acl "$@" ;;
        *)
            error "Unknown subcommand: '${subcmd}'"
            cmd_scope_usage
            exit 1
            ;;
    esac
}

cmd_scope_usage() {
    local count=0 default_val
    count=$(model_scopes | wc -l) || true
    default_val=$(read_default_scope)
    echo ""
    echo -e "${BOLD}tacctl scope${NC} — named (CIDR-prefixes, shared-secret) bundles"
    echo ""
    echo "Usage:"
    echo "  tacctl scope list                                        One row per scope (aggregated prefix list)"
    echo "  tacctl scope routing                                     One row per (scope, prefix) — first-match order"
    echo "  tacctl scope show <name>                                 Detailed view"
    echo "  tacctl scope add <name> --prefixes <cidrs>               Create a new scope"
    echo "                       [--secret <value>|--secret generate]"
    echo "                       [--protocols <protocol>[,<protocol>...]]"
    echo "                       [--vendor-attrs <vendor>[,<vendor>...]]"
    echo "                       [--default]"
    echo "  tacctl scope remove <name> [--force]                     Delete a scope (confirms)"
    echo "  tacctl scope rename <old> <new>                          Rename (updates user references)"
    echo "  tacctl scope default [<name>]                            Show or set the default scope"
    echo "  tacctl scope lookup <ip|cidr>                            Show which scope owns an address"
    echo ""
    echo "  tacctl scope prefixes <scope> list|add|remove|clear      Manage a scope's CIDR list"
    echo "  tacctl scope secret   <scope> show|set|generate          Manage a scope's shared secret"
    echo "  tacctl scope protocols <scope> list|set <csv>|clear      Limit a scope to some protocols (${SCOPE_PROTOCOLS// /, }); default: all"
    echo "  tacctl scope vendor-attrs <scope> [enable|disable <csv>] RADIUS: vendor privilege attributes sent to the scope's devices (${SCOPE_VENDORS// /, }); default: not sent"
    echo "  tacctl scope devices <scope> [set <ip|cidr> <vendor>|unset <ip|cidr>]  RADIUS: tag an address of the scope with its vendor (it gets that vendor's attribute only)"
    echo "  tacctl scope aaa-order <scope> [tacacs-first|local-first] AAA method-list order in this scope's rendered device configs (default tacacs-first)"
    echo "  tacctl scope exec-timeout <scope> [minutes]              Per-scope idle-session timeout in rendered device configs (0..60 min; default 60; 0 = never expire)"
    echo "  tacctl scope tacacs-group <scope> [name]                 Per-scope Cisco aaa-group-server label (default TACACS-GROUP)"
    echo "  tacctl scope radius-group <scope> [name]                 Per-scope Cisco aaa-group-server label for RADIUS (default RADIUS-GROUP)"
    echo "  tacctl scope auth-method <scope> [tacacs|radius|clear]   Protocol this scope's device configs and host enrollments use when the command names none"
    echo "  tacctl scope mgmt-acl <scope> list|add|remove|clear      Per-scope permit list (fallback: global mgmt_acl.permits)"
    echo "  tacctl scope mgmt-acl <scope> cisco-name|juniper-name [name]  Per-scope ACL / filter name (defaults VTY-ACL / MGMT-ACL)"
    echo ""
    echo "Current scopes: ${count}"
    echo "Default scope:  ${default_val:-<unset>}"
    echo ""
}

cmd_scope_list() {
    echo ""
    echo -e "${BOLD}Scopes${NC} ${CYAN}(one block per scope; see 'tacctl scope routing' for first-match prefix order)${NC}"
    echo "--------------------------------------------------------------"
    local default_val
    default_val=$(read_default_scope)
    # One block per scope. First prefix sits on the scope's summary
    # row (name / users / default marker); subsequent prefixes indent
    # under the PREFIXES column so the list reads top-to-bottom as
    # "this scope owns these CIDRs", narrowest first. Detailed
    # first-match resolution order is `tacctl scope routing`; per-scope
    # secret + knobs land in `tacctl scope show <name>`.
    local rows
    rows=$(_model_view scope-rows "$default_val") || exit 1

    if [[ -z "$rows" ]]; then
        echo "  (no scopes configured)"
        echo ""
        return
    fi

    # The vendor-attributes column (RADIUS) is there only when a scope has
    # something to show in it.
    local with_vendor=0
    [[ -n "$(cut -s -d'|' -f5 <<< "$rows" | awk 'NF')" ]] && with_vendor=1
    if (( with_vendor )); then
        printf "  ${BOLD}%-18s %-20s %5s  %-7s  %s${NC}\n" "NAME" "PREFIXES" "USERS" "DEFAULT" "VENDOR ATTRIBUTES (RADIUS)"
        echo "  ------------------------------------------------------------------------------------"
    else
        printf "  ${BOLD}%-18s %-20s %5s  %s${NC}\n" "NAME" "PREFIXES" "USERS" "DEFAULT"
        echo "  --------------------------------------------------------------"
    fi
    while IFS='|' read -r name cidr users is_default vendor; do
        if [[ -z "$name" ]]; then
            # Continuation row — blank NAME column, prefix only.
            [[ -z "$cidr" ]] && continue
            printf "  %-18s %-20s\n" "" "$cidr"
            continue
        fi
        local dfl=""
        [[ "$is_default" == "yes" ]] && dfl="${CYAN}yes${NC}"
        if (( with_vendor )); then
            printf "  ${BOLD}%-18s${NC} %-20s %5s  %-7s  %s\n" "$name" "$cidr" "$users" "${is_default}" "${vendor:-not sent}"
        else
            printf "  ${BOLD}%-18s${NC} %-20s %5s  %b\n" "$name" "$cidr" "$users" "$dfl"
        fi
    done <<< "$rows"
    echo ""
}

# --- tacctl scope routing — the per-(scope, prefix) view ---
# Each row is one (scope, prefix) pair as tacquito sees it, most specific
# first -- the order a connecting client is matched in. Multi-prefix
# scopes repeat their name. `tacctl scope list` is the dedup'd per-scope
# view for day-to-day work.
cmd_scope_routing() {
    echo ""
    echo -e "${BOLD}Scope routing${NC} ${CYAN}(first-match order — narrower prefixes win)${NC}"
    echo "--------------------------------------------------------------"
    local default_val
    default_val=$(read_default_scope)
    local rows
    rows=$(_model_view scope-routing "$default_val") || exit 1

    if [[ -z "$rows" ]]; then
        echo "  (no scopes configured)"
        echo ""
        return
    fi

    printf "  ${BOLD}%3s  %-18s %-20s %5s  %s${NC}\n" "#" "NAME" "PREFIX" "USERS" "DEFAULT"
    echo "  --------------------------------------------------------------"
    local i=0
    while IFS='|' read -r name cidr users is_default; do
        [[ -z "$name" ]] && continue
        i=$((i + 1))
        local dfl=""
        [[ "$is_default" == "yes" ]] && dfl="${CYAN}yes${NC}"
        printf "  %3d  ${BOLD}%-18s${NC} %-20s %5s  %b\n" "$i" "$name" "$cidr" "$users" "$dfl"
    done <<< "$rows"
    echo ""
}

cmd_scope_show() {
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        error "Usage: tacctl scope show <name>"
        exit 1
    fi
    local secret_val secret_len secret_line
    if ! secret_val=$(model_scope "$name" secret); then
        error "Scope '${name}' does not exist."
        exit 1
    fi
    # The value itself is never printed here: 'scope secret <name> show' is
    # the one command that reveals it (and config cisco|juniper|wti, whose
    # job is to hand it to a device).
    secret_len=${#secret_val}
    local secret_reveal="show with 'tacctl scope secret ${name} show'"
    if [[ -z "$secret_val" ]]; then
        secret_line="${RED}(unset)${NC}"
    elif [[ "$secret_val" == *REPLACE* ]]; then
        secret_line="${RED}(PLACEHOLDER, ${secret_len} chars — run 'tacctl scope secret ${name} generate')${NC}"
    elif [[ "$secret_len" -lt "$SECRET_MIN_LENGTH" ]]; then
        secret_line="${RED}(set, ${secret_len} chars, below min ${SECRET_MIN_LENGTH})${NC} — ${secret_reveal}"
    else
        secret_line="${GREEN}(set, ${secret_len} chars)${NC} — ${secret_reveal}"
    fi
    local default_val
    default_val=$(read_default_scope)
    local is_default="no"
    [[ "$name" == "$default_val" ]] && is_default="yes"
    local protocols vendor_attrs
    protocols=$(model_scope "$name" protocols | paste -sd, || true)
    vendor_attrs=$(model_scope "$name" vendor_attrs | paste -sd, || true)
    # Per-scope device-render knobs. Absence of an override falls back
    # through the per-scope -> global -> shipped-default chain,
    # matching what `tacctl config cisco|juniper --scope <name>` emits.
    local aaa_order_val exec_timeout_val exec_timeout_display tacacs_group_val radius_group_val cisco_acl_val juniper_acl_val auth_method_val
    auth_method_val=$(scope_auth_method "$name")
    aaa_order_val=$(conf_get "aaa.order.${name}" tacacs-first)
    exec_timeout_val=$(conf_get "exec_timeout.${name}" 60)
    tacacs_group_val=$(conf_get "tacacs_group.${name}" TACACS-GROUP)
    radius_group_val=$(conf_get "radius_group.${name}" RADIUS-GROUP)
    cisco_acl_val=$(read_mgmt_acl_name cisco "$name")
    juniper_acl_val=$(read_mgmt_acl_name juniper "$name")
    if [[ "$exec_timeout_val" == "0" ]]; then
        exec_timeout_display="0 min (never expire)"
    else
        exec_timeout_display="${exec_timeout_val} min"
    fi

    echo ""
    echo -e "${BOLD}Scope:${NC} ${name}"
    echo "--------------------------------------------"
    echo -e "  ${BOLD}Default:${NC}       ${is_default}"
    echo -e "  ${BOLD}Secret:${NC}        ${secret_line}"
    echo -e "  ${BOLD}Protocols:${NC}     ${protocols:-all (no filter)}"
    echo -e "  ${BOLD}Auth method:${NC}   ${auth_method_val:-not set ($(_scope_protocol_in_effect "$name"))}"
    echo -e "  ${BOLD}Vendor attributes:${NC} ${vendor_attrs:-not sent}   (RADIUS; tacctl scope vendor-attrs ${name})"
    echo -e "  ${BOLD}AAA order:${NC}     ${aaa_order_val}"
    echo -e "  ${BOLD}Exec timeout:${NC}  ${exec_timeout_display}"
    echo -e "  ${BOLD}TACACS group:${NC}  ${tacacs_group_val}"
    echo -e "  ${BOLD}RADIUS group:${NC}  ${radius_group_val}"
    echo -e "  ${BOLD}Cisco ACL:${NC}     ${cisco_acl_val}"
    echo -e "  ${BOLD}Juniper ACL:${NC}   ${juniper_acl_val}"
    echo -e "  ${BOLD}Prefixes:${NC}"
    local pfx
    pfx=$(model_scope_prefixes "$name")
    if [[ -z "$pfx" ]]; then
        echo "    (none — no clients can match this scope)"
    else
        echo "$pfx" | while IFS= read -r c; do
            [[ -z "$c" ]] && continue
            echo "    - ${c}"
        done
    fi
    local devices
    devices=$(model_scope_devices "$name")
    if [[ -n "$devices" ]]; then
        echo -e "  ${BOLD}Tagged addresses:${NC} (RADIUS: each gets its own vendor's attribute only)"
        local dc dv
        while IFS='|' read -r dc dv; do
            [[ -z "$dc" ]] && continue
            echo "    - ${dc}  ${dv}"
        done <<< "$devices"
    fi
    echo -e "  ${BOLD}Users:${NC}"
    local users
    users=$(model_scope_users "$name")
    if [[ -z "$users" ]]; then
        echo "    (none)"
    else
        echo "$users" | while IFS= read -r u; do
            echo "    - ${u}"
        done
    fi
    echo ""
}

# Print the "already claimed" lines for every CIDR in the newline-separated
# list $1 that another scope than $2 owns. One prefix belongs to one scope:
# tacquito answers a client from the first entry that matches, so a second
# owner's users could never authenticate from that device.
_scope_prefix_collisions() {
    local c owner
    while IFS= read -r c; do
        [[ -z "$c" ]] && continue
        owner=$(model_prefix_owner "$c")
        if [[ -n "$owner" && "$owner" != "$2" ]]; then
            echo "    - ${c}  (already in scope '${owner}')"
        fi
    done <<< "$1"
}

# _scope_vendor_list <csv> [<what to call it in the error>]: the vendors of a
# comma-separated list in the fixed order of SCOPE_VENDORS, each once, as a
# csv. Returns 1, with an error, for an unknown vendor or an empty list.
_scope_vendor_list() {
    local v known out=""
    for v in ${1//,/ }; do
        if [[ " ${SCOPE_VENDORS} " != *" ${v} "* ]]; then
            error "Unknown vendor '${v}'. Known vendors: ${SCOPE_VENDORS// /, }"
            return 1
        fi
    done
    for known in $SCOPE_VENDORS; do
        [[ " ${1//,/ } " == *" ${known} "* ]] && out+="${out:+,}${known}"
    done
    if [[ -z "$out" ]]; then
        error "No vendor given. Known vendors: ${SCOPE_VENDORS// /, }"
        return 1
    fi
    echo "$out"
}

# _scope_device_problems <scope> <prefix csv> [<cidr> <vendor>]: would that
# scope with those prefixes (and that address tagged) leave a tagged address
# where it cannot be? Prints one error per problem and returns 1. The store
# refuses the same; this says it before anything is written.
_scope_device_problems() {
    local problems pscope pcidr pmsg lead
    problems=$(_model_view device-problems "$@") && return 0
    while IFS='|' read -r pscope pcidr pmsg; do
        [[ -n "$pscope" ]] || continue
        lead="scope '${pscope}': devices: "
        error "    - ${pmsg#"$lead"}  (tagged in scope '${pscope}'; to remove the tag: tacctl scope devices ${pscope} unset ${pcidr})"
    done <<< "$problems"
    return 1
}

# Writer for store_apply: create the scope and, with a 4th argument, point
# scope.default at it. $5 is a protocols filter, $6 the vendor attributes to
# enable; either may be empty.
_scope_add_write() {
    local -a fields=("prefixes=$2" "secret=$3")
    [[ -n "${5:-}" ]] && fields+=("protocols=$5")
    [[ -n "${6:-}" ]] && fields+=("vendor_attrs=$6")
    store_scope_set "$1" "${fields[@]}" || return 1
    if [[ -n "${4:-}" ]]; then
        write_default_scope "$1" || return 1
    fi
}

cmd_scope_add() {
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        error "Usage: tacctl scope add <name> --prefixes <cidrs> [--secret <value>|generate] [--protocols <protocol>[,<protocol>...]] [--vendor-attrs <vendor>[,<vendor>...]] [--default]"
        exit 1
    fi
    shift
    store_require || exit 1
    if ! [[ "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,31}$ ]]; then
        error "Invalid scope name '${name}'. Use letters/digits/_-, starting with a letter."
        exit 1
    fi
    if model_scope_exists "$name"; then
        error "Scope '${name}' already exists."
        exit 1
    fi

    local prefixes="" secret_arg="" make_default="" protocols_arg="" protocols="" vendor_arg="" vendor_attrs=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --prefixes) prefixes="${2:-}"; shift 2 ;;
            --secret)   secret_arg="${2:-}"; shift 2 ;;
            --protocols) protocols_arg="${2:-}"; shift 2 ;;
            --vendor-attrs)
                vendor_arg="${2:-}"
                [[ -n "$vendor_arg" ]] || { error "--vendor-attrs needs a list of vendors (${SCOPE_VENDORS// /, })."; exit 1; }
                shift 2
                ;;
            --default)  make_default="yes"; shift ;;
            *) error "Unknown flag: '$1'"; exit 1 ;;
        esac
    done

    # --protocols: the filter 'scope protocols <name> set' would write,
    # stored in the fixed order of SCOPE_PROTOCOLS.
    if [[ -n "$protocols_arg" ]]; then
        local p known
        for p in ${protocols_arg//,/ }; do
            if [[ " ${SCOPE_PROTOCOLS} " != *" ${p} "* ]]; then
                error "Unknown protocol '${p}'. Known protocols: ${SCOPE_PROTOCOLS// /, }"
                exit 1
            fi
        done
        for known in $SCOPE_PROTOCOLS; do
            [[ ",${protocols_arg}," == *",${known},"* ]] && protocols+="${protocols:+,}${known}"
        done
    fi

    # --vendor-attrs: what 'scope vendor-attrs <name> enable' would write.
    if [[ -n "$vendor_arg" ]]; then
        vendor_attrs=$(_scope_vendor_list "$vendor_arg") || exit 1
    fi

    if [[ -z "$prefixes" ]]; then
        error "--prefixes <cidrs> is required (comma-separated list)."
        exit 1
    fi
    local canon
    canon=$(parse_cidr_list "$prefixes")
    [[ -z "$canon" ]] && { error "No valid CIDRs in --prefixes."; exit 1; }

    # One-scope-per-prefix invariant (the store enforces it too). Abort
    # before writing anything.
    local collisions
    collisions=$(_scope_prefix_collisions "$canon" "")
    if [[ -n "$collisions" ]]; then
        error "Cannot create scope '${name}': prefix(es) already claimed:"
        while IFS= read -r line; do error "$line"; done <<< "$collisions"
        error "Each CIDR belongs to exactly one scope. Remove it from the owning"
        error "scope first with 'tacctl scope prefixes <owner> remove <cidr>'."
        exit 1
    fi

    local csv
    csv=$(printf '%s\n' "$canon" | paste -sd,)

    # A new prefix inside another scope's range takes the addresses in it
    # away from that scope; one of them tagged there would be left behind.
    if ! _model_view device-problems "$name" "$csv" > /dev/null; then
        error "Cannot create scope '${name}': it would take over an address another scope has tagged with a vendor:"
        _scope_device_problems "$name" "$csv" || true
        exit 1
    fi

    local secret_value=""
    if [[ -z "$secret_arg" || "$secret_arg" == "generate" ]]; then
        secret_value=$(openssl rand -base64 24)
        info "Generated secret: ${BOLD}${secret_value}${NC}"
    else
        secret_value="$secret_arg"
        if [[ "${#secret_value}" -lt "$SECRET_MIN_LENGTH" ]]; then
            error "Secret is ${#secret_value} characters; minimum is ${SECRET_MIN_LENGTH}."
            exit 1
        fi
    fi

    store_apply _scope_add_write "$name" "$csv" "$secret_value" "$make_default" "$protocols" "$vendor_attrs" || exit $?

    if [[ -n "$make_default" ]]; then
        info "Scope '${name}' added and set as default."
    else
        info "Scope '${name}' added."
    fi
    echo ""
}

cmd_scope_remove() {
    local name="${1:-}" force="false"
    if [[ -z "$name" ]]; then
        error "Usage: tacctl scope remove <name> [--force]"
        exit 1
    fi
    shift 2>/dev/null || true
    [[ "${1:-}" == "--force" ]] && force="true"
    store_require || exit 1

    if ! model_scope_exists "$name"; then
        error "Scope '${name}' does not exist."
        exit 1
    fi

    local members user_count=0
    members=$(model_scope_users "$name") || exit 1
    [[ -n "$members" ]] && user_count=$(printf '%s\n' "$members" | wc -l)
    if [[ "$user_count" -gt 0 && "$force" != "true" ]]; then
        error "Cannot remove '${name}': ${user_count} user(s) still reference it."
        error "Remove them first:"
        printf '%s\n' "$members" | sed 's/^/    tacctl user scope /' | sed 's/$/ remove '"${name}"'/'
        error "Or pass --force to strip the scope from those users AND delete it."
        exit 1
    fi

    local default_val
    default_val=$(read_default_scope)
    if [[ "$name" == "$default_val" ]]; then
        error "Cannot remove '${name}': it is the default scope."
        error "Point the default at another scope first: tacctl scope default <other>"
        exit 1
    fi

    warn "About to remove scope '${name}'."
    [[ "$user_count" -gt 0 ]] && warn "This will also strip '${name}' from ${user_count} user(s)."
    read -rp "  Confirm removal? [y/N]: " confirm || true
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        info "Aborted."
        return
    fi

    # --strip-users takes the scope off any user still referencing it, in
    # the same write (_scope_remove_write).
    store_apply _scope_remove_write "$name" || exit $?
    info "Scope '${name}' removed."
    echo ""
}

# Writer for store_apply: rename the scope (and every user's reference to
# it; its vendor attributes and tagged addresses are in its store entry),
# then every tacctl.yaml key stored under its name, and scope.default if it
# pointed at the old name.
_scope_rename_write() {
    local old="$1" new="$2" default_val
    store_scope_rename "$old" "$new" || return 1
    _scope_conf_keys_move "$old" "$new" || return 1
    default_val=$(conf_get scope.default)
    if [[ "$default_val" == "$old" ]]; then
        write_default_scope "$new" || return 1
        info "Default-scope marker updated: ${old} -> ${new}"
    fi
}

cmd_scope_rename() {
    local old="${1:-}" new="${2:-}"
    if [[ -z "$old" || -z "$new" ]]; then
        error "Usage: tacctl scope rename <old> <new>"
        exit 1
    fi
    store_require || exit 1
    if ! model_scope_exists "$old"; then
        error "Scope '${old}' does not exist."
        exit 1
    fi
    if model_scope_exists "$new"; then
        error "Scope '${new}' already exists."
        exit 1
    fi
    if ! [[ "$new" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,31}$ ]]; then
        error "Invalid new name '${new}'."
        exit 1
    fi
    store_apply _scope_rename_write "$old" "$new" || exit $?
    local user_count
    user_count=$(model_scope_users "$new" | wc -l)
    info "Scope renamed: ${old} -> ${new} (${user_count} user(s) updated)."
    echo ""
}

cmd_scope_default() {
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        local current
        current=$(read_default_scope)
        echo ""
        if [[ -z "$current" ]]; then
            echo "  No default scope set (no scopes configured yet?)."
        else
            echo "  Default scope: ${current}"
        fi
        echo ""
        echo "  Usage: tacctl scope default <name>    # set default to <name>"
        echo "  The default scope is used when:"
        echo "    - 'tacctl user add <u> <g>' is run without --scopes"
        echo "    - 'tacctl config cisco/juniper' is run without --scope"
        echo ""
        return
    fi
    if ! model_scope_exists "$name"; then
        error "Scope '${name}' does not exist."
        exit 1
    fi
    write_default_scope "$name"
    info "Default scope set to '${name}'."
    echo ""
}

# --- Resolve an IP or CIDR to the scope that would own it ---
# Matches tacquito's selection logic: walks the (scope, prefix) pairs in
# the order they are rendered (most specific first) and returns the first
# scope whose prefix contains the query. Emits the owning scope name, the
# matching prefix, and (when a broader covering supernet exists) any
# additional scopes whose prefixes also contain the address — handy when
# debugging unexpected auth routing.
cmd_scope_lookup() {
    local query="${1:-}"
    if [[ -z "$query" ]]; then
        error "Usage: tacctl scope lookup <ip|cidr>"
        error "Examples:"
        error "  tacctl scope lookup 10.5.1.2"
        error "  tacctl scope lookup 10.5.0.0/16"
        exit 1
    fi
    # Exit status: 0 found, 1 no scope owns it, 2 not an address.
    _model_view scope-lookup "$query"
}

# --- Per-scope prefix management: tacctl scope prefixes <scope> ... ---
cmd_scope_prefixes_dispatch() {
    local scope="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"
    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope prefixes <scope> {list|add|remove|clear} [<cidrs>]"
        exit 1
    fi
    case "$sub" in
        add|remove|clear) store_require || exit 1 ;;
    esac
    # Display order (longest prefix first); also the membership list.
    local current
    if ! model_scope_exists "$scope"; then
        error "Scope '${scope}' does not exist."
        exit 1
    fi
    current=$(model_scope_prefixes "$scope") || exit 1
    case "$sub" in
        ""|-h|--help|help)
            local count=0
            count=$(printf '%s\n' "$current" | awk 'NF' | wc -l)
            echo ""
            echo -e "${BOLD}tacctl scope prefixes ${scope}${NC} — CIDR prefix list for scope '${scope}'"
            echo ""
            echo "Usage:"
            echo "  tacctl scope prefixes ${scope} list                        Show entries"
            echo "  tacctl scope prefixes ${scope} add    <cidr>[,<cidr>...]   Add one or more"
            echo "  tacctl scope prefixes ${scope} remove <cidr>[,<cidr>...]   Remove one or more"
            echo "  tacctl scope prefixes ${scope} clear [--force]             Wipe all, which removes the scope (confirms; --force also strips it from users)"
            echo ""
            echo "Current entries: ${count}"
            echo ""
            ;;
        list)
            echo ""
            echo -e "${BOLD}Prefixes for scope '${scope}'${NC}"
            echo "--------------------------------------------"
            if [[ -z "$current" ]]; then
                echo "  (empty — no clients can match this scope)"
            else
                local c
                while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    echo "  - ${c}"
                done <<< "$current"
            fi
            echo ""
            ;;
        add|remove)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope prefixes ${scope} ${sub} <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested c
            requested=$(parse_cidr_list "$arg")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local changed="" missing_or_present=""
            if [[ "$sub" == "add" ]]; then
                # Cross-scope collision check BEFORE any mutation. A CIDR owned
                # by another scope can't be silently stolen — operator must
                # remove it from the owning scope first.
                local collisions
                collisions=$(_scope_prefix_collisions "$requested" "$scope")
                if [[ -n "$collisions" ]]; then
                    error "Cannot add prefix(es) to scope '${scope}':"
                    while IFS= read -r line; do error "$line"; done <<< "$collisions"
                    error "Remove them from the owning scope first:"
                    error "  tacctl scope prefixes <owner> remove <cidr>"
                    exit 1
                fi
                while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF -- "$c"; then
                        missing_or_present+="${missing_or_present:+ }${c}"
                    else
                        changed+="${changed:+$'\n'}${c}"
                        current=$(printf '%s\n%s\n' "$current" "$c")
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { info "No new CIDRs (already present in '${scope}': ${missing_or_present})."; echo ""; return; }
            else
                while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF -- "$c"; then
                        changed+="${changed:+$'\n'}${c}"
                        current=$(printf '%s\n' "$current" | grep -vxF -- "$c" || true)
                    else
                        missing_or_present+="${missing_or_present:+ }${c}"
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { warn "Nothing to remove (not present: ${missing_or_present})."; exit 0; }
                if [[ -z "$(printf '%s\n' "$current" | awk 'NF')" ]]; then
                    error "Cannot remove every prefix of scope '${scope}': a scope needs at least one."
                    error "To delete the scope: tacctl scope remove ${scope}"
                    exit 1
                fi
            fi
            # Tagged addresses ('scope devices') must stay inside a prefix of
            # their scope. Refused rather than dropped: a tag says what a
            # device is, and losing it without a word (a prefix removed here
            # and added back wider a moment later) would change what that
            # device is sent. Add the new prefix first, or unset the tag.
            local new_csv
            new_csv=$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)
            if ! _model_view device-problems "$scope" "$new_csv" > /dev/null; then
                if [[ "$sub" == "remove" ]]; then
                    error "Cannot remove the prefix(es) from scope '${scope}': a tagged address would be left outside the scope's prefixes:"
                else
                    error "Cannot add the prefix(es) to scope '${scope}': it would take over an address another scope has tagged with a vendor:"
                fi
                _scope_device_problems "$scope" "$new_csv" || true
                error "Nothing was changed. Unset the tag first, or (when moving a range) add the new prefix before removing the old one."
                exit 1
            fi
            store_apply store_scope_set "$scope" "prefixes=${new_csv}" || exit $?
            local n
            n=$(printf '%s\n' "$changed" | wc -l)
            local verb="Added"; [[ "$sub" == "remove" ]] && verb="Removed"
            info "${verb} ${n} prefix(es) for scope '${scope}': $(printf '%s\n' "$changed" | paste -sd' ')"
            [[ -n "$missing_or_present" ]] && info "(Skipped: ${missing_or_present})"
            echo ""
            ;;
        clear)
            # A scope cannot exist without a prefix, so clearing them all
            # removes the scope. Same guard as 'scope remove': refuse while
            # users reference it unless --force, which strips it from them.
            local force="false"
            [[ "$arg" == "--force" ]] && force="true"
            if [[ -z "$current" ]]; then
                info "Scope '${scope}' prefix list is already empty."
                return
            fi
            local members user_count=0
            members=$(model_scope_users "$scope") || exit 1
            [[ -n "$members" ]] && user_count=$(printf '%s\n' "$members" | wc -l)
            if [[ "$user_count" -gt 0 && "$force" != "true" ]]; then
                error "Cannot clear prefixes for '${scope}': ${user_count} user(s) still reference it."
                error "Clearing every prefix removes the scope, and with it those users' grant."
                error "Detach users first:"
                printf '%s\n' "$members" | sed 's/^/    tacctl user scope /' | sed 's/$/ remove '"${scope}"'/'
                error "Or pass --force to strip the scope from those users AND remove it."
                exit 1
            fi
            local n
            n=$(printf '%s\n' "$current" | wc -l)
            warn "Clearing all ${n} prefix(es) from '${scope}' removes the scope."
            if [[ "$user_count" -gt 0 ]]; then
                warn "${user_count} user(s) will lose their grant of '${scope}'."
            fi
            read -rp "  Confirm? [y/N]: " confirm || true
            [[ ! "$confirm" =~ ^[Yy] ]] && { info "Aborted."; return; }
            store_apply _scope_remove_write "$scope" || exit $?
            info "Cleared prefixes for scope '${scope}' (the scope is removed)."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl scope prefixes ${scope}' for usage."
            exit 1
            ;;
    esac
}

# --- Per-scope secret management: tacctl scope secret <scope> ... ---
cmd_scope_secret_dispatch() {
    local scope="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"
    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope secret <scope> {show|set <value>|generate}"
        exit 1
    fi
    case "$sub" in
        set|generate) store_require || exit 1 ;;
    esac
    local cur s_len
    if ! cur=$(model_scope "$scope" secret); then
        error "Scope '${scope}' does not exist."
        exit 1
    fi
    s_len=${#cur}
    case "$sub" in
        ""|-h|--help|help)
            echo ""
            echo -e "${BOLD}tacctl scope secret ${scope}${NC} — shared secret for scope '${scope}'"
            echo ""
            echo "Usage:"
            echo "  tacctl scope secret ${scope} show                Print raw value + length/posture"
            echo "  tacctl scope secret ${scope} set <value>         Set to <value> (validated)"
            echo "  tacctl scope secret ${scope} generate            Auto-generate + apply"
            echo ""
            echo "Current length: ${s_len} chars (min ${SECRET_MIN_LENGTH})"
            echo ""
            ;;
        show)
            echo ""
            echo -e "${BOLD}Scope '${scope}' — shared secret${NC}"
            echo "--------------------------------------------"
            if [[ -z "$cur" ]]; then
                echo -e "  ${RED}(unset)${NC}"
            elif [[ "$cur" == *REPLACE* ]]; then
                echo -e "  Value:  ${BOLD}${cur}${NC}"
                echo -e "  ${RED}Length: ${s_len} chars — PLACEHOLDER (run 'tacctl scope secret ${scope} generate')${NC}"
            elif [[ "$s_len" -lt "$SECRET_MIN_LENGTH" ]]; then
                echo -e "  Value:  ${BOLD}${cur}${NC}"
                echo -e "  ${RED}Length: ${s_len} chars (below min ${SECRET_MIN_LENGTH})${NC}"
            else
                echo -e "  Value:  ${BOLD}${cur}${NC}"
                echo -e "  ${GREEN}Length: ${s_len} chars${NC}"
            fi
            echo ""
            ;;
        set)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope secret ${scope} set <value>"
                exit 1
            fi
            if [[ "${#arg}" -lt "$SECRET_MIN_LENGTH" ]]; then
                error "Secret is ${#arg} characters; minimum is ${SECRET_MIN_LENGTH}."
                exit 1
            fi
            if [[ "$arg" =~ ^[a-z]+$ ]] || [[ "$arg" =~ ^[A-Z]+$ ]] || [[ "$arg" =~ ^[0-9]+$ ]]; then
                error "Secret is single-character-class (low entropy)."
                exit 1
            fi
            # The value reaches the store writer on stdin (see store_mutate).
            store_apply store_scope_set "$scope" "secret=${arg}" || exit $?
            info "Scope '${scope}' secret updated."
            warn "Update ALL devices in scope '${scope}' with the new secret: ${arg}"
            echo ""
            ;;
        generate)
            local new_val
            new_val=$(openssl rand -base64 24)
            echo -e "  Generated: ${BOLD}${new_val}${NC}"
            store_apply store_scope_set "$scope" "secret=${new_val}" || exit $?
            info "Scope '${scope}' secret updated."
            warn "Update ALL devices in scope '${scope}' with the new secret above."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl scope secret ${scope}' for usage."
            exit 1
            ;;
    esac
}

# --- Per-scope protocol filter: tacctl scope protocols <scope> [list|set <csv>|clear] ---
# A scope without a filter is served by every enabled backend. A filter
# names the protocols that may serve it; a backend whose protocol is not
# listed leaves the scope (its prefixes, its secret, and its users' grant of
# it) out of what it renders.
cmd_scope_protocols() {
    local scope="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"
    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope protocols <scope> [list|set <protocol>[,<protocol>...]|clear]"
        exit 1
    fi
    case "$sub" in
        set|clear) store_require || exit 1 ;;
    esac
    local current
    if ! current=$(model_scope "$scope" protocols); then
        error "Scope '${scope}' does not exist."
        exit 1
    fi
    current=$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)

    case "$sub" in
        ""|list|-h|--help|help)
            echo ""
            if [[ -z "$current" ]]; then
                echo "  Scope '${scope}' protocols: all (no filter — every enabled backend serves it)"
            else
                echo "  Scope '${scope}' protocols: ${current}"
            fi
            echo ""
            echo "  Usage: tacctl scope protocols ${scope} set <protocol>[,<protocol>...]   (known: ${SCOPE_PROTOCOLS// /, })"
            echo "         tacctl scope protocols ${scope} clear                            (back to all)"
            echo ""
            ;;
        set)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope protocols ${scope} set <protocol>[,<protocol>...]"
                error "Known protocols: ${SCOPE_PROTOCOLS// /, }"
                exit 1
            fi
            local p known wanted=""
            local -a _REQ
            IFS=',' read -ra _REQ <<< "$arg"
            for p in "${_REQ[@]}"; do
                p=$(echo "$p" | xargs)
                [[ -z "$p" ]] && continue
                if [[ " ${SCOPE_PROTOCOLS} " != *" ${p} "* ]]; then
                    error "Unknown protocol '${p}'. Known protocols: ${SCOPE_PROTOCOLS// /, }"
                    exit 1
                fi
                wanted+=" ${p} "
            done
            # Stored in the fixed order of SCOPE_PROTOCOLS, each once.
            local new_list=""
            for known in $SCOPE_PROTOCOLS; do
                [[ "$wanted" == *" ${known} "* ]] && new_list+="${new_list:+,}${known}"
            done
            if [[ -z "$new_list" ]]; then
                error "No protocols given. To remove the filter: tacctl scope protocols ${scope} clear"
                exit 1
            fi
            if [[ "$new_list" == "$current" ]]; then
                info "Scope '${scope}' protocols already ${new_list}."
                echo ""
                return
            fi
            # The scope's auth-method names the protocol its devices and
            # hosts are configured for by default; a filter without it would
            # leave those defaults pointing at a backend that ignores the scope.
            local auth_method
            auth_method=$(scope_auth_method "$scope")
            if [[ -n "$auth_method" && ",${new_list}," != *",${auth_method},"* ]]; then
                error "Scope '${scope}' has auth-method ${auth_method}, which protocols '${new_list}' would leave unserved. Nothing was changed."
                error "Change or clear the auth-method first: tacctl scope auth-method ${scope} <tacacs|radius|clear>   (or keep ${auth_method} in the list)"
                exit 1
            fi
            store_apply store_scope_set "$scope" "protocols=${new_list}" || exit $?
            info "Scope '${scope}' protocols set to ${new_list}."
            if [[ ",${new_list}," != *",tacacs,"* ]]; then
                warn "Scope '${scope}' is no longer served over TACACS+: its devices and its users' grant of it are left out of tacquito.yaml."
            fi
            echo ""
            ;;
        clear)
            if [[ -z "$current" ]]; then
                info "Scope '${scope}' has no protocols filter."
                echo ""
                return
            fi
            store_apply store_scope_set "$scope" "protocols=null" || exit $?
            info "Scope '${scope}' protocols filter cleared (every enabled backend serves it)."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Usage: tacctl scope protocols ${scope} [list|set <protocol>[,<protocol>...]|clear]"
            exit 1
            ;;
    esac
}

# --- Per-scope vendor attributes (RADIUS): tacctl scope vendor-attrs <scope> [enable|disable <vendor>[,<vendor>...]] ---
# What an Access-Accept carries besides Service-Type is opt-in per scope: a
# new scope sends no vendor's privilege attribute. A vendor enabled here gets
# its attribute sent to every device of the scope that is not tagged
# ('scope devices'); a tagged address gets its own vendor's attribute only,
# whatever is enabled here.
#   cisco    Cisco-AVPair "shell:priv-lvl=<N>"
#   juniper  Juniper-Local-User-Name "<class>"
#   wti      WTI-Super <0-3>
# The verbs are enable and disable, as for backends: nothing is sent until it
# is enabled, and there is no 'set', 'clear' or 'none' whose empty form could
# be read as "all". Stored on the scope in store.yaml (vendor_attrs), so a
# change re-renders the RADIUS backend and restarts it. TACACS+ is not
# affected: a device asks for its own service there.
_scope_vendor_radius_notes() {
    local scope="$1" protocols
    protocols=$(model_scope "$scope" protocols | awk 'NF' | paste -sd, || true)
    if [[ -n "$protocols" && ",${protocols}," != *",radius,"* ]]; then
        warn "Scope '${scope}' is limited to ${protocols} (tacctl scope protocols), so it is not served over RADIUS and this has no effect yet."
    elif _backends_load 2> /dev/null && ! _backend_is_enabled radius; then
        warn "The RADIUS backend is not enabled on this server, so this has no effect yet: tacctl backend enable radius"
    fi
}

cmd_scope_vendor_attrs() {
    local scope="${1:-}" sub="${2:-}" arg="${3:-}"
    local usage="tacctl scope vendor-attrs <scope> [enable <vendor>[,<vendor>...]|disable <vendor>[,<vendor>...]]"
    if [[ -z "$scope" ]]; then
        error "Usage: ${usage}"
        error "Vendors: ${SCOPE_VENDORS// /, }"
        exit 1
    fi
    case "$sub" in
        enable|disable) store_require || exit 1 ;;
    esac
    local current
    if ! current=$(model_scope "$scope" vendor_attrs); then
        error "Scope '${scope}' does not exist."
        exit 1
    fi
    current=$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)

    case "$sub" in
        ""|show|list|-h|--help|help)
            local tagged
            tagged=$(model_scope_devices "$scope" | awk 'NF' | wc -l)
            echo ""
            echo "  Scope '${scope}' vendor attributes: ${current:-not sent}"
            if (( tagged > 0 )); then
                echo "  Tagged addresses: ${tagged} (each gets its own vendor's attribute only; tacctl scope devices ${scope})"
            fi
            echo ""
            echo "    Over RADIUS an Access-Accept always carries Service-Type. A vendor's privilege attribute"
            echo "    is added only when that vendor is enabled here (for every device of the scope that is not"
            echo "    tagged) or the device's address is tagged with it:"
            echo "      cisco    Cisco-AVPair \"shell:priv-lvl=<N>\"   (the group's privilege level)"
            echo "      juniper  Juniper-Local-User-Name            (the group's Juniper class)"
            echo "      wti      WTI-Super                          (0 ViewOnly, 1 User, 2 SuperUser, 3 Administrator)"
            echo "    TACACS+ is not affected."
            echo ""
            echo "  Usage: tacctl scope vendor-attrs ${scope} enable <vendor>[,<vendor>...]    (vendors: ${SCOPE_VENDORS// /, })"
            echo "         tacctl scope vendor-attrs ${scope} disable <vendor>[,<vendor>...]"
            echo ""
            ;;
        enable|disable)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope vendor-attrs ${scope} ${sub} <vendor>[,<vendor>...]"
                error "Vendors: ${SCOPE_VENDORS// /, }"
                exit 1
            fi
            local wanted v new_list="" changed=""
            wanted=$(_scope_vendor_list "$arg") || exit 1
            for v in $SCOPE_VENDORS; do
                if [[ ",${wanted}," == *",${v},"* ]]; then
                    # Named on the command line: on for enable, off for disable.
                    if [[ "$sub" == "enable" ]]; then
                        new_list+="${new_list:+,}${v}"
                        [[ ",${current}," == *",${v},"* ]] || changed+="${changed:+, }${v}"
                    else
                        [[ ",${current}," == *",${v},"* ]] && changed+="${changed:+, }${v}"
                    fi
                elif [[ ",${current}," == *",${v},"* ]]; then
                    new_list+="${new_list:+,}${v}"
                fi
            done
            if [[ -z "$changed" ]]; then
                if [[ "$sub" == "enable" ]]; then
                    info "Scope '${scope}': ${wanted//,/, } already enabled (vendor attributes: ${current//,/, })."
                else
                    info "Scope '${scope}': ${wanted//,/, } not enabled; no change (vendor attributes: ${current:-not sent})."
                fi
                echo ""
                return
            fi
            store_apply store_scope_set "$scope" "vendor_attrs=${new_list:-null}" || exit $?
            if [[ "$sub" == "enable" ]]; then
                info "Scope '${scope}': vendor attributes enabled: ${changed}. Now sent: ${new_list//,/, }."
            else
                info "Scope '${scope}': vendor attributes disabled: ${changed}. Now: ${new_list:-not sent}."
                local dc dv still=""
                while IFS='|' read -r dc dv; do
                    [[ -n "$dc" && ", ${changed}, " == *", ${dv}, "* ]] && still+="${still:+, }${dc}"
                done < <(model_scope_devices "$scope")
                if [[ -n "$still" ]]; then
                    info "Tagged addresses keep their vendor's attribute: ${still} (tacctl scope devices ${scope})."
                fi
            fi
            _scope_vendor_radius_notes "$scope"
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'. The verbs are enable and disable: nothing is sent until a vendor is enabled."
            error "Usage: ${usage}"
            exit 1
            ;;
    esac
}

# --- Tagged addresses of a scope (RADIUS): tacctl scope devices <scope> [set <ip|cidr> <vendor>|unset <ip|cidr>] ---
# A device whose vendor is known can be told to the server: its address (or
# a range) is tagged with the vendor, and over RADIUS it then gets that
# vendor's attribute and no other vendor's, whether or not the scope enables
# any ('scope vendor-attrs'). A bare address is a /32 (/128). Stored on the
# scope in store.yaml (devices: cidr -> vendor); the RADIUS backend renders a
# client of its own for each, with the scope's secret, which is why a tagged
# address must be one 'scope lookup' answers with this scope.
cmd_scope_devices() {
    local scope="${1:-}" sub="${2:-}" addr="${3:-}" vendor="${4:-}"
    local usage="tacctl scope devices <scope> [set <ip|cidr> <vendor>|unset <ip|cidr>]"
    if [[ -z "$scope" ]]; then
        error "Usage: ${usage}"
        exit 1
    fi
    case "$sub" in
        set|unset) store_require || exit 1 ;;
    esac
    if ! model_scope_exists "$scope"; then
        error "Scope '${scope}' does not exist."
        exit 1
    fi
    local current
    current=$(model_scope_devices "$scope") || exit 1

    case "$sub" in
        ""|list|-h|--help|help)
            local attrs dc dv
            attrs=$(model_scope "$scope" vendor_attrs | awk 'NF' | paste -sd, || true)
            echo ""
            echo -e "${BOLD}Tagged addresses of scope '${scope}'${NC} (RADIUS)"
            echo "--------------------------------------------"
            if [[ -z "$current" ]]; then
                echo "  (none)"
            else
                while IFS='|' read -r dc dv; do
                    [[ -z "$dc" ]] && continue
                    printf "  %-24s %s\n" "$dc" "$dv"
                done <<< "$current"
            fi
            echo ""
            echo "  A tagged address gets its own vendor's attribute and no other vendor's."
            echo "  Every other device of the scope gets what the scope enables: ${attrs:-not sent} (tacctl scope vendor-attrs ${scope})."
            echo ""
            echo "  Usage: tacctl scope devices ${scope} set <ip|cidr> <vendor>    (vendors: ${SCOPE_VENDORS// /, })"
            echo "         tacctl scope devices ${scope} unset <ip|cidr>"
            echo ""
            ;;
        set|unset)
            if [[ -z "$addr" || ( "$sub" == "set" && -z "$vendor" ) || ( "$sub" == "unset" && -n "$vendor" ) ]]; then
                if [[ "$sub" == "set" ]]; then
                    error "Usage: tacctl scope devices ${scope} set <ip|cidr> <vendor>   (vendors: ${SCOPE_VENDORS// /, })"
                else
                    error "Usage: tacctl scope devices ${scope} unset <ip|cidr>"
                fi
                exit 1
            fi
            local cidr
            cidr=$(canonicalize_cidr "$addr")
            if [[ -z "$cidr" ]]; then
                error "Invalid address or CIDR: '${addr}'"
                exit 1
            fi
            local dc dv had="" new_map=""
            while IFS='|' read -r dc dv; do
                [[ -z "$dc" ]] && continue
                if [[ "$dc" == "$cidr" ]]; then
                    had="$dv"
                else
                    new_map+="${new_map:+,}${dc}=${dv}"
                fi
            done <<< "$current"

            if [[ "$sub" == "unset" ]]; then
                if [[ -z "$had" ]]; then
                    info "${cidr} is not tagged in scope '${scope}'; no change."
                    echo ""
                    return
                fi
                store_apply store_scope_set "$scope" "devices=${new_map:-null}" || exit $?
                info "Scope '${scope}': ${cidr} is no longer tagged (it was ${had}); it gets what the scope enables (tacctl scope vendor-attrs ${scope})."
                echo ""
                return
            fi

            if [[ " ${SCOPE_VENDORS} " != *" ${vendor} "* ]]; then
                error "Unknown vendor '${vendor}'. Known vendors: ${SCOPE_VENDORS// /, }"
                exit 1
            fi
            if [[ "$had" == "$vendor" ]]; then
                info "${cidr} is already tagged ${vendor} in scope '${scope}'; no change."
                echo ""
                return
            fi
            local prefix_csv
            prefix_csv=$(model_scope "$scope" prefixes | awk 'NF' | paste -sd,)
            if ! _model_view device-problems "$scope" "$prefix_csv" "$cidr" "$vendor" > /dev/null; then
                error "Cannot tag ${cidr} in scope '${scope}': a tagged address must be one this scope answers for ('tacctl scope lookup ${addr}')."
                local problems pscope pcidr pmsg lead
                problems=$(_model_view device-problems "$scope" "$prefix_csv" "$cidr" "$vendor") || true
                while IFS='|' read -r pscope pcidr pmsg; do
                    [[ "$pcidr" == "$cidr" ]] || continue
                    lead="scope '${pscope}': devices: "
                    error "    - ${pmsg#"$lead"}"
                done <<< "$problems"
                error "Nothing was changed."
                exit 1
            fi
            store_apply store_scope_set "$scope" "devices=${new_map:+${new_map},}${cidr}=${vendor}" || exit $?
            if [[ -n "$had" ]]; then
                info "Scope '${scope}': ${cidr} is now tagged ${vendor} (it was ${had})."
            else
                info "Scope '${scope}': ${cidr} tagged ${vendor}: over RADIUS it gets that vendor's attribute only."
            fi
            _scope_vendor_radius_notes "$scope"
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Usage: ${usage}"
            exit 1
            ;;
    esac
}

# --- Per-scope AAA method-list order: tacctl scope aaa-order <scope> [value] ---
# Flips the order of methods in the Cisco `aaa authentication/authorization`
# and Junos `system authentication-order` lines that `tacctl config
# cisco --scope <name>` / `tacctl config juniper --scope <name>` emit.
# Per-scope so a lab scope can favor local break-glass access while a
# prod scope keeps TACACS+ authoritative. Absent an override, each
# scope defaults to tacacs-first.
cmd_scope_aaa_order() {
    local scope="${1:-}"
    local new_order="${2:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope aaa-order <scope> [tacacs-first|local-first]"
        exit 1
    fi
    _scope_require "$scope" || exit 1

    local current source
    current=$(conf_get "aaa.order.${scope}")
    if [[ -z "$current" ]]; then
        current="tacacs-first"
        source="default"
    else
        source="override (tacctl.yaml: aaa.order.${scope})"
    fi

    if [[ -z "$new_order" ]]; then
        echo ""
        echo "  Scope '${scope}' AAA method-list order: ${current}"
        echo "  Source: ${source}"
        echo ""
        echo "    tacacs-first  The server (TACACS+ or RADIUS) is authoritative; local used only on server outage."
        echo "    local-first   Local DB checked first; the server used for names not found locally."
        echo ""
        echo "  Usage: tacctl scope aaa-order ${scope} <tacacs-first|local-first>"
        echo ""
        return
    fi

    conf_set "aaa.order.${scope}" "$new_order" || exit 1
    info "Scope '${scope}' AAA method-list order set to ${new_order}."
    if [[ "$new_order" == "local-first" ]]; then
        warn "Local usernames that collide with tacctl users will win locally on devices in this scope (TACACS+ and RADIUS)."
        warn "Scope local accounts to break-glass / emergency use only."
    fi
    echo ""
    echo "  Re-run 'tacctl config cisco --scope ${scope}' / 'tacctl config juniper --scope ${scope}'"
    echo "  and push the updated method-lists to each device in this scope — the change is not"
    echo "  applied until the device receives the new AAA stanzas."
    echo ""
}

# --- Per-scope exec-timeout: tacctl scope exec-timeout <scope> [minutes] ---
# Sets the idle-session timeout in minutes for devices in this scope.
# Cisco substitutes into `line con 0 / line vty 0 15 ... exec-timeout
# <n> 0`; Junos renders `set system login idle-timeout <n>`. 0 means
# never expire (both vendors). Upper bound 60 matches Junos's max;
# Cisco accepts higher but we cap for cross-vendor portability.
cmd_scope_exec_timeout() {
    local scope="${1:-}"
    local new_mins="${2:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope exec-timeout <scope> [minutes]"
        exit 1
    fi
    _scope_require "$scope" || exit 1

    local current source
    current=$(conf_get "exec_timeout.${scope}")
    if [[ -z "$current" ]]; then
        current="60"
        source="default"
    else
        source="override (tacctl.yaml: exec_timeout.${scope})"
    fi

    if [[ -z "$new_mins" ]]; then
        echo ""
        echo "  Scope '${scope}' exec-timeout: ${current} minute(s)"
        echo "  Source: ${source}"
        echo ""
        echo "    0..60 minutes. 0 = never expire (both Cisco and Junos)."
        echo ""
        echo "  Usage: tacctl scope exec-timeout ${scope} <minutes>"
        echo ""
        return
    fi

    conf_set "exec_timeout.${scope}" "$new_mins" || exit 1
    info "Scope '${scope}' exec-timeout set to ${new_mins} minute(s)."
    if [[ "$new_mins" == "0" ]]; then
        warn "exec-timeout 0 disables idle-session expiry on devices in this scope."
        warn "Long-lived sessions on unattended terminals become a security risk."
    fi
    echo ""
    echo "  Re-run 'tacctl config cisco --scope ${scope}' / 'tacctl config juniper --scope ${scope}'"
    echo "  and push the updated line-config / login stanzas to each device in this scope."
    echo ""
}

# --- Per-scope Cisco aaa-group-server label: tacctl scope tacacs-group <scope> [name] ---
# Rendered into every Cisco `aaa group server tacacs+ <NAME>` and the
# method-lists/accounting lines that reference the group. Per-scope so
# each environment can match site naming conventions. Junos has no
# equivalent (its AAA doesn't group named servers this way).
cmd_scope_tacacs_group() {
    local scope="${1:-}"
    local new_name="${2:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope tacacs-group <scope> [name]"
        exit 1
    fi
    _scope_require "$scope" || exit 1

    local current source
    current=$(conf_get "tacacs_group.${scope}")
    if [[ -z "$current" ]]; then
        current="TACACS-GROUP"
        source="default"
    else
        source="override (tacctl.yaml: tacacs_group.${scope})"
    fi

    if [[ -z "$new_name" ]]; then
        echo ""
        echo "  Scope '${scope}' Cisco aaa-group-server name: ${current}"
        echo "  Source: ${source}"
        echo ""
        echo "    Rendered into every 'aaa group server tacacs+ <NAME>' and the method-list"
        echo "    / accounting lines that reference the group (Cisco only; Junos has no"
        echo "    equivalent)."
        echo ""
        echo "  Usage: tacctl scope tacacs-group ${scope} <name>"
        echo ""
        return
    fi

    conf_set "tacacs_group.${scope}" "$new_name" || exit 1
    info "Scope '${scope}' aaa-group-server label set to ${new_name}."
    echo ""
    echo "  Re-run 'tacctl config cisco --scope ${scope}' and push the updated AAA"
    echo "  stanzas to each device in this scope — the change is not applied until"
    echo "  the device receives the new group name. Leaving a stale local group"
    echo "  reference on the device will break authentication."
    echo ""
}

# --- Per-scope Cisco aaa-group-server label for RADIUS: tacctl scope radius-group <scope> [name] ---
# The RADIUS twin of tacacs-group: rendered into every Cisco
# `aaa group server radius <NAME>` and the method-list / accounting lines
# of `tacctl config cisco --protocol radius`. Junos has no equivalent.
cmd_scope_radius_group() {
    local scope="${1:-}"
    local new_name="${2:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope radius-group <scope> [name]"
        exit 1
    fi
    _scope_require "$scope" || exit 1

    local current source
    current=$(conf_get "radius_group.${scope}")
    if [[ -z "$current" ]]; then
        current="RADIUS-GROUP"
        source="default"
    else
        source="override (tacctl.yaml: radius_group.${scope})"
    fi

    if [[ -z "$new_name" ]]; then
        echo ""
        echo "  Scope '${scope}' Cisco RADIUS aaa-group-server name: ${current}"
        echo "  Source: ${source}"
        echo ""
        echo "    Rendered into every 'aaa group server radius <NAME>' and the method-list"
        echo "    / accounting lines that reference the group by"
        echo "    'tacctl config cisco --protocol radius' (Cisco only; Junos has no"
        echo "    equivalent)."
        echo ""
        echo "  Usage: tacctl scope radius-group ${scope} <name>"
        echo ""
        return
    fi

    conf_set "radius_group.${scope}" "$new_name" || exit 1
    info "Scope '${scope}' RADIUS aaa-group-server label set to ${new_name}."
    echo ""
    echo "  Re-run 'tacctl config cisco --scope ${scope} --protocol radius' and push the"
    echo "  updated AAA stanzas to each device in this scope — the change is not applied"
    echo "  until the device receives the new group name. Leaving a stale local group"
    echo "  reference on the device will break authentication."
    echo ""
}

# --- Per-scope default authentication method: tacctl scope auth-method <scope> [tacacs|radius|clear] ---
# The protocol used for this scope when a command is not told one:
#   config cisco|juniper|wti   without --protocol (an explicit --protocol wins)
#   host enroll                without --method, for a host that is not registered
#                              yet (a registered host keeps its method)
#   config linux script        without --method
# Stored as scope_auth_method.<scope> in tacctl.yaml. Without it the scope's
# protocols filter decides when it names exactly one protocol, and otherwise
# the global default does: device configs are TACACS+, hosts take
# 'host default-method' (scope_protocol_choice). 'clear' removes the setting,
# as it does for 'scope protocols' and 'scope mgmt-acl' ('default' is accepted
# for it); 'tacplus' (the name of the host method) is accepted for 'tacacs',
# which is the one spelling this command prints.
# The setting changes nothing on the server and re-renders nothing: it is
# read when a device config or a host script is produced.
cmd_scope_auth_method() {
    local scope="${1:-}"
    local new_method="${2:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope auth-method <scope> [tacacs|radius|clear]"
        exit 1
    fi
    _scope_require "$scope" || exit 1

    local current source
    current=$(scope_auth_method "$scope")
    if [[ -z "$current" ]]; then
        source="default (not set)"
    else
        source="override (tacctl.yaml: scope_auth_method.${scope})"
    fi

    if [[ -z "$new_method" ]]; then
        echo ""
        echo "  Scope '${scope}' auth-method: ${current:-not set}"
        echo "  Source: ${source}"
        if [[ -z "$current" ]]; then
            echo "  In effect: $(_scope_protocol_in_effect "$scope")"
        fi
        echo ""
        echo "    Used when the command names no protocol: 'tacctl config cisco|juniper|wti' without"
        echo "    --protocol, 'tacctl host enroll' (a host not yet registered) and"
        echo "    'tacctl config linux script' without --method. Without it: the scope's only"
        echo "    protocol when 'tacctl scope protocols' names exactly one, else tacacs for device"
        echo "    configs and 'tacctl host default-method' for hosts."
        echo ""
        echo "  Usage: tacctl scope auth-method ${scope} <tacacs|radius|clear>"
        echo ""
        return
    fi

    case "$new_method" in
        tacplus) new_method="tacacs" ;;
        tacacs|radius) ;;
        clear|default)
            if [[ -z "$(conf_get "scope_auth_method.${scope}")" ]]; then
                info "Scope '${scope}' has no auth-method set; no change."
                echo ""
                return
            fi
            conf_unset "scope_auth_method.${scope}" || exit 1
            info "Scope '${scope}' auth-method cleared (in effect: $(_scope_protocol_in_effect "$scope"))."
            echo ""
            return
            ;;
        *)
            error "Unknown auth-method '${new_method}'. Use tacacs, radius or clear."
            exit 1
            ;;
    esac

    # A protocols filter that leaves the method out means the backend for it
    # ignores the scope: every config made from this default would not work.
    local protocols
    protocols=$(model_scope "$scope" protocols | awk 'NF' | paste -sd, || true)
    if [[ -n "$protocols" && ",${protocols}," != *",${new_method},"* ]]; then
        error "Scope '${scope}' is limited to ${protocols} (tacctl scope protocols), so it is not served over ${new_method}."
        error "Serve it over ${new_method} first: tacctl scope protocols ${scope} set ${protocols},${new_method}   (or 'clear' for every protocol)"
        exit 1
    fi

    if [[ "$new_method" == "$current" ]]; then
        info "Scope '${scope}' auth-method already ${new_method}; no change."
        echo ""
        return
    fi
    conf_set "scope_auth_method.${scope}" "$new_method" || exit 1
    info "Scope '${scope}' auth-method set to ${new_method}."
    if _backends_load 2> /dev/null && ! _backend_is_enabled "$new_method"; then
        warn "The ${new_method} backend is not enabled on this server: tacctl backend enable ${new_method}"
    fi
    echo ""
    echo "  'tacctl config cisco|juniper|wti --scope ${scope}' and new 'tacctl host enroll --scope ${scope}'"
    echo "  now use ${new_method} unless told otherwise. Devices and hosts already configured are not"
    echo "  changed: push the new device config, or re-enroll a host with --method, to switch them."
    echo ""
}

# --- Per-scope mgmt-ACL: tacctl scope mgmt-acl <scope> <sub> [args] ---
# Subcommand shape mirrors the global `tacctl config mgmt-acl` so
# operators who know one form immediately know the other:
#   list | add <cidrs> | remove <cidrs> | clear   → permit CIDR list
#   cisco-name   [label]                          → Cisco VTY-ACL name
#   juniper-name [label]                          → Junos filter name
#
# Permit list fallback chain at render time is per-scope -> global
# (mgmt_acl.permits) -> empty. An explicit empty per-scope list
# prunes the override so the scope falls back through the chain.
# Name fallback chain is per-scope -> global (mgmt_acl.names.*) ->
# shipped default (VTY-ACL / MGMT-ACL).
cmd_scope_mgmt_acl() {
    local scope="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope mgmt-acl <scope> <list|add|remove|clear|cisco-name|juniper-name> [args]"
        exit 1
    fi
    _scope_require "$scope" || exit 1

    case "$sub" in
        ""|-h|--help|help)
            local n_scope n_global
            n_scope=$(read_mgmt_acl_cidrs "$scope" | awk 'NF' | wc -l)
            n_global=$(read_mgmt_acl_cidrs          | awk 'NF' | wc -l)
            echo ""
            echo -e "${BOLD}tacctl scope mgmt-acl ${scope}${NC} — per-scope Cisco VTY-ACL + Juniper lo0-filter"
            echo ""
            echo "Usage:"
            echo "  tacctl scope mgmt-acl ${scope} list                          Show effective permits for this scope"
            echo "  tacctl scope mgmt-acl ${scope} add    <cidr>[,<cidr>...]     Add one or more CIDRs to the per-scope list"
            echo "  tacctl scope mgmt-acl ${scope} remove <cidr>[,<cidr>...]     Remove one or more CIDRs from the per-scope list"
            echo "  tacctl scope mgmt-acl ${scope} clear                         Wipe the per-scope list (confirms; render falls back to global)"
            echo "  tacctl scope mgmt-acl ${scope} cisco-name   [label]          Per-scope Cisco VTY-ACL name"
            echo "  tacctl scope mgmt-acl ${scope} juniper-name [label]          Per-scope Junos filter name"
            echo ""
            echo "Current entries: ${n_scope} (per-scope) / ${n_global} (global fallback)"
            echo ""
            return
            ;;
        list)
            local scope_entries global_entries
            scope_entries=$(conf_get_list "scope_mgmt_acl.permits.${scope}")
            global_entries=$(conf_get_list mgmt_acl.permits)
            echo ""
            echo -e "${BOLD}Management ACL for scope '${scope}'${NC}"
            echo "--------------------------------------------"
            if [[ -n "$scope_entries" ]]; then
                echo "  Source: per-scope override (scope_mgmt_acl.permits.${scope})"
                echo "$scope_entries" | while IFS= read -r e; do
                    [[ -z "$e" ]] && continue
                    echo "  - ${e}"
                done
            elif [[ -n "$global_entries" ]]; then
                echo "  Source: global (mgmt_acl.permits) — per-scope list is empty"
                echo "$global_entries" | while IFS= read -r e; do
                    [[ -z "$e" ]] && continue
                    echo "  - ${e}"
                done
            else
                echo "  (empty — both per-scope and global lists are unset)"
                echo ""
                echo "  Add to this scope only:  tacctl scope mgmt-acl ${scope} add <cidr>"
                echo "  Add to the global list:  tacctl config mgmt-acl add <cidr>"
            fi
            echo ""
            ;;
        add)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope mgmt-acl ${scope} add <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested added="" skipped=""
            requested=$(parse_cidr_list "$arg")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(conf_get_list "scope_mgmt_acl.permits.${scope}")
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
                info "No new CIDRs to add to scope '${scope}' (already present: ${skipped})."
                echo ""
                return
            fi
            write_mgmt_acl_cidrs "$current" "$scope"
            local n
            n=$(printf '%s\n' "$added" | wc -l)
            info "Added ${n} to scope '${scope}' mgmt-acl: $(printf '%s\n' "$added" | paste -sd' ')"
            [[ -n "$skipped" ]] && info "(Already present, unchanged: ${skipped})"
            info "Re-run 'tacctl config cisco --scope ${scope}' / 'tacctl config juniper --scope ${scope}' to see the new output."
            echo ""
            ;;
        remove)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope mgmt-acl ${scope} remove <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested removed="" missing=""
            requested=$(parse_cidr_list "$arg")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(conf_get_list "scope_mgmt_acl.permits.${scope}")
            if [[ -z "$current" ]]; then
                warn "Nothing to remove — scope '${scope}' has no per-scope permits (rendering from the global list)."
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
                warn "Nothing to remove (not present in per-scope list: ${missing})."
                exit 0
            fi
            write_mgmt_acl_cidrs "$current" "$scope"
            local n
            n=$(printf '%s\n' "$removed" | wc -l)
            info "Removed ${n} from scope '${scope}' mgmt-acl: $(printf '%s\n' "$removed" | paste -sd' ')"
            [[ -n "$missing" ]] && info "(Not present, skipped: ${missing})"
            echo ""
            ;;
        clear)
            local current
            current=$(conf_get_list "scope_mgmt_acl.permits.${scope}")
            if [[ -z "$current" ]]; then
                info "Per-scope list for '${scope}' is already empty (render falls back to global)."
                echo ""
                return
            fi
            read -rp "  Clear all per-scope mgmt-acl entries for '${scope}'? Render will fall back to global. [y/N]: " confirm || true
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            conf_unset "scope_mgmt_acl.permits.${scope}"
            info "Per-scope mgmt-acl cleared for '${scope}'."
            echo ""
            ;;
        cisco-name|juniper-name)
            local vendor="${sub%-name}"
            local new_name="$arg"
            local current source effective
            current=$(conf_get "scope_mgmt_acl.names.${vendor}.${scope}")
            effective=$(read_mgmt_acl_name "$vendor" "$scope")
            if [[ -z "$current" ]]; then
                local global_val shipped
                case "$vendor" in
                    cisco)   global_val=$(conf_get mgmt_acl.names.cisco   "$CISCO_ACL_NAME_DEFAULT");   shipped="$CISCO_ACL_NAME_DEFAULT" ;;
                    juniper) global_val=$(conf_get mgmt_acl.names.juniper "$JUNIPER_ACL_NAME_DEFAULT"); shipped="$JUNIPER_ACL_NAME_DEFAULT" ;;
                esac
                if [[ "$global_val" == "$shipped" ]]; then
                    source="default"
                else
                    source="global (tacctl config mgmt-acl ${vendor}-name)"
                fi
            else
                source="override (tacctl.yaml: scope_mgmt_acl.names.${vendor}.${scope})"
            fi

            if [[ -z "$new_name" ]]; then
                echo ""
                echo "  Scope '${scope}' ${vendor} mgmt-acl name: ${effective}"
                echo "  Source: ${source}"
                echo ""
                echo "    Rendered into ${vendor} device configs for this scope only."
                echo "    Clear the per-scope override by setting it to the global value."
                echo ""
                echo "  Usage: tacctl scope mgmt-acl ${scope} ${sub} <name>"
                echo ""
                return
            fi

            conf_set "scope_mgmt_acl.names.${vendor}.${scope}" "$new_name" || exit 1
            info "Scope '${scope}' ${vendor} mgmt-acl name set to ${new_name}."
            echo ""
            echo "  Re-run 'tacctl config ${vendor} --scope ${scope}' and push the updated"
            echo "  ACL / filter block to each device in this scope. A stale ACL name on"
            echo "  the device will still reference the old filter until replaced."
            echo ""
            ;;
        *)
            error "Unknown subcommand '${sub}'. Use: list | add | remove | clear | cisco-name | juniper-name."
            exit 1
            ;;
    esac
}

