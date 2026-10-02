# shellcheck shell=bash
# tacctl lib/groups.sh -- config show, group commands
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.
#
# Groups live in the store ({priv_lvl, juniper_class}); their command rules
# and priv-exec mappings live in tacctl.yaml. Reads go through the model,
# writes through store_apply, which re-renders tacquito.yaml.

# =====================================================================
#  CONFIG COMMANDS
# =====================================================================

# --- CONFIG SHOW ---
cmd_config_show() {
    echo ""
    echo -e "${BOLD}Tacquito Configuration${NC}"
    echo "--------------------------------------------"

    # One model view carries everything below: 'scope=<name>|<secret
    # length>|<users>' followed by its 'prefix=<cidr>' lines, the built-in
    # groups' priv-lvl and Juniper class, and the two connection filters.
    local view
    view=$(_model_view config-show) || exit 1
    local -A cs=()
    local key value
    while IFS='=' read -r key value; do
        case "$key" in
            scope|prefix|"") ;;
            *) cs[$key]="$value" ;;
        esac
    done <<< "$view"

    # Scopes — one block per scope showing its secret length + prefixes.
    local default_scope
    default_scope=$(read_default_scope)
    echo ""
    echo -e "  ${BOLD}Scopes:${NC}"
    if ! grep -q '^scope=' <<< "$view"; then
        echo -e "    ${RED}(none configured)${NC}"
    else
        # A scope's prefix lines follow its scope line; the "(empty)" note
        # is printed when the next scope (or the end) arrives without any.
        local scope s_len n_users marker pending=""
        while IFS='=' read -r key value; do
            case "$key" in
                scope)
                    [[ -n "$pending" ]] && echo -e "        ${RED}(empty — no clients can auth against this scope)${NC}"
                    IFS='|' read -r scope s_len n_users <<< "$value"
                    marker=""
                    [[ "$scope" == "$default_scope" ]] && marker="  ${CYAN}(default)${NC}"
                    echo -e "    ${BOLD}${scope}${NC}${marker}"
                    echo -e "      Secret:             ${s_len} chars"
                    echo -e "      Users:              ${n_users}"
                    echo -e "      Prefixes:"
                    pending=1
                    ;;
                prefix)
                    echo "        - ${value}"
                    pending=""
                    ;;
            esac
        done <<< "$view"
        [[ -n "$pending" ]] && echo -e "        ${RED}(empty — no clients can auth against this scope)${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}Cisco (priv-lvl):${NC}"
    echo -e "    Super-user:         ${cs[cisco_rw]}"
    echo -e "    Operator:           ${cs[cisco_op]}"
    echo -e "    Read-only:          ${cs[cisco_ro]}"
    echo ""
    echo -e "  ${BOLD}Juniper (local-user-name):${NC}"
    echo -e "    Super-user class:   ${cs[juniper_rw]}"
    echo -e "    Operator class:     ${cs[juniper_op]}"
    echo -e "    Read-only class:    ${cs[juniper_ro]}"

    # Global mgmt-ACL names. Per-scope overrides land in the
    # `tacctl scope show <name>` summary — surfacing both here would
    # double up on every scope. The global values are what new
    # scopes inherit by default.
    local cisco_acl_name juniper_acl_name
    cisco_acl_name=$(read_mgmt_acl_name cisco)
    juniper_acl_name=$(read_mgmt_acl_name juniper)
    echo ""
    echo -e "  ${BOLD}Management ACL names (global defaults):${NC}"
    echo -e "    Cisco ACL:          ${cisco_acl_name}"
    echo -e "    Juniper filter:     ${juniper_acl_name}"

    echo ""
    echo -e "  ${BOLD}Connection Filters:${NC} ${CYAN}(deny takes precedence over allow)${NC}"
    if [[ -n "${cs[deny]}" ]]; then
        echo -e "    Deny:               ${cs[deny]}"
    else
        echo -e "    Deny:               ${CYAN}(none)${NC}"
    fi
    if [[ -n "${cs[allow]}" ]]; then
        echo -e "    Allow:              ${cs[allow]}"
    else
        echo -e "    Allow:              ${CYAN}(all)${NC}"
    fi

    # What each enabled backend serves: its rendered config, its service and
    # the listeners it should have, probed where the listener model says
    # (tcp or udp, the port of the listener -- not 49). With one backend these
    # are plain lines; with more, each has a labelled block.
    _backends_load || return 1
    local _b multi=0 ind="" artifact state lname lnet laddr _rest bound label pad
    (( ${#BACKENDS_ENABLED[@]} > 1 )) && multi=1
    for _b in "${BACKENDS_ENABLED[@]}"; do
        echo ""
        if (( multi )); then
            echo -e "  ${BOLD}Backend: ${_b}${NC}"
            ind="  "
        fi
        artifact=$(backend_call "$_b" artifacts | head -n 1 || true)
        echo -e "${ind}  ${BOLD}Config file:${NC}          ${artifact}"
        # is-active prints the state and fails for anything but 'active'.
        state=$(backend_call "$_b" service is-active) || true
        echo -e "${ind}  ${BOLD}Service status:${NC}       ${state:-unknown}"
        while read -r lname lnet laddr _rest; do
            [[ -n "$lname" ]] || continue
            if [[ "$lname" == "default" ]]; then
                label="Listening on:"
                pad="         "
            else
                label="Listening on (${lname}):"
                pad=" "
            fi
            bound=$(backend_listener_probe "$lnet" "$laddr")
            if [[ -n "$bound" ]]; then
                echo -e "${ind}  ${BOLD}${label}${NC}${pad}${bound}"
            else
                echo -e "${ind}  ${BOLD}${label}${NC}${pad}${RED}port ${laddr##*:} not detected${NC}"
            fi
        done < <(backend_call "$_b" listeners list)
    done
    echo ""
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

    # Highest priv-lvl first. The user count leaves out the accounting sink
    # so it matches what 'tacctl user list' shows.
    local rows name priv jclass user_count
    rows=$(model_group_rows) || exit 1
    while IFS='|' read -r name priv jclass user_count; do
        [[ -z "$name" ]] && continue
        printf "  %-20s %-15s %-20s %-10s\n" "$name" "$priv" "$jclass" "$user_count"
    done <<< "$rows"

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
    store_require || exit 1

    # Validate group name
    if [[ ! "$groupname" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        error "Group name must be lowercase, starting with a letter."
        exit 1
    fi

    # Check if group already exists
    if model_group_exists "$groupname"; then
        error "Group '${groupname}' already exists."
        exit 1
    fi

    # Validate priv-lvl
    if ! [[ "$privlvl" =~ ^[0-9]+$ ]] || [[ "$privlvl" -lt 0 || "$privlvl" -gt 15 ]]; then
        error "Cisco privilege level must be 0-15."
        exit 1
    fi

    validate_class_name "$jclass"

    store_apply store_group_set "$groupname" "priv_lvl=${privlvl}" "juniper_class=${jclass}" || exit $?

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
    store_require || exit 1

    # Protect built-in groups
    if [[ "$groupname" == "readonly" || "$groupname" == "operator" || "$groupname" == "superuser" ]]; then
        error "Cannot remove built-in group '${groupname}'."
        exit 1
    fi

    # Check if group exists
    if ! model_group_exists "$groupname"; then
        error "Group '${groupname}' does not exist."
        exit 1
    fi

    # Check if any users are assigned to this group
    local user_count
    user_count=$(model_group_users "$groupname" | wc -l) || exit 1
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

    store_apply store_group_del "$groupname" || exit $?

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
    store_require || exit 1

    # Check if group exists
    if ! model_group_exists "$groupname"; then
        error "Group '${groupname}' does not exist."
        exit 1
    fi

    case "$field" in
        priv-lvl)
            if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 0 || "$value" -gt 15 ]]; then
                error "Cisco privilege level must be 0-15."
                exit 1
            fi
            store_apply store_group_set "$groupname" "priv_lvl=${value}" || exit $?
            info "Group '${groupname}' Cisco priv-lvl changed to ${value}."
            ;;

        juniper-class)
            validate_class_name "$value"
            store_apply store_group_set "$groupname" "juniper_class=${value}" || exit $?
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

# --- GROUP COMMANDS (per-group authorized command rules) ---
# Drives Cisco TACACS+ command authorization (live; enforced by tacquito)
# and Juniper class allow/deny-commands (local enforcement on each device,
# requires per-device push).
#
# Source of truth: commands.<group> in tacctl.yaml, layered over shipped
# defaults in conf_emit_defaults(). tacquito.yaml's per-group commands:
# block is rendered from it with the rest of the file; every mutation below
# writes tacctl.yaml and re-renders inside one store_apply.
#
# Rule shape: list of dicts {name, action: permit|deny, match?: [regex]}.
# A trailing `name: "*"` rule's action is the group's default. Tacquito
# returns FAIL for any rule that doesn't match, so the catchall is the
# sole way to express "permit everything not explicitly denied."
#
# Safety: when ANY group has rules, every other group at the same Cisco
# priv-lvl is auto-seeded with a catchall permit. Without this, Cisco's
# `aaa authorization commands <level>` would route ALL command authz at
# that level through tacquito and users in the unseeded group would be
# denied every command.
cmd_group_commands() {
    local subcmd="${1:-}"
    shift 2>/dev/null || true

    case "$subcmd" in
        ""|-h|--help|help)
            cmd_group_commands_usage
            return
            ;;
        seed)
            cmd_group_commands_seed "$@"
            return
            ;;
        list|default|add|remove|clear)
            ;;
        *)
            error "Unknown subcommand: '${subcmd}'"
            cmd_group_commands_usage
            exit 1
            ;;
    esac

    local group="${1:-}"
    shift 2>/dev/null || true

    if [[ -z "$group" ]]; then
        error "Usage: tacctl group commands ${subcmd} <group> ..."
        exit 1
    fi
    case "$subcmd" in
        default|add|remove|clear) store_require || exit 1 ;;
    esac
    if ! model_group_exists "$group"; then
        error "Group '${group}' does not exist."
        exit 1
    fi

    case "$subcmd" in
        list)
            local rules default_action
            rules=$(read_group_commands "$group")
            default_action=$(read_group_default_action "$group")
            echo ""
            echo -e "${BOLD}Command rules for group '${group}'${NC}"
            echo "--------------------------------------------"
            echo -e "  Default action: ${BOLD}${default_action}${NC}"
            echo ""
            if [[ -z "$rules" ]]; then
                echo "  (no commands — custom group with no rules; all commands permitted)"
                echo ""
                return
            fi
            printf "  ${BOLD}%-20s %-8s %s${NC}\n" "NAME" "ACTION" "MATCH"
            echo "  -------------------------------------------------"
            local catchall_seen="false"
            while IFS='|' read -r name action match; do
                [[ -z "$name" ]] && continue
                local color="$GREEN"
                [[ "$action" == "deny" ]] && color="$RED"
                if [[ "$name" == "*" ]]; then
                    catchall_seen="true"
                    printf "  %-20s ${color}%-8s${NC} %s\n" "$name (catchall)" "$action" "$match"
                else
                    printf "  %-20s ${color}%-8s${NC} %s\n" "$name" "$action" "$match"
                fi
            done <<< "$rules"
            if [[ "$catchall_seen" == "false" ]]; then
                warn "No '*' catchall — tacquito will FAIL any unmatched command."
                warn "Set the default explicitly with 'tacctl group commands default ${group} permit|deny'."
            fi
            echo ""
            ;;
        default)
            local new_default="${1:-}"
            if [[ "$new_default" != "permit" && "$new_default" != "deny" ]]; then
                error "Usage: tacctl group commands default <group> <permit|deny>"
                exit 1
            fi
            store_apply _group_commands_write default "$group" "$new_default" || exit $?
            info "Group '${group}' default action set to ${new_default}."
            echo ""
            ;;
        add)
            local name="${1:-}"
            shift 2>/dev/null || true
            if [[ -z "$name" ]]; then
                error "Usage: tacctl group commands add <group> <name> [--match <regex>]... [--action permit|deny]"
                exit 1
            fi
            validate_command_name "$name"
            if [[ "$name" == "*" ]]; then
                error "Use 'tacctl group commands default ${group} permit|deny' to change the catchall."
                exit 1
            fi
            local action="permit"
            local matches=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --match)
                        validate_regex "${2:-}"
                        if command_match_is_dead "$name" "${2:-}"; then
                            error "--match '${2}' can never match for rule '${name}'."
                            error "tacquito tests --match against the command's ARGUMENTS only (the"
                            error "cmd-arg values after '${name}', e.g. 'running-config' for"
                            error "'${name} running-config'), never the full command line."
                            error "Omit --match to cover any arguments, or match the args alone"
                            error "(e.g. --match 'running-config')."
                            exit 1
                        fi
                        matches+="${matches:+,}${2}"
                        shift 2
                        ;;
                    --action)
                        action="${2:-}"
                        if [[ "$action" != "permit" && "$action" != "deny" ]]; then
                            error "--action must be 'permit' or 'deny'."
                            exit 1
                        fi
                        shift 2
                        ;;
                    *)
                        error "Unknown flag: '$1'"
                        exit 1
                        ;;
                esac
            done

            # Reject duplicate (name, match) — same name with same match
            # set is a no-op. Same name with different matches is fine.
            local existing
            existing=$(read_group_commands "$group" | grep "^${name}|" || true)
            if [[ -n "$existing" ]]; then
                while IFS='|' read -r en _ em; do
                    [[ "$en" == "$name" && "$em" == "$matches" ]] && {
                        info "Rule '${name}' (match='${matches}') already present; no change."
                        echo ""
                        return
                    }
                done <<< "$existing"
            fi

            store_apply _group_commands_write add "$group" "$name" "$action" "$matches" || exit $?
            info "Added rule '${name}' (action=${action}, match=[${matches}]) to group '${group}'."
            echo ""
            ;;
        remove)
            local name="${1:-}"
            if [[ -z "$name" ]]; then
                error "Usage: tacctl group commands remove <group> <name>"
                exit 1
            fi
            if [[ "$name" == "*" ]]; then
                error "Cannot remove the '*' catchall. Use 'tacctl group commands default' to change its action,"
                error "or 'tacctl group commands clear ${group}' to revert this group to shipped defaults."
                exit 1
            fi
            if ! read_group_commands "$group" | grep -q "^${name}|"; then
                warn "No rule named '${name}' in group '${group}'."
                exit 0
            fi
            store_apply remove_command_rule "$group" "$name" || exit $?
            info "Removed rule '${name}' from group '${group}'."
            echo ""
            ;;
        clear)
            if [[ -z "$(read_group_commands "$group")" ]]; then
                info "Group '${group}' has no command rules; nothing to clear."
                exit 0
            fi
            read -rp "  Clear all command rules for group '${group}'? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            store_apply write_group_commands "$group" "" || exit $?
            info "Cleared command rules for group '${group}' (reverted to shipped defaults)."
            warn "For a custom group, this leaves the group with no rules — if other groups"
            warn "at the same Cisco priv-lvl still have rules, Cisco will deny ALL commands to"
            warn "'${group}' users at that level until you re-add a catchall"
            warn "('tacctl group commands default ${group} permit') or clear the siblings too."
            echo ""
            ;;
    esac
}

# Writer for store_apply: the tacctl.yaml edits of 'commands default' and
# 'commands add', siblings seeded first.
_group_commands_write() {
    local verb="$1" group="$2"
    shift 2
    seed_command_rules_safely "$group" || return 1
    case "$verb" in
        default) update_group_catchall "$group" "$1" ;;
        add)     insert_command_rule "$group" "$1" "$2" "$3" ;;
    esac
}

cmd_group_commands_usage() {
    echo ""
    echo -e "${BOLD}tacctl group commands${NC} — per-group authorized commands"
    echo ""
    echo "Usage:"
    echo "  tacctl group commands list <group>                              Show rules + default action"
    echo "  tacctl group commands default <group> <permit|deny>             Set default action (catchall)"
    echo "  tacctl group commands add <group> <name> [--match <regex>]...   Add a rule"
    echo "                                            [--action permit|deny]"
    echo "  tacctl group commands remove <group> <name>                     Drop a rule"
    echo "  tacctl group commands clear <group>                             Drop overrides — revert to shipped defaults (confirms)"
    echo "  tacctl group commands seed [<group>] [--force]                  Re-apply legacy seed set (recovery tool)"
    echo ""
    echo "<name> is compared literally to the TACACS+ cmd= word. --match"
    echo "regexes are tested against the command's ARGUMENTS only (the"
    echo "cmd-arg values after the word: 'running-config' for 'show"
    echo "running-config'), never the full line -- so '^show .*$' can"
    echo "never match and is rejected. Omit --match to cover any args."
    echo ""
    echo "Rules live under commands.<group> in /etc/tacquito/tacctl.yaml;"
    echo "tacquito.yaml's per-group commands: block is a regenerated"
    echo "artifact (do not hand-edit). Built-ins ship with defaults:"
    echo "   superuser: permit *   |   operator: show/ping/traceroute/"
    echo "                              terminal + deny *   |   readonly:"
    echo "                              show/ping/traceroute + deny *"
    echo ""
    echo "Cisco devices ask tacquito per command (live enforcement) when"
    echo "'aaa authorization commands <level>' is in the device config —"
    echo "tacctl auto-emits these lines in 'tacctl config cisco'. Juniper"
    echo "enforcement is LOCAL via class allow/deny-commands, rendered"
    echo "from the same tacctl-authored rules by 'tacctl config juniper'."
    echo ""
}

# --- Default rule sets per built-in group ---
# Returns "default_action|space-separated-permit-names" for the group.
# Unknown groups return empty (the caller treats that as "no defaults").
default_rules_for_group() {
    local group="$1"
    case "$group" in
        readonly)
            echo "deny|show ping traceroute terminal exit end quit logout who where enable"
            ;;
        operator)
            echo "deny|show ping traceroute terminal exit end quit logout who where enable clear test monitor"
            ;;
        superuser)
            # No specific rules; catchall permit gives unrestricted access.
            echo "permit|"
            ;;
        *)
            echo ""
            ;;
    esac
}

# --- Apply the default rule set to one group (unconditional write) ---
apply_default_rules() {
    local group="$1"
    local spec
    spec=$(default_rules_for_group "$group")
    [[ -z "$spec" ]] && return 1
    local default_action="${spec%%|*}"
    local permit_list="${spec#*|}"
    local payload=""
    for cmd in $permit_list; do
        payload+="${cmd}|permit|"$'\n'
    done
    payload+="*|${default_action}|"
    write_group_commands "$group" "$payload"
}

# --- Seed built-in groups with reasonable default command rules ---
# Usage: tacctl group commands seed [<group>] [--force]
# - No group: seeds all three built-ins (readonly, operator, superuser).
# - With group: seeds only that group (must be a built-in).
# - Refuses to overwrite a group that already has rules unless --force.
cmd_group_commands_seed() {
    local force="false"
    local target=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force)
                force="true"
                shift
                ;;
            -*)
                error "Unknown flag: '$1'"
                cmd_group_commands_usage
                exit 1
                ;;
            *)
                if [[ -n "$target" ]]; then
                    error "seed takes at most one group name; got extra '$1'"
                    exit 1
                fi
                target="$1"
                shift
                ;;
        esac
    done

    local candidates=""
    if [[ -n "$target" ]]; then
        if [[ -z "$(default_rules_for_group "$target")" ]]; then
            error "seed only supports the built-in groups (readonly, operator, superuser)."
            error "Got '${target}'. Custom groups must be configured with 'tacctl group commands add'."
            exit 1
        fi
        candidates="$target"
    else
        candidates="readonly operator superuser"
    fi

    store_require || exit 1
    # shellcheck disable=SC2086  # candidates is a space-separated list of built-in names
    store_apply _group_commands_seed_write "$force" $candidates || exit $?
    local touched="$_GROUP_SEED_TOUCHED" skipped="$_GROUP_SEED_SKIPPED"

    if [[ -n "$touched" ]]; then
        info "Seeded default command rules for:${touched}"
        echo ""
        echo "  Review with:"
        for grp in $touched; do
            echo "    tacctl group commands list ${grp}"
        done
        echo ""
        echo "  Preview the device config with:"
        echo "    tacctl config cisco"
        echo "    tacctl config juniper"
        echo ""
    else
        info "No groups seeded."
        if [[ -n "$skipped" ]]; then
            info "(Skipped:${skipped}. Pass --force to overwrite.)"
        fi
        echo ""
    fi
}

# Writer for store_apply: seed each candidate group, recording which were
# written and which were skipped for the caller's summary.
_GROUP_SEED_TOUCHED=""
_GROUP_SEED_SKIPPED=""
_group_commands_seed_write() {
    local force="$1" grp
    shift
    _GROUP_SEED_TOUCHED=""
    _GROUP_SEED_SKIPPED=""
    for grp in "$@"; do
        if ! model_group_exists "$grp"; then
            warn "Group '${grp}' does not exist in config; skipping."
            continue
        fi
        if [[ -n "$(read_group_commands "$grp")" ]] && [[ "$force" != "true" ]]; then
            warn "Group '${grp}' already has command rules; skipping (pass --force to overwrite)."
            _GROUP_SEED_SKIPPED+=" ${grp}"
            continue
        fi
        # Protect siblings before writing rules to this group — if any
        # other priv-lvl sibling lacks command rules, seed it with the
        # permit-* catchall to avoid lockout once Cisco emits
        # 'aaa authorization commands <level>'.
        seed_command_rules_safely "$grp" || return 1
        apply_default_rules "$grp" || return 1
        _GROUP_SEED_TOUCHED+=" ${grp}"
    done
    return 0
}

# --- Compute and apply the group's catchall ('*' rule) action ---
update_group_catchall() {
    local group="$1"
    local action="$2"
    # Read current rules, strip any existing catchall, append the new one.
    local current cleaned
    current=$(read_group_commands "$group")
    cleaned=$(printf '%s\n' "$current" | awk -F'|' '$1 != "*" { print }')
    local payload
    payload=$(printf '%s\n*|%s|' "$cleaned" "$action" | awk 'NF')
    write_group_commands "$group" "$payload"
}

# --- Insert a new rule (before the catchall) ---
insert_command_rule() {
    local group="$1" name="$2" action="$3" matches="$4"
    local current default catchall non_catchall payload
    current=$(read_group_commands "$group")
    default=$(read_group_default_action "$group")
    catchall="*|${default}|"
    non_catchall=$(printf '%s\n' "$current" | awk -F'|' '$1 != "*" { print }')
    if [[ -n "$non_catchall" ]]; then
        payload=$(printf '%s\n%s|%s|%s\n%s\n' "$non_catchall" "$name" "$action" "$matches" "$catchall" | awk 'NF')
    else
        payload=$(printf '%s|%s|%s\n%s\n' "$name" "$action" "$matches" "$catchall" | awk 'NF')
    fi
    write_group_commands "$group" "$payload"
}

# --- Remove a rule by name (preserves catchall) ---
remove_command_rule() {
    local group="$1" name="$2"
    local current payload
    current=$(read_group_commands "$group")
    payload=$(printf '%s\n' "$current" | awk -F'|' -v n="$name" '$1 != n { print }')
    write_group_commands "$group" "$payload"
}

# --- Seed catchall-permit rules on sibling groups at the same priv-lvl ---
# When this group is about to gain its first commands: block, ensure
# every other group at the same Cisco priv-lvl ALSO has a (permit *)
# catchall — otherwise, the moment 'aaa authorization commands <level>'
# is in the device config, those siblings' users get denied everything.
#
# Safe to call repeatedly: groups that already have a commands: block
# are left alone.
seed_command_rules_safely() {
    local group="$1"
    local info_rows privlvl="" other other_priv _class
    info_rows=$(model_group_info) || return 1
    while IFS='|' read -r other other_priv _class; do
        [[ "$other" == "$group" ]] && privlvl="$other_priv"
    done <<< "$info_rows"
    [[ -z "$privlvl" ]] && return 0
    local seeded=""
    while IFS='|' read -r other other_priv _class; do
        [[ -z "$other" ]] && continue
        [[ "$other" == "$group" ]] && continue
        [[ "$other_priv" != "$privlvl" ]] && continue
        # Already has command rules? Skip.
        if [[ -n "$(read_group_commands "$other")" ]]; then
            continue
        fi
        write_group_commands "$other" "*|permit|" || return 1
        seeded+=" ${other}"
    done <<< "$info_rows"
    if [[ -n "$seeded" ]]; then
        info "Auto-seeded permit-* catchall on sibling groups at priv-lvl ${privlvl}:${seeded}"
        info "(prevents lockout once Cisco 'aaa authorization commands ${privlvl}' is applied.)"
    fi
}

# --- GROUP PRIVILEGE (Cisco priv-exec command mappings) ---
# Controls which IOS commands move to a group's priv-lvl via
# 'privilege exec level <N> <command>' lines emitted by
# 'tacctl config cisco'. Pure device-side config; tacquito itself
# doesn't read this data.
#
# Source of truth: privileges.<group> in /etc/tacquito/tacctl.yaml,
# layered over the shipped defaults in conf_emit_defaults() (only the
# verified move-DOWN commands; nothing inadvertently restricted from
# lower-priv groups). When no override exists, the merged view equals
# the shipped defaults.
cmd_group_privilege() {
    local subcmd="${1:-}"
    shift 2>/dev/null || true

    case "$subcmd" in
        ""|-h|--help|help)
            cmd_group_privilege_usage
            return
            ;;
        seed)
            cmd_group_privilege_seed "$@"
            return
            ;;
        list|add|remove|clear)
            ;;
        *)
            error "Unknown subcommand: '${subcmd}'"
            cmd_group_privilege_usage
            exit 1
            ;;
    esac

    local group="${1:-}"
    shift 2>/dev/null || true
    if [[ -z "$group" ]]; then
        error "Usage: tacctl group privilege ${subcmd} <group> ..."
        exit 1
    fi
    local privlvl
    if ! privlvl=$(model_group "$group" priv_lvl); then
        error "Group '${group}' does not exist."
        exit 1
    fi
    if [[ -z "$privlvl" ]]; then
        error "Group '${group}' has no Cisco priv-lvl; nothing to map."
        exit 1
    fi

    case "$subcmd" in
        list)
            local merged
            merged=$(read_group_privileges "$group")
            echo ""
            echo -e "${BOLD}Cisco priv-exec mappings for group '${group}' (priv-lvl ${privlvl})${NC}"
            echo "--------------------------------------------"
            if [[ -z "$merged" ]]; then
                echo "  (no mappings — group's priv-lvl uses Cisco defaults)"
            elif conf_has_override "privileges.${group}"; then
                echo -e "  Source: ${BOLD}explicit${NC} (tacctl.yaml: privileges.${group})"
                echo ""
                echo "$merged" | while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    echo "  - ${c}"
                done
            else
                echo -e "  Source: ${BOLD}default${NC} (built-in safe defaults; override via 'tacctl group privilege add')"
                echo ""
                echo "$merged" | while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    echo "  - ${c}  (default)"
                done
            fi
            echo ""
            ;;
        add)
            local input="${1:-}"
            if [[ -z "$input" ]]; then
                error "Usage: tacctl group privilege add <group> '<command>'[,'<command>'...]"
                exit 1
            fi
            # Parse comma-separated list, validating each; abort whole op
            # if any are invalid. Cisco exec commands don't contain commas,
            # so the separator is unambiguous.
            local requested="" cmd
            IFS=',' read -ra CMDS <<< "$input"
            for cmd in "${CMDS[@]}"; do
                cmd=$(echo "$cmd" | xargs)
                [[ -z "$cmd" ]] && continue
                validate_priv_command_string "$cmd"
                requested+="${requested:+$'\n'}${cmd}"
            done
            [[ -z "$requested" ]] && { error "No commands provided."; exit 1; }

            local current added="" skipped=""
            current=$(read_group_privileges "$group")
            # If empty, seed from defaults so the user's first add doesn't
            # silently drop the conservative defaults.
            if [[ -z "$current" ]]; then
                current=$(default_privileges_for_group "$group")
            fi
            while IFS= read -r cmd; do
                [[ -z "$cmd" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$cmd"; then
                    skipped+="${skipped:+, }'${cmd}'"
                else
                    added+="${added:+$'\n'}${cmd}"
                    current=$(printf '%s\n%s\n' "$current" "$cmd")
                fi
            done <<< "$requested"

            if [[ -z "$added" ]]; then
                info "No new mappings to add for group '${group}' (already present: ${skipped})."
                echo ""
                return
            fi
            write_group_privileges "$group" "$current"
            local n
            n=$(printf '%s\n' "$added" | wc -l)
            info "Added ${n} priv-exec mapping(s) for group '${group}' (level ${privlvl}):"
            printf '%s\n' "$added" | sed "s/^/    - /"
            [[ -n "$skipped" ]] && info "(Already present, unchanged: ${skipped})"
            echo ""
            ;;
        remove)
            local input="${1:-}"
            if [[ -z "$input" ]]; then
                error "Usage: tacctl group privilege remove <group> '<command>'[,'<command>'...]"
                exit 1
            fi
            local requested="" cmd
            IFS=',' read -ra CMDS <<< "$input"
            for cmd in "${CMDS[@]}"; do
                cmd=$(echo "$cmd" | xargs)
                [[ -z "$cmd" ]] && continue
                requested+="${requested:+$'\n'}${cmd}"
            done
            [[ -z "$requested" ]] && { error "No commands provided."; exit 1; }

            local current removed="" missing=""
            current=$(read_group_privileges "$group")
            # If no explicit mappings exist, seed from defaults so the
            # remove takes effect against a known set.
            if [[ -z "$current" ]]; then
                current=$(default_privileges_for_group "$group")
            fi
            while IFS= read -r cmd; do
                [[ -z "$cmd" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$cmd"; then
                    removed+="${removed:+$'\n'}${cmd}"
                    current=$(printf '%s\n' "$current" | grep -vxF "$cmd" || true)
                else
                    missing+="${missing:+, }'${cmd}'"
                fi
            done <<< "$requested"

            if [[ -z "$removed" ]]; then
                warn "Nothing to remove for group '${group}' (not mapped: ${missing})."
                exit 0
            fi
            write_group_privileges "$group" "$current"
            local n
            n=$(printf '%s\n' "$removed" | wc -l)
            info "Removed ${n} priv-exec mapping(s) for group '${group}':"
            printf '%s\n' "$removed" | sed "s/^/    - /"
            [[ -n "$missing" ]] && info "(Not mapped, skipped: ${missing})"
            echo ""
            ;;
        clear)
            if [[ -z "$(read_group_privileges "$group")" ]]; then
                info "Group '${group}' has no explicit priv mappings; nothing to clear."
                exit 0
            fi
            read -rp "  Clear all priv-exec mappings for group '${group}'? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            write_group_privileges "$group" ""
            info "Cleared explicit priv-exec mappings for group '${group}' (defaults will be used)."
            echo ""
            ;;
    esac
}

cmd_group_privilege_usage() {
    echo ""
    echo -e "${BOLD}tacctl group privilege${NC} — per-group Cisco priv-exec command mappings"
    echo ""
    echo "Usage:"
    echo "  tacctl group privilege list <group>                              Show mappings (explicit or default)"
    echo "  tacctl group privilege add <group>    '<cmd>'[,'<cmd>'...]       Move one or more commands to the priv-lvl"
    echo "  tacctl group privilege remove <group> '<cmd>'[,'<cmd>'...]       Remove mapping(s)"
    echo "  tacctl group privilege clear <group>                             Wipe explicit mappings (revert to defaults)"
    echo "  tacctl group privilege seed [<group>] [--force]                  Populate built-ins with safe defaults"
    echo ""
    echo "Drives 'privilege exec level <lvl> <cmd>' lines emitted by"
    echo "'tacctl config cisco'. Pure device-side; tacquito does not read"
    echo "these. When no explicit mappings exist for a group, a conservative"
    echo "default set is used (only commands moved DOWN from priv 15)."
    echo ""
}

cmd_group_privilege_seed() {
    local force="false"
    local target=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force) force="true"; shift ;;
            -*)
                error "Unknown flag: '$1'"; cmd_group_privilege_usage; exit 1 ;;
            *)
                if [[ -n "$target" ]]; then
                    error "seed takes at most one group name; got extra '$1'"; exit 1
                fi
                target="$1"; shift ;;
        esac
    done

    local candidates=""
    if [[ -n "$target" ]]; then
        if [[ -z "$(default_privileges_for_group "$target")" && "$target" != "readonly" && "$target" != "operator" && "$target" != "superuser" ]]; then
            error "seed only supports the built-in groups (readonly, operator, superuser)."
            exit 1
        fi
        candidates="$target"
    else
        candidates="readonly operator superuser"
    fi

    local touched="" skipped=""
    for grp in $candidates; do
        if ! model_group_exists "$grp"; then
            warn "Group '${grp}' does not exist; skipping."
            continue
        fi
        if [[ -n "$(read_group_privileges "$grp")" ]] && [[ "$force" != "true" ]]; then
            warn "Group '${grp}' already has explicit priv mappings; skipping (pass --force to overwrite)."
            skipped+=" ${grp}"
            continue
        fi
        local defaults
        defaults=$(default_privileges_for_group "$grp")
        write_group_privileges "$grp" "$defaults"
        touched+=" ${grp}"
    done

    if [[ -n "$touched" ]]; then
        info "Seeded default priv-exec mappings for:${touched}"
        echo ""
        echo "  Review with:"
        for grp in $touched; do
            echo "    tacctl group privilege list ${grp}"
        done
        echo ""
        echo "  Preview Cisco device config:"
        echo "    tacctl config cisco"
        echo ""
    else
        info "No groups seeded."
        if [[ -n "$skipped" ]]; then
            info "(Skipped:${skipped}. Pass --force to overwrite.)"
        fi
        echo ""
    fi
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
        commands)
            cmd_group_commands "$@"
            ;;
        privilege)
            cmd_group_privilege "$@"
            ;;
        *)
            echo ""
            echo -e "${BOLD}Group Commands${NC}"
            echo ""
            echo "Usage: tacctl group <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                                                List all groups"
            echo "  add <name> <priv-lvl> <juniper-class>               Add a new group"
            echo "  edit <name> priv-lvl <0-15>                         Change Cisco privilege level"
            echo "  edit <name> juniper-class <CLASS>                   Change Juniper class name"
            echo "  remove <name>                                       Remove a custom group"
            echo "  commands list|default|add|remove|clear|seed <group> ...  Per-group authorized commands"
            echo "  privilege list|add|remove|clear|seed <group> ...         Per-group Cisco priv-exec mappings"
            echo ""
            echo "Examples:"
            echo "  tacctl group list"
            echo "  tacctl group add helpdesk 5 HELPDESK-CLASS"
            echo "  tacctl group edit operator priv-lvl 10"
            echo "  tacctl group edit operator juniper-class NEW-CLASS"
            echo "  tacctl group remove helpdesk"
            echo "  tacctl group commands default operator deny"
            echo "  tacctl group commands add operator show --action permit"
            echo "  tacctl group privilege list operator"
            echo "  tacctl group privilege add operator 'show running-config'"
            echo ""
            exit 1
            ;;
    esac
}

