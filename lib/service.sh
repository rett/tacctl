# shellcheck shell=bash
# tacctl lib/service.sh -- daemon control: restart, systemd drop-in, backups, status, validate, loglevel/listen/metrics, log
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# --- Restart service after config changes ---
# sed -i and python rewrites change the file inode, breaking fsnotify hot-reload.
restart_service() {
    if systemctl restart tacquito 2>/dev/null; then
        info "Service restarted."
    else
        warn "Service restart failed — run: sudo systemctl restart tacquito"
    fi
}

# Most recent login timestamp for a user, or "never". Parses the accounting
# log for JSON lines that pair "User":"<name>" with cmd=login (Flags:2 START).
# Session stops (cmd=logout / cmd=exit on Flags:4) are excluded.
get_last_login() {
    local username="$1"
    [[ -r "$ACCT_LOG" ]] || { echo "never"; return; }
    local ts
    ts=$(grep -F "\"User\":\"${username}\"" "$ACCT_LOG" 2>/dev/null \
        | grep -F 'cmd=login' \
        | tail -1 \
        | grep -oE '[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' \
        | head -1)
    if [[ -z "$ts" ]]; then
        echo "never"
    else
        echo "${ts//\//-}"
    fi
}

# --- Drift of rendered artifacts (plan 4.5) ---
# backends_check_drift: compare every artifact tacctl rendered with the
# sha256 recorded for it in rendered.json. Prints one '<status>\t<path>' line
# per artifact that is no longer what tacctl rendered -- status is 'drift'
# (edited by hand), 'missing' (deleted) or 'unreadable' (rendered.json itself
# cannot be read) -- and returns 1 when there is any. Returns 0, silently,
# when everything matches or nothing has been rendered yet.
# Temporary home: moves to lib/backend.sh with the backend contract.
backends_check_drift() {
    [[ -f "$RENDERED_FILE" ]] || return 0
    local out rc=0
    out=$(_render_python drift "$RENDERED_FILE" 2>/dev/null) || rc=$?
    (( rc == 0 )) && return 0
    if [[ -z "$out" ]]; then
        printf 'unreadable\t%s\n' "$RENDERED_FILE"
    else
        printf '%s\n' "$out"
    fi
    return 1
}

# Print the red DRIFT lines 'status' and 'config validate' show, one per
# drifted artifact. Returns 1 when it printed any.
print_drift_lines() {
    local drift dstatus dpath
    drift=$(backends_check_drift) && return 0
    while IFS=$'\t' read -r dstatus dpath; do
        [[ -n "$dpath" ]] || continue
        case "$dstatus" in
            drift)   dstatus="edited since tacctl rendered it" ;;
            missing) dstatus="rendered by tacctl but no longer there" ;;
            *)       dstatus="render records cannot be read" ;;
        esac
        echo -e "  ${RED}DRIFT:${NC}                ${dpath} — ${dstatus}"
        echo "                        keep the edits: 'tacctl store import --replace' then 'tacctl config render --force'; discard them: 'tacctl config render --force'"
    done <<< "$drift"
    return 1
}

# --- Backup config before changes ---
BACKUP_RETENTION=30

backup_config() {
    mkdir -p "$BACKUP_DIR"
    chmod 750 "$BACKUP_DIR"
    chown tacquito:tacquito "$BACKUP_DIR" 2>/dev/null || true
    # Milliseconds (%3N) avoid collisions when two mutating commands land in
    # the same wall-clock second — prior YYYYMMDD_HHMMSS format silently
    # overwrote the first backup, losing the pre-mutation snapshot.
    # 'backup list' / 'restore' parse the suffix verbatim, so old-format
    # files are still recognized.
    local ts
    ts=$(date +%Y%m%d_%H%M%S_%3N)
    cp "$CONFIG" "${BACKUP_DIR}/tacquito.yaml.${ts}"
    chmod 640 "${BACKUP_DIR}/tacquito.yaml.${ts}"
    chown tacquito:tacquito "${BACKUP_DIR}/tacquito.yaml.${ts}" 2>/dev/null || true
    info "Config backed up to ${BACKUP_DIR}/tacquito.yaml.${ts}"

    # Prune old backups, keep last $BACKUP_RETENTION. Same no-match
    # guard as cmd_status: avoid set -e tripping the caller when the
    # backups directory is empty.
    local count
    count=$(find "${BACKUP_DIR}" -maxdepth 1 -name 'tacquito.yaml.*' 2>/dev/null | wc -l || true)
    if [[ "$count" -gt "$BACKUP_RETENTION" ]]; then
        # shellcheck disable=SC2012  # mtime order needed; names are tacctl-generated tacquito.yaml.<timestamp>
        ls -1t "${BACKUP_DIR}"/tacquito.yaml.* | tail -n +$((BACKUP_RETENTION + 1)) | xargs rm -f
    fi
}

# --- Validate listen address (host:port or [ipv6]:port) against network family ---
validate_listen_address() {
    local net="$1" addr="$2"
    if ! python3 - "$net" "$addr" <<'PY' 2>/dev/null
import ipaddress, re, sys
net, addr = sys.argv[1], sys.argv[2]
m = re.match(r'^\[([^\]]+)\]:(\d+)$', addr)
if m:
    host, port = m.group(1), int(m.group(2))
else:
    m = re.match(r'^([^:]*):(\d+)$', addr)
    if not m:
        sys.exit(1)
    host, port = m.group(1), int(m.group(2))
if not 1 <= port <= 65535:
    sys.exit(1)
if host:
    ip = ipaddress.ip_address(host)
    if net == "tcp" and ip.version != 4:
        sys.exit(1)
    if net == "tcp6" and ip.version != 6:
        sys.exit(1)
PY
    then
        error "Invalid ${net} address: '${addr}'"
        return 1
    fi
}

# --- Systemd service drop-in helpers ---
# User-customized flags (-network, -address, -level) live as Environment=
# entries in a drop-in so that `tacctl upgrade` can safely replace the main
# service unit without clobbering them. Template defaults are in
# config/tacquito.service; the drop-in only records overrides.
OVERRIDE_DIR="${TACCTL_OVERRIDE_DIR:-/etc/systemd/system/tacquito.service.d}"
OVERRIDE_FILE="${OVERRIDE_DIR}/tacctl-overrides.conf"

# Read an Environment= override; echo empty if not set.
# `|| true` absorbs grep's exit-1-on-no-match so `pipefail + set -e`
# callers don't abort when the override file doesn't exist / is empty.
read_service_override() {
    local key="$1"
    { grep -oP "^Environment=\"${key}=\K[^\"]*" "$OVERRIDE_FILE" 2>/dev/null || true; } | tail -1
}

# Write (or replace) an Environment= override for the given key.
set_service_override() {
    local key="$1" value="$2"
    mkdir -p "$OVERRIDE_DIR"
    if [[ ! -f "$OVERRIDE_FILE" ]] || ! grep -q "^\[Service\]" "$OVERRIDE_FILE"; then
        local tmp; tmp=$(mktemp)
        echo "[Service]" > "$tmp"
        [[ -f "$OVERRIDE_FILE" ]] && cat "$OVERRIDE_FILE" >> "$tmp"
        mv "$tmp" "$OVERRIDE_FILE"
    fi
    sed -i "/^Environment=\"${key}=/d" "$OVERRIDE_FILE"
    echo "Environment=\"${key}=${value}\"" >> "$OVERRIDE_FILE"
}

# Remove a single override key; drop the file (and dir) if no overrides remain.
clear_service_override() {
    local key="$1"
    [[ -f "$OVERRIDE_FILE" ]] || return 0
    sed -i "/^Environment=\"${key}=/d" "$OVERRIDE_FILE"
    if ! grep -q "^Environment=" "$OVERRIDE_FILE"; then
        rm -f "$OVERRIDE_FILE"
        rmdir "$OVERRIDE_DIR" 2>/dev/null || true
    fi
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
    listen=$(ss -tlnp 2>/dev/null | { grep ":49 " || true; } | awk '{print $4}' | head -1)
    if [[ -n "$listen" ]]; then
        echo -e "  ${BOLD}Listening:${NC}            ${GREEN}${listen}${NC}"
    else
        echo -e "  ${BOLD}Listening:${NC}            ${RED}port 49 not detected${NC}"
    fi

    # Log level
    # Tolerate no-match: when tacquito is launched with ${TACQUITO_LEVEL}
    # rather than a literal -level flag, grep finds nothing and (under
    # pipefail + set -e) would abort status. `|| true` absorbs that.
    # Log level resolution: drop-in override wins; fall back to scraping a
    # literal -level N from ExecStart (older unit files); fall back to the
    # template default of 20 (info). Units that use \${TACQUITO_LEVEL}
    # placeholders would otherwise come back as "unknown".
    local loglevel
    loglevel=$(read_service_override TACQUITO_LEVEL)
    if [[ -z "$loglevel" ]]; then
        loglevel=$(systemctl show tacquito --property=ExecStart 2>/dev/null | grep -oP '\-level \K\d+' || true)
    fi
    loglevel=${loglevel:-20}
    local level_name
    case "$loglevel" in
        10) level_name="error" ;;
        20) level_name="info" ;;
        30) level_name="debug" ;;
        *)  level_name="unknown" ;;
    esac
    echo -e "  ${BOLD}Log level:${NC}            ${level_name} (${loglevel})"

    # Everything status reports about users, scopes and filters comes from
    # one model view (key=value lines; 'orphan=' and 'pwdate=' repeat).
    local status_view key value
    local -A st=([user_count]=0 [scope_count]=0 [prefix_count]=0 [prefix_unrestricted]=0
                 [prefix_has_v6]=0 [allow_has_v6]=0 [placeholder_scopes]="" [weak_scopes]=""
                 [empty_prefix_scopes]="" [total_refs]=0 [empty_scopes]="")
    local orphan_lines="" pwdate_lines=""
    status_view=$(_model_view status "$SECRET_MIN_LENGTH") || status_view=""
    while IFS='=' read -r key value; do
        case "$key" in
            "")     ;;
            orphan) orphan_lines+="${orphan_lines:+$'\n'}${value}" ;;
            pwdate) pwdate_lines+="${pwdate_lines:+$'\n'}${value}" ;;
            *)      st[$key]="$value" ;;
        esac
    done <<< "$status_view"
    local user_count="${st[user_count]}"
    echo -e "  ${BOLD}Users:${NC}                ${user_count}"

    # Config file
    echo -e "  ${BOLD}Config:${NC}               ${CONFIG}"
    if [[ "$(model_mode)" == "legacy" ]]; then
        echo -e "  ${YELLOW}Store:                not initialised — read-only until 'tacctl store import' (see 'tacctl store import --check')${NC}"
    fi
    print_drift_lines || true

    # Accounting log size
    if [[ -f "$ACCT_LOG" ]]; then
        local log_size
        log_size=$(du -sh "$ACCT_LOG" 2>/dev/null | awk '{print $1}')
        local log_lines
        log_lines=$(wc -l < "$ACCT_LOG" 2>/dev/null)
        echo -e "  ${BOLD}Accounting log:${NC}       ${log_size} (${log_lines} entries)"
    fi

    # Backup count. `find` on a missing backups directory exits non-zero;
    # under `set -euo pipefail` that kills the pipeline *and* the script.
    # `|| true` absorbs the failure; `wc -l` has already printed the count
    # (0 in that case), so nothing more may be echoed here.
    local backup_count
    backup_count=$(find "${BACKUP_DIR}" -maxdepth 1 -name 'tacquito.yaml.*' 2>/dev/null | wc -l || true)
    echo -e "  ${BOLD}Config backups:${NC}       ${backup_count}"

    # Prometheus metrics — auth stats. Respects the tacctl config metrics
    # address override: when the exporter is bound to 127.0.0.1:0 (our
    # "disabled" sink) we skip scraping and report the disabled state
    # explicitly rather than pretending the service is unreachable.
    echo ""
    echo -e "  ${BOLD}Authentication Stats (since last restart):${NC}"
    local metrics_addr metrics_url
    metrics_addr=$(read_service_override TACQUITO_METRICS_ADDRESS)
    metrics_addr=${metrics_addr:-127.0.0.1:8080}
    if [[ "$metrics_addr" == "127.0.0.1:0" ]]; then
        echo -e "    ${YELLOW}Metrics exporter disabled (tacctl config metrics enable)${NC}"
    else
        if [[ "$metrics_addr" == :* ]]; then
            metrics_url="http://localhost${metrics_addr}/metrics"
        else
            metrics_url="http://${metrics_addr}/metrics"
        fi
        local metrics
        metrics=$(curl -s "$metrics_url" 2>/dev/null || true)
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
            echo -e "    ${YELLOW}Metrics unavailable (${metrics_url})${NC}"
        fi
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

    # Security posture — aggregate scope prefixes + per-scope secret check +
    # IPv6/IPv4 ACL parity. Iterates all scopes rather than reading the first
    # secrets[] entry, so multi-scope installs are accurately summarized.
    echo ""
    echo -e "  ${BOLD}Security Posture:${NC}"
    local prefix_count="${st[prefix_count]}" prefix_unrestricted="${st[prefix_unrestricted]}"
    local prefix_has_v6="${st[prefix_has_v6]}" allow_has_v6="${st[allow_has_v6]}"
    local placeholder_scopes="${st[placeholder_scopes]}" weak_scopes="${st[weak_scopes]}"
    local empty_prefix_scopes="${st[empty_prefix_scopes]}"

    if [[ "$prefix_unrestricted" == "1" ]]; then
        echo -e "    ${RED}Prefix scope:       UNRESTRICTED (all RFC 1918 — harden with 'tacctl scope prefixes <name>')${NC}"
    elif [[ "$prefix_count" -eq 0 ]]; then
        echo -e "    ${RED}Prefix scope:       EMPTY (no clients can connect)${NC}"
    else
        echo -e "    ${GREEN}Prefix scope:       ${prefix_count} CIDR(s) across all scopes${NC}"
    fi
    if [[ -n "$empty_prefix_scopes" ]]; then
        echo -e "      ${YELLOW}scopes with no prefixes: ${empty_prefix_scopes}${NC}"
    fi

    # IPv6 parity warning: if the listener is tcp6 but no IPv6 CIDR exists
    # anywhere in prefixes/allow, IPv4-mapped addresses can bypass ACLs.
    local listener_net
    listener_net=$(read_service_override TACQUITO_NETWORK)
    listener_net=${listener_net:-tcp}
    if [[ "$listener_net" == "tcp6" ]]; then
        if [[ "$prefix_has_v6" != "1" && "$allow_has_v6" != "1" ]]; then
            echo -e "    ${RED}IPv6 ACL parity:    MISSING (listener is tcp6 but no IPv6 CIDRs — v4-mapped clients bypass ACLs)${NC}"
        else
            echo -e "    ${GREEN}IPv6 ACL parity:    present${NC}"
        fi
    fi

    # Shared-secret sanity: flag any scope with a placeholder or short key.
    if [[ -n "$placeholder_scopes" ]]; then
        echo -e "    ${RED}Shared secret:      PLACEHOLDER in scope(s): ${placeholder_scopes} (run 'tacctl scope secret <name> generate')${NC}"
    elif [[ -n "$weak_scopes" ]]; then
        echo -e "    ${RED}Shared secret:      weak in scope(s): ${weak_scopes} (min ${SECRET_MIN_LENGTH})${NC}"
    else
        echo -e "    ${GREEN}Shared secret:      all scopes ≥ ${SECRET_MIN_LENGTH} chars${NC}"
    fi

    # Management ACL: shared permit list used by Cisco VTY-ACL and the
    # Juniper lo0-filter example. Empty means 'tacctl config cisco'
    # emits a placeholder scaffold and 'tacctl config juniper' emits a
    # comment.
    local mgmt_acl_count
    mgmt_acl_count=$(read_mgmt_acl_cidrs | wc -l)
    if [[ "$mgmt_acl_count" -eq 0 ]]; then
        echo -e "    ${RED}Management ACL:     EMPTY (configure via 'tacctl config mgmt-acl add <cidr>')${NC}"
    else
        echo -e "    ${GREEN}Management ACL:     configured (${mgmt_acl_count} entr$( [[ $mgmt_acl_count -eq 1 ]] && echo "y" || echo "ies" ))${NC}"
    fi

    # Scopes: multi-scope posture. An orphan is a user referencing a scope
    # that does not exist (possible only in a legacy config; the store
    # refuses one).
    local scope_count="${st[scope_count]}" total_refs="${st[total_refs]}" empty_scopes="${st[empty_scopes]}"
    if [[ "$scope_count" -eq 0 ]]; then
        echo -e "    ${RED}Scopes:             NONE (no auth targets defined)${NC}"
    elif [[ -n "$orphan_lines" ]]; then
        echo -e "    ${RED}Scopes:             ORPHAN references — users point at missing scopes${NC}"
        echo "$orphan_lines" | while IFS= read -r pair; do
            local u="${pair%%:*}"
            local s="${pair#*:}"
            echo -e "      ${RED}user '${u}' → scope '${s}' (does not exist)${NC}"
        done
    else
        echo -e "    ${GREEN}Scopes:             configured (${scope_count} scope(s), ${total_refs} user grant(s))${NC}"
        if [[ -n "$empty_scopes" ]]; then
            echo -e "      ${YELLOW}empty scope(s): ${empty_scopes} (no users — intentional?)${NC}"
        fi
    fi
    local def_scope
    def_scope=$(read_default_scope)
    if [[ -z "$def_scope" ]]; then
        echo -e "    ${YELLOW}Default scope:      UNSET (tacctl user add without --scopes will fail)${NC}"
    else
        echo -e "    ${GREEN}Default scope:      ${def_scope}${NC}"
    fi

    # Password age warnings
    echo ""
    echo -e "  ${BOLD}Password Age Warnings:${NC}"
    local pw_warnings=0
    local today
    today=$(date +%s)
    local uname pw_date pw_epoch age_days
    while IFS='|' read -r uname pw_date; do
        [[ -n "$uname" ]] || continue
        pw_epoch=$(date -d "$pw_date" +%s 2>/dev/null || echo 0)
        if [[ "$pw_epoch" -gt 0 ]]; then
            age_days=$(( (today - pw_epoch) / 86400 ))
            if [[ "$age_days" -gt "$PASSWORD_MAX_AGE_DAYS" ]]; then
                echo -e "    ${YELLOW}${uname}: password is ${age_days} days old (changed ${pw_date})${NC}"
                pw_warnings=$((pw_warnings + 1))
            fi
        fi
    done <<< "$pwdate_lines"
    if [[ "$pw_warnings" -eq 0 ]]; then
        echo -e "    ${GREEN}No passwords older than ${PASSWORD_MAX_AGE_DAYS} days${NC}"
    fi

    echo ""
}

# --- CONFIG VALIDATE ---
# With a store: the store against its schema, tacctl.yaml against its
# schema, a trial render of tacquito.yaml (which also checks the command
# rules and reads the result back), whether the live tacquito.yaml is that
# render, and drift (a hand-edited artifact).
# Without one (legacy read-only mode): the tacquito.yaml the daemon runs is
# still the source of truth, so it is checked as the model the importer
# reads from it; 'tacctl store import --check' is the full report.
cmd_config_validate() {
    local mode
    mode=$(model_mode)
    echo ""
    if [[ "$mode" == "store" ]]; then
        echo -e "${BOLD}Validating ${STORE_FILE}...${NC}"
    else
        echo -e "${BOLD}Validating ${CONFIG}...${NC}"
    fi
    echo ""

    local errors=0 line

    if [[ "$mode" == "store" ]]; then
        # store_validate prints one 'tacctl store: <problem>' line per error.
        local store_errors
        if store_errors=$(store_validate 2>&1); then
            echo -e "  ${GREEN}Store:${NC}                valid"
        else
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                echo -e "  ${RED}Store:${NC}                ${line#tacctl store: }"
                errors=$((errors + 1))
            done <<< "$store_errors"
        fi
    else
        # Check YAML syntax
        if python3 -c "import yaml; yaml.safe_load(open('$CONFIG'))" 2>/dev/null; then
            echo -e "  ${GREEN}YAML syntax:${NC}          valid"
        else
            echo -e "  ${RED}YAML syntax:${NC}          INVALID"
            python3 -c "import yaml; yaml.safe_load(open('$CONFIG'))" 2>&1 | head -3
            errors=$((errors + 1))
        fi
        echo -e "  ${YELLOW}Store:${NC}                not initialised — read-only until 'tacctl store import' ('tacctl store import --check' reports what it would do)"
    fi

    # Validate the tacctl overrides file. Malformed YAML would silently
    # revert tunables to their defaults; surfacing the parse error here
    # lets operators catch typos before they confuse 'tacctl status'.
    # (Defaults are embedded in the script — no file to validate.)
    if [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]; then
        echo -e "  ${GREEN}tacctl.yaml:${NC}          no overrides"
    elif python3 -c "import yaml; yaml.safe_load(open('$TACCTL_OVERRIDES_FILE'))" 2>/dev/null; then
        echo -e "  ${GREEN}tacctl.yaml:${NC}          valid"
        # Schema-walk the overrides against _CONF_SCHEMA (write-time
        # validation catches most issues; this catches hand-edits).
        local schema_errors
        schema_errors=$(_conf_validate_overrides_file 2>&1 || true)
        if [[ -n "$schema_errors" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                echo -e "  ${RED}tacctl.yaml:${NC}          ${line}"
                errors=$((errors + 1))
            done <<< "$schema_errors"
        fi
    else
        echo -e "  ${RED}tacctl.yaml:${NC}          INVALID"
        python3 -c "import yaml; yaml.safe_load(open('$TACCTL_OVERRIDES_FILE'))" 2>&1 | head -3
        errors=$((errors + 1))
    fi

    # What the model says: is there anything to serve, are the secrets
    # real. A store has already had its references checked above; a legacy
    # model has not, so it gets the full set here.
    local report="" structure_errors=0 scope_names=""
    local -A counts=([users]="?" [groups]="?" [scopes]="?")
    local full=()
    [[ "$mode" == "legacy" ]] && full=(full)
    if report=$(_model_view validate "${full[@]}"); then
        while IFS= read -r line; do
            case "$line" in
                COUNT:*)
                    line="${line#COUNT:}"
                    counts[${line%%=*}]="${line#*=}"
                    ;;
                ERROR:*)
                    echo -e "  ${RED}Error:${NC}                ${line#ERROR:}"
                    structure_errors=$((structure_errors + 1))
                    ;;
            esac
        done <<< "$report"
        scope_names=$(model_scopes) || scope_names=""
    else
        echo -e "  ${RED}Error:${NC}                users, groups and scopes could not be read (see above)"
        structure_errors=1
    fi
    if (( structure_errors == 0 )); then
        echo -e "  ${GREEN}Config structure:${NC}     valid"
    fi
    errors=$((errors + structure_errors))

    # scope.default in tacctl.yaml must name an existing scope.
    local default_scope_configured
    default_scope_configured=$(conf_get scope.default)
    if [[ -n "$report" && -n "$default_scope_configured" ]] \
        && ! grep -qxF -- "$default_scope_configured" <<< "$scope_names"; then
        echo -e "  ${RED}Error:${NC}                Default scope override points at '${default_scope_configured}' which is not a defined scope"
        errors=$((errors + 1))
    else
        echo -e "  ${GREEN}Scopes integrity:${NC}     valid"
    fi

    # Rendered artifact: can the store be rendered, and is the live file
    # that render? A hand-edited file is reported by the DRIFT line below
    # instead, and counted once.
    local drifted=0
    backends_check_drift > /dev/null || drifted=1
    if [[ "$mode" == "store" ]]; then
        local rstate=""
        if ! rstate=$(tacacs_render_check); then
            echo -e "  ${RED}Rendered config:${NC}      the store cannot be rendered (see above)"
            errors=$((errors + 1))
        elif (( drifted )); then
            :
        else
            case "$rstate" in
                current|same)
                    echo -e "  ${GREEN}Rendered config:${NC}      up to date"
                    ;;
                missing)
                    echo -e "  ${RED}Rendered config:${NC}      ${CONFIG} is missing — run 'tacctl config render'"
                    errors=$((errors + 1))
                    ;;
                unrecorded)
                    echo -e "  ${YELLOW}Rendered config:${NC}      ${CONFIG} was not rendered by tacctl yet — the next change replaces it if it says what the store says; otherwise run 'tacctl config render --force'"
                    ;;
                *)
                    echo -e "  ${RED}Rendered config:${NC}      ${CONFIG} is out of date with the store — run 'tacctl config render'"
                    errors=$((errors + 1))
                    ;;
            esac
        fi
    fi
    if (( drifted )); then
        print_drift_lines || true
        errors=$((errors + 1))
    fi

    echo -e "  ${GREEN}Groups defined:${NC}       ${counts[groups]}"
    echo -e "  ${GREEN}Scopes defined:${NC}       ${counts[scopes]}"
    echo -e "  ${GREEN}Users defined:${NC}        ${counts[users]}"

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

    local current_num
    current_num=$(read_service_override TACQUITO_LEVEL)
    current_num=${current_num:-20}

    if [[ -z "$new_level" ]]; then
        local level_name="unknown"
        case "$current_num" in
            10) level_name="error" ;;
            20) level_name="info" ;;
            30) level_name="debug" ;;
        esac
        echo ""
        echo "  Current log level: ${level_name} (${current_num})"
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

    if [[ "$current_num" == "$level_num" ]]; then
        info "Already at ${new_level} (${level_num})."
        return
    fi

    # Default level (20) uses the template default -- clear the override
    # instead of pinning it, so future template bumps can move the default.
    if [[ "$level_num" == "20" ]]; then
        clear_service_override TACQUITO_LEVEL
    else
        set_service_override TACQUITO_LEVEL "$level_num"
    fi
    systemctl daemon-reload
    systemctl restart tacquito

    info "Log level changed to ${new_level} (${level_num}). Service restarted."
    echo ""
}

# --- CONFIG LISTEN ---
cmd_config_listen() {
    local sub="${1:-}"
    local addr="${2:-}"

    local current_net current_addr net_src addr_src
    current_net=$(read_service_override TACQUITO_NETWORK)
    if [[ -n "$current_net" ]]; then net_src="override"; else net_src="default"; fi
    current_net=${current_net:-tcp}
    current_addr=$(read_service_override TACQUITO_ADDRESS)
    if [[ -n "$current_addr" ]]; then addr_src="override"; else addr_src="default"; fi
    current_addr=${current_addr:-:49}

    case "$sub" in
        ""|show)
            echo ""
            echo "  Current listener: ${current_net} ${current_addr}"
            if [[ "$net_src" == "override" || "$addr_src" == "override" ]]; then
                echo "  (override in ${OVERRIDE_FILE})"
            else
                echo "  (template default)"
            fi
            echo ""
            echo "  Usage: tacctl config listen <show|tcp|tcp6|reset> [address]"
            echo "  Examples:"
            echo "    tacctl config listen tcp :49"
            echo "    tacctl config listen tcp 10.1.0.1:49"
            echo "    tacctl config listen tcp6 [::]:49"
            echo "    tacctl config listen reset       # drop override, use template default"
            echo ""
            return
            ;;
        reset)
            if [[ "$net_src" == "default" && "$addr_src" == "default" ]]; then
                info "No listener override set. Already on template default (${current_net} ${current_addr})."
                return
            fi
            clear_service_override TACQUITO_NETWORK
            clear_service_override TACQUITO_ADDRESS
            systemctl daemon-reload
            systemctl restart tacquito
            if systemctl is-active --quiet tacquito; then
                info "Listener override removed. Using template default. Service restarted."
            else
                error "tacquito failed to start after reset."
                return 1
            fi
            echo ""
            return
            ;;
        tcp|tcp6)
            ;;
        *)
            error "Invalid subcommand: '${sub}'. Use: show, tcp, tcp6, or reset"
            return 1
            ;;
    esac

    if [[ -z "$addr" ]]; then
        error "Missing address. Example: tacctl config listen ${sub} :49"
        return 1
    fi

    validate_listen_address "$sub" "$addr" || return 1

    if [[ "$current_net" == "$sub" && "$current_addr" == "$addr" ]]; then
        info "Already listening on ${sub} ${addr}."
        return
    fi

    if [[ "$sub" == "tcp6" && "$current_net" != "tcp6" ]]; then
        echo ""
        warn "tcp6 enables dual-stack sockets on most platforms."
        warn "IPv4 clients connect with mapped addresses (::ffff:a.b.c.d)"
        warn "which do NOT match IPv4 rules in 'tacctl scope prefixes <name>',"
        warn "'config allow', or 'config deny' -- effectively bypassing them."
        echo ""
        read -rp "  Proceed with tcp6? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy] ]]; then
            info "Aborted."
            return
        fi
    fi

    # Snapshot override file for rollback if restart fails.
    local had_override="false"
    if [[ -f "$OVERRIDE_FILE" ]]; then
        cp "$OVERRIDE_FILE" "${OVERRIDE_FILE}.bak"
        had_override="true"
    fi

    set_service_override TACQUITO_NETWORK "$sub"
    set_service_override TACQUITO_ADDRESS "$addr"

    systemctl daemon-reload
    systemctl restart tacquito

    if systemctl is-active --quiet tacquito; then
        info "Listener changed to ${sub} ${addr}. Service restarted."
        rm -f "${OVERRIDE_FILE}.bak"
    else
        error "tacquito failed to start. Restoring previous override."
        if [[ "$had_override" == "true" ]]; then
            mv "${OVERRIDE_FILE}.bak" "$OVERRIDE_FILE"
        else
            rm -f "$OVERRIDE_FILE"
            rmdir "$OVERRIDE_DIR" 2>/dev/null || true
        fi
        systemctl daemon-reload
        systemctl restart tacquito
        return 1
    fi
    echo ""
}

# --- CONFIG METRICS ---
# Control the prometheus exporter's listen address (tacquito's -metrics-address
# flag). `disable` binds the exporter to 127.0.0.1:0 — a loopback address on
# an ephemeral port that no scraper can discover, so from any reader's
# perspective the exporter is gone even though the goroutine still runs.
# We deliberately do NOT toggle tacquito's -export-promhttp flag: upstream's
# goroutine unconditionally cancels the server context when the exporter
# returns, so `-export-promhttp=false` would tear down the whole daemon.
cmd_config_metrics() {
    local sub="${1:-}"
    local arg="${2:-}"

    # Defaults must match config/tacquito.service Environment= lines.
    # Loopback-only by default: local scrapers on the box can reach it, external
    # ones can't without an explicit `tacctl config metrics address` change.
    local default_addr="127.0.0.1:8080"
    local disable_sink="127.0.0.1:0"

    local cur_addr addr_src
    cur_addr=$(read_service_override TACQUITO_METRICS_ADDRESS)
    if [[ -n "$cur_addr" ]]; then addr_src="override"; else addr_src="default"; fi
    cur_addr=${cur_addr:-$default_addr}

    local state state_color
    if [[ "$cur_addr" == "$disable_sink" ]]; then
        state="disabled"; state_color="$RED"
    elif [[ "$cur_addr" == 127.* || "$cur_addr" == "[::1]"* || "$cur_addr" == "localhost:"* ]]; then
        state="enabled (loopback-only)"; state_color="$GREEN"
    else
        state="enabled (externally reachable)"; state_color="$YELLOW"
    fi

    case "$sub" in
        ""|show|-h|--help|help)
            echo ""
            echo -e "${BOLD}Prometheus metrics exporter${NC}"
            echo "--------------------------------------------"
            echo -e "  State:    ${state_color}${state}${NC}"
            echo -e "  Address:  ${cur_addr}  (${addr_src})"
            if [[ "$state" != "disabled" ]]; then
                echo ""
                local scrape_url
                if [[ "$cur_addr" == :* ]]; then
                    scrape_url="http://localhost${cur_addr}/metrics"
                else
                    scrape_url="http://${cur_addr}/metrics"
                fi
                echo "  Scrape URL: ${scrape_url}"
            fi
            echo ""
            echo "Usage:"
            echo "  tacctl config metrics                      Show current state"
            echo "  tacctl config metrics enable               Revert to default (${default_addr})"
            echo "  tacctl config metrics disable              Sink to ${disable_sink} (no scraper can reach)"
            echo "  tacctl config metrics address <host:port>  Explicit bind (e.g. 10.1.0.1:8080 for external)"
            echo "  tacctl config metrics reset                Clear override (revert to unit default)"
            echo ""
            if [[ "$state" == "disabled" ]]; then
                echo "  Note: tacquito still runs the exporter goroutine, bound to an"
                echo "        ephemeral loopback port unknown to any scraper. This is the"
                echo "        closest we can get without patching tacquito upstream."
                echo ""
            fi
            return
            ;;
        enable)
            if [[ "$state" != "disabled" && "$addr_src" == "default" ]]; then
                info "Already enabled on default (${default_addr})."
                return
            fi
            clear_service_override TACQUITO_METRICS_ADDRESS
            systemctl daemon-reload
            systemctl restart tacquito
            info "Metrics exporter enabled on ${default_addr}/metrics."
            echo ""
            ;;
        disable)
            if [[ "$state" == "disabled" ]]; then
                info "Already disabled (sunk to ${disable_sink})."
                return
            fi
            set_service_override TACQUITO_METRICS_ADDRESS "$disable_sink"
            systemctl daemon-reload
            systemctl restart tacquito
            info "Metrics exporter sunk to ${disable_sink} — no scraper can reach it."
            warn "Note: the exporter goroutine still runs; bind-to-loopback-0 is the"
            warn "closest 'off' state tacquito supports without an upstream patch."
            echo ""
            ;;
        address)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl config metrics address <host:port>"
                error "Examples:  127.0.0.1:8080  (loopback only — default)"
                error "           :8080           (all interfaces — external scrapers can reach)"
                error "           10.1.0.1:9090   (specific mgmt IP + custom port)"
                exit 1
            fi
            if [[ "$arg" != *:* ]]; then
                error "Address must include a port (e.g. '127.0.0.1:8080' or ':8080')."
                exit 1
            fi
            if [[ "$arg" == "$default_addr" ]]; then
                clear_service_override TACQUITO_METRICS_ADDRESS
            else
                set_service_override TACQUITO_METRICS_ADDRESS "$arg"
            fi
            systemctl daemon-reload
            systemctl restart tacquito
            info "Metrics listen address set to ${arg}. Service restarted."
            if [[ "$arg" != 127.* && "$arg" != "[::1]"* && "$arg" != "$disable_sink" ]]; then
                warn "Exporter is now externally reachable. Ensure downstream scrapers"
                warn "have appropriate network-level access controls."
            fi
            echo ""
            ;;
        reset)
            clear_service_override TACQUITO_METRICS_ADDRESS
            systemctl daemon-reload
            systemctl restart tacquito
            info "Metrics override cleared. Using unit default (${default_addr})."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl config metrics' with no arguments for usage."
            exit 1
            ;;
    esac
}

# =====================================================================
#  LOG COMMANDS
# =====================================================================

# Purge the tacquito journal and truncate the file-based accounting log.
# Destructive — prompts for confirmation. Accepts `--force` / `-y` to skip
# the prompt for scripted use (e.g. scheduled cleanups).
cmd_log_clear() {
    local force=false
    case "${1:-}" in
        -y|--force|--yes) force=true ;;
    esac

    echo ""
    echo -e "${BOLD}Clear tacquito logs${NC}"
    echo "--------------------------------------------"
    warn "This permanently deletes tacquito journal entries and truncates ${ACCT_LOG}."
    warn "Historical authentication and accounting records will be lost."

    if [[ "$force" != "true" ]]; then
        read -rp "  Continue? [y/N]: " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            info "Cancelled."
            return 0
        fi
    fi

    # Rotate closes the active journal file so the vacuum step can evict it;
    # --vacuum-time=1s then drops everything older than one second. The
    # per-unit filter keeps other services' journals intact.
    journalctl --rotate 2>/dev/null || true
    if ! journalctl --vacuum-time=1s -u tacquito >/dev/null 2>&1; then
        warn "journalctl vacuum failed — run manually: sudo journalctl --vacuum-time=1s -u tacquito"
    fi

    # Truncate in place so logrotate's ownership/permissions stay intact.
    if [[ -f "$ACCT_LOG" ]]; then
        : > "$ACCT_LOG" 2>/dev/null || warn "Could not truncate ${ACCT_LOG} (check permissions)."
    fi

    info "Logs cleared (journal + accounting)."
    echo ""
}

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
            journalctl -u tacquito --no-pager --since "7 days ago" 2>/dev/null | grep -i -e "$term" || echo "  No matches found."
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
        clear)
            cmd_log_clear "$@"
            ;;
        *)
            echo ""
            echo -e "${BOLD}Log Commands${NC}"
            echo ""
            echo "Usage: tacctl log <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  tail [n]              Show last N journal entries (default 20)"
            echo "  search <term>         Search journal for a username or keyword"
            echo "  failures              Show auth failures from the last 24 hours"
            echo "  accounting [n]        Show last N accounting log entries"
            echo "  clear                 Purge tacquito journal + truncate accounting log (confirms)"
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
                # shellcheck disable=SC2012  # mtime order needed; names are tacctl-generated tacquito.yaml.<timestamp>
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
                # shellcheck disable=SC2012  # mtime order needed; names are tacctl-generated tacquito.yaml.<timestamp>
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
            # Unified format (-u) shows surrounding context and
            # ---/+++ filename labels so changes land in their
            # structural neighborhood instead of as a bare `30c30`.
            # --label keeps the header short and stable (absolute
            # paths would churn per-host).
            diff -u \
                --label "backup/${ts}" \
                --label "current" \
                --color=always "$backup_file" "$CONFIG" || true
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

            if [[ "$(model_mode)" == "store" ]]; then
                # The store is canonical and tacquito.yaml is rendered from
                # it, so restoring means adopting the backup's content into
                # the store (a strict import: a backup the store cannot
                # represent restores nothing) and rendering it back out.
                # Interim until backups are store snapshots.
                if ! store_import --replace "$backup_file" > /dev/null; then
                    error "Backup ${timestamp} cannot be restored into the store. Nothing was changed."
                    exit 1
                fi
                local result
                if ! result=$(tacacs_render_apply --force); then
                    error "The store now holds backup ${timestamp}, but ${CONFIG} could not be rendered. Run 'tacctl config render --force'."
                    exit 1
                fi
                [[ "$result" == "CHANGED" ]] && restart_service
            else
                cp "$backup_file" "$CONFIG"
                chown tacquito:tacquito "$CONFIG"
                chmod 640 "$CONFIG"
                restart_service
            fi
            info "Config restored from backup ${timestamp}."
            echo ""
            ;;
        *)
            echo ""
            echo -e "${BOLD}Backup Commands${NC}"
            echo ""
            echo "Usage: tacctl backup <subcommand> [arguments]"
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

