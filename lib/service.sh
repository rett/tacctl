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

# --- Snapshots of the canonical files (plan 4.6) ---
# A snapshot is a directory backups/<ts>/ holding store.yaml, tacctl.yaml (when
# there is one) and a manifest: the rendered.json of that moment plus the
# tacctl version. Restoring one restores the truth, not the artifact derived
# from it. Snapshots hold shared secrets and password hashes: the directory is
# 0700 and the files 0600, root only.
#
# <ts> is YYYYMMDD_HHMMSS_mmm, with -N appended when two snapshots land in the
# same millisecond; names sort in time order. A directory under backups/ is a
# snapshot only if its name has that shape. Everything else there (password-
# dates/, disabled/, legacy/, old-style tacquito.yaml.<ts> files) is not ours
# to prune.
BACKUP_RETENTION=30
BACKUP_SNAPSHOT_RE='^[0-9]{8}_[0-9]{6}(_[0-9]{3})?(-[0-9]+)?$'

# Set to 1 while a command that already took its snapshot runs its writes
# (store_apply, backup restore): the store writer's own snapshot hook then
# stays quiet instead of snapshotting every intermediate state.
_BACKUP_SNAPSHOT_HELD=0
# A snapshot id retention must not delete (the one a restore reads from).
_BACKUP_KEEP_ID=""
_BACKUP_VERSION=""

# Snapshot ids, newest first, one per line. Never fails.
_backup_snapshot_ids() {
    { find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null || true; } \
        | { grep -E "$BACKUP_SNAPSHOT_RE" || true; } \
        | sort -r
}

# True when the live store.yaml and tacctl.yaml are byte-identical to the ones
# in snapshot directory $1 (tacctl.yaml absent on both sides counts).
_backup_snapshot_current() {
    local dir="$1"
    cmp -s "$STORE_FILE" "${dir}/store.yaml" || return 1
    if [[ -f "$TACCTL_OVERRIDES_FILE" ]]; then
        cmp -s "$TACCTL_OVERRIDES_FILE" "${dir}/tacctl.yaml" || return 1
    else
        [[ ! -e "${dir}/tacctl.yaml" ]] || return 1
    fi
}

# backup_snapshot: snapshot store.yaml and tacctl.yaml before a change.
# Called by store_apply and, through store_snapshot_hook, by every store write.
#   - Does nothing while _BACKUP_SNAPSHOT_HELD=1 (the caller has its own).
#   - Does nothing when the live files already equal the newest snapshot, so
#     a command that changes nothing, or a second write of one command, does
#     not pile up identical snapshots.
#   - Builds the directory under a private name and renames it into place, so
#     a snapshot is never seen half written; a name already taken gets a -N
#     suffix.
#   - Then keeps the newest $BACKUP_RETENTION snapshots. It never removes the
#     one just made, $_BACKUP_KEEP_ID, or anything that is not a snapshot.
# Returns 1 (message on stderr) when the snapshot could not be made.
backup_snapshot() {
    (( _BACKUP_SNAPSHOT_HELD )) && return 0
    [[ -f "$STORE_FILE" ]] || return 0
    local ids=()
    mapfile -t ids < <(_backup_snapshot_ids)
    if (( ${#ids[@]} )) && _backup_snapshot_current "${BACKUP_DIR}/${ids[0]}"; then
        return 0
    fi

    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR" || { error "Cannot create ${BACKUP_DIR}."; return 1; }
        chmod 750 "$BACKUP_DIR"
        chown tacquito:tacquito "$BACKUP_DIR" 2>/dev/null || true
    fi
    local tmp
    tmp=$(mktemp -d "${BACKUP_DIR}/.snap.XXXXXX") || { error "Cannot create a snapshot in ${BACKUP_DIR}."; return 1; }
    [[ -n "$_BACKUP_VERSION" ]] || _BACKUP_VERSION=$(get_version)
    if ! _backup_snapshot_fill "$tmp"; then
        rm -rf "$tmp"
        error "Cannot write a snapshot in ${BACKUP_DIR}."
        return 1
    fi

    # Milliseconds keep two commands in one second apart; the loop covers the
    # same millisecond.
    local name final n=0
    name=$(date +%Y%m%d_%H%M%S_%3N)
    final="${BACKUP_DIR}/${name}"
    while [[ -e "$final" || -L "$final" ]] || ! mv -T "$tmp" "$final" 2>/dev/null; do
        n=$((n + 1))
        if (( n > 100 )); then
            rm -rf "$tmp"
            error "Cannot name a snapshot in ${BACKUP_DIR}."
            return 1
        fi
        final="${BACKUP_DIR}/${name}-${n}"
    done
    name="${final##*/}"
    info "Config snapshot saved to ${final}"

    # Retention. ids was read before this snapshot existed: the new one goes
    # in front, and the oldest of the rest go.
    ids=("$name" ${ids[@]+"${ids[@]}"})
    local i
    for (( i = BACKUP_RETENTION; i < ${#ids[@]}; i++ )); do
        [[ "${ids[i]}" == "$name" || "${ids[i]}" == "$_BACKUP_KEEP_ID" ]] && continue
        rm -rf -- "${BACKUP_DIR:?}/${ids[i]}"
    done
    return 0
}

# Fill directory $1 (0700, private) with the files of a snapshot, 0600.
_backup_snapshot_fill() {
    local dir="$1"
    cp "$STORE_FILE" "${dir}/store.yaml" || return 1
    if [[ -f "$TACCTL_OVERRIDES_FILE" ]]; then
        cp "$TACCTL_OVERRIDES_FILE" "${dir}/tacctl.yaml" || return 1
    fi
    python3 - "$RENDERED_FILE" "$_BACKUP_VERSION" > "${dir}/manifest" <<'PY' || return 1
import datetime, json, sys
path, version = sys.argv[1:3]
try:
    with open(path) as f:
        rendered = json.load(f)
except FileNotFoundError:
    rendered = {}
except (OSError, ValueError):
    rendered = None  # present but unreadable: say so rather than guess
print(json.dumps({
    "tacctl_version": version,
    "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "rendered": rendered,
}, indent=2, sort_keys=True))
PY
    # mktemp -d made the directory 0700 already; stated so the mode does not
    # depend on it.
    chmod 700 "$dir"
    chmod 600 "${dir}"/*
}

# Old-style backup of tacquito.yaml alone. Only the legacy (no store yet)
# paths use it: a pre-store install keeps backing up the file that is still
# its source of truth. With a store, backup_snapshot is the backup.
backup_config() {
    mkdir -p "$BACKUP_DIR"
    chmod 750 "$BACKUP_DIR"
    chown tacquito:tacquito "$BACKUP_DIR" 2>/dev/null || true
    # Milliseconds (%3N) avoid collisions when two mutating commands land in
    # the same wall-clock second.
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

# Old-style backups: whole tacquito.yaml copies made before the store existed
# (backups/tacquito.yaml.<ts>, left in place by the state migration) and the
# files the renderer and the upgrade keep in backups/legacy/ (tacquito.yaml.
# drift.<ts>, tacquito.yaml.pre-store.<ts>). The id is the file name without
# the leading 'tacquito.yaml.', so it may contain dots. Printed newest first
# (by modification time), one '<id><TAB><path>' per line. Never fails.
_backup_legacy_entries() {
    local dir
    for dir in "$BACKUP_DIR" "${BACKUP_DIR}/legacy"; do
        find "$dir" -maxdepth 1 -type f -name 'tacquito.yaml.?*' -printf '%T@\t%f\t%p\n' 2>/dev/null || true
    done | sort -t$'\t' -k1,1nr -k2,2r | awk -F'\t' '{ id = $2; sub(/^tacquito\.yaml\./, "", id); print id "\t" $3 }'
}

# _backup_legacy_path <id>: print the path of an old-style backup, or fail.
# The id may not name a directory: letters, digits, dot, underscore, dash.
_backup_legacy_path() {
    local id="$1" dir
    [[ "$id" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*$ ]] || return 1
    for dir in "$BACKUP_DIR" "${BACKUP_DIR}/legacy"; do
        if [[ -f "${dir}/tacquito.yaml.${id}" && ! -L "${dir}/tacquito.yaml.${id}" ]]; then
            echo "${dir}/tacquito.yaml.${id}"
            return 0
        fi
    done
    return 1
}

# backup_names: every id 'backup diff|restore' takes, snapshots first, newest
# first, then old-style backups. For completion.
backup_names() {
    _backup_snapshot_ids
    _backup_legacy_entries | cut -f1
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

    # Backup count: snapshots, plus the old-style files an upgrade leaves
    # behind. Both listings absorb a missing backups directory themselves
    # (under `set -euo pipefail` a failing `find` would kill the script);
    # `wc -l` prints the count, 0 included, so nothing more may be echoed.
    # Without a store the old-style files are the backups, so they are the
    # count.
    local backup_count snapshot_count old_count
    snapshot_count=$(_backup_snapshot_ids | wc -l)
    old_count=$(_backup_legacy_entries | wc -l)
    if [[ "$(model_mode)" == "store" ]]; then
        backup_count="$snapshot_count"
        (( old_count > 0 )) && backup_count+=" (+${old_count} old-style)"
    else
        backup_count=$(( snapshot_count + old_count ))
    fi
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
#
# With a store, a backup is a snapshot (backup_snapshot above) and list, diff
# and restore work on those; old-style tacquito.yaml.<ts> copies are listed
# after them and can be diffed, and restored with --legacy (through the
# importer's check). Without a store (legacy read-only mode) nothing takes
# snapshots, and list, diff and restore work on the old-style files exactly as
# they always did: a snapshot found there (left by 'store rollback') is listed
# but refused, because restoring it would create the store without the import
# gate.

# Print one file's diff between a snapshot's copy and the live one; a file
# that does not exist diffs as empty. $1 label, $2 snapshot file, $3 live
# file, $4 snapshot id.
_backup_diff_file() {
    local label="$1" ts="$4" rc=0 a="$2" b="$3"
    [[ -f "$a" ]] || a=/dev/null
    [[ -f "$b" ]] || b=/dev/null
    if [[ "$a" == /dev/null && "$b" == /dev/null ]]; then
        echo "  ${label}: absent in the snapshot and now"
        return 0
    fi
    # Unified format (-u) shows surrounding context and ---/+++ labels so
    # changes land in their structural neighborhood instead of as a bare
    # `30c30`. --label keeps the header short and stable (absolute paths
    # would churn per-host).
    diff -u \
        --label "snapshot/${ts}/${label}" \
        --label "current/${label}" \
        --color=always "$a" "$b" || rc=$?
    (( rc == 0 )) && echo "  ${label}: no differences"
    return 0
}

# Diff of the live canonical files against snapshot $1.
_backup_diff_snapshot() {
    local ts="$1" dir="${BACKUP_DIR}/$1"
    echo ""
    echo -e "${BOLD}Diff: current store and tacctl.yaml vs snapshot ${ts}${NC}"
    echo "--------------------------------------------"
    _backup_diff_file store.yaml "${dir}/store.yaml" "$STORE_FILE" "$ts"
    _backup_diff_file tacctl.yaml "${dir}/tacctl.yaml" "$TACCTL_OVERRIDES_FILE" "$ts"
}

# Diff of the live tacquito.yaml against old-style backup file $2 (id $1).
_backup_diff_legacy() {
    local ts="$1" file="$2"
    echo ""
    echo -e "${BOLD}Diff: current config vs backup ${ts}${NC}"
    echo "--------------------------------------------"
    diff -u \
        --label "backup/${ts}" \
        --label "current" \
        --color=always "$file" "$CONFIG" || true
}

# Is $1 the id of a snapshot directory?
_backup_is_snapshot() {
    [[ "$1" =~ $BACKUP_SNAPSHOT_RE && -d "${BACKUP_DIR}/$1" && ! -L "${BACKUP_DIR}/$1" ]]
}

_backup_list() {
    local ids=() entries=() id path size entry
    mapfile -t ids < <(_backup_snapshot_ids)
    mapfile -t entries < <(_backup_legacy_entries)
    echo ""
    echo -e "${BOLD}Config Backups${NC}"
    echo "--------------------------------------------"
    if [[ "$(model_mode)" == "legacy" ]]; then
        echo "  No store yet: 'backup diff' and 'backup restore' work on old-style backups only."
    fi
    if (( ${#ids[@]} + ${#entries[@]} == 0 )); then
        echo "  No backups found."
        echo ""
        return 0
    fi
    printf "  ${BOLD}%-36s %-10s %-8s${NC}\n" "TIMESTAMP" "KIND" "SIZE"
    echo "  ------------------------------------------------------"
    for id in "${ids[@]}"; do
        size=$(du -sh "${BACKUP_DIR}/${id}" 2>/dev/null | awk '{print $1}')
        printf "  %-36s %-10s %-8s\n" "$id" "snapshot" "$size"
    done
    for entry in "${entries[@]}"; do
        IFS=$'\t' read -r id path <<< "$entry"
        size=$(du -sh "$path" 2>/dev/null | awk '{print $1}')
        printf "  %-36s %-10s %-8s\n" "$id" "old-style" "$size"
    done
    echo ""
    echo "  Old-style entries restore with 'tacctl backup restore <timestamp> --legacy'."
    echo ""
}

_backup_diff() {
    local id="${1:-}" path

    if [[ -z "$id" ]]; then
        # The most recent backup: a snapshot with a store, else an old-style file.
        if [[ "$(model_mode)" == "store" ]]; then
            id=$(_backup_snapshot_ids | head -n 1 || true)
            if [[ -z "$id" ]]; then
                error "No snapshots found."
                return 1
            fi
        else
            id=$(_backup_legacy_entries | head -n 1 | cut -f1 || true)
            if [[ -z "$id" ]]; then
                error "No backups found."
                return 1
            fi
        fi
    fi

    if _backup_is_snapshot "$id"; then
        if [[ "$(model_mode)" != "store" ]]; then
            error "Snapshot ${id} holds the store, which is not initialised here. ${STORE_NOT_INITIALISED_MSG}"
            return 1
        fi
        _backup_diff_snapshot "$id"
    elif path=$(_backup_legacy_path "$id"); then
        _backup_diff_legacy "$id" "$path"
    else
        error "Backup not found: ${id}"
        error "Run 'tacctl backup list' to see available backups."
        return 1
    fi
    echo ""
}

# Ask the operator; 0 only on y/Y.
_backup_confirm() {
    local confirm
    read -rp "  Restore this backup? [y/N]: " confirm || true
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        return 1
    fi
}

# Install file $1 as $2 through a temporary file beside it and a rename, so a
# reader never sees a half-written file. With a mode $3 the file gets it;
# without, it keeps the mode and owner of $1.
_backup_put() {
    local src="$1" dst="$2" mode="${3:-}" tmp="${2}.tacctl-new"
    if [[ -n "$mode" ]]; then
        cp "$src" "$tmp" || { rm -f "$tmp"; return 1; }
        chmod "$mode" "$tmp"
    else
        cp -p "$src" "$tmp" || { rm -f "$tmp"; return 1; }
    fi
    mv -f "$tmp" "$dst" || { rm -f "$tmp"; return 1; }
}

# Put the four files a restore can touch back as _backup_apply saved them in
# $1: store.yaml, tacctl.yaml, tacquito.yaml and rendered.json. A file that was
# absent then is removed now.
_backup_apply_rollback() {
    local keep="$1" f dst name
    for f in "${STORE_FILE}:store.yaml" "${TACCTL_OVERRIDES_FILE}:tacctl.yaml" \
             "${CONFIG}:tacquito.yaml" "${RENDERED_FILE}:rendered.json"; do
        dst="${f%:*}"
        name="${f##*:}"
        if [[ -f "${keep}/${name}" ]]; then
            _backup_put "${keep}/${name}" "$dst" || warn "Could not put ${dst} back."
        else
            rm -f "$dst"
        fi
    done
    rm -rf "$keep"
    _model_invalidate
    _conf_invalidate
}

# _backup_apply <writer> [<arg>...]
# Run <writer>, which installs the restored store (and tacctl.yaml) as the
# live files, then force-render tacquito.yaml from them. If either fails, the
# four files are put back as they were -- store.yaml, tacctl.yaml, tacquito.yaml
# and rendered.json -- so store, overrides, rendered config and its record
# always agree. Returns 0 applied, 1 failed and rolled back.
_backup_apply() {
    local keep f rc=0
    keep=$(mktemp -d "${TACCTL_STATE_DIR}/.restore.XXXXXX") || return 1
    for f in "${STORE_FILE}:store.yaml" "${TACCTL_OVERRIDES_FILE}:tacctl.yaml" \
             "${CONFIG}:tacquito.yaml" "${RENDERED_FILE}:rendered.json"; do
        if [[ -f "${f%:*}" ]]; then
            cp -p "${f%:*}" "${keep}/${f##*:}" || { rm -rf "$keep"; return 1; }
        fi
    done
    _BACKUP_SNAPSHOT_HELD=1
    "$@" || rc=$?
    # --force: a restore is an explicit overwrite, the operator has seen the
    # diff, and a hand-edited tacquito.yaml is kept under backups/legacy/.
    if (( rc == 0 )); then
        tacacs_render_apply --force > /dev/null || rc=$?
    fi
    _BACKUP_SNAPSHOT_HELD=0
    if (( rc != 0 )); then
        _backup_apply_rollback "$keep"
        return 1
    fi
    rm -rf "$keep"
    return 0
}

# Writer for _backup_apply: make snapshot directory $1 the live store.yaml
# and tacctl.yaml (no tacctl.yaml in it means none now).
_backup_install_snapshot() {
    local dir="$1"
    _backup_put "${dir}/store.yaml" "$STORE_FILE" 600 || return 1
    if [[ -f "${dir}/tacctl.yaml" ]]; then
        _backup_put "${dir}/tacctl.yaml" "$TACCTL_OVERRIDES_FILE" 640 || return 1
        chown tacquito:tacquito "$TACCTL_OVERRIDES_FILE" 2>/dev/null || true
    else
        rm -f "$TACCTL_OVERRIDES_FILE"
    fi
    _model_invalidate
    _conf_invalidate
}

# Writer for _backup_apply: import old-style backup $1 over the store.
_backup_import_legacy() {
    store_import --replace "$1" > /dev/null
}

_backup_restore_snapshot() {
    local id="$1" dir="${BACKUP_DIR}/$1" problems
    if [[ ! -f "${dir}/store.yaml" ]]; then
        error "Snapshot ${id} has no store.yaml. Nothing was changed."
        return 1
    fi
    # Everything that can be checked without touching a live file is checked
    # first. What only the render can tell (the read-back of the rendered
    # config) is covered by _backup_apply's rollback.
    if ! store_validate "${dir}/store.yaml"; then
        error "Snapshot ${id} cannot be restored: its store.yaml is not valid. Nothing was changed."
        return 1
    fi
    problems=$(TACCTL_OVERRIDES_FILE="${dir}/tacctl.yaml" _conf_validate_overrides_file) || true
    if [[ -n "$problems" ]]; then
        printf '%s\n' "$problems" | sed 's/^/  tacctl.yaml: /' >&2
        error "Snapshot ${id} cannot be restored: its tacctl.yaml is not valid. Nothing was changed."
        return 1
    fi

    echo ""
    echo "  Restoring snapshot: ${id}"
    _backup_diff_snapshot "$id"
    echo ""
    _backup_confirm || return 0

    # The current state first, so the restore can be undone with another one.
    # Retention must not take the snapshot being read in the process.
    _BACKUP_KEEP_ID="$id"
    backup_snapshot || { error "Could not snapshot the current state. Nothing was changed."; return 1; }
    if ! _backup_apply _backup_install_snapshot "$dir"; then
        error "Snapshot ${id} was not restored: ${CONFIG} could not be rendered from it. Store, tacctl.yaml and ${CONFIG} are as they were."
        return 1
    fi
    restart_service
    info "Restored snapshot ${id}."
    echo ""
}

_backup_restore_legacy() {
    local id="$1" file
    if ! file=$(_backup_legacy_path "$id"); then
        error "Old-style backup not found: ${id}"
        error "Run 'tacctl backup list' to see available backups."
        return 1
    fi
    echo ""
    echo "  Checking that the store can take ${file}"
    if ! store_import --check "$file"; then
        error "Old-style backup ${id} cannot be restored: the importer's check failed (see above). Nothing was changed."
        error "To import it anyway: 'tacctl store import --replace ${file}', then 'tacctl config render --force'."
        return 1
    fi

    echo ""
    echo "  Restoring old-style backup: ${id}"
    _backup_diff_legacy "$id" "$file"
    echo ""
    _backup_confirm || return 0

    backup_snapshot || { error "Could not snapshot the current state. Nothing was changed."; return 1; }
    if ! _backup_apply _backup_import_legacy "$file"; then
        error "Old-style backup ${id} was not restored. Store, tacctl.yaml and ${CONFIG} are as they were."
        return 1
    fi
    restart_service
    info "Restored old-style backup ${id}."
    echo ""
}

# No store yet: copy the old-style file back, as it always did.
_backup_restore_unflipped() {
    local id="$1" file
    if ! file=$(_backup_legacy_path "$id"); then
        if _backup_is_snapshot "$id"; then
            error "Snapshot ${id} holds the store, which is not initialised here. ${STORE_NOT_INITIALISED_MSG}"
        else
            error "Backup not found: ${id}"
            error "Run 'tacctl backup list' to see available backups."
        fi
        return 1
    fi

    echo ""
    echo "  Restoring config from: ${id}"
    echo ""
    echo -e "  ${BOLD}Changes that will be applied:${NC}"
    diff --color=always "$CONFIG" "$file" || true
    echo ""
    _backup_confirm || return 0

    # Back up current config before restoring (safety net)
    backup_config
    cp "$file" "$CONFIG"
    chown tacquito:tacquito "$CONFIG"
    chmod 640 "$CONFIG"
    restart_service
    info "Config restored from backup ${id}."
    echo ""
}

_backup_restore() {
    local id="" legacy=0 arg
    for arg in "$@"; do
        case "$arg" in
            --legacy) legacy=1 ;;
            -*)
                error "Unknown option '${arg}'. Usage: tacctl backup restore <timestamp> [--legacy]"
                return 1
                ;;
            *)
                if [[ -n "$id" ]]; then
                    error "Only one timestamp may be given."
                    return 1
                fi
                id="$arg"
                ;;
        esac
    done
    if [[ -z "$id" ]]; then
        error "Usage: tacctl backup restore <timestamp> [--legacy]"
        error "Run 'tacctl backup list' to see available backups."
        return 1
    fi

    if [[ "$(model_mode)" != "store" ]]; then
        _backup_restore_unflipped "$id"
    elif (( legacy )); then
        _backup_restore_legacy "$id"
    elif _backup_is_snapshot "$id"; then
        _backup_restore_snapshot "$id"
    elif _backup_legacy_path "$id" > /dev/null; then
        error "${id} is an old-style backup. Restore it with: tacctl backup restore ${id} --legacy"
        return 1
    else
        error "Backup not found: ${id}"
        error "Run 'tacctl backup list' to see available backups."
        return 1
    fi
}

cmd_backup() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        list)    _backup_list ;;
        diff)    _backup_diff "$@" ;;
        restore) _backup_restore "$@" ;;
        *)
            echo ""
            echo -e "${BOLD}Backup Commands${NC}"
            echo ""
            echo "Usage: tacctl backup <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                           Show snapshots, then old-style backups"
            echo "  diff [timestamp]               Diff store.yaml and tacctl.yaml against a snapshot (default: most recent)"
            echo "  restore <timestamp> [--legacy] Restore a snapshot (with confirmation); --legacy for an old-style backup"
            echo ""
            exit 1
            ;;
    esac
}
