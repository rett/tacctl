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
    local posture_json
    posture_json=$(python3 - "$CONFIG" "$SECRET_MIN_LENGTH" <<'PY' 2>/dev/null
import json, re, sys, yaml
cfg_path = sys.argv[1]
min_secret = int(sys.argv[2])
with open(cfg_path) as f:
    d = yaml.safe_load(f) or {}

# Collect CIDRs + secret lengths per scope (from secrets: list).
all_cidrs = []
weak_scopes = []
placeholder_scopes = []
empty_prefix_scopes = []
for s in (d.get('secrets') or []):
    name = s.get('name') or '(unnamed)'
    key = (s.get('secret') or {}).get('key') or ''
    opts = s.get('options') or {}
    pfx = opts.get('prefixes') or ''
    cidrs = []
    try:
        cidrs = json.loads(pfx) if pfx else []
    except Exception:
        cidrs = re.findall(r'"([^"]+)"', pfx)
    if not cidrs:
        empty_prefix_scopes.append(name)
    all_cidrs.extend(cidrs)
    if 'REPLACE' in key:
        placeholder_scopes.append(name)
    elif len(key) < min_secret:
        weak_scopes.append(f"{name}:{len(key)}")

cfg_text = open(cfg_path).read()
def flat_list(key):
    m = re.search(r'^' + key + r':\s*\[(.*?)\]', cfg_text, re.MULTILINE)
    return re.findall(r'"([^"]+)"', m.group(1)) if m and m.group(1).strip() else []
allow = flat_list('prefix_allow')

def has_v6(lst):
    return any(':' in c for c in lst)

rfc1918 = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
unrestricted = rfc1918.issubset(set(all_cidrs)) and len(all_cidrs) == 3

print(f"prefix_count={len(all_cidrs)}")
print(f"prefix_unrestricted={'1' if unrestricted else '0'}")
print(f"prefix_has_v6={'1' if has_v6(all_cidrs) else '0'}")
print(f"allow_has_v6={'1' if has_v6(allow) else '0'}")
print(f"placeholder_scopes={','.join(placeholder_scopes)}")
print(f"weak_scopes={','.join(weak_scopes)}")
print(f"empty_prefix_scopes={','.join(empty_prefix_scopes)}")
PY
)
    local prefix_count=0 prefix_unrestricted=0 prefix_has_v6=0 allow_has_v6=0
    local placeholder_scopes="" weak_scopes="" empty_prefix_scopes=""
    if [[ -n "$posture_json" ]]; then
        eval "$posture_json"
    fi

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

    # Scopes: multi-scope posture. Orphan detection = any user referencing
    # a scope name that has no matching secrets[] entry.
    local all_scopes scope_count="0"
    all_scopes=$(list_scopes)
    [[ -n "$all_scopes" ]] && scope_count=$(printf '%s\n' "$all_scopes" | wc -l)
    local orphan_report
    orphan_report=$(python3 - "$CONFIG" <<'PY' 2>/dev/null
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
names = {s.get('name') for s in (d.get('secrets') or []) if s.get('name')}
empty_scopes = set(names)
orphans = []
total_refs = 0
for u in (d.get('users') or []):
    uname = u.get('name')
    for s in (u.get('scopes') or []):
        total_refs += 1
        if s in names:
            empty_scopes.discard(s)
        else:
            orphans.append(f"{uname}:{s}")
print(f"REFS={total_refs}")
print(f"EMPTY={','.join(sorted(empty_scopes))}")
for o in orphans:
    print(f"ORPHAN={o}")
PY
)
    local total_refs="0" empty_scopes=""
    if [[ -n "$orphan_report" ]]; then
        total_refs=$(echo "$orphan_report" | awk -F= '/^REFS=/{print $2}')
        empty_scopes=$(echo "$orphan_report" | awk -F= '/^EMPTY=/{print $2}')
    fi
    local orphan_lines
    orphan_lines=$(echo "$orphan_report" | awk -F= '/^ORPHAN=/{print $2}' || true)
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

    # Check required sections exist
    local result
    result=$(python3 -c "
import re, sys

config = open(sys.argv[1]).read()
DISABLED_MARKER = sys.argv[2]
errors = []

# Check for users section
if not re.search(r'^users:', config, re.MULTILINE):
    errors.append('Missing users: section')

# Check for secrets section
if not re.search(r'^secrets:', config, re.MULTILINE):
    errors.append('Missing secrets: section')

# Check for at least one user
users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
# 'root' is allowed as an accounting-only sink (install-time seed); it
# must carry the disabled-hash + accounter pattern, enforced below.
# 'tacquito' collides with the service user and is never legitimate.
RESERVED_AUTHABLE = {'tacquito'}
if users_match:
    users = re.findall(r'- name: (\S+)', users_match.group(1))
    if len(users) == 0:
        errors.append('No users defined')
    else:
        # Check each user has a bcrypt anchor + an accounter field, and
        # isn't using a reserved OS/service name. Missing accounter triggers
        # a stream of acct.go errors at auth time ('user [X] does not have
        # an accounter associated'); reserved names collide with local OS
        # accounts tacquito resolves outside the YAML.
        for u in users:
            if u in RESERVED_AUTHABLE:
                errors.append(f'User \"{u}\" uses a reserved name (remove with: tacctl user remove {u})')
            if not re.search(r'^bcrypt_' + re.escape(u) + r':', config, re.MULTILINE):
                errors.append(f'User \"{u}\" has no bcrypt authenticator anchor')
            # Every user entry must carry 'accounter: *file_accounter'
            # within its block. Bound the block with a look-ahead for the
            # next list item or the next top-level '# ---' heading.
            user_block = re.search(
                r'^  - name: ' + re.escape(u) + r'\s*\n((?:    .*\n|  #.*\n)+?)(?=^  - name:|^# ---|\Z)',
                users_match.group(1), re.MULTILINE)
            if user_block and 'accounter:' not in user_block.group(1):
                errors.append(f'User \"{u}\" has no accounter: field (tacquito will error on every auth)')

        # Check for disabled-marker or empty hashes
        for m in re.finditer(r'^bcrypt_(\w+):.*?hash:\s*(\S+)', config, re.MULTILINE | re.DOTALL):
            username = m.group(1)
            h = m.group(2)
            if h == 'REPLACE_ME':
                errors.append(f'User \"{username}\" has placeholder hash (REPLACE_ME)')
            elif h == DISABLED_MARKER:
                pass  # valid disabled-marker state
            elif len(h) < 20:
                errors.append(f'User \"{username}\" has suspiciously short hash')
            elif username == 'root':
                # Root must stay a disabled accounting sink. A real bcrypt
                # hash here means someone set a password for the sink,
                # which would make Junos's built-in root account
                # TACACS+-authable — a policy break.
                errors.append('User \"root\" has a real password set — must remain a disabled accounting sink')

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
" "$CONFIG" "$DISABLED_MARKER_HEX")

    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}Config structure:${NC}     valid"
    else
        while IFS= read -r line; do
            local msg="${line#ERROR:}"
            echo -e "  ${RED}Error:${NC}                ${msg}"
            errors=$((errors + 1))
        done <<< "$result"
    fi

    # Scope integrity: every user's scopes[] must reference an existing
    # secrets[].name; scope.default in tacctl.yaml must also name one.
    local default_scope_configured
    default_scope_configured=$(conf_get scope.default)
    local scope_report
    scope_report=$(python3 - "$CONFIG" "$default_scope_configured" <<'PY' 2>/dev/null
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
names = [s.get('name') for s in (d.get('secrets') or []) if s.get('name')]
name_set = set(names)
issues = []
# Flat-emission invariant: every entry sharing a name must share its
# secret.key. Divergence means one or more entries will auth with a
# stale key, producing non-deterministic "bad secret" failures on the
# subset of prefixes that rolled their key.
keys_by_name = {}
for s in (d.get('secrets') or []):
    nm = s.get('name')
    if not nm:
        continue
    k = (s.get('secret') or {}).get('key') or ''
    keys_by_name.setdefault(nm, []).append(k)
for nm, keys in keys_by_name.items():
    uniq = set(keys)
    if len(uniq) > 1:
        issues.append(f"Scope '{nm}' has {len(keys)} entries but {len(uniq)} distinct secret.key values — entries must share a key")
for u in (d.get('users') or []):
    uname = u.get('name')
    for s in (u.get('scopes') or []):
        if s not in name_set:
            issues.append(f"User '{uname}' references nonexistent scope '{s}'")
# Default-scope override (read from tacctl.yaml before we were invoked).
default_scope = sys.argv[2]
if default_scope and default_scope not in name_set:
    issues.append(f"Default scope override points at '{default_scope}' which is not a defined scope")
for i in issues:
    print(f"ERROR:{i}")
if not issues:
    print('OK')
PY
)
    if [[ "$scope_report" == "OK" ]]; then
        echo -e "  ${GREEN}Scopes integrity:${NC}     valid"
    else
        while IFS= read -r line; do
            [[ "$line" == ERROR:* ]] || continue
            local msg="${line#ERROR:}"
            echo -e "  ${RED}Error:${NC}                ${msg}"
            errors=$((errors + 1))
        done <<< "$scope_report"
    fi

    # Check services
    local svc_count
    # Match shell (current template), exec (pre-0.1.2 legacy installs),
    # and junos-exec. Exec anchors can carry either service name
    # depending on install vintage.
    svc_count=$(grep -c "name: shell\|name: exec\|name: junos-exec" "$CONFIG" 2>/dev/null || echo 0)
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

