# shellcheck shell=bash
# tacctl lib/service.sh -- snapshots and backups, listen-address validator, status, validate, log
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

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
# Called by store_apply (lib/backend.sh) and, through store_snapshot_hook, by every store write.
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
# The check itself is the listener model's (lib/conf.sh: _listener_py), so
# the CLI and the tacctl.yaml schema cannot disagree.
validate_listen_address() {
    local net="$1" addr="$2"
    if ! python3 <(_listener_py; printf '%s\n' 'import sys' \
            'sys.exit(1 if listen_address_problem(sys.argv[1], sys.argv[2]) else 0)') "$net" "$addr" 2>/dev/null
    then
        error "Invalid ${net} address: '${addr}'"
        return 1
    fi
}

# =====================================================================
#  STATUS & VALIDATION COMMANDS
# =====================================================================

# --- STATUS ---
cmd_status() {
    echo ""
    echo -e "${BOLD}Service Status${NC}"
    echo "--------------------------------------------"

    # With one enabled backend it prints its own lines, in the places this
    # report has always had them. With more, each backend gets a labelled
    # section of its own (below, after the backup count) with all of its lines,
    # and what is not any backend's stays up here.
    _backends_load || return 1
    local multi=0 _b
    (( ${#BACKENDS_ENABLED[@]} > 1 )) && multi=1

    # Service state, uptime, PID, memory, listener, log level
    (( multi )) || backends_run status service

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
    (( multi )) || backends_run status config
    if [[ "$(model_mode)" == "legacy" ]]; then
        echo -e "  ${YELLOW}Store:                not initialised — read-only until 'tacctl store import' (see 'tacctl store import --check')${NC}"
    fi
    # Drift: a backend's own artifacts are reported in its section.
    if (( multi )); then
        print_drift_lines --unowned || true
    else
        print_drift_lines || true
    fi

    # Accounting log size
    (( multi )) || backends_run status accounting

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

    # Authentication stats and recent errors
    if (( multi )); then
        for _b in "${BACKENDS_ENABLED[@]}"; do
            backend_heading "$_b"
            backend_call "$_b" status service
            backend_call "$_b" status config
            backend_call "$_b" status accounting
            print_drift_lines "$_b" || true
            backend_call "$_b" status activity
        done
    else
        backends_run status activity
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

    # IPv6 parity warning: if a listener is on an IPv6 network (tcp6, udp6) but
    # no IPv6 CIDR exists anywhere in prefixes/allow, IPv4-mapped addresses can
    # bypass ACLs. Scopes are shared by every backend, so any backend's
    # listener counts; the message names the first one (and its backend, when
    # there is more than one).
    local listener_net="" listener_who="listener" _lname _lnet _laddr
    for _b in "${BACKENDS_ENABLED[@]}"; do
        while read -r _lname _lnet _laddr; do
            if [[ "$_lnet" == *6 && -z "$listener_net" ]]; then
                listener_net="$_lnet"
                (( multi )) && listener_who="${_b} listener ${_lname}"
            fi
        done < <(backend_call "$_b" listeners list)
    done
    if [[ -n "$listener_net" ]]; then
        if [[ "$prefix_has_v6" != "1" && "$allow_has_v6" != "1" ]]; then
            echo -e "    ${RED}IPv6 ACL parity:    MISSING (${listener_who} is ${listener_net} but no IPv6 CIDRs — v4-mapped clients bypass ACLs)${NC}"
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

    # Rendered artifacts: can the store be rendered, and are the live files
    # that render? A hand-edited file is reported by the DRIFT line instead,
    # and counted once. With one enabled backend these are plain lines; with
    # more, each backend has a labelled block of its own (a drifted artifact
    # of one backend does not hide the render state of another), and the
    # artifacts no backend claims are reported first. What a disabled backend
    # left behind is not reported: nothing serves it.
    if [[ "$mode" == "store" ]]; then
        if ! _backends_load; then
            errors=$((errors + 1))
            BACKENDS_ENABLED=()
        fi
    elif ! _backends_load 2> /dev/null; then
        BACKENDS_ENABLED=()
    fi
    local multi=0 rstate="" _b label drifted ind=""
    local -a targets=(${BACKENDS_ENABLED[@]+"${BACKENDS_ENABLED[@]}"})
    (( ${#targets[@]} > 1 )) && multi=1
    (( ${#targets[@]} )) || targets=("")
    if (( multi )) && ! backends_check_drift --unowned > /dev/null; then
        print_drift_lines --unowned || true
        errors=$((errors + 1))
    fi
    for _b in "${targets[@]}"; do
        drifted=0
        if (( multi )); then
            echo -e "  ${BOLD}Backend ${_b}:${NC}"
            ind="  "
            backends_check_drift "$_b" > /dev/null || drifted=1
        else
            backends_check_drift > /dev/null || drifted=1
        fi
        if [[ "$mode" == "store" && -n "$_b" ]]; then
            label=$(backend_artifact_names "$_b") || label="$_b"
            if ! rstate=$(backend_call "$_b" render_check); then
                echo -e "${ind}  ${RED}Rendered config:${NC}      the store cannot be rendered (see above)"
                errors=$((errors + 1))
            elif (( drifted )); then
                :
            else
                case "$rstate" in
                    current|same)
                        echo -e "${ind}  ${GREEN}Rendered config:${NC}      up to date"
                        ;;
                    missing)
                        echo -e "${ind}  ${RED}Rendered config:${NC}      ${label} is missing — run 'tacctl config render'"
                        errors=$((errors + 1))
                        ;;
                    unrecorded)
                        echo -e "${ind}  ${YELLOW}Rendered config:${NC}      ${label} was not rendered by tacctl yet — the next change replaces it if it says what the store says; otherwise run 'tacctl config render --force'"
                        ;;
                    *)
                        echo -e "${ind}  ${RED}Rendered config:${NC}      ${label} is out of date with the store — run 'tacctl config render'"
                        errors=$((errors + 1))
                        ;;
                esac
            fi
        fi
        if (( drifted )); then
            if (( multi )); then print_drift_lines "$_b" || true; else print_drift_lines || true; fi
            errors=$((errors + 1))
        fi
        # RADIUS sends a vendor's privilege attribute only where a scope opts
        # in. A scope that opts into none is right for Linux hosts and wrong
        # for network devices; the Linux-host scopes are told apart by the
        # host registry (model_vendor_gaps). A warning, not an error: a
        # scope of devices that need no attribute is legitimate.
        if [[ "$mode" == "store" && "$_b" == "radius" ]]; then
            local gaps
            gaps=$(model_vendor_gaps 2> /dev/null | paste -sd, || true)
            if [[ -n "$gaps" ]]; then
                echo -e "${ind}  ${YELLOW}Vendor attributes:${NC}    not sent to the devices of scope(s) ${gaps//,/, } over RADIUS: Cisco, Juniper and WTI devices there get Service-Type only"
                echo -e "${ind}                        (Linux hosts need none). Enable what they need: tacctl scope vendor-attrs <scope> enable cisco|juniper|wti"
            fi
        fi
    done
    ind=""

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

# =====================================================================
#  LOG COMMANDS
# =====================================================================

# Each backend prints its own section (lib/backend.sh: log, accounting): every
# enabled backend, or the one --backend names. With more than one at work each
# section has a heading naming its backend; with one, the output is what it
# always was.
cmd_log() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        tail|search|failures|clear|accounting)
            local -a rest=() ids=()
            local only="" _b multi=0
            while (( $# )); do
                case "$1" in
                    --backend)
                        if [[ -z "${2:-}" ]]; then
                            error "--backend needs a backend id. Usage: tacctl log ${subcmd} [--backend <id>] ..."
                            return 1
                        fi
                        only="$2"
                        shift 2
                        ;;
                    --backend=*) only="${1#*=}"; shift ;;
                    *)           rest+=("$1"); shift ;;
                esac
            done
            _backends_load || return 1
            if [[ -n "$only" ]]; then
                if ! backend_registered "$only"; then
                    error "Unknown backend '${only}' (known: ${BACKEND_IDS[*]})."
                    return 1
                fi
                ids=("$only")
            else
                ids=("${BACKENDS_ENABLED[@]}")
            fi
            (( ${#ids[@]} > 1 )) && multi=1
            for _b in "${ids[@]}"; do
                (( multi )) && backend_heading "$_b"
                if [[ "$subcmd" == "accounting" ]]; then
                    backend_call "$_b" accounting tail ${rest[@]+"${rest[@]}"}
                else
                    backend_call "$_b" log "$subcmd" ${rest[@]+"${rest[@]}"}
                fi
            done
            ;;
        *)
            echo ""
            echo -e "${BOLD}Log Commands${NC}"
            echo ""
            echo "Usage: tacctl log <subcommand> [--backend <id>] [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  tail [n]              Show the last N log entries (default 20; TACACS+: journal, RADIUS: auth and daemon log)"
            echo "  search <term>         Search the logs for a username or keyword"
            echo "  failures              Show auth failures from the last 24 hours"
            echo "  accounting [n]        Show last N accounting log entries"
            echo "  clear [--force|-y]    Purge each backend's logs: journal or auth log, accounting log (confirms)"
            echo ""
            echo "With more than one backend enabled each subcommand shows every backend's log in a"
            echo "section of its own; --backend <id> shows only that backend's."
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

# Put store.yaml and tacctl.yaml back as _backup_apply saved them in $1. A
# file that was absent then is removed now.
_backup_apply_rollback() {
    local keep="$1" f dst name
    for f in "${STORE_FILE}:store.yaml" "${TACCTL_OVERRIDES_FILE}:tacctl.yaml"; do
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
# live files, then force-render every enabled backend from them. A render
# that fails leaves every rendered config and rendered.json as they were
# (backends_render_all); store.yaml and tacctl.yaml are then put back here,
# so store, overrides, rendered configs and their records always agree.
# Returns 0 applied, 1 failed and rolled back.
_backup_apply() {
    local keep f rc=0
    keep=$(mktemp -d "${TACCTL_STATE_DIR}/.restore.XXXXXX") || return 1
    for f in "${STORE_FILE}:store.yaml" "${TACCTL_OVERRIDES_FILE}:tacctl.yaml"; do
        if [[ -f "${f%:*}" ]]; then
            cp -p "${f%:*}" "${keep}/${f##*:}" || { rm -rf "$keep"; return 1; }
        fi
    done
    _BACKUP_SNAPSHOT_HELD=1
    "$@" || rc=$?
    # --force: a restore is an explicit overwrite, the operator has seen the
    # diff, and a hand-edited rendered config is kept under backups/legacy/.
    if (( rc == 0 )); then
        backends_render_all --force || rc=$?
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

# The backends a snapshot's tacctl.yaml enables, one per line.
_backup_snapshot_enabled() {
    (
        TACCTL_OVERRIDES_FILE="${1}/tacctl.yaml"
        _conf_invalidate
        _backends_load && printf '%s\n' "${BACKENDS_ENABLED[@]}"
    )
}

# A restore brings back the snapshot's backends.enabled with the rest of
# tacctl.yaml, and the daemons follow it the way 'tacctl backend enable' and
# 'disable' do: a backend it enables is enabled at boot (the restart that
# follows starts it), one it takes out is stopped and disabled. $1 is the
# enabled list before the restore, space-separated.
_backup_reconcile_backends() {
    local before=" $1 " _b
    _backends_load || return 1
    for _b in "${BACKENDS_ENABLED[@]}"; do
        [[ "$before" == *" ${_b} "* ]] && continue
        info "Backend '${_b}' is enabled by this snapshot."
        backend_call "$_b" service enable || warn "Could not enable the service of backend '${_b}' at boot."
    done
    for _b in $1; do
        [[ " ${BACKENDS_ENABLED[*]} " == *" ${_b} "* ]] && continue
        info "Backend '${_b}' is not enabled by this snapshot: stopping and disabling its service."
        backend_call "$_b" service stop || warn "Could not stop the service of backend '${_b}'."
        backend_call "$_b" service disable || warn "Could not disable the service of backend '${_b}'."
    done
    return 0
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

    # The backends it enables must be on this machine: a restore cannot
    # install one. (Nothing is touched yet.)
    local before_enabled snap_enabled _b
    _backends_load || return 1
    before_enabled="${BACKENDS_ENABLED[*]}"
    snap_enabled=$(_backup_snapshot_enabled "$dir") || snap_enabled=""
    for _b in $snap_enabled; do
        # One that is enabled already is running here.
        [[ " ${before_enabled} " == *" ${_b} "* ]] && continue
        if ! backend_call "$_b" installed; then
            error "Snapshot ${id} enables backend '${_b}', which is not installed here. Run 'tacctl backend enable ${_b}' first. Nothing was changed."
            return 1
        fi
    done

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
        error "Snapshot ${id} was not restored: $(backends_artifact_names) could not be rendered from it. Store, tacctl.yaml and $(backends_artifact_names) are as they were."
        return 1
    fi
    _backup_reconcile_backends "$before_enabled" || true
    backends_restart_all
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
        error "Old-style backup ${id} was not restored. Store, tacctl.yaml and $(backends_artifact_names) are as they were."
        return 1
    fi
    backends_restart_all
    info "Restored old-style backup ${id}."
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
