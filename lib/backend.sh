# shellcheck shell=bash
# shellcheck disable=SC2034  # registry and result globals assigned here are read by the other lib files
# tacctl lib/backend.sh -- backend registry and contract, enabled backends, rendered-artifact bookkeeping and drift, render/restart across backends, the mutation path (store_apply), 'tacctl config render'
# Sourced by bin/tacctl.sh before lib/backends/*.sh (see the load block there for ordering); not executable.
#
# A backend is a daemon that serves the model (lib/model.sh) over one
# protocol: tacquito for TACACS+ (lib/backends/tacacs.sh), FreeRADIUS for
# RADIUS next. Everything protocol-neutral -- the store, tacctl.yaml,
# snapshots, the commands that change users, groups and scopes -- talks to
# a daemon only through the verbs below, so a second backend is one more
# module and no edits here.
#
# --- The contract -----------------------------------------------------------
#
# A module lib/backends/<id>.sh appends <id> to BACKEND_IDS when sourced and
# defines one function backend_<id>_<verb> per entry of BACKEND_VERBS.
# Generic code calls them through backend_call (one backend) or the
# backends_* helpers (every enabled backend). tests/unit/backend.bats fails
# when a registered backend lacks a verb.
#
#   describe            key=value lines: protocol, impl, units, user,
#                       config_dir, log_dir. Read one with backend_describe.
#   installed           0 when the daemon and its unit are on this machine.
#   install <phase> <tree>
#   upgrade <phase> <tree>
#   uninstall <phase> [--keep-logs]
#                       One step of the lifecycle command; <tree> is the
#                       tacctl checkout shipped files are taken from
#                       (config/backends/<id>/). The phases are the points
#                       at which the generic command hands over (see
#                       BACKEND_*_PHASES below); a module does nothing, and
#                       returns 0, for a phase it has no work in. They run
#                       with errexit as the commands always did: a failing
#                       step aborts the run.
#   artifacts           the files this backend renders, one absolute path
#                       per line, whether or not they exist yet.
#   render_check        trial render of the current store, nothing
#                       installed. Prints one word for the live artifacts
#                       against that render: current | same (identical, not
#                       recorded) | ok (differs; it is what tacctl last
#                       rendered) | drift | unrecorded | missing |
#                       unreadable. Returns 1, message on stderr, when the
#                       store cannot be rendered. A backend with a config
#                       checker (freeradius -CX) runs it here.
#   render_gate         may a mutating command replace the artifacts?
#                       0 yes; 10 yes, and they must be adopted (rendered
#                       with force: tacctl never rendered them, but they say
#                       what the store says); 3 refused, they hold edits
#                       tacctl would discard; 1 failed. Messages on stderr.
#   render_stage <dir> [--force]
#                       render the current store and tacctl.yaml into the
#                       private directory <dir>, prove the result (read it
#                       back, run the daemon's checker), and decide whether
#                       the live artifacts may be replaced. Touches nothing
#                       outside <dir>. 0 staged; 1 failed; 3 refused
#                       (drift, and no --force). Prints nothing on stdout.
#   render_commit <dir>
#                       install what render_stage left in <dir>: each
#                       artifact by rename, owner and mode set, checksum
#                       recorded (rendered_record). Prints CHANGED or
#                       UNCHANGED on stdout, messages on stderr. 1 failed.
#   render_notes        after 'tacctl config render': warn about anything
#                       the rendered state means for this daemon (tacquito
#                       refuses a config without users). Usually silent.
#   service <start|stop|restart|reload|is-active|since|pid>
#                       'restart' reports its own outcome and never fails
#                       the caller; 'is-active' prints and returns what
#                       systemctl does.
#   listeners list      one '<name> <network> <address>' line per listener,
#                       effective values. (Setting one is still the TACACS+
#                       module's 'tacctl config listen'; show/set/reset join
#                       this verb with the listener model.)
#   status <service|config|accounting|activity>
#                       this backend's lines of 'tacctl status', one part
#                       per place the report has always had them.
#   log <tail [n]|search <term>|failures|clear [-y]>
#                       the daemon's log, as 'tacctl log' prints it. 'clear'
#                       confirms, and covers the accounting log too.
#   accounting tail [n] the accounting log, as 'tacctl log accounting'.
#   last_login <user>   'YYYY-MM-DD HH:MM:SS', or 'never'.
#   secret_constraints  max_len= and charset= (a bracket expression) the
#                       daemon puts on a shared secret; empty = no limit.
#   device_vars <vendor> <scope>
#                       KEY=VALUE lines for the device templates of this
#                       protocol; none when the template needs nothing from
#                       the daemon.
#
# Against plan 3.2: 'render' became render_gate + render_stage +
# render_commit (see the next section) and reads the current store instead
# of taking a model file -- the model is one shared, cached document
# (model_dump), and writing it to a file per backend would only add copies
# of the secrets. 'validate' is render_check, because the proof of a config
# is part of rendering it. 'health' (JSON) became 'status <part>': the
# counters differ per daemon (Decision 12), so each module prints its own
# lines and nothing has to parse JSON in bash. install, upgrade and
# uninstall take a phase, because the generic commands have work of their
# own between the daemon's steps (the CLI is deployed after the daemon is
# built; the config is rendered after the service account exists and before
# the unit starts). 'accounting clear' is gone: one confirmation in
# 'log clear' has always covered both logs. artifacts and render_notes are
# new. 'listeners' is only as wide as today's single listener needs.
#
# Commands that exist for one daemon only -- 'config listen', 'config
# loglevel', 'config metrics', 'store import' and 'store rollback' -- are
# that backend's own CLI. The dispatcher calls them by name; they are not
# generic code reaching into a daemon, and not part of the contract.
#
# --- Two backends: what is shared, what is per backend ----------------------
#
# Shared: the truth. store.yaml and tacctl.yaml are one pair of files, so a
# mutation is one write, a snapshot is one directory (backups/<ts>/), and
# rollback of a failed command restores one pair. rendered.json is one file
# too, {path: sha256}; paths never collide between backends and
# 'artifacts' says whose a path is.
#
# Per backend: the artifacts, their drift state, the gate, the restart.
#
# The mutation path (store_apply) with N backends:
#
#   1. gate      every enabled backend's render_gate, before anything is
#                written. One refusal refuses the command. A backend that
#                answers 10 is rendered with force in step 4, the others
#                are not.
#   2. snapshot  backup_snapshot, once.
#   3. write     the caller's writer, once.
#   4. render    backends_render_all, in two passes so that either every
#                backend's artifacts are replaced or none is:
#                  stage   every backend renders into a private directory
#                          and proves the result. A failure here -- a model
#                          one daemon cannot express, a failed read-back, a
#                          checker that rejects the config -- stops the
#                          command with no artifact touched.
#                  commit  only renames and checksum records remain. The
#                          artifacts and rendered.json are copied first; if
#                          a commit still fails (disk full, a directory
#                          gone), every artifact already replaced and
#                          rendered.json are put back from the copies.
#                So a failed render leaves all artifacts as they were, and
#                store_apply then puts store.yaml and tacctl.yaml back: the
#                store never disagrees with a rendered artifact because one
#                backend failed after another succeeded.
#   5. restart   only the backends whose commit said CHANGED.
#
# What remains possible is a crash between two renames of step 4, or a
# restore that itself fails (it warns per file). Both leave an artifact
# that is not what the store renders, and neither is silent:
# 'tacctl config validate' reports "out of date with the store" for it,
# and 'tacctl config render' repairs it.
#
# Drift is per artifact: backends_check_drift walks rendered.json whatever
# backend recorded the path. A drifted artifact refuses its backend's gate
# and with it every mutation, on purpose -- applying a change to one
# protocol and not the other is the disagreement this design exists to
# prevent.
#
# Legacy mode (no store.yaml yet) predates backends. Only a TACACS+ install
# can be in it: its tacquito.yaml is still the source of truth. The code for
# that mode -- the import gate of upgrade, 'store rollback', the in-place
# migrations, old-style restore -- lives in lib/backends/tacacs.sh and is
# called by name from the few places that branch on model_mode. It is not
# part of the contract because no other backend can ever be in that mode.

# --- Registry ---------------------------------------------------------------

# Filled by the modules as they are sourced.
BACKEND_IDS=()

# Every verb a module must define (backend_<id>_<verb>).
BACKEND_VERBS=(describe installed install upgrade uninstall
               artifacts render_check render_gate render_stage render_commit render_notes
               service listeners status log accounting last_login
               secret_constraints device_vars)

# Lifecycle phases, in the order the generic commands run them. Everything
# up to 'account' comes before the first render of an install, 'start' after.
BACKEND_INSTALL_PHASES=(build files account start)
BACKEND_UPGRADE_PHASES=(preflight config build files finish)
BACKEND_UNINSTALL_PHASES=(stop program data account)

# backends.enabled when tacctl.yaml does not set it. The schema in
# lib/conf.sh carries the same default (a unit test pins the two together).
BACKENDS_DEFAULT_ENABLED=(tacacs)

# {path: sha256} of every artifact tacctl rendered (plan 4.5).
RENDERED_FILE="${TACCTL_STATE_DIR:-/etc/tacctl}/rendered.json"

# Enabled backends, in order; filled by _backends_load. _conf_invalidate
# (lib/conf.sh) resets _BACKENDS_LOADED with every tacctl.yaml write.
BACKENDS_ENABLED=()
_BACKENDS_LOADED=0
# Set by backends_render_all: ids whose artifacts it replaced.
BACKENDS_CHANGED=()
# Set by backends_gate: a --force=<id> flag per backend to adopt.
BACKENDS_ADOPT=()
# Filled by the 'finish' phase of upgrade and the 'data' phase of uninstall
# for the closing summary of the generic command.
UPGRADE_SUMMARY_HEAD=""
UPGRADE_SUMMARY_NOTES=()
UNINSTALL_SAVED=()

# backend_registered <id>
backend_registered() {
    local id
    for id in ${BACKEND_IDS[@]+"${BACKEND_IDS[@]}"}; do
        [[ "$id" == "${1:-}" ]] && return 0
    done
    return 1
}

# backend_call <id> <verb> [<arg>...]
# Run one verb of one backend, in the current shell, with its exit status.
# Returns 2 (message on stderr) for an id or a verb that does not exist.
backend_call() {
    local id="${1:-}" verb="${2:-}"
    if ! backend_registered "$id"; then
        error "Unknown backend '${id}'."
        return 2
    fi
    if ! declare -F "backend_${id}_${verb}" > /dev/null; then
        error "Backend '${id}' does not implement '${verb}'."
        return 2
    fi
    shift 2
    "backend_${id}_${verb}" "$@"
}

# backend_describe <id> <key>: one value of the backend's describe output.
# Returns 1, printing nothing, when it has no such key.
backend_describe() {
    local id="$1" key="$2" line
    while IFS= read -r line; do
        if [[ "$line" == "${key}="* ]]; then
            printf '%s\n' "${line#*=}"
            return 0
        fi
    done < <(backend_call "$id" describe)
    return 1
}

# --- Enabled backends -------------------------------------------------------

# Fill BACKENDS_ENABLED from backends.enabled in tacctl.yaml (default: see
# BACKENDS_DEFAULT_ENABLED). Returns 1, message on stderr, when it names a
# backend this tacctl has no module for. Call it in the current shell before
# looping over BACKENDS_ENABLED.
_backends_load() {
    (( _BACKENDS_LOADED )) && return 0
    local ids=() id seen=" "
    # A tacctl.yaml that never mentions the key takes the default without a
    # read of the merged view: every command comes through here.
    if grep -qs 'backends' "$TACCTL_OVERRIDES_FILE"; then
        mapfile -t ids < <(conf_get_list backends.enabled)
    fi
    (( ${#ids[@]} )) || ids=("${BACKENDS_DEFAULT_ENABLED[@]}")
    BACKENDS_ENABLED=()
    for id in "${ids[@]}"; do
        [[ -n "$id" && "$seen" != *" ${id} "* ]] || continue
        if ! backend_registered "$id"; then
            error "tacctl.yaml: backends.enabled names '${id}', and this tacctl has no such backend (it has: ${BACKEND_IDS[*]})."
            return 1
        fi
        seen+="${id} "
        BACKENDS_ENABLED+=("$id")
    done
    _BACKENDS_LOADED=1
}

# backends_enabled: the enabled backend ids, one per line, in order.
backends_enabled() {
    _backends_load || return 1
    printf '%s\n' "${BACKENDS_ENABLED[@]}"
}

# backends_run <verb> [<arg>...]: the verb on every backend in
# BACKENDS_ENABLED, in order (the caller has run _backends_load). The calls
# are deliberately bare. A lifecycle phase or a section of a report used to
# be inline in a command that runs under errexit, where a failing step
# aborts the run; testing the call's status here would switch errexit off
# for everything beneath it.
backends_run() {
    local _b
    for _b in "${BACKENDS_ENABLED[@]}"; do
        backend_call "$_b" "$@"
    done
}

# backends_select_present: for uninstall. BACKENDS_ENABLED becomes every
# backend that is enabled or installed (a disabled backend's daemon is still
# on the machine). A tacctl.yaml that cannot say which are enabled does not
# stop an uninstall: every backend is taken then.
backends_select_present() {
    local id
    if ! _backends_load 2> /dev/null; then
        BACKENDS_ENABLED=("${BACKEND_IDS[@]}")
    fi
    for id in "${BACKEND_IDS[@]}"; do
        if [[ " ${BACKENDS_ENABLED[*]} " != *" ${id} "* ]] && backend_call "$id" installed; then
            BACKENDS_ENABLED+=("$id")
        fi
    done
    _BACKENDS_LOADED=1
}

# backends_artifacts: every artifact of every enabled backend, one per line.
backends_artifacts() {
    local _b
    _backends_load || return 1
    for _b in "${BACKENDS_ENABLED[@]}"; do
        backend_call "$_b" artifacts || return 1
    done
}

# backend_artifact_names <id>: the backend's artifacts as 'a, b' for a message.
backend_artifact_names() {
    local out
    out=$(backend_call "$1" artifacts) || return 1
    printf '%s\n' "${out//$'\n'/, }"
}

# backends_artifact_names: the same for every enabled backend.
backends_artifact_names() {
    local out
    out=$(backends_artifacts) || return 1
    printf '%s\n' "${out//$'\n'/, }"
}

# backends_last_login <user>: the most recent login any enabled backend
# knows of, or "never".
backends_last_login() {
    local user="$1" _b ts best=""
    if _backends_load; then
        for _b in "${BACKENDS_ENABLED[@]}"; do
            ts=$(backend_call "$_b" last_login "$user") || ts=""
            if [[ -n "$ts" && "$ts" != "never" && ( -z "$best" || "$ts" > "$best" ) ]]; then
                best="$ts"
            fi
        done
    fi
    echo "${best:-never}"
}

# --- Rendered-artifact bookkeeping (plan 4.5) -------------------------------
# Python appended to _store_py (lib/store.sh), whose names it uses. A
# backend's own render program includes _rendered_py for rendered_status.
_rendered_py() {
    cat <<'PY'
# ---- rendered-artifact bookkeeping (plan 4.5) ------------------------------

def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def rendered_load(json_path):
    """{path: sha256}; {} when nothing was ever recorded."""
    try:
        with open(json_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except ValueError:
        raise StoreError(f'{json_path}: not valid JSON')
    if not isinstance(data, dict) or any(not isinstance(v, str) for v in data.values()):
        raise StoreError(f'{json_path}: not a path-to-sha256 mapping')
    return data


def rendered_status(records, path):
    """ok | drift | missing | unrecorded"""
    if not os.path.exists(path):
        return 'missing'
    if path not in records:
        return 'unrecorded'
    return 'ok' if file_sha256(path) == records[path] else 'drift'

PY
}

_rendered_main_py() {
    cat <<'PY'

def rendered_main(argv):
    cmd, rest = argv[0], argv[1:]

    if cmd == 'record':
        # record <rendered.json> <path>
        json_path, path = rest[0], os.path.abspath(rest[1])
        with store_lock(json_path):
            records = rendered_load(json_path)
            records[path] = file_sha256(path)
            atomic_write(json_path, json.dumps(records, indent=2, sort_keys=True) + '\n')

    elif cmd == 'forget':
        # forget <rendered.json> <path>
        json_path, path = rest[0], os.path.abspath(rest[1])
        if os.path.exists(json_path):
            with store_lock(json_path):
                records = rendered_load(json_path)
                if records.pop(path, None) is not None:
                    atomic_write(json_path, json.dumps(records, indent=2, sort_keys=True) + '\n')

    elif cmd == 'check':
        # check <rendered.json> <path>
        print(rendered_status(rendered_load(rest[0]), os.path.abspath(rest[1])))

    elif cmd == 'drift':
        # drift <rendered.json>: one '<status>\t<path>' line per artifact that
        # no longer is what tacctl rendered.
        bad = 0
        for path, _sha in sorted(rendered_load(rest[0]).items()):
            status = rendered_status({path: _sha}, path)
            if status != 'ok':
                print(f'{status}\t{path}')
                bad = 1
        return bad

    else:
        raise StoreError(f'internal: unknown command {cmd!r}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(rendered_main(sys.argv[1:]))
    except StoreError as e:
        print(f'tacctl render: {e}', file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f'tacctl render: {e.filename or "I/O"}: {e.strerror}', file=sys.stderr)
        sys.exit(1)
PY
}

# Run the bookkeeping program: _rendered_python <command> [args...].
_rendered_python() {
    python3 <(_store_py; _rendered_py; _rendered_main_py) "$@"
}

# rendered_record <path>: remember the file's current sha256 as "what tacctl
# rendered" in rendered.json.
rendered_record() {
    _rendered_python record "$RENDERED_FILE" "$1"
}

# rendered_forget <path>: drop a path from rendered.json (no-op if absent).
rendered_forget() {
    _rendered_python forget "$RENDERED_FILE" "$1"
}

# rendered_check <path>: compare a file with its record. Prints one word and
# returns: ok (0) unchanged since tacctl rendered it; drift (1) content
# differs; missing (2) the file is gone; unrecorded (3) tacctl has no record
# of rendering it. An unreadable rendered.json is a failure (4, message on
# stderr) -- callers must not treat it as "ok".
rendered_check() {
    local status
    status=$(_rendered_python check "$RENDERED_FILE" "$1") || status=""
    case "$status" in
        ok)         echo "ok";         return 0 ;;
        drift)      echo "drift";      return 1 ;;
        missing)    echo "missing";    return 2 ;;
        unrecorded) echo "unrecorded"; return 3 ;;
        *)          return 4 ;;
    esac
}

# --- Drift of rendered artifacts (plan 4.5) ---
# backends_check_drift: compare every artifact tacctl rendered with the
# sha256 recorded for it in rendered.json. Prints one '<status>\t<path>' line
# per artifact that is no longer what tacctl rendered -- status is 'drift'
# (edited by hand), 'missing' (deleted) or 'unreadable' (rendered.json itself
# cannot be read) -- and returns 1 when there is any. Returns 0, silently,
# when everything matches or nothing has been rendered yet.
backends_check_drift() {
    [[ -f "$RENDERED_FILE" ]] || return 0
    local out rc=0
    out=$(_rendered_python drift "$RENDERED_FILE" 2>/dev/null) || rc=$?
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

# --- Rendering every enabled backend ----------------------------------------

# backends_gate: step 1 of store_apply (see the header). Sets BACKENDS_ADOPT.
# Returns 0 go ahead; 3 refused; 1 failed.
backends_gate() {
    local _b rc
    BACKENDS_ADOPT=()
    _backends_load || return 1
    for _b in "${BACKENDS_ENABLED[@]}"; do
        rc=0
        backend_call "$_b" render_gate || rc=$?
        case "$rc" in
            0)  ;;
            10) BACKENDS_ADOPT+=("--force=${_b}") ;;
            *)  return "$rc" ;;
        esac
    done
}

# backends_render_all [--force] [--force=<id>]...
# Render the current store into the artifacts of every enabled backend,
# all of them or none (see the header).
#   --force       every backend overwrites artifacts that are not what
#                 tacctl rendered (each keeps a copy first)
#   --force=<id>  only that backend does
#   return  0 done, BACKENDS_CHANGED holds the ids whose artifacts changed;
#           1 failed; 3 refused by a backend because of drift. On 1 and 3
#           no artifact and no render record has changed.
# Requires the store. Messages go to stderr. Call it in the current shell,
# not in $(...): the result is a shell variable.
backends_render_all() {
    local arg force_all=0
    local -a forced=()
    for arg in "$@"; do
        case "$arg" in
            --force)   force_all=1 ;;
            --force=*) forced+=("${arg#--force=}") ;;
            *)
                error "Usage: backends_render_all [--force] [--force=<backend>]..."
                return 1
                ;;
        esac
    done
    BACKENDS_CHANGED=()
    if [[ ! -f "$STORE_FILE" ]]; then
        error "$STORE_NOT_INITIALISED_MSG"
        return 1
    fi
    _backends_load || return 1
    local out rc=0
    # Subshell: scopes the staging directory (it holds every backend's
    # candidate config, secrets included) and its cleanup trap.
    out=$(_backends_render_run "$force_all" ${forced[@]+"${forced[@]}"}) || rc=$?
    (( rc == 0 )) || return "$rc"
    if [[ -n "$out" ]]; then
        mapfile -t BACKENDS_CHANGED <<< "$out"
    fi
    return 0
}

# Runs in backends_render_all's subshell. Prints the ids that changed.
_backends_render_run() {
    local force_all="$1"
    shift
    local tmpd _b rc result path n=0
    local -a flag changed=()
    tmpd=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064  # expand tmpd now; the subshell owns this trap
    trap "rm -rf '${tmpd}'" EXIT

    # Pass 1: stage. Nothing outside tmpd changes.
    for _b in "${BACKENDS_ENABLED[@]}"; do
        mkdir "${tmpd}/${_b}" || exit 1
        flag=()
        if (( force_all )) || [[ " $* " == *" ${_b} "* ]]; then
            flag=(--force)
        fi
        rc=0
        backend_call "$_b" render_stage "${tmpd}/${_b}" ${flag[@]+"${flag[@]}"} >&2 || rc=$?
        (( rc == 0 )) || exit "$rc"
    done

    # Copies to put back if a commit fails: line n of the index names the
    # artifact kept as file n (no file: the artifact did not exist).
    mkdir "${tmpd}/.keep" || exit 1
    : > "${tmpd}/.keep/index"
    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        n=$((n + 1))
        printf '%s\n' "$path" >> "${tmpd}/.keep/index"
        if [[ -f "$path" ]]; then
            cp -p "$path" "${tmpd}/.keep/${n}" || exit 1
        fi
    done < <(backends_artifacts)
    if [[ -f "$RENDERED_FILE" ]]; then
        cp -p "$RENDERED_FILE" "${tmpd}/.keep/rendered.json" || exit 1
    fi

    # Pass 2: commit.
    for _b in "${BACKENDS_ENABLED[@]}"; do
        rc=0
        result=$(backend_call "$_b" render_commit "${tmpd}/${_b}") || rc=$?
        if (( rc != 0 )); then
            _backends_render_restore "${tmpd}/.keep"
            exit 1
        fi
        if [[ "$result" == "CHANGED" ]]; then
            changed+=("$_b")
        fi
    done
    if (( ${#changed[@]} )); then
        printf '%s\n' "${changed[@]}"
    fi
    exit 0
}

# Put one kept file back through a rename beside its target, owner and mode
# as they were; no kept file means the target did not exist.
_backends_render_put() {
    local kept="$1" dst="$2"
    if [[ ! -f "$kept" ]]; then
        rm -f "$dst"
        return 0
    fi
    if cp -p "$kept" "${dst}.tacctl-new" && mv -f "${dst}.tacctl-new" "$dst"; then
        return 0
    fi
    rm -f "${dst}.tacctl-new"
    warn "Could not put ${dst} back; 'tacctl config render' rewrites it from the store." >&2
    return 0
}

# Undo a partly committed render from the copies in $1.
_backends_render_restore() {
    local keep="$1" n=0 path
    while IFS= read -r path; do
        n=$((n + 1))
        _backends_render_put "${keep}/${n}" "$path"
    done < "${keep}/index"
    _backends_render_put "${keep}/rendered.json" "$RENDERED_FILE"
}

# backends_restart_changed: restart the backends the last
# backends_render_all changed.
backends_restart_changed() {
    local _b
    for _b in ${BACKENDS_CHANGED[@]+"${BACKENDS_CHANGED[@]}"}; do
        backend_call "$_b" service restart
    done
    return 0
}

# backends_restart_all: restart every enabled backend (a restore or a
# rollback restarts whether or not the rendered bytes changed).
backends_restart_all() {
    local _b
    _backends_load || return 1
    for _b in "${BACKENDS_ENABLED[@]}"; do
        backend_call "$_b" service restart
    done
    return 0
}

# --- Mutations: store write + render as one step ----------------------------
#
# Every command that changes users, groups, scopes, filters or command rules
# goes through store_apply. The sequence (the header says what each step
# means with more than one backend):
#
#   1. gate     the store must exist (plan 4.4), and every enabled backend's
#               artifacts must be replaceable (render_gate). For tacquito:
#               what tacctl last rendered, or missing, or a file tacctl never
#               rendered that says exactly what the store says (the state
#               right after 'store import'; it is adopted, and a copy kept
#               under backups/legacy/). A hand-edited file, or a
#               never-rendered one that says something else, refuses the
#               command here -- before anything is written.
#   2. backup   backup_snapshot (store.yaml, tacctl.yaml and the manifest,
#               under backups/<ts>/; skipped when nothing changed since the
#               newest snapshot), then a private copy of store.yaml and
#               tacctl.yaml to roll back to. A snapshot that cannot be made
#               refuses the command, before anything is written.
#   3. write    the caller's writer (store_* and/or conf_* calls).
#   4. render   backends_render_all. If it fails, no artifact has changed,
#               and store.yaml and tacctl.yaml are put back as they were, so
#               the canonical files and the rendered configs never disagree
#               because of a failed command.
#   5. restart  only the backends whose rendered config changed.
#
# store_require: return 0 when the store exists; else print the plan-4.4
# message and return 1. Mutating commands call it before they prompt.
store_require() {
    [[ -f "$STORE_FILE" ]] && return 0
    error "$STORE_NOT_INITIALISED_MSG"
    return 1
}

# store_apply <writer> [<arg>...]
# Run <writer> (a function making the store_* / conf_* writes of one command)
# inside the sequence above. The writer must return non-zero on failure and
# must not exit.
#   return 0  applied, rendered, daemons restarted where the config changed
#          1  failed; nothing is changed (a partial write was rolled back)
#          3  refused at the gate because a rendered config is not what
#             tacctl rendered; nothing is changed
# Call it in the current shell, not in $(...).
store_apply() {
    store_require || return 1
    local rc=0
    backends_gate || rc=$?
    (( rc == 0 )) || return "$rc"
    backup_snapshot || { error "Nothing was changed: the pre-change snapshot could not be made."; return 1; }

    local keep
    keep=$(mktemp -d "${TACCTL_STATE_DIR}/.apply.XXXXXX") || return 1
    cp -p "$STORE_FILE" "${keep}/store.yaml" || { rm -rf "$keep"; return 1; }
    if [[ -f "$TACCTL_OVERRIDES_FILE" ]]; then
        cp -p "$TACCTL_OVERRIDES_FILE" "${keep}/tacctl.yaml" || { rm -rf "$keep"; return 1; }
    fi

    # The snapshot above is this command's; the writer's own store writes
    # must not add one per intermediate state.
    _BACKUP_SNAPSHOT_HELD=1
    if ! "$@"; then
        _BACKUP_SNAPSHOT_HELD=0
        _store_apply_rollback "$keep"
        return 1
    fi
    _BACKUP_SNAPSHOT_HELD=0
    backends_render_all ${BACKENDS_ADOPT[@]+"${BACKENDS_ADOPT[@]}"} || rc=$?
    if (( rc != 0 )); then
        _store_apply_rollback "$keep"
        error "The change was not applied: $(backends_artifact_names) could not be rendered. Store and tacctl.yaml are as they were."
        return 1
    fi
    rm -rf "$keep"
    backends_restart_changed
    return 0
}

# Put store.yaml and tacctl.yaml back from the copies store_apply took.
_store_apply_rollback() {
    local keep="$1"
    mv -f "${keep}/store.yaml" "$STORE_FILE"
    if [[ -f "${keep}/tacctl.yaml" ]]; then
        mv -f "${keep}/tacctl.yaml" "$TACCTL_OVERRIDES_FILE"
    else
        rm -f "$TACCTL_OVERRIDES_FILE"
    fi
    rm -rf "$keep"
    _model_invalidate
    _conf_invalidate
}

# --- CLI: tacctl config render [--force] ------------------------------------

cmd_config_render() {
    local force=()
    case "${1:-}" in
        "")      ;;
        --force) force=(--force) ;;
        *)
            error "Usage: tacctl config render [--force]"
            return 1
            ;;
    esac
    if (( $# > 1 )); then
        error "Usage: tacctl config render [--force]"
        return 1
    fi
    local rc=0 _b
    backends_render_all "${force[@]}" || rc=$?
    if (( rc != 0 )); then
        return "$rc"
    fi
    for _b in "${BACKENDS_ENABLED[@]}"; do
        if [[ " ${BACKENDS_CHANGED[*]} " == *" ${_b} "* ]]; then
            info "Rendered $(backend_artifact_names "$_b")."
            backend_call "$_b" service restart
        else
            info "$(backend_artifact_names "$_b") is already up to date."
        fi
        backend_call "$_b" render_notes
    done
}
