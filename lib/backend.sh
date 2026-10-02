# shellcheck shell=bash
# shellcheck disable=SC2034  # registry and result globals assigned here are read by the other lib files
# tacctl lib/backend.sh -- backend registry and contract, enabled backends, listeners ('tacctl config listen'), rendered-artifact bookkeeping and drift, render/restart across backends, the mutation path (store_apply), 'tacctl config render'
# Sourced by bin/tacctl.sh before lib/backends/*.sh (see the load block there for ordering); not executable.
#
# A backend is a daemon that serves the model (lib/model.sh) over one
# protocol: tacquito for TACACS+ (lib/backends/tacacs.sh), FreeRADIUS for
# RADIUS (lib/backends/radius.sh). Everything protocol-neutral -- the store, tacctl.yaml,
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
#                       config_dir, log_dir, and optionally import_cmd (the
#                       command that adopts a hand edit of this backend's
#                       artifacts into the store; absent when there is none,
#                       which is what the DRIFT hint says). Read one with
#                       backend_describe.
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
#   service <start|stop|restart|reload|enable|disable|is-active|since|pid> [<listener>]
#                       'restart' reports its own outcome and never fails
#                       the caller; 'is-active' prints and returns what
#                       systemctl does. 'enable' and 'disable' are the
#                       boot-time half of 'start' and 'stop' ('tacctl backend
#                       enable|disable' runs both; they were added to this
#                       verb for it). Without a listener the action is on
#                       the backend as a whole; with one, on the unit (or
#                       whatever the daemon has) that serves that listener.
#   listeners <list|show [<name>]|set <name> <network> <address>|reset [<name>]>
#                       the backend's listeners.<id>.<name> of tacctl.yaml
#                       (lib/conf.sh: _listener_py; read with
#                       backend_listeners). 'list' prints one
#                       '<name> <network> <address>' line per listener in
#                       effect, the built-in one first. 'show' prints one
#                       for the operator. 'set' creates or changes one and
#                       'reset' puts a built-in one back to its default or
#                       removes any other: both validate before they write,
#                       make the daemon follow, report, and return 1 with
#                       everything as it was when the daemon does not come
#                       up. 'tacctl config listen' (cmd_config_listen below)
#                       is the CLI of this verb. The reports read 'list':
#                       'backend status', 'config show' and the IPv6 check of
#                       'status' look for a socket at each listener's port,
#                       tcp for a network that starts with tcp, udp for one
#                       that starts with udp, and a network that ends in 6 is
#                       an IPv6 one.
#   status <service|config|accounting|activity>
#                       this backend's lines of 'tacctl status', one part
#                       per place the report has always had them. With more
#                       than one backend enabled the four parts of a backend
#                       are printed together, in that order, under its own
#                       heading (backend_heading), so a part must read well
#                       after the others and carry no heading of its own.
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
# new.
#
# Commands that exist for one daemon only -- 'config loglevel', 'config
# metrics', 'store import' and 'store rollback' -- are that backend's own
# CLI. The dispatcher calls them by name; they are not generic code reaching
# into a daemon, and not part of the contract. Their settings are per backend
# in tacctl.yaml (backends.<id>.<key>).
#
# Listeners, log level and metrics are settings of a daemon, not of the
# model, and do not go through store_apply: nothing in them needs the store,
# so they work before an install has one. A backend that renders them into
# artifacts (the TACACS+ module's systemd drop-ins) stages and commits those
# with the rest, so a restored tacctl.yaml is applied by the render that
# follows it.
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

# --- Listeners (plan 3.4) ---------------------------------------------------

# backend_listeners <id>: the backend's listeners in effect, from tacctl.yaml
# and the built-in defaults, the built-in ones first. One tab-separated line
# each: name, network, address, role, metrics address ('-' for none), and
# 'override' (written in tacctl.yaml) or 'default'.
backend_listeners() {
    _conf_load_cache
    python3 <(_listener_py; cat <<'PY'
import json, sys
doc, backend = json.loads(sys.argv[1]), sys.argv[2]
section = doc.get('listeners') if isinstance(doc.get('listeners'), dict) else {}
mine = section.get(backend) if isinstance(section.get(backend), dict) else {}
for name, l in listeners_effective(doc, backend).items():
    print('\t'.join((name, l['network'], l['address'], l['role'], l['metrics_address'] or '-',
                     'override' if name in mine else 'default')))
PY
) "$_TACCTL_CFG_CACHE" "$1"
}

# tacctl config listen [--backend <id>] [--listener <name>] [show|<network> <address>|reset]
# Without flags: the TACACS+ backend's default listener, as this command
# always worked.
cmd_config_listen() {
    local backend="tacacs" listener="default"
    local -a args=()
    while (( $# )); do
        case "$1" in
            --backend|--listener)
                if [[ -z "${2:-}" ]]; then
                    error "$1 needs a value. Usage: tacctl config listen [--backend <id>] [--listener <name>] <show|<network> <address>|reset>"
                    return 1
                fi
                if [[ "$1" == "--backend" ]]; then backend="$2"; else listener="$2"; fi
                shift 2
                ;;
            --backend=*)  backend="${1#*=}"; shift ;;
            --listener=*) listener="${1#*=}"; shift ;;
            *)            args+=("$1"); shift ;;
        esac
    done
    if ! backend_registered "$backend"; then
        error "Unknown backend '${backend}' (known: ${BACKEND_IDS[*]})."
        return 1
    fi
    if [[ ! "$listener" =~ ^[a-z][a-z0-9_-]{0,31}$ ]]; then
        error "Invalid listener name '${listener}': a lowercase letter, then up to 31 of [a-z0-9_-]."
        return 1
    fi

    local sub="${args[0]:-}" shown
    case "$sub" in
        ""|show)
            shown=$(backend_call "$backend" listeners show "$listener") || return 1
            echo ""
            echo "$shown"
            echo ""
            if [[ "$backend" != "tacacs" ]]; then
                # Another backend's networks and listener names are its own.
                echo "  Usage: tacctl config listen --backend ${backend} --listener <name> <network> <address>"
                echo "         tacctl config listen --backend ${backend} --listener <name> reset"
                echo ""
                return 0
            fi
            echo "  Usage: tacctl config listen <show|tcp|tcp6|reset> [address]"
            echo "  Examples:"
            echo "    tacctl config listen tcp :49"
            echo "    tacctl config listen tcp 10.1.0.1:49"
            echo "    tacctl config listen tcp6 [::]:49"
            echo "    tacctl config listen reset       # drop override, use template default"
            echo ""
            ;;
        reset)
            backend_call "$backend" listeners reset "$listener"
            ;;
        *)
            # A network and an address; the backend says which networks it has.
            backend_call "$backend" listeners set "$listener" "$sub" "${args[1]:-}"
            ;;
    esac
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
# backends_check_drift [<id>|--unowned]: compare every artifact tacctl rendered
# with the sha256 recorded for it in rendered.json. Prints one
# '<status>\t<path>' line per artifact that is no longer what tacctl rendered
# -- status is 'drift' (edited by hand), 'missing' (deleted) or 'unreadable'
# (rendered.json itself cannot be read) -- and returns 1 when there is any.
# Returns 0, silently, when everything matches or nothing has been rendered yet.
#   (no argument)  every artifact that matters: those of an enabled backend and
#                  those no backend claims. The artifacts a disabled backend
#                  left behind are not reported: nothing serves them.
#   <id>           only that backend's artifacts.
#   --unowned      only the artifacts no registered backend claims, and
#                  rendered.json itself when it cannot be read.
backends_check_drift() {
    [[ -f "$RENDERED_FILE" ]] || return 0
    local out rc=0 mode="${1:-}"
    out=$(_rendered_python drift "$RENDERED_FILE" 2>/dev/null) || rc=$?
    (( rc == 0 )) && return 0
    if [[ -z "$out" ]]; then
        out=$(printf 'unreadable\t%s' "$RENDERED_FILE")
    fi
    out=$(_drift_select "$mode" <<< "$out")
    [[ -n "$out" ]] || return 0
    printf '%s\n' "$out"
    return 1
}

# The id of the registered backend that lists $1 among its artifacts, or
# nothing.
backends_artifact_owner() {
    local id list
    for id in ${BACKEND_IDS[@]+"${BACKEND_IDS[@]}"}; do
        # Captured, not piped into grep -q: under pipefail its early exit
        # would fail the pipeline.
        list=$(backend_call "$id" artifacts 2> /dev/null) || continue
        if [[ $'\n'"$list"$'\n' == *$'\n'"$1"$'\n'* ]]; then
            echo "$id"
            return 0
        fi
    done
    return 0
}

# Filter '<status>\t<path>' lines on stdin as backends_check_drift's mode says.
_drift_select() {
    local mode="$1" line dpath owner
    local enabled=" "
    if _backends_load 2> /dev/null; then
        enabled=" ${BACKENDS_ENABLED[*]} "
    else
        enabled=" ${BACKEND_IDS[*]} "
    fi
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        dpath="${line#*$'\t'}"
        owner=""
        [[ "$dpath" == "$RENDERED_FILE" ]] || owner=$(backends_artifact_owner "$dpath")
        case "$mode" in
            "")        [[ -z "$owner" || "$enabled" == *" ${owner} "* ]] || continue ;;
            --unowned) [[ -z "$owner" ]] || continue ;;
            *)         [[ "$owner" == "$mode" ]] || continue ;;
        esac
        printf '%s\n' "$line"
    done
}

# Print the red DRIFT lines 'status' and 'config validate' show, one per
# drifted artifact (the same selection as backends_check_drift, with the same
# argument). Returns 1 when it printed any. The hint after a line depends on
# whose artifact it is: only a backend whose describe says import_cmd can adopt
# a hand edit.
print_drift_lines() {
    local drift dstatus dpath owner import_cmd
    drift=$(backends_check_drift "$@") && return 0
    while IFS=$'\t' read -r dstatus dpath; do
        [[ -n "$dpath" ]] || continue
        case "$dstatus" in
            drift)   dstatus="edited since tacctl rendered it" ;;
            missing) dstatus="rendered by tacctl but no longer there" ;;
            *)       dstatus="render records cannot be read" ;;
        esac
        echo -e "  ${RED}DRIFT:${NC}                ${dpath} — ${dstatus}"
        owner=""
        [[ "$dpath" == "$RENDERED_FILE" ]] || owner=$(backends_artifact_owner "$dpath")
        import_cmd=""
        if [[ -n "$owner" ]]; then
            import_cmd=$(backend_describe "$owner" import_cmd) || import_cmd=""
        fi
        case "$dpath" in
            */tacctl.conf)
                # A unit drop-in a backend renders (always under this name)
                # holds nothing tacctl.yaml does not: there is nothing to
                # import, and a render replaces it without --force.
                echo "                        'tacctl config render' rewrites it from tacctl.yaml (a copy is kept); unit settings of your own belong in another .conf file of that directory"
                ;;
            *)
                if [[ -n "$import_cmd" || -z "$owner" ]]; then
                    echo "                        keep the edits: '${import_cmd:-tacctl store import --replace}' then 'tacctl config render --force'; discard them: 'tacctl config render --force'"
                else
                    echo "                        discard the edits: 'tacctl config render --force' (a copy is kept); there is no way to adopt them into the store"
                fi
                ;;
        esac
    done <<< "$drift"
    return 1
}

# --- Rendering every enabled backend ----------------------------------------

# backends_gate [<id>...]: step 1 of store_apply (see the header). Sets
# BACKENDS_ADOPT. Gates the enabled backends, or the ids given: a command that
# changes backends.enabled gates the set its render will cover (the one after
# the change), which is not the one the writer has not yet changed.
# Returns 0 go ahead; 3 refused; 1 failed.
backends_gate() {
    local _b rc
    local -a ids=("$@")
    BACKENDS_ADOPT=()
    _backends_load || return 1
    (( ${#ids[@]} )) || ids=("${BACKENDS_ENABLED[@]}")
    for _b in "${ids[@]}"; do
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
    local tmpd _b rc result
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

    # Copies to put back if a commit fails.
    _backends_keep "${tmpd}/.keep" "${BACKENDS_ENABLED[@]}" || exit 1

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

# _backends_keep <dir> <id>...: copies of every artifact of those backends and
# of rendered.json, to put back with _backends_render_restore. Line n of the
# index names the artifact kept as file n (no file: it did not exist).
_backends_keep() {
    local keep="$1" _b path n=0
    shift
    mkdir -p "$keep" || return 1
    : > "${keep}/index"
    for _b in "$@"; do
        while IFS= read -r path; do
            [[ -n "$path" ]] || continue
            n=$((n + 1))
            printf '%s\n' "$path" >> "${keep}/index"
            if [[ -f "$path" ]]; then
                cp -p "$path" "${keep}/${n}" || return 1
            fi
        done < <(backend_call "$_b" artifacts)
    done
    if [[ -f "$RENDERED_FILE" ]]; then
        cp -p "$RENDERED_FILE" "${keep}/rendered.json" || return 1
    fi
    return 0
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

# backends_restart_changed [<id>...]: restart the backends the last
# backends_render_all changed, except the ids given (a caller that starts one
# itself, 'tacctl backend enable').
backends_restart_changed() {
    local _b
    for _b in ${BACKENDS_CHANGED[@]+"${BACKENDS_CHANGED[@]}"}; do
        [[ " $* " == *" ${_b} "* ]] && continue
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

# store_apply [--gate "<id>..."] [--defer-restart <id>] <writer> [<arg>...]
# Run <writer> (a function making the store_* / conf_* writes of one command)
# inside the sequence above. The writer must return non-zero on failure and
# must not exit.
#   --gate "<id>..."       gate these backends instead of the enabled ones
#                          (for a writer that changes backends.enabled: the
#                          backends that will be rendered, not those that were)
#   --defer-restart <id>   leave the restart of that backend to the caller;
#                          it is still in BACKENDS_CHANGED if it changed
#   return 0  applied, rendered, daemons restarted where the config changed
#          1  failed; nothing is changed (a partial write was rolled back)
#          3  refused at the gate because a rendered config is not what
#             tacctl rendered; nothing is changed
# Call it in the current shell, not in $(...).
store_apply() {
    local gate_set=0 rc=0
    local -a gate_ids=() defer=()
    while [[ "${1:-}" == --* ]]; do
        case "$1" in
            --gate)          gate_set=1; read -ra gate_ids <<< "${2:-}"; shift 2 ;;
            --defer-restart) defer+=("${2:-}"); shift 2 ;;
            *)
                error "store_apply: unknown option '$1'."
                return 1
                ;;
        esac
    done
    store_require || return 1
    if (( gate_set )); then
        backends_gate ${gate_ids[@]+"${gate_ids[@]}"} || rc=$?
    else
        backends_gate || rc=$?
    fi
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
        # Named before the rollback: a change of backends.enabled changes
        # which backends these are.
        local names
        names=$(backends_artifact_names)
        _store_apply_rollback "$keep"
        error "The change was not applied: ${names} could not be rendered. Store and tacctl.yaml are as they were."
        return 1
    fi
    rm -rf "$keep"
    backends_restart_changed ${defer[@]+"${defer[@]}"}
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

# --- Labelled sections, listener probes -------------------------------------

# backend_heading <id>: the heading of a backend's section in a report that
# covers more than one backend (status, log, config show...).
backend_heading() {
    local id="$1" proto impl
    proto=$(backend_describe "$id" protocol) || proto="$id"
    impl=$(backend_describe "$id" impl) || impl=""
    echo ""
    echo -e "${BOLD}== Backend: ${id} (${proto}${impl:+, ${impl}}) ==${NC}"
}

# backend_listener_probe <network> <address>: the local address something
# listens on at that port, or nothing. tcp* is looked up with ss -tln, udp*
# with ss -uln; the match is on the port, as it always was.
backend_listener_probe() {
    local net="$1" port="${2##*:}" flags="-tlnp"
    [[ "$net" == udp* ]] && flags="-ulnp"
    # shellcheck disable=SC2086  # flags is one of two fixed words
    ss $flags 2>/dev/null | { grep ":${port} " || true; } | awk '{print $4}' | head -1
}

# _completion_listeners [<backend>]: listener names, one per line, for bash
# completion of 'config listen --listener'. Best effort, never fails.
_completion_listeners() {
    local _b name _rest
    for _b in ${1:-${BACKEND_IDS[@]}}; do
        backend_registered "$_b" || continue
        while read -r name _rest; do
            [[ -n "$name" ]] && printf '%s\n' "$name"
        done < <(backend_call "$_b" listeners list 2>/dev/null) || true
    done | sort -u
    return 0
}

# --- CLI: tacctl backend ----------------------------------------------------
#
#   backend list                 every backend this tacctl has
#   backend status [<id>]        service and listener state, per backend
#   backend enable <id> [-y]     install if needed, add to backends.enabled,
#                                render, start
#   backend disable <id> [-y]    remove from backends.enabled, stop, disable
#
# list and status only read. enable and disable are one transaction on the
# files tacctl owns (tacctl.yaml's backends.enabled, the store, every
# rendered artifact): they either complete or leave all of them as they were.
# What cannot be undone is software: an install that enable ran stays
# installed, and disable leaves the package and every rendered file in place.

# Seconds to wait between starting a backend and asking whether it is
# running (tests set it to 0).
BACKEND_START_WAIT=2

_backend_usage() {
    echo ""
    echo -e "${BOLD}Backend Commands${NC}"
    echo ""
    echo "Usage: tacctl backend <subcommand> [arguments]"
    echo ""
    echo "Subcommands:"
    echo "  list                    Every backend: protocol, implementation, installed, enabled, service"
    echo "  status [<id>]           Service and listener state of every backend (or one)"
    echo "  enable <id> [-y]        Install the backend if needed, enable it, render its config, start it"
    echo "  disable <id> [-y]       Stop and disable it, take it out of backends.enabled (confirms);"
    echo "                          its package and rendered files stay"
    echo ""
    echo "Backends: ${BACKEND_IDS[*]}"
    echo ""
}

# _backend_known <id>: 0, or an error naming the backends there are.
_backend_known() {
    if [[ -z "${1:-}" ]]; then
        error "Missing backend id (known: ${BACKEND_IDS[*]})."
        return 1
    fi
    if ! backend_registered "$1"; then
        error "Unknown backend '${1}' (known: ${BACKEND_IDS[*]})."
        return 1
    fi
}

# _backend_is_enabled <id>: BACKENDS_ENABLED must be loaded.
_backend_is_enabled() {
    [[ " ${BACKENDS_ENABLED[*]} " == *" ${1} "* ]]
}

_backend_list() {
    _backends_load || return 1
    local id proto impl inst enab svc
    echo ""
    echo -e "${BOLD}Backends${NC}"
    echo "--------------------------------------------"
    printf "  ${BOLD}%-12s %-10s %-16s %-10s %-8s %-10s${NC}\n" "ID" "PROTOCOL" "IMPLEMENTATION" "INSTALLED" "ENABLED" "SERVICE"
    echo "  ------------------------------------------------------------------"
    for id in "${BACKEND_IDS[@]}"; do
        proto=$(backend_describe "$id" protocol) || proto="-"
        impl=$(backend_describe "$id" impl) || impl="-"
        inst="no"; enab="no"; svc="-"
        if backend_call "$id" installed; then
            inst="yes"
            svc=$(backend_call "$id" service is-active) || true
            svc="${svc:-unknown}"
        fi
        _backend_is_enabled "$id" && enab="yes"
        printf "  %-12s %-10s %-16s %-10s %-8s %-10s\n" "$id" "$proto" "$impl" "$inst" "$enab" "$svc"
    done
    echo ""
}

_backend_status() {
    local -a ids=("$@")
    _backends_load || return 1
    if (( ${#ids[@]} )); then
        _backend_known "${ids[0]}" || return 1
        ids=("${ids[0]}")
    else
        ids=("${BACKEND_IDS[@]}")
    fi
    local id enab state since pid name net addr _rest bound unit ustate
    for id in "${ids[@]}"; do
        backend_heading "$id"
        if _backend_is_enabled "$id"; then enab="enabled"; else enab="not enabled"; fi
        if ! backend_call "$id" installed; then
            echo -e "  ${BOLD}State:${NC}                not installed, ${enab}"
            continue
        fi
        echo -e "  ${BOLD}State:${NC}                installed, ${enab}"
        state=$(backend_call "$id" service is-active) || true
        state=${state:-unknown}
        if [[ "$state" == "active" ]]; then
            echo -e "  ${BOLD}Service:${NC}              ${GREEN}${state}${NC}"
            since=$(backend_call "$id" service since) || since=""
            [[ -z "$since" ]] || echo -e "  ${BOLD}Since:${NC}                ${since}"
            pid=$(backend_call "$id" service pid) || pid=""
            if [[ -n "$pid" && "$pid" != "0" ]]; then
                echo -e "  ${BOLD}PID:${NC}                  ${pid}"
            fi
        elif _backend_is_enabled "$id"; then
            echo -e "  ${BOLD}Service:${NC}              ${RED}${state}${NC}"
        else
            echo -e "  ${BOLD}Service:${NC}              ${state}"
        fi
        while read -r name net addr _rest; do
            [[ -n "$name" ]] || continue
            bound=$(backend_listener_probe "$net" "$addr")
            ustate=$(backend_call "$id" service is-active "$name") || true
            ustate=${ustate:-unknown}
            if [[ -n "$bound" ]]; then
                bound="${GREEN}listening on ${bound}${NC}"
            elif [[ "$state" == "active" ]]; then
                bound="${RED}port ${addr##*:} not detected${NC}"
            else
                bound="not listening"
            fi
            unit="unit ${ustate}"
            echo -e "  ${BOLD}Listener ${name}:${NC} ${net} ${addr} — ${unit}, ${bound}"
        done < <(backend_call "$id" listeners list)
    done
    echo ""
}

# _backend_confirm <prompt> <assume-yes>: 0 only on y/Y (or assume-yes); anything
# else, an empty stdin included, is a no (the callers then return 0: declining
# is not a failure, as in 'tacctl install').
_backend_confirm() {
    local confirm=""
    (( ${2:-0} )) && return 0
    read -rp "  $1 [y/N]: " confirm || true
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled. Nothing was changed."
        return 1
    fi
}

# _backend_run_phases <id> <install|upgrade|uninstall> <tree> <phase>...
# The module's lifecycle phases are written for the generic commands, which
# run them under errexit: a failing step exits. Here each runs in a subshell
# so that a failure comes back as a status and 'exit' or 'cd' inside cannot
# take the caller with it.
_backend_run_phases() {
    local id="$1" verb="$2" tree="$3" phase rc had_e=0
    shift 3
    [[ $- == *e* ]] && had_e=1
    for phase in "$@"; do
        rc=0
        set +e
        ( set -e; backend_call "$id" "$verb" "$phase" "$tree" )
        rc=$?
        (( had_e )) && set -e
        if (( rc != 0 )); then
            error "Backend '${id}': ${verb} step '${phase}' failed (exit ${rc})."
            return 1
        fi
    done
    return 0
}

# Writer for store_apply: backends.enabled becomes the ids given.
_backend_enabled_write() {
    # Not a pipe: conf_set_list must run in this shell for its cache reset
    # (_conf_invalidate, which also drops the enabled list) to count.
    conf_set_list backends.enabled < <(printf '%s\n' "$@")
}

# _backend_enable_undo <keep> <id>: put tacctl.yaml, every artifact and
# rendered.json back from <keep> after the backend did not come up, and stop
# what was started. The other backends were restarted by the render that this
# undoes, so the ones it changed are restarted again onto what they had.
_backend_enable_undo() {
    local keep="$1" id="$2" _b
    backend_call "$id" service stop || true
    backend_call "$id" service disable || true
    if [[ -f "${keep}/tacctl.yaml" ]]; then
        cp -p "${keep}/tacctl.yaml" "$TACCTL_OVERRIDES_FILE" \
            || warn "Could not put ${TACCTL_OVERRIDES_FILE} back."
    else
        rm -f "$TACCTL_OVERRIDES_FILE"
    fi
    _conf_invalidate
    _model_invalidate
    _backends_render_restore "${keep}/artifacts"
    for _b in ${BACKENDS_CHANGED[@]+"${BACKENDS_CHANGED[@]}"}; do
        [[ "$_b" == "$id" ]] && continue
        backend_call "$_b" service restart
    done
}

# tacctl backend enable <id> [-y]
#
#   1. refuse unless the backend exists, is not enabled, and the store exists
#   2. if it is not installed: confirm (-y skips), then run its install phases
#      build, files, account. Failure: nothing but its software is touched;
#      backends.enabled, the store and every artifact are as they were.
#   3. store_apply: gate every backend of the new set (the new one included),
#      snapshot, add the id to backends.enabled, render every backend (the new
#      one's artifacts are created here), all or none. Failure: store_apply
#      puts everything back; the backend is installed but not enabled.
#   4. bring it up: the install phase 'start' for a backend installed in step
#      2; otherwise 'service enable', then a restart if its render changed
#      anything or a start if not. Then it must report 'active'. Failure at
#      either: tacctl.yaml, every artifact and rendered.json are put back from
#      copies taken before step 3, the service is stopped and disabled, and
#      the backends the render had restarted are restarted again. The store
#      was not changed by any of it.
# Whatever fails exits 1 (3 when a gate refused: a rendered file was edited
# by hand), saying what state it left.
cmd_backend_enable() {
    local id="" assume_yes=0 arg
    for arg in "$@"; do
        case "$arg" in
            -y|--yes) assume_yes=1 ;;
            -*)
                error "Unknown option '${arg}'. Usage: tacctl backend enable <id> [-y]"
                return 1
                ;;
            *)
                if [[ -n "$id" ]]; then
                    error "Usage: tacctl backend enable <id> [-y]"
                    return 1
                fi
                id="$arg"
                ;;
        esac
    done
    _backend_known "$id" || return 1
    _backends_load || return 1
    if _backend_is_enabled "$id"; then
        info "Backend '${id}' is already enabled."
        return 0
    fi
    store_require || return 1

    local tree fresh=0
    tree="$(cd "${SCRIPT_DIR}/.." && pwd)"
    if ! backend_call "$id" installed; then
        fresh=1
        echo ""
        echo "  Backend '${id}' is not installed. Enabling it installs $(backend_describe "$id" impl || echo "its daemon")"
        echo "  (packages, a service account, its service unit), then renders its config and starts it."
        _backend_confirm "Install and enable '${id}'?" "$assume_yes" || return 0
        if ! _backend_run_phases "$id" install "$tree" build files account; then
            error "Backend '${id}' was not enabled. tacctl.yaml, the store and every rendered file are as they were; what the install did stays on this machine."
            return 1
        fi
    fi

    local keep rc=0 kept_note=""
    local -a new_enabled=("${BACKENDS_ENABLED[@]}" "$id")
    (( fresh )) && kept_note="; the install stays on this machine"
    keep=$(mktemp -d "${TACCTL_STATE_DIR}/.enable.XXXXXX") || return 1
    if ! _backends_keep "${keep}/artifacts" "${new_enabled[@]}"; then
        rm -rf "$keep"
        error "Could not copy the rendered files before the change. Nothing was changed."
        return 1
    fi
    if [[ -f "$TACCTL_OVERRIDES_FILE" ]]; then
        cp -p "$TACCTL_OVERRIDES_FILE" "${keep}/tacctl.yaml" || { rm -rf "$keep"; return 1; }
    fi

    store_apply --gate "${new_enabled[*]}" --defer-restart "$id" \
        _backend_enabled_write "${new_enabled[@]}" || rc=$?
    if (( rc != 0 )); then
        rm -rf "$keep"
        error "Backend '${id}' was not enabled. tacctl.yaml, the store and every rendered file are as they were${kept_note}."
        return "$rc"
    fi

    local render_changed=0 state=""
    [[ " ${BACKENDS_CHANGED[*]:-} " == *" ${id} "* ]] && render_changed=1
    rc=0
    if (( fresh )); then
        _backend_run_phases "$id" install "$tree" start || rc=1
    else
        backend_call "$id" service enable || rc=1
        if (( rc == 0 )); then
            if (( render_changed )); then
                backend_call "$id" service restart || rc=1
            else
                backend_call "$id" service start || rc=1
            fi
        fi
    fi
    if (( rc == 0 )); then
        sleep "$BACKEND_START_WAIT"
        state=$(backend_call "$id" service is-active) || true
        [[ "$state" == "active" ]] || rc=1
    fi
    if (( rc != 0 )); then
        warn "Backend '${id}' did not come up (service ${state:-unknown}); undoing the change."
        _backend_enable_undo "$keep" "$id"
        rm -rf "$keep"
        error "Backend '${id}' was not enabled. tacctl.yaml and every rendered file are back as they were, the service is stopped and disabled${kept_note}."
        return 1
    fi
    rm -rf "$keep"
    info "Backend '${id}' is enabled and running."
    echo ""
}

# tacctl backend disable <id> [-y]
#
# Refused: the last enabled backend (with none enabled tacctl would render
# and serve nothing; enable another first, or 'tacctl uninstall'), and tacacs
# while there is no store (an install still in legacy mode: tacquito.yaml is
# the only source of truth and tacquito the one thing left serving it).
#   1. confirm (-y skips)
#   2. store mode: store_apply gates the backends that stay, snapshots,
#      removes the id from backends.enabled and renders the rest. Failure:
#      everything as it was, the service untouched.
#      Legacy mode (a backend other than tacacs): tacctl.yaml is rewritten
#      alone, from a copy kept for the failure case.
#   3. 'service stop', then 'service disable'. A failure here is reported
#      (exit 1): the backend is out of backends.enabled and its service still
#      runs, and the message names what to run.
# Its rendered files, rendered.json records, snapshots and package stay.
cmd_backend_disable() {
    local id="" assume_yes=0 arg
    for arg in "$@"; do
        case "$arg" in
            -y|--yes) assume_yes=1 ;;
            -*)
                error "Unknown option '${arg}'. Usage: tacctl backend disable <id> [-y]"
                return 1
                ;;
            *)
                if [[ -n "$id" ]]; then
                    error "Usage: tacctl backend disable <id> [-y]"
                    return 1
                fi
                id="$arg"
                ;;
        esac
    done
    _backend_known "$id" || return 1
    _backends_load || return 1
    if ! _backend_is_enabled "$id"; then
        info "Backend '${id}' is not enabled. Nothing to do."
        return 0
    fi
    local -a remaining=()
    local _b
    for _b in "${BACKENDS_ENABLED[@]}"; do
        [[ "$_b" == "$id" ]] || remaining+=("$_b")
    done
    if (( ${#remaining[@]} == 0 )); then
        error "Backend '${id}' is the only enabled backend. With none enabled nothing would serve the store."
        error "Enable another first ('tacctl backend enable <id>'), or remove tacctl's daemons with 'tacctl uninstall'."
        return 1
    fi
    local legacy=0
    [[ -f "$STORE_FILE" ]] || legacy=1
    if (( legacy )) && [[ "$id" == "tacacs" ]]; then
        error "Backend 'tacacs' cannot be disabled while there is no store: ${CONFIG} is still the source of truth and tacquito the only thing serving it."
        error "${STORE_NOT_INITIALISED_MSG}"
        return 1
    fi

    echo ""
    echo "  This takes backend '${id}' out of backends.enabled and stops and disables its service."
    echo "  Clients of that protocol can no longer authenticate. Its package and rendered files stay on this machine;"
    echo "  'tacctl backend enable ${id}' brings it back."
    _backend_confirm "Disable '${id}'?" "$assume_yes" || return 0

    local rc=0
    if (( legacy )); then
        local keep
        keep=$(mktemp "${TACCTL_STATE_DIR}/.disable.XXXXXX") || return 1
        cp -p "$TACCTL_OVERRIDES_FILE" "$keep" 2> /dev/null || : > "$keep"
        _backend_enabled_write "${remaining[@]}" || rc=1
        if (( rc != 0 )); then
            cp -p "$keep" "$TACCTL_OVERRIDES_FILE" || true
            _conf_invalidate
        fi
        rm -f "$keep"
    else
        store_apply --gate "${remaining[*]}" _backend_enabled_write "${remaining[@]}" || rc=$?
    fi
    if (( rc != 0 )); then
        error "Backend '${id}' was not disabled. tacctl.yaml, the store and every rendered file are as they were."
        return "$rc"
    fi

    rc=0
    backend_call "$id" service stop || rc=1
    backend_call "$id" service disable || rc=1
    if (( rc != 0 )); then
        error "Backend '${id}' is out of backends.enabled, but its service could not be stopped or disabled. Run: systemctl stop $(backend_describe "$id" units || echo "<unit>") ; systemctl disable $(backend_describe "$id" units || echo "<unit>")"
        return 1
    fi
    info "Backend '${id}' is disabled: removed from backends.enabled, service stopped and disabled."
    info "Left in place: its package and $(backend_artifact_names "$id" || echo "its rendered files") (not rendered any more)."
    echo ""
}

cmd_backend() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        list)    _backend_list ;;
        status)  _backend_status "$@" ;;
        enable)  cmd_backend_enable "$@" ;;
        disable) cmd_backend_disable "$@" ;;
        *)
            _backend_usage
            exit 1
            ;;
    esac
}
