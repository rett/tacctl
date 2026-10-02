#!/usr/bin/env bats
# 'tacctl backend list|status|enable|disable' and the per-backend sections of
# status, log, config validate, config show and backup restore, with a
# stand-in second backend 'fake' (written to a file below and sourced after
# tacctl.sh, so it registers itself the way a module in lib/backends/ does).
# The commands run in a bash of their own under 'set -euo pipefail', as the
# script does: the lifecycle phases of a module exit on failure, which a bats
# test body (errexit ignored inside 'run') could not show.
#
# What must hold whichever step of enable fails, and wherever:
#   - backends.enabled (tacctl.yaml), the store, every rendered artifact and
#     rendered.json are as they were;
#   - no staging or keep directory is left behind.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd logger
    stub_cmd sleep
    stub_cmd journalctl
    stub_cmd curl 'exit 7'
    stub_cmd ps 'echo 1234'
    # systemd: everything is active, and nothing else to say.
    stub_cmd systemctl '
case "$1" in
  is-active) echo active; exit 0 ;;
  show) case " $* " in *MainPID*) echo MainPID=4242 ;; *) echo "ActiveEnterTimestamp=Fri 2026-10-02 10:00:00 UTC" ;; esac ;;
esac
exit 0'
    # tcp: tacquito on 49; udp: the stand-in on 1812 and 1813.
    stub_cmd ss 'case "$*" in
  *-u*) echo "UNCONN 0 0 *:1812 *:*"; echo "UNCONN 0 0 *:1813 *:*" ;;
  *)    echo "LISTEN 0 128 *:49 *:* users:((\"tacquito\",pid=4242,fd=3))" ;;
esac'
    STORE="${TACCTL_STATE_DIR}/store.yaml"
    RENDERED="${TACCTL_STATE_DIR}/rendered.json"
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    export FAKE_DIR="${BATS_TEST_TMPDIR}/fake"
    export FAKE_CONF="${TACCTL_ETC}/fake.conf"
    export FAKE_LOG="${BATS_TEST_TMPDIR}/fake.log"
    FAKE_SH="${BATS_TEST_TMPDIR}/fake_backend.sh"
    mkdir -p "$FAKE_DIR"
    : > "$FAKE_LOG"
    export TMPDIR="${BATS_TEST_TMPDIR}/tmp"
    mkdir -p "$TMPDIR"
    # tacquito is installed.
    touch "${TACCTL_BIN}/tacquito" "$(dirname "$TACCTL_OVERRIDE_DIR")/tacquito.service"
    chmod +x "${TACCTL_BIN}/tacquito"

    cp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    chmod 600 "$STORE"
    "$TACCTL_BIN_SCRIPT" config render > /dev/null
    : > "$CALLS_LOG"
    fake_backend_write
}

# The stand-in. Knobs, all environment variables:
#   FAKE_GATE         its render_gate's answer (0, 10, 3, 1)
#   FAKE_FAIL         stage | commit: the step of its render that fails
#   FAKE_PHASE_FAIL   an install phase that exits 1
#   FAKE_START        'failed': a start or restart leaves the service not active
#   FAKE_STOP_FAIL    non-empty: 'service stop' fails
#   FAKE_CHECK        what its render_check prints (default: current)
#   FAKE_LISTEN6      non-empty: its auth listener is udp6
fake_backend_write() {
    cat > "$FAKE_SH" <<'FAKE'
BACKEND_IDS+=(fake)
BACKEND_START_WAIT=0
_fake_state() { cat "${FAKE_DIR}/active" 2>/dev/null || echo inactive; }
_fake_up() { if [[ "${FAKE_START:-ok}" == "ok" ]]; then echo active > "${FAKE_DIR}/active"; else echo failed > "${FAKE_DIR}/active"; fi; }
backend_fake_describe() { printf '%s\n' "protocol=fake" "impl=faked" "units=fake.service" "log_dir=${FAKE_DIR}"; }
backend_fake_installed() { [[ -f "${FAKE_DIR}/installed" ]]; }
backend_fake_install() {
    echo "install $1 $2" >> "$FAKE_LOG"
    if [[ "${FAKE_PHASE_FAIL:-}" == "$1" ]]; then
        error "fake: ${1} failed"
        exit 1
    fi
    case "$1" in
        account) touch "${FAKE_DIR}/installed" ;;
        start)   echo "enabled" > "${FAKE_DIR}/boot"; _fake_up ;;
    esac
}
backend_fake_upgrade() { :; }
backend_fake_uninstall() { :; }
backend_fake_artifacts() { printf '%s\n' "$FAKE_CONF"; }
backend_fake_render_gate() { echo "gate" >> "$FAKE_LOG"; return "${FAKE_GATE:-0}"; }
backend_fake_render_stage() {
    echo "stage ${2:-}" >> "$FAKE_LOG"
    if [[ "${FAKE_FAIL:-}" == "stage" ]]; then
        error "fake: cannot express this model"
        return 1
    fi
    model_users > "${1}/fake.conf"
}
backend_fake_render_commit() {
    echo "commit" >> "$FAKE_LOG"
    if [[ "${FAKE_FAIL:-}" == "commit" ]]; then
        printf 'half a fake render\n' > "$FAKE_CONF"
        printf '{}\n' > "$RENDERED_FILE"
        return 1
    fi
    if cmp -s "${1}/fake.conf" "$FAKE_CONF"; then
        echo "UNCHANGED"
        return 0
    fi
    cp "${1}/fake.conf" "$FAKE_CONF" || return 1
    rendered_record "$FAKE_CONF" || return 1
    echo "CHANGED"
}
backend_fake_render_check() { echo "${FAKE_CHECK:-current}"; }
backend_fake_render_notes() { :; }
backend_fake_service() {
    echo "service $*" >> "$FAKE_LOG"
    case "${1:-}" in
        start|restart) _fake_up ;;
        stop)
            [[ -z "${FAKE_STOP_FAIL:-}" ]] || return 1
            echo inactive > "${FAKE_DIR}/active"
            ;;
        enable)  echo enabled > "${FAKE_DIR}/boot" ;;
        disable) echo disabled > "${FAKE_DIR}/boot" ;;
        is-active) local s; s=$(_fake_state); echo "$s"; [[ "$s" == "active" ]] ;;
        since) echo "Fri 2026-10-02 10:00:00 UTC" ;;
        pid)   echo 777 ;;
    esac
}
backend_fake_listeners() {
    case "${1:-}" in
        list)
            if [[ -n "${FAKE_LISTEN6:-}" ]]; then echo "auth udp6 [::]:1812"; else echo "auth udp :1812"; fi
            echo "acct udp :1813"
            ;;
    esac
}
backend_fake_status() {
    case "${1:-}" in
        service)    echo -e "  ${BOLD}Fake service:${NC}         $(_fake_state)" ;;
        config)     echo -e "  ${BOLD}Fake config:${NC}          ${FAKE_CONF}" ;;
        accounting) echo "  Fake accounting:      0 entries" ;;
        activity)   echo ""; echo "  Fake activity:        quiet" ;;
    esac
}
backend_fake_log() { echo "fake log $*"; }
backend_fake_accounting() { echo "fake accounting $*"; }
backend_fake_last_login() { echo never; }
backend_fake_secret_constraints() { printf '%s\n' "max_len=" "charset="; }
backend_fake_device_vars() { :; }
FAKE
}

# tc <function> [args]: the function in a bash that has sourced tacctl.sh and
# the stand-in, under the script's own options. Output and status via 'run'.
tc() {
    run bash -c 'set -euo pipefail; source "$1"; source "$2"; shift 2; "$@"' _ \
        "$TACCTL_BIN_SCRIPT" "$FAKE_SH" "$@"
    # Without the colours, so that a pattern can span a label and its value.
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# Write backends.enabled by hand (the real tacctl.sh cannot read the stand-in).
enable_by_hand() {
    printf 'backends:\n  enabled: [%s]\n' "$1" > "$OVERRIDES"
}

# Bring the stand-in fully up: installed, enabled, rendered, running.
fake_up() {
    : > "${FAKE_DIR}/installed"
    tc cmd_backend_enable fake -y
    assert_success
    : > "$FAKE_LOG"
    : > "$CALLS_LOG"
}

state() {
    local f
    for f in "$STORE" "$OVERRIDES" "$TACCTL_CONFIG" "$FAKE_CONF" "$RENDERED"; do
        if [[ -f "$f" ]]; then
            echo "$(basename "$f") $(sha256sum < "$f")"
        else
            echo "$(basename "$f") absent"
        fi
    done
}

no_leftovers() {
    [[ -z "$(find "$TMPDIR" -mindepth 1 -maxdepth 1)" ]]
    [[ -z "$(find "$TACCTL_STATE_DIR" -maxdepth 1 \( -name '.apply.*' -o -name '.enable.*' -o -name '.disable.*' \))" ]]
    [[ -z "$(find "$TACCTL_ETC" -name '*.tacctl-new')" ]]
}

enabled_now() {
    python3 - "$OVERRIDES" <<'PY'
import sys, yaml
try:
    d = yaml.safe_load(open(sys.argv[1])) or {}
except FileNotFoundError:
    d = {}
print(' '.join((d.get('backends') or {}).get('enabled') or ['tacacs']))
PY
}

# --- list and status ---------------------------------------------------------

@test "backend list: every backend with protocol, implementation, installed, enabled, service" {
    tc cmd_backend list
    assert_success
    assert_line --regexp 'ID +PROTOCOL +IMPLEMENTATION +INSTALLED +ENABLED +SERVICE'
    assert_line --regexp '^  tacacs +tacacs +tacquito +yes +yes +active'
    assert_line --regexp '^  fake +fake +faked +no +no +-'
}

@test "backend list: an installed, disabled backend shows its own service state" {
    echo active > "${FAKE_DIR}/active"
    : > "${FAKE_DIR}/installed"
    tc cmd_backend list
    assert_line --regexp '^  fake +fake +faked +yes +no +active'
}

@test "backend list: needs no store and does not write anything" {
    rm "$STORE"
    local before
    before=$(state)
    tc cmd_backend list
    assert_success
    [[ "$(state)" == "$before" ]]
    ! stub_called 'systemctl (start|stop|restart|enable|disable)'
}

@test "backend status: per backend, the service and each listener, tcp and udp probed apart" {
    fake_up
    tc cmd_backend status
    assert_success
    assert_line --partial "== Backend: tacacs (tacacs, tacquito) =="
    assert_line --partial "== Backend: fake (fake, faked) =="
    assert_line --regexp 'State:.*installed, enabled'
    assert_line --regexp 'Service:.*active'
    assert_line --regexp 'Listener default:.* tcp :49 — unit active, .*listening on \*:49'
    assert_line --regexp 'Listener auth:.* udp :1812 — unit active, .*listening on \*:1812'
    assert_line --regexp 'Listener acct:.* udp :1813 — unit active, .*listening on \*:1813'
    stub_called '^ss -ulnp'
    stub_called '^ss -tlnp'
}

@test "backend status: one backend by id, a port nobody listens on is named, a missing backend is said" {
    stub_cmd ss
    tc cmd_backend status tacacs
    assert_success
    refute_output --partial "Backend: fake"
    assert_line --regexp 'Listener default:.*port 49 not detected'
    tc cmd_backend status fake
    assert_success
    assert_line --regexp 'State:.*not installed, not enabled'
    tc cmd_backend status nope
    assert_failure 1
    assert_output --partial "Unknown backend 'nope' (known: tacacs radius fake)"
}

@test "backend list and status are read-only commands: they never write or start anything" {
    fake_up
    local before
    before=$(state)
    tc cmd_backend list
    tc cmd_backend status
    [[ "$(state)" == "$before" ]]
    ! grep -qE 'service (start|stop|restart|enable|disable)' "$FAKE_LOG"
    ! stub_called 'systemctl (start|stop|restart|enable|disable)'
}

@test "backend: no subcommand, or an unknown one, prints the usage and fails" {
    tc cmd_backend
    assert_failure 1
    assert_output --partial "tacctl backend <subcommand>"
    assert_output --partial "enable <id>"
    tc cmd_backend frobnicate
    assert_failure 1
}

# --- enable ------------------------------------------------------------------

@test "backend enable: installs, gates the new backend, renders everything, starts it, in that order" {
    tc cmd_backend_enable fake -y
    assert_success
    assert_output --partial "Backend 'fake' is enabled and running."
    [[ "$(enabled_now)" == "tacacs fake" ]]
    grep -q '^bob$' "$FAKE_CONF"
    run cat "$FAKE_LOG"
    assert_line --index 0 "install build ${TACCTL_SRC}"
    assert_line --index 1 "install files ${TACCTL_SRC}"
    assert_line --index 2 "install account ${TACCTL_SRC}"
    assert_line --index 3 "gate"
    assert_line --index 4 "stage "
    assert_line --index 5 "commit"
    assert_line --index 6 "install start ${TACCTL_SRC}"
    # Recorded for drift, and the running tacquito was not touched.
    cd "$TACCTL_SRC"
    run bash -c 'source "$1"; rendered_check "$2"' _ "$TACCTL_BIN_SCRIPT" "$FAKE_CONF"
    assert_output "ok"
    ! stub_called 'systemctl restart'
    no_leftovers
}

@test "backend enable: the prompt is shown for an install; no answers 'no' and nothing is touched" {
    local before
    before=$(state)
    tc cmd_backend_enable fake <<< "n"
    assert_success
    assert_output --partial "Backend 'fake' is not installed. Enabling it installs faked"
    assert_output --partial "Cancelled. Nothing was changed."
    [[ "$(state)" == "$before" ]]
    [[ ! -s "$FAKE_LOG" ]]
    [[ ! -e "${FAKE_DIR}/installed" ]]
    # and an empty stdin (no terminal) is a no, not a yes
    tc cmd_backend_enable fake < /dev/null
    [[ ! -e "${FAKE_DIR}/installed" ]]
}

@test "backend enable: yes at the prompt installs" {
    tc cmd_backend_enable fake <<< "y"
    assert_success
    [[ "$(enabled_now)" == "tacacs fake" ]]
}

@test "backend enable: an installed backend is not installed again; it is enabled at boot and restarted onto its new config" {
    : > "${FAKE_DIR}/installed"
    tc cmd_backend_enable fake
    assert_success
    refute_output --partial "is not installed. Enabling it installs"
    run cat "$FAKE_LOG"
    refute_output --partial "install "
    assert_line "service enable"
    assert_line "service restart"
    [[ "$(cat "${FAKE_DIR}/boot")" == "enabled" ]]
    [[ "$(enabled_now)" == "tacacs fake" ]]
}

@test "backend enable: an installed backend whose config did not change is started, not restarted" {
    : > "${FAKE_DIR}/installed"
    tc cmd_backend_enable fake
    assert_success
    tc cmd_backend_disable fake -y
    assert_success
    : > "$FAKE_LOG"
    # Its artifact is still there and still what the store renders.
    tc cmd_backend_enable fake
    assert_success
    run cat "$FAKE_LOG"
    assert_line "service enable"
    assert_line "service start"
    refute_line "service restart"
}

@test "backend enable: already enabled is said, not an error, and changes nothing" {
    fake_up
    local before
    before=$(state)
    tc cmd_backend_enable fake -y
    assert_success
    assert_output --partial "already enabled"
    [[ "$(state)" == "$before" ]]
    [[ ! -s "$FAKE_LOG" ]]
}

@test "backend enable: an unknown or missing id is refused" {
    local before
    before=$(state)
    tc cmd_backend_enable ldap -y
    assert_failure 1
    assert_output --partial "Unknown backend 'ldap'"
    tc cmd_backend_enable
    assert_failure 1
    tc cmd_backend_enable fake extra -y
    assert_failure 1
    tc cmd_backend_enable --bogus fake
    assert_failure 1
    [[ "$(state)" == "$before" ]]
}

@test "backend enable: refused without a store, before anything is installed" {
    rm "$STORE"
    local before
    before=$(state)
    tc cmd_backend_enable fake -y
    assert_failure 1
    assert_output --partial "store not initialised"
    [[ "$(state)" == "$before" ]]
    [[ ! -s "$FAKE_LOG" ]]
}

@test "backend enable: an install step that fails leaves backends.enabled, the store and every artifact as they were" {
    export FAKE_PHASE_FAIL=files
    local before
    before=$(state)
    tc cmd_backend_enable fake -y
    assert_failure 1
    assert_output --partial "install step 'files' failed"
    assert_output --partial "was not enabled"
    [[ "$(state)" == "$before" ]]
    run cat "$FAKE_LOG"
    refute_output --partial "gate"
    no_leftovers
}

@test "backend enable: the new backend's gate refuses (exit 3); everything as it was, the install stays" {
    export FAKE_GATE=3
    local before
    before=$(state)
    tc cmd_backend_enable fake -y
    assert_failure 3
    assert_output --partial "was not enabled"
    assert_output --partial "the install stays on this machine"
    [[ "$(state)" == "$before" ]]
    [[ -f "${FAKE_DIR}/installed" ]]
    run cat "$FAKE_LOG"
    refute_output --partial "stage"
    no_leftovers
}

@test "backend enable: a gate that says 'adopt' renders that backend with force" {
    export FAKE_GATE=10
    tc cmd_backend_enable fake -y
    assert_success
    grep -qx 'stage --force' "$FAKE_LOG"
    [[ "$(enabled_now)" == "tacacs fake" ]]
}

@test "backend enable: a hand-edited artifact of an enabled backend refuses it (exit 3) before anything is written" {
    echo "# hand edit" >> "$TACCTL_CONFIG"
    local before
    before=$(state)
    tc cmd_backend_enable fake -y
    assert_failure 3
    assert_output --partial "was edited since tacctl rendered it"
    [[ "$(state)" == "$before" ]]
    no_leftovers
}

@test "backend enable: a backend that cannot stage its render leaves every artifact and the store untouched" {
    export FAKE_FAIL=stage
    local before
    before=$(state)
    tc cmd_backend_enable fake -y
    assert_failure 1
    assert_output --partial "fake: cannot express this model"
    # the new backend's artifact is named among those that could not be rendered
    assert_output --partial "${FAKE_CONF} could not be rendered"
    assert_output --partial "was not enabled"
    [[ "$(state)" == "$before" ]]
    ! stub_called 'systemctl restart'
    no_leftovers
}

@test "backend enable: a commit that fails after damaging its artifact is undone, records and all" {
    export FAKE_FAIL=commit
    local before
    before=$(state)
    tc cmd_backend_enable fake -y
    assert_failure 1
    [[ "$(state)" == "$before" ]]
    [[ ! -e "$FAKE_CONF" ]]
    no_leftovers
}

@test "backend enable: a start step that fails undoes the enable, the render and the records" {
    export FAKE_PHASE_FAIL=start
    local before
    before=$(state)
    tc cmd_backend_enable fake -y
    assert_failure 1
    assert_output --partial "install step 'start' failed"
    assert_output --partial "undoing the change"
    assert_output --partial "back as they were"
    [[ "$(state)" == "$before" ]]
    [[ ! -e "$FAKE_CONF" ]]
    [[ "$(enabled_now)" == "tacacs" ]]
    # stopped and disabled, and the install stays
    grep -qx 'service stop' "$FAKE_LOG"
    grep -qx 'service disable' "$FAKE_LOG"
    [[ -f "${FAKE_DIR}/installed" ]]
    no_leftovers
}

@test "backend enable: an installed backend that does not report active afterwards is undone" {
    : > "${FAKE_DIR}/installed"
    export FAKE_START=failed
    local before
    before=$(state)
    tc cmd_backend_enable fake
    assert_failure 1
    assert_output --partial "did not come up (service failed)"
    [[ "$(state)" == "$before" ]]
    [[ ! -e "$FAKE_CONF" ]]
    [[ "$(cat "${FAKE_DIR}/boot")" == "disabled" ]]
    no_leftovers
    # nothing is stuck: with the fault gone the same command works
    unset FAKE_START
    tc cmd_backend_enable fake
    assert_success
    [[ "$(enabled_now)" == "tacacs fake" ]]
}

@test "backend enable: an undo restarts the backends the render had restarted, onto what they had" {
    : > "${FAKE_DIR}/installed"
    export FAKE_START=failed
    # A change that makes tacquito's render differ is not what enable does, so
    # force it: tacquito.yaml is missing, so the enable's render recreates it.
    rm "$TACCTL_CONFIG"
    rm "$RENDERED"
    : > "$CALLS_LOG"
    tc cmd_backend_enable fake
    assert_failure 1
    # restarted once by the render, once more by the undo
    run grep -c '^systemctl restart tacquito$' "$CALLS_LOG"
    assert_output "2"
    [[ ! -e "$TACCTL_CONFIG" ]]
}

# --- disable -----------------------------------------------------------------

@test "backend disable: confirms, takes it out of backends.enabled, stops and disables it, leaves its files" {
    fake_up
    tc cmd_backend_disable fake <<< "y"
    assert_success
    assert_output --partial "This takes backend 'fake' out of backends.enabled"
    assert_output --partial "Backend 'fake' is disabled"
    assert_output --partial "Left in place: its package and ${FAKE_CONF}"
    [[ "$(enabled_now)" == "tacacs" ]]
    grep -qx 'service stop' "$FAKE_LOG"
    grep -qx 'service disable' "$FAKE_LOG"
    [[ "$(cat "${FAKE_DIR}/boot")" == "disabled" ]]
    [[ -f "$FAKE_CONF" ]]
    [[ -f "${FAKE_DIR}/installed" ]]
    grep -q "$FAKE_CONF" "$RENDERED"
    no_leftovers
}

@test "backend disable: 'no' at the prompt changes nothing" {
    fake_up
    local before
    before=$(state)
    tc cmd_backend_disable fake <<< "n"
    assert_success
    assert_output --partial "Cancelled. Nothing was changed."
    [[ "$(state)" == "$before" ]]
    ! grep -q 'service stop' "$FAKE_LOG"
    tc cmd_backend_disable fake < /dev/null
    [[ "$(enabled_now)" == "tacacs fake" ]]
}

@test "backend disable: -y skips the prompt" {
    fake_up
    tc cmd_backend_disable fake -y
    assert_success
    refute_output --partial "Cancelled"
    [[ "$(enabled_now)" == "tacacs" ]]
}

@test "backend disable: the last enabled backend is refused" {
    local before
    before=$(state)
    tc cmd_backend_disable tacacs -y
    assert_failure 1
    assert_output --partial "only enabled backend"
    assert_output --partial "tacctl backend enable <id>"
    [[ "$(state)" == "$before" ]]
    ! stub_called 'systemctl (stop|disable)'
}

@test "backend disable: tacacs is refused while there is no store, even with another backend enabled" {
    fake_up
    rm "$STORE"
    local before
    before=$(state)
    tc cmd_backend_disable tacacs -y
    assert_failure 1
    assert_output --partial "cannot be disabled while there is no store"
    [[ "$(state)" == "$before" ]]
    ! stub_called 'systemctl (stop|disable)'
}

@test "backend disable: another backend can be disabled without a store (tacctl.yaml only)" {
    fake_up
    rm "$STORE"
    tc cmd_backend_disable fake -y
    assert_success
    [[ "$(enabled_now)" == "tacacs" ]]
    grep -qx 'service stop' "$FAKE_LOG"
    no_leftovers
}

@test "backend disable: tacacs, when another backend stays, stops and disables tacquito and keeps tacquito.yaml" {
    fake_up
    local yaml_before
    yaml_before=$(sha256sum < "$TACCTL_CONFIG")
    tc cmd_backend_disable tacacs -y
    assert_success
    [[ "$(enabled_now)" == "fake" ]]
    stub_called '^systemctl stop tacquito$'
    stub_called '^systemctl disable tacquito.service$'
    [[ "$(sha256sum < "$TACCTL_CONFIG")" == "$yaml_before" ]]
}

@test "backend disable: not enabled is said, not an error; unknown is refused" {
    tc cmd_backend_disable fake -y
    assert_success
    assert_output --partial "not enabled. Nothing to do."
    tc cmd_backend_disable ldap -y
    assert_failure 1
    assert_output --partial "Unknown backend 'ldap'"
}

@test "backend disable: the gate covers the backends that stay, not the one going" {
    fake_up
    # The one being disabled refuses its gate: that must not stop its disabling.
    export FAKE_GATE=3
    tc cmd_backend_disable fake -y
    assert_success
    [[ "$(enabled_now)" == "tacacs" ]]
    # A backend that stays and was edited by hand does stop it.
    unset FAKE_GATE
    tc cmd_backend_enable fake
    assert_success
    echo "# hand edit" >> "$TACCTL_CONFIG"
    local before
    before=$(state)
    tc cmd_backend_disable fake -y
    assert_failure 3
    assert_output --partial "was not disabled"
    [[ "$(state)" == "$before" ]]
    no_leftovers
}

@test "backend disable: a service that will not stop is reported, with what to run; backends.enabled is already updated" {
    fake_up
    export FAKE_STOP_FAIL=1
    tc cmd_backend_disable fake -y
    assert_failure 1
    assert_output --partial "out of backends.enabled, but its service could not be stopped or disabled"
    assert_output --partial "systemctl stop fake.service"
    [[ "$(enabled_now)" == "tacacs" ]]
}

@test "backend disable then enable: the same files, and the backend serves again" {
    fake_up
    local rendered_before
    rendered_before=$(sha256sum < "$FAKE_CONF")
    tc cmd_backend_disable fake -y
    assert_success
    tc cmd_backend_enable fake
    assert_success
    [[ "$(sha256sum < "$FAKE_CONF")" == "$rendered_before" ]]
    [[ "$(enabled_now)" == "tacacs fake" ]]
    [[ "$(cat "${FAKE_DIR}/active")" == "active" ]]
}

@test "mutations after a disable render only the backends that are enabled" {
    fake_up
    tc cmd_backend_disable fake -y
    assert_success
    : > "$FAKE_LOG"
    tc store_apply store_user_del carol
    assert_success
    [[ ! -s "$FAKE_LOG" ]]
    # tacquito's file followed the change; the disabled backend's did not
    ! grep -q 'carol' "$TACCTL_CONFIG"
    grep -qx 'carol' "$FAKE_CONF"
}

@test "store rollback: refused while another backend is enabled, since legacy mode is TACACS+ only" {
    fake_up
    local before
    before=$(state)
    tc cmd_store_rollback
    assert_failure 1
    assert_output --partial "Backend(s) fake are enabled"
    assert_output --partial "tacctl backend disable <id>"
    [[ "$(state)" == "$before" ]]
}

# --- the tacacs module's own enable and disable of its units -------------------

@test "tacacs service enable and disable act on every listener's unit" {
    "$TACCTL_BIN_SCRIPT" config listen --listener mgmt tcp 127.0.0.1:4949 > /dev/null
    : > "$CALLS_LOG"
    run bash -c 'source "$1"; backend_call tacacs service enable; backend_call tacacs service disable' _ "$TACCTL_BIN_SCRIPT"
    assert_success
    stub_called '^systemctl enable tacquito.service tacquito@mgmt.service$'
    stub_called '^systemctl disable tacquito.service tacquito@mgmt.service$'
}

# --- drift of what a disabled backend left behind ------------------------------

@test "drift: a hand edit of a disabled backend's artifact is not reported; an enabled one's is, with its own hint" {
    fake_up
    echo "intruder" >> "$FAKE_CONF"
    tc backends_check_drift
    assert_failure 1
    assert_output "drift	${FAKE_CONF}"
    tc print_drift_lines
    assert_output --partial "${FAKE_CONF} — edited since tacctl rendered it"
    assert_output --partial "discard the edits: 'tacctl config render --force'"
    refute_output --partial "store import"
    tc backends_check_drift fake
    assert_failure 1
    tc backends_check_drift tacacs
    assert_success
    tc cmd_backend_disable fake -y
    assert_success
    tc backends_check_drift
    assert_success
    assert_output ""
}

@test "drift: tacquito's artifacts keep the hint that adopts a hand edit" {
    echo "# hand edit" >> "$TACCTL_CONFIG"
    run bash -c 'source "$1"; print_drift_lines' _ "$TACCTL_BIN_SCRIPT"
    assert_output --partial "keep the edits: 'tacctl store import --replace' then 'tacctl config render --force'"
}

@test "drift: a recorded file no backend claims is reported whoever is enabled" {
    printf 'x\n' > "${TACCTL_ETC}/stray.conf"
    run bash -c 'source "$1"; rendered_record "$2"; echo more >> "$2"; backends_check_drift' _ "$TACCTL_BIN_SCRIPT" "${TACCTL_ETC}/stray.conf"
    assert_failure 1
    assert_output "drift	${TACCTL_ETC}/stray.conf"
}

# --- status ------------------------------------------------------------------

@test "status: one backend prints no backend headings" {
    tc cmd_status
    assert_success
    refute_output --partial "== Backend"
    assert_line --regexp 'Service:.*active'
}

@test "status: each backend gets a labelled section with all its lines; the rest stays general" {
    fake_up
    tc cmd_status
    assert_success
    assert_line --partial "== Backend: tacacs (tacacs, tacquito) =="
    assert_line --partial "== Backend: fake (fake, faked) =="
    # tacacs's lines are in its section, fake's in its own
    local tac fk gen
    tac=$(echo "$output" | sed -n '/Backend: tacacs/,/Backend: fake/p')
    fk=$(echo "$output" | sed -n '/Backend: fake/,/Security Posture/p')
    [[ "$tac" == *"Config:"*"tacquito.yaml"* ]]
    [[ "$tac" == *"Authentication Stats"* ]]
    [[ "$fk" == *"Fake service:"*"active"* ]]
    [[ "$fk" == *"Fake config:"* ]]
    [[ "$fk" == *"Fake activity:"* ]]
    [[ "$tac" != *"Fake "* ]]
    gen=$(echo "$output" | sed -n '1,/Backend: tacacs/p')
    [[ "$gen" == *"Users:"* ]]
    [[ "$gen" == *"Config backups:"* ]]
    assert_line --partial "Security Posture:"
    assert_line --partial "Password Age Warnings:"
}

@test "status: a drifted artifact is shown in its backend's section, and not twice" {
    fake_up
    echo "intruder" >> "$FAKE_CONF"
    tc cmd_status
    assert_success
    run bash -c 'echo "$1" | sed -n "/Backend: fake/,/Security Posture/p" | grep -c "DRIFT:"' _ "$output"
    assert_output "1"
    tc cmd_status
    [[ "$(echo "$output" | sed -n '/Backend: tacacs/,/Backend: fake/p')" != *"DRIFT"* ]]
}

@test "status: an IPv6 listener of any backend triggers the ACL parity check, naming it" {
    fake_up
    export FAKE_LISTEN6=1
    tc cmd_status
    assert_line --partial "IPv6 ACL parity:"
    assert_line --partial "fake listener auth is udp6 but no IPv6 CIDRs"
}

@test "status: with one backend the IPv6 parity wording is unchanged" {
    "$TACCTL_BIN_SCRIPT" config listen tcp6 '[::]:49' <<< "y" > /dev/null
    tc cmd_status
    assert_line --partial "IPv6 ACL parity:    MISSING (listener is tcp6 but no IPv6 CIDRs — v4-mapped clients bypass ACLs)"
}

# --- config validate ---------------------------------------------------------

@test "config validate: one backend, the plain lines as always" {
    tc cmd_config_validate
    assert_success
    assert_line --regexp 'Rendered config:.* up to date'
    refute_output --partial "Backend "
}

@test "config validate: a block per backend; one backend's drift does not hide the other's state" {
    fake_up
    echo "intruder" >> "$FAKE_CONF"
    tc cmd_config_validate
    assert_failure 1
    assert_line --partial "Backend tacacs:"
    assert_line --partial "Backend fake:"
    local tac fk
    tac=$(echo "$output" | sed -n '/Backend tacacs:/,/Backend fake:/p')
    fk=$(echo "$output" | sed -n '/Backend fake:/,/Groups defined/p')
    [[ "$tac" == *"Rendered config:"*"up to date"* ]]
    [[ "$tac" != *"DRIFT"* ]]
    [[ "$fk" == *"DRIFT:"*"${FAKE_CONF}"* ]]
    [[ "$fk" == *"discard the edits"* ]]
    assert_output --partial "Validation failed with 1 error(s)."
}

@test "config validate: each backend's own render state is judged" {
    fake_up
    export FAKE_CHECK=missing
    tc cmd_config_validate
    assert_failure 1
    local fk
    fk=$(echo "$output" | sed -n '/Backend fake:/,/Groups defined/p')
    [[ "$fk" == *"${FAKE_CONF} is missing — run 'tacctl config render'"* ]]
    local tac
    tac=$(echo "$output" | sed -n '/Backend tacacs:/,/Backend fake:/p')
    [[ "$tac" == *"up to date"* ]]
}

@test "config validate: a disabled backend's edited leftovers are not an error" {
    fake_up
    tc cmd_backend_disable fake -y
    echo "intruder" >> "$FAKE_CONF"
    tc cmd_config_validate
    assert_success
    refute_output --partial "DRIFT"
    assert_output --partial "Configuration is valid."
}

@test "config validate: a store that cannot be rendered by one backend is that backend's error" {
    fake_up
    export FAKE_CHECK=bad
    tc cmd_config_validate
    # an unknown word is 'out of date'
    assert_failure 1
    [[ "$(echo "$output" | sed -n '/Backend fake:/,/Groups defined/p')" == *"out of date with the store"* ]]
}

# --- config show -------------------------------------------------------------

@test "config show: one backend, the lines it always printed" {
    tc cmd_config_show
    assert_success
    assert_line --regexp '^  Config file: +'"${TACCTL_CONFIG}"'$'
    assert_line --regexp '^  Service status: +active$'
    assert_line --regexp '^  Listening on: +\*:49$'
    refute_output --partial "Backend:"
}

@test "config show: the listener's own port is probed, not 49" {
    "$TACCTL_BIN_SCRIPT" config listen tcp 10.1.0.1:4901 > /dev/null
    stub_cmd ss 'echo "LISTEN 0 128 10.1.0.1:4901 *:*"'
    tc cmd_config_show
    assert_line --regexp '^  Listening on: +10\.1\.0\.1:4901$'
    stub_cmd ss
    tc cmd_config_show
    assert_line --regexp 'Listening on: +.*port 4901 not detected'
}

@test "config show: a block per backend, tcp and udp listeners probed apart" {
    fake_up
    tc cmd_config_show
    assert_success
    assert_line --partial "Backend: tacacs"
    assert_line --partial "Backend: fake"
    local tac fk
    tac=$(echo "$output" | sed -n '/Backend: tacacs/,/Backend: fake/p')
    fk=$(echo "$output" | sed -n '/Backend: fake/,$p')
    [[ "$tac" == *"Config file:"*"tacquito.yaml"* ]]
    [[ "$tac" == *"Listening on:"*"*:49"* ]]
    [[ "$fk" == *"Config file:"*"fake.conf"* ]]
    [[ "$fk" == *"Service status:"*"active"* ]]
    [[ "$fk" == *"Listening on (auth):"*"*:1812"* ]]
    [[ "$fk" == *"Listening on (acct):"*"*:1813"* ]]
}

# --- log ---------------------------------------------------------------------

@test "log: one backend, no heading; the arguments pass through" {
    tc cmd_log tail 5
    assert_success
    refute_output --partial "== Backend"
    stub_called '^journalctl -u tacquito --no-pager -n 5$'
}

@test "log tail|search|failures|accounting: every enabled backend, each under a heading" {
    fake_up
    tc cmd_log tail 7
    assert_success
    assert_line --partial "== Backend: tacacs (tacacs, tacquito) =="
    assert_line --partial "== Backend: fake (fake, faked) =="
    assert_line "fake log tail 7"
    stub_called '^journalctl -u tacquito --no-pager -n 7$'
    tc cmd_log search alice
    assert_line "fake log search alice"
    tc cmd_log failures
    assert_line "fake log failures"
    tc cmd_log accounting 3
    assert_line "fake accounting tail 3"
    assert_line --partial "Recent Accounting Entries"
}

@test "log --backend: one backend only, anywhere on the line, no heading" {
    fake_up
    tc cmd_log tail --backend fake 9
    assert_success
    assert_output "fake log tail 9"
    tc cmd_log --backend=tacacs
    assert_failure 1
    tc cmd_log accounting 4 --backend fake
    assert_output "fake accounting tail 4"
    : > "$CALLS_LOG"
    tc cmd_log tail --backend tacacs
    refute_output --partial "fake log"
    refute_output --partial "== Backend"
    stub_called '^journalctl -u tacquito --no-pager -n 20$'
}

@test "log --backend: an unknown id or none is refused; a disabled backend can be read" {
    tc cmd_log tail --backend nope
    assert_failure 1
    assert_output --partial "Unknown backend 'nope'"
    tc cmd_log tail --backend
    assert_failure 1
    assert_output --partial "--backend needs a backend id"
    tc cmd_log tail --backend fake
    assert_success
    assert_output "fake log tail"
}

@test "log clear: every enabled backend, each with its own confirmation, -y passed on" {
    fake_up
    tc cmd_log clear -y
    assert_success
    assert_line "fake log clear -y"
    assert_output --partial "Clear tacquito logs"
    tc cmd_log clear --backend fake
    assert_line "fake log clear"
}

@test "log with no subcommand prints the usage with --backend" {
    tc cmd_log
    assert_failure 1
    assert_output --partial "[--backend <id>]"
}

# --- backup restore ----------------------------------------------------------

@test "backup restore: a snapshot that enables a backend that is not installed is refused, nothing changed" {
    fake_up
    tc store_apply store_user_set bob disabled=true
    local snap
    snap=$(find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | tail -n 1)
    # The newest snapshot is the state before the last change: both enabled.
    grep -q 'fake' "${snap}/tacctl.yaml"
    tc cmd_backend_disable fake -y
    rm "${FAKE_DIR}/installed"
    local before
    before=$(state)
    tc _backup_restore_snapshot "$(basename "$snap")" <<< "y"
    assert_failure 1
    assert_output --partial "enables backend 'fake', which is not installed here"
    [[ "$(state)" == "$before" ]]
}

@test "backup restore: the backends a snapshot enables follow it: enabled at boot, or stopped and disabled" {
    fake_up
    # Snapshot of 'tacacs only' = the state before fake was enabled.
    local first
    first=$(find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | head -n 1)
    ! grep -q 'fake' "${first}/tacctl.yaml" 2> /dev/null
    : > "$FAKE_LOG"
    tc _backup_restore_snapshot "$(basename "$first")" <<< "y"
    assert_success
    assert_output --partial "Backend 'fake' is not enabled by this snapshot: stopping and disabling its service."
    [[ "$(enabled_now)" == "tacacs" ]]
    grep -qx 'service stop' "$FAKE_LOG"
    grep -qx 'service disable' "$FAKE_LOG"
    # And forward again: the snapshot of the state just left enables it.
    local last
    last=$(find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | tail -n 1)
    grep -q 'fake' "${last}/tacctl.yaml"
    : > "$FAKE_LOG"
    tc _backup_restore_snapshot "$(basename "$last")" <<< "y"
    assert_success
    assert_output --partial "Backend 'fake' is enabled by this snapshot."
    [[ "$(enabled_now)" == "tacacs fake" ]]
    grep -qx 'service enable' "$FAKE_LOG"
    # every enabled backend is restarted, whether or not its bytes changed
    grep -qx 'service restart' "$FAKE_LOG"
}

@test "backup restore: a render that fails in any backend leaves all files as they were" {
    fake_up
    tc store_apply store_user_set bob disabled=true
    local snap before
    snap=$(find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | tail -n 1)
    before=$(state)
    export FAKE_FAIL=stage
    tc _backup_restore_snapshot "$(basename "$snap")" <<< "y"
    assert_failure 1
    assert_output --partial "could not be rendered from it"
    [[ "$(state)" == "$before" ]]
}

# --- uninstall --------------------------------------------------------------

@test "uninstall: selects every backend that is present, enabled or not, and not the ones that are absent" {
    : > "${FAKE_DIR}/installed"
    run bash -c 'set -euo pipefail; source "$1"; source "$2"; backends_select_present; echo "${BACKENDS_ENABLED[*]}"' _ "$TACCTL_BIN_SCRIPT" "$FAKE_SH"
    assert_output "tacacs fake"
    rm "${FAKE_DIR}/installed"
    run bash -c 'set -euo pipefail; source "$1"; source "$2"; backends_select_present; echo "${BACKENDS_ENABLED[*]}"' _ "$TACCTL_BIN_SCRIPT" "$FAKE_SH"
    assert_output "tacacs"
}

@test "uninstall: a tacctl.yaml that cannot say what is enabled takes every backend" {
    printf 'backends:\n  enabled: [tacacs, gone]\n' > "$OVERRIDES"
    run bash -c 'set -euo pipefail; source "$1"; source "$2"; backends_select_present; echo "${BACKENDS_ENABLED[*]}"' _ "$TACCTL_BIN_SCRIPT" "$FAKE_SH"
    assert_output "tacacs radius fake"
}

@test "uninstall: the present backends are selected before the first phase, and the phases loop over that selection" {
    run bash -c 'source "$1"; declare -f cmd_uninstall' _ "$TACCTL_BIN_SCRIPT"
    # selected before the first phase runs, and the loops that follow use it
    [[ "$output" == *"backends_select_present"* ]]
    local before_stop
    before_stop="${output%%backends_run uninstall stop*}"
    [[ "$before_stop" == *"backends_select_present"* ]]
}
