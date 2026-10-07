#!/usr/bin/env bats
# 'tacctl backend list|status' and the per-backend sections of status and
# log, through the command line with the two shipped backends (TACACS+
# installed and enabled; RADIUS neither, or enabled by hand). 'backend
# enable|disable' with the real RADIUS module are in radius.bats; the
# generic machinery with a stand-in backend (gate, stage, commit, undo) is
# tested in Go with internal/backend/faketest.

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
    # tcp: tacquito on 49; udp: 1812 and 1813.
    stub_cmd ss 'case "$*" in
  *-u*) echo "UNCONN 0 0 *:1812 *:*"; echo "UNCONN 0 0 *:1813 *:*" ;;
  *)    echo "LISTEN 0 128 *:49 *:* users:((\"tacquito\",pid=4242,fd=3))" ;;
esac'
    STORE="${TACCTL_STATE_DIR}/store.yaml"
    RENDERED="${TACCTL_STATE_DIR}/rendered.json"
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    export TMPDIR="${BATS_TEST_TMPDIR}/tmp"
    mkdir -p "$TMPDIR"
    # tacquito is installed.
    touch "${TACCTL_BIN}/tacquito" "$(dirname "$TACCTL_OVERRIDE_DIR")/tacquito.service"
    chmod +x "${TACCTL_BIN}/tacquito"

    cp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    chmod 600 "$STORE"
    "$TACCTL_BIN_SCRIPT" config render > /dev/null
    : > "$CALLS_LOG"
}

# Write backends.enabled by hand.
enable_by_hand() {
    printf 'backends:\n  enabled: [%s]\n' "$1" > "$OVERRIDES"
}

state() {
    local f
    for f in "$STORE" "$OVERRIDES" "$TACCTL_CONFIG" "$RENDERED"; do
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

# Without the colours, for patterns that span a label and its value.
run_plain() {
    run "$TACCTL_BIN_SCRIPT" "$@"
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# bats test_tags=cutover:wp2-4d
@test "cli: backend list shows both shipped backends, installed and enabled or not" {
    run_plain backend list
    assert_success
    assert_line --regexp '^  ID +PROTOCOL +IMPLEMENTATION +INSTALLED +ENABLED +SERVICE'
    assert_line --regexp '^  tacacs +tacacs +tacquito +yes +yes +active$'
    assert_line --regexp '^  radius +radius +freeradius +no +no +-$'
}

# bats test_tags=cutover:wp2-4d
@test "cli: backend status shows each backend under a heading; one id; an unknown or empty one is refused" {
    run_plain backend status
    assert_success
    assert_line "== Backend: tacacs (tacacs, tacquito) =="
    assert_line "== Backend: radius (radius, freeradius) =="
    assert_line --regexp '^  State: +installed, enabled$'
    assert_line --regexp '^  Service: +active$'
    assert_line --regexp '^  Listener default: tcp :49 — unit active, listening on \*:49$'
    assert_line --regexp '^  State: +not installed, not enabled$'
    stub_called '^ss -tlnp'
    run_plain backend status radius
    assert_success
    refute_output --partial "Backend: tacacs"
    assert_line --regexp '^  State: +not installed, not enabled$'
    run_plain backend status nope
    assert_failure 1
    assert_output --partial "Unknown backend 'nope' (known: tacacs radius)."
    run_plain backend status ""
    assert_failure 1
    assert_output --partial "Missing backend id (known: tacacs radius)."
}

# bats test_tags=cutover:wp2-4d
@test "cli: backend status names a port nobody listens on" {
    stub_cmd ss
    run_plain backend status tacacs
    assert_success
    assert_line --regexp '^  Listener default: tcp :49 — unit active, port 49 not detected$'
}

# bats test_tags=cutover:wp2-4d
@test "cli: backend list and status write nothing and start nothing" {
    local before
    before=$(state)
    run "$TACCTL_BIN_SCRIPT" backend list
    assert_success
    run "$TACCTL_BIN_SCRIPT" backend status
    assert_success
    [[ "$(state)" == "$before" ]]
    ! stub_called 'systemctl (start|stop|restart|enable|disable)'
    no_leftovers
}

# bats test_tags=cutover:wp2-4d
@test "cli: backend with no subcommand or an unknown one prints the usage, exit 1" {
    run "$TACCTL_BIN_SCRIPT" backend
    assert_failure 1
    assert_output --partial "Usage: tacctl backend <subcommand> [arguments]"
    assert_output --partial "Backends: tacacs radius"
    run "$TACCTL_BIN_SCRIPT" backend frobnicate
    assert_failure 1
    assert_output --partial "enable <id> [-y]"
}

# bats test_tags=cutover:wp2-4d
@test "cli: a backends.enabled naming no backend is refused by list, status and log" {
    enable_by_hand "tacacs, ldap"
    for cmd in "backend list" "backend status" "log tail" "status"; do
        # shellcheck disable=SC2086
        run "$TACCTL_BIN_SCRIPT" $cmd
        assert_failure 1
        assert_output --partial "backends.enabled names 'ldap', and this tacctl has no such backend (it has: tacacs radius)."
    done
}

# bats test_tags=cutover:wp2-4d
@test "cli: status and log with two enabled backends: a section each, under its heading" {
    enable_by_hand "tacacs, radius"
    run_plain status
    assert_success
    assert_line "== Backend: tacacs (tacacs, tacquito) =="
    assert_line "== Backend: radius (radius, freeradius) =="
    assert_line --regexp '^  Users: +3$'
    assert_line --regexp '^  Config backups: +[0-9]+'
    run_plain log tail 5
    assert_success
    assert_line "== Backend: tacacs (tacacs, tacquito) =="
    assert_line "== Backend: radius (radius, freeradius) =="
    stub_called '^journalctl -u tacquito --no-pager -n 5'
    run_plain log tail --backend radius
    assert_success
    refute_output --partial "== Backend:"
    ! stub_called '^journalctl -u tacquito --no-pager -n 20'
}

@test "cli: log tail -f prints the tails, then follows every backend, each line behind its id" {
    enable_by_hand "tacacs, radius"
    stub_cmd journalctl 'if [[ " $* " == *" -f "* ]]; then echo "srv1 tacquito[1]: new entry"; fi'
    stub_cmd tail 'printf "%s\n" "auth: Access-Accept user=alice"'
    run_plain log tail -f 5
    assert_success
    assert_line "== Backend: tacacs (tacacs, tacquito) =="
    assert_line "Following new entries (Ctrl-C to stop)..."
    assert_line "[tacacs] srv1 tacquito[1]: new entry"
    assert_line "[radius] auth: Access-Accept user=alice"
    stub_called '^journalctl -u tacquito --no-pager -n 5$'
    stub_called '^journalctl -u tacquito --no-pager -f -n 0$'
    stub_called '^tail -F -q -n 0 .*tacctl-auth.log '
    refute_output --partial "invalid number of lines"
    # One backend: no prefix.
    run_plain log tail --follow --backend tacacs
    assert_success
    assert_line "srv1 tacquito[1]: new entry"
}

# bats test_tags=cutover:wp2-4d
@test "cli: log --backend: unknown or missing id refused; --backend=<id> anywhere; a disabled backend can be read" {
    run "$TACCTL_BIN_SCRIPT" log tail --backend nope
    assert_failure 1
    assert_output --partial "Unknown backend 'nope' (known: tacacs radius)."
    run "$TACCTL_BIN_SCRIPT" log failures --backend
    assert_failure 1
    assert_output --partial "--backend needs a backend id. Usage: tacctl log failures [--backend <id>] ..."
    run_plain log --backend=tacacs tail
    assert_failure 1
    assert_output --partial "Usage: tacctl log <subcommand> [--backend <id>] [arguments]"
    run_plain log tail 3 --backend=tacacs
    assert_success
    stub_called '^journalctl -u tacquito --no-pager -n 3'
    run_plain log accounting --backend radius
    assert_success
    refute_output --partial "== Backend:"
}

# bats test_tags=cutover:wp2-4d
@test "cli: completion names backends, and the enabled ones" {
    run "$TACCTL_BIN_SCRIPT" _completion-names backends
    assert_success
    assert_output "tacacs
radius"
    run "$TACCTL_BIN_SCRIPT" _completion-names enabled-backends
    assert_success
    assert_output "tacacs"
    enable_by_hand "radius, tacacs"
    run "$TACCTL_BIN_SCRIPT" _completion-names enabled-backends
    assert_output "radius
tacacs"
    enable_by_hand "tacacs, ldap"
    run "$TACCTL_BIN_SCRIPT" _completion-names enabled-backends
    assert_success
    assert_output ""
}
