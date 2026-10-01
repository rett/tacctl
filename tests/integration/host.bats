#!/usr/bin/env bats
# Integration tests for 'tacctl host' (enroll / sync / unenroll / list) with
# ssh stubbed: the stub stores what would have been copied to the host and
# records the command that would have run there.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_LINUX_DIR="${BATS_TEST_TMPDIR}/linux"
    export PUSHED="${BATS_TEST_TMPDIR}/pushed"
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    "$TACCTL_BIN_SCRIPT" scope secret lab set "0123456789abcdef0123456789abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$HASH" --scopes lab > /dev/null
    mkdir -p "$TACCTL_LINUX_DIR"
    echo "not really a tarball" > "$TACCTL_LINUX_DIR/pam_tacplus-1.7.0.tar.gz"

    stub_cmd getent 'echo "192.0.2.50 STREAM web1"'
    stub_cmd ip 'echo "192.0.2.50 dev eth0 src 192.0.2.1 uid 0"'
    # Copy step (remote command contains mktemp): keep stdin, print a path.
    # Run step: succeed unless SSH_RUN_FAILS is set.
    stub_cmd ssh 'case "$*" in
        *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *) [[ -z "${SSH_RUN_FAILS:-}" ]] ;;
    esac'
}

_hosts() { cat "$TACCTL_ETC/linux-hosts" 2>/dev/null; }

@test "host enroll: pushes the install script and registers the host" {
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab
    assert_success
    assert_output --partial "Host 'web1' enrolled"
    run _hosts
    assert_output "web1|admin@web1.example.net||lab|192.0.2.1|"
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_output --partial "TAC_SERVER=192.0.2.1"
    assert_output --partial "TAC_SECRET=0123456789abcdef0123456789abcdef"
    assert_output --partial "alice:superuser:20000"
    grep -q '^__TARBALL__$' "$PUSHED"
    # Ran as root or via sudo on the host, then removed the copy.
    stub_called "ssh .*admin@web1.example.net .*sudo -n bash /tmp/tacctl.AbCd1234 ;.*rm -f /tmp/tacctl.AbCd1234"
}

@test "host enroll: without --scope creates a per-host /32 scope with its own secret" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope lookup 192.0.2.50
    assert_output --partial "linux-web1"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1|"
    run grep -c "TAC_SECRET=0123456789abcdef0123456789abcdef" "$PUSHED"
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_success
    assert_output --partial "Using existing scope"
}

@test "host enroll: passes port and identity to ssh and names bare IPs" {
    touch "$BATS_TEST_TMPDIR/key"
    run "$TACCTL_BIN_SCRIPT" host enroll root@192.0.2.50 --scope lab --port 2222 --identity "$BATS_TEST_TMPDIR/key"
    assert_success
    stub_called "ssh -o ConnectTimeout=10 -p 2222 -i ${BATS_TEST_TMPDIR}/key "
    run _hosts
    assert_output --partial "h192-0-2-50|root@192.0.2.50|2222|lab|"
}

@test "host enroll: a failed remote run registers nothing" {
    SSH_RUN_FAILS=1 run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_failure
    assert_output --partial "was not registered"
    run _hosts
    assert_output ""
}

@test "host enroll: rejects option-like and malformed targets" {
    run "$TACCTL_BIN_SCRIPT" host enroll "web1;reboot" --scope lab
    assert_failure
    run "$TACCTL_BIN_SCRIPT" host enroll -oProxyCommand=x --scope lab
    assert_failure
    run grep -c "^ssh" "$CALLS_LOG"
    assert_output "0"
}

@test "host enroll: needs the prepared tarball and an existing scope" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope nope
    assert_failure
    rm -f "$TACCTL_LINUX_DIR"/*.tar.gz
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_failure
    assert_output --partial "tacctl config linux build"
}

@test "host sync: pushes an accounts-only script without the tarball" {
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add bob readonly --hash "$HASH" --scopes lab > /dev/null
    rm -f "$TACCTL_LINUX_DIR"/*.tar.gz
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_success
    assert_output --partial "web1: synced (2 users)"
    run cat "$PUSHED"
    assert_output --partial "bob:readonly:20001"
    refute_line "__TARBALL__"
    stub_called "ssh .*bash /tmp/tacctl.AbCd1234 --accounts-only"
}

@test "host sync --all: covers every host and reports a failure" {
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" host enroll web2 --scope lab > /dev/null
    run "$TACCTL_BIN_SCRIPT" host sync --all
    assert_success
    assert_output --partial "web1: synced"
    assert_output --partial "web2: synced"
    SSH_RUN_FAILS=1 run "$TACCTL_BIN_SCRIPT" host sync --all
    assert_failure
    assert_output --partial "web1: sync failed"
}

@test "host enroll/sync: --allow-uid-mismatch is passed through to the host" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --allow-uid-mismatch
    assert_success
    stub_called "ssh .*bash /tmp/tacctl.AbCd1234 --allow-uid-mismatch;"
    run "$TACCTL_BIN_SCRIPT" host sync --all --allow-uid-mismatch
    assert_success
    stub_called "ssh .*bash /tmp/tacctl.AbCd1234 --accounts-only --allow-uid-mismatch;"
}

@test "host enroll/sync: --adopt is validated and passed through" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --adopt alice,bob
    assert_success
    stub_called "ssh .*bash /tmp/tacctl.AbCd1234 --adopt alice,bob;"
    run "$TACCTL_BIN_SCRIPT" host sync web1 --adopt alice
    assert_success
    stub_called "ssh .*bash /tmp/tacctl.AbCd1234 --accounts-only --adopt alice;"
    run "$TACCTL_BIN_SCRIPT" host sync web1 --adopt 'x;reboot'
    assert_failure
    assert_output --partial "comma-separated list"
}

@test "host list: counts only users that get accounts" {
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add bob readonly --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user disable bob > /dev/null
    run "$TACCTL_BIN_SCRIPT" host list
    assert_line --regexp "web1 +web1 +lab +192\.0\.2\.1 +1$"
}

@test "host sync: unknown host is an error" {
    run "$TACCTL_BIN_SCRIPT" host sync ghost
    assert_failure
    assert_output --partial "No enrolled host named 'ghost'"
}

@test "host unenroll: pushes the secret-free removal script and forgets the host" {
    "$TACCTL_BIN_SCRIPT" host enroll web1 > /dev/null
    run "$TACCTL_BIN_SCRIPT" host unenroll web1
    assert_success
    assert_output --partial "left in place"
    assert_output --partial "tacctl scope remove linux-web1"
    run grep -c "TAC_SECRET" "$PUSHED"
    assert_output "0"
    grep -q "tacctl Linux client: remove" "$PUSHED"
    run _hosts
    assert_output ""
}

@test "host unenroll: stays registered on failure unless --force" {
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null
    SSH_RUN_FAILS=1 run "$TACCTL_BIN_SCRIPT" host unenroll web1
    assert_failure
    run _hosts
    assert_output --partial "web1|"
    SSH_RUN_FAILS=1 run "$TACCTL_BIN_SCRIPT" host unenroll web1 --force
    assert_success
    run _hosts
    assert_output ""
}

@test "host list: shows enrolled hosts with scope and user count" {
    run "$TACCTL_BIN_SCRIPT" host list
    assert_output --partial "None."
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null
    run "$TACCTL_BIN_SCRIPT" host list
    assert_success
    assert_line --regexp "web1 +web1 +lab +192\.0\.2\.1 +1"
}

@test "host: is superuser-only" {
    stub_cmd id 'echo "users tac-users"'
    "$TACCTL_BIN_SCRIPT" user add op operator --hash "$HASH" --scopes lab > /dev/null
    SUDO_USER=op run "$TACCTL_BIN_SCRIPT" host list
    assert_failure
    assert_output --partial "not permitted"
}
