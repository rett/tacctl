#!/usr/bin/env bats
# Integration tests for 'tacctl server' (addresses 0.2.21, show 0.2.22) with the real
# binary: the one address this release holds, the refusals, the change of the
# address on this server's own login (the client script is a stub), the audit
# lines, and that the verb is the superuser's alone with a tiers sudoers
# drop-in that no release before 0.2.21 needs to be rewritten for.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

bats_require_minimum_version 1.5.0

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
FOLLOW_UPS="Re-point the devices and hosts at the new address: tacctl host sync --all; the device walkthroughs name the new address"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_LINUX_DIR="${BATS_TEST_TMPDIR}/linux"
    export TACCTL_TIER_SUDOERS_FILE="${BATS_TEST_TMPDIR}/sudoers.d/tacctl-tiers"
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$HASH" --scopes lab > /dev/null
    mkdir -p "$TACCTL_LINUX_DIR"
    echo "not really a tarball" > "$TACCTL_LINUX_DIR/pam_tacplus-1.7.0.tar.gz"
    stub_cmd ip 'echo "192.0.2.50 dev eth0 src 192.0.2.1 uid 0"'
}

registry() { cat "${TACCTL_STATE_DIR}/linux-hosts" 2> /dev/null || true; }

@test "server: the family prints its usage; an unknown word is refused" {
    run "$TACCTL_BIN_SCRIPT" server
    assert_success
    assert_output --partial "Usage: tacctl server <subcommand>"
    assert_output --partial "addresses add <ip>[,<ip>...]"
    assert_output --partial "listen [show|reset|<network> <address>]"
    assert_output --partial "metrics [show|enable|disable|reset|address <host:port>]"
    run "$TACCTL_BIN_SCRIPT" server bogus
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'bogus'"
}

@test "server show: the overview prints the settings and the backends, --json the same as a document, and it changes nothing" {
    local before
    before="$(cat "${TACCTL_STATE_DIR}/tacctl.yaml" 2> /dev/null || true)"
    run "$TACCTL_BIN_SCRIPT" server show
    assert_success
    assert_output --partial "Server"
    assert_output --partial "Address:         (none"
    assert_output --partial "Default method:  tacplus"
    assert_output --partial "Metrics:         enabled, loopback only  (127.0.0.1:8080)"
    assert_output --partial "Backends"
    assert_output --partial "Listeners"
    "$TACCTL_BIN_SCRIPT" server addresses add 192.0.2.10 > /dev/null
    run "$TACCTL_BIN_SCRIPT" server show --json
    assert_success
    run jq -r '.addresses[0], .address_source, .default_method, .metrics.state, (.backends | map(.id) | join(","))' <<< "$output"
    assert_output "$(printf '192.0.2.10\nsetting\ntacplus\nenabled\ntacacs,radius')"
    run "$TACCTL_BIN_SCRIPT" server show bogus
    assert_failure 1
    assert_output --partial "Unknown argument: 'bogus'"
    [ -z "$before" ] || [ "$before" = "$(cat "${TACCTL_STATE_DIR}/tacctl.yaml")" ]
}

@test "server addresses: nothing recorded, then add sets the one address and says what is left to do" {
    run "$TACCTL_BIN_SCRIPT" server addresses
    assert_success
    assert_output --partial "(none"
    run "$TACCTL_BIN_SCRIPT" server addresses add 192.0.2.10
    assert_success
    assert_output --partial "Server address set: 192.0.2.10."
    assert_output --partial "$FOLLOW_UPS"
    run "$TACCTL_BIN_SCRIPT" config get-list server.addresses
    assert_output "192.0.2.10"
    run "$TACCTL_BIN_SCRIPT" server addresses list
    assert_success
    assert_output --partial "  - 192.0.2.10"
}

@test "server addresses: one address is held, so add while one is set and remove of the only one are refused" {
    "$TACCTL_BIN_SCRIPT" server addresses add 192.0.2.10 > /dev/null
    local before
    before="$(cat "${TACCTL_STATE_DIR}/tacctl.yaml")"
    run "$TACCTL_BIN_SCRIPT" server addresses add 198.51.100.7
    assert_failure 1
    assert_output --partial "only one server address is supported yet; use replace. Nothing was changed."
    run "$TACCTL_BIN_SCRIPT" server addresses remove 192.0.2.10
    assert_failure 1
    assert_output --partial "the server needs an address; use replace. Nothing was changed."
    run "$TACCTL_BIN_SCRIPT" server addresses replace 198.51.100.7,198.51.100.8
    assert_failure 1
    assert_output --partial "only one server address is supported yet. Nothing was changed."
    for bad in web1.example.net 0.0.0.0 127.0.0.1 fe80::1; do
        run "$TACCTL_BIN_SCRIPT" server addresses replace "$bad"
        assert_failure 1
        assert_output --partial "'$bad' "
    done
    [[ "$(cat "${TACCTL_STATE_DIR}/tacctl.yaml")" == "$before" ]]
}

@test "server addresses: with this server's login set up, the address it is set up at is a no-op and runs nothing" {
    # host enroll --local runs the client script on this machine, so no test
    # here enrols; the move of the login is the Go tests' (internal/cli/server_test.go)
    printf 'authsrv|local||tacctl|192.0.2.10|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    run "$TACCTL_BIN_SCRIPT" server addresses
    assert_success
    assert_output --partial "  - 192.0.2.10  (this server's registry entry"
    printf 'server:\n  addresses:\n  - 192.0.2.10\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" server addresses replace 192.0.2.10
    assert_success
    assert_output --partial "The server address is 192.0.2.10 already. Nothing was changed."
    refute_output --partial "Re-point"
    run "$TACCTL_BIN_SCRIPT" server addresses add 192.0.2.10
    assert_success
    assert_output --partial "No new address (already present: 192.0.2.10)."
    [[ "$(registry)" == "authsrv|local||tacctl|192.0.2.10|" ]]
}

@test "server addresses: the walkthroughs and the linux script take the recorded address, --server wins" {
    run "$TACCTL_BIN_SCRIPT" config linux script --scope lab -o "${BATS_TEST_TMPDIR}/s.sh"
    assert_success
    grep -q '^TAC_SERVER=192.0.2.1$' "${BATS_TEST_TMPDIR}/s.sh"
    "$TACCTL_BIN_SCRIPT" server addresses add 203.0.113.9 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config linux script --scope lab -o "${BATS_TEST_TMPDIR}/s.sh"
    assert_success
    grep -q '^TAC_SERVER=203.0.113.9$' "${BATS_TEST_TMPDIR}/s.sh"
    run "$TACCTL_BIN_SCRIPT" config linux script --scope lab --server 198.51.100.7 -o "${BATS_TEST_TMPDIR}/s.sh"
    grep -q '^TAC_SERVER=198.51.100.7$' "${BATS_TEST_TMPDIR}/s.sh"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_output --partial "set system tacplus-server 203.0.113.9 secret "
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --server 198.51.100.7
    assert_output --partial "set system tacplus-server 198.51.100.7 secret "
    refute_output --partial "203.0.113.9"
}

@test "server addresses: a change writes the command's pair of audit lines and its own, a list none" {
    run "$TACCTL_BIN_SCRIPT" server addresses list
    run "$TACCTL_BIN_SCRIPT" server addresses add 192.0.2.10
    assert_success
    stub_calls | grep -q 'cmd start .*cmd="server addresses"'
    stub_calls | grep -q 'server addresses op=add address=192.0.2.10'
    stub_calls | grep -q 'cmd end .*result=ok'
}

@test "server: the verb has no tier row, so the tiers sudoers drop-in is the one 0.2.20 wrote" {
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    assert_success
    refute_output --partial "server"
}
