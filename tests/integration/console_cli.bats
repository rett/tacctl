#!/usr/bin/env bats
# Integration tests for `tacctl console`: console.yaml, the verbs and their
# exit codes, `console show` (with a stubbed sshd) and the hidden
# `_console-policy`.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    # alice (superuser), bob (operator), carol (readonly), all in scope lab.
    load_store_fixture store.multiscope.yaml
    CONSOLE="${TACCTL_STATE_DIR}/console.yaml"
    printf '/bin/sh\n/bin/bash\n' > "$TACCTL_SHELLS_FILE"
    # tacctl's fixed host locations (the console's symlink) under the tmpdir.
    ROOT="${BATS_TEST_TMPDIR}/root"
    export TACCTL_TEST_ROOT="$ROOT"
    mkdir -p "$ROOT/usr/local/bin"
    # A closed sshd by default; tests that want otherwise stub it again.
    stub_cmd sshd 'printf "port 22\nallowtcpforwarding no\nallowagentforwarding no\nforcecommand ${TACCTL_TEST_ROOT:-}/usr/local/bin/tacctl-console\npubkeyauthentication no\n"'
}

# plain: the last output with colours stripped.
plain() { output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output"); }

# enrol_local: this server enrolled with --local (registry line only).
enrol_local() { printf 'authsrv|local||lab|127.0.0.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"; }

snapshot_count() { find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -name '2*' | wc -l; }

@test "console: no subcommand, help, -h and --help print the usage and exit 0; an unknown word exits 1" {
    local w
    for w in "" help -h --help; do
        run "$TACCTL_BIN_SCRIPT" console $w
        assert_success
        plain
        assert_output --partial "Usage: tacctl console <subcommand>"
        assert_output --partial "system-shell tiers [<csv>|none]"
    done
    run "$TACCTL_BIN_SCRIPT" console frobnicate
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'frobnicate'"
    [[ ! -e "$CONSOLE" ]]
}

@test "console: bad arguments exit 1 with the verb's usage and write nothing" {
    local args
    while IFS= read -r args; do
        run "$TACCTL_BIN_SCRIPT" console $args
        assert_failure 1
    done <<'LIST'
tiers root enable
tiers readonly maybe
tiers readonly enable extra
user
user bob maybe
user nobody enable
idle-timeout 1441
idle-timeout abc
idle-timeout -1
agent-forwarding yes
ssh-escape on
system-shell
system-shell mode
system-shell tiers operator,operator
system-shell tiers root
system-shell path bash
system-shell path /no/such/shell
system-shell path /bin/ls
show extra
LIST
    [[ ! -e "$CONSOLE" ]]
    (( $(snapshot_count) == 0 ))
}

@test "console show on a fresh state: every tier enable, the defaults of the settings" {
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    plain
    assert_output --partial "  readonly: enable"
    assert_output --partial "  operator: enable"
    assert_output --partial "  superuser: enable"
    assert_output --partial "system-shell tiers: superuser"
    assert_output --partial "system-shell path: /bin/bash"
    assert_output --partial "idle-timeout: 30 min"
    assert_output --partial "agent-forwarding: disabled"
    assert_output --partial "ssh-escape: disabled"
    assert_output --partial "this server is not enrolled (tacctl host enroll --local): no tacctl user has an account here"
    # Reading writes nothing.
    [[ ! -e "$CONSOLE" ]]
}

@test "console tiers and user: show lists the effective shell and why; writes print the sync command" {
    enrol_local
    run "$TACCTL_BIN_SCRIPT" console tiers readonly disable
    assert_success
    plain
    assert_output --partial "Apply to the accounts: tacctl host sync authsrv"
    run "$TACCTL_BIN_SCRIPT" console user bob enable
    assert_success
    run "$TACCTL_BIN_SCRIPT" console user carol enable
    assert_success
    run "$TACCTL_BIN_SCRIPT" console user carol clear
    assert_success
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    plain
    assert_output --partial "Users of authsrv (scope lab)"
    assert_output --regexp "alice +superuser +console +tier superuser"
    assert_output --regexp "bob +operator +console +user override"
    assert_output --regexp "carol +readonly +bash +tier readonly disabled"
    run "$TACCTL_BIN_SCRIPT" console user bob
    assert_output "enable"
    run "$TACCTL_BIN_SCRIPT" console user alice
    assert_output "none"
    # An override beats a tier that is off.
    run "$TACCTL_BIN_SCRIPT" console user carol enable
    run "$TACCTL_BIN_SCRIPT" console show
    plain
    assert_output --regexp "carol +readonly +console +user override"
}

@test "console writes: console.yaml is 0600 with the documented shape, snapshotted, in backup diff" {
    enrol_local
    local n
    n=$(snapshot_count)
    "$TACCTL_BIN_SCRIPT" console tiers readonly disable
    "$TACCTL_BIN_SCRIPT" console user bob disable
    "$TACCTL_BIN_SCRIPT" console idle-timeout 15
    (( $(snapshot_count) == n + 3 ))
    [[ "$(stat -c %a "$CONSOLE")" == 600 ]]
    run cat "$CONSOLE"
    assert_output --partial "version: 1"
    assert_output --partial "tiers: {readonly: disable, operator: enable, superuser: enable}"
    assert_output --partial "users: {bob: disable}"
    assert_output --partial "  idle_timeout: 15"
    assert_output --partial "  system_shell_tiers: [superuser]"
    # The newest snapshot holds the file as it was before the last write.
    local snap
    snap=$(find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -name '2*' | sort | tail -1)
    [[ -f "$snap/console.yaml" ]]
    run "$TACCTL_BIN_SCRIPT" backup diff
    assert_success
    assert_output --partial "console.yaml"
    assert_output --partial "idle_timeout"
}

@test "console settings: getters, setters and the system shell" {
    run "$TACCTL_BIN_SCRIPT" console idle-timeout
    assert_output "30"
    run "$TACCTL_BIN_SCRIPT" console idle-timeout 0
    assert_success
    run "$TACCTL_BIN_SCRIPT" console idle-timeout
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" console agent-forwarding enable
    assert_success
    run "$TACCTL_BIN_SCRIPT" console agent-forwarding
    assert_output "enabled"
    run "$TACCTL_BIN_SCRIPT" console ssh-escape enable
    run "$TACCTL_BIN_SCRIPT" console ssh-escape
    assert_output "enabled"
    run "$TACCTL_BIN_SCRIPT" console system-shell tiers operator,superuser
    assert_success
    run "$TACCTL_BIN_SCRIPT" console system-shell tiers
    assert_output "operator,superuser"
    run "$TACCTL_BIN_SCRIPT" console system-shell tiers none
    run "$TACCTL_BIN_SCRIPT" console system-shell tiers
    assert_output "none"
    # The path must be listed in /etc/shells (the sandbox's copy).
    printf '/bin/bash\n' > "$TACCTL_SHELLS_FILE"
    run "$TACCTL_BIN_SCRIPT" console system-shell path /bin/sh
    assert_failure 1
    assert_output --partial "is not listed in"
    printf '/bin/bash\n/bin/sh\n' > "$TACCTL_SHELLS_FILE"
    run "$TACCTL_BIN_SCRIPT" console system-shell path /bin/sh
    assert_success
    run "$TACCTL_BIN_SCRIPT" console system-shell path
    assert_output "/bin/sh"
}

@test "console show: sshd still forwarding warns in red, a missing drop-in too; a closed server is quiet" {
    enrol_local
    stub_cmd sshd 'printf "port 22\nallowtcpforwarding yes\nallowagentforwarding no\nforcecommand ${TACCTL_TEST_ROOT:-}/usr/local/bin/tacctl-console\npubkeyauthentication no\n"'
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    stub_called '^sshd -T -C user=alice,host=localhost,addr=127.0.0.1$'
    [[ "$output" == *$'\033[0;31mWARNING'* ]]
    plain
    assert_output --partial "sshd for alice: allowtcpforwarding yes, allowagentforwarding no"
    assert_output --partial "WARNING: a console user can do more over ssh than the console allows"
    assert_output --partial "is missing"
    assert_output --partial "tacctl host sync authsrv"

    # With the drop-in present and sshd closed: no warning.
    mkdir -p "$(dirname "$TACCTL_SSHD_DROPIN")"
    printf 'Match Group tac-console\n    AllowTcpForwarding no\n' > "$TACCTL_SSHD_DROPIN"
    stub_cmd sshd 'printf "port 22\nallowtcpforwarding no\nallowagentforwarding no\nforcecommand ${TACCTL_TEST_ROOT:-}/usr/local/bin/tacctl-console\npubkeyauthentication no\n"'
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    plain
    refute_output --partial "WARNING"
    assert_output --partial "tacctl-console.conf: present"

    # Drop-in present but sshd (an include missing) still forwards: warned.
    stub_cmd sshd 'printf "allowtcpforwarding yes\nallowagentforwarding no\nforcecommand ${TACCTL_TEST_ROOT:-}/usr/local/bin/tacctl-console\npubkeyauthentication no\n"'
    run "$TACCTL_BIN_SCRIPT" console show
    plain
    assert_output --partial "WARNING"
    assert_output --partial "allowtcpforwarding is 'yes'"
    refute_output --partial "is missing"
}

@test "console show: the server's pieces as they are" {
    enrol_local
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    plain
    assert_output --partial "${ROOT}/usr/local/bin/tacctl-console: missing"
    assert_output --partial "does not list the console"
    ln -s /usr/local/bin/tacctl "${ROOT}/usr/local/bin/tacctl-console"
    printf '/bin/bash\n%s\n' "${ROOT}/usr/local/bin/tacctl-console" > "$TACCTL_SHELLS_FILE"
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    plain
    assert_output --partial "tacctl-console: symlink to /usr/local/bin/tacctl"
    assert_output --partial ": lists the console"
}

@test "console show: an sshd that cannot answer is reported, not fatal" {
    enrol_local
    stub_cmd sshd 'echo "Missing Match criteria for address" >&2; exit 255'
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    plain
    assert_output --partial "could not be checked: sshd -T failed: Missing Match criteria for address"
}

@test "console show with every tier off asks sshd nothing and does not warn" {
    enrol_local
    local t
    for t in readonly operator superuser; do "$TACCTL_BIN_SCRIPT" console tiers "$t" disable; done
    stub_cmd sshd 'printf "allowtcpforwarding yes\nallowagentforwarding yes\n"'
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    plain
    refute_output --partial "WARNING"
    assert_output --partial "sshd: not checked (no user has the console)"
    ! stub_called '^sshd '
}

@test "_console-policy: the settings of the caller, per tier" {
    local out
    # Root (no SUDO_USER): unrestricted, system shell yes.
    run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_success
    assert_output "shell=system idle=30 system_shell=yes system_shell_path=/bin/bash ssh_escape=no agent=no tier=unrestricted list_max=40"
    stub_called '^logger -t tacctl -p auth.info console policy user=root tier=unrestricted system_shell=yes session=$'

    # A tier user: the id stub puts the caller in tac-users and its tier group.
    stub_cmd id 'echo "$3 tac-users"'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=console idle=30 system_shell=yes system_shell_path=/bin/bash ssh_escape=no agent=no tier=superuser list_max=40"
    SUDO_USER=bob TACCTL_CONSOLE=0123456789ab run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no tier=operator list_max=40"
    stub_called '^logger -t tacctl -p auth.info console policy user=bob tier=operator system_shell=no session=0123456789ab$'
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no tier=readonly list_max=40"

    # A tier user with no tacctl user is denied by the gate.
    SUDO_USER=mallory run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_failure 1

    # Settings reach the line.
    "$TACCTL_BIN_SCRIPT" console tiers readonly disable
    "$TACCTL_BIN_SCRIPT" console system-shell tiers readonly
    "$TACCTL_BIN_SCRIPT" console idle-timeout 5
    "$TACCTL_BIN_SCRIPT" console ssh-escape enable
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=system idle=5 system_shell=yes system_shell_path=/bin/bash ssh_escape=yes agent=no tier=readonly list_max=40"
}

@test "console verbs are gated by tier: show for operators, the rest for superusers" {
    stub_cmd id 'echo "$3 tac-users"'
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" console show
    assert_failure 1
    assert_output --partial "is not permitted for the readonly tier"
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" console tiers readonly disable
    assert_failure 1
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" console idle-timeout 5
    assert_failure 1
    [[ ! -e "$CONSOLE" ]]
}
