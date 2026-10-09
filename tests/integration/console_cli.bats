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
        assert_output --partial "forwarding tiers [<csv>|none]"
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
space-completion enable
space-completion on off
system-shell
system-shell mode
system-shell tiers operator,operator
system-shell tiers root
system-shell tiers engineer
system-shell tiers superuser,engineer
system-shell path bash
system-shell path /no/such/shell
system-shell path /bin/ls
forwarding
forwarding mode
forwarding tiers root
forwarding tiers superuser,superuser
forwarding tiers engineer
forwarding gateway-ports on
forwarding gateway-ports enable extra
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
    assert_output --partial "  engineer: enable"
    assert_output --partial "  superuser: enable"
    assert_output --partial "system-shell tiers: superuser"
    assert_output --partial "forwarding tiers: superuser (X11 and TCP ports)"
    assert_output --partial "forwarding gateway-ports: disabled"
    assert_output --partial "system-shell path: /bin/bash"
    assert_output --partial "idle-timeout: 30 min"
    assert_output --partial "agent-forwarding: disabled"
    assert_output --partial "ssh-escape: disabled"
    assert_output --partial "space-completion: on"
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
    assert_output --partial "tiers: {readonly: disable, operator: enable, engineer: enable, superuser: enable}"
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

@test "console space-completion: on by default, written to console.yaml only while off, shown by console show" {
    run "$TACCTL_BIN_SCRIPT" console space-completion
    assert_success
    assert_output "on"
    # Switching it on while it is on writes nothing.
    run "$TACCTL_BIN_SCRIPT" console space-completion on
    assert_success
    [[ ! -e "$CONSOLE" ]] || ! grep -q space_completion "$CONSOLE"
    run "$TACCTL_BIN_SCRIPT" console space-completion off
    assert_success
    assert_output --partial "A typed space at the console's prompt is an ordinary space."
    refute_output --partial "host sync"
    run "$TACCTL_BIN_SCRIPT" console space-completion
    assert_output "off"
    run grep -c '^  space_completion: false$' "$CONSOLE"
    assert_output "1"
    run "$TACCTL_BIN_SCRIPT" console show
    plain
    assert_output --partial "space-completion: off"
    # On again: the key is gone, so a 0.2.2 reader accepts the file.
    run "$TACCTL_BIN_SCRIPT" console space-completion on
    assert_success
    assert_output --partial "completes a fixed word"
    run grep -c space_completion "$CONSOLE"
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" console space-completion
    assert_output "on"
    # A console.yaml written before 0.2.3 (no key) reads as on.
    printf 'version: 1\ntiers: {readonly: enable, operator: enable, superuser: enable}\nusers: {}\nsettings: {idle_timeout: 30}\n' > "$CONSOLE"
    run "$TACCTL_BIN_SCRIPT" console space-completion
    assert_output "on"
    # A value that is not a boolean is refused when the file is read.
    printf 'version: 1\nsettings: {space_completion: maybe}\n' > "$CONSOLE"
    run "$TACCTL_BIN_SCRIPT" console space-completion
    assert_failure
    assert_output --partial "invalid value for 'space_completion'"
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
    run "$TACCTL_BIN_SCRIPT" console forwarding tiers
    assert_output "superuser"
    run "$TACCTL_BIN_SCRIPT" console forwarding tiers operator,superuser
    assert_success
    assert_output --partial "X11 and TCP forwarding is open to: operator,superuser."
    run "$TACCTL_BIN_SCRIPT" console forwarding tiers
    assert_output "operator,superuser"
    run "$TACCTL_BIN_SCRIPT" console forwarding tiers none
    run "$TACCTL_BIN_SCRIPT" console forwarding tiers
    assert_output "none"
    run cat "$CONSOLE"
    assert_output --partial "  forwarding_tiers: []"
    run "$TACCTL_BIN_SCRIPT" console forwarding gateway-ports
    assert_output "disabled"
    run "$TACCTL_BIN_SCRIPT" console forwarding gateway-ports enable
    assert_success
    assert_output --partial "may listen on other addresses than loopback"
    run "$TACCTL_BIN_SCRIPT" console forwarding gateway-ports
    assert_output "enabled"
    run cat "$CONSOLE"
    assert_output --partial "  gateway_ports: true"
    run "$TACCTL_BIN_SCRIPT" console forwarding gateway-ports disable
    assert_success
    assert_output --partial "Forwarded ports listen on loopback only."
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

@test "console show: TCP forwarding is as designed for a user of a forwarding tier, and warned for others" {
    enrol_local
    mkdir -p "$(dirname "$TACCTL_SSHD_DROPIN")"
    printf 'Match Group tac-console\n    AllowTcpForwarding no\n' > "$TACCTL_SSHD_DROPIN"
    stub_cmd id 'echo "$3 tac-users tac-console tac-superuser"'
    stub_cmd sshd 'printf "allowtcpforwarding yes\nallowagentforwarding no\nforcecommand ${TACCTL_TEST_ROOT:-}/usr/local/bin/tacctl-console\npubkeyauthentication no\n"'
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    plain
    assert_output --partial "sshd for alice: allowtcpforwarding yes"
    refute_output --partial "WARNING"
    stub_called '^id -nG -- alice$'
    # Closed to every tier: the same answer is a warning.
    "$TACCTL_BIN_SCRIPT" console forwarding tiers none
    run "$TACCTL_BIN_SCRIPT" console show
    plain
    assert_output --partial "WARNING"
    assert_output --partial "allowtcpforwarding is 'yes'"
}

@test "console show: a user of a tier that may not forward is checked too; a value read before the drop-in is named as the cause" {
    enrol_local
    mkdir -p "$(dirname "$TACCTL_SSHD_DROPIN")"
    printf 'Match Group tac-console\n    AllowTcpForwarding no\n' > "$TACCTL_SSHD_DROPIN"
    # alice is a superuser (forwards); everyone else is not.
    stub_cmd id 'if [[ "$3" == alice ]]; then echo "alice tac-users tac-console tac-superuser"; else echo "$3 tac-users tac-console tac-operator"; fi'
    # sshd answers the superuser block's values for everyone (a global
    # X11Forwarding/AllowTcpForwarding read before the drop-in).
    stub_cmd sshd 'printf "allowtcpforwarding yes\nallowagentforwarding no\nx11forwarding yes\ndisableforwarding no\nforcecommand ${TACCTL_TEST_ROOT:-}/usr/local/bin/tacctl-console\npubkeyauthentication no\n"'
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    plain
    [[ $(grep -c '^  sshd for ' <<< "$output") == 2 ]]
    assert_output --partial "WARNING"
    assert_output --partial "allowtcpforwarding is 'yes'; x11forwarding is 'yes'"
    assert_output --partial "sshd keeps the first value it reads"
    # console check prints the console's drop-in and sshd_config lines once
    # (and the engineer tier's drop-in once, on its own).
    run "$TACCTL_BIN_SCRIPT" console check
    plain
    [[ $(grep -c 'sshd drop-in .*tacctl-console.conf' <<< "$output") == 1 ]]
    [[ $(grep -c 'sshd drop-in .*00-tacctl-engineer.conf' <<< "$output") == 1 ]]
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
    assert_output "shell=system idle=30 system_shell=yes system_shell_path=/bin/bash ssh_escape=no agent=no forward=yes tier=unrestricted list_max=40 space_completion=yes"
    stub_called '^logger -t tacctl -p auth.info shell policy user=root tier=unrestricted$'

    # A tier user: the id stub puts the caller in tac-users and its tier group.
    stub_cmd id 'echo "$3 tac-users"'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=console idle=30 system_shell=yes system_shell_path=/bin/bash ssh_escape=no agent=no forward=yes tier=superuser list_max=40 space_completion=yes"
    SUDO_USER=bob TACCTL_CONSOLE=0123456789ab run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no forward=no tier=operator list_max=40 space_completion=yes"
    stub_called '^logger -t tacctl -p auth.info console policy user=bob tier=operator system_shell=no session=0123456789ab$'
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no forward=no tier=readonly list_max=40 space_completion=yes"

    # A tier user with no tacctl user is denied by the gate.
    SUDO_USER=mallory run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_failure 1

    # Settings reach the line.
    "$TACCTL_BIN_SCRIPT" console tiers readonly disable
    "$TACCTL_BIN_SCRIPT" console system-shell tiers readonly
    "$TACCTL_BIN_SCRIPT" console idle-timeout 5
    "$TACCTL_BIN_SCRIPT" console ssh-escape enable
    "$TACCTL_BIN_SCRIPT" console forwarding tiers readonly
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=system idle=5 system_shell=yes system_shell_path=/bin/bash ssh_escape=yes agent=no forward=yes tier=readonly list_max=40 space_completion=yes"
    "$TACCTL_BIN_SCRIPT" console space-completion off
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=system idle=5 system_shell=yes system_shell_path=/bin/bash ssh_escape=yes agent=no forward=yes tier=readonly list_max=40 space_completion=no"
}

@test "console: the engineer tier is always on, and never gets the system shell or forwarding (D18, D24)" {
    run "$TACCTL_BIN_SCRIPT" console system-shell tiers superuser,engineer
    assert_failure 1
    assert_output --partial "The engineer tier cannot be given the system shell on this server: a shell here would reach the server's secrets. Nothing was changed."
    run "$TACCTL_BIN_SCRIPT" console forwarding tiers engineer
    assert_failure 1
    assert_output --partial "The engineer tier cannot be given forwarding on this server: engineers reach devices with the console's ssh. Nothing was changed."
    [[ ! -e "$CONSOLE" ]]
    # The engineer has the console or no login: nothing switches it off.
    run "$TACCTL_BIN_SCRIPT" console tiers engineer disable
    assert_failure 1
    assert_output --partial "The engineer tier has the console or no login on this server; it cannot be disabled. To keep a user off this server, remove its scope from the user."
    [[ ! -e "$CONSOLE" ]]
    run "$TACCTL_BIN_SCRIPT" console tiers engineer
    assert_output "enable"
    # bob's group is given the engineer tier: his console settings follow.
    printf 'tier:\n  operator: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    "$TACCTL_BIN_SCRIPT" console system-shell tiers operator,superuser
    run "$TACCTL_BIN_SCRIPT" console user bob disable
    assert_failure 1
    assert_output --partial "it cannot be disabled"
    [[ ! -e "$CONSOLE" ]] || ! grep -q "bob" "$CONSOLE"
    stub_cmd id 'echo "$3 tac-users"'
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output "shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no forward=no tier=engineer list_max=40 space_completion=yes"
    # A tacctl.yaml that cannot be read caps the gate's tier at operator, but
    # an engineer keeps the lockdown: no system shell, no forwarding, even
    # though the operator tier is given both. Someone who is not an engineer
    # gets what the operator tier gets.
    "$TACCTL_BIN_SCRIPT" console forwarding tiers operator,superuser
    printf 'tier:\n  operator: engineer\n  - [broken\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    stub_cmd id 'echo "$3 tac-users tac-engineer"'
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output --partial "could not parse ${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_output --partial "shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no forward=no tier=engineer gate=operator list_max=40 space_completion=yes"
    stub_cmd id 'echo "$3 tac-users tac-superuser"'
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output --partial " forward=yes tier=operator "
    printf 'tier:\n  operator: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    stub_cmd id 'echo "$3 tac-users"'
    # A stored 'disable' (an older file, or edited by hand) is ignored and said so.
    printf 'version: 1\ntiers: {readonly: enable, operator: enable, engineer: disable, superuser: enable}\nusers: {bob: disable}\n' > "$CONSOLE"
    chmod 600 "$CONSOLE"
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output --partial "shell=console "
    run "$TACCTL_BIN_SCRIPT" console tiers
    assert_output --partial "engineer: enable (always; the stored disable is ignored)"
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" console system-shell tiers
    assert_failure 1
    assert_output --partial "is not permitted for the engineer tier"
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

@test "console check: the engineer tier's sshd drop-in is checked on its own, and written without the console" {
    enrol_local
    mkdir -p "$(dirname "$TACCTL_SSHD_DROPIN")"
    printf 'Match Group tac-console\n    AllowTcpForwarding no\n' > "$TACCTL_SSHD_DROPIN"
    local engineer
    engineer="$(dirname "$TACCTL_SSHD_DROPIN")/00-tacctl-engineer.conf"
    stub_cmd sshd 'printf "allowtcpforwarding no\nallowagentforwarding no\nforcecommand ${TACCTL_TEST_ROOT:-}/usr/local/bin/tacctl-console\npubkeyauthentication no\n"'
    run "$TACCTL_BIN_SCRIPT" console check
    plain
    assert_output --partial "sshd drop-in ${engineer}: missing"
    assert_output --partial "sshd's drop-in for the engineer tier ${engineer} is missing"
    printf 'Match Group tac-engineer\n    AllowTcpForwarding yes\n' > "$engineer"
    run "$TACCTL_BIN_SCRIPT" console check
    plain
    assert_output --partial "sshd drop-in ${engineer}: present, differs from this release's"
}

@test "console check: an engineer drop-in under its old name is flagged (the new one sorts before the console's)" {
    enrol_local
    mkdir -p "$(dirname "$TACCTL_SSHD_DROPIN")"
    printf 'Match Group tac-console\n    AllowTcpForwarding no\n' > "$TACCTL_SSHD_DROPIN"
    local old
    old="$(dirname "$TACCTL_SSHD_DROPIN")/tacctl-engineer.conf"
    printf 'Match Group tac-engineer\n    AllowTcpForwarding no\n' > "$old"
    stub_cmd sshd 'printf "allowtcpforwarding no\nallowagentforwarding no\nforcecommand ${TACCTL_TEST_ROOT:-}/usr/local/bin/tacctl-console\npubkeyauthentication no\n"'
    run "$TACCTL_BIN_SCRIPT" console check
    plain
    assert_output --partial "sshd drop-in ${old}: present (the old name)"
    assert_output --partial "the engineer tier's old sshd drop-in ${old} is still there"
    # The name the engineer drop-in is written under sorts before the console's.
    [[ "00-tacctl-engineer.conf" < "$(basename "$TACCTL_SSHD_DROPIN")" ]]
}
