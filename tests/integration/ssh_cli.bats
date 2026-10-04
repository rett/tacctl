#!/usr/bin/env bats
# Integration tests for `tacctl ssh <name>` and `tacctl device ssh-config`.
# Nothing reaches a host: `sudo` is a stub that records the drop to the
# invoking user and runs the rest, `ssh` a stub that records its argv and
# exits with $SSH_EXIT, `ssh-keyscan` answers with the public keys generated
# for the tests (internal/devreg/testdata/hostkeys). `script` gives tacctl the
# terminal it requires.

bats_require_minimum_version 1.5.0

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

KEYS="${TACCTL_SRC}/internal/devreg/testdata/hostkeys"
HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

# key <name>: '<type> <base64>' of a test key; fp <name>: its fingerprint.
key() { cut -d' ' -f1,2 "${KEYS}/$1.pub"; }
fp() { awk -v f="$1.pub" '$1 == f { print $3 }' "${KEYS}/fingerprints.txt"; }

# offer <name>...: ssh-keyscan answers for its last argument with these keys.
offer() {
    local lines="" k
    for k in "$@"; do
        lines+="echo \"\${!#} $(key "$k")\"; "
    done
    stub_cmd ssh-keyscan "${lines}"
}

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    "$TACCTL_BIN_SCRIPT" scope prefixes lab add 192.0.2.0/24 > /dev/null
    "$TACCTL_BIN_SCRIPT" scope add prod --prefixes 10.99.0.0/24 --secret generate > /dev/null
    "$TACCTL_BIN_SCRIPT" user add carol readonly --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$HASH" --scopes lab,prod > /dev/null
    offer rsa
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --vendor cisco --legacy-ssh > /dev/null
    offer ed25519
    "$TACCTL_BIN_SCRIPT" device add lab-rtr2 192.0.2.7 --vendor juniper > /dev/null
    "$TACCTL_BIN_SCRIPT" device add oob-con1 10.99.0.9 --vendor wti --no-host-key > /dev/null
    : > "$CALLS_LOG"
    KH="${TACCTL_VAR_LIB}/ssh/known_hosts"
    PIN_SW="-o UserKnownHostsFile=${KH} -o GlobalKnownHostsFile=none -o StrictHostKeyChecking=yes -o HostKeyAlias=core-sw1 -o UpdateHostKeys=no"
    PIN_RTR="-o UserKnownHostsFile=${KH} -o GlobalKnownHostsFile=none -o StrictHostKeyChecking=yes -o HostKeyAlias=lab-rtr2 -o UpdateHostKeys=no"
    CT="-o ConnectTimeout=10 -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password"
    LEGACY="-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"

    # sudo -u <user> -H ssh ...: record, drop the sudo options, run the rest.
    stub_cmd sudo 'while [[ $# -gt 0 && "$1" == -* ]]; do case "$1" in -u) shift 2 ;; *) shift ;; esac; done; exec "$@"'
    stub_cmd ssh 'exit "${SSH_EXIT:-0}"'
    # alice is a local administrator (not in tac-users) and a tacctl
    # superuser (lab, prod), carol a read-only user (lab), dave a local
    # account that is no tacctl user.
    stub_cmd id 'case "$*" in *carol*) echo "carol tac-users tac-readonly" ;; *) echo "alice sudo" ;; esac'
    # The caller has an agent: tacctl ssh never hands it to ssh.
    export SSH_AUTH_SOCK=/tmp/agent.sock
}

# called <line>: the calls log has exactly this line (no regular expression:
# the options carry '+' and '.').
called() { grep -qxF -- "$1" "$CALLS_LOG" || { echo "not called: $1"; cat "$CALLS_LOG"; return 1; }; }

# on_tty <args...>: tacctl with a pseudo-terminal on stdin; output holds
# stdout and stderr, without the terminal's carriage returns.
on_tty() {
    local cmd
    printf -v cmd '%q ' "$TACCTL_BIN_SCRIPT" "$@"
    run script -qec "$cmd" /dev/null
    output=${output//$'\r'/}
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
}

@test "ssh: runs ssh as the invoking user, logged in as them by password, with the profile and the pin" {
    SUDO_USER=alice on_tty ssh core-sw1
    assert_success
    called "sudo -u alice -H ssh ${CT} ${LEGACY} ${PIN_SW} -l alice 10.99.0.1"
    called "ssh ${CT} ${LEGACY} ${PIN_SW} -l alice 10.99.0.1"
    # The address finds the same device.
    : > "$CALLS_LOG"
    SUDO_USER=alice on_tty ssh 10.99.0.1
    assert_success
    stub_called "HostKeyAlias=core-sw1 .* -l alice 10\.99\.0\.1$"
    # Juniper: no options of its own.
    SUDO_USER=alice on_tty ssh lab-rtr2
    assert_success
    called "ssh ${CT} ${PIN_RTR} -l alice 192.0.2.7"
    # WTI: the password method alone; unpinned, so the notice first and no pin.
    SUDO_USER=alice on_tty ssh oob-con1
    assert_success
    assert_output --partial "hostkey-unpinned: no host key is pinned for 'oob-con1'"
    called "ssh -o ConnectTimeout=10 -o PubkeyAuthentication=no -o PreferredAuthentications=password -l alice 10.99.0.9"
    run grep -c "BatchMode\|StrictHostKeyChecking=no\|SSH_AUTH_SOCK\| -i " "$CALLS_LOG"
    assert_output "0"
    # The known_hosts ssh is pointed at holds the pinned keys, and every user
    # can read it: 0644 in a 0755 directory under a 0711 VarLib.
    run cat "$KH"
    assert_output --partial "core-sw1 $(key rsa)"
    assert_output --partial "lab-rtr2 $(key ed25519)"
    run stat -c '%a' "$KH" "${TACCTL_VAR_LIB}/ssh" "$TACCTL_VAR_LIB"
    assert_output "644
755
711"
}

@test "ssh: -p and the arguments after -- reach ssh, -l is refused; device ssh is the same" {
    SUDO_USER=alice on_tty ssh core-sw1 -p 2200 -- -v show version
    assert_success
    called "ssh ${CT} ${LEGACY} ${PIN_SW} -p 2200 -l alice 10.99.0.1 -v show version"
    : > "$CALLS_LOG"
    SUDO_USER=alice on_tty ssh core-sw1 -l admin
    assert_failure 1
    assert_output --partial "Unknown option: '-l' (pass ssh's own options after --)"
    run stub_called "^ssh "
    assert_failure
    SUDO_USER=alice on_tty device ssh lab-rtr2
    assert_success
    called "sudo -u alice -H ssh ${CT} ${PIN_RTR} -l alice 192.0.2.7"
}

@test "ssh: an enrolled host is reached as the caller, never as the enrolment's account or with its identity" {
    printf 'web1|admin@192.0.2.10|2222|lab|192.0.2.1|/k/id_web1\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    SUDO_USER=carol on_tty ssh web1
    assert_success
    called "sudo -u carol -H ssh ${CT} -p 2222 -l carol 192.0.2.10"
    run grep -c "admin\|id_web1" "$CALLS_LOG"
    assert_output "0"
}

@test "ssh: the session is logged, and ssh's exit status is tacctl's" {
    SUDO_USER=alice on_tty ssh lab-rtr2
    assert_success
    called "logger -t tacctl -p auth.info ssh user=alice device=lab-rtr2 addr=192.0.2.7"
    SSH_EXIT=3 SUDO_USER=alice on_tty ssh lab-rtr2
    assert_failure 3
    SSH_EXIT=130 SUDO_USER=alice on_tty ssh oob-con1
    assert_failure 130
}

@test "ssh: only active tacctl users, and only in their own scopes, whatever the tier" {
    SUDO_USER=carol on_tty ssh lab-rtr2
    assert_success
    called "sudo -u carol -H ssh ${CT} ${PIN_RTR} -l carol 192.0.2.7"
    : > "$CALLS_LOG"
    SUDO_USER=carol on_tty ssh core-sw1
    assert_failure 1
    assert_output --partial "'carol' has no access to scope 'prod' (device core-sw1)"
    called "logger -t tacctl -p auth.warning ssh DENY user=carol device=core-sw1 scope=prod reason=scope"
    run stub_called "^ssh "
    assert_failure
    SUDO_USER=carol on_tty ssh 10.99.0.9
    assert_failure 1
    assert_output --partial "'carol' has no access to scope 'prod' (device oob-con1)"
    # A superuser outside the scope.
    "$TACCTL_BIN_SCRIPT" scope add dmz --prefixes 203.0.113.0/24 --secret generate > /dev/null
    "$TACCTL_BIN_SCRIPT" device add edge-fw 203.0.113.5 --no-host-key > /dev/null
    SUDO_USER=alice on_tty ssh edge-fw
    assert_failure 1
    assert_output --partial "'alice' has no access to scope 'dmz' (device edge-fw)"
    # A device no scope covers: no one.
    "$TACCTL_BIN_SCRIPT" device add stray 198.51.100.9 --no-host-key > /dev/null
    SUDO_USER=alice on_tty ssh stray
    assert_failure 1
    assert_output --partial "'stray' is in no configured scope, so no one may open a session to it."
    called "logger -t tacctl -p auth.warning ssh DENY user=alice device=stray scope=- reason=unconfigured"
    # A local account that is not a tacctl user.
    SUDO_USER=dave on_tty ssh lab-rtr2
    assert_failure 1
    assert_output --partial "'dave' is not a tacctl user"
    called "logger -t tacctl -p auth.warning ssh DENY user=dave device=lab-rtr2 scope=lab reason=not-a-tacctl-user"
    # A disabled tacctl user.
    "$TACCTL_BIN_SCRIPT" user disable alice <<< y > /dev/null
    SUDO_USER=alice on_tty ssh lab-rtr2
    assert_failure 1
    assert_output --partial "tacctl user 'alice' is disabled"
    run stub_called "^ssh "
    assert_failure
}

@test "ssh: refused as root, without a terminal, for an unregistered address, and for a forged SUDO_USER" {
    on_tty ssh lab-rtr2
    assert_failure 1
    assert_output --partial "tacctl ssh runs ssh as the user who invoked it; run it from your own account, not as root"
    SUDO_USER=root on_tty ssh lab-rtr2
    assert_failure 1
    assert_output --partial "not as root"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" ssh lab-rtr2 < /dev/null
    assert_failure 1
    assert_output --partial "a terminal is required"
    SUDO_USER=alice on_tty ssh 198.51.100.4
    assert_failure 1
    assert_output --partial "'198.51.100.4' is not a registered device; register it: tacctl device add <name> 198.51.100.4"
    # SUDO_UID 1003 is carol's account: SUDO_USER=alice is refused before anything.
    stub_cmd getent 'case "$*" in "passwd 1003") echo "carol:x:1003:1003::/home/carol:/bin/bash" ;; *) exit 2 ;; esac'
    SUDO_USER=alice SUDO_UID=1003 on_tty ssh lab-rtr2
    assert_failure 1
    assert_output --partial "SUDO_USER 'alice' is not the account of SUDO_UID 1003, so tacctl access is denied."
    called "logger -t tacctl -p auth.warning tier DENY user=alice uid=1003 reason=sudo-user-mismatch cmd=ssh lab-rtr2"
    run stub_called "^ssh "
    assert_failure
    # The genuine pair runs.
    SUDO_USER=carol SUDO_UID=1003 on_tty ssh lab-rtr2
    assert_success
    called "sudo -u carol -H ssh ${CT} ${PIN_RTR} -l carol 192.0.2.7"
    run "$TACCTL_BIN_SCRIPT" ssh
    assert_success
    assert_output --partial "Usage: tacctl ssh <name|address> [-p <port>] [-- <ssh args>]"
}

@test "ssh: exit 255 on a pinned device whose key changed names both fingerprints and the fix" {
    offer ecdsa
    SSH_EXIT=255 SUDO_USER=alice on_tty ssh lab-rtr2
    assert_failure 255
    called "ssh-keyscan -T 5 -p 22 -t ed25519,ecdsa,rsa 192.0.2.7"
    assert_output --partial "The ssh host key of 'lab-rtr2' (192.0.2.7 port 22) is not the one pinned for it; ssh refused the connection."
    assert_output --partial "Pinned:  ED25519 $(fp ed25519)"
    assert_output --partial "Offered: ECDSA $(fp ecdsa)"
    assert_output --partial "Compare on the device console: Junos: 'show system ssh host-key'"
    assert_output --partial "tacctl device hostkey lab-rtr2 accept"
    assert_output --partial "tacctl device hostkey lab-rtr2 set SHA256:<fingerprint>"
    called "logger -t tacctl -p auth.warning ssh hostkey-mismatch user=alice device=lab-rtr2 addr=192.0.2.7"
    # The same key still offered: ssh failed for another reason, nothing added.
    offer ed25519
    SSH_EXIT=255 SUDO_USER=alice on_tty ssh lab-rtr2
    assert_failure 255
    refute_output --partial "not the one pinned"
}

@test "device ssh-config: Host blocks with the profile and the pin, no login, the Include hint on stderr" {
    printf 'web1|admin@web1.example.net|2222|lab|192.0.2.1|/k/id_web1\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    run --separate-stderr "$TACCTL_BIN_SCRIPT" device ssh-config
    assert_success
    assert_line --index 0 --regexp "^# Generated by tacctl device ssh-config on .+, [0-9]{4}-[0-9]{2}-[0-9]{2}\. Re-run after registry changes\.$"
    [[ "$(sed 1d <<< "$output")" == "Host core-sw1
    HostName 10.99.0.1
    PubkeyAuthentication no
    PreferredAuthentications keyboard-interactive,password
    KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
    HostKeyAlgorithms +ssh-rsa
    PubkeyAcceptedAlgorithms +ssh-rsa
    UserKnownHostsFile ${KH}
    GlobalKnownHostsFile none
    StrictHostKeyChecking yes
    HostKeyAlias core-sw1
    UpdateHostKeys no
Host lab-rtr2
    HostName 192.0.2.7
    PubkeyAuthentication no
    PreferredAuthentications keyboard-interactive,password
    UserKnownHostsFile ${KH}
    GlobalKnownHostsFile none
    StrictHostKeyChecking yes
    HostKeyAlias lab-rtr2
    UpdateHostKeys no
Host oob-con1
    HostName 10.99.0.9
    PubkeyAuthentication no
    PreferredAuthentications password
    # No host key is pinned: ssh asks with your own known_hosts. Pin it: tacctl device hostkey oob-con1 accept
Host web1
    HostName web1.example.net
    Port 2222
    PubkeyAuthentication no
    PreferredAuthentications keyboard-interactive,password
    # No host key is pinned: ssh asks with your own known_hosts. Pin it: tacctl device hostkey web1 accept" ]]
    [[ "$stderr" == *"Save it with: tacctl device ssh-config > ~/.ssh/tacctl.conf"* ]]
    [[ "$stderr" == *"'Include ~/.ssh/tacctl.conf' at the top of ~/.ssh/config"* ]]
    # carol gets the blocks of her own scope.
    SUDO_USER=carol run --separate-stderr "$TACCTL_BIN_SCRIPT" device ssh-config
    assert_success
    run grep '^Host ' <<< "$output"
    assert_output "Host lab-rtr2
Host web1"
}

@test "completion: tacctl ssh offers the device names the bridge gives" {
    stub_cmd sudo 'case "$*" in *"_completion-names devices") printf "%s\n" core-sw1 lab-rtr2 web1 ;; esac'
    run "$TACCTL_BIN_SCRIPT" __complete ssh ""
    assert_success
    assert_line "core-sw1"
    assert_line "lab-rtr2"
    run "$TACCTL_BIN_SCRIPT" __complete ssh l
    assert_success
    assert_line "lab-rtr2"
    refute_line "core-sw1"
    run "$TACCTL_BIN_SCRIPT" __complete device ssh ""
    assert_success
    assert_line "web1"
}
