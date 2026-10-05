#!/usr/bin/env bats
# Integration tests for 'tacctl host' (enroll / sync / unenroll / list) with
# ssh stubbed: the stub stores what would have been copied to the host and
# records the command that would have run there. The second half is the
# method (tacplus | radius): what is pushed, the registry's seventh field,
# the scope's protocols, switching, and host.default_method.

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

_hosts() { cat "${TACCTL_STATE_DIR}/linux-hosts" 2>/dev/null; }
# _own_scope <name> <address> [protocols]: a scope of the host's own (its
# address as a /32, its own secret), as an administrator makes one.
_own_scope() {
    "$TACCTL_BIN_SCRIPT" scope add "linux-$1" --prefixes "$2/32" --secret generate ${3:+--protocols "$3"} > /dev/null
}

@test "host enroll: pushes the install script and registers the host" {
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab
    assert_success
    assert_output --partial "Host 'web1' enrolled"
    run _hosts
    assert_output "web1|admin@web1.example.net||lab|192.0.2.1|"
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_output --partial "TAC_SERVER=192.0.2.1"
    assert_output --partial "TAC_SECRET=0123456789abcdef0123456789abcdef"
    assert_output --partial "alice:superuser:80000"
    grep -q '^__TARBALL__$' "$PUSHED"
    # Ran as root or via sudo on the host, then removed the copy.
    stub_called "ssh .*admin@web1.example.net .*rm -f /tmp/tacctl.AbCd1234.*sudo -n bash /tmp/tacctl.AbCd1234"
}

@test "host enroll: without --scope, the scope that covers the host; none is refused, no scope is made" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_failure
    assert_output --partial "No scope covers 192.0.2.50 (web1), so the server would refuse every login of 'web1'. Nothing was changed."
    assert_output --partial "tacctl scope add linux-web1 --prefixes 192.0.2.50/32 --secret generate"
    [[ ! -e "$PUSHED" ]]
    [[ -z "$(_hosts)" ]]
    run "$TACCTL_BIN_SCRIPT" scope show linux-web1
    assert_failure

    _own_scope web1 192.0.2.50
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_success
    assert_output --partial "192.0.2.50 (web1) is answered by scope 'linux-web1' (prefix 192.0.2.50/32); enrolling web1 there"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1|"
    run grep -c "TAC_SECRET=0123456789abcdef0123456789abcdef" "$PUSHED"
    assert_output "0"
    # Registered: it stays in its scope, even once a broader prefix of
    # another scope comes first.
    "$TACCTL_BIN_SCRIPT" scope prefixes lab add 192.0.2.0/24 > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_success
    assert_output --partial "web1 is registered in scope 'linux-web1' and stays in it"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1|"
}

@test "host enroll: passes port and identity to ssh and names bare IPs" {
    touch "$BATS_TEST_TMPDIR/key"
    run "$TACCTL_BIN_SCRIPT" host enroll root@192.0.2.50 --scope lab --port 2222 --identity "$BATS_TEST_TMPDIR/key"
    assert_success
    stub_called "ssh -o ConnectTimeout=10 .*-p 2222 -i ${BATS_TEST_TMPDIR}/key "
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

@test "host enroll: every step shares one ssh connection, closed at the end" {
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab
    assert_success
    run grep -c "^ssh .*-o ControlMaster=auto -o ControlPath=~/.ssh/tacctl-%C -o ControlPersist=60 " "$CALLS_LOG"
    total="$output"
    run grep -c "^ssh" "$CALLS_LOG"
    assert_output "$total"
    run bash -c "grep ^ssh '$CALLS_LOG' | tail -1"
    assert_output --regexp "^ssh .*-O exit admin@web1.example.net$"
}

@test "host enroll: rejects option-like and malformed targets" {
    run "$TACCTL_BIN_SCRIPT" host enroll "web1;reboot" --scope lab
    assert_failure
    run "$TACCTL_BIN_SCRIPT" host enroll -oProxyCommand=x --scope lab
    assert_failure
    run grep -c "^ssh" "$CALLS_LOG"
    assert_output "0"
}

@test "host enroll: a name that does not resolve, or a failing route lookup, is an error naming the way out" {
    stub_cmd getent 'exit 2'
    run "$TACCTL_BIN_SCRIPT" host enroll ghost --scope lab
    assert_failure 1
    assert_output --partial "[ERROR]"
    assert_output --partial "Cannot resolve 'ghost'"
    stub_cmd getent 'echo "192.0.2.50 STREAM web1"'
    stub_cmd ip 'exit 2'
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_failure 1
    assert_output --partial "Could not determine this server's address for web1 (ip route failed); pass --server <address>"
    [[ -z "$(_hosts)" ]]
    if stub_called '^ssh '; then stub_calls; return 1; fi
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
    assert_output --partial "bob:readonly:80001"
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

@test "host enroll/sync: --adopt is not an option" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --adopt alice
    assert_failure
    assert_output --partial "Unknown option: '--adopt'"
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null
    : > "$CALLS_LOG"
    run "$TACCTL_BIN_SCRIPT" host sync web1 --adopt alice
    assert_failure
    assert_output --partial "Unknown option: '--adopt'"
    if stub_called '^ssh '; then stub_calls; return 1; fi
}

# Users who leave the scope: the host deletes their accounts; their homes
# go with --remove-home, or when the operator says so on the terminal.
_removed_users() {
    "$TACCTL_BIN_SCRIPT" user add dave readonly --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add erin readonly --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add fred readonly --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user remove dave <<< "y" > /dev/null
    "$TACCTL_BIN_SCRIPT" user scope erin remove lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user disable fred > /dev/null
    # What 'getent passwd' says on the host: dave and erin are tacctl's
    # accounts of removed users, fred's is disabled (expired, never deleted),
    # gus is a local account in the range that tacctl did not name, carl a
    # local account outside it.
    export PASSWD_ON_HOST="${BATS_TEST_TMPDIR}/host-passwd"
    printf '%s\n' 'root:x:0:0:root:/root:/bin/bash' \
        'alice:x:80000:80000:alice (TACACS+):/home/alice:/bin/bash' \
        'dave:x:80001:80001:dave (TACACS+):/home/dave:/bin/bash' \
        'erin:x:80002:80002:erin (TACACS+):/home/erin:/bin/bash' \
        'fred:x:80003:80003:fred (TACACS+):/home/fred:/bin/bash' \
        'gus:x:80009:80009:gus (TACACS+):/home/gus:/bin/bash' \
        'carl:x:1001:1001:Carl:/home/carl:/bin/bash' > "$PASSWD_ON_HOST"
    stub_cmd ssh 'case "$*" in
        *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *"getent passwd") cat "$PASSWD_ON_HOST" ;;
    esac'
    : > "$CALLS_LOG"
}

# on_tty <stdin text> <args...>: tacctl on a pseudo-terminal fed the text.
on_tty() {
    local input="$1" cmd
    shift
    printf -v cmd '%q ' "$TACCTL_BIN_SCRIPT" "$@"
    run bash -c "printf '%b' '$input' | script -qec '$cmd' /dev/null"
    output=${output//$'\r'/}
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
}

@test "host sync: on a terminal, asks per removed user whether its home goes too" {
    _removed_users
    on_tty 'y\nn\n' host sync web1
    assert_success
    assert_output --partial "[INFO] web1: removed users with an account there (deleted by this run): dave, erin"
    assert_output --partial "Delete /home/dave of removed user 'dave'? [y/N]"
    assert_output --partial "Delete /home/erin of removed user 'erin'? [y/N]"
    refute_output --partial "/home/fred"
    refute_output --partial "/home/gus"
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_line "TAC_USERS=alice:superuser:80000"
    assert_line "TAC_INACTIVE=fred"
    assert_line "TAC_REMOVE_HOMES=dave"
    assert_line "TAC_UID_FIRST=80000"
    assert_line "TAC_UID_LAST=89999"
    assert_line "TAC_UID_PREVIOUS=''"
    assert_line "TAC_PROTOCOL=5"
    # The ID maps, then the accounts, were read over the shared connection,
    # read-only, before the copy.
    stub_called "^ssh -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath=~/.ssh/tacctl-%C -o ControlPersist=60 -T web1 getent passwd$"
    run bash -c "grep -n '^ssh' '$CALLS_LOG' | head -3"
    assert_line --index 0 --partial "cat /proc/self/uid_map"
    assert_line --index 1 --partial "getent passwd"
    assert_line --index 2 --partial "mktemp"
}

@test "host sync: without a terminal nothing is asked and every home is kept; --remove-home deletes them all" {
    _removed_users
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_success
    refute_output --partial "Delete /home"
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_line "TAC_REMOVE_HOMES=''"
    if stub_called "getent passwd"; then stub_calls; return 1; fi
    run "$TACCTL_BIN_SCRIPT" host sync web1 --remove-home
    assert_success
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_line 'TAC_REMOVE_HOMES=\*'
    # On a terminal too, --remove-home asks nothing.
    on_tty '' host sync --all --remove-home
    assert_success
    refute_output --partial "Delete /home"
    if stub_called "getent passwd"; then stub_calls; return 1; fi
    # enroll asks the same way.
    on_tty 'n\ny\n' host enroll web1 --scope lab --build-on-host
    assert_success
    assert_output --partial "Delete /home/erin of removed user 'erin'? [y/N]"
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_line "TAC_REMOVE_HOMES=erin"
}

@test "host list: counts only users that get accounts" {
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add bob readonly --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user disable bob > /dev/null
    run "$TACCTL_BIN_SCRIPT" host list
    assert_line --regexp "web1 +web1 +lab +192\.0\.2\.1 +tacplus +1$"
}

@test "host sync: unknown host is an error" {
    run "$TACCTL_BIN_SCRIPT" host sync ghost
    assert_failure
    assert_output --partial "No enrolled host named 'ghost'"
}

@test "host sync, list, validate: a host another scope now answers is reported, not moved; a move is confirmed" {
    _own_scope web1 192.0.2.50
    "$TACCTL_BIN_SCRIPT" host enroll web1 > /dev/null
    run "$TACCTL_BIN_SCRIPT" host sync web1
    refute_output --partial "registered in scope"
    # The prefixes change: linux-web1 no longer holds the address, lab does.
    "$TACCTL_BIN_SCRIPT" scope prefixes linux-web1 add 192.0.2.99/32 > /dev/null
    "$TACCTL_BIN_SCRIPT" scope prefixes linux-web1 remove 192.0.2.50/32 > /dev/null
    "$TACCTL_BIN_SCRIPT" scope prefixes lab add 192.0.2.0/24 > /dev/null
    want="web1: registered in scope 'linux-web1', but 192.0.2.50 is answered by scope 'lab' (prefix 192.0.2.0/24): its logins are checked against that scope's users and secret, so they are refused. To move it: tacctl host move web1"
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_success
    assert_output --partial "$want"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1|"
    run "$TACCTL_BIN_SCRIPT" host list
    assert_output --partial "$want"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_line --regexp "Linux hosts:.* web1: registered in scope 'linux-web1', but 192\.0\.2\.50 is answered by scope 'lab'"
    assert_output --partial "$want"
    # Re-enrolling without --scope keeps it, and points at the move.
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_success
    assert_output --partial "(or enroll it in that scope: --scope lab)"
    # The move: linux-web1 has no users, so nothing is deleted and nothing asked.
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "Moving web1 from scope 'linux-web1' to scope 'lab': it gets that scope's secret and users."
    refute_output --partial "are deleted"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_line --regexp "Linux hosts:.* each answered by its scope"
    # Back: lab's users would lose their accounts; no terminal, no --yes.
    rm -f "$PUSHED"
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope linux-web1
    assert_failure
    assert_output --partial "their accounts on web1 are deleted: alice"
    assert_output --partial "Moving web1 to scope 'linux-web1' deletes accounts; nothing was changed. Confirm with --yes."
    [[ ! -e "$PUSHED" ]]
    run _hosts
    assert_output "web1|web1||lab|192.0.2.1|"
}

@test "host move, scope prefixes move, scope remove: hosts follow their prefixes only when moved" {
    _own_scope web1 192.0.2.50
    "$TACCTL_BIN_SCRIPT" host enroll web1 > /dev/null
    # A scope a host uses is not removed, --force or not.
    run "$TACCTL_BIN_SCRIPT" scope remove linux-web1 --force <<< y
    assert_failure
    assert_output --partial "Cannot remove 'linux-web1': enrolled hosts use it: web1. Nothing was changed."
    assert_output --partial "tacctl host move <host> [<scope>]"
    run "$TACCTL_BIN_SCRIPT" scope prefixes linux-web1 remove --all --force <<< y
    assert_failure
    assert_output --partial "enrolled hosts use it: web1"

    # Prefixes move in one change; the host is named, not moved.
    "$TACCTL_BIN_SCRIPT" scope prefixes linux-web1 add 192.0.2.99/32 > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope prefixes linux-web1 move 192.0.2.50/32 lab
    assert_success
    assert_output --partial "Moved 1 prefix(es) from scope 'linux-web1' to 'lab': 192.0.2.50/32"
    assert_output --partial "web1: registered in scope 'linux-web1', but 192.0.2.50 is answered by scope 'lab'"
    assert_output --partial "To move it: tacctl host move web1"
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    assert_output --partial "192.0.2.50/32"
    run "$TACCTL_BIN_SCRIPT" scope prefixes linux-web1 list
    refute_output --partial "192.0.2.50/32"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1|"
    # Refusals: not its prefix; the last one; unknown target.
    run "$TACCTL_BIN_SCRIPT" scope prefixes linux-web1 move 10.9.9.0/24 lab
    assert_failure
    assert_output --partial "Not prefixes of scope 'linux-web1': 10.9.9.0/24. Nothing was changed."
    run "$TACCTL_BIN_SCRIPT" scope prefixes linux-web1 move 192.0.2.99/32 lab
    assert_failure
    assert_output --partial "Cannot move every prefix of scope 'linux-web1'"
    run "$TACCTL_BIN_SCRIPT" scope prefixes linux-web1 move 192.0.2.99/32 nope
    assert_failure
    assert_output --partial "Scope 'nope' does not exist."

    # host move without a scope: the one answering its address.
    run "$TACCTL_BIN_SCRIPT" host move web1
    assert_success
    assert_output --partial "Moving web1 from scope 'linux-web1' to scope 'lab'"
    assert_output --partial "Host 'web1' enrolled"
    run _hosts
    assert_output "web1|web1||lab|192.0.2.1|"
    grep -q "TAC_SCOPE=lab" "$PUSHED"
    run "$TACCTL_BIN_SCRIPT" host move web1
    assert_success
    assert_output --partial "web1 is already in scope 'lab'."
    run "$TACCTL_BIN_SCRIPT" host move --all
    assert_success
    assert_output --partial "Every enrolled host is answered by its scope; nothing to move."
    # Named: back to its own scope, which deletes lab's users' accounts.
    run "$TACCTL_BIN_SCRIPT" host move web1 linux-web1
    assert_failure
    assert_output --partial "Confirm with --yes"
    run "$TACCTL_BIN_SCRIPT" host move web1 linux-web1 --yes
    assert_success
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1|"
    # Now unused: removable.
    run "$TACCTL_BIN_SCRIPT" host move web1 lab --yes
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope remove linux-web1 <<< y
    assert_success
}

@test "host enroll --staging: the bench address joins the scope until the host is seen in place" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --staging
    assert_failure
    assert_output --partial "--staging provisions a host off-site for the scope it will be installed in"
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --staging
    assert_success
    assert_output --partial "Staging address 192.0.2.50/32 added to scope 'lab' (its secret and users) for host 'web1'"
    refute_output --partial "does not cover"
    grep -q "TAC_SCOPE=lab" "$PUSHED"
    grep -q "TAC_SECRET=0123456789abcdef0123456789abcdef" "$PUSHED"
    run _hosts
    assert_output "web1|web1||lab|192.0.2.1|"
    run "$TACCTL_BIN_SCRIPT" scope lookup 192.0.2.50
    assert_output --partial "lab"
    run "$TACCTL_BIN_SCRIPT" scope staging
    assert_success
    assert_output --regexp "192\.0\.2\.50/32 +lab +host web1"
    # Still on the bench: a sync keeps it.
    "$TACCTL_BIN_SCRIPT" host sync web1 > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    assert_output --partial "192.0.2.50/32"
    # Installed: it now resolves into lab's prefixes; the next sync ends it.
    "$TACCTL_BIN_SCRIPT" scope prefixes lab add 198.51.100.0/24 > /dev/null
    stub_cmd getent 'echo "198.51.100.77 STREAM web1"'
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_success
    assert_output --partial "Staging address 192.0.2.50/32 removed from scope 'lab': web1 is now seen at 198.51.100.77 (prefix 198.51.100.0/24)."
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    refute_output --partial "192.0.2.50/32"
    run "$TACCTL_BIN_SCRIPT" scope staging
    assert_output --partial "None."
}

@test "config cisco --staging: the bench address joins the scope; the configuration stays clean; removed when the device moves" {
    run "$TACCTL_BIN_SCRIPT" config cisco --staging 203.0.113.9
    assert_failure
    assert_output --partial "--staging provisions a device off-site"
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --staging 203.0.113.0/24
    assert_failure
    assert_output --partial "--staging takes the device's bench IPv4 address"
    "$TACCTL_BIN_SCRIPT" config cisco --scope lab --staging 203.0.113.9 --name sw1 > "$BATS_TEST_TMPDIR/cfg" 2> "$BATS_TEST_TMPDIR/err"
    grep -q "Staging address 203.0.113.9/32 added to scope 'lab' (its secret and users) for device 'sw1'" "$BATS_TEST_TMPDIR/err"
    ! grep -q "Staging" "$BATS_TEST_TMPDIR/cfg"
    grep -q "tacacs" "$BATS_TEST_TMPDIR/cfg"
    run "$TACCTL_BIN_SCRIPT" scope staging
    assert_output --regexp "203\.0\.113\.9/32 +lab +device sw1"
    # Registered on the bench: kept; moved to lab's prefixes: removed.
    "$TACCTL_BIN_SCRIPT" device add sw1 203.0.113.9 --vendor cisco --no-host-key > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    assert_output --partial "203.0.113.9/32"
    run "$TACCTL_BIN_SCRIPT" device address sw1 192.168.5.9
    assert_success
    assert_output --partial "Staging address 203.0.113.9/32 removed from scope 'lab': sw1 is now seen at 192.168.5.9 (prefix 192.168.0.0/16)."
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    refute_output --partial "203.0.113.9/32"
    # Without a name it is removed by hand.
    "$TACCTL_BIN_SCRIPT" config juniper --scope lab --staging 203.0.113.10 > /dev/null 2>&1
    run "$TACCTL_BIN_SCRIPT" scope staging remove 203.0.113.10
    assert_success
    assert_output --partial "Staging address 203.0.113.10/32 removed from scope 'lab'."
    run "$TACCTL_BIN_SCRIPT" scope prefixes lab list
    refute_output --partial "203.0.113.10/32"
}

@test "host unenroll: pushes the secret-free removal script and forgets the host" {
    _own_scope web1 192.0.2.50
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
    assert_line --regexp "web1 +web1 +lab +192\.0\.2\.1 +tacplus +1"
}

@test "host: is superuser-only" {
    stub_cmd id 'echo "users tac-users"'
    "$TACCTL_BIN_SCRIPT" user add op operator --hash "$HASH" --scopes lab > /dev/null
    SUDO_USER=op run "$TACCTL_BIN_SCRIPT" host list
    assert_failure
    assert_output --partial "not permitted"
}

# --- prebuilt module (container build on the server) --------------------------

# The probe answers as <os-release lines> on <arch>; podman is a stand-in
# that "builds" a two-file bundle.
_prebuilt_env() {
    export PROBE_OS="$1" PROBE_ARCH="${2:-$(uname -m)}"
    stub_cmd ssh 'case "$*" in
        *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *os-release*) printf "%b" "$PROBE_OS"; [[ "$*" == *"echo; echo"* ]] && echo; echo "TACCTL_ARCH=$PROBE_ARCH" ;;
        *) [[ -z "${SSH_RUN_FAILS:-}" ]] ;;
    esac'
    stub_cmd podman 'case "$1" in
        build) [[ -z "${PODMAN_FAILS:-}" ]] ;;
        run)   cat > /dev/null; d=$(mktemp -d); echo lib > "$d/libtac.so.5.0.0"; echo mod > "$d/pam_tacplus.so"
               tar -C "$d" -czf - libtac.so.5.0.0 pam_tacplus.so ;;
        image) echo "sha256:feedface" ;;
    esac'
}

@test "host enroll: builds the module in a container for the host's OS and ships it" {
    _prebuilt_env 'ID=neon\nID_LIKE="ubuntu debian"\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble'
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "Building pam_tacplus for ubuntu:noble in a container"
    stub_called "podman build .*-t localhost/tacctl-build:ubuntu-noble-$(uname -m)"
    stub_called "podman run --rm -i --network none .*localhost/tacctl-build:ubuntu-noble-$(uname -m)"

    local dir="$TACCTL_LINUX_DIR/builds/ubuntu-noble-$(uname -m)"
    run cat "$dir/info"
    assert_line "image=docker.io/library/ubuntu:noble"
    assert_line "digest=sha256:feedface"

    # The pushed script carries the bundle, its checksum, and still the source.
    local want got
    want=$(sed -n 's/^PREBUILT_SHA256=//p' "$PUSHED")
    got=$(sed -n '/^__PREBUILT__$/,$p' "$PUSHED" | tail -n +2 | base64 -d | sha256sum | awk '{print $1}')
    [[ -n "$want" && "$want" == "$got" ]]
    want=$(sed -n 's/^TARBALL_SHA256=//p' "$PUSHED")
    got=$(sed -n '/^__TARBALL__$/,/^__PREBUILT__$/p' "$PUSHED" | sed '1d;/^__PREBUILT__$/d' | base64 -d | sha256sum | awk '{print $1}')
    [[ "$want" == "$got" ]]

    # A second host of the same OS reuses the cached build.
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --name web2
    assert_success
    refute_output --partial "in a container"
    run grep -c "^podman run" "$CALLS_LOG"
    assert_output "1"

    run "$TACCTL_BIN_SCRIPT" config linux builds
    assert_output --partial "ubuntu:noble"
    run "$TACCTL_BIN_SCRIPT" config linux builds clear
    assert_success
    [[ ! -d "$TACCTL_LINUX_DIR/builds" ]]
}

@test "host enroll: Debian and plain Ubuntu hosts map to their own images" {
    _prebuilt_env 'ID=debian\nVERSION_CODENAME=bookworm'
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    stub_called "podman build .*-t localhost/tacctl-build:debian-bookworm-"
    _prebuilt_env 'ID=ubuntu\nVERSION_CODENAME=jammy'
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    stub_called "podman build .*-t localhost/tacctl-build:ubuntu-jammy-"
}

@test "host enroll: unknown OS, other architecture or --build-on-host compile on the host" {
    _prebuilt_env 'ID=fedora\nVERSION_CODENAME=""'
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "No container image is known"

    _prebuilt_env 'ID=ubuntu\nVERSION_CODENAME=noble' riscv64
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "The host is riscv64"

    _prebuilt_env 'ID=ubuntu\nVERSION_CODENAME=noble'
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --build-on-host
    assert_success
    assert_output --partial "compiled on the host (--build-on-host)"

    run grep -c "^podman" "$CALLS_LOG"
    assert_output "0"
    refute grep -q -e '^__PREBUILT__$' -e '^PREBUILT_SHA256=' "$PUSHED"
    grep -q '^__TARBALL__$' "$PUSHED"
}

@test "host enroll: a failed container build falls back to compiling on the host" {
    _prebuilt_env 'ID=ubuntu\nVERSION_CODENAME=noble; rm -rf /'
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "No container image is known"

    _prebuilt_env 'ID=ubuntu\nVERSION_CODENAME=noble'
    PODMAN_FAILS=1 run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "compiled on the host instead"
    assert_output --partial "Host 'web1' enrolled"
    refute grep -q '^__PREBUILT__$' "$PUSHED"
}

@test "host enroll: re-enrolling a registered host keeps its server address" {
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --server 198.51.100.7 > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    run _hosts
    assert_output "web1|web1||lab|198.51.100.7|"
}

# --- methods (tacplus | radius) ------------------------------------------------

# Enable the RADIUS backend the way tacctl.yaml records it. Enough for
# commands that only read (an enroll into an existing scope).
radius_on() {
    printf 'backends:\n  enabled: [tacacs, radius]\n' >> "${TACCTL_STATE_DIR}/tacctl.yaml"
}

# The same, for tests whose command also changes the store (a scope created
# or its protocols changed): the render then needs the daemon's config check,
# which a stand-in that accepts everything provides.
radius_on_rendering() {
    mkdir -p "$(dirname "$TACCTL_RADIUS_BIN")" "$TACCTL_RADIUS_DIR" "$TACCTL_RADIUS_LOG"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$TACCTL_RADIUS_BIN"
    chmod +x "$TACCTL_RADIUS_BIN"
    stub_cmd id 'exit 0'
    stub_cmd sleep
    stub_cmd ss
    export TACCTL_SETTLE_SECONDS=0
    radius_on
    "$TACCTL_BIN_SCRIPT" config render > /dev/null
}

_protocols() { "$TACCTL_BIN_SCRIPT" scope protocols "$1" | sed -n "s/.*Scope '$1' protocols: //p"; }

@test "host enroll --method radius: refused while the RADIUS backend is not enabled; nothing reaches the host" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --method radius
    assert_failure
    assert_output --partial "needs the RADIUS backend, which is not enabled"
    assert_output --partial "tacctl backend enable radius"
    run grep -c "^ssh" "$CALLS_LOG"
    assert_output "0"
    run _hosts
    assert_output ""
    # No per-host scope was created on the way either.
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --method radius
    assert_failure
    run "$TACCTL_BIN_SCRIPT" scope show linux-web1
    assert_failure
}

@test "host enroll --method: an unknown method is refused" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --method ldap
    assert_failure
    assert_output --partial "Unknown method 'ldap'. Methods: tacplus, radius"
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --method
    assert_failure
    run grep -c "^ssh" "$CALLS_LOG"
    assert_output "0"
}

@test "host enroll --method radius: pushes the package-based script and registers the method" {
    radius_on
    # Neither the pam_tacplus tarball nor a container build is involved.
    rm -f "$TACCTL_LINUX_DIR"/*.tar.gz
    stub_cmd podman
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab --method radius
    assert_success
    assert_output --partial "in scope 'lab', server 192.0.2.1, method radius..."
    assert_output --partial "Host 'web1' enrolled"
    run _hosts
    assert_output "web1|admin@web1.example.net||lab|192.0.2.1||radius"
    run cat "$PUSHED"
    assert_line "TAC_METHOD=radius"
    assert_line "TAC_SERVER=192.0.2.1"
    assert_line "TAC_PORT=1812"
    assert_line "TAC_ACCT_PORT=1813"
    assert_line "TAC_SECRET=0123456789abcdef0123456789abcdef"
    assert_output --partial "alice:superuser:80000"
    refute_line "__TARBALL__"
    refute_output --partial "TARBALL_SHA256="
    run bash -n "$PUSHED"
    assert_success
    run grep -cE "^podman|os-release" "$CALLS_LOG"
    assert_output "0"
}

@test "host enroll --method radius: the ports are the auth and acct listeners'; --build-on-host does not apply" {
    radius_on
    printf 'listeners:\n  radius:\n    auth: {network: udp, address: "192.0.2.1:11812", role: auth}\n    acct: {network: udp, address: ":11899", role: acct}\n' \
        >> "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --method radius --build-on-host
    assert_success
    assert_output --partial "--build-on-host does not apply to method radius"
    run cat "$PUSHED"
    assert_line "TAC_PORT=11812"
    assert_line "TAC_ACCT_PORT=11899"
}

@test "host enroll: the default method is tacplus and its script says so" {
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    refute_output --partial "method"
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_line "TAC_METHOD=tacplus"
    assert_line "TAC_PORT=49"
    refute_line --regexp "^TAC_ACCT_PORT="
}

@test "host enroll --method radius: a scope that is not served over RADIUS is refused" {
    "$TACCTL_BIN_SCRIPT" scope protocols lab set tacacs > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --method radius
    assert_failure
    assert_output --partial "Scope 'lab' is not served over RADIUS (its protocols: tacacs)"
    assert_output --partial "tacctl scope protocols lab set tacacs,radius"
    run grep -c "^ssh" "$CALLS_LOG"
    assert_output "0"
}

@test "host enroll: a host's own scope served over RADIUS only is a RADIUS client, not a TACACS+ one" {
    radius_on_rendering
    stub_cmd getent 'echo "192.0.2.51 STREAM web2"'
    _own_scope web2 192.0.2.51 radius
    run "$TACCTL_BIN_SCRIPT" host enroll web2 --method radius
    assert_success
    run _protocols linux-web2
    assert_output "radius"
    run _hosts
    assert_line "web2|web2||linux-web2|192.0.2.1||radius"
    # Its /32 and secret are a RADIUS client, and not a TACACS+ one.
    grep -q "tacctl_scope = \"linux-web2\"" "${TACCTL_RADIUS_DIR}/tacctl-radius.conf"
    run grep -c "linux-web2" "${TACCTL_ETC}/tacquito.yaml"
    assert_output "0"
}

@test "host enroll: re-enrolling with the other method switches the host and its own scope" {
    radius_on_rendering
    _own_scope web1 192.0.2.50 tacacs
    "$TACCTL_BIN_SCRIPT" host enroll web1 > /dev/null
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1|"

    run "$TACCTL_BIN_SCRIPT" host enroll web1 --method radius
    assert_success
    assert_output --partial "Scope 'linux-web1' was limited to tacacs; opening it to radius"
    assert_output --partial "Switching web1 from tacplus to radius."
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1||radius"
    run _protocols linux-web1
    assert_output "radius"
    grep -q '^TAC_METHOD=radius$' "$PUSHED"

    # Without --method a registered host keeps the method it has.
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_success
    refute_output --partial "Switching"
    grep -q '^TAC_METHOD=radius$' "$PUSHED"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1||radius"

    # And back.
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --method tacplus
    assert_success
    assert_output --partial "Switching web1 from radius to tacplus."
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1|"
    run _protocols linux-web1
    assert_output "tacacs"
    grep -q '^TAC_METHOD=tacplus$' "$PUSHED"
}

@test "host enroll: a failed switch leaves the registration, and the scope open to both" {
    radius_on_rendering
    _own_scope web1 192.0.2.50 tacacs
    "$TACCTL_BIN_SCRIPT" host enroll web1 > /dev/null
    SSH_RUN_FAILS=1 run "$TACCTL_BIN_SCRIPT" host enroll web1 --method radius
    assert_failure
    assert_output --partial "its registration (method tacplus) was left as it was"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1|"
    run _protocols linux-web1
    assert_output "tacacs,radius"
}

@test "host enroll: a per-host scope other hosts use is not opened to another protocol" {
    radius_on_rendering
    _own_scope web1 192.0.2.50 tacacs
    "$TACCTL_BIN_SCRIPT" host enroll web1 > /dev/null
    "$TACCTL_BIN_SCRIPT" host enroll web1 --name web9 --scope linux-web1 > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --method radius
    assert_failure
    assert_output --partial "Scope 'linux-web1' is not served over RADIUS"
    assert_output --partial "Other enrolled hosts use scope 'linux-web1'"
    run _protocols linux-web1
    assert_output "tacacs"
}

@test "host sync and unenroll: use the method the host was enrolled with" {
    radius_on
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --method radius > /dev/null
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --name web2 > /dev/null
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_success
    run cat "$PUSHED"
    assert_line "TAC_METHOD=radius"
    assert_line "TAC_PORT=1812"
    run "$TACCTL_BIN_SCRIPT" host sync web2
    assert_success
    run cat "$PUSHED"
    assert_line "TAC_METHOD=tacplus"
    assert_line "TAC_PORT=49"

    run "$TACCTL_BIN_SCRIPT" host list
    assert_line --regexp "web1 +web1 +lab +192\.0\.2\.1 +radius +1$"
    assert_line --regexp "web2 +web1 +lab +192\.0\.2\.1 +tacplus +1$"

    run "$TACCTL_BIN_SCRIPT" host unenroll web1
    assert_success
    assert_output --partial "Removing RADIUS authentication from web1"
    run "$TACCTL_BIN_SCRIPT" host unenroll web2
    assert_success
    assert_output --partial "Removing TACACS+ authentication from web2"
}

@test "host: a six-field registry line is a tacplus host" {
    echo "old1|admin@old1||lab|192.0.2.1|" > "${TACCTL_STATE_DIR}/linux-hosts"
    run "$TACCTL_BIN_SCRIPT" host list
    assert_line --regexp "old1 +admin@old1 +lab +192\.0\.2\.1 +tacplus +1$"
    run "$TACCTL_BIN_SCRIPT" host sync old1
    assert_success
    run cat "$PUSHED"
    assert_line "TAC_METHOD=tacplus"
    # Re-enrolled without --method it stays tacplus, whatever the default is.
    radius_on
    "$TACCTL_BIN_SCRIPT" host default-method radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll admin@old1 --scope lab
    assert_success
    run _hosts
    assert_output "old1|admin@old1||lab|192.0.2.1|"
}

@test "host default-method: sets host.default_method, which new hosts get" {
    run "$TACCTL_BIN_SCRIPT" host default-method
    assert_success
    assert_output --partial "Default method for new hosts: tacplus"
    run "$TACCTL_BIN_SCRIPT" host default-method ldap
    assert_failure
    run "$TACCTL_BIN_SCRIPT" host default-method radius
    assert_success
    assert_output --partial "RADIUS backend is not enabled yet"
    run "$TACCTL_BIN_SCRIPT" config get host.default_method
    assert_output "radius"
    # The default names a backend that is off: enroll says so, and --method wins.
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_failure
    assert_output --partial "tacctl backend enable radius"
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --method tacplus
    assert_success
    radius_on
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --name web2
    assert_success
    run _hosts
    assert_line "web1|web1||lab|192.0.2.1|"
    assert_line "web2|web1||lab|192.0.2.1||radius"
    run "$TACCTL_BIN_SCRIPT" host default-method tacplus
    assert_success
    run "$TACCTL_BIN_SCRIPT" config get host.default_method
    assert_output "tacplus"
}

@test "host.default_method: only tacplus or radius is accepted in tacctl.yaml" {
    printf 'host:\n  default_method: ldap\n' >> "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_output --partial "host.default_method"
}

# --- the scope's auth-method (tacctl scope auth-method) ----------------------------

@test "host enroll: without --method a new host takes the scope's auth-method" {
    radius_on
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "Method radius: scope 'lab' has auth-method radius (tacctl scope auth-method)"
    run _hosts
    assert_output "web1|web1||lab|192.0.2.1||radius"
    grep -q '^TAC_METHOD=radius$' "$PUSHED"
}

@test "host enroll: --method wins over the scope's auth-method" {
    radius_on
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --method tacplus
    assert_success
    refute_output --partial "auth-method"
    run _hosts
    assert_output "web1|web1||lab|192.0.2.1|"
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_line "TAC_METHOD=tacplus"
}

@test "host enroll: a registered host keeps its method whatever the scope's auth-method says" {
    radius_on
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "web1 is registered with method tacplus and keeps it; scope 'lab' has auth-method radius (tacctl scope auth-method). To switch the host: --method radius"
    refute_output --partial "Switching"
    run _hosts
    assert_output "web1|web1||lab|192.0.2.1|"
    # Asked to, it switches.
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --method radius
    assert_success
    run _hosts
    assert_output "web1|web1||lab|192.0.2.1||radius"
}

@test "host enroll: the scope's auth-method comes before host default-method" {
    radius_on
    "$TACCTL_BIN_SCRIPT" host default-method radius > /dev/null
    "$TACCTL_BIN_SCRIPT" scope auth-method lab tacacs > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "Method tacplus: scope 'lab' has auth-method tacacs (tacctl scope auth-method)"
    run _hosts
    assert_output "web1|web1||lab|192.0.2.1|"
    # A scope without one still takes the default.
    "$TACCTL_BIN_SCRIPT" scope auth-method lab default > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --name web2
    assert_success
    run _hosts
    assert_line "web2|web1||lab|192.0.2.1||radius"
}

@test "host enroll: without --method or an auth-method, a scope served over one protocol only decides" {
    radius_on_rendering
    "$TACCTL_BIN_SCRIPT" scope protocols lab set radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_success
    assert_output --partial "Method radius: scope 'lab' is served over radius only (tacctl scope protocols)"
    run _hosts
    assert_output "web1|web1||lab|192.0.2.1||radius"
    # Both protocols decide nothing: the default (tacplus) again.
    "$TACCTL_BIN_SCRIPT" scope protocols lab set tacacs,radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab --name web2
    assert_success
    refute_output --partial "served over"
    run _hosts
    assert_line "web2|web1||lab|192.0.2.1|"
}

@test "host enroll: an existing linux-<name> scope limited to one protocol is re-enrolled with it after the registration is gone" {
    radius_on_rendering
    _own_scope web1 192.0.2.50 radius
    "$TACCTL_BIN_SCRIPT" host enroll web1 --method radius > /dev/null
    run _protocols linux-web1
    assert_output "radius"
    : > "${TACCTL_STATE_DIR}/linux-hosts"
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_success
    assert_output --partial "Method radius: scope 'linux-web1' is served over radius only"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1||radius"
}

@test "host enroll: the scope's auth-method names a backend that is off: refused, nothing reaches the host" {
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab
    assert_failure
    assert_output --partial "tacctl backend enable radius"
    run grep -c "^ssh" "$CALLS_LOG"
    assert_output "0"
}

@test "host enroll: the host's scope's auth-method is used" {
    radius_on_rendering
    "$TACCTL_BIN_SCRIPT" scope add linux-web1 --prefixes 192.0.2.50/32 --secret generate > /dev/null
    "$TACCTL_BIN_SCRIPT" scope auth-method linux-web1 radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1
    assert_success
    assert_output --partial "Method radius: scope 'linux-web1' has auth-method radius (tacctl scope auth-method)"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1||radius"
}

@test "host enroll: switching a host does not limit its scope away from the scope's auth-method" {
    radius_on_rendering
    _own_scope web1 192.0.2.50 tacacs
    "$TACCTL_BIN_SCRIPT" host enroll web1 > /dev/null
    "$TACCTL_BIN_SCRIPT" scope auth-method linux-web1 tacacs > /dev/null
    run "$TACCTL_BIN_SCRIPT" host enroll web1 --method radius
    assert_success
    assert_output --partial "Scope 'linux-web1' has auth-method tacacs, so it stays open to tacacs, radius instead of being limited to radius."
    run _protocols linux-web1
    assert_output "tacacs,radius"
    run _hosts
    assert_output "web1|web1||linux-web1|192.0.2.1||radius"
}

# --- hosts that cannot hold the UID range ---------------------------------------

# An unprivileged container: its user namespace maps 0-65535 only.
_container_ssh() {
    stub_cmd ssh 'case "$*" in
        *uid_map*) printf "%s\n" uid_map "0 100000 65536" gid_map "0 100000 65536" ;;
        *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *) true ;;
    esac'
}

@test "host enroll|sync: a host whose user namespace cannot hold the UID range is refused before anything changes" {
    _container_ssh
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab
    assert_failure 1
    assert_output --partial "'web1' cannot hold UIDs 80000-89999: its user namespace maps only 0-65535 (an unprivileged container)."
    assert_output --partial "Enrollment of web1 refused; nothing was changed."
    [[ ! -e "$PUSHED" ]]
    [[ -z "$(_hosts)" ]]
    # Enrolled from a host that could, then synced as a container: refused.
    stub_cmd ssh 'case "$*" in
        *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *) true ;;
    esac'
    "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab > /dev/null
    rm -f "$PUSHED"
    _container_ssh
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_failure 1
    assert_output --partial "'web1' cannot hold UIDs 80000-89999"
    [[ ! -e "$PUSHED" ]]
    # A range it can hold.
    "$TACCTL_BIN_SCRIPT" config linux uid-range 40000-49999 > /dev/null
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_success
    run sed '/^__TARBALL__$/,$d' "$PUSHED"
    assert_line "TAC_USERS=alice:superuser:40000"
    assert_line "TAC_UID_FIRST=40000"
}

@test "host enroll --local: this machine's own ID maps are checked" {
    mkdir -p "$BATS_TEST_TMPDIR/proc"
    echo "0 100000 65536" > "$BATS_TEST_TMPDIR/proc/uid_map"
    echo "0 100000 65536" > "$BATS_TEST_TMPDIR/proc/gid_map"
    "$TACCTL_BIN_SCRIPT" scope prefixes lab add 127.0.0.1/32 > /dev/null
    TACCTL_TEST_PROC="$BATS_TEST_TMPDIR/proc" run "$TACCTL_BIN_SCRIPT" host enroll --local --name authsrv --scope lab
    assert_failure 1
    assert_output --partial "'authsrv' cannot hold UIDs 80000-89999: its user namespace maps only 0-65535"
    [[ -z "$(_hosts)" ]]
}

@test "host enroll --local: a scope that does not cover 127.0.0.1 is refused before anything changes" {
    run "$TACCTL_BIN_SCRIPT" host enroll --local --name authsrv --scope lab
    assert_failure 1
    assert_output --partial "Scope 'lab' does not cover 127.0.0.1, the address this server's own logins reach TACACS+ and RADIUS from"
    assert_output --partial "tacctl scope prefixes lab add 127.0.0.1/32"
    assert_output --partial "Nothing was changed."
    [[ -z "$(_hosts)" ]]
    if stub_called '^bash '; then stub_calls; return 1; fi
}
