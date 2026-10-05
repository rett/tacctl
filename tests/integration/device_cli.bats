#!/usr/bin/env bats
# Integration tests for `tacctl device`: the registry file, CRUD, import and
# export, name notices, and the namespace shared with `host enroll`.

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
    DEVICES="${TACCTL_STATE_DIR}/devices.yaml"
}

# plain: the last output with colours stripped.
plain() { output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output"); }

# snapshot_count: snapshots in the backup directory.
snapshot_count() { find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -name '2*' | wc -l; }

# --- the acceptance scenario ---------------------------------------------------------

@test "device add: unconfigured until a scope's prefixes cover it, configured after" {
    run "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --vendor cisco --no-host-key
    assert_success
    run "$TACCTL_BIN_SCRIPT" device list
    assert_success
    plain
    assert_output --partial "Registered devices (1) and enrolled hosts (0)"
    assert_output --regexp "core-sw1 +10\.99\.0\.1 +cisco +- +unconfigured"
    assert_output --partial "seen data: none (tacctl device scan)"

    run "$TACCTL_BIN_SCRIPT" scope prefixes lab add 10.99.0.0/24
    assert_success
    run "$TACCTL_BIN_SCRIPT" device list
    plain
    assert_output --regexp "core-sw1 +10\.99\.0\.1 +cisco +lab +configured +- +- +- +hostkey-unpinned"
    run "$TACCTL_BIN_SCRIPT" device show 10.99.0.1
    assert_success
    plain
    assert_output --partial "Device core-sw1"
    assert_output --partial "lab  (via prefix 10.99.0.0/24)"
}

@test "device add: a name differing only in case is a duplicate" {
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --vendor cisco --no-host-key
    run "$TACCTL_BIN_SCRIPT" device add Core-SW1 10.99.0.2
    assert_failure 1
    plain
    assert_output --partial "'core-sw1' is already registered (10.99.0.1); choose another name, or see 'tacctl device show core-sw1'"
    run "$TACCTL_BIN_SCRIPT" device add other-sw 10.99.0.1
    assert_failure 1
    plain
    assert_output --partial "10.99.0.1 is already registered as 'core-sw1'; rename it with 'tacctl device rename core-sw1 <new>'"
    run grep -c '^  ' "$DEVICES"
    assert_output "1"
}

@test "device registry: a 0.1.18 store round-trips unchanged and the registry is 0600" {
    local before after
    before=$(sha256sum < "${TACCTL_STATE_DIR}/store.yaml")
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --vendor cisco --no-host-key
    "$TACCTL_BIN_SCRIPT" device rename core-sw1 dc1-core1
    "$TACCTL_BIN_SCRIPT" device remove dc1-core1 -y
    after=$(sha256sum < "${TACCTL_STATE_DIR}/store.yaml")
    [[ "$before" == "$after" ]]
    run stat -c %a "$DEVICES"
    assert_output "600"
    run grep -c "tacquito\|systemctl" "$CALLS_LOG"
    assert_output "0"
}

@test "devices.yaml has the documented shape" {
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --vendor cisco --no-host-key --description "DC1 core"
    "$TACCTL_BIN_SCRIPT" device add lab-rtr2 192.0.2.7 --vendor juniper --hostname lab-rtr2.lab.example.net --no-host-key
    run cat "$DEVICES"
    assert_output "# tacctl device registry: names for the devices and hosts that authenticate here.
# Edit with 'tacctl device ...'. Scope and activity are not stored; they are looked up.
version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco, description: DC1 core}
  lab-rtr2: {address: 192.0.2.7, vendor: juniper, hostname: lab-rtr2.lab.example.net}"
}

# --- usage and exit codes ---------------------------------------------------------------

@test "device: no subcommand prints the usage and exits 0; an unknown one exits 1" {
    run "$TACCTL_BIN_SCRIPT" device
    assert_success
    assert_output --partial "Usage: tacctl device <subcommand>"
    run "$TACCTL_BIN_SCRIPT" device help
    assert_success
    run "$TACCTL_BIN_SCRIPT" device frobnicate
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'frobnicate'"
    assert_output --partial "Usage: tacctl device <subcommand>"
}

@test "device add: refuses bad input and writes nothing" {
    local args
    for args in "x1" "bad_name!" "-x 10.0.0.1" "x1 10.0.0.0/24" "x1 not-an-ip" "x1 10.0.0.1 --vendor arista" \
                "x1 10.0.0.1 --vendor linux" "x1 10.0.0.1 --port 70000" "x1 10.0.0.1 --login admin" \
                "scope 10.0.0.1" "x1 10.0.0.1 --host-key SHA256:short" "x1 10.0.0.1 --bogus"; do
        # shellcheck disable=SC2086
        run "$TACCTL_BIN_SCRIPT" device add $args
        assert_failure 1
    done
    [[ ! -e "$DEVICES" ]]
}

@test "device add: a generic name is refused with the remedy; --allow-generic registers it with a notice" {
    run "$TACCTL_BIN_SCRIPT" device add switch 10.99.0.1 --vendor juniper
    assert_failure 1
    plain
    assert_output --partial "'switch' is a generic name"
    assert_output --partial "set system host-name <name>"
    assert_output --partial "--allow-generic"
    [[ ! -e "$DEVICES" ]]
    run "$TACCTL_BIN_SCRIPT" device add switch 10.99.0.1 --vendor juniper --allow-generic --no-host-key
    assert_success
    run "$TACCTL_BIN_SCRIPT" device notices
    plain
    assert_output --partial "switch  generic-name:"
    assert_output --partial "tacctl device rename switch <new>"
    run "$TACCTL_BIN_SCRIPT" device notice switch ack generic-name
    assert_success
    run "$TACCTL_BIN_SCRIPT" device list
    plain
    refute_output --partial "generic-name"
    run "$TACCTL_BIN_SCRIPT" device show switch
    plain
    assert_output --partial "generic-name (acknowledged)"
}

# --- CRUD -----------------------------------------------------------------------------------

@test "device setters: show, set and clear one field" {
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --vendor cisco --no-host-key
    run "$TACCTL_BIN_SCRIPT" device port core-sw1
    assert_output "22"
    run "$TACCTL_BIN_SCRIPT" device port core-sw1 830
    assert_success
    run "$TACCTL_BIN_SCRIPT" device port core-sw1
    assert_output "830"
    run "$TACCTL_BIN_SCRIPT" device port core-sw1 clear
    assert_success
    run "$TACCTL_BIN_SCRIPT" device port core-sw1
    assert_output "22"
    run "$TACCTL_BIN_SCRIPT" device hostname core-sw1 core.example.net
    assert_success
    run "$TACCTL_BIN_SCRIPT" device hostname core-sw1
    assert_output "core.example.net"
    run "$TACCTL_BIN_SCRIPT" device description core-sw1 the DC1 core
    assert_success
    run "$TACCTL_BIN_SCRIPT" device description core-sw1
    assert_output "the DC1 core"
    run "$TACCTL_BIN_SCRIPT" device address core-sw1 2001:DB8::7
    assert_success
    run "$TACCTL_BIN_SCRIPT" device address core-sw1
    assert_output "2001:db8::7"
    run "$TACCTL_BIN_SCRIPT" device address core-sw1 clear
    assert_failure 1
    run "$TACCTL_BIN_SCRIPT" device legacy-ssh core-sw1 enable
    assert_success
    run "$TACCTL_BIN_SCRIPT" device legacy-ssh core-sw1
    assert_output "enabled"
    run "$TACCTL_BIN_SCRIPT" device stale-days 45
    assert_success
    run "$TACCTL_BIN_SCRIPT" device stale-days
    assert_output "45"
    run "$TACCTL_BIN_SCRIPT" device stale-days 0
    assert_failure 1
}

@test "device rename: keeps the entry, refuses a taken or generic name" {
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --no-host-key
    "$TACCTL_BIN_SCRIPT" device add edge-fw 10.99.0.2 --no-host-key
    run "$TACCTL_BIN_SCRIPT" device rename core-sw1 EDGE-FW
    assert_failure 1
    run "$TACCTL_BIN_SCRIPT" device rename core-sw1 router
    assert_failure 1
    run "$TACCTL_BIN_SCRIPT" device rename core-sw1 dc1-core1
    assert_success
    run "$TACCTL_BIN_SCRIPT" device show dc1-core1
    assert_success
    run "$TACCTL_BIN_SCRIPT" device show core-sw1
    assert_failure 1
}

@test "device remove: confirms, cancels on closed stdin, -y and --all skip the question" {
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --no-host-key
    "$TACCTL_BIN_SCRIPT" device add edge-fw 10.99.0.2 --no-host-key
    local before
    before=$(sha256sum < "$DEVICES")
    run "$TACCTL_BIN_SCRIPT" device remove core-sw1 < /dev/null
    assert_success
    plain
    assert_output --partial "Aborted."
    [[ "$(sha256sum < "$DEVICES")" == "$before" ]]
    run "$TACCTL_BIN_SCRIPT" device remove core-sw1 <<< "y"
    assert_success
    run grep -c core-sw1 "$DEVICES"
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" device remove nope -y
    assert_failure 1
    run "$TACCTL_BIN_SCRIPT" device remove --all -y
    assert_success
    run "$TACCTL_BIN_SCRIPT" device list
    plain
    assert_output --partial "None."
}

@test "device writes take a snapshot first, and backup diff shows devices.yaml" {
    local n
    n=$(snapshot_count)
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --no-host-key
    "$TACCTL_BIN_SCRIPT" device add edge-fw 10.99.0.2 --no-host-key
    (( $(snapshot_count) == n + 2 ))
    run "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.9
    assert_failure 1
    (( $(snapshot_count) == n + 2 ))
    run "$TACCTL_BIN_SCRIPT" backup diff
    assert_success
    assert_output --partial "devices.yaml"
    assert_output --partial "edge-fw"
}

# --- import and export --------------------------------------------------------------------------

@test "device import/export: CSV in, YAML/CSV/JSON out, --check writes nothing" {
    local csv="${BATS_TEST_TMPDIR}/devices.csv"
    cat > "$csv" <<'CSV'
name,address,vendor,port,description
core-sw1,10.99.0.1,cisco,,"DC1, core"
lab-rtr2,192.0.2.7,juniper,830,
CSV
    run "$TACCTL_BIN_SCRIPT" device import --check "$csv"
    assert_success
    plain
    assert_output --partial "Check passed; nothing written. Would import: 2 added, 0 updated, 0 unchanged, 0 removed."
    [[ ! -e "$DEVICES" ]]
    run "$TACCTL_BIN_SCRIPT" device import "$csv"
    assert_success
    run "$TACCTL_BIN_SCRIPT" device export --csv
    assert_success
    assert_output --partial 'name,address,vendor,port,description'
    assert_output --partial 'core-sw1,10.99.0.1,cisco,,"DC1, core"'
    assert_output --partial "lab-rtr2,192.0.2.7,juniper,830,"
    run "$TACCTL_BIN_SCRIPT" device export --json
    assert_success
    assert_output --partial '"name": "lab-rtr2"'
    # YAML out is the file; it imports back (--replace) to the same bytes.
    "$TACCTL_BIN_SCRIPT" device export > "${BATS_TEST_TMPDIR}/out.yaml"
    cmp "${BATS_TEST_TMPDIR}/out.yaml" "$DEVICES"
    run "$TACCTL_BIN_SCRIPT" device import --replace -y - < "${BATS_TEST_TMPDIR}/out.yaml"
    assert_success
    cmp "${BATS_TEST_TMPDIR}/out.yaml" "$DEVICES"
}

@test "device import: any bad line refuses the whole file, with its line number" {
    local csv="${BATS_TEST_TMPDIR}/bad.csv"
    printf 'a1,10.0.0.1\nb2,10.0.0.0/8\nswitch,10.0.0.3\n' > "$csv"
    run "$TACCTL_BIN_SCRIPT" device import "$csv"
    assert_failure 1
    plain
    assert_output --partial "line 2: Invalid address"
    [[ ! -e "$DEVICES" ]]
    printf 'a1,10.0.0.1\nswitch,10.0.0.3\n' > "$csv"
    run "$TACCTL_BIN_SCRIPT" device import "$csv"
    assert_failure 1
    plain
    assert_output --partial "'switch' is a generic name"
    [[ ! -e "$DEVICES" ]]
    run "$TACCTL_BIN_SCRIPT" device import --allow-generic "$csv"
    assert_success
}

# --- the namespace shared with the hosts ----------------------------------------------------------

@test "host enroll --name refuses a registry name and a generic name" {
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --no-host-key
    run "$TACCTL_BIN_SCRIPT" host enroll --local --name Core-SW1
    assert_failure 1
    plain
    assert_output --partial "'core-sw1' is already registered as a device (10.99.0.1)"
    run "$TACCTL_BIN_SCRIPT" host enroll --local --name switch
    assert_failure 1
    plain
    assert_output --partial "'switch' is a generic name"
    [[ ! -e "${TACCTL_STATE_DIR}/linux-hosts" ]]
}

@test "enrolled hosts appear in device list and show, read-only" {
    printf 'web1|root@192.0.2.10|2222|lab|192.0.2.1|\nubuntu|root@192.0.2.11||lab|192.0.2.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    run "$TACCTL_BIN_SCRIPT" device list
    assert_success
    plain
    assert_output --partial "Registered devices (0) and enrolled hosts (2)"
    assert_output --regexp "web1 +- +linux +lab +configured"
    assert_output --regexp "ubuntu .*generic-name"
    run "$TACCTL_BIN_SCRIPT" device add web1 10.99.0.5
    assert_failure 1
    plain
    assert_output --partial "'web1' is an enrolled host"
    run "$TACCTL_BIN_SCRIPT" device remove web1 -y
    assert_failure 1
    plain
    assert_output --partial "is an enrolled host"
}

@test "completion: _completion-names devices lists the registry and the hosts" {
    printf 'web1|root@192.0.2.10||lab|192.0.2.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --no-host-key
    run "$TACCTL_BIN_SCRIPT" _completion-names devices
    assert_success
    assert_output "core-sw1
web1"
}

# --- host-key pinning ---------------------------------------------------------------------
# ssh-keyscan is stubbed with public keys generated for the tests
# (internal/devreg/testdata/hostkeys; no real host's keys).

KEYS="${TACCTL_SRC}/internal/devreg/testdata/hostkeys"

# key <name>: '<type> <base64>' of a test key; fp <name>: its fingerprint as
# ssh-keygen -lf printed it.
key() { cut -d' ' -f1,2 "${KEYS}/$1.pub"; }
fp() { awk -v f="$1.pub" '$1 == f { print $3 }' "${KEYS}/fingerprints.txt"; }

# offer <name>...: ssh-keyscan answers for its last argument with these keys.
offer() {
    local lines="" k
    for k in "$@"; do
        lines+="echo \"\${!#} $(key "$k")\"; "
    done
    stub_cmd ssh-keyscan "echo '# banner' >&2; ${lines}"
}

@test "device add: pins the keys the device offers, prints the fingerprints, writes known_hosts" {
    offer rsa ed25519
    run "$TACCTL_BIN_SCRIPT" device add x 192.0.2.1 --vendor juniper
    assert_success
    plain
    stub_called "ssh-keyscan -T 5 -p 22 -t ed25519,ecdsa,rsa 192.0.2.1"
    assert_output --partial "Host keys pinned (2); compare with the device console before first use:"
    assert_output --partial "ED25519  $(fp ed25519)"
    assert_output --partial "RSA      $(fp rsa)"
    assert_output --partial "On the device: Junos: 'file show /etc/ssh/ssh_host_ed25519_key.pub'"
    refute_output --partial "hostkey-unpinned"
    run cat "${TACCTL_VAR_LIB}/ssh/known_hosts"
    assert_output "# Generated by tacctl from devices.yaml on every registry change; do not edit.
# ssh reads it with: -o UserKnownHostsFile=<this file> -o HostKeyAlias=<name> -o StrictHostKeyChecking=yes
x $(key ed25519)
x $(key rsa)"
    run stat -c %a "${TACCTL_VAR_LIB}/ssh/known_hosts" "${TACCTL_VAR_LIB}/ssh" "$TACCTL_VAR_LIB"
    assert_output "644
755
711"
    run grep -c "host_keys: \[$(key ed25519), $(key rsa)\]" "$DEVICES"
    assert_output "1"
}

@test "device add: a --host-key the device does not offer is refused and nothing is written" {
    offer ed25519 rsa
    run "$TACCTL_BIN_SCRIPT" device add x 192.0.2.1 --host-key "$(fp ecdsa)"
    assert_failure 1
    plain
    assert_output --partial "No host key 192.0.2.1 offers matches $(fp ecdsa); nothing was registered."
    assert_output --partial "ED25519  $(fp ed25519)"
    [[ ! -e "$DEVICES" ]]
    [[ ! -e "${TACCTL_VAR_LIB}/ssh/known_hosts" ]]
    [[ "$(snapshot_count)" == 0 ]]
    # The matching one pins that key alone.
    run "$TACCTL_BIN_SCRIPT" device add x 192.0.2.1 --host-key "$(fp rsa)"
    assert_success
    plain
    assert_output --partial "Host key pinned (it matches --host-key):"
    assert_output --partial "Also offered, not pinned (unverified)"
    run grep -c '^x ' "${TACCTL_VAR_LIB}/ssh/known_hosts"
    assert_output "1"
}

@test "device add: a device that does not answer is refused unless --no-host-key" {
    run "$TACCTL_BIN_SCRIPT" device add x 192.0.2.1 --port 2222
    assert_failure 1
    plain
    assert_output --partial "No ssh host key could be read from 192.0.2.1 port 2222 (ssh-keyscan); nothing was changed."
    assert_output --partial "register it without a pinned key: tacctl device add x 192.0.2.1 --port 2222 --no-host-key"
    [[ ! -e "$DEVICES" ]]
    stub_cmd ssh-keyscan
    run "$TACCTL_BIN_SCRIPT" device add x 192.0.2.1 --no-host-key
    assert_success
    plain
    assert_output --partial "hostkey-unpinned: no host key is pinned for 'x'"
    assert_output --partial "'tacctl device hostkey x accept'"
    run stub_called "ssh-keyscan"
    assert_failure
    run cat "${TACCTL_VAR_LIB}/ssh/known_hosts"
    refute_output --partial "x "
}

@test "device add --legacy-ssh asks for ssh-rsa by name" {
    offer rsa
    run "$TACCTL_BIN_SCRIPT" device add old-ios 192.0.2.4 --vendor cisco --legacy-ssh --port 830
    assert_success
    stub_called "ssh-keyscan -T 5 -p 830 -t ed25519,ecdsa,rsa,ssh-rsa 192.0.2.4"
}

@test "device hostkey: show, accept (confirms), set" {
    "$TACCTL_BIN_SCRIPT" device add core-sw1 10.99.0.1 --vendor cisco --no-host-key
    run "$TACCTL_BIN_SCRIPT" device hostkey core-sw1
    assert_success
    plain
    assert_output --partial "No host key is pinned for 'core-sw1'."
    offer ed25519 ecdsa
    run "$TACCTL_BIN_SCRIPT" device hostkey core-sw1 accept < /dev/null
    assert_success
    plain
    assert_output --partial "Aborted; the pin was not changed."
    run grep -c host_keys "$DEVICES"
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" device hostkey core-sw1 accept -y
    assert_success
    plain
    assert_output --partial "Pinned 2 host key(s) for 'core-sw1'."
    stub_called "logger -t tacctl -p auth.info device hostkey accept name=core-sw1 keys=2 by="
    run "$TACCTL_BIN_SCRIPT" device hostkey core-sw1 set "$(fp ecdsa)"
    assert_success
    run "$TACCTL_BIN_SCRIPT" device hostkey core-sw1 show
    plain
    assert_output --partial "ECDSA    $(fp ecdsa)"
    assert_output --partial "$(key ecdsa)"
    refute_output --partial "ED25519"
    run "$TACCTL_BIN_SCRIPT" device hostkey core-sw1 set "$(fp rsa)"
    assert_failure 1
    plain
    assert_output --partial "the pin was not changed"
    run cat "${TACCTL_VAR_LIB}/ssh/known_hosts"
    assert_output --partial "core-sw1 $(key ecdsa)"
    refute_output --partial "ssh-ed25519"
}

# hostpub <name>...: the host's 'cat /etc/ssh/ssh_host_*_key.pub', read over
# the enrolment session, prints these keys (none: nothing, exit 1).
hostpub() {
    local lines="" k
    for k in "$@"; do
        lines+="echo \"$(key "$k") root@web1\"; "
    done
    [[ -n "$lines" ]] || lines="exit 1"
    stub_cmd ssh 'case "$*" in *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;; *"cat /etc/ssh/ssh_host_*_key.pub") '"${lines}"' ;; esac'
}

host_setup() {
    export PUSHED="${BATS_TEST_TMPDIR}/pushed" TACCTL_LINUX_DIR="${BATS_TEST_TMPDIR}/linux"
    mkdir -p "$TACCTL_LINUX_DIR"
    echo "not really a tarball" > "$TACCTL_LINUX_DIR/pam_tacplus-1.7.0.tar.gz"
    stub_cmd getent 'echo "192.0.2.50 STREAM web1"'
    stub_cmd ip 'echo "192.0.2.50 dev eth0 src 192.0.2.1 uid 0"'
}

@test "host enroll and sync pin the keys the session and the scan agree on, once; a changed key is reported, not pinned" {
    host_setup
    hostpub ed25519 rsa
    offer ed25519 ecdsa
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab --build-on-host
    assert_success
    plain
    stub_called "ssh .* -T admin@web1.example.net cat /etc/ssh/ssh_host_\\*_key.pub$"
    stub_called "ssh-keyscan -T 5 -p 22 -t ed25519,ecdsa,rsa web1.example.net"
    assert_output --partial "web1: pinned 1 ssh host key(s) for 'tacctl ssh': ED25519 $(fp ed25519)"
    assert_output --partial "web1: not offered to ssh-keyscan, not pinned: RSA $(fp rsa)"
    assert_output --partial "web1: offered but not among the host's key files, not pinned: ECDSA $(fp ecdsa)"
    run grep -c "^web1 " "${TACCTL_VAR_LIB}/ssh/known_hosts"
    assert_output "1"
    run grep -c "^web1 $(key ed25519)$" "${TACCTL_VAR_LIB}/ssh/known_hosts"
    assert_output "1"
    # sync: the session's keys against the pin, never re-pinned.
    hostpub ecdsa
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_success
    plain
    assert_output --partial "web1: the ssh host key differs from the one pinned; the pin was not changed."
    run grep -c "^web1 $(key ed25519)$" "${TACCTL_VAR_LIB}/ssh/known_hosts"
    assert_output "1"
    run "$TACCTL_BIN_SCRIPT" host unenroll web1
    assert_success
    run grep -c "^web1 " "${TACCTL_VAR_LIB}/ssh/known_hosts"
    assert_output "0"
}

@test "host enroll pins nothing when the session's key files cannot be read; the enrolment succeeds" {
    host_setup
    hostpub
    offer ed25519
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab --build-on-host
    assert_success
    plain
    assert_output --partial "web1: the host's ssh keys could not be read over the enrolment session"
    assert_output --partial "tacctl device hostkey web1 accept"
    run stub_called "ssh-keyscan"
    assert_failure
    run grep -c "host_keys" "$DEVICES"
    assert_failure
}

# hostfacts <address> [login.defs lines]: the session's facts read prints
# sshd's SSH_CONNECTION with <address> as the host's side, and login.defs.
hostfacts() {
    echo "ssh_connection=198.51.100.9 50022 $1 22" > "${BATS_TEST_TMPDIR}/facts"
    if [[ -n "${2:-}" ]]; then printf 'login_defs=present\n%b\n' "$2" >> "${BATS_TEST_TMPDIR}/facts"; fi
    stub_cmd ssh 'case "$*" in *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *SSH_CONNECTION*) cat "'"${BATS_TEST_TMPDIR}"'/facts" ;; esac'
}

@test "host enroll and sync record the address the session reached; a changed one raises address-changed" {
    host_setup
    hostfacts 192.0.2.50 'UID_MIN 1000\nUID_MAX 60000'
    run "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab --build-on-host
    assert_success
    plain
    stub_called "ssh .* -T admin@web1.example.net printf"
    assert_output --partial "web1: local useradd there gives out UIDs 1000-60000 (/etc/login.defs UID_MIN/UID_MAX), which overlaps tacctl's 20000-29999:"
    assert_output --partial "Set 'UID_MAX 19999' in /etc/login.defs on web1 (tacctl does not change it)."
    run grep -c "useradd there" <<< "$output"
    assert_output "1"
    run grep -A1 "^  web1:" "$DEVICES"
    assert_output --partial "web1: {address: 192.0.2.50}"
    # The registry holds it: refused to device add, found by it, not discovered.
    run "$TACCTL_BIN_SCRIPT" device add web9 192.0.2.50 --no-host-key
    assert_failure 1
    assert_output --partial "192.0.2.50 belongs to the enrolled host 'web1'."
    run "$TACCTL_BIN_SCRIPT" device show 192.0.2.50
    assert_success
    assert_output --partial "Enrolled host web1"
    # A sync that reaches another address records it, and says so.
    hostfacts 192.0.2.51 'UID_MAX 19999'
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_success
    plain
    assert_output --partial "web1: the enrolment session reached 192.0.2.51, but 'web1.example.net' resolves to 192.0.2.50; recorded 192.0.2.51"
    assert_output --partial "web1: its address changed from 192.0.2.50 to 192.0.2.51; recorded 192.0.2.51 (notice address-changed: tacctl device show web1)."
    refute_output --partial "useradd there"
    stub_called "logger -t tacctl -p auth.warning host address-changed name=web1 old=192.0.2.50 new=192.0.2.51 by="
    run "$TACCTL_BIN_SCRIPT" device notices
    assert_output --partial "web1  address-changed: the address of 'web1' changed from 192.0.2.50 to 192.0.2.51"
    run "$TACCTL_BIN_SCRIPT" device notice web1 ack address-changed
    assert_success
    assert_output --partial "Notice 'address-changed' of 'web1' acknowledged."
    run "$TACCTL_BIN_SCRIPT" device notices
    refute_output --partial "address-changed"
    run "$TACCTL_BIN_SCRIPT" host unenroll web1
    assert_success
    run grep -c "web1" "$DEVICES"
    assert_output "0"
}

# targetssh <root|sudo|sudo-password> <key>...: the test connection of
# 'host target' answers how it reaches root and prints these host keys; the
# facts are hostfacts' file.
targetssh() {
    local root="$1" lines="" k; shift
    for k in "$@"; do lines+="echo \"$(key "$k") root@web1\"; "; done
    [[ -n "$lines" ]] || lines="exit 1"
    stub_cmd ssh 'case "$*" in *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *"sudo -n true"*) echo '"$root"' ;;
        *"cat /etc/ssh/ssh_host_*_key.pub") '"${lines}"' ;;
        *SSH_CONNECTION*) cat "'"${BATS_TEST_TMPDIR}"'/facts" ;; esac'
}

@test "host target: shows the target; a change is tested (login, root, keys against the pin) before it is written" {
    host_setup
    hostfacts 192.0.2.50
    targetssh root ed25519
    offer ed25519
    "$TACCTL_BIN_SCRIPT" host enroll admin@web1.example.net --scope lab --build-on-host > /dev/null
    run "$TACCTL_BIN_SCRIPT" host target web1
    assert_success
    assert_output --partial "Target:       admin@web1.example.net"
    assert_output --partial "Address:      192.0.2.50"
    before=$(cat "$TACCTL_STATE_DIR/linux-hosts")
    # Refused: a tacctl user as the login, sudo with a password and no
    # terminal, other keys, a --local host.
    "$TACCTL_BIN_SCRIPT" user add opx operator --hash "24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" --scopes lab > /dev/null
    run "$TACCTL_BIN_SCRIPT" host target web1 opx@web1.example.net
    assert_failure 1
    assert_output --partial "The provisioning account 'opx' (the ssh login for opx@web1.example.net) is a tacctl user."
    targetssh sudo-password ed25519
    run "$TACCTL_BIN_SCRIPT" host target web1 admin@web1b.example.net < /dev/null
    assert_failure 1
    assert_output --partial "sudo there needs a password (or the login may not sudo)"
    targetssh root rsa
    run "$TACCTL_BIN_SCRIPT" host target web1 admin@web1b.example.net
    assert_failure 1
    assert_output --partial "The host reached is not 'web1' as pinned: its ssh keys differ; nothing was changed."
    assert_output --partial "On the host: RSA $(fp rsa)"
    [[ "$(cat "$TACCTL_STATE_DIR/linux-hosts")" == "$before" ]]
    # Accepted: written in place, logged, the address it reached recorded.
    hostfacts 192.0.2.60
    targetssh sudo ed25519
    run "$TACCTL_BIN_SCRIPT" host target web1 root@web1b.example.net --port 2200
    assert_success
    plain
    assert_output --partial "Host 'web1' is now reached at root@web1b.example.net port 2200 (scope, server and method unchanged)."
    assert_output --partial "web1: its address changed from 192.0.2.50 to 192.0.2.60"
    stub_called "logger -t tacctl -p auth.info host target name=web1 target=root@web1b.example.net port=2200 by="
    run cat "$TACCTL_STATE_DIR/linux-hosts"
    assert_output "web1|root@web1b.example.net|2200|lab|192.0.2.1|"
    # A tier user may not.
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=opx run "$TACCTL_BIN_SCRIPT" host target web1
    assert_failure
    assert_output --partial "not permitted"
}

@test "host target: a host enrolled with --local has no target to change" {
    host_setup
    echo "authsrv|local||lab|127.0.0.1|" > "$TACCTL_STATE_DIR/linux-hosts"
    run "$TACCTL_BIN_SCRIPT" host target authsrv
    assert_success
    assert_output --partial "Target:       local"
    run "$TACCTL_BIN_SCRIPT" host target authsrv root@x
    assert_failure 1
    assert_output --partial "'authsrv' is this server (enrolled with --local)"
}
