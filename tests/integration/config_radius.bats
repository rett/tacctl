#!/usr/bin/env bats
# `tacctl config cisco|juniper|wti --protocol radius`: goldens for the lab
# scope, the unchanged default (TACACS+) output, the refusals (backend not
# enabled, scope not served over RADIUS, the vendor's attribute not sent, a
# secret that cannot be pasted), warnings, listener-derived ports and address,
# the WTI walkthrough, and operator template overrides. Set UPDATE_GOLDEN=1 to
# regenerate the goldens.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

bats_require_minimum_version 1.5.0

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    # Freeze server-IP discovery so rendered output is deterministic.
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'

    # The setup and set_vendors change the store through the CLI, which
    # renders and may restart (systemctl is stubbed): no settling pause.
    export TACCTL_SETTLE_SECONDS=0

    load_fixture tacquito.multiscope.yaml
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    # Every scope sends every vendor's attribute (the opt-in tests below take
    # it away again).
    local s
    for s in dmz lab prod prod-inner; do
        "$TACCTL_BIN_SCRIPT" scope vendor-attrs "$s" enable cisco,juniper,wti > /dev/null
    done
}

# A scope's vendor attributes in the store: set_vendors <scope> <csv|null>
# (call it before radius_on: with the backend enabled it would render it).
set_vendors() {
    "$TACCTL_BIN_SCRIPT" scope vendor-attrs "$1" disable cisco,juniper,wti > /dev/null
    if [[ "$2" != null ]]; then
        "$TACCTL_BIN_SCRIPT" scope vendor-attrs "$1" enable "$2" > /dev/null
    fi
}

# Same normalisation as config_templates.bats.
_normalize() {
    sed -E 's/\x1b\[[0-9;]*m//g' \
        | sed -E 's/^hostname .*/hostname TACQUITO-HOSTNAME/' \
        | awk '{
            p = "Using template: " ENVIRON["TACCTL_SRC"] "/config/templates/"
            i = index($0, p)
            if (i) $0 = substr($0, 1, i - 1) "Using template: built-in " substr($0, i + length(p))
            print
        }'
}

# The 'Using template:' note of a shipped template: its embedded copy.
shipped_template_note() {
    echo "Using template: built-in $1.template"
}

# Enable the RADIUS backend the way tacctl.yaml records it. Call it after the
# store mutations of a test: with the backend enabled they would render it.
radius_on() {
    printf 'backends:\n  enabled: [tacacs, radius]\n' >> "$OVERRIDES"
}

# Listener overrides for tacctl.yaml (no daemon is involved in rendering a
# device config). $1 = auth address, $2 = acct address, $3 = network.
radius_listeners() {
    local net="${3:-udp}"
    printf 'listeners:\n  radius:\n    auth: {network: %s, address: "%s", role: auth}\n    acct: {network: %s, address: "%s", role: acct}\n' \
        "$net" "$1" "$net" "$2" >> "$OVERRIDES"
}

# --- goldens -----------------------------------------------------------------

@test "config cisco --protocol radius: renders deterministic IOS config for the lab scope" {
    radius_on
    local out="$BATS_TEST_TMPDIR/cisco-radius.conf"
    "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "cisco-radius-lab.conf"
}

@test "config juniper --protocol radius: renders deterministic Junos config for the lab scope" {
    radius_on
    local out="$BATS_TEST_TMPDIR/juniper-radius.conf"
    "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "juniper-radius-lab.conf"
}

# --- the default protocol is untouched ----------------------------------------

@test "config cisco|juniper|wti: --protocol tacacs is the same output as no flag, and the backend need not be enabled" {
    local v a b
    for v in cisco juniper wti; do
        a=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab)
        b=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol tacacs)
        [[ -n "$a" && "$a" == "$b" ]]
    done
    a=$("$TACCTL_BIN_SCRIPT" config cisco --scope lab --legacy)
    b=$("$TACCTL_BIN_SCRIPT" config cisco --protocol tacacs --legacy --scope lab)
    [[ -n "$a" && "$a" == "$b" ]]
}

@test "config cisco|juniper: the default output does not change when the RADIUS backend is enabled" {
    local before_c before_j
    before_c=$("$TACCTL_BIN_SCRIPT" config cisco --scope lab)
    before_j=$("$TACCTL_BIN_SCRIPT" config juniper --scope lab)
    radius_on
    [[ "$("$TACCTL_BIN_SCRIPT" config cisco --scope lab)" == "$before_c" ]]
    [[ "$("$TACCTL_BIN_SCRIPT" config juniper --scope lab)" == "$before_j" ]]
}

# --- Cisco content ------------------------------------------------------------

@test "config cisco --protocol radius: server block, group, method lists, exec accounting" {
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "radius server RADIUS"
    assert_output --partial "address ipv4 10.0.0.42 auth-port 1812 acct-port 1813"
    assert_output --partial "key lab-secret-0123456789abcdef"
    assert_output --partial "aaa group server radius RADIUS-GROUP"
    assert_output --partial "aaa authentication login default group RADIUS-GROUP local"
    assert_output --partial "aaa authorization exec default group RADIUS-GROUP local if-authenticated"
    assert_output --partial "aaa accounting exec default start-stop group RADIUS-GROUP"
    assert_output --partial "$(shipped_template_note cisco-radius)"
}

@test "config cisco --protocol radius: nothing RADIUS cannot do is configured" {
    radius_on
    # The fixture's groups carry command rules: TACACS+ would emit per-command authorization.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_output --partial "aaa authorization commands 15"
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    refute_output --partial "aaa authorization commands"
    refute_output --partial "aaa accounting commands"
    refute_output --partial "tacacs"
    refute_output --partial "TACACS-GROUP"
    refute_output --partial "single-connection"
}

@test "config cisco --protocol radius: the summary says what RADIUS loses, not the config" {
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    local cfg summary
    cfg="${output%%Group → Privilege Level Mapping*}"
    summary="${output#*Group → Privilege Level Mapping}"
    [[ "$summary" == *"What RADIUS does not give you (compared with TACACS+)"* ]]
    [[ "$summary" == *"What an Access-Accept carries for this device:"* ]]
    [[ "$summary" == *"Service-Type: Administrative-User at privilege 15, else NAS-Prompt-User (always sent)"* ]]
    [[ "$summary" == *'Cisco-AVPair "shell:priv-lvl=N" from the user'"'"'s group: the scope enables it (tacctl scope vendor-attrs lab)'* ]]
    [[ "$summary" == *"No other vendor's attribute. A reject carries none"* ]]
    [[ "$summary" == *"No per-command authorization"* ]]
    [[ "$summary" == *"shell:priv-lvl=N"* ]]
    [[ "$summary" == *"No command accounting"* ]]
    [[ "$summary" == *"Password logins only (PAP)"* ]]
    [[ "$summary" == *"allow UDP 1812 (authentication) and 1813 (accounting)"* ]]
    [[ "$cfg" != *"does not give you"* ]]
    [[ "$cfg" != *"per-command"* ]]
}

@test "config cisco --protocol radius: aaa-order local-first, exec-timeout and the group label follow the scope" {
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 15 > /dev/null
    "$TACCTL_BIN_SCRIPT" scope radius-group lab RADIUS_LAB > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "aaa authentication login default local group RADIUS_LAB"
    assert_output --partial "aaa authorization exec default local group RADIUS_LAB if-authenticated"
    assert_output --partial "aaa accounting exec default start-stop group RADIUS_LAB"
    assert_output --partial "aaa group server radius RADIUS_LAB"
    refute_output --partial "RADIUS-GROUP"
    run bash -c '"'"$TACCTL_BIN_SCRIPT"'" config cisco --scope lab --protocol radius | grep -c "^  exec-timeout 15 0$"'
    [[ "$output" == "2" ]]
    # The TACACS+ label is separate.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_output --partial "aaa group server tacacs+ TACACS-GROUP"
}

@test "config cisco --protocol radius: the management ACL and privilege mappings are rendered as for TACACS+" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "ip access-list standard VTY-ACL"
    assert_output --partial "permit 10.0.0.0 0.255.255.255"
    assert_output --partial "  access-class VTY-ACL in"
    assert_output --partial "privilege exec level 7 show running-config"
}

@test "config cisco --protocol radius --legacy: refused, legacy syntax is TACACS+ only" {
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius --legacy
    assert_failure
    assert_output --partial "--legacy"
    assert_output --partial "TACACS+ only"
    refute_output --partial "address ipv4"
}

# --- Juniper content ----------------------------------------------------------

@test "config juniper --protocol radius: server, order, accounting, template users, local class rules" {
    radius_on
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius
    assert_success
    assert_output --partial "set system radius-server 10.0.0.42 port 1812"
    assert_output --partial "set system radius-server 10.0.0.42 accounting-port 1813"
    assert_output --partial "set system radius-server 10.0.0.42 secret lab-secret-0123456789abcdef"
    assert_output --partial "set system authentication-order radius"
    assert_output --partial "set system accounting destination radius"
    assert_output --partial "set system login user RW-CLASS class RW-CLASS"
    # The class is local to the device: the allow/deny rules stay meaningful.
    assert_output --partial 'set system login class RO-CLASS allow-commands "^(show|ping|traceroute)( .*)?$"'
    assert_output --partial "enforced LOCALLY by Junos on the class, not by the RADIUS server"
    assert_output --partial "show configuration system radius-server"
    local cfg="${output%%Group → Juniper Class Mapping*}"
    [[ "$cfg" != *tacplus* && "$cfg" != *TACACS* ]]
    assert_output --partial "$(shipped_template_note juniper-radius)"
}

@test "config juniper --protocol radius: the summary says what RADIUS loses and that the class rules stay" {
    radius_on
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius
    assert_success
    assert_output --partial "What RADIUS does not give you (compared with TACACS+)"
    assert_output --partial "Juniper-Local-User-Name"
    assert_output --partial "the allow-commands/deny-commands"
    assert_output --partial "No command accounting"
    assert_output --partial "Password logins only (PAP)"
}

@test "config juniper --protocol radius: aaa-order local-first and exec-timeout follow the scope" {
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 15 > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius
    assert_success
    assert_output --partial "set system authentication-order [ password radius ]"
    assert_output --partial "set system login idle-timeout 15"
}

@test "config juniper --protocol radius: the lo0 filter is built from the management ACL" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius
    assert_success
    assert_output --partial "set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 10.0.0.0/8"
}

# --- ports and address from the listeners -----------------------------------------

@test "config cisco|juniper --protocol radius: ports come from the RADIUS listeners" {
    radius_listeners ":1645" ":1646"
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "address ipv4 10.0.0.42 auth-port 1645 acct-port 1646"
    assert_output --partial "allow UDP 1645 (authentication) and 1646 (accounting)"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius
    assert_success
    assert_output --partial "set system radius-server 10.0.0.42 port 1645"
    assert_output --partial "set system radius-server 10.0.0.42 accounting-port 1646"
}

@test "config cisco|juniper --protocol radius: a listener bound to one IPv4 address is the server address" {
    radius_listeners "10.0.0.77:1812" ":1813"
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "address ipv4 10.0.0.77 auth-port 1812 acct-port 1813"
    refute_output --partial "10.0.0.42"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius
    assert_success
    assert_output --partial "set system radius-server 10.0.0.77 secret"
}

@test "config cisco --protocol radius: listeners bound to different addresses, to loopback, or to IPv6 are warned about" {
    radius_listeners "10.0.0.77:1812" "10.0.0.78:1813"
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "bound to different addresses (10.0.0.77, 10.0.0.78)"
    assert_output --partial "address ipv4 10.0.0.77 "
    rm -f "$OVERRIDES"
    radius_listeners "127.0.0.1:1812" "127.0.0.1:1813"
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "listener is bound to 127.0.0.1: no device can reach it"
    rm -f "$OVERRIDES"
    radius_listeners "[::]:1812" "[::]:1813" udp6
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "IPv6 listener(s): auth (udp6 [::]:1812), acct (udp6 [::]:1813)"
}

# --- refusals ---------------------------------------------------------------------

@test "config cisco|juniper --protocol radius: refused, with no config, when the RADIUS backend is not enabled" {
    local v
    for v in cisco juniper; do
        run --separate-stderr "$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol radius
        assert_failure
        [[ -z "$output" ]]
        [[ "$stderr" == *"RADIUS backend is not enabled"* ]]
        [[ "$stderr" == *"tacctl backend enable radius"* ]]
    done
}

@test "config cisco|juniper --protocol radius: refused, with no config, for a scope whose protocols leave RADIUS out" {
    "$TACCTL_BIN_SCRIPT" scope protocols lab set tacacs > /dev/null
    radius_on
    local v
    for v in cisco juniper; do
        run --separate-stderr "$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol radius
        assert_failure
        [[ -z "$output" ]]
        [[ "$stderr" == *"Scope 'lab' is limited to tacacs"* ]]
        [[ "$stderr" == *"ignores its devices"* ]]
        [[ "$stderr" == *"tacctl scope protocols lab set tacacs,radius"* ]]
    done
    # Another scope, and the scope once it lists radius, render.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope prod --protocol radius
    assert_success
}

@test "config cisco --protocol radius: a scope listing radius among its protocols renders" {
    "$TACCTL_BIN_SCRIPT" scope protocols lab set radius > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "radius server RADIUS"
    # TACACS+ output is not gated by the filter (unchanged behaviour).
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
}

@test "config cisco|juniper --protocol radius: a secret a device CLI would read as syntax is refused, never printed" {
    local v secret
    # Each is long and mixed enough for 'scope secret set', and breaks a paste differently.
    local -a bad=(
        'has space in the secret-0123'
        'quote"inside-the-secret-0123'
        "apostrophe'in-the-secret-0123"
        'question?mark-in-secret-0123'
        'dollar$in-the-secret-0123456'
        'back\slash-in-the-secret-012'
        'hash#in-the-secret-012345678'
        'semi;colon-in-the-secret-012'
        'bang!in-the-secret-012345678'
        'caf'$'\303\251''-in-the-secret-0123456'
    )
    for secret in "${bad[@]}"; do
        "$TACCTL_BIN_SCRIPT" scope secret lab set "$secret" > /dev/null
        radius_on
        for v in cisco juniper; do
            run --separate-stderr "$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol radius
            assert_failure
            [[ -z "$output" ]]
            [[ "$stderr" == *"cannot be pasted into a device configuration"* ]]
            [[ "$stderr" == *"tacctl scope secret lab generate"* ]]
            [[ "$stderr" != *"in-the-secret"* ]]
        done
        rm -f "$OVERRIDES"
    done
}

@test "config cisco|juniper --protocol radius: a secret of letters, digits and . _ + / = : @ % ^ ~ - is printed as it is" {
    local secret='aB3.d_f+h/j=l:n@p%r^t~v-xyz0123456789'
    "$TACCTL_BIN_SCRIPT" scope secret lab set "$secret" > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_line "  key ${secret}"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius
    assert_success
    assert_line "set system radius-server 10.0.0.42 secret ${secret}"
    # What 'scope secret generate' makes (base64) is inside the set.
    "$TACCTL_BIN_SCRIPT" scope secret lab generate > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
}

@test "config cisco|juniper --protocol radius: the same unsafe secret still renders for TACACS+, unchanged" {
    "$TACCTL_BIN_SCRIPT" scope secret lab set 'has space in the secret-0123' > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "key has space in the secret-0123"
}

@test "config cisco --protocol radius: a secret longer than the backend's advice renders with a warning" {
    local secret
    secret=$(printf 'abcdefghij%.0s' 1 2 3 4 5 6 7)   # 70 characters
    "$TACCTL_BIN_SCRIPT" scope secret lab set "${secret}A" > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "key ${secret}A"
    assert_output --partial "Warnings:"
    assert_output --partial "The secret is 71 characters; some RADIUS clients take no more than 63"
    # A 32-character secret raises none.
    "$TACCTL_BIN_SCRIPT" scope secret lab generate > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    refute_output --partial "Warnings:"
}

# --- arguments --------------------------------------------------------------------

@test "config cisco|juniper|wti: --protocol needs a known value" {
    local v
    for v in cisco juniper wti; do
        run "$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol ldap
        assert_failure
        assert_output --partial "Unknown protocol 'ldap'"
        assert_output --partial "tacacs, radius"
        run "$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol
        assert_failure
        assert_output --partial "--protocol tacacs"
    done
}

# --- vendor attributes: the scope must send the vendor's ------------------------------

@test "config cisco|juniper|wti --protocol radius: refused, with the command that enables it, when the scope sends that vendor nothing" {
    set_vendors lab null
    radius_on
    local v label
    for v in cisco juniper wti; do
        case "$v" in cisco) label=Cisco ;; juniper) label=Juniper ;; wti) label=WTI ;; esac
        run --separate-stderr "$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol radius
        assert_failure
        [[ -z "$output" ]]
        [[ "$stderr" == *"Scope 'lab' sends no ${label} attribute over RADIUS"* ]]
        [[ "$stderr" == *"${v} is not enabled for the scope and no address of it is tagged ${v}"* ]]
        [[ "$stderr" == *"tacctl scope vendor-attrs lab enable ${v}"* ]]
        [[ "$stderr" == *"tacctl scope devices lab set <device-ip> ${v}"* ]]
    done
    # Another vendor's enablement does not count.
    set_vendors lab juniper,wti
    run --separate-stderr "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius
    assert_success
}

@test "config cisco --protocol radius: an address tagged with the vendor is enough, with a warning that only it gets the attribute" {
    set_vendors lab juniper
    "$TACCTL_BIN_SCRIPT" scope devices lab set 192.168.7.7/32 cisco > /dev/null
    "$TACCTL_BIN_SCRIPT" scope devices lab set 192.168.8.0/24 wti > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "Scope 'lab' does not enable the Cisco attribute; only its addresses tagged cisco get it: 192.168.7.7/32."
    assert_output --partial "tacctl scope vendor-attrs lab enable cisco"
    assert_output --partial "only to the addresses of the scope tagged cisco (tacctl scope devices lab)"
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol radius
    assert_success
    assert_output --partial "only its addresses tagged wti get it: 192.168.8.0/24."
}

@test "config cisco|juniper|wti: TACACS+ output does not depend on the vendor attributes" {
    local v a b
    for v in cisco juniper wti; do
        a=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab)
        set_vendors lab null
        b=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab)
        set_vendors lab cisco,juniper,wti
        [[ -n "$a" && "$a" == "$b" ]]
    done
}

# --- WTI over RADIUS ---------------------------------------------------------------

@test "config wti --protocol radius: renders the deterministic walkthrough for the lab scope" {
    radius_on
    local out="$BATS_TEST_TMPDIR/wti-radius.conf"
    "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol radius | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "wti-radius-lab.conf"
}

@test "config wti --protocol radius: says up front it is not verified on a unit, and where WTI's documents disagree" {
    radius_on
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol radius
    assert_success
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    [[ "$(grep -n 'NOT VERIFIED ON A UNIT' <<< "$output" | cut -d: -f1)" -lt "$(grep -n 'Step 1:' <<< "$output" | cut -d: -f1)" ]]
    assert_output --partial "Where WTI's documents disagree (not checked on a unit):"
    assert_output --partial "factory default User"
    assert_output --partial "says View only"
}

@test "config wti --protocol radius: the RADIUS menu with the scope's values, ports from the listeners, Fallback Local from aaa-order" {
    radius_listeners ':11812' ':11813'
    radius_on
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol radius
    assert_success
    assert_output --partial "29 [Enter]              RADIUS Parameters"
    assert_output --partial "Primary Host/Address (IPv4)   : 10.0.0.42"
    assert_output --partial "Primary Secret Word           : lab-secret-0123456789abcdef"
    assert_output --partial "Authentication Port           : 11812"
    assert_output --partial "Accounting Port               : 11813"
    assert_output --partial "Fallback Local                : On (Transport Failure)"
    assert_output --partial "Default RADIUS User Access    : Enable On, Access Level ViewOnly,"
    assert_output --partial "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    assert_output --partial "/UL clears it"
    # The TACACS+-only items are gone.
    refute_output --partial "Account Management Module"
    refute_output --partial "Service Name"
    refute_output --partial "patch 0002"
    refute_output --partial "tacquito"
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol radius
    assert_output --partial "Fallback Local                : On (All Failures)"
}

@test "config wti --protocol radius: the group to WTI-Super table follows the bands, and the server's auth log is how to see what the unit sends" {
    "$TACCTL_BIN_SCRIPT" group add wtisuper 12 OP-CLASS > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol radius
    assert_success
    assert_output --partial "superuser: priv-lvl 15 → WTI-Super 3 (Administrator)"
    assert_output --partial "operator: priv-lvl 7 → WTI-Super 1 (User)"
    assert_output --partial "readonly: priv-lvl 1 → WTI-Super 0 (ViewOnly)"
    assert_output --partial "wtisuper: priv-lvl 12 → WTI-Super 2 (SuperUser)"
    assert_output --partial "tacctl log tail 20 --backend radius"
    assert_output --partial "nas= -- what the unit sent as its"
    assert_output --partial "WTI-Super from the user's group: the scope enables it"
}

@test "config wti: without --protocol a scope that resolves to RADIUS gets the RADIUS walkthrough, like cisco and juniper" {
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    radius_on
    local a b
    a=$("$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol radius)
    run --separate-stderr "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    [[ -z "$stderr" ]]
    [[ "$output" == *"protocol: RADIUS — the scope's auth-method"* ]]
    b=$(sed "s/ — the scope's auth-method//" <<< "$output")
    [[ "$a" == "$b" ]]
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol tacacs
    assert_output --partial "TACACS Parameters"
}

# --- operator template overrides ---------------------------------------------------

@test "config cisco|juniper --protocol radius: an operator template in the state directory replaces the shipped one" {
    mkdir -p "${TACCTL_STATE_DIR}/templates"
    printf 'MY-CISCO %s\n' '${SERVER_IP} ${AUTH_PORT}/${ACCT_PORT} ${RADIUS_GROUP} ${SECRET} ${AUTHN_METHODS} ${EXEC_TIMEOUT}' \
        > "${TACCTL_STATE_DIR}/templates/cisco-radius.template"
    printf 'MY-JUNOS %s\n' '${SERVER_IP} ${RADIUS_CONFIG}' > "${TACCTL_STATE_DIR}/templates/juniper-radius.template"
    printf 'MY-WTI %s\n' '${SERVER_IP} ${SECRET} ${AUTH_PORT}/${ACCT_PORT} ${FALLBACK_LOCAL} ${SCOPE}' > "${TACCTL_STATE_DIR}/templates/wti-radius.template"
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "MY-CISCO 10.0.0.42 1812/1813 RADIUS-GROUP lab-secret-0123456789abcdef group RADIUS-GROUP local 60"
    assert_output --partial "Using template: ${TACCTL_STATE_DIR}/templates/cisco-radius.template"
    refute_output --partial "radius server RADIUS"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --protocol radius
    assert_success
    assert_output --partial "MY-JUNOS 10.0.0.42 delete system authentication-order"
    assert_output --partial "Using template: ${TACCTL_STATE_DIR}/templates/juniper-radius.template"
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol radius
    assert_success
    assert_output --partial "MY-WTI 10.0.0.42 lab-secret-0123456789abcdef 1812/1813 On (Transport Failure) lab"
    assert_output --partial "Using template: ${TACCTL_STATE_DIR}/templates/wti-radius.template"
    # The TACACS+ templates are not affected by (or used for) the override.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_output --partial "tacacs server TACACS"
    refute_output --partial "MY-CISCO"
}

# --- shipping -----------------------------------------------------------------------

@test "the RADIUS templates ship in config/templates, which the binary embeds" {
    [[ -f "${TACCTL_SRC}/config/templates/cisco-radius.template" ]]
    [[ -f "${TACCTL_SRC}/config/templates/juniper-radius.template" ]]
    [[ -f "${TACCTL_SRC}/config/templates/wti-radius.template" ]]
    # The binary carries config/templates/*.template (the set install and
    # upgrade keep in the state directory): a render with no override names
    # the embedded copy.
    grep -qxF '//go:embed config/templates/*.template' "${TACCTL_SRC}/assets.go"
    radius_on
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol radius
    assert_success
    assert_output --partial "$(shipped_template_note wti-radius)"
}

@test "scope show lists the RADIUS group label" {
    run "$TACCTL_BIN_SCRIPT" scope show lab
    assert_success
    assert_line --regexp 'RADIUS group:.* RADIUS-GROUP$'
}
