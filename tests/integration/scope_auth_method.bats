#!/usr/bin/env bats
# `tacctl scope auth-method <scope> [tacacs|radius|clear]`: the per-scope
# default protocol (scope_auth_method.<scope> in tacctl.yaml), how it stands
# against the scope's protocols filter, the rung after it (the one protocol
# a protocols filter names), what happens to it and to every other per-scope
# key of tacctl.yaml on rename and remove, and what it does to `config
# cisco|juniper|wti` without --protocol. The host side (host enroll, config
# linux script) is in host.bats and config_linux.bats.

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

    load_fixture tacquito.multiscope.yaml
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    # Every scope sends every vendor's attribute, so a RADIUS device config
    # renders (config_radius.bats has the refusal): one store write.
    bash -c 'source "$1"; store_mutate "for s in store[\"scopes\"].values(): s[\"vendor_attrs\"] = list(KNOWN_VENDORS)"' _ "$TACCTL_BIN_SCRIPT" > /dev/null
}

# Enable the RADIUS backend the way tacctl.yaml records it. Call it after the
# store mutations of a test: with the backend enabled they would render it.
radius_on() {
    printf 'backends:\n  enabled: [tacacs, radius]\n' >> "$OVERRIDES"
}

stored() { "$TACCTL_BIN_SCRIPT" config get "scope_auth_method.$1"; }

# --- the command ---------------------------------------------------------------

@test "scope auth-method: not set by default; says what is in effect" {
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab
    assert_success
    assert_output --partial "Scope 'lab' auth-method: not set"
    assert_output --partial "Source: default"
    assert_output --partial "In effect: devices: tacacs; hosts: tacacs"
    # One spelling in output: the protocol is tacacs, tacplus is a host method's name.
    refute_output --partial "tacplus"
    [[ -z "$(stored lab)" ]]
    [[ ! -f "$OVERRIDES" ]]
}

@test "scope auth-method: needs a scope that exists" {
    run "$TACCTL_BIN_SCRIPT" scope auth-method
    assert_failure
    assert_output --partial "Usage: tacctl scope auth-method <scope> [tacacs|radius|clear]"
    run "$TACCTL_BIN_SCRIPT" scope auth-method nosuchscope radius
    assert_failure
    assert_output --partial "does not exist"
}

@test "scope auth-method: set, read back with its source, shown by scope show, per scope" {
    radius_on
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab radius
    assert_success
    assert_output --partial "Scope 'lab' auth-method set to radius."
    refute_output --partial "not enabled"
    [[ "$(stored lab)" == "radius" ]]
    [[ -z "$(stored prod)" ]]

    run "$TACCTL_BIN_SCRIPT" scope auth-method lab
    assert_success
    assert_output --partial "Scope 'lab' auth-method: radius"
    assert_output --partial "Source: override (tacctl.yaml: scope_auth_method.lab)"
    run "$TACCTL_BIN_SCRIPT" scope show lab
    assert_line --regexp 'Auth method:.* radius$'
    run "$TACCTL_BIN_SCRIPT" scope show prod
    assert_line --regexp 'Auth method:.* not set \(devices: tacacs; hosts: tacacs\)$'

    run "$TACCTL_BIN_SCRIPT" scope auth-method lab radius
    assert_success
    assert_output --partial "already radius"
}

@test "scope auth-method: an explicit tacacs is stored, and tacplus is another name for it" {
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab tacacs
    assert_success
    [[ "$(stored lab)" == "tacacs" ]]
    run "$TACCTL_BIN_SCRIPT" scope auth-method prod tacplus
    assert_success
    assert_output --partial "Scope 'prod' auth-method set to tacacs."
    [[ "$(stored prod)" == "tacacs" ]]
}

@test "scope auth-method clear: removes the setting, as 'scope protocols clear' does; 'default' is taken for it" {
    "$TACCTL_BIN_SCRIPT" scope auth-method lab tacacs > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab clear
    assert_success
    assert_output --partial "Scope 'lab' auth-method cleared (in effect: devices: tacacs; hosts: tacacs)."
    [[ -z "$(stored lab)" ]]
    [[ ! -f "$OVERRIDES" ]]
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab clear
    assert_success
    assert_output --partial "no auth-method set; no change"
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab default
    assert_success
    assert_output --partial "auth-method cleared"
    [[ -z "$(stored lab)" ]]
    # Not advertised: the usage names clear only.
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab
    assert_output --partial "<tacacs|radius|clear>"
    refute_output --partial "|default"
}

@test "scope auth-method: without a setting, a scope its protocols filter limits to one protocol has that one in effect" {
    "$TACCTL_BIN_SCRIPT" scope protocols dmz set radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope auth-method dmz
    assert_output --partial "In effect: radius: the scope's only protocol"
    run "$TACCTL_BIN_SCRIPT" scope show dmz
    assert_line --regexp "Auth method:.* not set \(radius: the scope's only protocol\)$"
    "$TACCTL_BIN_SCRIPT" scope protocols dmz set tacacs,radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope auth-method dmz
    assert_output --partial "In effect: devices: tacacs; hosts: tacacs"
}

@test "scope auth-method: an unknown value is refused and nothing is stored" {
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab ldap
    assert_failure
    assert_output --partial "Unknown auth-method 'ldap'"
    [[ -z "$(stored lab)" ]]
    # The schema refuses it in a hand-edited tacctl.yaml too, and it reads as not set.
    printf 'scope_auth_method:\n  lab: ldap\n' > "$OVERRIDES"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_output --partial "scope_auth_method.lab"
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab
    assert_output --partial "auth-method: not set"
}

@test "scope auth-method: a backend that is not enabled is a warning, not a refusal" {
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab radius
    assert_success
    assert_output --partial "The radius backend is not enabled on this server: tacctl backend enable radius"
    [[ "$(stored lab)" == "radius" ]]
}

# --- against the protocols filter ----------------------------------------------

@test "scope auth-method: refused when the scope's protocols leave the protocol out" {
    "$TACCTL_BIN_SCRIPT" scope protocols lab set tacacs > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab radius
    assert_failure
    assert_output --partial "Scope 'lab' is limited to tacacs (tacctl scope protocols), so it is not served over radius."
    assert_output --partial "tacctl scope protocols lab set tacacs,radius"
    [[ -z "$(stored lab)" ]]
    run "$TACCTL_BIN_SCRIPT" scope auth-method lab tacacs
    assert_success

    "$TACCTL_BIN_SCRIPT" scope protocols dmz set radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope auth-method dmz tacacs
    assert_failure
    assert_output --partial "tacctl scope protocols dmz set radius,tacacs"
    run "$TACCTL_BIN_SCRIPT" scope auth-method dmz radius
    assert_success
}

@test "scope protocols set: refuses a list without the scope's auth-method; the store is unchanged" {
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    cp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/before.yaml"
    run "$TACCTL_BIN_SCRIPT" scope protocols lab set tacacs
    assert_failure
    assert_output --partial "Scope 'lab' has auth-method radius, which protocols 'tacacs' would leave unserved. Nothing was changed."
    assert_output --partial "tacctl scope auth-method lab <tacacs|radius|clear>"
    cmp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/before.yaml"

    # A list that keeps it, another scope, and the same list once the setting is gone.
    run "$TACCTL_BIN_SCRIPT" scope protocols lab set tacacs,radius
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz set tacacs
    assert_success
    "$TACCTL_BIN_SCRIPT" scope auth-method lab clear > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope protocols lab set tacacs
    assert_success
}

# --- rename and remove ------------------------------------------------------------

@test "scope rename: the auth-method follows the scope" {
    "$TACCTL_BIN_SCRIPT" scope auth-method dmz radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope rename dmz edge
    assert_success
    [[ "$(stored edge)" == "radius" ]]
    [[ -z "$(stored dmz)" ]]
    run "$TACCTL_BIN_SCRIPT" scope show edge
    assert_line --regexp 'Auth method:.* radius$'
}

@test "scope remove: the auth-method goes with the scope, so a new scope of that name has none" {
    "$TACCTL_BIN_SCRIPT" scope auth-method dmz radius > /dev/null
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove dmz --force'
    assert_success
    [[ -z "$(stored dmz)" ]]
    [[ ! -f "$OVERRIDES" ]]
    "$TACCTL_BIN_SCRIPT" scope add dmz --prefixes 198.18.7.0/24 --secret "dmz-secret-0123456789abcdef" > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope auth-method dmz
    assert_output --partial "auth-method: not set"
}

@test "scope prefixes clear: removing the scope that way drops its auth-method too" {
    "$TACCTL_BIN_SCRIPT" scope auth-method dmz tacacs > /dev/null
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope prefixes dmz clear --force'
    assert_success
    [[ -z "$(stored dmz)" ]]
}

@test "scope remove: a scope without an auth-method leaves tacctl.yaml byte-identical" {
    "$TACCTL_BIN_SCRIPT" scope auth-method lab tacacs > /dev/null
    printf '# a comment a rewrite would lose\n' >> "$OVERRIDES"
    cp "$OVERRIDES" "${BATS_TEST_TMPDIR}/before.yaml"
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove dmz --force'
    assert_success
    cmp "$OVERRIDES" "${BATS_TEST_TMPDIR}/before.yaml"
}

# --- every per-scope key of tacctl.yaml -------------------------------------------

# Set every key tacctl.yaml stores under a scope's name, for scope $1.
set_every_scope_key() {
    local s="$1"
    "$TACCTL_BIN_SCRIPT" scope aaa-order "$s" local-first > /dev/null
    "$TACCTL_BIN_SCRIPT" scope exec-timeout "$s" 15 > /dev/null
    "$TACCTL_BIN_SCRIPT" scope tacacs-group "$s" TG-X > /dev/null
    "$TACCTL_BIN_SCRIPT" scope radius-group "$s" RG-X > /dev/null
    "$TACCTL_BIN_SCRIPT" scope auth-method "$s" tacacs > /dev/null
    "$TACCTL_BIN_SCRIPT" scope mgmt-acl "$s" cisco-name CACL-X > /dev/null
    "$TACCTL_BIN_SCRIPT" scope mgmt-acl "$s" juniper-name JACL-X > /dev/null
    "$TACCTL_BIN_SCRIPT" scope mgmt-acl "$s" add 198.18.0.0/24 > /dev/null
}

# key=value for every per-scope key of scope $1 that tacctl.yaml holds.
scope_keys() {
    local k
    for k in aaa.order exec_timeout tacacs_group radius_group scope_auth_method \
             scope_mgmt_acl.names.cisco scope_mgmt_acl.names.juniper; do
        echo "${k}=$("$TACCTL_BIN_SCRIPT" config get "${k}.$1")"
    done
    echo "scope_mgmt_acl.permits=$("$TACCTL_BIN_SCRIPT" config get-list "scope_mgmt_acl.permits.$1" | paste -sd,)"
}

EVERY_KEY="aaa.order=local-first
exec_timeout=15
tacacs_group=TG-X
radius_group=RG-X
scope_auth_method=tacacs
scope_mgmt_acl.names.cisco=CACL-X
scope_mgmt_acl.names.juniper=JACL-X
scope_mgmt_acl.permits=198.18.0.0/24"

NO_KEY="aaa.order=
exec_timeout=
tacacs_group=
radius_group=
scope_auth_method=
scope_mgmt_acl.names.cisco=
scope_mgmt_acl.names.juniper=
scope_mgmt_acl.permits="

@test "scope rename: every per-scope key of tacctl.yaml moves to the new name" {
    set_every_scope_key dmz
    [[ "$(scope_keys dmz)" == "$EVERY_KEY" ]]
    run "$TACCTL_BIN_SCRIPT" scope rename dmz edge
    assert_success
    [[ "$(scope_keys edge)" == "$EVERY_KEY" ]]
    [[ "$(scope_keys dmz)" == "$NO_KEY" ]]
    ! grep -q 'dmz' "$OVERRIDES"
    # What the renamed scope's device config says.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope edge
    assert_output --partial "aaa group server tacacs+ TG-X"
    assert_output --partial "ip access-list standard CACL-X"
    assert_output --partial "exec-timeout 15 0"
}

@test "scope remove and prefixes clear: every per-scope key of tacctl.yaml goes, so a new scope of that name starts from the defaults" {
    set_every_scope_key dmz
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove dmz --force'
    assert_success
    [[ "$(scope_keys dmz)" == "$NO_KEY" ]]
    [[ ! -f "$OVERRIDES" ]]
    "$TACCTL_BIN_SCRIPT" scope add dmz --prefixes 198.18.7.0/24 --secret "dmz-secret-0123456789abcdef" > /dev/null
    [[ "$(scope_keys dmz)" == "$NO_KEY" ]]

    set_every_scope_key dmz
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope prefixes dmz clear --force'
    assert_success
    [[ "$(scope_keys dmz)" == "$NO_KEY" ]]
}

@test "scope rename: another scope's keys, and keys whose name only contains the scope's, are not touched" {
    set_every_scope_key lab
    "$TACCTL_BIN_SCRIPT" scope add lab2 --prefixes 198.18.9.0/24 --secret "lab2-secret-0123456789abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab2 5 > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope rename dmz edge
    assert_success
    [[ "$(scope_keys lab)" == "$EVERY_KEY" ]]
    [[ "$("$TACCTL_BIN_SCRIPT" config get exec_timeout.lab2)" == "5" ]]
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove lab2 --force'
    assert_success
    [[ "$(scope_keys lab)" == "$EVERY_KEY" ]]
}

# --- device configs ---------------------------------------------------------------

# The header names where the protocol came from; the rest must be what
# --protocol radius prints.
_strip_source() { sed "s/ — the scope's \(auth-method\|only protocol\)//"; }

@test "config cisco|juniper: an explicit auth-method tacacs is the output of a scope with none" {
    local v a b
    for v in cisco juniper wti; do
        a=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab)
        "$TACCTL_BIN_SCRIPT" scope auth-method lab tacacs > /dev/null
        b=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab)
        "$TACCTL_BIN_SCRIPT" scope auth-method lab clear > /dev/null
        [[ -n "$a" && "$a" == "$b" ]]
    done
}

@test "config cisco|juniper: without --protocol a radius scope gets the RADIUS configuration" {
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    radius_on
    local v a b
    for v in cisco juniper; do
        a=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol radius)
        b=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab)
        [[ "$b" == *"protocol: RADIUS — the scope's auth-method)"* ]]
        [[ "$a" != *"auth-method"* ]]
        [[ "$a" == "$(_strip_source <<< "$b")" ]]
    done
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_output --partial "radius server RADIUS"
    refute_output --partial "tacacs server TACACS"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_output --partial "set system radius-server 10.0.0.42 port 1812"
    # Another scope is untouched.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope prod
    assert_output --partial "tacacs server TACACS"
    refute_output --partial "RADIUS"
}

@test "config cisco|juniper: the default scope's auth-method applies without --scope" {
    "$TACCTL_BIN_SCRIPT" scope default lab > /dev/null
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco
    assert_success
    assert_output --partial "(scope: lab, protocol: RADIUS — the scope's auth-method)"
}

@test "config cisco|juniper: --protocol always wins over the scope's auth-method" {
    local v a b
    for v in cisco juniper; do
        a=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab)
        "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
        b=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol tacacs)
        "$TACCTL_BIN_SCRIPT" scope auth-method lab clear > /dev/null
        [[ -n "$a" && "$a" == "$b" ]]
    done
    "$TACCTL_BIN_SCRIPT" scope auth-method lab tacacs > /dev/null
    radius_on
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --protocol radius
    assert_success
    assert_output --partial "(scope: lab, protocol: RADIUS)"
}

@test "config cisco|juniper: a radius scope gets the RADIUS refusals without --protocol" {
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    local v
    for v in cisco juniper; do
        run --separate-stderr "$TACCTL_BIN_SCRIPT" config "$v" --scope lab
        assert_failure
        [[ -z "$output" ]]
        [[ "$stderr" == *"The RADIUS backend is not enabled"* ]]
    done
}

@test "config cisco --legacy: refused on a radius scope unless --protocol tacacs is given" {
    local a b
    a=$("$TACCTL_BIN_SCRIPT" config cisco --scope lab --legacy)
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    radius_on
    run --separate-stderr "$TACCTL_BIN_SCRIPT" config cisco --scope lab --legacy
    assert_failure
    [[ -z "$output" ]]
    [[ "$stderr" == *"Scope 'lab' has auth-method radius"* ]]
    [[ "$stderr" == *"tacctl config cisco --scope lab --legacy --protocol tacacs"* ]]
    b=$("$TACCTL_BIN_SCRIPT" config cisco --scope lab --legacy --protocol tacacs)
    [[ "$a" == "$b" ]]
}

@test "config wti: a radius scope gets the RADIUS walkthrough without --protocol, like cisco and juniper; --protocol tacacs is TACACS+" {
    local a
    a=$("$TACCTL_BIN_SCRIPT" config wti --scope lab 2> "${BATS_TEST_TMPDIR}/quiet")
    [[ ! -s "${BATS_TEST_TMPDIR}/quiet" ]]
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    radius_on
    run --separate-stderr "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    [[ -z "$stderr" ]]
    [[ "$output" == *"protocol: RADIUS — the scope's auth-method"* ]]
    [[ "$output" == *"RADIUS Parameters"* ]]
    run --separate-stderr "$TACCTL_BIN_SCRIPT" config wti --scope lab --protocol tacacs
    assert_success
    [[ "$output" == "$a" && -z "$stderr" ]]
}

# --- the scope's only protocol --------------------------------------------------------

@test "config cisco|juniper|wti: a scope its protocols filter limits to radius gets RADIUS without an auth-method" {
    "$TACCTL_BIN_SCRIPT" scope protocols lab set radius > /dev/null
    radius_on
    local v a b
    for v in cisco juniper wti; do
        a=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab --protocol radius)
        b=$("$TACCTL_BIN_SCRIPT" config "$v" --scope lab)
        [[ "$b" == *"protocol: RADIUS — the scope's only protocol"* ]]
        [[ "$a" == "$(_strip_source <<< "$b")" ]]
    done
    run --separate-stderr "$TACCTL_BIN_SCRIPT" config cisco --scope lab --legacy
    assert_failure
    [[ "$stderr" == *"Scope 'lab' is served over RADIUS only (tacctl scope protocols)"* ]]
}

@test "config cisco|juniper|wti: a filter naming tacacs alone, or both protocols, leaves the output as it was" {
    local v a b c
    for v in cisco juniper wti; do
        a=$("$TACCTL_BIN_SCRIPT" config "$v" --scope dmz)
        "$TACCTL_BIN_SCRIPT" scope protocols dmz set tacacs > /dev/null
        b=$("$TACCTL_BIN_SCRIPT" config "$v" --scope dmz)
        "$TACCTL_BIN_SCRIPT" scope protocols dmz set tacacs,radius > /dev/null
        c=$("$TACCTL_BIN_SCRIPT" config "$v" --scope dmz)
        "$TACCTL_BIN_SCRIPT" scope protocols dmz clear > /dev/null
        [[ -n "$a" && "$a" == "$b" && "$a" == "$c" ]]
    done
}
