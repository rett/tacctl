#!/usr/bin/env bats
# `tacctl scope vendor-attrs <scope> [enable|disable <vendor>,...]` and
# `tacctl scope devices <scope> [set <ip|cidr> <vendor>|unset <ip|cidr>]`:
# the RADIUS vendor attributes a scope opts into, and the addresses it tags
# with their vendor. The CLI, what the store keeps, the refusals (unknown
# vendor, set/clear/none, an address the scope does not answer for, a prefix
# change that would orphan a tag), rename and remove, scope show/list/lookup,
# and that TACACS+ is untouched. What the RADIUS backend renders from them is
# in tests/unit/render_radius.bats and tests/integration/radius.bats; what
# FreeRADIUS sends is in tests/containers/radius/.

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
    load_fixture tacquito.multiscope.yaml
    STORE="${TACCTL_STATE_DIR}/store.yaml"
}

tc() {
    run "$TACCTL_BIN_SCRIPT" "$@"
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# The scope's entry in store.yaml, as written.
entry() { sed -n "/^  $1:/,/^  [a-z]/p" "$STORE" | sed '$d'; }

# --- vendor-attrs ------------------------------------------------------------------

@test "vendor-attrs: a scope sends none until enabled, and says 'not sent'" {
    tc scope vendor-attrs lab
    assert_success
    assert_output --partial "Scope 'lab' vendor attributes: not sent"
    assert_output --partial 'cisco    Cisco-AVPair "shell:priv-lvl=<N>"'
    assert_output --partial "WTI-Super"
    refute_output --partial "none"
    run entry lab
    refute_output --partial "vendor_attrs"
    tc scope show lab
    assert_line --regexp '^  Vendor attributes: not sent '
}

@test "vendor-attrs enable|disable: stored in a fixed order, each once; disabling the last removes the field" {
    tc scope vendor-attrs lab enable wti,cisco
    assert_success
    assert_output --partial "Scope 'lab': vendor attributes enabled: cisco, wti. Now sent: cisco, wti."
    run entry lab
    assert_line "    vendor_attrs: [cisco, wti]"
    tc scope vendor-attrs lab enable juniper,cisco
    assert_output --partial "enabled: juniper. Now sent: cisco, juniper, wti."
    tc scope vendor-attrs lab enable cisco
    assert_success
    assert_output --partial "cisco already enabled"
    tc scope vendor-attrs lab disable cisco,wti
    assert_output --partial "disabled: cisco, wti. Now: juniper."
    tc scope vendor-attrs lab disable cisco
    assert_success
    assert_output --partial "not enabled; no change"
    tc scope vendor-attrs lab disable juniper
    assert_output --partial "Now: not sent."
    run entry lab
    refute_output --partial "vendor_attrs"
    tc scope vendor-attrs lab
    assert_output --partial "vendor attributes: not sent"
}

@test "vendor-attrs: an unknown vendor, a missing list, and the verbs of a filter are refused; nothing is written" {
    cp "$STORE" "${BATS_TEST_TMPDIR}/before"
    tc scope vendor-attrs lab enable cisco,arista
    assert_failure
    assert_output --partial "Unknown vendor 'arista'. Known vendors: cisco, juniper, wti"
    tc scope vendor-attrs lab enable
    assert_failure
    assert_output --partial "Usage: tacctl scope vendor-attrs lab enable <vendor>[,<vendor>...]"
    local verb
    for verb in set clear none; do
        tc scope vendor-attrs lab "$verb" cisco
        assert_failure
        assert_output --partial "Unknown subcommand: '${verb}'. The verbs are enable and disable"
    done
    tc scope vendor-attrs nosuch enable cisco
    assert_failure
    assert_output --partial "Scope 'nosuch' does not exist."
    cmp "$STORE" "${BATS_TEST_TMPDIR}/before"
}

@test "vendor-attrs: TACACS+ ignores them: tacquito.yaml is byte-identical and tacquito is not restarted" {
    local before
    # The fixture's tacquito.yaml becomes the rendered one first.
    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null 2>&1
    before=$(sha256sum < "$TACCTL_CONFIG")
    : > "$CALLS_LOG"
    tc scope vendor-attrs lab enable cisco,juniper,wti
    assert_success
    tc scope devices lab set 192.168.1.1 wti
    assert_success
    [[ "$(sha256sum < "$TACCTL_CONFIG")" == "$before" ]]
    ! stub_called '^systemctl restart'
    # Without the RADIUS backend the change is noted as having no effect yet.
    assert_output --partial "The RADIUS backend is not enabled on this server, so this has no effect yet"
}

@test "vendor-attrs: a scope that is not served over RADIUS says so" {
    tc scope protocols dmz set tacacs
    tc scope vendor-attrs dmz enable cisco
    assert_success
    assert_output --partial "Scope 'dmz' is limited to tacacs (tacctl scope protocols), so it is not served over RADIUS"
}

@test "scope add --vendor-attrs: enabled at creation, in the stored order; an unknown vendor creates nothing" {
    tc scope add edge --prefixes 198.18.0.0/24 --secret "edge-secret-0123456789abcdef" --vendor-attrs wti,juniper
    assert_success
    run entry edge
    assert_line "    vendor_attrs: [juniper, wti]"
    tc scope add edge2 --prefixes 198.18.1.0/24 --secret "edge-secret-0123456789abcdef" --vendor-attrs bogus
    assert_failure
    assert_output --partial "Unknown vendor 'bogus'"
    tc scope show edge2
    assert_failure
    tc scope add edge3 --prefixes 198.18.2.0/24 --vendor-attrs
    assert_failure
    assert_output --partial "--vendor-attrs needs a list of vendors"
}

# --- devices -----------------------------------------------------------------------

@test "devices set|unset: a bare address is a /32, stored on the scope; listed, shown, looked up" {
    tc scope devices lab set 192.168.10.20 cisco
    assert_success
    assert_output --partial "Scope 'lab': 192.168.10.20/32 tagged cisco: over RADIUS it gets that vendor's attribute only."
    tc scope devices lab set 172.16.5.0/24 juniper
    assert_success
    run entry lab
    assert_line "    devices: {172.16.5.0/24: juniper, 192.168.10.20/32: cisco}"
    tc scope devices lab
    assert_line --regexp '^  192\.168\.10\.20/32 +cisco$'
    assert_line --regexp '^  172\.16\.5\.0/24 +juniper$'
    tc scope show lab
    assert_line "    - 192.168.10.20/32  cisco"
    tc scope lookup 192.168.10.20
    assert_line "  Tagged cisco (scope devices entry 192.168.10.20/32): over RADIUS it gets that vendor's attribute only"
    tc scope lookup 172.16.5.9
    assert_output --partial "Tagged juniper (scope devices entry 172.16.5.0/24)"
    tc scope lookup 192.168.11.1
    refute_output --partial "Tagged"
    # Re-tag, then unset.
    tc scope devices lab set 192.168.10.20/32 wti
    assert_output --partial "now tagged wti (it was cisco)"
    tc scope devices lab unset 192.168.10.20
    assert_success
    assert_output --partial "192.168.10.20/32 is no longer tagged (it was wti)"
    tc scope devices lab unset 192.168.10.20
    assert_success
    assert_output --partial "is not tagged in scope 'lab'; no change"
    tc scope devices lab unset 172.16.5.0/24
    run entry lab
    refute_output --partial "devices"
}

@test "devices: a tag must be an address the scope answers for; nothing is written otherwise" {
    cp "$STORE" "${BATS_TEST_TMPDIR}/before"
    # Outside every prefix of the scope.
    tc scope devices lab set 10.1.2.3 cisco
    assert_failure
    assert_output --partial "Cannot tag 10.1.2.3/32 in scope 'lab'"
    assert_output --partial "10.1.2.3/32 is not inside a prefix of the scope"
    # Inside prod's 10.0.0.0/8, but prod-inner owns the more specific 10.10.99.0/24.
    tc scope devices prod set 10.10.99.5 cisco
    assert_failure
    assert_output --partial "10.10.99.5/32 belongs to scope 'prod-inner' (its prefix 10.10.99.0/24 is the most specific one that contains it)"
    # Equal to another scope's prefix: two clients for one network.
    tc scope devices prod set 10.10.99.0/24 cisco
    assert_failure
    # Not a vendor, not an address, missing arguments.
    tc scope devices lab set 192.168.1.1 arista
    assert_failure
    assert_output --partial "Unknown vendor 'arista'"
    tc scope devices lab set not-an-ip cisco
    assert_failure
    assert_output --partial "Invalid address or CIDR"
    tc scope devices lab set 192.168.1.1
    assert_failure
    assert_output --partial "Usage: tacctl scope devices lab set <ip|cidr> <vendor>"
    tc scope devices lab clear
    assert_failure
    assert_output --partial "Unknown subcommand: 'clear'"
    cmp "$STORE" "${BATS_TEST_TMPDIR}/before"
    # A range that holds another scope's more specific prefix is fine: those
    # addresses stay the other scope's.
    tc scope devices prod set 10.10.0.0/16 juniper
    assert_success
    tc scope lookup 10.10.99.5
    assert_output --partial "scope 'prod-inner'"
    refute_output --partial "Tagged"
}

@test "devices: a tag equal to one of the scope's own prefixes is allowed" {
    tc scope devices prod-inner set 10.10.99.0/24 wti
    assert_success
}

@test "prefixes remove refuses to orphan a tag; adding the new prefix first works; nothing is written when refused" {
    tc scope devices lab set 172.16.5.5 cisco
    cp "$STORE" "${BATS_TEST_TMPDIR}/before"
    tc scope prefixes lab remove 172.16.0.0/12
    assert_failure
    assert_output --partial "Cannot remove the prefix(es) from scope 'lab': a tagged address would be left outside the scope's prefixes:"
    assert_output --partial "172.16.5.5/32 is not inside a prefix of the scope"
    assert_output --partial "tacctl scope devices lab unset 172.16.5.5/32"
    cmp "$STORE" "${BATS_TEST_TMPDIR}/before"
    # Moving the range: the new prefix first, then the old one goes, the tag stays.
    tc scope prefixes lab add 172.16.5.0/24
    assert_success
    tc scope prefixes lab remove 172.16.0.0/12
    assert_success
    run entry lab
    assert_line --partial "devices: {172.16.5.5/32: cisco}"
}

@test "prefixes add and scope add refuse to take a tagged address from its scope" {
    tc scope devices lab set 172.16.5.5 cisco
    cp "$STORE" "${BATS_TEST_TMPDIR}/before"
    tc scope prefixes dmz add 172.16.5.0/24
    assert_failure
    assert_output --partial "Cannot add the prefix(es) to scope 'dmz': it would take over an address another scope has tagged with a vendor:"
    assert_output --partial "172.16.5.5/32 belongs to scope 'dmz'"
    tc scope add grab --prefixes 172.16.5.5/32 --secret "grab-secret-0123456789abcdef"
    assert_failure
    assert_output --partial "Cannot create scope 'grab'"
    cmp "$STORE" "${BATS_TEST_TMPDIR}/before"
}

@test "rename keeps the vendor attributes and the tags; remove and prefixes remove --all take them with the scope" {
    tc scope vendor-attrs dmz enable juniper
    tc scope devices dmz set 203.0.113.9 wti
    tc scope rename dmz edge
    assert_success
    run entry edge
    assert_line "    vendor_attrs: [juniper]"
    assert_line "    devices: {203.0.113.9/32: wti}"
    run bash -c 'echo y | "$1" scope remove edge --force' _ "$TACCTL_BIN_SCRIPT"
    assert_success
    ! grep -q '203.0.113.9' "$STORE"
    tc scope add dmz --prefixes 203.0.113.0/24 --secret "dmz-secret-0123456789abcdef"
    tc scope vendor-attrs dmz
    assert_output --partial "not sent"
    tc scope devices dmz set 203.0.113.9 cisco
    run bash -c 'echo y | "$1" scope prefixes dmz remove --all --force' _ "$TACCTL_BIN_SCRIPT"
    assert_success
    ! grep -q '203.0.113.9' "$STORE"
}

@test "scope list: the vendor column appears only when a scope has something to show" {
    tc scope list
    refute_output --partial "VENDOR ATTRIBUTES"
    tc scope vendor-attrs lab enable cisco,juniper
    tc scope devices prod set 10.1.2.3 wti
    tc scope list
    assert_output --partial "VENDOR ATTRIBUTES (RADIUS)"
    assert_line --regexp '^  lab .* cisco,juniper$'
    assert_line --regexp '^  prod .* 1 tagged$'
    assert_line --regexp '^  dmz .* not sent$'
}

@test "store: a hand-edited orphan tag or an unknown vendor makes the store invalid, and config validate says so" {
    tc scope devices lab set 192.168.10.20 cisco
    sed -i 's#{192.168.10.20/32: cisco}#{10.99.0.1/32: arista}#' "$STORE"
    tc config validate
    assert_failure
    assert_output --partial "devices 10.99.0.1/32: vendor must be one of: cisco, juniper, wti"
    sed -i 's#{10.99.0.1/32: arista}#{10.99.0.1/32: cisco}#' "$STORE"
    tc config validate
    assert_failure
    assert_output --partial "scope 'lab': devices: 10.99.0.1/32 is not inside a prefix of the scope"
    # Inside the scope, but another scope's prefix is more specific.
    sed -i 's#{10.99.0.1/32: cisco}#{192.168.10.20/32: cisco}#' "$STORE"
    python3 - "$STORE" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d['scopes']['inner'] = {'prefixes': ['192.168.10.0/24'], 'secret': 'inner-secret-0123456789abcdef'}
yaml.safe_dump(d, open(sys.argv[1], 'w'))
PY
    tc config validate
    assert_failure
    assert_output --partial "scope 'lab': devices: 192.168.10.20/32 belongs to scope 'inner' (its prefix 192.168.10.0/24 is the most specific one that contains it)"
}

@test "completion-friendly usage: scope's own usage names both commands" {
    tc scope
    assert_output --partial "tacctl scope vendor-attrs <scope> [enable|disable <csv>]"
    assert_output --partial "tacctl scope devices <scope> [set <ip|cidr> <vendor>|unset <ip|cidr>]"
    assert_output --partial "tacctl scope auth-method <scope> [tacacs|radius|clear]"
    assert_output --partial "[--vendor-attrs <vendor>[,<vendor>...]]"
}
