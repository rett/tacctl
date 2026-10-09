#!/usr/bin/env bats
# Golden-file tests for device config template rendering.
# Set UPDATE_GOLDEN=1 to regenerate tests/fixtures/golden/*.conf after
# intentional changes.

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
    # Freeze server-IP discovery so rendered output is deterministic.
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'

    load_fixture tacquito.multiscope.yaml
}

# Strip ANSI color codes and the dynamic hostname line that can vary across
# machines / test runs, so the golden file is reproducible. The "Using
# template:" note stays: it pins which template was picked ('built-in
# <name>.template' for a shipped one).
_normalize() {
    sed -E 's/\x1b\[[0-9;]*m//g' \
        | sed -E 's/^hostname .*/hostname TACQUITO-HOSTNAME/'
}

@test "config cisco: renders deterministic IOS config from fixture + lab scope" {
    local out="$BATS_TEST_TMPDIR/cisco.conf"
    "$TACCTL_BIN_SCRIPT" config cisco --scope lab | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "cisco-lab.conf"
}

@test "config cisco: renders deterministic IOS config for prod scope" {
    local out="$BATS_TEST_TMPDIR/cisco-prod.conf"
    "$TACCTL_BIN_SCRIPT" config cisco --scope prod | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "cisco-prod.conf"
}

@test "config cisco --legacy: renders deterministic legacy IOS config for lab scope" {
    local out="$BATS_TEST_TMPDIR/cisco-legacy.conf"
    "$TACCTL_BIN_SCRIPT" config cisco --legacy --scope lab | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "cisco-legacy-lab.conf"
}

@test "config cisco --legacy: emits legacy tacacs-server host syntax, not the IOS 15.0 block" {
    run "$TACCTL_BIN_SCRIPT" config cisco --legacy --scope lab
    assert_success
    assert_output --partial "tacacs-server host 10.0.0.42 single-connection timeout 5 key "
    assert_output --partial "aaa group server tacacs+ TACACS-GROUP"
    assert_output --partial "  server 10.0.0.42"
    # Refute the real (substituted) IOS 15.0 config lines — not bare tokens, which
    # also appear in the template's explanatory comments.
    refute_output --partial "  address ipv4 10.0.0.42"
    refute_output --partial "  server name TACACS"
}

@test "config cisco --legacy: --legacy is order-independent with --scope" {
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --legacy
    assert_success
    assert_output --partial "tacacs-server host 10.0.0.42"
}

@test "config cisco: default (non-legacy) output keeps the IOS 15.0 tacacs server block" {
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "tacacs server TACACS"
    assert_output --partial "address ipv4 10.0.0.42"
    assert_output --partial "server name TACACS"
    refute_output --partial "tacacs-server host"
}

@test "config juniper: renders deterministic Junos config from fixture + lab scope" {
    local out="$BATS_TEST_TMPDIR/juniper.conf"
    "$TACCTL_BIN_SCRIPT" config juniper --scope lab | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "juniper-lab.conf"
}

# --- config cisco: per-level authorization and accounting (0.2.2) -------------

@test "config cisco: authorization and accounting for every level in use, config-commands, console commented" {
    "$TACCTL_BIN_SCRIPT" group add netops 12 OP-CLASS > /dev/null
    "$TACCTL_BIN_SCRIPT" group commands default netops permit > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    local l
    for l in 1 7 12 15; do
        assert_line "aaa authorization commands $l default group TACACS-GROUP local"
        assert_line "aaa accounting commands $l default start-stop group TACACS-GROUP"
    done
    assert_line "aaa authorization config-commands"
    assert_line "! aaa authorization console   ! uncomment to have the console line ask the server too"
    # Ascending order.
    [[ "$output" == *"commands 7 default group TACACS-GROUP local"*"commands 12 default group TACACS-GROUP local"*"commands 15 default"* ]]
}

@test "config cisco: a level whose group has no command rules gets a commented line naming the group and the fix" {
    "$TACCTL_BIN_SCRIPT" group add helpdesk 5 OP-CLASS > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_line "! aaa authorization commands 5 default group TACACS-GROUP local   ! NOT emitted: group 'helpdesk' has no command rules and would be denied every command; run 'tacctl group commands default helpdesk permit'"
    refute_line "aaa authorization commands 5 default group TACACS-GROUP local"
    # Accounting does not depend on rules.
    assert_line "aaa accounting commands 5 default start-stop group TACACS-GROUP"
    assert_line "aaa authorization commands 7 default group TACACS-GROUP local"
    "$TACCTL_BIN_SCRIPT" group commands default helpdesk permit > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_line "aaa authorization commands 5 default group TACACS-GROUP local"
    refute_output --partial "NOT emitted"
}

@test "config cisco: two groups without rules at one level are both named" {
    "$TACCTL_BIN_SCRIPT" group add helpdesk 5 OP-CLASS > /dev/null
    "$TACCTL_BIN_SCRIPT" group add noc 5 OP-CLASS > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "! NOT emitted: groups 'helpdesk', 'noc' have no command rules and would be denied every command; run 'tacctl group commands default <group> permit' for each"
}

@test "config cisco --legacy: accounting per level in use too" {
    "$TACCTL_BIN_SCRIPT" group add helpdesk 5 OP-CLASS > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --legacy --scope lab
    assert_success
    assert_line "aaa accounting commands 5 default start-stop group TACACS-GROUP"
    assert_line "aaa authorization config-commands"
}

@test "config cisco: privilege modes render as privilege <mode> [all] level <N>" {
    "$TACCTL_BIN_SCRIPT" group privilege add operator 'configure: router bgp','exec all: show ip','configure all: interface' > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_line "privilege configure level 7 router bgp"
    assert_line "privilege exec all level 7 show ip"
    assert_line "privilege configure all level 7 interface"
    assert_line "privilege exec level 7 clear counters"
    assert_line "privilege exec level 1 show running-config"
}

# --- config juniper: the server's rules per class (0.2.2) -------------------

@test "config juniper: Step 3 lists what the server sends per class, with sizes, and no class rules to paste" {
    printf 'junos:\n  operator:\n    deny_commands: ["^(request|start)( .*)?$", "^file"]\n    deny_configuration: ["^system login"]\n' >> "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_output --partial "# Step 3: Per-class rules sent by the server at login (read-only summary)"
    assert_output --partial "#   deny-commands       33/241 bytes: (^(request|start)( .*)?$)|(^file)"
    assert_output --partial "#   deny-configuration  15/236 bytes: (^system login)"
    assert_output --partial "#   none: tacctl group junos readonly deny-commands add '<regex>'"
    refute_output --regexp "(^|"$'\n'")set system login class [A-Z-]+ (allow|deny)-commands"
    assert_output --partial "operator: OP-CLASS (local: clear/network/trace/view + view-configuration), junos: deny-commands 33/241, deny-configuration 15/236"
    assert_output --partial "show cli authorization    (after a TACACS+ login: lists the server's deny values)"
}

@test "config juniper: a group using EN-CLASS gets the engineer class and template user" {
    "$TACCTL_BIN_SCRIPT" group add engineer 15 EN-CLASS > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_line "set system login class EN-CLASS permissions [ view view-configuration network clear trace reset configure rollback interface interface-control routing routing-control firewall firewall-control system system-control snmp ]"
    assert_line "set system login user EN-CLASS class EN-CLASS"
    assert_line "  show configuration system login user EN-CLASS"
    assert_output --partial "engineer: EN-CLASS (local: operator bits + reset, configure/rollback and interface, routing, firewall, system, snmp)"
}

@test "config cisco: errors on unknown scope" {
    run "$TACCTL_BIN_SCRIPT" config cisco --scope nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "config juniper: errors on unknown scope" {
    run "$TACCTL_BIN_SCRIPT" config juniper --scope nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

# --- config wti -------------------------------------------------------------
# WTI console servers are driven by numbered serial menus, so the render is a
# walkthrough (not a pasteable config). The unit asks for the factory
# `wti` service: a group's wti-level answers it, else its priv-lvl band
# through patch 0001. The goldens pin the menu values + band mapping.

@test "config wti: renders deterministic walkthrough from fixture + lab scope" {
    local out="$BATS_TEST_TMPDIR/wti.conf"
    "$TACCTL_BIN_SCRIPT" config wti --scope lab | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "wti-lab.conf"
}

@test "config wti: fills in server IP, secret, port 49, service name wti" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Primary Host/Address       : 10.0.0.42"
    assert_output --partial "Secret Word                : lab-secret-0123456789abcdef"
    assert_output --partial "Authentication Port        : 49"
    assert_output --partial "Service Name               : wti       (factory default; per-group levels need it, see notes)"
    refute_output --partial "Service Name               : shell"
    # A unit left on 'shell' by an earlier walkthrough ignores the per-group levels.
    assert_output --partial "A unit set to Service Name 'shell' by the walkthrough of tacctl 0.2.1 or"
    assert_output --partial "Account Management Module  : Enabled"
    assert_output --partial "Session Management Module  : Enabled"
}

@test "config wti: verification covers both sides (WTI Debug + tacquito debug log)" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    # Debug stays Off in the base procedure and is only flipped in the
    # troubleshooting step, which must tell the operator to flip it back.
    assert_output --partial "12. Debug                      : Off"
    assert_output --partial "Step 9: Only if Step 8 fails"
    assert_output --partial "12. Debug: On"
    assert_output --partial "back to Off"
    assert_output --partial "tacctl config loglevel debug"
    assert_output --partial "client args [service=wti"
    assert_output --partial "args [priv-lvl=N]"
    assert_output --partial "bad secret detected"
    assert_output --partial "tacctl config loglevel info"
}

@test "config wti: Default User Access is On (ViewOnly floor), never Off" {
    # Verified on a v8.10 unit: with item 8 Off, the unit's OpenSSH treats a
    # TACACS-only user as invalid and forwards a junk password to tacquito.
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Default User Access        : Enable On, Access Level ViewOnly"
    refute_output --partial "Default User Access        : Off"
    assert_output --partial "INCORRECT"
    assert_output --partial "password' on EVERY attempt = Default User Access Off"
}

@test "config wti: walkthrough covers the unit firewall and password-method test" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "iptables -A INPUT -i lo -j ACCEPT"
    assert_output --partial "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    assert_output --partial "ssh -o PreferredAuthentications=password"
    assert_output --partial "/UL clears it"
}

@test "config wti: Session Management calls out tacquito patch 0002" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Session Management Module  : Enabled   (TACACS+ accounting -- needs tacctl's tacquito patch 0002)"
    assert_output --partial "the tacquito binary lacks patch 0002"
}

@test "config wti: maps shipped groups onto WTI access-level bands" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "readonly: priv-lvl 1 → ViewOnly"
    assert_output --partial "operator: priv-lvl 7 → User"
    assert_output --partial "superuser: priv-lvl 15 → Administrator"
    # Nothing ships in the 10-14 band; the hint tells the operator how to get there.
    assert_output --partial "No group lands in the SuperUser band"
}

@test "config wti: a group at priv-lvl 10-14 lands in the SuperUser band" {
    "$TACCTL_BIN_SCRIPT" group add wtisuper 12 OP-CLASS > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "wtisuper: priv-lvl 12 → SuperUser"
    refute_output --partial "No group lands in the SuperUser band"
}

@test "config wti: a group's wti-level overrides its band in the mapping and in Port access" {
    printf 'wti_level:\n  operator: superuser\n  superuser: user\n' >> "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "operator: priv-lvl 7 → SuperUser (wti-level override; auto: User)"
    assert_output --partial "superuser: priv-lvl 15 → User (wti-level override; auto: Administrator)"
    assert_output --partial "readonly: priv-lvl 1 → ViewOnly"
    refute_output --partial "No group lands in the SuperUser band"
    assert_output --partial "    superuser: User"
    refute_output --partial "    operator: User"
}

@test "config wti: the SuperUser hint points at wti-level" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "e.g. 'tacctl group edit <group> wti-level superuser'."
}

@test "config wti: Port access names the User and ViewOnly groups, which need ports turned On" {
    "$TACCTL_BIN_SCRIPT" group add wtisuper 12 OP-CLASS > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Port Access: the serial ports User- and"
    assert_output --partial "Port access (8. Default User Access → Port Access, Step 3):"
    assert_output --partial "    readonly: ViewOnly"
    assert_output --partial "    operator: User"
    refute_output --partial "    wtisuper: SuperUser"
    refute_output --partial "    superuser: Administrator"
}

@test "config wti: Port access says the list is unused when no group is below SuperUser" {
    "$TACCTL_BIN_SCRIPT" group edit readonly priv-lvl 12 > /dev/null
    "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl 12 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "No group lands at User or ViewOnly, so the Port Access list is not used."
}

@test "config wti: default tacacs-first renders Fallback Local 'On (Transport Failure)'" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Fallback Local             : On (Transport Failure)"
}

@test "config wti: scope aaa-order local-first renders Fallback Local 'On (All Failures)'" {
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Fallback Local             : On (All Failures)"
    refute_output --partial "On (Transport Failure)"
    # Override stays scoped: prod keeps the default.
    run "$TACCTL_BIN_SCRIPT" config wti --scope prod
    assert_success
    assert_output --partial "Fallback Local             : On (Transport Failure)"
}

@test "config wti: no secret warning for a hyphenated alphanumeric key of <= 32 chars" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    refute_output --partial "Warnings:"
}

@test "config wti: warns when the scope secret carries punctuation" {
    "$TACCTL_BIN_SCRIPT" scope secret lab set 'ab+cd/ef=0123456789xyz' > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Warnings:"
    assert_output --partial "Secret contains punctuation"
    assert_output --partial "tacctl scope secret lab set"
}

@test "config wti: warns when the scope secret exceeds 32 chars" {
    "$TACCTL_BIN_SCRIPT" scope secret lab set 'abcdefghij0123456789ABCDEFGHIJ0123456789' > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Secret is 40 chars"
}

@test "config wti: warns when a scope member's username exceeds WTI's 32-char cap" {
    local longname="abcdefghij0123456789abcdefghij012"   # 33 chars
    local test_hash="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
    "$TACCTL_BIN_SCRIPT" user add "$longname" readonly --scopes lab --hash "$test_hash" > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "User '${longname}' is 33 chars"
    # Members of other scopes only are not the WTI's problem.
    run "$TACCTL_BIN_SCRIPT" config wti --scope prod
    assert_success
    refute_output --partial "is 33 chars"
}

@test "config wti: errors on unknown scope" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "config wti: rejects unknown arguments" {
    run "$TACCTL_BIN_SCRIPT" config wti --legacy
    assert_failure
    assert_output --partial "Unknown argument"
}

@test "config validate: succeeds on a valid config" {
    # Build the config the way the product does: the shipped template with a
    # real shared secret, imported into the store, then one user via
    # 'user add' -- which renders tacquito.yaml from the store.
    cp "${TACCTL_SRC}/config/backends/tacacs/tacquito.yaml" "$TACCTL_CONFIG"
    sed -i 's/REPLACE_WITH_SHARED_SECRET/lab-secret-0123456789abcdef/' "$TACCTL_CONFIG"
    rm -f "${TACCTL_STATE_DIR}/store.yaml"
    run "$TACCTL_BIN_SCRIPT" store import
    assert_success
    run "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
    assert_success
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    assert_line --regexp 'Rendered config:.* up to date$'
    assert_output --partial "Configuration is valid."
}

# --- per-scope aaa-order: render flip ----------------------------------------
# Goldens above cover the tacacs-first default. These assert the
# local-first shape when a specific scope overrides via
# `tacctl scope aaa-order <scope> local-first`, and verify that
# overrides stay scoped (other scopes keep the default).

@test "config cisco: scope aaa-order local-first puts local ahead of the TACACS group" {
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "aaa authentication login default local group TACACS-GROUP"
    assert_output --partial "aaa authorization exec default local group TACACS-GROUP if-authenticated"
    assert_output --partial "aaa authorization commands 1 default local group TACACS-GROUP"
    assert_output --partial "aaa authorization commands 15 default local group TACACS-GROUP"
    refute_output --partial "aaa authentication login default group TACACS-GROUP local"
}

@test "config juniper: scope aaa-order local-first flips authentication-order" {
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_output --partial "set system authentication-order [ password tacplus ]"
    refute_output --partial "set system authentication-order [ tacplus password ]"
}

@test "config cisco: scope aaa-order override is per-scope (prod unaffected)" {
    # Flip lab to local-first; prod (no override) should still render
    # the default tacacs-first shape.
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope prod
    assert_success
    assert_output --partial "aaa authentication login default group TACACS-GROUP local"
    refute_output --partial "aaa authentication login default local group TACACS-GROUP"
}

@test "config cisco: scope exec-timeout applies to line con + line vty" {
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 15 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    # Both line con 0 and line vty 0 15 carry the override.
    run bash -c '"'"$TACCTL_BIN_SCRIPT"'" config cisco --scope lab | grep -c "^  exec-timeout 15 0$"'
    [[ "$output" == "2" ]]
}

@test "config juniper: scope exec-timeout emits idle-timeout line" {
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 15 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_output --partial "set system login idle-timeout 15"
}

@test "config cisco: scope tacacs-group overrides the aaa-group-server label" {
    "$TACCTL_BIN_SCRIPT" scope tacacs-group lab TACACS_PROD > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "aaa group server tacacs+ TACACS_PROD"
    assert_output --partial "aaa authentication login default group TACACS_PROD local"
    assert_output --partial "aaa accounting exec default start-stop group TACACS_PROD"
    refute_output --partial "TACACS-GROUP"
}

@test "config cisco: per-scope mgmt-acl wins over global" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name GLOBAL-VTY > /dev/null
    "$TACCTL_BIN_SCRIPT" scope  mgmt-acl lab cisco-name LAB-VTY-ACL > /dev/null
    # Populate at least one permit so the ACL block actually renders.
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "ip access-list standard LAB-VTY-ACL"
    assert_output --partial "access-class LAB-VTY-ACL in"
    refute_output --partial "GLOBAL-VTY"
}

@test "config juniper: per-scope mgmt-acl wins over global" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl juniper-name GLOBAL-MGMT > /dev/null
    "$TACCTL_BIN_SCRIPT" scope  mgmt-acl lab juniper-name LAB-MGMT-FILTER > /dev/null
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_output --partial "filter LAB-MGMT-FILTER"
    refute_output --partial "GLOBAL-MGMT"
}

# --- SNMP and NETCONF in the walkthroughs (0.2.3: D41, D43, D53) ----------------------------

# snmp_setup: scope lab with a community, two ranges and a contact.
snmp_setup() {
    printf 'lab-ro-community\n' | "$TACCTL_BIN_SCRIPT" scope snmp lab community --stdin > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp lab clients add 198.51.100.0/24,10.0.0.0/8 > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp lab contact 'NOC <noc@example.net>' > /dev/null
}

@test "config cisco|juniper|wti: SNMP not configured is a comment saying so, and NETCONF is commented" {
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_line "! SNMP is not configured in tacctl for scope 'lab': nothing is rendered here."
    refute_output --partial "snmp-server community"
    assert_line "! netconf-yang"
    refute_line "netconf-yang"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_line "# SNMP is not configured in tacctl for scope 'lab': nothing is rendered here."
    assert_line "#   set system services netconf ssh"
    refute_line "set system services netconf ssh"
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_output --partial "SNMP is not configured in tacctl for scope 'lab': nothing is listed here."
    assert_output --partial "NETCONF does not exist on the unit"
    refute_output --partial "Unfilled SNMP values"
}

@test "config cisco: v2c with the server, the ranges in order and the final refusal; unset values are commented and listed last" {
    snmp_setup
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_line "ip access-list standard TACCTL-SNMP"
    assert_line "  permit host 10.0.0.42"
    assert_line "  permit 198.51.100.0 0.0.0.255"
    assert_line "  permit 10.0.0.0 0.255.255.255"
    assert_line "  deny   any"
    assert_line "snmp-server community lab-ro-community RO TACCTL-SNMP"
    assert_line "snmp-server contact NOC <noc@example.net>"
    assert_line "! snmp-server location <location>   ! NOT SET: tacctl device location <name> '<text>'"
    [[ "$output" == *"permit host 10.0.0.42"*"permit 198.51.100.0"*"permit 10.0.0.0 0.255"*"deny   any"* ]]
    # The location is one device's, not a gap of the walkthrough: with the
    # contact, the credentials and the server address set, nothing is listed.
    refute_output --partial "Unfilled SNMP values"
}

@test "config juniper: the client list, the community bound to it and the final restrict" {
    snmp_setup
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_line "set snmp client-list TACCTL-SNMP 10.0.0.42/32"
    assert_line "set snmp client-list TACCTL-SNMP 198.51.100.0/24"
    assert_line "set snmp client-list TACCTL-SNMP 0.0.0.0/0 restrict"
    assert_line "set snmp community lab-ro-community authorization read-only"
    assert_line "set snmp community lab-ro-community client-list-name TACCTL-SNMP"
    assert_line 'set snmp contact "NOC <noc@example.net>"'
    assert_line '# set snmp location "<location>"   (NOT SET: tacctl device location <name> '"'"'<text>'"'"')'
    assert_line "  show configuration snmp"
}

@test "config wti: the SNMP step is Step 6, the IP Tables list Step 5 and the final DROP Step 11; the restriction is the udp 161 lines" {
    snmp_setup
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Step 6: SNMP"
    assert_output --partial "Read-only Community       : lab-ro-community"
    assert_output --partial "Client restriction (not verified on a unit): the udp port 161 lines of the IP Tables list (Step 5) are"
    refute_output --partial "depends on the IP Tables"
    assert_output --partial "allow  198.51.100.0/24"
    assert_output --partial "Step 7: Save"
    assert_output --partial "Step 8: Test from a SECOND session"
    assert_output --partial "Step 9: Only if Step 8 fails"
    assert_output --partial "Step 10: Break-glass local accounts"
    assert_output --partial "Step 11: The final DROP of the IP Tables list"
}

# iptables_setup: scope lab with two management ranges and the SNMP setup.
iptables_setup() {
    snmp_setup
    "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab add 192.0.2.0/24,198.51.100.0/25 > /dev/null
}

@test "config wti: Step 5 keeps its caution as the introduction and renders the scope's IP Tables list, the DROP last (golden)" {
    iptables_setup
    local out="$BATS_TEST_TMPDIR/wti-iptables.conf"
    "$TACCTL_BIN_SCRIPT" config wti --scope lab | _normalize > "$out"
    golden_diff "$out" "iptables/cli-wti-lab.conf"
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    # The caution is the introduction; the generated list follows it.
    assert_output --partial "        login waits out the Fallback Timer and tacquito logs nothing.

        Generated for scope 'lab'. Not verified on a unit."
    assert_output --partial "  1. iptables -A INPUT -i lo -j ACCEPT"
    assert_output --partial "  2. iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    assert_output --partial "-s 10.0.0.42/32 --dport 22 -j ACCEPT"
    assert_output --partial "-s 192.0.2.0/24 --dport 443 -j ACCEPT"
    assert_output --partial "-s 198.51.100.0/25 --dport 22 -j ACCEPT"
    assert_output --partial "-p udp -s 10.0.0.42/32 --dport 161 -j ACCEPT"
    assert_output --partial "-p udp -s 198.51.100.0/24 --dport 161 -j ACCEPT"
    assert_output --partial "-p udp -s 10.0.0.0/8 --dport 161 -j ACCEPT"
    assert_output --partial "'-m state --state ESTABLISHED,RELATED' in place of"
    assert_output --partial "does not apply it"
    # The only DROP to paste is in Step 11, after every other rule.
    [[ "$(grep -c '^ *[0-9]*\. iptables -A INPUT -j DROP$' <<< "$output")" == 1 ]]
    [[ "$(grep -n '^ *[0-9]*\. iptables -A INPUT -j DROP$' <<< "$output" | cut -d: -f1)" -gt "$(grep -n '^Step 11:' <<< "$output" | cut -d: -f1)" ]]
    [[ "$(grep -n -- '-j ACCEPT$' <<< "$output" | tail -1 | cut -d: -f1)" -lt "$(grep -n '^Step 6:' <<< "$output" | cut -d: -f1)" ]]
}

@test "config wti: a scope with no management permit list gets the guard, a commented DROP" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    assert_output --partial "  1. iptables -A INPUT -i lo -j ACCEPT"
    assert_output --partial "-p tcp -s 10.0.0.42/32 --dport 22 -j ACCEPT"
    assert_output --partial "# no management permit list for scope 'lab': only the tacctl server is permitted for ssh and https"
    assert_line "        # iptables -A INPUT -j DROP"
    assert_output --partial "NOT rendered as a paste: scope 'lab' has no management permit list"
    assert_output --partial "lock out every"
    [[ "$(grep -c '^ *[0-9]*\. iptables -A INPUT -j DROP$' <<< "$output")" == 0 ]]
}

@test "config wti: the list comes from the scope's permits, else the global ones" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 203.0.113.0/24 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "-p tcp -s 203.0.113.0/24 --dport 22 -j ACCEPT"
    refute_output --partial "NOT rendered as a paste"
    "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab add 192.0.2.0/24 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_output --partial "-p tcp -s 192.0.2.0/24 --dport 22 -j ACCEPT"
    refute_output --partial "203.0.113.0/24"
    echo y | "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab clear > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_output --partial "-p tcp -s 203.0.113.0/24 --dport 22 -j ACCEPT"
    # Cisco reads the same list; nothing was stored for WTI.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_line "  permit 203.0.113.0 0.0.0.255"
    run grep -ci 'iptables\|wti' "${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_output "0"
}

@test "config wti: an IPv6 permit is skipped with a note, and --source names the server in the rules" {
    "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab add 192.0.2.0/24,fd00::/64 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --server 203.0.113.9 --source 198.51.100.77
    assert_success
    assert_output --partial "# skipped, not rendered: fd00::/64 (IPv6; the list is IPv4 only)"
    refute_output --partial "-s fd00"
    assert_output --partial "-p tcp -s 198.51.100.77/32 --dport 443 -j ACCEPT"
    assert_output --partial "-p udp -s 198.51.100.77/32 --dport 161 -j ACCEPT"
    refute_output --partial "-s 203.0.113.9"
    assert_output --partial "Primary Host/Address       : 203.0.113.9"
}

@test "config cisco|juniper|wti: SNMP goldens (v2c, ranges, contact; location unset)" {
    snmp_setup
    local v out
    for v in cisco juniper wti; do
        out="$BATS_TEST_TMPDIR/snmp-$v.conf"
        "$TACCTL_BIN_SCRIPT" config "$v" --scope lab | _normalize > "$out"
        golden_diff "$out" "snmp/cli-$v-lab.conf"
    done
}

@test "config cisco|juniper|wti: --name takes the device's location, description and sysName; --snmp-location overrides for one paste" {
    snmp_setup
    "$TACCTL_BIN_SCRIPT" device add lab-sw1 192.168.1.1 --vendor cisco --no-host-key --snmp-location "Rack 4" --description "Lab switch" > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --name lab-sw1
    assert_success
    assert_line 'set snmp location "Rack 4"'
    assert_line 'set snmp description "Lab switch"'
    refute_output --partial "Unfilled SNMP values"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --name lab-sw1 --snmp-location "Rack 9"
    assert_line 'set snmp location "Rack 9"'
    run grep -c 'Rack 9' "${TACCTL_STATE_DIR}/devices.yaml"
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --name nosuch
    assert_failure 1
    assert_output --partial "Device 'nosuch' not found."
}

@test "config cisco|juniper|wti --server and --source: the AAA lines carry --server, the SNMP clients --source, a note says which is which" {
    snmp_setup
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --server 203.0.113.9 --source 198.51.100.77
    assert_success
    assert_line "  address ipv4 203.0.113.9"
    assert_line "  permit host 198.51.100.77"
    refute_line "  permit host 203.0.113.9"
    assert_output --partial "Two server addresses:"
    assert_output --partial "The device is told to authenticate against 203.0.113.9 (--server)"
    assert_output --partial "tacctl reaches the device from 198.51.100.77 (--source)"
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab --server 203.0.113.9
    assert_line "set system tacplus-server 203.0.113.9 secret lab-secret-0123456789abcdef"
    assert_line "set snmp client-list TACCTL-SNMP 10.0.0.42/32"
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab --server 203.0.113.9
    assert_output --partial "Primary Host/Address       : 203.0.113.9"
    assert_output --partial "allow  10.0.0.42/32"
    # Equal addresses: no note. Not stored.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --server 10.0.0.42 --source 10.0.0.42
    refute_output --partial "Two server addresses"
    run grep -c '203.0.113.9' "${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_output "0"
    # --staging combined: the staged /32 is the device's bench address.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --staging 192.0.2.77 --server 203.0.113.9
    assert_success
    assert_line "  address ipv4 203.0.113.9"
    run "$TACCTL_BIN_SCRIPT" scope staging list
    assert_output --partial "192.0.2.77"
}

@test "config cisco|juniper|wti: --server and --source are checked" {
    local bad
    for bad in "--server 2001:db8::1" "--server 10.0.0.0/8" "--server bad_name" "--source 10.0.0.0/8" "--source ::1" "--source host.example"; do
        run "$TACCTL_BIN_SCRIPT" config cisco --scope lab $bad
        assert_failure 1
        refute_output --partial "ip access-list"
    done
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --server
    assert_failure 1
    assert_output --partial "[--server <address|name>] [--source <address>] [--snmp-location <text>]"
}

@test "config cisco: the NETCONF step is a superuser's; an engineer is told to ask one" {
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_line "! netconf-yang"
    assert_output --partial "! Prerequisite: exec authorization above"
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab --legacy
    assert_output --partial "! NETCONF (netconf-yang) does not exist on IOS 12.x."
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$(printf 'x' | python3 -c 'import bcrypt,binascii,sys; print(binascii.hexlify(bcrypt.hashpw(sys.stdin.buffer.read(), bcrypt.gensalt(rounds=4))).decode())')" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=en run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "NETCONF (netconf-yang) is enabled by a superuser: ask one to run 'tacctl config cisco' for this scope."
    refute_line "! netconf-yang"
}

@test "config juniper: the NETCONF step is commented; the management filter permits tcp 830 and says so" {
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_output --partial "No management filter is rendered (Step 4)"
    "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab add 10.0.0.0/8 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_output --partial "permits tcp port 830 next to ssh from the same"
    assert_output --partial "# tcp port 830 (NETCONF over ssh, Step 6) is permitted by the same terms as ssh."
    assert_line "set firewall family inet filter MGMT-ACL term permit-mgmt from destination-port [ ssh 830 ]"
    assert_line "#   ssh -p 830 -s <user>@<device> netconf     (expect a <hello> from the device)"
    run grep -E '^set system services netconf' <<<"$output"
    assert_failure
}
