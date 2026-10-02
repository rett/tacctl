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
# template:" line legitimately prints the absolute path of the template it
# rendered, which sits under this checkout; swap that checkout prefix for a
# <TACCTL_SRC> placeholder (literal match via index(), so any path is safe)
# so the goldens pass from any checkout or worktree while still pinning
# which template file was picked.
_normalize() {
    sed -E 's/\x1b\[[0-9;]*m//g' \
        | sed -E 's/^hostname .*/hostname TACQUITO-HOSTNAME/' \
        | awk '{
            p = "Using template: " ENVIRON["TACCTL_SRC"] "/"
            i = index($0, p)
            if (i) $0 = substr($0, 1, i - 1) "Using template: <TACCTL_SRC>/" substr($0, i + length(p))
            print
        }'
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
# walkthrough (not a pasteable config). The unit reads priv-lvl from the same
# `shell` service Cisco uses; the goldens pin the menu values + band mapping.

@test "config wti: renders deterministic walkthrough from fixture + lab scope" {
    local out="$BATS_TEST_TMPDIR/wti.conf"
    "$TACCTL_BIN_SCRIPT" config wti --scope lab | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "wti-lab.conf"
}

@test "config wti: fills in server IP, secret, port 49, service name shell" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    assert_output --partial "Primary Host/Address       : 10.0.0.42"
    assert_output --partial "Secret Word                : lab-secret-0123456789abcdef"
    assert_output --partial "Authentication Port        : 49"
    assert_output --partial "Service Name               : shell"
    assert_output --partial "Account Management Module  : Enabled"
    assert_output --partial "Session Management Module  : Enabled"
}

@test "config wti: verification covers both sides (WTI Debug + tacquito debug log)" {
    run "$TACCTL_BIN_SCRIPT" config wti --scope lab
    assert_success
    # Debug stays Off in the base procedure and is only flipped in the
    # troubleshooting step, which must tell the operator to flip it back.
    assert_output --partial "12. Debug                      : Off"
    assert_output --partial "Step 8: Only if Step 7 fails"
    assert_output --partial "12. Debug: On"
    assert_output --partial "back to Off"
    assert_output --partial "tacctl config loglevel debug"
    assert_output --partial "client args [service=shell"
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

@test "config wti: falls back to the inline walkthrough when no template resolves" {
    # Point both template dirs at nowhere: TACCTL_ETC is already the tmp etc
    # (no templates/ dir), and the repo dir is derived from the script's own
    # location, so run a copy of the script from an empty directory.
    local alt="$BATS_TEST_TMPDIR/alt/bin"
    mkdir -p "$alt"
    cp "$TACCTL_BIN_SCRIPT" "$alt/tacctl.sh"
    cp -r "${TACCTL_SRC}/lib" "$BATS_TEST_TMPDIR/alt/lib"
    run "$alt/tacctl.sh" config wti --scope lab
    assert_success
    refute_output --partial "Using template:"
    assert_output --partial "Secret Word                : lab-secret-0123456789abcdef"
    assert_output --partial "Service Name               : shell"
    # The inline fallback carries the same load-bearing settings and
    # troubleshooting step as the template.
    assert_output --partial "Default User Access        : Enable On, Access Level ViewOnly"
    assert_output --partial "ESTABLISHED,RELATED -j ACCEPT"
    assert_output --partial "Step 8: Only if Step 7 fails"
}

@test "config validate: succeeds on a valid config" {
    # The hand-written multiscope fixture is not valid by validate's own
    # rules (inline authenticators instead of bcrypt_<user> anchors, users
    # without accounter:), so build the config the way the product does:
    # shipped template + real shared secret + one user via 'user add'.
    cp "${TACCTL_SRC}/config/tacquito.yaml" "$TACCTL_CONFIG"
    sed -i 's/REPLACE_WITH_SHARED_SECRET/lab-secret-0123456789abcdef/' "$TACCTL_CONFIG"
    run "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
    assert_success
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
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
