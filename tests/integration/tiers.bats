#!/usr/bin/env bats
# Integration tests for the RO/OP/SU caller-tier gate, self-service
# 'tacctl passwd', and the per-tier sudoers drop-in.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures
load ../helpers/fakedev

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_TIER_SUDOERS_FILE="${BATS_TEST_TMPDIR}/sudoers.d/tacctl-tiers"
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml

    # Cost-10 hash of a known password, generated once per test file run.
    OLD_PW="Old-password-12345"
    HASH=$(printf '%s' "$OLD_PW" | python3 -c '
import bcrypt, binascii, sys
print(binascii.hexlify(bcrypt.hashpw(sys.stdin.buffer.read(), bcrypt.gensalt(rounds=4))).decode())')
    for pair in ro:readonly op:operator su:superuser; do
        "$TACCTL_BIN_SCRIPT" user add "${pair%%:*}" "${pair##*:}" \
            --hash "$HASH" --scopes lab > /dev/null
    done
}

# as_user <name> <managed:yes|no> -- <tacctl args...>
# Simulates 'sudo tacctl ...' by <name>. Managed callers are members of
# tac-users (via a stubbed 'id').
as_user() {
    local name="$1" managed="$2"; shift 3
    if [[ "$managed" == "yes" ]]; then
        stub_cmd id 'echo "users tac-users"'
    else
        stub_cmd id 'echo "users sudo"'
    fi
    SUDO_USER="$name" run "$TACCTL_BIN_SCRIPT" "$@"
}

# A user's hash as tacquito reads it from the rendered config (quoted there
# when the hex happens to be all digits).
_hash_of() {
    grep -A5 "^bcrypt_$1:" "$TACCTL_CONFIG" | awk '/^[[:space:]]*hash:/ {gsub(/"/, "", $2); print $2; exit}'
}

# One field of a user in the canonical store.
store_user() {
    python3 -c '
import sys, yaml
with open(sys.argv[1]) as f:
    v = yaml.safe_load(f)["users"][sys.argv[2]].get(sys.argv[3])
print("" if v is None else v)' "${TACCTL_STATE_DIR}/store.yaml" "$1" "$2"
}

# --- tier gate ----------------------------------------------------------------

@test "tier: readonly may list users" {
    as_user ro yes -- user list
    assert_success
    assert_output --partial "ro"
}

@test "tier: readonly sees a group's Junos patterns through group show, not through group junos" {
    "$TACCTL_BIN_SCRIPT" group junos operator deny-commands add '^request' > /dev/null
    "$TACCTL_BIN_SCRIPT" group junos operator deny-configuration add '^snmp' > /dev/null
    as_user ro yes -- group show operator
    assert_success
    assert_output --partial "Junos rules:       deny-commands 10/241 bytes, deny-configuration 7/236 bytes"
    assert_line --regexp '^ +\^request$'
    assert_line --regexp '^ +\^snmp$'
    refute_output --partial "group junos"
    as_user ro yes -- group junos operator list
    assert_failure
    assert_output --partial "not permitted for the readonly tier"
    # The superuser is pointed to the verb.
    as_user su yes -- group show operator
    assert_success
    assert_line --regexp '^ +\^snmp$'
    assert_output --partial "tacctl group junos operator list"
}

@test "tier: readonly may not add users, read logs, or print device config" {
    as_user ro yes -- user add mallory superuser
    assert_failure
    assert_output --partial "not permitted for the readonly tier"
    as_user ro yes -- log tail
    assert_failure
    as_user ro yes -- config cisco
    assert_failure
    as_user ro yes -- user passwd su --hash "$HASH"
    assert_failure
}

@test "tier: operator may validate config and list backups" {
    as_user op yes -- backup list
    assert_success
    as_user op yes -- config validate
    refute_output --partial "not permitted"
}

@test "tier: operator may not change users, read secrets, or diff backups" {
    as_user op yes -- user passwd su --hash "$HASH"
    assert_failure
    assert_output --partial "not permitted for the operator tier"
    as_user op yes -- scope show lab
    assert_failure
    as_user op yes -- backup diff
    assert_failure
    as_user op yes -- backup restore 20250101_000000
    assert_failure
    assert_output --partial "not permitted for the operator tier"
    as_user op yes -- log clear
    assert_failure
    as_user op yes -- config sudoers tiers install
    assert_failure
}

@test "tier: config snmp (the SNMP credentials) is the superuser's alone" {
    local who
    for who in ro op; do
        as_user "$who" yes -- config snmp show
        assert_failure
        assert_output --partial "not permitted for the"
    done
    as_user su yes -- config snmp show
    assert_success
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    refute_output --partial "config snmp"
}

@test "tier: superuser has full access" {
    as_user su yes -- user add newbie readonly --hash "$HASH" --scopes lab
    assert_success
}

@test "tier: tier follows tacquito.yaml after a group move" {
    "$TACCTL_BIN_SCRIPT" user move op readonly > /dev/null
    as_user op yes -- backup list
    assert_failure
    assert_output --partial "readonly tier"
}

@test "tier: help, -h and --help print the usage to both lower tiers (exit 1, as for everyone)" {
    local who word
    for who in ro op; do
        for word in help -h --help; do
            as_user "$who" yes -- "$word"
            assert_failure 1
            assert_output --partial "Usage:"
            refute_output --partial "not permitted"
        done
    done
    as_user ro yes -- help user
    assert_failure
    assert_output --partial "'tacctl help user' is not permitted for the readonly tier."
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    assert_output --partial "/usr/local/bin/tacctl help, /usr/local/bin/tacctl -h, /usr/local/bin/tacctl --help"
}

@test "tier: managed caller with no tacctl user is denied everything" {
    as_user ghost yes -- status
    assert_failure
    assert_output --partial "no active tacctl user"
}

@test "tier: disabled user is denied everything" {
    "$TACCTL_BIN_SCRIPT" user disable ro > /dev/null
    as_user ro yes -- user list
    assert_failure
    assert_output --partial "no active tacctl user"
}

@test "tier: local admin outside tac-users keeps full access" {
    as_user ro no -- user add newbie readonly --hash "$HASH" --scopes lab
    assert_success
}

@test "tier: denial is logged" {
    as_user ro yes -- user remove su
    assert_failure
    stub_called "logger .*tier DENY user=ro tier=readonly cmd=user remove"
}

# --- self-service passwd -------------------------------------------------------

@test "passwd: changes the caller's own password after verifying the current one" {
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=ro run bash -c 'printf "%s\n%s\n%s\n" "'"$OLD_PW"'" "New-password-67890" "New-password-67890" | "'"$TACCTL_BIN_SCRIPT"'" passwd'
    assert_success
    assert_output --partial "Password changed for 'ro'"
    [[ "$(_hash_of ro)" != "$HASH" ]]
    [[ "$(_hash_of su)" == "$HASH" ]]
    # The store holds the same new hash, and today's date for it.
    [[ "$(store_user ro hash)" == "$(_hash_of ro)" ]]
    [[ "$(store_user su hash)" == "$HASH" ]]
    [[ "$(store_user ro password_changed)" == "$(date +%Y-%m-%d)" ]]
}

@test "passwd: wrong current password leaves the hash alone" {
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=ro run bash -c 'printf "%s\n%s\n%s\n" "wrong-password-000" "New-password-67890" "New-password-67890" | "'"$TACCTL_BIN_SCRIPT"'" passwd'
    assert_failure
    assert_output --partial "Current password does not match"
    [[ "$(_hash_of ro)" == "$HASH" ]]
}

@test "passwd: rejects a new password equal to the current one" {
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=ro run bash -c 'printf "%s\n%s\n%s\n" "'"$OLD_PW"'" "'"$OLD_PW"'" "'"$OLD_PW"'" | "'"$TACCTL_BIN_SCRIPT"'" passwd'
    assert_failure
    assert_output --partial "must differ"
    [[ "$(_hash_of ro)" == "$HASH" ]]
}

@test "passwd: enforces the strength policy" {
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=ro run bash -c 'printf "%s\n%s\n%s\n" "'"$OLD_PW"'" "short" "short" | "'"$TACCTL_BIN_SCRIPT"'" passwd'
    assert_failure
    [[ "$(_hash_of ro)" == "$HASH" ]]
}

@test "passwd: takes no username argument" {
    as_user ro yes -- passwd su
    assert_failure
    assert_output --partial "takes no arguments"
    [[ "$(_hash_of su)" == "$HASH" ]]
}

@test "passwd: refuses when there is no invoking user" {
    run env -u SUDO_USER "$TACCTL_BIN_SCRIPT" passwd
    assert_failure
    assert_output --partial "tacctl user passwd <username>"
}

# --- sudoers tiers ------------------------------------------------------------

@test "config sudoers tiers show: prints the rules it would install" {
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    assert_success
    assert_output --partial "not installed"
    assert_output --partial "%tac-readonly ALL=(root) NOPASSWD: TACCTL_RO"
    assert_output --partial "%tac-superuser ALL=(ALL:ALL) ALL"
}

@test "config sudoers tiers show: ssh and device rows per tier, env_keep for the agent socket, no SETENV" {
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    assert_success
    # SETENV would let a caller set SUDO_USER and pose as someone else.
    refute_output --partial "SETENV"
    assert_output --partial 'Defaults!/usr/local/bin/tacctl env_keep += "SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY"'
    assert_output --partial "%tac-operator ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP"
    local text ro op r
    text=$(sed -n 's/^    //p' <<<"$output" | sed -e ':a' -e '/\\$/N; s/\\\n//; ta')
    ro=$(grep '^Cmnd_Alias TACCTL_RO' <<<"$text")
    op=$(grep '^Cmnd_Alias TACCTL_OP' <<<"$text")
    for r in 'tacctl ssh \*' 'tacctl device list,' 'tacctl device list \*' 'tacctl device show \*' 'tacctl device ssh \*' 'tacctl device ssh-config'; do
        grep -q -- "$r" <<<"$ro" || { echo "readonly lacks $r"; return 1; }
        if grep -q -- "$r" <<<"$op"; then echo "operator alias has $r"; return 1; fi
    done
    for r in 'tacctl device check \*' 'tacctl device scan,' 'tacctl device discover \*' 'tacctl device export \*' 'tacctl console show,' 'tacctl console check'; do
        grep -q -- "$r" <<<"$op" || { echo "operator lacks $r"; return 1; }
        if grep -q -- "$r" <<<"$ro"; then echo "readonly alias has $r"; return 1; fi
    done
    # The login console reads its settings with _console-policy, at every tier.
    grep -q -- 'tacctl _console-policy' <<<"$ro" || { echo "readonly lacks _console-policy"; return 1; }
    if grep -q -- '_console-policy' <<<"$op"; then echo "operator alias has _console-policy"; return 1; fi
}

@test "config sudoers tiers: generated rules pass a real visudo" {
    local visudo_bin
    visudo_bin=$(PATH="$PATH:/usr/sbin:/sbin" command -v visudo) || skip "visudo not installed"
    "$TACCTL_BIN_SCRIPT" config sudoers tiers show | sed -n 's/^    //p' > "$BATS_TEST_TMPDIR/tiers"
    run "$visudo_bin" -cf "$BATS_TEST_TMPDIR/tiers"
    assert_success
}

@test "config sudoers tiers: lower tiers get no secret-bearing or mutating command" {
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    refute_output --partial "backup diff"
    refute_output --partial "user passwd"
    refute_output --partial "log clear"
    refute_output --partial "group edit"
    # The device configurations and the reads of a scope's secret (the
    # engineer reads those of its own scopes) are the engineer alias's only.
    local text ro_op en
    text=$(sed -n 's/^    //p' <<<"$output" | sed -e ':a' -e '/\\$/N; s/\\\n//; ta')
    ro_op=$(grep -E '^Cmnd_Alias TACCTL_(RO|OP)' <<<"$text")
    en=$(grep '^Cmnd_Alias TACCTL_EN' <<<"$text")
    for r in "config cisco" "scope show" "scope secret" "host unenroll" "scope staging" "device config pull" "device config diff" "device config show" "device config forget"; do
        if grep -q "$r" <<<"$ro_op"; then echo "$r below the engineer tier"; return 1; fi
    done
    for r in 'tacctl config cisco \*' 'tacctl config juniper,' 'tacctl config wti \*' 'tacctl device add \*' 'tacctl device import - \*' \
        'tacctl device hostkey \*' 'tacctl device config show \*' 'tacctl device config pull \*' 'tacctl device config diff \*' \
        'tacctl scope devices \*' \
        'tacctl host list,' 'tacctl host show \*' 'tacctl scope staging list' \
        'tacctl scope secret \*' 'tacctl scope show \*' 'tacctl scope snmp \*' 'tacctl device location \*'; do
        grep -q -- "$r" <<<"$en" || { echo "engineer lacks $r"; return 1; }
    done
    # The operator's alias holds the list of device configurations and no
    # other verb of it; forget is nobody's but the superuser's.
    grep -q 'tacctl device config list \*' <<<"$ro_op" || { echo "operator lacks device config list"; return 1; }
    for r in 'device config forget'; do
        if grep -q -- "$r" <<<"$ro_op$en"; then echo "$r below the superuser tier"; return 1; fi
    done
    # Sudoers sees these: stdin only for an import, a list but no removal of
    # staging addresses. Linux host deployment is the superuser's: an engineer
    # reads hosts (list, show) and nothing else of 'host'.
    for r in 'device import \*' 'device import /' 'scope staging \*' 'scope staging remove' 'host enroll' 'host sync' 'host move' \
        'host target' 'host provisioner' 'host unenroll' 'host default-method' \
        'scope prefixes' 'device stale-days' 'config linux' 'user ' 'backend enable' 'config snmp' 'console '; do
        if grep -q -- "$r" <<<"$en"; then echo "engineer alias has $r"; return 1; fi
    done
}

@test "config sudoers tiers: tac-engineer gets tacctl's verbs only, no (ALL:ALL) ALL" {
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    assert_success
    assert_output --partial "    %tac-engineer ALL=(root) NOPASSWD: TACCTL_RO, TACCTL_OP, TACCTL_EN"
    run grep -c "tac-engineer" <<<"$output"
    assert_output "1"
}

@test "tier: a group's tier setting decides before its priv-lvl band (engineer at priv-lvl 15)" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    as_user en yes -- scope prefixes lab list
    assert_success
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    as_user en yes -- scope prefixes lab list
    assert_failure
    assert_output --partial "'tacctl scope prefixes' is not permitted for the engineer tier."
    as_user en yes -- user add mallory superuser
    assert_failure
    assert_output --partial "not permitted for the engineer tier"
    as_user en yes -- backup list
    refute_output --partial "not permitted"
    as_user en yes -- device add lab-sw 192.168.1.1 --no-host-key
    assert_success
    as_user en yes -- device add prod-sw 10.99.0.1 --no-host-key
    assert_failure
    assert_output --partial "is at an address no scope answers: the engineer tier registers devices at the addresses of its own scopes only"
    # The operator tier keeps its rows only.
    as_user op yes -- device add lab-sw2 192.168.1.2 --no-host-key
    assert_failure
    assert_output --partial "not permitted for the operator tier"
}

@test "config sudoers tiers install/remove: writes and deletes the drop-in" {
    mkdir -p "$(dirname "$TACCTL_TIER_SUDOERS_FILE")"
    stub_cmd visudo
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers install
    assert_success
    [[ -f "$TACCTL_TIER_SUDOERS_FILE" ]]
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers remove
    assert_success
    [[ ! -f "$TACCTL_TIER_SUDOERS_FILE" ]]
}

@test "config sudoers tiers install: aborts when visudo validation fails" {
    mkdir -p "$(dirname "$TACCTL_TIER_SUDOERS_FILE")"
    stub_cmd visudo 'exit 1'
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers install
    assert_failure
    [[ ! -f "$TACCTL_TIER_SUDOERS_FILE" ]]
}

# --- backend and store verbs ---------------------------------------------------

@test "tier: backend list and backend status are read-only commands, for both lower tiers" {
    as_user ro yes -- backend list
    assert_success
    assert_output --partial "tacacs"
    as_user ro yes -- backend status
    assert_success
    assert_output --partial "== Backend: tacacs"
    as_user op yes -- backend list
    assert_success
    as_user op yes -- backend status tacacs
    assert_success
}

@test "tier: enabling or disabling a backend, and everything about the store, is superuser only" {
    local tier
    for tier in ro op; do
        as_user "$tier" yes -- backend enable tacacs
        assert_failure
        assert_output --partial "not permitted for the"
        as_user "$tier" yes -- backend disable tacacs -y
        assert_failure
        as_user "$tier" yes -- store show
        assert_failure
        assert_output --partial "'tacctl store show' is not permitted"
        as_user "$tier" yes -- store import --check
        assert_failure
        as_user "$tier" yes -- store rollback
        assert_failure
        as_user "$tier" yes -- config render
        assert_failure
    done
    as_user su yes -- store show
    assert_success
    assert_output --partial "secret"
    as_user su yes -- backend enable tacacs
    assert_success
    assert_output --partial "already enabled"
}

@test "config sudoers tiers: the backend verbs are in the read-only rule and pass a real visudo" {
    local visudo_bin
    visudo_bin=$(PATH="$PATH:/usr/sbin:/sbin" command -v visudo) || skip "visudo not installed"
    "$TACCTL_BIN_SCRIPT" config sudoers tiers show | sed -n 's/^    //p' > "$BATS_TEST_TMPDIR/tiers"
    grep -q 'backend list' "$BATS_TEST_TMPDIR/tiers"
    grep -q 'backend status \*' "$BATS_TEST_TMPDIR/tiers"
    ! grep -qE 'backend (enable|disable)' "$BATS_TEST_TMPDIR/tiers"
    run "$visudo_bin" -cf "$BATS_TEST_TMPDIR/tiers"
    assert_success
}

# --- the upgrade's refresh of the tiers drop-in ------------------------------------

# 'tacctl upgrade' with git, go and apt stubbed and no management repo to
# pull (radius.bats "upgrade: the output reads in order" has the recipe):
# tacctl's fixed host paths under TACCTL_TEST_ROOT, tacquito current.
_upgrade() {
    local root="${BATS_TEST_TMPDIR}/hostroot"
    mkdir -p "${root}/opt/tacctl/bin" "${root}/usr/local/go/bin" "${BATS_TEST_TMPDIR}/tacquito-src"
    : > "${root}/opt/tacctl/bin/tacctl.sh"
    printf '#!/bin/sh\n' > "${root}/usr/local/go/bin/go"
    chmod 755 "${root}/usr/local/go/bin/go"
    printf '#!/bin/sh\n' > "${TACCTL_BIN}/tacquito"
    stub_cmd git 'case "$*" in *"rev-parse --short HEAD"*) echo abc1234 ;; *"rev-parse"*) echo abc1234abc1234 ;; esac'
    stub_cmd dpkg-query 'echo "install ok installed"'
    stub_cmd apt-get
    stub_cmd ln
    run env TACCTL_TEST_ROOT="$root" TACQUITO_SRC="${BATS_TEST_TMPDIR}/tacquito-src" "$TACCTL_BIN_SCRIPT" upgrade
}

@test "upgrade: an installed tiers drop-in that differs is rewritten through visudo; a current one is left; none is never created" {
    mkdir -p "$(dirname "$TACCTL_TIER_SUDOERS_FILE")"
    stub_cmd visudo
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'
    _upgrade
    assert_success
    refute_output --partial "tiers sudoers"
    [[ ! -e "$TACCTL_TIER_SUDOERS_FILE" ]]
    if stub_called '^visudo '; then stub_calls; return 1; fi

    printf '# an older release\n' > "$TACCTL_TIER_SUDOERS_FILE"
    : > "$CALLS_LOG"
    _upgrade
    assert_success
    assert_output --partial "  Updated: tiers sudoers"
    stub_called '^visudo -cf '
    stub_called "^install -m 0440 -o root -g root .* ${TACCTL_TIER_SUDOERS_FILE}$"
    diff <("$TACCTL_BIN_SCRIPT" config sudoers tiers show | sed -n 's/^    //p') "$TACCTL_TIER_SUDOERS_FILE"

    : > "$CALLS_LOG"
    _upgrade
    assert_success
    assert_output --partial "  Unchanged: tiers sudoers"
    if stub_called '^(visudo|install) '; then stub_calls; return 1; fi
}

@test "upgrade: visudo refusing the new tiers rules leaves the old drop-in and warns; the upgrade finishes" {
    mkdir -p "$(dirname "$TACCTL_TIER_SUDOERS_FILE")"
    printf '# an older release\n' > "$TACCTL_TIER_SUDOERS_FILE"
    stub_cmd visudo 'exit 1'
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'
    _upgrade
    assert_success
    assert_output --partial "Not updated: tiers sudoers (visudo validation failed; ${TACCTL_TIER_SUDOERS_FILE} is unchanged)"
    assert_output --partial "Managed scripts:"
    [[ "$(cat "$TACCTL_TIER_SUDOERS_FILE")" == "# an older release" ]]
    if stub_called '^install '; then stub_calls; return 1; fi
}

@test "tier: an engineer reads the secret of a scope of their own, logged, and changes no secret" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    local secret
    secret=$("$TACCTL_BIN_SCRIPT" scope secret lab show | sed 's/\x1b\[[0-9;]*m//g' | sed -n 's/^  Value:  //p')
    [[ -n "$secret" ]]
    as_user en yes -- scope secret lab show
    assert_success
    assert_output --partial "$secret"
    stub_called "logger -t tacctl -p auth.info secret-read kind=scope name=lab by=en"
    run grep -c "secret-read.*${secret}" "$CALLS_LOG"
    assert_output "0"
    as_user en yes -- scope show lab
    assert_success
    refute_output --partial "$secret"
    # Another scope is unknown to them; nothing is changed.
    as_user en yes -- scope secret prod show
    assert_failure
    assert_output --partial "Scope 'prod' does not exist."
    as_user en yes -- scope show prod
    assert_failure
    as_user en yes -- scope secret lab generate
    assert_failure
    assert_output --partial "The engineer tier reads a scope's secret: tacctl scope secret lab show. Changing it is the superuser's. Nothing was changed."
    as_user en yes -- scope secret lab set Abcdefgh12345678xyz
    assert_failure
    run "$TACCTL_BIN_SCRIPT" scope secret lab show
    assert_output --partial "$secret"
    # The operator tier has neither.
    as_user op yes -- scope secret lab show
    assert_failure
    assert_output --partial "'tacctl scope secret' is not permitted for the operator tier."
}

@test "tier: scope breakglass is the superuser's; an engineer's walkthroughs show the accounts of their scope" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    printf 'tier:\n  superuser: engineer\n' >> "${TACCTL_STATE_DIR}/tacctl.yaml"
    local before
    before=$(cat "${TACCTL_STATE_DIR}/tacctl.yaml")
    local who args
    for who in ro op en; do
        for args in "scope breakglass lab" "scope breakglass lab list" "scope breakglass lab add x" "scope breakglass lab remove lab-admin"; do
            as_user "$who" yes -- $args
            assert_failure
            assert_output --partial "'tacctl scope breakglass' is not permitted for the "
        done
    done
    [[ "$(cat "${TACCTL_STATE_DIR}/tacctl.yaml")" == "$before" ]]
    # The sudoers rules of no lower tier name it.
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    refute_output --partial "breakglass"
    # The walkthroughs of their own scope carry the accounts (the lines are
    # comments with a placeholder).
    local v
    for v in cisco juniper wti; do
        as_user en yes -- config "$v" --scope lab
        assert_success
        assert_output --partial "lab-admin"
        assert_output --regexp "<(HASH|TYPE9-HASH|PASSWORD)>"
        assert_output --partial "Unfilled break-glass credentials"
    done
}

@test "tier: an engineer lists and shows the hosts of their own scopes and deploys none" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    printf 'web1|root@192.0.2.10||lab|192.0.2.1|\ndb1|root@192.0.2.11||prod|192.0.2.1|\nauthsrv|local||lab|127.0.0.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    local before
    before=$(cat "${TACCTL_STATE_DIR}/linux-hosts")
    as_user en yes -- host list
    assert_success
    assert_output --partial "web1"
    refute_output --partial "db1"
    as_user en yes -- host show web1
    assert_success
    as_user en yes -- host show db1
    assert_failure
    assert_output --partial "No enrolled host named 'db1'"
    # --check logs in to the host over ssh as the invoker: the superuser's.
    as_user en yes -- host show web1 --check
    assert_failure
    assert_output --partial "'host show --check' logs in to the host over ssh, which is the superuser's"
    # Enrolling, syncing and the rest of the deployment are the superuser's.
    local args
    for args in "enroll root@192.0.2.50 --name h1 --scope lab --server 192.0.2.1" "enroll --local --scope lab" "sync web1" "sync --all" \
        "move web1 lab" "target web1 root@192.0.2.20" "provisioner web1 rotate deploy2 --key /tmp/k --yes" "unenroll web1 --force" \
        "default-method" "default-method radius"; do
        as_user en yes -- host $args
        assert_failure
        assert_output --partial "'tacctl host ${args%% *}' is not permitted for the engineer tier."
    done
    [[ "$(cat "${TACCTL_STATE_DIR}/linux-hosts")" == "$before" ]]
    run "$TACCTL_BIN_SCRIPT" host default-method
    assert_output --partial "Default method for new hosts: tacplus"
    as_user op yes -- host list
    assert_failure
    assert_output --partial "not permitted for the operator tier"
}

@test "tier: the operator and read-only tiers do not get host provisioner" {
    "$TACCTL_BIN_SCRIPT" user add op2 operator --hash "$HASH" --scopes lab > /dev/null
    printf 'web1|admin@192.0.2.10||lab|192.0.2.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    as_user op2 yes -- host provisioner web1 rotate deploy2 --password
    assert_failure
    assert_output --partial "'tacctl host provisioner' is not permitted for the operator tier."
    as_user ro yes -- host provisioner web1 rotate deploy2 --password
    assert_failure
    assert_output --partial "'tacctl host provisioner' is not permitted for the readonly tier."
}

@test "tier: an engineer imports devices from standard input only" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    printf 'lab-sw,192.168.1.1\n' > "${BATS_TEST_TMPDIR}/devices.csv"
    as_user en yes -- device import "${BATS_TEST_TMPDIR}/devices.csv"
    assert_failure
    assert_output --partial "The engineer tier imports from standard input only: tacctl device import - [--check|--replace] < file"
    as_user en yes -- device import --check -
    assert_failure
    assert_output --partial "imports from standard input only"
    SUDO_USER=en run "$TACCTL_BIN_SCRIPT" device import - --check < "${BATS_TEST_TMPDIR}/devices.csv"
    assert_success
    assert_output --partial "Check passed"
}

@test "tier: an engineer prints the walkthrough of a device of their own scope; an operator may not" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    "$TACCTL_BIN_SCRIPT" device add lab-sw 192.168.1.1 --vendor cisco --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device add prod-sw 10.99.0.1 --vendor cisco --no-host-key > /dev/null
    as_user en yes -- device config show lab-sw
    assert_success
    assert_output --partial "Device lab-sw"
    assert_output --partial "(scope: lab)"
    as_user en yes -- device config show prod-sw
    assert_failure
    assert_output --partial "Device 'prod-sw' not found."
    as_user op yes -- device config show lab-sw
    assert_failure
    assert_output --partial "'tacctl device config show' is not permitted for the operator tier."
}

@test "tier: device config list is the operator's; show, pull and diff the engineer's; forget the superuser's" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    "$TACCTL_BIN_SCRIPT" device add lab-sw 192.168.1.1 --vendor cisco --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device add prod-sw 10.99.0.1 --vendor cisco --no-host-key > /dev/null
    # The operator lists; the other verbs say the operator tier may not.
    as_user op yes -- device config list
    assert_success
    assert_output --partial "lab-sw"
    for v in show pull diff forget; do
        as_user op yes -- device config "$v" lab-sw
        assert_failure
        assert_output --partial "'tacctl device config $v' is not permitted for the operator tier."
    done
    # The read-only tier does not get the family at all, and none of the
    # configuration state in the registry's views: no column, no row, no field.
    as_user ro yes -- device config list
    assert_failure
    assert_output --partial "'tacctl device config' is not permitted for the readonly tier."
    as_user ro yes -- device list
    assert_success
    assert_output --partial "lab-sw"
    refute_output --partial "CONFIG"
    as_user ro yes -- device show lab-sw
    assert_success
    refute_output --partial "Configuration:"
    as_user ro yes -- device list --json
    assert_success
    refute_output --partial '"config"'
    as_user op yes -- device list
    assert_success
    assert_output --partial "CONFIG"
    as_user op yes -- device show lab-sw
    assert_output --partial "Configuration: never pulled"
    # The engineer lists their own scopes' devices, and may not forget.
    as_user en yes -- device config list
    assert_success
    assert_output --partial "lab-sw"
    refute_output --partial "prod-sw"
    as_user en yes -- device config forget lab-sw
    assert_failure
    assert_output --partial "'tacctl device config forget' is not permitted for the engineer tier."
    as_user en yes -- device config pull prod-sw
    assert_failure
    assert_output --partial "Device 'prod-sw' not found."
}

@test "tier: an engineer pulls the devices of their own scope as themselves and the pull is audited" {
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    unset FAKEDEV_PID
    local jdir
    jdir=$(fakedev_dir junos)
    FAKEDEV_USER=en fakedev_start "$jdir"
    fakedev_register lab-j 192.168.1.20 juniper
    fakedev_serve "$jdir" juniper lab lab-j
    as_user en yes -- device config pull lab-j
    fakedev_stop
    assert_success
    assert_output --partial "lab-j  ok via netconf"
    # The login was the engineer's own, and the scope's secret read is logged
    # as the walkthrough logs it.
    stub_called 'logger -t tacctl -p auth.info device config pull user=en device=lab-j transport=netconf result=ok'
    stub_called 'logger -t tacctl -p auth.info secret-read kind=scope name=lab by=en'
}

@test "tier: group reset is the superuser's alone: no lower tier, the engineer included, and no sudoers rule" {
    # op is an engineer through its group's tier setting; ro stays readonly.
    printf 'tier:\n  operator: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl 10 > /dev/null
    cp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/store.before"
    cp "${TACCTL_STATE_DIR}/tacctl.yaml" "${BATS_TEST_TMPDIR}/yaml.before"
    for pair in ro:readonly op:engineer; do
        as_user "${pair%%:*}" yes -- group reset operator --yes
        assert_failure
        assert_output --partial "'tacctl group reset' is not permitted for the ${pair##*:} tier."
        as_user "${pair%%:*}" yes -- group reset engineer --preset --dry-run
        assert_failure
        assert_output --partial "'tacctl group reset' is not permitted for the ${pair##*:} tier."
    done
    run cmp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/store.before"
    assert_success
    run cmp "${TACCTL_STATE_DIR}/tacctl.yaml" "${BATS_TEST_TMPDIR}/yaml.before"
    assert_success
    # A plain operator (no tier setting), --dry-run included.
    rm -f "${TACCTL_STATE_DIR}/tacctl.yaml"
    for flag in --yes --dry-run; do
        as_user op yes -- group reset operator "$flag"
        assert_failure
        assert_output --partial "'tacctl group reset' is not permitted for the operator tier."
    done
    run cmp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/store.before"
    assert_success
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    refute_output --partial "group reset"
    refute_output --partial "group preset"
    # The superuser sees the diff.
    as_user su yes -- group reset operator --dry-run
    assert_success
    assert_output --partial "Cisco priv-lvl:  10 -> 7"
}

@test "tier: group privilege reset and group commands reset are the superuser's alone: no lower tier, the engineer included, and no sudoers rule" {
    printf 'tier:\n  operator: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    "$TACCTL_BIN_SCRIPT" group commands add operator configure --action permit > /dev/null
    "$TACCTL_BIN_SCRIPT" group privilege add operator 'show version' > /dev/null
    cp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/store.before"
    cp "${TACCTL_STATE_DIR}/tacctl.yaml" "${BATS_TEST_TMPDIR}/yaml.before"
    local fam flag pair
    for fam in privilege commands; do
        for pair in ro:readonly op:engineer; do
            for flag in --yes --dry-run; do
                as_user "${pair%%:*}" yes -- group "$fam" reset operator "$flag"
                assert_failure
                assert_output --partial "'tacctl group $fam' is not permitted for the ${pair##*:} tier."
            done
        done
    done
    run cmp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/store.before"
    assert_success
    run cmp "${TACCTL_STATE_DIR}/tacctl.yaml" "${BATS_TEST_TMPDIR}/yaml.before"
    assert_success
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    refute_output --partial "group privilege"
    refute_output --partial "group commands"
    # The superuser sees the diff.
    as_user su yes -- group privilege reset operator --dry-run
    assert_success
    assert_output --partial "    - show version"
    as_user su yes -- group commands reset operator --dry-run
    assert_success
    assert_output --partial "    - configure    permit"
}

@test "tier: a tacctl.yaml that cannot be read caps every tacctl user at the operator tier" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n  - [broken\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    as_user su yes -- host sync web1
    assert_failure
    assert_output --partial "is not permitted: ${TACCTL_STATE_DIR}/tacctl.yaml cannot be read ("
    assert_output --partial "so no tacctl user is trusted above the operator tier until it is fixed (tacctl config validate)."
    stub_called "logger -t tacctl -p auth.warning tier DENY user=su tier=operator reason=conf-problem cmd=host sync"
    as_user su yes -- config validate
    refute_output --partial "is not permitted"
    # A tier setting that is not a tier is read-only, not the band.
    printf 'tier:\n  superuser: root\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    as_user su yes -- user list
    assert_success
    as_user su yes -- log tail
    assert_failure
    assert_output --partial "not permitted for the readonly tier"
}

@test "tier: a tier setting of any other shape is read-only, never the band, and the syncs refuse" {
    local yaml
    for yaml in $'tier:\n  superuser: {x: engineer}\n' $'tier:\n  superuser: [engineer]\n' $'tier:\n  superuser:\n' \
                $'tier:\n  superuser: \'\'\n' $'tier: engineer\n' $'tier: [superuser]\n' $'tier:\n  superuser: Engineer\n'; do
        printf '%s' "$yaml" > "${TACCTL_STATE_DIR}/tacctl.yaml"
        as_user su yes -- user list
        assert_success
        as_user su yes -- log tail
        assert_failure
        assert_output --partial "not permitted for the readonly tier"
    done
    printf 'tier:\n  superuser: [engineer]\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_failure 1
    assert_output --partial "cannot be read ('tier.superuser' must be one of readonly, operator, engineer, superuser); accounts and tiers are not synced until it is fixed."
    printf 'tier: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" host sync --all
    assert_failure 1
    assert_output --partial "cannot be read ('tier' must be a mapping of group names to tiers); accounts and tiers are not synced until it is fixed."
    # The verb that writes the setting repairs it.
    run "$TACCTL_BIN_SCRIPT" group edit superuser tier superuser
    assert_success
    as_user su yes -- log tail
    assert_success
}

@test "tier: a group at priv-lvl 15 has an explicit tier; one that lost it holds back only its own members" {
    rm -f "${TACCTL_STATE_DIR}/tacctl.yaml"
    as_user su yes -- config validate
    assert_success
    # A managed superuser adds the group with no tacctl.yaml: the tier is
    # recorded, and nobody is locked out.
    as_user su yes -- group add neteng 15 EN-CLASS
    assert_success
    assert_output --partial "tacctl tier: superuser (recorded, as every group at priv-lvl 15 has one; change it with: tacctl group edit neteng tier <tier>)."
    grep -q 'neteng: superuser' "${TACCTL_STATE_DIR}/tacctl.yaml"
    as_user su yes -- group edit neteng tier engineer
    assert_success
    "$TACCTL_BIN_SCRIPT" group edit neteng tier superuser > /dev/null
    "$TACCTL_BIN_SCRIPT" user add en neteng --hash "$HASH" --scopes lab > /dev/null
    printf 'web1|root@192.0.2.10||lab|192.0.2.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    # The setting is lost (a restored older file): its members are held at the
    # operator tier (the gate names the group and the verb); a sync is not
    # refused, it gives them the operator tier and prints the repair.
    printf 'backends:\n  enabled: [tacacs]\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    as_user en yes -- host sync web1
    assert_failure
    assert_output --partial "is not permitted: your group 'neteng' is at priv-lvl 15 or more and has no tier setting in ${TACCTL_STATE_DIR}/tacctl.yaml (it was lost)"
    run "$TACCTL_BIN_SCRIPT" host sync web1
    assert_output --partial "Group 'neteng' (priv-lvl 15) has no tier setting in ${TACCTL_STATE_DIR}/tacctl.yaml, so its members are synced as operators (no tac-superuser, no tac-engineer) until: tacctl group edit neteng tier <tier>"
    refute_output --partial "accounts are not synced"
    # The built-in superuser group is not affected, and repairs it.
    as_user su yes -- group show neteng
    assert_success
    assert_output --partial "NOT SET"
    as_user su yes -- group edit neteng tier engineer
    assert_success
    grep -q 'neteng: engineer' "${TACCTL_STATE_DIR}/tacctl.yaml"
    as_user su yes -- host sync web1
    refute_output --partial "is not permitted"
    refute_output --partial "has no tier setting"
}

@test "tier: a built-in group raised to priv-lvl 15 with a lost tier setting is ambiguous, not a superuser group" {
    "$TACCTL_BIN_SCRIPT" group edit operator tier engineer > /dev/null
    "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl 15 > /dev/null
    grep -q 'operator: engineer' "${TACCTL_STATE_DIR}/tacctl.yaml"
    as_user op yes -- _console-policy
    assert_output --partial " tier=engineer "
    # The file is restored without its tier section.
    rm -f "${TACCTL_STATE_DIR}/tacctl.yaml"
    as_user op yes -- _console-policy
    assert_output --partial " tier=operator "
    as_user op yes -- host sync web1
    assert_failure
    assert_output --partial "your group 'operator' is at priv-lvl 15 or more and has no tier setting"
    # The built-in superuser group is never ambiguous.
    as_user su yes -- _console-policy
    assert_output --partial " tier=superuser "
    as_user su yes -- group show operator
    assert_success
    assert_output --partial "NOT SET"
}

@test "tier: group edit priv-lvl keeps the tier setting of a custom group in step with the band" {
    "$TACCTL_BIN_SCRIPT" group add mid 10 MID-CLASS > /dev/null
    run "$TACCTL_BIN_SCRIPT" group edit mid priv-lvl 15
    assert_success
    assert_output --partial "tacctl tier: superuser (recorded"
    grep -q 'mid: superuser' "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" group edit mid priv-lvl 9
    assert_success
    assert_output --partial "tacctl tier: automatic again"
    ! grep -q 'mid:' "${TACCTL_STATE_DIR}/tacctl.yaml"
}

@test "tier: nobody enrolls this machine under an address of it, and an engineer enrolls nothing" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    printf 'web1|root@192.0.2.10||lab|192.0.2.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    stub_cmd getent 'if [[ "$1 $2" == "ahostsv4 0.0.0.0" || "$1 $2" == "ahostsv4 0" ]]; then echo "0.0.0.0 STREAM $2"; fi'
    local before
    before=$(cat "${TACCTL_STATE_DIR}/linux-hosts")
    as_user en yes -- host enroll root@0.0.0.0 --name sneaky --scope lab --server 192.0.2.1
    assert_failure
    assert_output --partial "'tacctl host enroll' is not permitted for the engineer tier."
    as_user en yes -- host target web1 root@0
    assert_failure
    assert_output --partial "'tacctl host target' is not permitted for the engineer tier."
    [[ "$(cat "${TACCTL_STATE_DIR}/linux-hosts")" == "$before" ]]
    # The superuser is told to use --local for this machine.
    run "$TACCTL_BIN_SCRIPT" host enroll root@0.0.0.0 --name sneaky --scope lab --server 192.0.2.1
    assert_failure
    assert_output --partial "'root@0.0.0.0' is this server; enroll it with --local"
    [[ "$(cat "${TACCTL_STATE_DIR}/linux-hosts")" == "$before" ]]
}

@test "tier: an engineer reads the SNMP settings of a scope of their own (logged on --reveal) and changes none" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    printf 'lab-community-bats\n' | "$TACCTL_BIN_SCRIPT" scope snmp lab community --stdin > /dev/null
    "$TACCTL_BIN_SCRIPT" scope snmp lab clients add 198.51.100.0/24 > /dev/null
    as_user en yes -- scope snmp lab show
    assert_success
    refute_output --partial "lab-community-bats"
    if stub_called "secret-read kind=snmp"; then echo "plain show was logged"; return 1; fi
    as_user en yes -- scope snmp lab show --reveal
    assert_success
    assert_output --partial "lab-community-bats"
    stub_called "logger -t tacctl -p auth.info secret-read kind=snmp name=lab by=en"
    run grep -c "secret-read.*lab-community-bats" "$CALLS_LOG"
    assert_output "0"
    as_user en yes -- scope snmp lab clients list
    assert_success
    assert_output --partial "198.51.100.0/24"
    # Another scope is unknown to them.
    as_user en yes -- scope snmp prod show --reveal
    assert_failure
    assert_output --partial "Scope 'prod' does not exist."
    # No setter, no clear, no test.
    local args
    for args in "community --stdin" "version v3" "clients add 192.0.2.0/24" "contact x" "port 162" "clear" "test 127.0.0.1"; do
        # shellcheck disable=SC2086
        as_user en yes -- scope snmp lab $args
        assert_failure
        assert_output --partial "The engineer tier reads a scope's SNMP settings"
    done
    run "$TACCTL_BIN_SCRIPT" scope snmp lab show --reveal
    assert_output --partial "lab-community-bats"
    # The default's credentials, and the operator, are shut out.
    as_user en yes -- config snmp show --reveal
    assert_failure
    assert_output --partial "'tacctl config snmp' is not permitted for the engineer tier."
    as_user op yes -- scope snmp lab show
    assert_failure
    assert_output --partial "'tacctl scope snmp' is not permitted for the operator tier."
    # device location is the engineer's, in their own scopes.
    "$TACCTL_BIN_SCRIPT" device add lab-sw1 192.168.1.1 --no-host-key > /dev/null
    as_user en yes -- device location lab-sw1 "Rack 4"
    assert_success
    as_user op yes -- device location lab-sw1 "Rack 5"
    assert_failure
    assert_output --partial "not permitted for the operator tier."
}

@test "tier: an engineer's walkthrough shows the SNMP credentials of their own scope, logged" {
    "$TACCTL_BIN_SCRIPT" user add en superuser --hash "$HASH" --scopes lab > /dev/null
    printf 'tier:\n  superuser: engineer\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    printf 'lab-community-bats\n' | "$TACCTL_BIN_SCRIPT" scope snmp lab community --stdin > /dev/null
    as_user en yes -- config cisco --scope lab
    assert_success
    assert_output --partial "snmp-server community lab-community-bats RO TACCTL-SNMP"
    assert_output --partial "NETCONF (netconf-yang) is enabled by a superuser"
    stub_called "logger -t tacctl -p auth.info secret-read kind=snmp name=lab by=en"
}
