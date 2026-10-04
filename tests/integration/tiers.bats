#!/usr/bin/env bats
# Integration tests for the RO/OP/SU caller-tier gate, self-service
# 'tacctl passwd', and the per-tier sudoers drop-in.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

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

@test "config sudoers tiers: generated rules pass a real visudo" {
    local visudo_bin
    visudo_bin=$(PATH="$PATH:/usr/sbin:/sbin" command -v visudo) || skip "visudo not installed"
    "$TACCTL_BIN_SCRIPT" config sudoers tiers show | sed -n 's/^    //p' > "$BATS_TEST_TMPDIR/tiers"
    run "$visudo_bin" -cf "$BATS_TEST_TMPDIR/tiers"
    assert_success
}

@test "config sudoers tiers: lower tiers get no secret-bearing or mutating command" {
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    refute_output --partial "config cisco"
    refute_output --partial "scope show"
    refute_output --partial "backup diff"
    refute_output --partial "user passwd"
    refute_output --partial "log clear"
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
