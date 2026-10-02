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

@test "tier: store show never reaches the read-only tier, in the gate or in sudoers" {
    run "$TACCTL_BIN_SCRIPT" config sudoers tiers show
    refute_output --partial "store"
    run bash -c 'source "$1"; for t in readonly operator; do tier_permits "$t" store show && echo "$t permitted"; done; exit 0' _ "$TACCTL_BIN_SCRIPT"
    refute_output --partial "permitted"
}

# The gate (tier_permits) and the sudoers rules (emit_tier_sudoers) are written
# apart and must say the same. The rules' command lists are read from the
# emitted text; every verb the CLI has that could be told apart is asked of
# both for each lower tier.
@test "tier gate and sudoers rules agree on every verb, for each lower tier" {
    run bash -c '
        source "$1"
        t=/usr/local/bin/tacctl
        text=$(emit_tier_sudoers)
        alias_of() { # name -> its commands, one per line, without the binary path
            printf "%s\n" "$text" | python3 -c "
import re, sys
text = sys.stdin.read().replace(\"\\\\\n\", \" \")
m = re.search(r\"^Cmnd_Alias \" + sys.argv[1] + r\" = (.*)$\", text, re.M)
for item in m.group(1).split(\",\"):
    item = item.strip()
    assert item.startswith(sys.argv[2]), item
    print(item[len(sys.argv[2]):].strip())
" "$1" "$t"
        }
        ro=$(alias_of TACCTL_RO)
        op=$(alias_of TACCTL_OP)
        in_alias() { # <alias text> <cmd> <sub>: is "cmd sub" (or "cmd sub *") listed?
            printf "%s\n" "$1" | grep -qxE -- "$2 $3( \*)?"
        }
        bad=""
        # every verb the usage texts offer a lower tier could ask for
        while read -r cmd sub; do
            in_ro=no; in_op=no
            in_alias "$ro" "$cmd" "$sub" && in_ro=yes
            in_alias "$op" "$cmd" "$sub" && in_op=yes
            tier_permits readonly "$cmd" "$sub" && g_ro=yes || g_ro=no
            tier_permits operator "$cmd" "$sub" && g_op=yes || g_op=no
            [[ "$g_ro" == "$in_ro" ]] || bad+=" readonly:${cmd}/${sub}(gate=${g_ro},sudoers=${in_ro})"
            [[ "$g_op" == yes && ( "$in_ro" == yes || "$in_op" == yes ) || "$g_op" == no && "$in_ro" == no && "$in_op" == no ]] \
                || bad+=" operator:${cmd}/${sub}(gate=${g_op},sudoers=${in_ro}/${in_op})"
        done <<LIST
user list
user show
user add
user remove
user passwd
group list
group add
scope list
scope show
scope secret
scope protocols
backend list
backend status
backend enable
backend disable
store show
store import
store rollback
config validate
config show
config render
config dump
config cisco
config sudoers
log tail
log search
log failures
log accounting
log clear
backup list
backup diff
backup restore
host list
host enroll
LIST
        # a verb in a rule the gate does not know is as wrong
        while read -r item; do
            [[ -n "$item" && "$item" != \"\"* ]] || continue
            set -- ${item% \*}
            [[ $# -ge 2 ]] || continue
            tier_permits readonly "$1" "$2" || tier_permits operator "$1" "$2" || bad+=" sudoers-only:${item}"
        done <<< "$ro
$op"
        echo "disagreements:${bad:- none}"
    ' _ "$TACCTL_BIN_SCRIPT"
    assert_success
    assert_output "disagreements: none"
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
