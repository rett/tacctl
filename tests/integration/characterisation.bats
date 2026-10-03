#!/usr/bin/env bats
# Characterisation tests: CLI behaviour of the 0.1.16 bash implementation that
# no other test pins (docs/plans/go-rewrite.md 2.2 "Blind spots", WP0.2).
# They are written against bash and are green on it first; once a verb is cut
# over to Go the same tests run against the Go binary and must stay green
# (parity rule: a failure there means the Go port is wrong, unless the plan's
# 3.9 lists the difference). Covered: `hash generate|commands`, `user verify`,
# the generated-password path of `user add|passwd`, `config defaults`,
# `config branch`, the argument handling of `install|upgrade --branch`, and the
# top-level and per-family usage blocks.
#
# Quirks worth knowing before "fixing" one: `user verify` exits 0 on a wrong
# password (it only prints an error), a closed stdin is the same as a blank
# password line (a password is generated), `upgrade --branch` with no value
# exits 1 without a word (a failed `shift` under `set -e`).
#
# Cut-over tags (`# bats test_tags=cutover:wp2-4a`): the work package that moves
# the verb to Go. A package checks its verbs with
#   TACCTL_IMPL=go tests/bats/bats-core/bin/bats --filter-tags cutover:wp2-4a \
#       tests/integration/characterisation.bats
# (tests/blackbox.list runs the whole file against Go only once the last of
# them, WP3.3d, is done). `bash-only` marks what cannot move as it is.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

bats_require_minimum_version 1.5.0

ESC=$'\e'
USAGE_DIR="${TACCTL_SRC}/internal/cli/testdata/usage"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    # `user verify` waits half a second after a wrong password.
    stub_cmd sleep
    load_fixture tacquito.minimal.yaml
}

# --- helpers ----------------------------------------------------------------

# bcrypt at its cheapest, so tests that hash many passwords stay quick. The
# default cost (12) has its own test.
fast_bcrypt() {
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 10 > /dev/null 2>&1
}

# runs <command...>: like bats' run, for commands whose stdout and stderr both
# matter. Sets status, output and stderr (trailing newlines stripped, nothing
# else touched: bats' own splitting would eat the blank lines and the leading
# blanks of the first line that these tests pin) and lines / stderr_lines.
runs() {
    local o="${BATS_TEST_TMPDIR}/runs.out" e="${BATS_TEST_TMPDIR}/runs.err"
    status=0
    "$@" > "$o" 2> "$e" || status=$?
    output=$(<"$o")
    stderr=$(<"$e")
    mapfile -t lines < <(printf '%s\n' "$output")
    mapfile -t stderr_lines < <(printf '%s\n' "$stderr")
    [[ -n "$output" ]] || lines=()
    [[ -n "$stderr" ]] || stderr_lines=()
}

# refute_called <regex>: no stub was called with a line matching the regex.
# (A bare `! stub_called ...` would not fail a bats test: errexit ignores `!`.)
refute_called() {
    if stub_called "$1"; then
        echo "unexpected call matching '$1':" >&2
        stub_calls >&2
        return 1
    fi
}

plain() { sed -E "s/${ESC}\[[0-9;]*m//g"; }

# The hex hash `hash generate` printed: the one line of 100+ hex digits.
hash_of() {
    printf '%s\n' "$1" | sed -n 's/^  \([0-9a-f]\{100,\}\)$/\1/p'
}

# make_user <name> <password> [group]: a user whose password is known.
make_user() {
    local hash
    hash=$(printf '%s\n%s\n' "$2" "$2" | "$TACCTL_BIN_SCRIPT" hash generate 2> /dev/null)
    hash=$(hash_of "$hash")
    [[ -n "$hash" ]] || return 1
    "$TACCTL_BIN_SCRIPT" user add "$1" "${3:-superuser}" --hash "$hash" --scopes lab > /dev/null 2>&1
}

# The password "Generated password:" announced on stderr.
generated_password() {
    printf '%s\n' "$1" | sed -n "s/^  Generated password: ${ESC}\[1m\(.*\)${ESC}\[0m\$/\1/p"
}

# usage_case <name>: run the case of internal/cli/testdata/usage/cases.tsv
# and compare stdout and the exit code with the golden block, which
# tests/tools/usage-goldens.sh generated from the 0.1.16 tag.
usage_case() {
    local name="$1" line want_rc argv got
    line=$(awk -F'\t' -v n="$name" '$1 == n' "${USAGE_DIR}/cases.tsv")
    [[ -n "$line" ]] || { echo "no usage case '$name'" >&2; return 1; }
    IFS=$'\t' read -r _ want_rc argv <<< "$line"
    local -a args=()
    read -ra args <<< "$argv"
    runs "$TACCTL_BIN_SCRIPT" "${args[@]}" < /dev/null
    assert_equal "$status" "$want_rc"
    assert_equal "$stderr" ""
    # The generator wrote the production state path and no version.
    got=$(printf '%s\n' "$output" \
        | sed -E "s#${TACCTL_STATE_DIR}/#/etc/tacctl/#g; 1,3s/(tacctl${ESC}\[0m) \([^)]*\)/\1 (unknown)/")
    assert_equal "$got" "$(cat "${USAGE_DIR}/${name}.out")"
}

# --- top-level and per-family usage ------------------------------------------

# bats test_tags=cutover:wp0-1
@test "usage: no command prints the top-level usage on stdout, exit 1" {
    usage_case top
}

# bats test_tags=cutover:wp0-1
@test "usage: help, -h, --help and an unknown word print the same usage, exit 1" {
    local want
    want=$("$TACCTL_BIN_SCRIPT" < /dev/null || true)
    for word in help -h --help bogus 'user-add'; do
        runs "$TACCTL_BIN_SCRIPT" "$word" < /dev/null
        assert_equal "$status" 1
        assert_equal "$stderr" ""
        assert_equal "$output" "$want"
    done
}

# bats test_tags=cutover:wp0-1
@test "usage: the top-level usage names the version of the tree" {
    runs "$TACCTL_BIN_SCRIPT" < /dev/null
    local ver
    ver=$("$TACCTL_BIN_SCRIPT" version | sed 's/^tacctl //')
    [[ -n "$ver" ]]
    [[ "$(plain <<< "${lines[1]}")" == "tacctl (${ver}) — TACACS+ (tacquito) and RADIUS (FreeRADIUS) from one store" ]]
}

# bats test_tags=cutover:wp0-1
@test "version, --version and -v print 'tacctl <version>' and exit 0" {
    local want
    want=$("$TACCTL_BIN_SCRIPT" version)
    [[ "$want" =~ ^tacctl\ [^[:space:]]+$ ]]
    for word in --version -v; do
        runs "$TACCTL_BIN_SCRIPT" "$word"
        assert_success
        assert_output "$want"
        assert_equal "$stderr" ""
    done
}

# bats test_tags=cutover:wp2-4a
@test "usage block: tacctl user (exit 1)"             { usage_case user; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl group (exit 1)"            { usage_case group; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl group commands"            { usage_case group-commands; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl group privilege"           { usage_case group-privilege; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl scope (exit 0)"            { usage_case scope; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl scope prefixes"            { usage_case scope-prefixes; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl scope secret"              { usage_case scope-secret; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl scope mgmt-acl"            { usage_case scope-mgmt-acl; }
# bats test_tags=cutover:wp2-4c
@test "usage block: tacctl config (exit 1)"           { usage_case config; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl config allow"              { usage_case config-allow; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl config deny"               { usage_case config-deny; }
# bats test_tags=cutover:wp2-4b
@test "usage block: tacctl config mgmt-acl"           { usage_case config-mgmt-acl; }
# bats test_tags=cutover:wp3-1
@test "usage block: tacctl config linux"              { usage_case config-linux; }
# bats test_tags=cutover:wp3-2
@test "usage block: tacctl host (exit 0)"             { usage_case host; }
# bats test_tags=cutover:wp2-4d
@test "usage block: tacctl backend (exit 1)"          { usage_case backend; }
# bats test_tags=cutover:wp2-4d
@test "usage block: tacctl store (exit 0)"            { usage_case store; }
# bats test_tags=cutover:wp2-4d
@test "usage block: tacctl log (exit 1)"              { usage_case log; }
# bats test_tags=cutover:wp2-4d
@test "usage block: tacctl backup (exit 1)"           { usage_case backup; }
# bats test_tags=cutover:wp2-4a
@test "usage block: tacctl hash (exit 0)"             { usage_case hash; }

# --- hash ---------------------------------------------------------------------

# bats test_tags=cutover:wp2-4a
@test "hash: help, -h, --help print the usage and exit 0; an unknown word exits 1" {
    local want
    want=$("$TACCTL_BIN_SCRIPT" hash)
    for word in help -h --help; do
        runs "$TACCTL_BIN_SCRIPT" hash "$word"
        assert_success
        assert_output "$want"
        assert_equal "$stderr" ""
    done
    runs "$TACCTL_BIN_SCRIPT" hash bogus
    assert_failure 1
    assert_output "$want"
    assert_equal "$stderr" "${ESC}[0;31m[ERROR]${ESC}[0m Unknown subcommand: 'bogus'"
}

# bats test_tags=cutover:wp2-4a
@test "hash: needs neither a store nor tacquito.yaml" {
    rm -rf "${TACCTL_STATE_DIR}" "${TACCTL_CONFIG}"
    run "$TACCTL_BIN_SCRIPT" hash commands
    assert_success
    run "$TACCTL_BIN_SCRIPT" hash
    assert_success
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: a typed, confirmed password gives a bcrypt hash; prompts go to stderr" {
    runs "$TACCTL_BIN_SCRIPT" hash generate <<< $'CorrectHorse99\nCorrectHorse99'
    assert_success
    local hash
    hash=$(hash_of "$output")
    [[ "$hash" =~ ^24326224313224[0-9a-f]{106}$ ]]   # hex of '$2b$12$' + 53 characters
    assert_equal "${#lines[@]}" 7
    assert_equal "${lines[0]}" ""
    assert_equal "${lines[1]}" "  Bcrypt hash (provide this to your admin):"
    assert_equal "${lines[2]}" ""
    assert_equal "${lines[3]}" "  ${hash}"
    assert_equal "${lines[4]}" ""
    assert_equal "${lines[5]}" "  Admin command:"
    assert_equal "${lines[6]}" "    tacctl user add <username> <group> --hash '${hash}'"
    # The prompts echo '*' per typed character, then a newline.
    assert_equal "${stderr_lines[0]}" "  Enter password (leave blank to auto-generate): **************"
    assert_equal "${stderr_lines[1]}" "  Confirm password: **************"
    assert_equal "${#stderr_lines[@]}" 2
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: salted, so the same password gives two different hashes" {
    fast_bcrypt
    local a b
    a=$(hash_of "$("$TACCTL_BIN_SCRIPT" hash generate 2> /dev/null <<< $'CorrectHorse99\nCorrectHorse99')")
    b=$(hash_of "$("$TACCTL_BIN_SCRIPT" hash generate 2> /dev/null <<< $'CorrectHorse99\nCorrectHorse99')")
    [[ -n "$a" && -n "$b" && "$a" != "$b" ]]
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: the cost is bcrypt.cost from the config" {
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 10 > /dev/null 2>&1
    runs "$TACCTL_BIN_SCRIPT" hash generate <<< $'CorrectHorse99\nCorrectHorse99'
    assert_success
    [[ "$(hash_of "$output")" =~ ^24326224313024[0-9a-f]{106}$ ]]   # '$2b$10$'
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 11 > /dev/null 2>&1
    runs "$TACCTL_BIN_SCRIPT" hash generate <<< $'CorrectHorse99\nCorrectHorse99'
    [[ "$(hash_of "$output")" =~ ^24326224313124[0-9a-f]{106}$ ]]   # '$2b$11$'
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: the hash is the password's: it works as --hash and verifies" {
    fast_bcrypt
    make_user alice 'CorrectHorse99'
    runs "$TACCTL_BIN_SCRIPT" user verify alice <<< 'CorrectHorse99'
    assert_success
    assert_output --partial "Password is correct."
    runs "$TACCTL_BIN_SCRIPT" user verify alice <<< 'CorrectHorse98'
    [[ "$stderr" == *"Password does not match."* ]]
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: a blank line or a closed stdin generates a password and announces it on stderr" {
    fast_bcrypt
    local variant
    for variant in blank closed; do
        if [[ "$variant" == blank ]]; then
            runs "$TACCTL_BIN_SCRIPT" hash generate <<< ''
        else
            runs "$TACCTL_BIN_SCRIPT" hash generate < /dev/null
        fi
        assert_success
        assert_equal "${stderr_lines[0]}" "  Enter password (leave blank to auto-generate): "
        local pw hash
        pw=$(generated_password "$stderr")
        [[ "$pw" =~ ^[A-Za-z0-9+/]{24}$ ]]            # openssl rand -base64 18
        assert_equal "${#stderr_lines[@]}" 2
        hash=$(hash_of "$output")
        [[ -n "$hash" ]]
        # The announced password is the hash's.
        "$TACCTL_BIN_SCRIPT" user add "bob_${variant}" operator --hash "$hash" --scopes lab > /dev/null 2>&1
        runs "$TACCTL_BIN_SCRIPT" user verify "bob_${variant}" <<< "$pw"
        assert_output --partial "Password is correct."
    done
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: refuses a short password" {
    runs "$TACCTL_BIN_SCRIPT" hash generate <<< 'short'
    assert_failure 1
    assert_output ""
    assert_equal "${stderr_lines[0]}" "  Enter password (leave blank to auto-generate): *****"
    assert_equal "${stderr_lines[1]}" "${ESC}[0;31m[ERROR]${ESC}[0m Password is 5 characters; minimum is 12."
    assert_equal "${#stderr_lines[@]}" 2
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: the minimum length is password.min_length" {
    "$TACCTL_BIN_SCRIPT" config password-min-length 8 > /dev/null 2>&1
    runs "$TACCTL_BIN_SCRIPT" hash generate <<< $'longenough\nlongenough'
    assert_success
    runs "$TACCTL_BIN_SCRIPT" hash generate <<< 'seven77'
    assert_failure 1
    [[ "$stderr" == *"Password is 7 characters; minimum is 8."* ]]
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: refuses a password on the common-weak list" {
    local pw
    for pw in 'Password1' 'qwertyuiop123' '123456789012' 'aaaaaaaaaaaa'; do
        "$TACCTL_BIN_SCRIPT" config password-min-length 8 > /dev/null 2>&1
        runs "$TACCTL_BIN_SCRIPT" hash generate <<< "$pw"
        assert_failure 1
        assert_output ""
        [[ "$stderr" == *"Password is on the common-weak list. Choose another."* ]]
    done
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: a confirmation that differs fails; the message is on stderr" {
    runs "$TACCTL_BIN_SCRIPT" hash generate <<< $'CorrectHorse99\nCorrectHorse98'
    assert_failure 1
    assert_output ""
    assert_equal "${stderr_lines[0]}" "  Enter password (leave blank to auto-generate): **************"
    assert_equal "${stderr_lines[1]}" "  Confirm password: **************"
    assert_equal "${stderr_lines[2]}" "  ${ESC}[0;31mPasswords do not match.${ESC}[0m"
}

# Bash looks for the bcrypt module by importing it; the Go port has no
# python3 and drops the check (plan 3.5 / 3.9).
# bats test_tags=bash-only
@test "hash generate: without python3-bcrypt it says so and points at 'hash commands'" {
    # Only the import check fails; every other python3 call (the config
    # loader, the model) still works.
    local real_python
    real_python=$(command -v python3)
    cat > "${STUB_BIN}/python3" <<STUB
#!/usr/bin/env bash
[[ "\$*" == "-c import bcrypt" ]] && exit 1
exec ${real_python} "\$@"
STUB
    chmod +x "${STUB_BIN}/python3"
    runs "$TACCTL_BIN_SCRIPT" hash generate <<< $'CorrectHorse99\nCorrectHorse99'
    assert_failure 1
    assert_output ""
    assert_equal "$stderr" "${ESC}[0;31m[ERROR]${ESC}[0m python3-bcrypt not installed. Run 'tacctl hash commands' for client-side alternatives."
}

# bats test_tags=cutover:wp2-4a
@test "hash generate: changes nothing on disk" {
    fast_bcrypt
    local before after
    before=$(cd "${BATS_TEST_TMPDIR}" && find . -path ./stubs -prune -o -path ./calls.log -prune -o -type f -print0 | sort -z | xargs -0 sha256sum)
    "$TACCTL_BIN_SCRIPT" hash generate > /dev/null 2>&1 <<< $'CorrectHorse99\nCorrectHorse99'
    "$TACCTL_BIN_SCRIPT" hash commands > /dev/null
    after=$(cd "${BATS_TEST_TMPDIR}" && find . -path ./stubs -prune -o -path ./calls.log -prune -o -type f -print0 | sort -z | xargs -0 sha256sum)
    assert_equal "$after" "$before"
}

# bats test_tags=cutover:wp2-4a
@test "hash commands: prints the client-side recipes, exactly" {
    local want
    want=$(cat <<'EOF'

  Bcrypt hash generation — client-side recipes
  (run on the operator's machine; plaintext password never leaves it)

  =================================================================
  Any OS — Python 3 with the 'bcrypt' module
  =================================================================
    # install once:  python3 -m pip install --user bcrypt
    #                (use 'py' instead of 'python3' on Windows)
    python3 -c "import bcrypt,binascii,getpass; p=getpass.getpass('Password: ').encode(); r=bcrypt.hashpw(p,bcrypt.gensalt(12)); print('raw:',r.decode()); print('hex:',binascii.hexlify(r).decode())"

  =================================================================
  Linux / macOS — htpasswd (no Python needed)
  =================================================================
    # install once:  apt install apache2-utils  OR  brew install httpd
    htpasswd -nBC 12 "" | cut -d: -f2

  =================================================================
  Handing the hash to your admin
  =================================================================
  'tacctl user passwd --hash' accepts either form; the server
  normalizes to hex internally. So either line works:
      tacctl user passwd <user> --hash '$2b$12$...'          # raw
      tacctl user passwd <user> --hash '24326224313224...'   # hex

EOF
)
    runs "$TACCTL_BIN_SCRIPT" hash commands
    assert_success
    assert_equal "$output" "$want"
    assert_equal "$stderr" ""
}

# --- user verify --------------------------------------------------------------

# bats test_tags=cutover:wp2-4a
@test "user verify: a right password prints the details and 'Password is correct.' (raw colours)" {
    fast_bcrypt
    make_user alice 'CorrectHorse99'
    runs "$TACCTL_BIN_SCRIPT" user verify alice <<< 'CorrectHorse99'
    assert_success
    local today
    today=$(date +%Y-%m-%d)
    local want
    want=$(printf '%s\n' \
        "" \
        "  ${ESC}[1mUser:${ESC}[0m           alice" \
        "  ${ESC}[1mGroup:${ESC}[0m          superuser" \
        "  ${ESC}[1mStatus:${ESC}[0m         ${ESC}[0;32mactive${ESC}[0m" \
        "  ${ESC}[1mPW changed:${ESC}[0m     ${today}" \
        "" \
        "${ESC}[0;32m[INFO]${ESC}[0m Password is correct." \
        "")
    assert_equal "$output" "${want%$'\n'}"
    # The prompt goes to stderr, the typed characters echoed as '*'.
    assert_equal "$stderr" "  Enter password to verify: **************"
}

# bats test_tags=cutover:wp2-4a
@test "user verify: a wrong password prints the details, an error on stderr, and still exits 0" {
    fast_bcrypt
    make_user alice 'CorrectHorse99'
    runs "$TACCTL_BIN_SCRIPT" user verify alice <<< 'nope'
    assert_success
    [[ "$(plain <<< "$output")" == *"User:           alice"* ]]
    [[ "$output" != *"Password is correct"* ]]
    assert_equal "${stderr_lines[0]}" "  Enter password to verify: ****"
    assert_equal "${stderr_lines[1]}" "${ESC}[0;31m[ERROR]${ESC}[0m Password does not match."
    assert_equal "${#stderr_lines[@]}" 2
}

# bats test_tags=cutover:wp2-4a
@test "user verify: a closed stdin is a blank password, which does not match" {
    fast_bcrypt
    make_user alice 'CorrectHorse99'
    runs "$TACCTL_BIN_SCRIPT" user verify alice < /dev/null
    assert_success
    assert_equal "${stderr_lines[0]}" "  Enter password to verify: "
    assert_equal "${stderr_lines[1]}" "${ESC}[0;31m[ERROR]${ESC}[0m Password does not match."
}

# bats test_tags=cutover:wp2-4a
@test "user verify: audits the outcome with logger, naming the sudo caller" {
    fast_bcrypt
    make_user alice 'CorrectHorse99'
    : > "$CALLS_LOG"
    SUDO_USER=ops SUDO_UID=1234 "$TACCTL_BIN_SCRIPT" user verify alice > /dev/null 2>&1 <<< 'CorrectHorse99'
    SUDO_USER=ops SUDO_UID=1234 "$TACCTL_BIN_SCRIPT" user verify alice > /dev/null 2>&1 <<< 'wrong'
    grep -qxF 'logger -t tacctl -p auth.info verify OK user=alice by=ops(uid=1234)' "$CALLS_LOG"
    grep -qxF 'logger -t tacctl -p auth.warning verify FAIL user=alice result=NO_MATCH by=ops(uid=1234)' "$CALLS_LOG"
}

# bats test_tags=cutover:wp2-4a
@test "user verify: without sudo the caller is root and the uid is the process's" {
    fast_bcrypt
    make_user alice 'CorrectHorse99'
    : > "$CALLS_LOG"
    env -u SUDO_USER -u SUDO_UID "$TACCTL_BIN_SCRIPT" user verify alice > /dev/null 2>&1 <<< 'CorrectHorse99'
    grep -qxF "logger -t tacctl -p auth.info verify OK user=alice by=root(uid=$(id -u))" "$CALLS_LOG"
}

# bats test_tags=cutover:wp2-4a
@test "user verify: a disabled user is refused with exit 1, details shown, password not asked" {
    fast_bcrypt
    make_user alice 'CorrectHorse99'
    "$TACCTL_BIN_SCRIPT" user disable alice > /dev/null 2>&1 <<< 'y'
    runs "$TACCTL_BIN_SCRIPT" user verify alice <<< 'CorrectHorse99'
    assert_failure 1
    [[ "$(plain <<< "$output")" == *"Status:         disabled"* ]]
    [[ "$output" == *"${ESC}[0;31mdisabled${ESC}[0m"* ]]
    assert_equal "$stderr" "${ESC}[0;31m[ERROR]${ESC}[0m User is disabled — cannot verify password."
}

# bats test_tags=cutover:wp2-4a
@test "user verify: unknown user, no argument and a bad name exit 1 with an error" {
    runs "$TACCTL_BIN_SCRIPT" user verify ghost <<< 'x'
    assert_failure 1
    assert_output ""
    assert_equal "$stderr" "${ESC}[0;31m[ERROR]${ESC}[0m User 'ghost' does not exist."

    runs "$TACCTL_BIN_SCRIPT" user verify
    assert_failure 1
    assert_equal "$stderr" "${ESC}[0;31m[ERROR]${ESC}[0m Usage: tacctl user verify <username>"

    runs "$TACCTL_BIN_SCRIPT" user verify 'bad name'
    assert_failure 1
    assert_equal "$stderr" "${ESC}[0;31m[ERROR]${ESC}[0m Username must contain only letters, numbers, underscores, and hyphens."
}

# bats test_tags=cutover:wp2-4a
@test "user verify: changes nothing in the store" {
    fast_bcrypt
    make_user alice 'CorrectHorse99'
    local before
    before=$(sha256sum "${TACCTL_STATE_DIR}/store.yaml" "${TACCTL_CONFIG}")
    "$TACCTL_BIN_SCRIPT" user verify alice > /dev/null 2>&1 <<< 'CorrectHorse99'
    "$TACCTL_BIN_SCRIPT" user verify alice > /dev/null 2>&1 <<< 'wrong'
    assert_equal "$(sha256sum "${TACCTL_STATE_DIR}/store.yaml" "${TACCTL_CONFIG}")" "$before"
}

# --- the generated-password path of user add / user passwd ---------------------

# bats test_tags=cutover:wp2-4a
@test "user add: a blank line generates a password, announced on stderr, and it works" {
    fast_bcrypt
    runs "$TACCTL_BIN_SCRIPT" user add bob operator --scopes lab <<< ''
    assert_success
    local pw
    pw=$(generated_password "$stderr")
    [[ "$pw" =~ ^[A-Za-z0-9+/]{24}$ ]]
    assert_equal "${stderr_lines[0]}" "  Enter password (leave blank to auto-generate): "
    [[ "$(plain <<< "$output")" == *"User 'bob' added (operator) with scopes: lab"* ]]
    # The password is not in stdout, only on stderr.
    [[ "$output" != *"$pw"* ]]
    runs "$TACCTL_BIN_SCRIPT" user verify bob <<< "$pw"
    assert_output --partial "Password is correct."
}

# bats test_tags=cutover:wp2-4a
@test "user add: a closed stdin generates a password too" {
    fast_bcrypt
    runs "$TACCTL_BIN_SCRIPT" user add bob operator --scopes lab < /dev/null
    assert_success
    local pw
    pw=$(generated_password "$stderr")
    [[ -n "$pw" ]]
    runs "$TACCTL_BIN_SCRIPT" user verify bob <<< "$pw"
    assert_output --partial "Password is correct."
}

# bats test_tags=cutover:wp2-4a
@test "user add: a typed password needs confirming and is then the user's" {
    fast_bcrypt
    runs "$TACCTL_BIN_SCRIPT" user add bob operator --scopes lab <<< $'CorrectHorse99\nCorrectHorse99'
    assert_success
    assert_equal "${stderr_lines[0]}" "  Enter password (leave blank to auto-generate): **************"
    assert_equal "${stderr_lines[1]}" "  Confirm password: **************"
    [[ -z "$(generated_password "$stderr")" ]]
    runs "$TACCTL_BIN_SCRIPT" user verify bob <<< 'CorrectHorse99'
    assert_output --partial "Password is correct."
}

# bats test_tags=cutover:wp2-4a
@test "user add: a weak, short or unconfirmed password creates no user" {
    fast_bcrypt
    runs "$TACCTL_BIN_SCRIPT" user add bob operator --scopes lab <<< 'short'
    assert_failure 1
    [[ "$stderr" == *"Password is 5 characters; minimum is 12."* ]]
    runs "$TACCTL_BIN_SCRIPT" user add bob operator --scopes lab <<< 'qwerty123456'
    assert_failure 1
    [[ "$stderr" == *"Password is on the common-weak list. Choose another."* ]]
    runs "$TACCTL_BIN_SCRIPT" user add bob operator --scopes lab <<< $'CorrectHorse99\nCorrectHorse98'
    assert_failure 1
    [[ "$stderr" == *"Passwords do not match."* ]]
    run "$TACCTL_BIN_SCRIPT" user show bob
    assert_failure
    assert_output --partial "User 'bob' does not exist."
}

# bats test_tags=cutover:wp2-4a
@test "user passwd: a blank line generates a password, sets it and enables the account" {
    fast_bcrypt
    make_user alice 'CorrectHorse99'
    "$TACCTL_BIN_SCRIPT" user disable alice > /dev/null 2>&1 <<< 'y'
    runs "$TACCTL_BIN_SCRIPT" user passwd alice <<< ''
    assert_success
    local pw
    pw=$(generated_password "$stderr")
    [[ -n "$pw" ]]
    [[ "$(plain <<< "$output")" == *"Password changed for 'alice'."* ]]
    runs "$TACCTL_BIN_SCRIPT" user verify alice <<< "$pw"
    assert_success
    assert_output --partial "Password is correct."
    runs "$TACCTL_BIN_SCRIPT" user verify alice <<< 'CorrectHorse99'
    [[ "$stderr" == *"Password does not match."* ]]
}

# --- config defaults ------------------------------------------------------------

# bats test_tags=cutover:wp2-4c
@test "config defaults: prints the shipped defaults, exactly what conf_emit_defaults emits" {
    runs "$TACCTL_BIN_SCRIPT" config defaults
    assert_success
    assert_equal "$stderr" ""
    assert_equal "${lines[0]}" '# tacctl canonical defaults (emitted by `tacctl config defaults`).'
    assert_equal "${lines[1]}" '# DO NOT edit this output — it is generated by conf_emit_defaults() in'
    assert_equal "${lines[2]}" '# lib/conf.sh. Override any key in /etc/tacctl/tacctl.yaml.'
    local want
    want=$(bash -c 'source "$1"; conf_emit_defaults' _ "${TACCTL_SRC}/bin/tacctl.sh")
    assert_equal "$output" "$want"
}

# bats test_tags=cutover:wp2-4c
@test "config defaults: pins the shipped values of the common keys" {
    run "$TACCTL_BIN_SCRIPT" config defaults
    assert_success
    assert_line '  max_age_days: 90        # warning threshold used by `tacctl status`'
    assert_line '  min_length: 12          # floor for interactively-typed passwords'
    assert_line '  min_length: 16          # floor for operator-typed shared secrets'
    assert_line '  cost: 12                # applies to new hashes; range 10..14'
    assert_line '  default: lab            # matches the fresh-install seed scope; override via `tacctl scope default <name>`'
}

# bats test_tags=cutover:wp2-4c
@test "config defaults: ignores overrides and extra arguments, and writes nothing" {
    local plain_out
    plain_out=$("$TACCTL_BIN_SCRIPT" config defaults)
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 10 > /dev/null 2>&1
    local before
    before=$(sha256sum "${TACCTL_STATE_DIR}/store.yaml" "${TACCTL_OVERRIDES_FILE:-${TACCTL_STATE_DIR}/tacctl.yaml}")
    run "$TACCTL_BIN_SCRIPT" config defaults extra arguments
    assert_success
    assert_output "$plain_out"
    assert_equal "$(sha256sum "${TACCTL_STATE_DIR}/store.yaml" "${TACCTL_OVERRIDES_FILE:-${TACCTL_STATE_DIR}/tacctl.yaml}")" "$before"
}

# --- config branch ----------------------------------------------------------------
# The deploy clone is /opt/tacctl in bash (DEPLOY_DIR is not read from the
# environment), so these call cmd_config_branch with DEPLOY_DIR pointed at a
# scratch directory and `git` stubbed. The Go port takes the clone from
# TACCTL_TREE: the package that cuts `config branch` over rewrites these as
# plain CLI runs against a scratch TACCTL_TREE and drops the bash-only tag.

branch_setup() {
    DEPLOY="${BATS_TEST_TMPDIR}/deploy"
    mkdir -p "${DEPLOY}/.git" "${DEPLOY}/bin"
    : > "${DEPLOY}/bin/tacctl.sh"
    chmod 600 "${DEPLOY}/bin/tacctl.sh"
    cat > "${STUB_BIN}/git" <<'STUB'
#!/usr/bin/env bash
echo "git $*" >> "${CALLS_LOG}"
case "$*" in
    *"branch --show-current"*) echo "${STUB_GIT_BRANCH:-develop}" ;;
    *"branch -r"*) printf '  origin/HEAD -> origin/develop\n  origin/develop\n  origin/master\n  origin/feature/x\n' ;;
    *"rev-parse --verify origin/feature/x"*) ;;
    *"rev-parse --verify"*) exit 1 ;;
    *"checkout feature/x"*) [[ -z "${STUB_GIT_NO_LOCAL:-}" ]] || exit 1 ;;
esac
exit 0
STUB
    chmod +x "${STUB_BIN}/git"
}

config_branch() {
    bash -c 'source "$1"; DEPLOY_DIR="$2"; shift 2; cmd_config_branch "$@"' _ \
        "${TACCTL_SRC}/bin/tacctl.sh" "$DEPLOY" "$@"
}

# bats test_tags=bash-only
@test "config branch: without a clone it says so and exits 1" {
    branch_setup
    rm -rf "$DEPLOY"
    runs config_branch
    assert_failure 1
    assert_equal "$stderr" "${ESC}[0;31m[ERROR]${ESC}[0m Deploy directory not found at ${DEPLOY}."
    refute_called '^git '
}

# bats test_tags=bash-only
@test "config branch: with no name it shows the current branch and the remote ones, marking the current" {
    branch_setup
    runs config_branch
    assert_success
    assert_equal "$stderr" ""
    local want
    want=$(printf '%s\n' \
        "" \
        "  ${ESC}[1mCurrent branch:${ESC}[0m develop" \
        "" \
        "  Available remote branches:" \
        "    ${ESC}[0;32m* develop${ESC}[0m" \
        "      master" \
        "      feature/x" \
        "")
    assert_equal "$output" "${want%$'\n'}"
    run stub_calls
    assert_line "git -C ${DEPLOY} branch --show-current"
    assert_line "git -C ${DEPLOY} fetch --quiet"
    assert_line "git -C ${DEPLOY} branch -r"
}

# bats test_tags=bash-only
@test "config branch: naming the current branch changes nothing" {
    branch_setup
    run config_branch develop
    assert_success
    assert_output "${ESC}[0;32m[INFO]${ESC}[0m Already on branch 'develop'."
    refute_called 'checkout'
}

# bats test_tags=bash-only
@test "config branch: a branch that is not on the remote is an error" {
    branch_setup
    runs config_branch nope
    assert_failure 1
    assert_output ""
    assert_equal "$stderr" "${ESC}[0;31m[ERROR]${ESC}[0m Branch 'nope' does not exist on remote."
    stub_called "^git -C ${DEPLOY} rev-parse --verify origin/nope"
    refute_called 'checkout'
}

# bats test_tags=bash-only
@test "config branch: switching fetches, discards local edits, checks out, pulls, fixes modes" {
    branch_setup
    runs config_branch feature/x
    assert_success
    assert_equal "$output" "${ESC}[0;32m[INFO]${ESC}[0m Switched to branch 'feature/x'.
${ESC}[0;32m[INFO]${ESC}[0m Run 'tacctl upgrade' to apply any changes."
    assert_equal "$(grep '^git ' "$CALLS_LOG" | tr '\n' '|')" \
        "git -C ${DEPLOY} branch --show-current|git -C ${DEPLOY} fetch --quiet|git -C ${DEPLOY} rev-parse --verify origin/feature/x|git -C ${DEPLOY} checkout -- .|git -C ${DEPLOY} checkout feature/x|git -C ${DEPLOY} pull --quiet|"
    assert_equal "$(stat -c %a "${DEPLOY}/bin/tacctl.sh")" 755
}

# bats test_tags=bash-only
@test "config branch: a branch with no local copy is created from origin" {
    branch_setup
    STUB_GIT_NO_LOCAL=1 run config_branch feature/x
    assert_success
    assert_output --partial "Switched to branch 'feature/x'."
    stub_called "^git -C ${DEPLOY} checkout -b feature/x origin/feature/x$"
}

# --- install / upgrade --branch ---------------------------------------------------
# Only the argument handling, which happens before either command touches
# anything. `upgrade --branch <name>` is not run at all: past its parsing it
# builds the TACACS+ daemon, so a test of it needs the lifecycle harness.

# bats test_tags=cutover:wp3-3d
@test "upgrade --branch: no value exits 1 with no output at all, before running git" {
    stub_cmd git
    runs "$TACCTL_BIN_SCRIPT" upgrade --branch < /dev/null
    assert_failure 1
    assert_output ""
    assert_equal "$stderr" ""
    refute_called '^git '
}

# bats test_tags=cutover:wp3-3d
@test "upgrade --branch: a trailing --branch with no value fails the same way, after a good one" {
    stub_cmd git
    runs "$TACCTL_BIN_SCRIPT" upgrade --branch feature/x --branch < /dev/null
    assert_failure 1
    assert_output ""
    assert_equal "$stderr" ""
    refute_called '^git '
}

# bats test_tags=cutover:wp3-3d
@test "install --branch: no value exits 1 with no output at all" {
    stub_cmd git
    stub_cmd wget
    runs "$TACCTL_BIN_SCRIPT" install --branch < /dev/null
    assert_failure 1
    assert_output ""
    assert_equal "$stderr" ""
    refute_called '^(git|wget) '
}

# bats test_tags=cutover:wp3-3d
@test "install --branch <name>: shows the plan and, on a closed stdin, cancels with exit 0 untouched" {
    stub_cmd git
    stub_cmd wget
    runs "$TACCTL_BIN_SCRIPT" install --branch feature/x < /dev/null
    assert_success
    assert_equal "$stderr" ""
    local text
    text=$(plain <<< "$output")
    [[ "$text" == *"  tacctl Installer"* ]]
    [[ "$text" == *"Install tacctl (/opt/tacctl, /usr/local/bin/tacctl) and its state directory (${TACCTL_STATE_DIR})"* ]]
    [[ "$text" == *"RADIUS (FreeRADIUS) is not installed; add it later with: tacctl backend enable radius"* ]]
    assert_equal "${lines[-1]}" "${ESC}[0;32m[INFO]${ESC}[0m Cancelled."
    # Cancelled before anything ran: no git, no wget, no systemctl.
    [[ ! -s "$CALLS_LOG" || -z "$(grep -vE '^(chown|logger|sleep) ' "$CALLS_LOG")" ]]
}

# bats test_tags=cutover:wp3-3d
@test "install: anything but y or Y at the prompt cancels; unknown arguments are ignored" {
    stub_cmd git
    stub_cmd wget
    local answer
    for answer in n N yes Y1 ''; do
        runs "$TACCTL_BIN_SCRIPT" install whatever --branch feature/x extra <<< "$answer"
        assert_success
        assert_equal "${lines[-1]}" "${ESC}[0;32m[INFO]${ESC}[0m Cancelled."
    done
    [[ -z "$(grep -vE '^(chown|logger|sleep) ' "$CALLS_LOG")" ]]
}
