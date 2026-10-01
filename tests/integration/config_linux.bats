#!/usr/bin/env bats
# Integration tests for 'tacctl config linux' (script generation) and for the
# generated client scripts, run unprivileged against scratch directories via
# TACCTL_CLIENT_TEST=1 with the account tools stubbed.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_LINUX_DIR="${BATS_TEST_TMPDIR}/linux"
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    "$TACCTL_BIN_SCRIPT" scope secret lab set "0123456789abcdef0123456789abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add bob readonly --hash "$HASH" --scopes lab > /dev/null

    # Stand-in for the tarball 'config linux build' would produce.
    mkdir -p "$TACCTL_LINUX_DIR"
    echo "not really a tarball" > "$TACCTL_LINUX_DIR/pam_tacplus-1.7.0.tar.gz"
    OUT="${BATS_TEST_TMPDIR}/install.sh"
}

_gen() {
    "$TACCTL_BIN_SCRIPT" config linux script --scope lab --server 192.0.2.10 --output "$OUT" "$@"
}

# Scratch host for the client scripts: PAM dir, state dir, fake user db.
_client_env() {
    export TACCTL_CLIENT_TEST=1
    export TACCTL_CLIENT_STATE="${BATS_TEST_TMPDIR}/state"
    export TACCTL_CLIENT_PAM_DIR="${BATS_TEST_TMPDIR}/pam.d"
    export TACCTL_CLIENT_SUDOERS="${BATS_TEST_TMPDIR}/sudoers-host"
    export FAKE_DB="${BATS_TEST_TMPDIR}/db"
    mkdir -p "$TACCTL_CLIENT_PAM_DIR" "$FAKE_DB"
    printf '%s\n' '# sshd' '@include common-auth' 'account    required     pam_nologin.so' \
        '@include common-account' '@include common-session' 'session optional pam_motd.so' \
        '@include common-password' > "$TACCTL_CLIENT_PAM_DIR/sshd"
    printf '%s\n' 'session required pam_limits.so' '@include common-auth' \
        '@include common-account' '@include common-session-noninteractive' > "$TACCTL_CLIENT_PAM_DIR/sudo"
    cp "$TACCTL_CLIENT_PAM_DIR/sshd" "$BATS_TEST_TMPDIR/sshd.orig"
    cp "$TACCTL_CLIENT_PAM_DIR/sudo" "$BATS_TEST_TMPDIR/sudo.orig"

    printf '%s\n' 'root:x:0:0::/root:/bin/bash' 'admin:x:1000:1000::/home/admin:/bin/bash' \
        'bob:x:1001:1001::/home/bob:/bin/bash' > "$FAKE_DB/passwd"
    printf '%s\n' 'sudo:x:27:admin' > "$FAKE_DB/group"
    printf '%s\n' 'root:*:1::::::' 'admin:$y$hash:1::::::' 'bob:$y$hash:1::::::' > "$FAKE_DB/shadow"

    stub_cmd getent 'db="$1"; shift
        [[ $# -eq 0 ]] && { cat "$FAKE_DB/$db"; exit 0; }
        rc=2
        for key in "$@"; do
            awk -F: -v k="$key" "\$1 == k || \$3 == k { print; found=1 } END { exit !found }" "$FAKE_DB/$db" && rc=0
        done
        exit $rc'
    stub_cmd groupadd 'gid=900; [[ "$1" == "-g" ]] && { gid="$2"; shift 2; }
        echo "$1:x:$gid:" >> "$FAKE_DB/group"'
    stub_cmd useradd
    stub_cmd usermod
    stub_cmd gpasswd
    stub_cmd id 'echo "users ${FAKE_ID_GROUPS:-}"'
    stub_cmd apt-get
    stub_cmd visudo
    stub_cmd sshd 'printf "usepam yes\npasswordauthentication yes\n"'
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'
    stub_cmd ldconfig
}

# --- generation ---------------------------------------------------------------

@test "config linux script: requires the prepared tarball" {
    rm -f "$TACCTL_LINUX_DIR"/*.tar.gz
    run _gen
    assert_failure
    assert_output --partial "tacctl config linux build"
}

@test "config linux script: writes a 0600 script carrying server, secret and users" {
    run _gen
    assert_success
    [[ "$(stat -c %a "$OUT")" == "600" ]]
    run bash -n "$OUT"
    assert_success
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_output --partial "TAC_SERVER=192.0.2.10"
    assert_output --partial "TAC_PORT=49"
    assert_output --partial "TAC_SECRET=0123456789abcdef0123456789abcdef"
    assert_output --partial "alice:superuser:20000"
    assert_output --partial "bob:readonly:20001"
}

@test "config linux script: embedded tarball matches the recorded checksum" {
    _gen > /dev/null
    local want got
    want=$(sed -n 's/^TARBALL_SHA256=//p' "$OUT")
    got=$(sed -n '/^__TARBALL__$/,$p' "$OUT" | tail -n +2 | base64 -d | sha256sum | awk '{print $1}')
    [[ -n "$want" && "$want" == "$got" ]]
}

@test "config linux script: UIDs are stable across runs and never reused" {
    _gen > /dev/null
    "$TACCTL_BIN_SCRIPT" user remove alice <<< "y" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add carol operator --hash "$HASH" --scopes lab > /dev/null
    _gen > /dev/null
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_output --partial "bob:readonly:20001"
    assert_output --partial "carol:operator:20002"
    refute_output --partial "alice"
}

@test "config linux script: skips names Linux would reject, without polluting the list" {
    "$TACCTL_BIN_SCRIPT" user add Dave readonly --hash "$HASH" --scopes lab > /dev/null
    run _gen
    assert_success
    assert_output --partial "Skipping 'Dave'"
    run grep -c "Dave" <(sed '/^__TARBALL__$/,$d' "$OUT")
    assert_output "0"
}

@test "config linux script: leaves disabled users out until they are re-enabled" {
    "$TACCTL_BIN_SCRIPT" user disable bob > /dev/null
    _gen > /dev/null
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_output --partial "alice:superuser:20000"
    refute_output --partial "bob:"
    "$TACCTL_BIN_SCRIPT" user enable bob > /dev/null
    _gen > /dev/null
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_output --partial "bob:readonly:20001"
}

@test "config linux script: refuses a placeholder or unsafe secret" {
    load_fixture tacquito.minimal.yaml
    sed -i 's/key: ".*"/key: "REPLACE_WITH_SHARED_SECRET"/' "$TACCTL_CONFIG"
    run _gen
    assert_failure
    assert_output --partial "tacctl scope secret lab generate"
    [[ ! -f "$OUT" ]]
}

@test "config linux script: rejects an unknown scope and a bad --server" {
    run "$TACCTL_BIN_SCRIPT" config linux script --scope nope --output "$OUT"
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config linux script --scope lab --server 'x;reboot' --output "$OUT"
    assert_failure
    assert_output --partial "Invalid server address"
}

@test "config linux remove-script: carries no secret" {
    run "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    run grep -c "0123456789abcdef" "$BATS_TEST_TMPDIR/remove.sh"
    assert_output "0"
    run bash -n "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
}

@test "config linux: is superuser-only" {
    stub_cmd id 'echo "users tac-users"'
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" config linux script --scope lab --output "$OUT"
    assert_failure
    assert_output --partial "not permitted"
}

# --- client scripts -----------------------------------------------------------

@test "client install: creates new accounts, adopts existing ones, sets tier groups" {
    _gen > /dev/null
    _client_env
    run bash "$OUT" --accounts-only --adopt bob
    assert_success
    stub_called "groupadd -g 20000 alice"
    stub_called "useradd -m -u 20000 -g alice -s /bin/bash .* alice"
    run grep -c "useradd .* bob" "$CALLS_LOG"
    assert_output "0"
    stub_called "usermod -aG tac-users,tac-superuser alice"
    stub_called "usermod -aG tac-users,tac-readonly bob"
    run cat "$TACCTL_CLIENT_STATE/adopted"
    assert_output "bob"
    [[ ! -f "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" ]]
}

@test "client install: stops before changing anything when the assigned UID is taken" {
    _gen > /dev/null
    _client_env
    echo 'squatter:x:20000:20000::/home/squatter:/bin/bash' >> "$FAKE_DB/passwd"
    run bash "$OUT" --accounts-only --adopt bob
    assert_failure
    assert_output --partial "alice: UID 20000 already belongs to user 'squatter'"
    assert_output --partial "Nothing was changed"
    assert_output --partial "tacctl config linux uid <user> <new-uid>"
    assert_output --partial "--allow-uid-mismatch"
    run grep -cE "^(useradd|groupadd|usermod|gpasswd)" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: stops when the assigned GID or the user's group name is taken" {
    _gen > /dev/null
    _client_env
    echo 'staff2:x:20000:' >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only --adopt bob
    assert_failure
    assert_output --partial "alice: GID 20000 already belongs to group 'staff2'"
    printf '%s\n' 'sudo:x:27:admin' 'alice:x:1500:' > "$FAKE_DB/group"
    run bash "$OUT" --accounts-only --adopt bob
    assert_failure
    assert_output --partial "a group named 'alice' exists with GID 1500, not 20000"
}

@test "client install: --allow-uid-mismatch falls back to the host's next free number" {
    _gen > /dev/null
    _client_env
    echo 'squatter:x:20000:20000::/home/squatter:/bin/bash' >> "$FAKE_DB/passwd"
    run bash "$OUT" --accounts-only --allow-uid-mismatch --adopt bob
    assert_success
    assert_output --partial "conflicts accepted"
    stub_called "useradd -m -s /bin/bash .* alice"
    run grep -c "useradd -m -u" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: an adopted account with a different UID is reported with fixes" {
    _gen > /dev/null
    _client_env
    run bash "$OUT" --accounts-only --adopt bob
    assert_success
    assert_output --partial "bob: UID 1001 on this host, 20001 assigned by tacctl"
    assert_output --partial "usermod -u <uid> <user> && groupmod -g <uid> <user>"
    assert_output --partial "tacctl config linux uid <user> <uid-on-this-host>"
}

@test "config linux uid: lists, shows and reassigns; refuses duplicates and bad values" {
    _gen > /dev/null
    run "$TACCTL_BIN_SCRIPT" config linux uid
    assert_success
    assert_line --regexp "alice +20000"
    run "$TACCTL_BIN_SCRIPT" config linux uid bob
    assert_output "20001"
    run "$TACCTL_BIN_SCRIPT" config linux uid bob 1001
    assert_success
    assert_output --partial "usermod -u 1001 bob && groupmod -g 1001 bob"
    _gen > /dev/null
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_output --partial "bob:readonly:1001"
    run "$TACCTL_BIN_SCRIPT" config linux uid bob 20000
    assert_failure
    assert_output --partial "already assigned to 'alice'"
    run "$TACCTL_BIN_SCRIPT" config linux uid bob 500
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config linux uid ghost 30000
    assert_failure
    # A new user is numbered after the highest assignment, never into a gap.
    "$TACCTL_BIN_SCRIPT" user add carol operator --hash "$HASH" --scopes lab > /dev/null
    _gen > /dev/null
    run "$TACCTL_BIN_SCRIPT" config linux uid carol
    assert_output "20001"
}

@test "client install: a pre-existing account stops the run unless named with --adopt" {
    _gen > /dev/null
    _client_env
    run bash "$OUT" --accounts-only
    assert_failure
    assert_output --partial "already have a local account on this host that tacctl did not create: bob"
    assert_output --partial "Nothing was changed"
    assert_output --partial "--adopt <name>"
    assert_output --partial "tacctl user rename <old> <new>"
    run grep -cE "^(useradd|groupadd|usermod|gpasswd)" "$CALLS_LOG"
    assert_output "0"
    [[ ! -s "$TACCTL_CLIENT_STATE/adopted" ]]
}

@test "client install: an adopted account needs no flag on later runs" {
    _gen > /dev/null
    _client_env
    bash "$OUT" --accounts-only --adopt bob > /dev/null
    run bash "$OUT" --accounts-only
    assert_success
}

@test "client install: adopting an account in privileged local groups warns" {
    _gen > /dev/null
    _client_env
    FAKE_ID_GROUPS="sudo docker" run bash "$OUT" --accounts-only --adopt bob
    assert_success
    assert_output --partial "'bob' is in local group(s): sudo, docker. Those rights stay whatever the TACACS+ tier (readonly) is."
}

@test "client install: a removed adopted account is left usable and says so" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE"
    echo "olduser" > "$TACCTL_CLIENT_STATE/adopted"
    echo "tac-users:x:900:olduser" >> "$FAKE_DB/group"
    echo 'olduser:x:1500:1500::/nonexistent:/bin/bash' >> "$FAKE_DB/passwd"
    echo 'olduser:$y$hash:1::::::' >> "$FAKE_DB/shadow"
    run bash "$OUT" --accounts-only --adopt bob
    assert_success
    assert_output --partial "'olduser' is no longer a TACACS+ user here but its local account was NOT disabled (local password works"
    assert_output --partial "usermod -L -e 1 olduser"
    run grep -c "usermod -e 1 olduser" "$CALLS_LOG"
    assert_output "0"
    run grep -c olduser "$TACCTL_CLIENT_STATE/adopted"
    assert_output "0"
}

@test "client install: a tier change drops the old tier group" {
    _gen > /dev/null
    _client_env
    FAKE_ID_GROUPS="tac-users tac-superuser" run bash "$OUT" --accounts-only --adopt bob
    assert_success
    stub_called "gpasswd -d bob tac-superuser"
}

@test "client install: users gone from the scope lose groups; created accounts are expired" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE"
    echo "olduser" > "$TACCTL_CLIENT_STATE/created"
    echo "tac-users:x:900:olduser,localguy" >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only --adopt bob
    assert_success
    stub_called "gpasswd -d olduser tac-users"
    stub_called "usermod -e 1 olduser"
    stub_called "gpasswd -d localguy tac-users"
    run grep -c "usermod -e 1 localguy" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: refuses when no local admin exists outside TACACS+" {
    _gen > /dev/null
    _client_env
    printf '%s\n' 'sudo:x:27:bob' > "$FAKE_DB/group"
    run bash "$OUT" --accounts-only --adopt bob
    assert_failure
    assert_output --partial "No local administrator"
    run grep -c "useradd" "$CALLS_LOG"
    assert_output "0"
}

@test "client install then remove: PAM files are edited and restored byte-for-byte" {
    _gen > /dev/null
    _client_env
    run bash "$OUT" --adopt bob
    assert_success

    run cat "$TACCTL_CLIENT_PAM_DIR/sshd"
    assert_line "@include tacctl-auth"
    assert_line "@include tacctl-account"
    assert_line "@include tacctl-session"
    assert_line "@include common-password"
    refute_line "@include common-auth"
    run cat "$TACCTL_CLIENT_PAM_DIR/sudo"
    assert_line "@include tacctl-auth"
    refute_line "@include tacctl-session"
    run cat "$TACCTL_CLIENT_PAM_DIR/tacctl-auth"
    assert_output --partial "pam_succeed_if.so quiet user ingroup tac-users"
    assert_output --partial "pam_tacplus.so server=192.0.2.10:49 secret=0123456789abcdef0123456789abcdef"
    assert_line "@include common-auth"
    run cat "$TACCTL_CLIENT_SUDOERS"
    assert_output --partial "%tac-superuser ALL=(ALL:ALL) ALL"

    # Re-running must not stack a second session include.
    run bash "$OUT" --adopt bob
    assert_success
    run grep -c "tacctl-session" "$TACCTL_CLIENT_PAM_DIR/sshd"
    assert_output "1"

    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    assert_output --partial "left in place"
    cmp "$TACCTL_CLIENT_PAM_DIR/sshd" "$BATS_TEST_TMPDIR/sshd.orig"
    cmp "$TACCTL_CLIENT_PAM_DIR/sudo" "$BATS_TEST_TMPDIR/sudo.orig"
    [[ ! -f "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" ]]
    [[ ! -f "$TACCTL_CLIENT_SUDOERS" ]]
    run grep -cE "userdel|groupdel" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a failure after PAM edits begin rolls them back" {
    _gen > /dev/null
    _client_env
    stub_cmd visudo 'exit 1'
    run bash "$OUT" --adopt bob
    assert_failure
    assert_output --partial "restored from backup"
    cmp "$TACCTL_CLIENT_PAM_DIR/sshd" "$BATS_TEST_TMPDIR/sshd.orig"
    cmp "$TACCTL_CLIENT_PAM_DIR/sudo" "$BATS_TEST_TMPDIR/sudo.orig"
    [[ ! -f "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" ]]
}

@test "client install: refuses an unfamiliar PAM layout before touching anything" {
    _gen > /dev/null
    _client_env
    echo "auth required pam_unix.so" > "$TACCTL_CLIENT_PAM_DIR/sshd"
    run bash "$OUT" --adopt bob
    assert_failure
    assert_output --partial "unfamiliar PAM layout"
}

@test "client remove: refuses when nobody would keep a usable local password" {
    _client_env
    printf '%s\n' 'root:*:1::::::' 'admin:!:1::::::' > "$FAKE_DB/shadow"
    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_failure
    assert_output --partial "lock"
}

@test "client remove: reports accounts left without a way to log in" {
    _client_env
    echo "tac-users:x:900:ghost" >> "$FAKE_DB/group"
    echo 'ghost:x:20009:20009::/nonexistent:/bin/bash' >> "$FAKE_DB/passwd"
    echo 'ghost:!:1::::::' >> "$FAKE_DB/shadow"
    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    assert_output --partial "cannot log in: ghost"
}
