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
    printf '%s\n' 'session required pam_limits.so' '@include common-auth' \
        '@include common-account' '@include common-session' > "$TACCTL_CLIENT_PAM_DIR/sudo-i"
    cp "$TACCTL_CLIENT_PAM_DIR/sudo-i" "$BATS_TEST_TMPDIR/sudo-i.orig"
    printf '%s\n' 'auth    requisite       pam_nologin.so' '@include common-auth' \
        '-auth   optional        pam_kwallet5.so' '@include common-account' \
        'session required        pam_loginuid.so' '@include common-session' \
        '@include common-password' > "$TACCTL_CLIENT_PAM_DIR/sddm"
    cp "$TACCTL_CLIENT_PAM_DIR/sddm" "$BATS_TEST_TMPDIR/sddm.orig"
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
    got=$(sed -n '/^__TARBALL__$/,/^__PREBUILT__$/p' "$OUT" | sed '1d;/^__PREBUILT__$/d' | base64 -d | sha256sum | awk '{print $1}')
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

@test "client install: accounts are named after their login; old generic names are corrected" {
    _gen > /dev/null
    _client_env
    run bash "$OUT" --accounts-only --adopt bob
    assert_success
    stub_called "useradd -m -u 20000 -g alice -s /bin/bash -c alice .TACACS.. alice"

    # An account created by an earlier version carries the generic name.
    echo "alice:x:20000:20000:TACACS+ user (tacctl):/home/alice:/bin/bash" >> "$FAKE_DB/passwd"
    echo "alice" > "$TACCTL_CLIENT_STATE/created"
    run bash "$OUT" --accounts-only
    assert_success
    stub_called "usermod -c alice .TACACS.. alice"
    # Adopted accounts keep their own name.
    run grep -c "usermod -c .* bob" "$CALLS_LOG"
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
    # 'sudo -i' authenticates through its own service file.
    run cat "$TACCTL_CLIENT_PAM_DIR/sudo-i"
    assert_line "@include tacctl-auth"
    assert_line "@include tacctl-account"
    refute_line "@include tacctl-session"
    # Graphical login, session included.
    run cat "$TACCTL_CLIENT_PAM_DIR/sddm"
    assert_line "@include tacctl-auth"
    assert_line "@include tacctl-account"
    assert_line "@include tacctl-session"
    refute_line "@include common-auth"
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
    cmp "$TACCTL_CLIENT_PAM_DIR/sudo-i" "$BATS_TEST_TMPDIR/sudo-i.orig"
    cmp "$TACCTL_CLIENT_PAM_DIR/sddm" "$BATS_TEST_TMPDIR/sddm.orig"
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
    run grep -cE "useradd|groupadd" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a host that cannot get the build packages is left untouched" {
    _gen > /dev/null
    _client_env
    export TACCTL_CLIENT_NEED_PKGS=" gcc make"
    stub_cmd apt-get 'exit 100'
    run bash "$OUT" --adopt bob
    assert_failure
    assert_output --partial "Could not install the build packages: gcc make"
    stub_called "apt-get update"
    run grep -cE "useradd|groupadd|usermod" "$CALLS_LOG"
    assert_output "0"
    cmp "$TACCTL_CLIENT_PAM_DIR/sshd" "$BATS_TEST_TMPDIR/sshd.orig"
    [[ ! -f "$TACCTL_CLIENT_STATE/module" ]]
}

@test "client install: a stale package index is refreshed once and the install retried" {
    _gen > /dev/null
    _client_env
    export TACCTL_CLIENT_NEED_PKGS=" libpam0g-dev"
    stub_cmd apt-get '[[ "$1" == "update" ]] && { touch "$FAKE_DB/updated"; exit 0; }
        [[ -f "$FAKE_DB/updated" ]]'
    run bash "$OUT" --adopt bob
    assert_success
    assert_output --partial "refreshing the package index"
    run grep -c "apt-get install -y libpam0g-dev" "$CALLS_LOG"
    assert_output "2"
}

@test "client install: the module is built once and reused until the source changes" {
    _gen > /dev/null
    _client_env
    run bash "$OUT" --adopt bob
    assert_success
    assert_output --partial "Building pam_tacplus"
    [[ -f "$TACCTL_CLIENT_STATE/lib/security/pam_tacplus.so" ]]

    run bash "$OUT"
    assert_success
    assert_output --partial "not rebuilding"
    refute_output --partial "Building pam_tacplus"

    # A missing file forces a rebuild.
    rm "$TACCTL_CLIENT_STATE/lib/security/pam_tacplus.so"
    run bash "$OUT"
    assert_success
    assert_output --partial "Building pam_tacplus"

    # So does a different source tarball.
    echo "another tarball" > "$TACCTL_LINUX_DIR/pam_tacplus-1.7.0.tar.gz"
    _gen > /dev/null
    run bash "$OUT"
    assert_success
    assert_output --partial "Building pam_tacplus"
}

@test "client install: a prebuilt module is installed without build tools; a bad one falls back" {
    stub_cmd getent 'echo "192.0.2.50 STREAM web1"'
    stub_cmd ip 'echo "192.0.2.50 dev eth0 src 192.0.2.1 uid 0"'
    stub_cmd ssh 'case "$*" in
        *mktemp*) cat > "$PUSHED"; echo /tmp/tacctl.AbCd1234 ;;
        *os-release*) echo "ID=ubuntu"; echo "VERSION_CODENAME=noble"; echo "TACCTL_ARCH=$(uname -m)" ;;
    esac'
    stub_cmd podman 'case "$1" in
        build) ;;
        run)   cat > /dev/null; d=$(mktemp -d); echo lib > "$d/libtac.so.5.0.0"; echo mod > "$d/pam_tacplus.so"
               tar -C "$d" -czf - libtac.so.5.0.0 pam_tacplus.so ;;
        image) echo "sha256:feedface" ;;
    esac'
    export PUSHED="${BATS_TEST_TMPDIR}/pushed.sh"
    "$TACCTL_BIN_SCRIPT" host enroll web1 --scope lab > /dev/null

    _client_env
    export TACCTL_CLIENT_NEED_PKGS=" gcc"
    run bash "$PUSHED" --adopt bob
    assert_success
    assert_output --partial "built on the tacctl server for docker.io/library/ubuntu:noble"
    refute_output --partial "Building pam_tacplus"
    run cat "$TACCTL_CLIENT_STATE/lib/security/pam_tacplus.so"
    assert_output "mod"
    run grep -c "^apt-get" "$CALLS_LOG"
    assert_output "0"

    # Corrupt the recorded checksum: the host compiles from source instead.
    rm -rf "$TACCTL_CLIENT_STATE/lib" "$TACCTL_CLIENT_STATE/module"
    sed -i 's/^PREBUILT_SHA256=.*/PREBUILT_SHA256=0000/' "$PUSHED"
    run bash "$PUSHED"
    assert_success
    assert_output --partial "failed its checksum"
    assert_output --partial "Building pam_tacplus on this host"
    stub_called "apt-get install -y gcc"
}

# RHEL-family layout: service files include password-auth/system-auth.
_rhel_env() {
    _client_env
    export TACCTL_CLIENT_FAMILY=rhel
    printf '%s\n' '#%PAM-1.0' 'auth       substack     password-auth' 'auth       include      postlogin' \
        'account    required     pam_nologin.so' 'account    include      password-auth' \
        'password   include      password-auth' 'session    required     pam_loginuid.so' \
        'session    include      password-auth' 'session    include      postlogin' > "$TACCTL_CLIENT_PAM_DIR/sshd"
    printf '%s\n' '#%PAM-1.0' 'auth       include      system-auth' 'account    include      system-auth' \
        'password   include      system-auth' 'session    include      system-auth' > "$TACCTL_CLIENT_PAM_DIR/sudo"
    printf '%s\n' '#%PAM-1.0' 'auth       include      sudo' 'account    include      sudo' \
        'session    include      sudo' > "$TACCTL_CLIENT_PAM_DIR/sudo-i"
    rm -f "$TACCTL_CLIENT_PAM_DIR/sddm"
    printf '%s\n' 'auth     [success=done ignore=ignore default=bad] pam_selinux_permit.so' \
        'auth        substack      password-auth' 'auth        optional      pam_gnome_keyring.so' \
        'account     required      pam_nologin.so' 'account     include       password-auth' \
        'password    substack       password-auth' 'session     required      pam_loginuid.so' \
        'session     include       password-auth' 'session     include       postlogin' \
        > "$TACCTL_CLIENT_PAM_DIR/gdm-password"
    for f in sshd sudo sudo-i gdm-password; do cp "$TACCTL_CLIENT_PAM_DIR/$f" "$BATS_TEST_TMPDIR/$f.orig"; done
    stub_cmd dnf
}

@test "client install (RHEL family): include lines go in front of the shared stack and come out cleanly" {
    _gen > /dev/null
    _rhel_env
    run bash "$OUT" --adopt bob
    assert_success

    run cat "$TACCTL_CLIENT_PAM_DIR/sshd"
    assert_line --index 1 "auth       include      tacctl-auth"
    assert_line --index 2 "auth       substack     password-auth"
    assert_line --index 5 "account    include      tacctl-account"
    assert_line --index 6 "account    include      password-auth"
    assert_line --index 9 "session    include      password-auth"
    assert_line --index 10 "session    include      tacctl-session"
    run cat "$TACCTL_CLIENT_PAM_DIR/sudo"
    assert_line --index 1 "auth       include      tacctl-auth"
    assert_line --index 3 "account    include      tacctl-account"
    refute_output --partial "tacctl-session"
    run cat "$TACCTL_CLIENT_PAM_DIR/gdm-password"
    assert_line --index 1 "auth       include      tacctl-auth"
    assert_line --index 2 "auth        substack      password-auth"
    assert_line --index 5 "account    include      tacctl-account"
    assert_line --index 10 "session    include      tacctl-session"
    # sudo-i only includes sudo here, so it is left alone.
    cmp "$TACCTL_CLIENT_PAM_DIR/sudo-i" "$BATS_TEST_TMPDIR/sudo-i.orig"
    # The tacctl files carry no Debian @include.
    run cat "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" "$TACCTL_CLIENT_PAM_DIR/tacctl-account"
    assert_output --partial "pam_tacplus.so server=192.0.2.10:49"
    refute_output --partial "@include"

    # Re-running must not stack a second set of lines.
    run bash "$OUT"
    assert_success
    run grep -c "tacctl-" "$TACCTL_CLIENT_PAM_DIR/sshd"
    assert_output "3"

    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    for f in sshd sudo sudo-i gdm-password; do cmp "$TACCTL_CLIENT_PAM_DIR/$f" "$BATS_TEST_TMPDIR/$f.orig"; done
    [[ ! -f "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" ]]
}

@test "client install (RHEL family): build packages come from dnf; unfamiliar layout is refused" {
    _gen > /dev/null
    _rhel_env
    export TACCTL_CLIENT_NEED_PKGS=" gcc pam-devel"
    run bash "$OUT" --adopt bob
    assert_success
    stub_called "dnf install -y -q gcc pam-devel"
    run grep -c "^apt-get" "$CALLS_LOG"
    assert_output "0"

    rm -rf "$TACCTL_CLIENT_STATE"
    echo "auth required pam_unix.so" > "$TACCTL_CLIENT_PAM_DIR/sudo"
    run bash "$OUT" --adopt bob
    assert_failure
    assert_output --partial "unfamiliar PAM layout"
}

@test "client install: with SELinux on, a policy module for the TACACS+ port is installed and later removed" {
    _gen > /dev/null
    _rhel_env
    stub_cmd selinuxenabled
    stub_cmd semodule
    stub_cmd restorecon
    run bash "$OUT" --adopt bob
    assert_success
    assert_output --partial "policy module tacctl_pam installed"
    stub_called "semodule -i .*/tacctl_pam.cil"
    run cat "$TACCTL_CLIENT_STATE/tacctl_pam.cil"
    assert_line "(portcon tcp 49 (system_u object_r tacctl_tacacs_port_t ((s0) (s0))))"
    assert_output --partial "(allow sshd_t tacctl_tacacs_port_t (tcp_socket (name_connect)))"

    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    stub_called "semodule -r tacctl_pam"
    [[ ! -f "$TACCTL_CLIENT_STATE/tacctl_pam.cil" ]]
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
