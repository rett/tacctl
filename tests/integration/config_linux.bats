#!/usr/bin/env bats
# Integration tests for 'tacctl config linux' (script generation) and for the
# generated client scripts, run unprivileged against scratch directories via
# TACCTL_CLIENT_TEST=1 with the account tools stubbed. The last section is
# the radius method (pam_radius_auth from the host's packages) and switching
# a host between the two.

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
    export TACCTL_CLIENT_XDG="${BATS_TEST_TMPDIR}/xdg"
    export TACCTL_CLIENT_RADIUS_CONF="${BATS_TEST_TMPDIR}/etc-tacctl-pam_radius.conf"
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

    printf '%s\n' 'root:x:0:0::/root:/bin/bash' 'admin:x:1000:1000::/home/admin:/bin/bash' > "$FAKE_DB/passwd"
    printf '%s\n' 'sudo:x:27:admin' > "$FAKE_DB/group"
    printf '%s\n' 'root:*:1::::::' 'admin:$y$hash:1::::::' > "$FAKE_DB/shadow"
    # Home directories live under a scratch /home, owned by whoever runs
    # the tests.
    export TACCTL_CLIENT_HOME_ROOT="${BATS_TEST_TMPDIR}/home"
    TACCTL_CLIENT_HOME_OWNER=$(stat -c %u "$BATS_TEST_TMPDIR")
    export TACCTL_CLIENT_HOME_OWNER
    mkdir -p "$TACCTL_CLIENT_HOME_ROOT"

    stub_cmd getent 'db="$1"; shift
        [[ $# -eq 0 ]] && { cat "$FAKE_DB/$db"; exit 0; }
        rc=2
        for key in "$@"; do
            awk -F: -v k="$key" "\$1 == k || \$3 == k { print; found=1 } END { exit !found }" "$FAKE_DB/$db" && rc=0
        done
        exit $rc'
    stub_cmd groupadd 'gid=900; [[ "$1" == "-g" ]] && { gid="$2"; shift 2; }
        echo "$1:x:$gid:" >> "$FAKE_DB/group"'
    # The account database is kept up to date: useradd adds the account
    # (and its home), userdel and groupdel take them out again.
    stub_cmd useradd 'uid=""; gid=""; gecos=""; sh=/bin/bash
        while [[ $# -gt 1 ]]; do case "$1" in
            -u) uid="$2"; shift 2 ;;
            -g) gid=$(getent group "$2" | cut -d: -f3); shift 2 ;;
            -c) gecos="$2"; shift 2 ;;
            -s) sh="$2"; shift 2 ;;
            *) shift ;;
        esac; done
        echo "$1:x:${uid:-1500}:${gid:-1500}:${gecos}:${TACCTL_CLIENT_HOME_ROOT}/$1:${sh}" >> "$FAKE_DB/passwd"
        mkdir -p "${TACCTL_CLIENT_HOME_ROOT}/$1"'
    stub_cmd userdel '[[ -z "${USERDEL_FAILS:-}" ]] || exit 8
        sed -i "/^$1:/d" "$FAKE_DB/passwd" "$FAKE_DB/shadow"'
    stub_cmd groupdel 'sed -i "/^$1:/d" "$FAKE_DB/group"'
    # usermod -u/-g and groupmod -g renumber in the database (groupmod moves
    # the primary GID of the group's users too, as shadow-utils does), and
    # usermod -s changes the shell; the rest of usermod is recorded only.
    stub_cmd usermod 'u=""; g=""; sh=""
        while [[ $# -gt 1 ]]; do case "$1" in
            -u) u="$2"; shift 2 ;;
            -g) g=$(getent group "$2" | cut -d: -f3); shift 2 ;;
            -s) sh="$2"; shift 2 ;;
            -c|-e|-aG|-G) shift 2 ;;
            *) shift ;;
        esac; done
        if [[ -n "$sh" ]]; then
            awk -F: -v OFS=: -v n="$1" -v v="$sh" "\$1 == n { \$7 = v } 1" "$FAKE_DB/passwd" > "$FAKE_DB/p.new" && mv "$FAKE_DB/p.new" "$FAKE_DB/passwd"
        fi
        if [[ -n "$u" ]]; then
            awk -F: -v OFS=: -v n="$1" -v v="$u" "\$1 == n { \$3 = v } 1" "$FAKE_DB/passwd" > "$FAKE_DB/p.new" && mv "$FAKE_DB/p.new" "$FAKE_DB/passwd"
        fi
        if [[ -n "$g" ]]; then
            awk -F: -v OFS=: -v n="$1" -v v="$g" "\$1 == n { \$4 = v } 1" "$FAKE_DB/passwd" > "$FAKE_DB/p.new" && mv "$FAKE_DB/p.new" "$FAKE_DB/passwd"
        fi'
    stub_cmd groupmod '[[ "$1" == "-g" ]] || exit 0
        old=$(getent group "$3" | cut -d: -f3)
        awk -F: -v OFS=: -v n="$3" -v v="$2" "\$1 == n { \$3 = v } 1" "$FAKE_DB/group" > "$FAKE_DB/g.new" && mv "$FAKE_DB/g.new" "$FAKE_DB/group"
        awk -F: -v OFS=: -v o="$old" -v v="$2" "\$4 == o { \$4 = v } 1" "$FAKE_DB/passwd" > "$FAKE_DB/p.new" && mv "$FAKE_DB/p.new" "$FAKE_DB/passwd"'
    # Nobody is logged in unless a test says so.
    stub_cmd pgrep 'exit 1'
    stub_cmd gpasswd
    stub_cmd id 'echo "users ${FAKE_ID_GROUPS:-}"'
    stub_cmd apt-get
    stub_cmd visudo
    stub_cmd sshd 'printf "usepam yes\npasswordauthentication yes\n"'
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'
    stub_cmd ldconfig
    # A kept home is made root's: recorded, not run (the tests are not root).
    stub_cmd chown
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
    assert_output --partial "alice:superuser:80000"
    assert_output --partial "bob:readonly:80001"
}

@test "config linux script: the port is the default listener's, from the listener model" {
    TACCTL_SETTLE_SECONDS=0 "$TACCTL_BIN_SCRIPT" config listen tcp 192.0.2.10:4949 > /dev/null
    TACCTL_SETTLE_SECONDS=0 "$TACCTL_BIN_SCRIPT" config listen --listener mgmt tcp 127.0.0.1:5050 > /dev/null
    run _gen
    assert_success
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_output --partial "TAC_PORT=4949"
    refute_output --partial "5050"
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
    assert_output --partial "bob:readonly:80001"
    assert_output --partial "carol:operator:80002"
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
    assert_output --partial "alice:superuser:80000"
    refute_output --partial "bob:"
    "$TACCTL_BIN_SCRIPT" user enable bob > /dev/null
    _gen > /dev/null
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_output --partial "bob:readonly:80001"
}

@test "config linux script: refuses a placeholder or unsafe secret" {
    load_fixture tacquito.minimal.yaml
    # The secret is the store's; put the placeholder there.
    sed -i 's/secret: .*/secret: REPLACE_WITH_SHARED_SECRET/' "${TACCTL_STATE_DIR}/store.yaml"
    grep -q 'secret: REPLACE_WITH_SHARED_SECRET' "${TACCTL_STATE_DIR}/store.yaml"
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

@test "config linux script: an output it cannot write, or a failing route lookup, is an error (exit 1, no 'Wrote')" {
    local bad="${BATS_TEST_TMPDIR}/no/such/dir/x.sh"
    run "$TACCTL_BIN_SCRIPT" config linux script --scope lab --server 192.0.2.10 -o "$bad"
    assert_failure 1
    assert_output --partial "[ERROR]"
    assert_output --partial "Cannot write ${bad}: No such file or directory"
    refute_output --partial "Wrote"
    stub_cmd ip 'exit 2'
    run "$TACCTL_BIN_SCRIPT" config linux script --scope lab --output "$OUT"
    assert_failure 1
    assert_output --partial "Could not determine this server's address (ip route failed); pass --server <address>"
    [[ ! -e "$OUT" ]]
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

@test "client install: creates new accounts with their UIDs, tac-users as primary group, private homes" {
    _gen > /dev/null
    _client_env
    run bash "$OUT" --accounts-only
    assert_success
    # tacctl's groups of a host other than the server, at their fixed GIDs.
    stub_called "groupadd -g 80000 tac-users"
    stub_called "groupadd -g 80002 tac-superuser"
    run grep -cE "^groupadd .*(tac-readonly|tac-operator|tac-console|alice|bob)" "$CALLS_LOG"
    assert_output "0"
    stub_called "useradd -m -u 80000 -g tac-users -s /bin/bash .* alice"
    stub_called "useradd -m -u 80001 -g tac-users -s /bin/bash .* bob"
    stub_called "usermod -aG tac-superuser alice"
    # tac-users is their primary group, so never a supplementary one too;
    # bob (readonly) is in no other group of a host other than the server.
    run grep -cE "^usermod -aG .*tac-users|^usermod -aG .*bob" "$CALLS_LOG"
    assert_output "0"
    run grep -E "^(alice|bob):" "$FAKE_DB/passwd"
    assert_line --partial "alice:x:80000:80000:"
    assert_line --partial "bob:x:80001:80000:"
    [[ "$(stat -c %a "$TACCTL_CLIENT_HOME_ROOT/alice")" == "700" ]]
    [[ "$(stat -c %a "$TACCTL_CLIENT_HOME_ROOT/bob")" == "700" ]]
    run cat "$TACCTL_CLIENT_STATE/created"
    assert_output "alice
bob"
    [[ ! -e "$TACCTL_CLIENT_STATE/adopted" ]]
    [[ ! -f "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" ]]
    # The protocol it ran, for 'host show --check'; no PAM file was written.
    run cat "$TACCTL_CLIENT_STATE/protocol"
    assert_output "$(sed -n 's/^TAC_PROTOCOL=//p' "$OUT")"
    [[ ! -e "$TACCTL_CLIENT_STATE/pam.sha256" ]]
}

@test "client install: the tacctl server's own script keeps every tier group, at fixed GIDs" {
    _gen > /dev/null
    _client_env
    _local_header
    run bash "$OUT" --accounts-only
    assert_success
    stub_called "groupadd -g 80000 tac-users"
    stub_called "groupadd -g 80001 tac-console"
    stub_called "groupadd -g 80002 tac-superuser"
    stub_called "groupadd -g 80003 tac-operator"
    stub_called "groupadd -g 80004 tac-readonly"
    stub_called "usermod -aG tac-superuser alice"
    stub_called "usermod -aG tac-readonly bob"
}

@test "client install: an earlier release's groups move to the fixed GIDs; own groups go; unused tier groups go" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE" "$TACCTL_CLIENT_HOME_ROOT/alice" "$TACCTL_CLIENT_HOME_ROOT/bob"
    chmod 755 "$TACCTL_CLIENT_HOME_ROOT/alice" "$TACCTL_CLIENT_HOME_ROOT/bob"
    printf '%s\n' alice bob > "$TACCTL_CLIENT_STATE/created"
    printf '%s\n' "alice:x:80000:80000:alice (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/alice:/bin/bash" \
        "bob:x:80001:80001:bob (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/bob:/bin/bash" >> "$FAKE_DB/passwd"
    printf '%s\n' "alice:x:80000:" "bob:x:80001:" "tac-users:x:1001:alice,bob" "tac-readonly:x:1002:bob" \
        "tac-operator:x:1003:" "tac-superuser:x:1004:alice" "tac-console:x:20002:alice,admin" >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only
    assert_success
    stub_called "usermod -g tac-users alice"
    stub_called "groupdel alice"
    stub_called "groupdel bob"
    assert_output --partial "[INFO] 'alice': primary group is now tac-users (was GID 80000)."
    stub_called "groupmod -g 80000 tac-users"
    stub_called "groupmod -g 80002 tac-superuser"
    assert_output --partial "[INFO] Group 'tac-users' is now GID 80000 (was 1001)."
    # Only tacctl's accounts in them: removed. admin keeps tac-console.
    stub_called "groupdel tac-readonly"
    stub_called "groupdel tac-operator"
    assert_output --partial "[INFO] Group 'tac-console' is not used by tacctl on this host, but is kept: admin."
    run grep -E "^(alice|bob|tac-[a-z]+):" "$FAKE_DB/group"
    assert_output $'tac-users:x:80000:alice,bob\ntac-superuser:x:80002:alice\ntac-console:x:20002:alice,admin'
    run grep -E "^(alice|bob):" "$FAKE_DB/passwd"
    assert_line --partial "alice:x:80000:80000:"
    assert_line --partial "bob:x:80001:80000:"
    [[ "$(stat -c %a "$TACCTL_CLIENT_HOME_ROOT/alice")" == "700" ]]
    # Once: a second run changes no group.
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    run grep -cE "^(groupadd|groupmod|groupdel|usermod -g)" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: an account with tac-users as primary group is no longer listed in it as well, once" {
    _gen > /dev/null
    _client_env
    # gpasswd -d takes the member out of the group in the database.
    stub_cmd gpasswd '[[ "$1" == "-d" ]] || exit 0
        awk -F: -v OFS=: -v u="$2" -v g="$3" "\$1 == g { n = split(\$4, m, \",\"); \$4 = \"\"; for (i = 1; i <= n; i++) if (m[i] != u) \$4 = \$4 (\$4 == \"\" ? \"\" : \",\") m[i] } 1" "$FAKE_DB/group" > "$FAKE_DB/g.new" && mv "$FAKE_DB/g.new" "$FAKE_DB/group"'
    mkdir -p "$TACCTL_CLIENT_STATE" "$TACCTL_CLIENT_HOME_ROOT/alice" "$TACCTL_CLIENT_HOME_ROOT/bob"
    chmod 700 "$TACCTL_CLIENT_HOME_ROOT/alice" "$TACCTL_CLIENT_HOME_ROOT/bob"
    printf '%s\n' alice bob > "$TACCTL_CLIENT_STATE/created"
    # As 0.2.1 leaves a 0.2.0 host: tac-users is the primary group of both,
    # and alice is still listed in it as a supplementary group; bob is not.
    printf '%s\n' "alice:x:80000:80000:alice (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/alice:/bin/bash" \
        "bob:x:80001:80000:bob (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/bob:/bin/bash" >> "$FAKE_DB/passwd"
    printf '%s\n' "tac-users:x:80000:alice" "tac-superuser:x:80002:alice" >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[INFO] 'alice': no longer listed in tac-users as a supplementary group (it is the primary group)."
    refute_output --partial "'bob': no longer listed"
    [[ $(grep -c "supplementary" <<< "$output") == 1 ]]
    stub_called "gpasswd -d alice tac-users"
    run grep -c "^gpasswd -d bob tac-users" "$CALLS_LOG"
    assert_output "0"
    # Once: a second run changes nothing.
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    refute_output --partial "supplementary"
    run grep -cE "^(gpasswd|usermod -aG .*tac-users)" "$CALLS_LOG"
    assert_output "0"
    run grep -E "^tac-" "$FAKE_DB/group"
    assert_output $'tac-users:x:80000:\ntac-superuser:x:80002:alice'
}

@test "client install: an own group at tac-users' fixed GID (an earlier build) gives way to it" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE" "$TACCTL_CLIENT_HOME_ROOT/alice"
    echo alice > "$TACCTL_CLIENT_STATE/created"
    echo "alice:x:80000:80000:alice (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/alice:/bin/bash" >> "$FAKE_DB/passwd"
    echo "alice:x:80000:" >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only
    assert_success
    refute_output --partial "[WARN]"
    stub_called "groupdel alice"
    stub_called "groupmod -g 80000 tac-users"
    run grep -E "^(alice|tac-users):" "$FAKE_DB/group"
    assert_output "tac-users:x:80000:"
    run grep "^alice:" "$FAKE_DB/passwd"
    assert_output --partial "alice:x:80000:80000:"
}

@test "client install: tacctl's groups numbered in an earlier build's order swap to their fixed GIDs" {
    _gen > /dev/null
    _client_env
    _local_header
    printf '%s\n' "tac-users:x:80000:" "tac-readonly:x:80001:" "tac-operator:x:80002:" \
        "tac-superuser:x:80003:" "tac-console:x:80004:" >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only
    assert_success
    refute_output --partial "[WARN] Group"
    # The GID each had, not the spare one it waited on.
    assert_output --partial "[INFO] Group 'tac-superuser' is now GID 80002 (was 80003)."
    assert_output --partial "[INFO] Group 'tac-console' is now GID 80001 (was 80004)."
    run grep -E "^tac-" "$FAKE_DB/group"
    assert_output $'tac-users:x:80000:\ntac-readonly:x:80004:\ntac-operator:x:80003:\ntac-superuser:x:80002:\ntac-console:x:80001:'
}

@test "client install: a fixed GID held by another group is left to it, and said" {
    _gen > /dev/null
    _client_env
    echo 'staff9:x:80002:' >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] Group 'tac-superuser' was created with GID 900, not 80002: GID 80002 belongs to group 'staff9' here."
    stub_called "groupadd -g 80000 tac-users"
}

@test "client install: stops before changing anything when the assigned UID is taken" {
    _gen > /dev/null
    _client_env
    echo 'squatter:x:80000:80000::/home/squatter:/bin/bash' >> "$FAKE_DB/passwd"
    run bash "$OUT" --accounts-only
    assert_failure
    assert_output --partial "alice: UID 80000 already belongs to user 'squatter'"
    assert_output --partial "Nothing was changed"
    assert_output --partial "tacctl config linux uid <user> <new-uid>"
    assert_output --partial "--allow-uid-mismatch"
    run grep -cE "^(useradd|groupadd|usermod|gpasswd)" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a group named like the user, or a GID equal to its UID, does not stand in the way" {
    _gen > /dev/null
    _client_env
    printf '%s\n' 'staff2:x:80001:' 'alice:x:1500:' >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only
    assert_success
    stub_called "useradd -m -u 80000 -g tac-users -s /bin/bash .* alice"
    stub_called "useradd -m -u 80001 -g tac-users -s /bin/bash .* bob"
    run grep -cE "^group(add|mod|del) .*(alice|staff2)" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: --allow-uid-mismatch takes a free number of the range, from the top" {
    _gen > /dev/null
    _client_env
    echo 'squatter:x:80000:80000::/home/squatter:/bin/bash' >> "$FAKE_DB/passwd"
    echo 'other:x:89999:' >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only --allow-uid-mismatch
    assert_success
    assert_output --partial "conflicts accepted (--allow-uid-mismatch); these users get a free number of 80000-89999 on this host"
    # A GID of the range (the group 'other') does not matter: UIDs only.
    assert_output --partial "Created account 'alice' (superuser) with UID 89999 (tacctl assigned 80000; --allow-uid-mismatch)."
    stub_called "useradd -m -u 89999 -g tac-users -s /bin/bash .* alice"
    run grep -c "useradd -m -s" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a tacctl account whose UID differs (in the range) is kept and reported with fixes" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE"
    echo bob > "$TACCTL_CLIENT_STATE/created"
    echo 'bob:x:80500:80500:bob (TACACS+):/home/bob:/bin/bash' >> "$FAKE_DB/passwd"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "bob: UID 80500 on this host, 80001 assigned by tacctl"
    assert_output --partial "usermod -u <uid> <user>"
    refute_output --partial "groupmod"
    assert_output --partial "tacctl config linux uid <user> <uid-on-this-host>"
    stub_called "usermod -g tac-users bob"
    run grep -cE "^usermod -aG .*bob" "$CALLS_LOG"
    assert_output "0"
}

@test "config linux uid: lists, shows and reassigns within 80000-89999; refuses duplicates and other values" {
    _gen > /dev/null
    run "$TACCTL_BIN_SCRIPT" config linux uid
    assert_success
    assert_line --regexp "alice +80000"
    run "$TACCTL_BIN_SCRIPT" config linux uid bob
    assert_output "80001"
    for bad in 1001 20000 29999 79999 90000 65534 080000; do
        run "$TACCTL_BIN_SCRIPT" config linux uid bob "$bad"
        assert_failure
        assert_output --partial "UID must be a number from 80000 to 89999: tacctl gives out UIDs in that range only."
    done
    run "$TACCTL_BIN_SCRIPT" config linux uid bob 85000
    assert_success
    assert_output --partial "usermod -u 85000 bob"
    _gen > /dev/null
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_output --partial "bob:readonly:85000"
    run "$TACCTL_BIN_SCRIPT" config linux uid bob 80000
    assert_failure
    assert_output --partial "already assigned to 'alice'"
    run "$TACCTL_BIN_SCRIPT" config linux uid ghost 81000
    assert_failure
    # A new user is numbered after the highest assignment, never into a gap.
    "$TACCTL_BIN_SCRIPT" user add carol operator --hash "$HASH" --scopes lab > /dev/null
    _gen > /dev/null
    run "$TACCTL_BIN_SCRIPT" config linux uid carol
    assert_output "85001"
}

@test "config linux uid: an entry outside the range (from an earlier release) is reported and never sent to a host" {
    printf '%s\n' 'alice:80000' 'bob:1001' > "${TACCTL_STATE_DIR}/linux-uids"
    run "$TACCTL_BIN_SCRIPT" config linux uid
    assert_success
    assert_line --regexp "^  bob +1001   outside 80000-89999: not used on hosts$"
    run _gen
    assert_success
    assert_output --partial "Skipping 'bob': its UID 1001 is outside 80000-89999, so no host gets an account for it."
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_line "TAC_USERS=alice:superuser:80000"
    assert_line "TAC_INACTIVE=bob"
}

@test "config linux script: no UID is given out past 89999" {
    echo 'alice:89999' > "${TACCTL_STATE_DIR}/linux-uids"
    run _gen
    assert_failure 1
    assert_output --partial "No UID left for 'bob': every number of 80000-89999 has been given out (UIDs are never reused)."
    assert_output --partial "Give it a free number of the range by hand: tacctl config linux uid bob <uid>"
    [[ ! -e "$OUT" ]]
    run cat "${TACCTL_STATE_DIR}/linux-uids"
    assert_output $'# range 80000-89999\nalice:89999'
}

@test "config linux uid: a listing or a lookup does not create or rewrite the UID file" {
    local f="${TACCTL_STATE_DIR}/linux-uids"
    rm -f "$f"
    run "$TACCTL_BIN_SCRIPT" config linux uid
    assert_success
    assert_output --partial "None yet."
    run "$TACCTL_BIN_SCRIPT" config linux uid bob
    assert_failure
    assert_output --partial "No UID assigned to 'bob' yet."
    [ ! -e "$f" ]
    # A refused change does not create it either.
    run "$TACCTL_BIN_SCRIPT" config linux uid bob 500
    assert_failure
    [ ! -e "$f" ]

    _gen > /dev/null
    touch -d '2001-01-01 00:00:00' "$f"
    local before
    before="$(stat -c '%Y %s' "$f"):$(cat "$f")"
    run "$TACCTL_BIN_SCRIPT" config linux uid
    assert_success
    run "$TACCTL_BIN_SCRIPT" config linux uid bob
    assert_output "80001"
    [ "$(stat -c '%Y %s' "$f"):$(cat "$f")" = "$before" ]
}

@test "client install: a local account with a tacctl user's name is refused for that user; the rest proceeds" {
    _gen > /dev/null
    _client_env
    echo 'bob:x:1001:1001::/home/bob:/bin/bash' >> "$FAKE_DB/passwd"
    echo 'bob:$y$hash:1::::::' >> "$FAKE_DB/shadow"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] 'bob': this host has a local account of that name that tacctl did not create, so 'bob' gets no TACACS+ account here. The local account is left as it is."
    assert_output --partial "[INFO] Accounts: 1 managed by tacctl here; refused: bob."
    stub_called "useradd -m -u 80000 -g tac-users .* alice"
    run grep -cE "^(useradd|groupadd|usermod|gpasswd|userdel|groupdel) .*bob" "$CALLS_LOG"
    assert_output "0"
    run cat "$TACCTL_CLIENT_STATE/created"
    assert_output "alice"
    # In tacctl's groups (an account an earlier release adopted): taken out
    # of them, and only that.
    printf '%s\n' "tac-users:x:900:bob" "tac-readonly:x:901:bob" >> "$FAKE_DB/group"
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[INFO] 'bob': removed from tacctl's groups (tac-users, tac-readonly); it is a plain local account again."
    stub_called "gpasswd -d bob tac-users"
    stub_called "gpasswd -d bob tac-readonly"
    run grep -cE "^(useradd|usermod|userdel|groupdel|chage|passwd) .*bob" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: --adopt is not an option" {
    _gen > /dev/null
    _client_env
    run bash "$OUT" --accounts-only --adopt bob
    assert_failure
    assert_output --partial "Unknown argument '--adopt'. Usage:"
    run grep -cE "^(useradd|groupadd)" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a header of another protocol stops the run before anything changes" {
    _gen > /dev/null
    _client_env
    sed -i 's/^TAC_PROTOCOL=5$/TAC_PROTOCOL=2/' "$OUT"
    run bash "$OUT" --accounts-only
    assert_failure
    assert_output --partial "This script's header speaks protocol 2 and its body protocol 5"
    sed -i '/^TAC_PROTOCOL=/d' "$OUT"
    run bash "$OUT" --accounts-only
    assert_failure
    assert_output --partial "header speaks protocol 1"
    run grep -cE "^(useradd|groupadd|usermod)" "$CALLS_LOG"
    assert_output "0"
    [[ ! -e "$TACCTL_CLIENT_STATE/created" ]]
}

@test "client install: accounts an earlier release adopted are reported once and never changed" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE"
    printf '%s\n' olduser bob > "$TACCTL_CLIENT_STATE/adopted"
    echo "tac-users:x:900:olduser,bob" >> "$FAKE_DB/group"
    echo 'olduser:x:1500:1500::/nonexistent:/bin/bash' >> "$FAKE_DB/passwd"
    echo 'bob:x:1001:1001::/home/bob:/bin/bash' >> "$FAKE_DB/passwd"
    echo 'olduser:$y$hash:1::::::' >> "$FAKE_DB/shadow"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] Accounts an earlier tacctl adopted are no longer tracked: bob olduser. Only their membership in tacctl's groups is removed."
    # Cleaned up in the same run that forgets them, and nothing else changes.
    assert_output --partial "[INFO] 'olduser': removed from tacctl's groups (tac-users); it is a plain local account again."
    assert_output --partial "[INFO] 'bob': removed from tacctl's groups (tac-users); it is a plain local account again."
    stub_called "gpasswd -d olduser tac-users"
    stub_called "gpasswd -d bob tac-users"
    run grep -cE "^(useradd|usermod|userdel|groupdel) .*(olduser|bob)" "$CALLS_LOG"
    assert_output "0"
    [[ ! -e "$TACCTL_CLIENT_STATE/adopted" ]]
    run bash "$OUT" --accounts-only
    assert_success
    refute_output --partial "adopted"
}

@test "client install: accounts are named after their login; old generic names are corrected" {
    _gen > /dev/null
    _client_env
    run bash "$OUT" --accounts-only
    assert_success
    stub_called "useradd -m -u 80000 -g tac-users -s /bin/bash -K UID_MIN=80000 -K UID_MAX=89999 -c alice .TACACS.. alice"

    # An account created by an earlier version carries the generic name.
    sed -i 's/^alice:x:80000:80000:alice (TACACS+):/alice:x:80000:80000:TACACS+ user (tacctl):/' "$FAKE_DB/passwd"
    run bash "$OUT" --accounts-only
    assert_success
    stub_called "usermod -c alice .TACACS.. alice"
    run grep -c "usermod -c .* bob" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a tier change drops the old tier group" {
    _gen > /dev/null
    _client_env
    FAKE_ID_GROUPS="tac-users tac-superuser" run bash "$OUT" --accounts-only
    assert_success
    stub_called "gpasswd -d bob tac-superuser"
}

@test "client install: a removed user's account is deleted with its group; the home is kept unless asked for" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE" "$TACCTL_CLIENT_HOME_ROOT/olduser"
    echo "olduser" > "$TACCTL_CLIENT_STATE/created"
    echo "olduser" > "$TACCTL_CLIENT_STATE/expired"
    echo "olduser:x:80005:80005:olduser (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/olduser:/bin/bash" >> "$FAKE_DB/passwd"
    printf '%s\n' "tac-users:x:900:olduser,localguy" "olduser:x:80005:" >> "$FAKE_DB/group"
    echo 'localguy:x:1600:1600::/home/localguy:/bin/bash' >> "$FAKE_DB/passwd"
    run bash "$OUT" --accounts-only
    assert_success
    stub_called "gpasswd -d olduser tac-users"
    stub_called "userdel olduser"
    stub_called "groupdel olduser"
    assert_output --partial "[INFO] Deleted account 'olduser': no longer a TACACS+ user here (its UID 80005 stays reserved on the tacctl server, never reused)."
    # The kept home moves out of reach of a later account with the same UID.
    assert_output --regexp "\[INFO\] home kept: ${TACCTL_CLIENT_HOME_ROOT}/\.tacctl-removed/olduser-[0-9]{8}-[0-9]{6}"$'\n'
    moved=("$TACCTL_CLIENT_HOME_ROOT"/.tacctl-removed/olduser-*)
    [[ ${#moved[@]} == 1 && -d "${moved[0]}" && ! -e "$TACCTL_CLIENT_HOME_ROOT/olduser" ]]
    stub_called "chown root:root ${TACCTL_CLIENT_HOME_ROOT}/.tacctl-removed"
    stub_called "chown -hR root:root -- ${moved[0]}"
    # A local account in tac-users that tacctl did not create: out of
    # tacctl's groups, nothing else.
    assert_output --partial "[INFO] 'localguy': removed from tacctl's groups (tac-users); it is a plain local account again."
    run grep -c olduser "$TACCTL_CLIENT_STATE/created" "$TACCTL_CLIENT_STATE/expired"
    assert_output "${TACCTL_CLIENT_STATE}/created:0
${TACCTL_CLIENT_STATE}/expired:0"
    # Not userdel -r: the home is the operator's call.
    run grep -c "userdel -r" "$CALLS_LOG"
    assert_output "0"
    stub_called "gpasswd -d localguy tac-users"
    run grep -cE "^(usermod|userdel) .*localguy" "$CALLS_LOG"
    assert_output "0"
    run stat -c %a "$TACCTL_CLIENT_HOME_ROOT/.tacctl-removed" "${moved[0]}"
    assert_output "700
700"
}

@test "client install: removed users' homes go only when named (TAC_REMOVE_HOMES) or with --remove-home" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE"
    printf '%s\n' old1 old2 > "$TACCTL_CLIENT_STATE/created"
    for u in old1 old2; do
        mkdir -p "$TACCTL_CLIENT_HOME_ROOT/$u/.ssh"
        echo key > "$TACCTL_CLIENT_HOME_ROOT/$u/.ssh/authorized_keys"
    done
    echo "old1:x:80005:80005:old1 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/old1:/bin/bash" >> "$FAKE_DB/passwd"
    echo "old2:x:80006:80006:old2 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/old2:/bin/bash" >> "$FAKE_DB/passwd"
    # A link inside a home is removed, never followed.
    mkdir -p "$BATS_TEST_TMPDIR/precious"
    ln -s "$BATS_TEST_TMPDIR/precious" "$TACCTL_CLIENT_HOME_ROOT/old1/link"
    sed -i "s/^TAC_REMOVE_HOMES=.*/TAC_REMOVE_HOMES=old1/" "$OUT"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[INFO] Deleted home ${TACCTL_CLIENT_HOME_ROOT}/old1."
    assert_output --partial "[INFO] home kept: ${TACCTL_CLIENT_HOME_ROOT}/.tacctl-removed/old2-"
    moved=("$TACCTL_CLIENT_HOME_ROOT"/.tacctl-removed/old2-*)
    [[ ! -e "$TACCTL_CLIENT_HOME_ROOT/old1" && ! -e "$TACCTL_CLIENT_HOME_ROOT/old2" && -d "$BATS_TEST_TMPDIR/precious" ]]
    [[ -f "${moved[0]}/.ssh/authorized_keys" ]]

    # --remove-home (TAC_REMOVE_HOMES='*' from 'host sync --remove-home'): every one.
    echo old3 >> "$TACCTL_CLIENT_STATE/created"
    mkdir -p "$TACCTL_CLIENT_HOME_ROOT/old3"
    echo "old3:x:80007:80007:old3 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/old3:/bin/bash" >> "$FAKE_DB/passwd"
    sed -i "s/^TAC_REMOVE_HOMES=.*/TAC_REMOVE_HOMES=''/" "$OUT"
    run bash "$OUT" --accounts-only --remove-home
    assert_success
    assert_output --partial "Deleted home ${TACCTL_CLIENT_HOME_ROOT}/old3."
    [[ ! -e "$TACCTL_CLIENT_HOME_ROOT/old3" ]]
}

@test "client install: a home outside /home, behind a link, shared or not the user's own is kept" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE" "$BATS_TEST_TMPDIR/elsewhere/h1" "$BATS_TEST_TMPDIR/real" \
        "$TACCTL_CLIENT_HOME_ROOT/team" "$TACCTL_CLIENT_HOME_ROOT/h4"
    ln -s "$BATS_TEST_TMPDIR/real" "$TACCTL_CLIENT_HOME_ROOT/h2"
    printf '%s\n' h1 h2 h3 h4 > "$TACCTL_CLIENT_STATE/created"
    printf '%s\n' "h1:x:80011:80011:h1 (TACACS+):${BATS_TEST_TMPDIR}/elsewhere/h1:/bin/bash" \
        "h2:x:80012:80012:h2 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/h2:/bin/bash" \
        "h3:x:80013:80013:h3 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/team:/bin/bash" \
        "mate:x:1700:1700::${TACCTL_CLIENT_HOME_ROOT}/team:/bin/bash" >> "$FAKE_DB/passwd"
    run bash "$OUT" --accounts-only --remove-home
    assert_success
    assert_output --partial "[WARN] home kept in place: ${BATS_TEST_TMPDIR}/elsewhere/h1 (not a directory directly under ${TACCTL_CLIENT_HOME_ROOT})"
    assert_output --partial "[WARN] home kept in place: ${TACCTL_CLIENT_HOME_ROOT}/h2 (it is a symbolic link)"
    assert_output --partial "[WARN] home kept in place: ${TACCTL_CLIENT_HOME_ROOT}/team (also the home of 'mate')"
    [[ -d "$BATS_TEST_TMPDIR/elsewhere/h1" && -L "$TACCTL_CLIENT_HOME_ROOT/h2" && -d "$BATS_TEST_TMPDIR/real" && -d "$TACCTL_CLIENT_HOME_ROOT/team" ]]
    # Owned by another UID than the account's.
    echo "h4:x:80014:80014:h4 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/h4:/bin/bash" >> "$FAKE_DB/passwd"
    echo h4 >> "$TACCTL_CLIENT_STATE/created"
    TACCTL_CLIENT_HOME_OWNER=4242 run bash "$OUT" --accounts-only --remove-home
    assert_success
    assert_output --partial "home kept in place: ${TACCTL_CLIENT_HOME_ROOT}/h4 (owned by UID $(stat -c %u "$TACCTL_CLIENT_HOME_ROOT/h4"), not 80014)"
    [[ -d "$TACCTL_CLIENT_HOME_ROOT/h4" ]]
}

@test "client install: a kept home is not moved through a removed-homes directory that is a link" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE" "$TACCTL_CLIENT_HOME_ROOT/k1" "$TACCTL_CLIENT_HOME_ROOT/k2" "$BATS_TEST_TMPDIR/elsewhere"
    printf '%s\n' k1 k2 > "$TACCTL_CLIENT_STATE/created"
    printf '%s\n' "k1:x:80021:80021:k1 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/k1:/bin/bash" \
        "k2:x:80022:80022:k2 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/k2:/bin/bash" >> "$FAKE_DB/passwd"
    # .tacctl-removed is a link to somewhere else: nothing is moved through it.
    ln -s "$BATS_TEST_TMPDIR/elsewhere" "$TACCTL_CLIENT_HOME_ROOT/.tacctl-removed"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] home kept in place: ${TACCTL_CLIENT_HOME_ROOT}/k1 (${TACCTL_CLIENT_HOME_ROOT}/.tacctl-removed is not a real directory)"
    assert_output --partial "[WARN] home kept in place: ${TACCTL_CLIENT_HOME_ROOT}/k2 (${TACCTL_CLIENT_HOME_ROOT}/.tacctl-removed is not a real directory)"
    [[ -d "$TACCTL_CLIENT_HOME_ROOT/k1" && -d "$TACCTL_CLIENT_HOME_ROOT/k2" ]]
    run ls -A "$BATS_TEST_TMPDIR/elsewhere"
    assert_output ""
    run grep -c "^chown -hR" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: an account outside 80000-89999 is never touched, even when listed as created" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE" "$TACCTL_CLIENT_HOME_ROOT/legacy"
    printf '%s\n' legacy bob > "$TACCTL_CLIENT_STATE/created"
    echo "legacy:x:1500:1500:legacy (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/legacy:/bin/bash" >> "$FAKE_DB/passwd"
    echo "bob:x:1001:1001:bob (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/bob:/bin/bash" >> "$FAKE_DB/passwd"
    echo "tac-users:x:900:legacy,bob" >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only --remove-home
    assert_success
    assert_output --partial "[WARN] 'legacy' has UID 1500, outside 80000-89999: tacctl changes nothing on it but its membership in tacctl's groups, although it created it."
    assert_output --partial "[WARN] 'bob': its account has UID 1001, outside 80000-89999; tacctl changes nothing on it but its membership in tacctl's groups."
    assert_output --partial "[INFO] 'legacy': removed from tacctl's groups (tac-users); it is a plain local account again."
    assert_output --partial "[INFO] 'bob': removed from tacctl's groups (tac-users); it is a plain local account again."
    assert_output --partial "[INFO] Accounts: 1 managed by tacctl here; refused: bob."
    run grep -cE "^(usermod|userdel|groupdel|useradd) .*(legacy|bob)" "$CALLS_LOG"
    assert_output "0"
    [[ -d "$TACCTL_CLIENT_HOME_ROOT/legacy" ]]
}

# --- renumbering from the legacy range (20000-29999) ---------------------------

# A server map and a host as an earlier release left them: alice (listed)
# and gone (removed from the scope) were created by tacctl at legacy UIDs;
# pat is a local account in the legacy range that tacctl did not create.
_legacy_host() {
    printf '%s\n' 'alice:20000' 'bob:20001' 'gone:20002' > "${TACCTL_STATE_DIR}/linux-uids"
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE" "$TACCTL_CLIENT_HOME_ROOT/alice" "$TACCTL_CLIENT_HOME_ROOT/gone" "$TACCTL_CLIENT_HOME_ROOT/pat"
    echo note > "$TACCTL_CLIENT_HOME_ROOT/alice/note"
    printf '%s\n' alice gone > "$TACCTL_CLIENT_STATE/created"
    printf '%s\n' "alice:x:20000:20000:alice (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/alice:/bin/bash" \
        "gone:x:20002:20002:gone (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/gone:/bin/bash" \
        "pat:x:20005:20005:Pat:${TACCTL_CLIENT_HOME_ROOT}/pat:/bin/bash" >> "$FAKE_DB/passwd"
    printf '%s\n' "alice:x:20000:" "gone:x:20002:" "pat:x:20005:" "tac-users:x:900:alice,gone" >> "$FAKE_DB/group"
}

@test "client install: accounts it created at legacy UIDs are renumbered once (UID, home; own group gone); others untouched" {
    _legacy_host
    # The server's map was renumbered by the script's generation, logged,
    # the old one kept.
    run cat "${TACCTL_STATE_DIR}/linux-uids"
    assert_output $'# range 80000-89999\n# previous 20000-29999\nalice:80000\nbob:80001\ngone:80002'
    run cat "${TACCTL_STATE_DIR}"/linux-uids.pre-renumber-*
    assert_output $'alice:20000\nbob:20001\ngone:20002'
    stub_called "logger -t tacctl -p auth.info uid-map renumbered 3 entries from=20000-29999 to=80000-89999 backup=${TACCTL_STATE_DIR}/linux-uids.pre-renumber-"
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_line "TAC_USERS=\$'alice:superuser:80000\\nbob:readonly:80001'"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[INFO] 'alice': renumbered 20000 -> 80000 (home re-owned)"
    assert_output --partial "[INFO] 'gone': renumbered 20002 -> 80002 (home re-owned)"
    # alice is managed again at once; gone, renumbered first, is deleted
    # under its new number; bob is created.
    assert_output --partial "Deleted account 'gone': no longer a TACACS+ user here (its UID 80002 stays reserved"
    assert_output --partial "[INFO] Accounts: 2 managed by tacctl here; 2 renumbered."
    stub_called "usermod -aG tac-superuser alice"
    stub_called "useradd -m -u 80001 -g tac-users"
    stub_called "pgrep -u 20000"
    stub_called "usermod -u 80000 alice"
    stub_called "usermod -g tac-users alice"
    stub_called "groupdel alice"
    run grep -cE "^(alice|gone):" "$FAKE_DB/group"
    assert_output "0"
    run grep "^alice:" "$FAKE_DB/passwd"
    assert_output "alice:x:80000:80000:alice (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/alice:/bin/bash"
    # pat (legacy range, not tacctl's) is left exactly as it is.
    run grep -cE "^(usermod|groupmod|userdel|groupdel|gpasswd|pgrep) .*(pat|20005)" "$CALLS_LOG"
    assert_output "0"
    run grep -c "^pat:x:20005:20005:Pat:" "$FAKE_DB/passwd"
    assert_output "1"
    # Once: a second run renumbers nothing.
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    refute_output --partial "renumbered"
    assert_output --partial "[INFO] Accounts: 2 managed by tacctl here."
    run grep -cE "^(usermod -u|groupmod)" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a legacy account whose new UID is taken here is left as it is and refused" {
    _legacy_host
    echo "squat:x:80000:80000::/srv/squat:/bin/bash" >> "$FAKE_DB/passwd"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] 'alice': not renumbered from 20000 to 80000: UID 80000 belongs to 'squat' here. The account is left as it is until 80000 is free here."
    assert_output --partial "[INFO] Accounts: 1 managed by tacctl here; 1 renumbered; refused: alice."
    run grep -cE "^(usermod|groupmod|gpasswd) .*alice" "$CALLS_LOG"
    assert_output "0"
    run grep -c "^alice:x:20000:20000:" "$FAKE_DB/passwd"
    assert_output "1"

    # A group with GID 80000 is no obstacle to the UID: tac-users then
    # keeps its number, and that is said.
    sed -i '/^squat:/d' "$FAKE_DB/passwd"
    sed -i 's/^tac-users:x:80000:/tac-users:x:900:/' "$FAKE_DB/group"
    echo "staff9:x:80000:" >> "$FAKE_DB/group"
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[INFO] 'alice': renumbered 20000 -> 80000 (home re-owned)"
    assert_output --partial "[WARN] Group 'tac-users' keeps GID 900, not 80000: GID 80000 belongs to group 'staff9' here."
}

@test "client install: a legacy account whose user is logged in is left as it is until the next sync" {
    _legacy_host
    stub_cmd pgrep '[[ "$*" == "-u 20000" ]]'
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] 'alice': not renumbered from 20000 to 80000: processes run as UID 20000 (still logged in?). The account is left as it is until the next sync."
    assert_output --partial "[INFO] Accounts: 1 managed by tacctl here; 1 renumbered; refused: alice."
    # Untouched, its groups too.
    run grep -cE "^(usermod|groupmod|gpasswd) .*alice" "$CALLS_LOG"
    assert_output "0"
    refute_output --partial "'alice': removed from tacctl's groups"
    # Logged out: the next sync renumbers it.
    stub_cmd pgrep 'exit 1'
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[INFO] 'alice': renumbered 20000 -> 80000 (home re-owned)"
    assert_output --partial "[INFO] Accounts: 2 managed by tacctl here; 1 renumbered."
}

@test "client install: usermod that fails before or after changing the UID is reported as such" {
    _legacy_host
    # Fails outright: nothing changed, the account is left as it is.
    stub_cmd usermod '[[ "$1" == "-u" ]] && exit 12; exit 0'
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] 'alice': not renumbered from 20000 to 80000: usermod failed. The account is left as it is until the next sync."
    assert_output --partial "refused: alice."
    # Changes the UID, then cannot re-own the home: renumbered, and said so.
    stub_cmd usermod '[[ "$1" == "-u" ]] || exit 0
        awk -F: -v OFS=: -v n="$3" -v v="$2" "\$1 == n { \$3 = v } 1" "$FAKE_DB/passwd" > "$FAKE_DB/p.new" && mv "$FAKE_DB/p.new" "$FAKE_DB/passwd"
        exit 12'
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] 'alice': its UID is now 80000, but usermod could not re-own all of ${TACCTL_CLIENT_HOME_ROOT}/alice; finish it by hand: chown -hR --from=20000 80000 ${TACCTL_CLIENT_HOME_ROOT}/alice"
    assert_output --partial "[INFO] 'alice': renumbered 20000 -> 80000 (home not fully re-owned)"
}

@test "client install: files outside the home that keep the old number are listed (at most 20), never changed" {
    _legacy_host
    stub_cmd find 'if [[ " $* " == *" -print "* ]]; then for i in $(seq 1 25); do echo "/var/tmp/stray$i"; done; fi'
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] 'alice': these files still carry its old number 20000 and were left as they are (chown -h 80000:tac-users <file> gives them back):"
    assert_line "    /var/tmp/stray20"
    refute_line "    /var/tmp/stray21"
    assert_output --partial "    ... more; find them with: find / -xdev \\( -uid 20000 -o -gid 20000 \\)"
    stub_called "find ${TACCTL_CLIENT_HOME_ROOT} -xdev \\( -uid 20000 -o -gid 20000 \\) -print"
    run grep -cE "^(chown|chgrp) .*stray" "$CALLS_LOG"
    assert_output "0"
}

# --- the tacctl server's own accounts: the login shell field --------------------

# _console_header: the script's TAC_USERS with a shell per user, as 'host
# enroll --local' writes it (config linux script writes three fields).
_console_header() {
    sed -i "s|^TAC_USERS=.*|TAC_USERS=\$'alice:superuser:80000:$1\\\\nbob:readonly:80001:$2'|" "$OUT"
    _local_header
}
# The tacctl server's own script (host enroll --local): TAC_LOCAL=1.
_local_header() {
    grep -q '^TAC_LOCAL=1$' "$OUT" || sed -i 's/^TAC_PROTOCOL=/TAC_LOCAL=1\nTAC_PROTOCOL=/' "$OUT"
}
CONSOLE=/usr/local/bin/tacctl-console

@test "client install: the shell field makes console accounts, tac-console follows it, the summary counts them" {
    _gen > /dev/null
    _client_env
    _console_header "$CONSOLE" /bin/bash
    run bash "$OUT" --accounts-only
    assert_success
    stub_called "groupadd -g 80001 tac-console"
    stub_called "useradd -m -u 80000 -g tac-users -s ${CONSOLE} -K UID_MIN=80000 -K UID_MAX=89999 -c alice \\(TACACS\\+\\) alice"
    stub_called "useradd -m -u 80001 -g tac-users -s /bin/bash -K UID_MIN=80000 -K UID_MAX=89999 -c bob \\(TACACS\\+\\) bob"
    stub_called "usermod -aG tac-superuser,tac-console alice"
    stub_called "usermod -aG tac-readonly bob"
    assert_output --partial "[INFO] Accounts: 2 managed by tacctl here; console: 1."
    # Switched: alice back to bash (out of tac-console), bob to the console.
    _console_header /bin/bash "$CONSOLE"
    : > "$CALLS_LOG"
    FAKE_ID_GROUPS="tac-users tac-superuser tac-console" run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[INFO] 'alice': login shell is now /bin/bash."
    assert_output --partial "[INFO] 'bob': login shell is now the tacctl console."
    stub_called "usermod -s /bin/bash alice"
    stub_called "usermod -s ${CONSOLE} bob"
    stub_called "gpasswd -d alice tac-console"
    stub_called "usermod -aG tac-readonly,tac-console bob"
    run grep -E "^(alice|bob):" "$FAKE_DB/passwd"
    assert_line --partial "alice:x:80000:80000:alice (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/alice:/bin/bash"
    assert_line --partial "bob:x:80001:80000:bob (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/bob:${CONSOLE}"
    # Unchanged shells: nothing to do.
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    refute_output --partial "login shell is now"
    if stub_called "^usermod -s "; then stub_calls; return 1; fi
}

@test "client install: three fields (every other host) leave the shell alone" {
    _gen > /dev/null
    _client_env
    bash "$OUT" --accounts-only > /dev/null
    awk -F: -v OFS=: -v c="$CONSOLE" '$1 == "alice" { $7 = c } 1' "$FAKE_DB/passwd" > "$FAKE_DB/p.new" && mv "$FAKE_DB/p.new" "$FAKE_DB/passwd"
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    if stub_called "^usermod -s "; then stub_calls; return 1; fi
    refute_output --partial "console:"
}

@test "client remove: tacctl's accounts with the console get /bin/bash back; others are named and left" {
    _gen > /dev/null
    _client_env
    _console_header "$CONSOLE" /bin/bash
    bash "$OUT" --accounts-only > /dev/null
    echo "ext:x:1200:1200::/home/ext:${CONSOLE}" >> "$FAKE_DB/passwd"
    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    : > "$CALLS_LOG"
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    assert_output --partial "[INFO] 'alice': login shell is /bin/bash again (it was the tacctl console)."
    assert_output --partial "[WARN] 'ext' has the tacctl console (${CONSOLE}) as its login shell, but tacctl did not create it; left as it is."
    stub_called "usermod -s /bin/bash alice"
    if stub_called "^usermod .* (bob|ext)$"; then stub_calls; return 1; fi
}

# --- another UID range (tacctl.yaml linux.uid_min, linux.uid_max) --------------

@test "config linux uid-range: shows the range, refuses one that cannot be used, nothing changed" {
    _gen > /dev/null
    local before
    before=$(cat "${TACCTL_STATE_DIR}/linux-uids")
    run "$TACCTL_BIN_SCRIPT" config linux uid-range
    assert_success
    assert_line "  Linux UID range: 80000-89999 (default; one range for all hosts)"
    assert_line "  ${TACCTL_STATE_DIR}/linux-uids is numbered for 80000-89999"
    run "$TACCTL_BIN_SCRIPT" config linux uid-range 500-5000
    assert_failure 1
    assert_output --partial "Cannot use UID range 500-5000: it starts below 1000 (system accounts)."
    run "$TACCTL_BIN_SCRIPT" config linux uid-range 61000-62999
    assert_failure 1
    assert_output --partial "it overlaps 61184-65519, which systemd reserves."
    run "$TACCTL_BIN_SCRIPT" config linux uid-range 100000
    assert_failure 1
    assert_output --partial "Usage: tacctl config linux uid-range <min>-<max>"
    [[ "$(cat "${TACCTL_STATE_DIR}/linux-uids")" == "$before" ]]
    run "$TACCTL_BIN_SCRIPT" config get linux.uid_min
    assert_output "80000"
    # A range in useradd's is allowed, with a warning.
    run "$TACCTL_BIN_SCRIPT" config linux uid-range 40000-49999
    assert_success
    assert_output --partial "UID range 40000-49999 overlaps 1000-60000, where local useradd gives out UIDs by default"
    # A range set by hand in tacctl.yaml that cannot be used stops the
    # commands that give out numbers.
    sed -i "s/^\\( *uid_max:\\).*/\\1 40500/" "${TACCTL_STATE_DIR}/tacctl.yaml"
    run _gen
    assert_failure 1
    assert_output --partial "The Linux UID range in tacctl.yaml (40000-40500) cannot be used: it holds 501 numbers"
    assert_output --partial "Set one that can: tacctl config linux uid-range <min>-<max>"
}

@test "config linux uid-range: the map moves by offset, scripts carry the range and the earlier ones" {
    _gen > /dev/null
    run "$TACCTL_BIN_SCRIPT" config linux uid-range 100000-109999
    assert_success
    assert_output --partial "Renumbered 2 entries of ${TACCTL_STATE_DIR}/linux-uids from 80000-89999 to 100000-109999"
    assert_output --partial "Linux UID range set to 100000-109999 (was 80000-89999)."
    stub_called "logger -t tacctl -p auth.info uid-range set from=80000-89999 to=100000-109999"
    run cat "${TACCTL_STATE_DIR}/linux-uids"
    assert_output $'# range 100000-109999\n# previous 80000-89999\nalice:100000\nbob:100001'
    _gen > /dev/null
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_line "TAC_USERS=\$'alice:superuser:100000\\nbob:readonly:100001'"
    assert_line "TAC_UID_FIRST=100000"
    assert_line "TAC_UID_LAST=109999"
    assert_line "TAC_UID_PREVIOUS=80000-89999"
    run "$TACCTL_BIN_SCRIPT" config linux uid bob 85000
    assert_failure
    assert_output --partial "UID must be a number from 100000 to 109999"
    # Back into a range the map was numbered for: refused.
    run "$TACCTL_BIN_SCRIPT" config linux uid-range 85000-95000
    assert_failure 1
    assert_output --partial "it overlaps 80000-89999, a range the file was numbered for (hosts may still have accounts there). Nothing was changed."
    run "$TACCTL_BIN_SCRIPT" config get linux.uid_min
    assert_output "100000"
}

@test "client install: a header without a valid UID range stops the run before anything changes" {
    _gen > /dev/null
    _client_env
    cp "$OUT" "$BATS_TEST_TMPDIR/good.sh"
    sed -i '/^TAC_UID_FIRST=/d' "$OUT"
    run bash "$OUT" --accounts-only
    assert_failure
    assert_output --partial "The header has no valid UID range (TAC_UID_FIRST, TAC_UID_LAST). Nothing was changed."
    sed 's/^TAC_UID_LAST=.*/TAC_UID_LAST=70000/; s/^TAC_UID_FIRST=.*/TAC_UID_FIRST=080000/' "$BATS_TEST_TMPDIR/good.sh" > "$OUT"
    run bash "$OUT" --accounts-only
    assert_failure
    assert_output --partial "The header has no valid UID range"
    run grep -cE "^(useradd|groupadd|usermod)" "$CALLS_LOG"
    assert_output "0"
    [[ ! -e "$TACCTL_CLIENT_STATE/created" ]]
}

@test "client install: after a range change, accounts it created in any earlier range move by offset, once" {
    _legacy_host
    "$TACCTL_BIN_SCRIPT" config linux uid-range 100000-109999 > /dev/null
    _gen > /dev/null
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_line "TAC_UID_PREVIOUS=20000-29999\\ 80000-89999"
    # The host still has alice and gone at legacy UIDs: the offsets add up.
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[INFO] 'alice': renumbered 20000 -> 100000 (home re-owned)"
    assert_output --partial "[INFO] 'gone': renumbered 20002 -> 100002 (home re-owned)"
    assert_output --partial "[INFO] Accounts: 2 managed by tacctl here; 2 renumbered."
    stub_called "useradd -m -u 100001 -g tac-users"
    run grep "^alice:" "$FAKE_DB/passwd"
    assert_output "alice:x:100000:100000:alice (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/alice:/bin/bash"
    # pat (not tacctl's) is left as it is.
    run grep -c "^pat:x:20005:20005:Pat:" "$FAKE_DB/passwd"
    assert_output "1"

    # Again: 100000-109999 -> 120000-129999.
    "$TACCTL_BIN_SCRIPT" config linux uid-range 120000-129999 > /dev/null
    _gen > /dev/null
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[INFO] 'alice': renumbered 100000 -> 120000 (home re-owned)"
    assert_output --partial "[INFO] 'bob': renumbered 100001 -> 120001 (home re-owned)"
    stub_called "usermod -u 120000 alice"
    # tacctl's groups follow the range's start.
    stub_called "groupmod -g 120000 tac-users"
    # Once.
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    refute_output --partial "renumbered"
    run grep -cE "^(usermod -u|groupmod)" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: an account whose new number would fall outside the range is left as it is and refused" {
    _gen > /dev/null
    _client_env
    bash "$OUT" --accounts-only > /dev/null
    # A header whose earlier range is larger than its current one (written
    # by hand: the server refuses such a range).
    sed -i 's/^TAC_UID_FIRST=.*/TAC_UID_FIRST=100000/; s/^TAC_UID_LAST=.*/TAC_UID_LAST=100001/; s/^TAC_UID_PREVIOUS=.*/TAC_UID_PREVIOUS=79999-89999/' "$OUT"
    sed -i "s/^TAC_USERS=.*/TAC_USERS=alice:superuser:100000/" "$OUT"
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] 'bob': not renumbered from 80001: 100002 would be outside 100000-100001. The account is left as it is."
    run grep -cE "^usermod -u .* bob" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a disabled user's account is expired, not deleted; re-enabling restores it" {
    _gen > /dev/null
    _client_env
    bash "$OUT" --accounts-only > /dev/null
    "$TACCTL_BIN_SCRIPT" user disable bob > /dev/null
    _gen > /dev/null
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_line "TAC_INACTIVE=bob"
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only --remove-home
    assert_success
    assert_output --partial "[INFO] 'bob' has no TACACS+ login here now (disabled): account expired, files kept."
    stub_called "usermod -e 1 bob"
    stub_called "gpasswd -d bob tac-users"
    run grep -cE "^(userdel|groupdel) " "$CALLS_LOG"
    assert_output "0"
    [[ -d "$TACCTL_CLIENT_HOME_ROOT/bob" ]]
    # A second sync says nothing more about it.
    run bash "$OUT" --accounts-only
    refute_output --partial "'bob'"
    "$TACCTL_BIN_SCRIPT" user enable bob > /dev/null
    _gen > /dev/null
    : > "$CALLS_LOG"
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "Re-activated account 'bob'."
    stub_called "usermod -e  bob"
    # tac-users is its primary group: not added again as a supplementary one.
    run grep -cE "^usermod -aG .*bob" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a removed user still logged in (userdel fails) is expired and deleted at the next sync" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE"
    echo old1 > "$TACCTL_CLIENT_STATE/created"
    echo "old1:x:80005:80005:old1 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/old1:/bin/bash" >> "$FAKE_DB/passwd"
    echo "old1:x:80005:" >> "$FAKE_DB/group"
    USERDEL_FAILS=1 run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "[WARN] Could not delete 'old1' (userdel failed; still logged in?): account expired, deleted at the next sync."
    stub_called "usermod -e 1 old1"
    run cat "$TACCTL_CLIENT_STATE/created"
    assert_output --partial old1
    run bash "$OUT" --accounts-only
    assert_success
    assert_output --partial "Deleted account 'old1'"
    stub_called "groupdel old1"
}

@test "client install: a per-user group that still has members or another GID stays" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE"
    printf '%s\n' g1 g2 > "$TACCTL_CLIENT_STATE/created"
    printf '%s\n' "g1:x:80005:80005:g1 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/g1:/bin/bash" \
        "g2:x:80006:80006:g2 (TACACS+):${TACCTL_CLIENT_HOME_ROOT}/g2:/bin/bash" >> "$FAKE_DB/passwd"
    printf '%s\n' "g1:x:80005:admin" "g2:x:81111:" >> "$FAKE_DB/group"
    run bash "$OUT" --accounts-only
    assert_success
    stub_called "userdel g1"
    stub_called "userdel g2"
    run grep -c "^groupdel" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: refuses when no local admin exists outside TACACS+" {
    _gen > /dev/null
    _client_env
    printf '%s\n' 'sudo:x:27:bob' > "$FAKE_DB/group"
    run bash "$OUT" --accounts-only
    assert_failure
    assert_output --partial "No local administrator"
    run grep -c "useradd" "$CALLS_LOG"
    assert_output "0"
}

@test "client install then remove: PAM files are edited and restored byte-for-byte" {
    _gen > /dev/null
    _client_env
    run bash "$OUT"
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
    # What it wrote is recorded, for 'host show --check'.
    run bash -c 'cd "$TACCTL_CLIENT_PAM_DIR" && sha256sum -c "$TACCTL_CLIENT_STATE/pam.sha256"'
    assert_success
    assert_line "tacctl-auth: OK"
    assert_line "tacctl-session: OK"

    # Re-running must not stack a second session include.
    run bash "$OUT"
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
    [[ ! -e "$TACCTL_CLIENT_STATE/pam.sha256" && ! -e "$TACCTL_CLIENT_STATE/protocol" ]]
    run grep -cE "userdel|groupdel" "$CALLS_LOG"
    assert_output "0"
}

@test "client install: a failure after PAM edits begin rolls them back" {
    _gen > /dev/null
    _client_env
    stub_cmd visudo 'exit 1'
    run bash "$OUT"
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
    run bash "$OUT"
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
    run bash "$OUT"
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
    run bash "$OUT"
    assert_success
    assert_output --partial "refreshing the package index"
    run grep -c "apt-get install -y libpam0g-dev" "$CALLS_LOG"
    assert_output "2"
}

@test "client install: the module is built once and reused until the source changes" {
    _gen > /dev/null
    _client_env
    run bash "$OUT"
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
    run bash "$PUSHED"
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
    run bash "$OUT"
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
    run bash "$OUT"
    assert_success
    stub_called "dnf install -y -q gcc pam-devel"
    run grep -c "^apt-get" "$CALLS_LOG"
    assert_output "0"

    rm -rf "$TACCTL_CLIENT_STATE"
    echo "auth required pam_unix.so" > "$TACCTL_CLIENT_PAM_DIR/sudo"
    run bash "$OUT"
    assert_failure
    assert_output --partial "unfamiliar PAM layout"
}

@test "client install: with SELinux on, a policy module for the TACACS+ port is installed and later removed" {
    _gen > /dev/null
    _rhel_env
    stub_cmd selinuxenabled
    stub_cmd semodule
    stub_cmd restorecon
    run bash "$OUT"
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

@test "client install: on a Plasma host, screen locking is switched off for TACACS+ accounts only" {
    _gen > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_XDG/plasma-workspace/env"
    run bash "$OUT"
    assert_success
    assert_output --partial "screen locking is switched off for TACACS+ accounts"

    run cat "$TACCTL_CLIENT_XDG/tacctl/kscreenlockerrc"
    assert_line 'Autolock[$i]=false'
    assert_line 'Timeout[$i]=0'
    assert_line 'LockOnResume[$i]=false'
    run cat "$TACCTL_CLIENT_XDG/tacctl/kdeglobals"
    assert_line '[KDE Action Restrictions][$i]'
    assert_line 'action/lock_screen=false'

    # The session script only redirects accounts this script created.
    env_script="$TACCTL_CLIENT_XDG/plasma-workspace/env/tacctl-nolock.sh"
    mkdir -p "$BATS_TEST_TMPDIR/stub"
    printf '%s\n' '#!/bin/sh' 'echo "u:x:1:1:$FAKE_GECOS:/h:/bin/sh"' > "$BATS_TEST_TMPDIR/stub/getent"
    chmod +x "$BATS_TEST_TMPDIR/stub/getent"
    run env PATH="$BATS_TEST_TMPDIR/stub:$PATH" FAKE_GECOS="carol (TACACS+)" XDG_CONFIG_DIRS=/etc/xdg \
        sh -c ". '$env_script'; echo \"\$XDG_CONFIG_DIRS\""
    assert_output "$TACCTL_CLIENT_XDG/tacctl:/etc/xdg"
    run env PATH="$BATS_TEST_TMPDIR/stub:$PATH" FAKE_GECOS="Local Admin" XDG_CONFIG_DIRS=/etc/xdg \
        sh -c ". '$env_script'; echo \"\$XDG_CONFIG_DIRS\""
    assert_output "/etc/xdg"

    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    [ ! -e "$env_script" ]
    [ ! -e "$TACCTL_CLIENT_XDG/tacctl" ]
}

@test "client install: without Plasma, no desktop configuration is written" {
    _gen > /dev/null
    _client_env
    run bash "$OUT"
    assert_success
    refute_output --partial "screen locking"
    [ ! -e "$TACCTL_CLIENT_XDG" ]
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
    # ghost is listed in tac-users (an earlier release), shade has it as its
    # primary group only.
    echo "tac-users:x:900:ghost" >> "$FAKE_DB/group"
    printf '%s\n' 'ghost:x:80009:80009::/nonexistent:/bin/bash' 'shade:x:80010:900::/nonexistent:/bin/bash' >> "$FAKE_DB/passwd"
    printf '%s\n' 'ghost:!:1::::::' 'shade:!:1::::::' >> "$FAKE_DB/shadow"
    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    assert_output --partial "cannot log in: ghost shade"
}

# --- method radius --------------------------------------------------------------

# Enable the RADIUS backend the way tacctl.yaml records it (no store mutation
# follows in these tests, so nothing is rendered).
radius_on() {
    printf 'backends:\n  enabled: [tacacs, radius]\n' >> "${TACCTL_STATE_DIR}/tacctl.yaml"
}

# The radius install script for scope lab.
_gen_radius() {
    radius_on
    _gen --method radius "$@"
}

RCONF_LINE="192.0.2.10:1812 0123456789abcdef0123456789abcdef 3"

@test "config linux script --method radius: needs the backend, not the tarball; carries no module" {
    run _gen --method radius
    assert_failure
    assert_output --partial "tacctl backend enable radius"
    [[ ! -f "$OUT" ]]

    rm -f "$TACCTL_LINUX_DIR"/*.tar.gz
    run _gen_radius
    assert_success
    assert_output --partial "Method:  radius"
    assert_output --partial "port 1812"
    [[ "$(stat -c %a "$OUT")" == "600" ]]
    run bash -n "$OUT"
    assert_success
    run cat "$OUT"
    assert_line "TAC_METHOD=radius"
    assert_line "TAC_PORT=1812"
    assert_line "TAC_ACCT_PORT=1813"
    assert_line "TAC_SECRET=0123456789abcdef0123456789abcdef"
    refute_line "__TARBALL__"

    run _gen --method ldap
    assert_failure
    assert_output --partial "Unknown method 'ldap'"
}

@test "config linux script --method radius: refuses a scope that is not served over RADIUS" {
    "$TACCTL_BIN_SCRIPT" scope protocols lab set tacacs > /dev/null
    run _gen_radius
    assert_failure
    assert_output --partial "Scope 'lab' is not served over RADIUS"
}

@test "client install (radius): package, root-only server file, PAM lines; remove restores everything" {
    _gen_radius > /dev/null
    _client_env
    # The NAS-Identifier is the host's name (client_id=), not the PAM service's.
    stub_cmd hostname 'echo web1.example.net'
    run bash "$OUT"
    assert_success
    assert_output --partial "Installing the RADIUS PAM module: libpam-radius-auth"
    assert_output --partial "RADIUS authentication installed for scope 'lab' (server 192.0.2.10:1812)."
    assert_output --partial "RADIUS is UDP"
    refute_output --partial "TACACS+"
    stub_called "apt-get install -y libpam-radius-auth"
    # Nothing of the tacplus method.
    refute_output --partial "pam_tacplus"
    [[ ! -e "$TACCTL_CLIENT_STATE/module" && ! -e "$TACCTL_CLIENT_STATE/files" ]]
    run cat "$TACCTL_CLIENT_STATE/method"
    assert_output "radius"
    run cat "$TACCTL_CLIENT_STATE/packages"
    assert_output "libpam-radius-auth"

    # The secret is in the server file, mode 0600, and on no PAM line.
    [[ "$(stat -c %a "$TACCTL_CLIENT_RADIUS_CONF")" == "600" ]]
    run grep -v '^#' "$TACCTL_CLIENT_RADIUS_CONF"
    assert_output "$RCONF_LINE"
    run grep -rl "0123456789abcdef" "$TACCTL_CLIENT_PAM_DIR"
    assert_output ""

    # The same control line as pam_tacplus has; the local stack behind it.
    run cat "$TACCTL_CLIENT_PAM_DIR/tacctl-auth"
    assert_line --index 1 "auth    [success=ok default=1]                               pam_succeed_if.so quiet user ingroup tac-users"
    assert_line --index 2 "auth    [success=done authinfo_unavail=ignore default=die]   pam_radius_auth.so conf=${TACCTL_CLIENT_RADIUS_CONF} retry=1 client_id=web1.example.net"
    assert_line --index 3 "@include common-auth"
    # No account step: only the distribution's.
    run grep -v '^#' "$TACCTL_CLIENT_PAM_DIR/tacctl-account"
    assert_output "@include common-account"
    # Accounting at session start and end, for tac-users only.
    run grep -v '^#' "$TACCTL_CLIENT_PAM_DIR/tacctl-session"
    assert_line --index 0 "session [success=ok default=1]                               pam_succeed_if.so quiet user ingroup tac-users"
    assert_line --index 1 "session optional                                             pam_radius_auth.so conf=${TACCTL_CLIENT_RADIUS_CONF} client_id=web1.example.net"
    [[ "${#lines[@]}" == "2" ]]

    # The service files are edited exactly as for tacplus.
    run cat "$TACCTL_CLIENT_PAM_DIR/sshd"
    assert_line "@include tacctl-auth"
    assert_line "@include tacctl-account"
    assert_line "@include tacctl-session"
    refute_line "@include common-auth"
    run cat "$TACCTL_CLIENT_SUDOERS"
    assert_line "%tac-superuser ALL=(ALL:ALL) ALL"
    assert_output --partial "RADIUS superusers"
    stub_called "useradd -m -u 80000 -g tac-users -s /bin/bash -K UID_MIN=80000 -K UID_MAX=89999 -c alice .RADIUS. alice"

    # A second run finds the module and installs nothing.
    : > "$CALLS_LOG"
    run bash "$OUT"
    assert_success
    assert_output --partial "pam_radius_auth is already installed"
    run grep -c "^apt-get" "$CALLS_LOG"
    assert_output "0"
    run grep -c "tacctl-session" "$TACCTL_CLIENT_PAM_DIR/sshd"
    assert_output "1"

    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    assert_output --partial "RADIUS authentication removed."
    assert_output --partial "Packages the install added were left installed: libpam-radius-auth"
    cmp "$TACCTL_CLIENT_PAM_DIR/sshd" "$BATS_TEST_TMPDIR/sshd.orig"
    cmp "$TACCTL_CLIENT_PAM_DIR/sudo" "$BATS_TEST_TMPDIR/sudo.orig"
    cmp "$TACCTL_CLIENT_PAM_DIR/sudo-i" "$BATS_TEST_TMPDIR/sudo-i.orig"
    cmp "$TACCTL_CLIENT_PAM_DIR/sddm" "$BATS_TEST_TMPDIR/sddm.orig"
    [[ ! -e "$TACCTL_CLIENT_RADIUS_CONF" ]]
    [[ ! -e "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" && ! -e "$TACCTL_CLIENT_SUDOERS" && ! -e "$TACCTL_CLIENT_STATE/method" ]]
    run grep -rl "0123456789abcdef" "$TACCTL_CLIENT_PAM_DIR"
    assert_output ""
}

@test "client install (radius): a host that cannot get the package is left untouched" {
    _gen_radius > /dev/null
    _client_env
    stub_cmd apt-get 'exit 100'
    run bash "$OUT"
    assert_failure
    assert_output --partial "Could not install the RADIUS PAM module: libpam-radius-auth"
    assert_output --partial "Nothing was changed"
    stub_called "apt-get update"
    run grep -cE "useradd|groupadd|usermod" "$CALLS_LOG"
    assert_output "0"
    cmp "$TACCTL_CLIENT_PAM_DIR/sshd" "$BATS_TEST_TMPDIR/sshd.orig"
    [[ ! -e "$TACCTL_CLIENT_RADIUS_CONF" && ! -e "$TACCTL_CLIENT_STATE/method" && ! -e "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" ]]
}

@test "client install (radius): no accounting line for pam_radius_auth 2.0.1 or an accounting port that is not auth+1" {
    _gen_radius > /dev/null
    _client_env
    TACCTL_CLIENT_RADIUS_VERSION="2.0.1-1" run bash "$OUT"
    assert_success
    assert_output --partial "pam_radius_auth 2.0.1-1 sends malformed accounting records"
    run grep -v '^#' "$TACCTL_CLIENT_PAM_DIR/tacctl-session"
    assert_output ""
    # The service file still includes it; it is just empty.
    grep -q '^@include tacctl-session$' "$TACCTL_CLIENT_PAM_DIR/sshd"

    TACCTL_CLIENT_RADIUS_VERSION="2.0.0-1" run bash "$OUT"
    assert_success
    grep -q "pam_radius_auth.so" "$TACCTL_CLIENT_PAM_DIR/tacctl-session"

    sed -i 's/^TAC_ACCT_PORT=.*/TAC_ACCT_PORT=1899/' "$OUT"
    run bash "$OUT"
    assert_success
    assert_output --partial "authentication port plus one (1813), and the server's accounting listener is 1899"
    run grep -v '^#' "$TACCTL_CLIENT_PAM_DIR/tacctl-session"
    assert_output ""
}

@test "client install (radius): require_message_authenticator only where the module has it; IPv6 server in brackets" {
    _gen_radius > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_STATE/lib/security"
    echo "... require_message_authenticator ..." > "$TACCTL_CLIENT_STATE/lib/security/pam_radius_auth.so"
    sed -i 's/^TAC_SERVER=.*/TAC_SERVER=2001:db8::10/' "$OUT"
    run bash "$OUT"
    assert_success
    run cat "$TACCTL_CLIENT_PAM_DIR/tacctl-auth"
    assert_line --regexp "pam_radius_auth.so conf=[^ ]+ retry=1 require_message_authenticator( client_id=[^ ]+)?$"
    run grep -v '^#' "$TACCTL_CLIENT_RADIUS_CONF"
    assert_output "[2001:db8::10]:1812 0123456789abcdef0123456789abcdef 3"
}

@test "client install (radius): a hostname that is not one PAM argument sends no client_id" {
    _gen_radius > /dev/null
    _client_env
    stub_cmd hostname 'echo "bad name"'
    run bash "$OUT"
    assert_success
    run cat "$TACCTL_CLIENT_PAM_DIR/tacctl-auth"
    assert_line --regexp "pam_radius_auth.so conf=[^ ]+ retry=1$"
    refute_output --partial "client_id"
}

@test "client install (radius): a failure after PAM edits begin rolls them back and removes the server file" {
    _gen_radius > /dev/null
    _client_env
    stub_cmd visudo 'exit 1'
    run bash "$OUT"
    assert_failure
    assert_output --partial "restored from backup, RADIUS not enabled"
    cmp "$TACCTL_CLIENT_PAM_DIR/sshd" "$BATS_TEST_TMPDIR/sshd.orig"
    [[ ! -e "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" && ! -e "$TACCTL_CLIENT_RADIUS_CONF" ]]
}

# dnf and rpm for a host that has no EPEL: pam_radius is unknown until
# epel-release is installed. EPEL_BY_NAME=no makes 'dnf install epel-release'
# find nothing (RHEL, Oracle Linux); RADIUS_PKG=no makes pam_radius
# uninstallable even then.
_epel_stubs() {
    stub_cmd rpm 'case "$*" in
        "-q epel-release") [[ -e "$FAKE_DB/epel" ]] ;;
        "-E %{?rhel}") echo 9 ;;
        *) exit 1 ;;
    esac'
    stub_cmd dnf 'case " $* " in
        *" list pam_radius "*) [[ -e "$FAKE_DB/epel" ]] ;;
        *" install "*" epel-release "*) [[ "${EPEL_BY_NAME:-yes}" == "yes" ]] && touch "$FAKE_DB/epel"; exit 0 ;;
        *" install "*epel-release-latest-9.noarch.rpm*) touch "$FAKE_DB/epel" ;;
        *" install "*" pam_radius "*) [[ -e "$FAKE_DB/epel" && "${RADIUS_PKG:-yes}" == "yes" ]] ;;
        *" remove "*" epel-release "*) rm -f "$FAKE_DB/epel" ;;
    esac'
}

@test "client install (radius, RHEL family): enables EPEL, installs pam_radius, adds no @include" {
    _gen_radius > /dev/null
    _rhel_env
    _epel_stubs
    run bash "$OUT"
    assert_success
    assert_output --partial "pam_radius is packaged in EPEL, which this host does not have: installing epel-release."
    stub_called "dnf install -y -q epel-release"
    stub_called "dnf install -y -q --enablerepo=epel pam_radius"
    run grep -c "^apt-get" "$CALLS_LOG"
    assert_output "0"
    run cat "$TACCTL_CLIENT_STATE/packages"
    assert_line "pam_radius"
    assert_line "epel-release"

    run cat "$TACCTL_CLIENT_PAM_DIR/sshd"
    assert_line --index 1 "auth       include      tacctl-auth"
    assert_line --index 2 "auth       substack     password-auth"
    assert_line --index 5 "account    include      tacctl-account"
    assert_line --index 10 "session    include      tacctl-session"
    run cat "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" "$TACCTL_CLIENT_PAM_DIR/tacctl-account" "$TACCTL_CLIENT_PAM_DIR/tacctl-session"
    refute_output --partial "@include"
    assert_output --partial "pam_radius_auth.so conf=${TACCTL_CLIENT_RADIUS_CONF} retry=1"
    # The account file has no rule at all on this family.
    run grep -vc '^#\|^$' "$TACCTL_CLIENT_PAM_DIR/tacctl-account"
    assert_output "0"

    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    assert_output --partial "left installed: pam_radius epel-release"
    for f in sshd sudo sudo-i gdm-password; do cmp "$TACCTL_CLIENT_PAM_DIR/$f" "$BATS_TEST_TMPDIR/$f.orig"; done
    [[ ! -e "$TACCTL_CLIENT_RADIUS_CONF" ]]
}

@test "client install (radius, RHEL family): epel-release comes from the EPEL project where the distribution has none" {
    _gen_radius > /dev/null
    _rhel_env
    _epel_stubs
    EPEL_BY_NAME=no run bash "$OUT"
    assert_success
    stub_called "dnf install -y -q https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm"
    stub_called "dnf install -y -q --enablerepo=epel pam_radius"
}

@test "client install (radius, RHEL family): a host with pam_radius in its repositories gets no EPEL" {
    _gen_radius > /dev/null
    _rhel_env
    _epel_stubs
    touch "$FAKE_DB/epel"
    run bash "$OUT"
    assert_success
    refute_output --partial "EPEL"
    stub_called "dnf install -y -q pam_radius"
    run grep -c "epel-release" "$CALLS_LOG"
    assert_output "0"
}

@test "client install (radius, RHEL family): when pam_radius cannot be installed, the EPEL it added is taken out again" {
    _gen_radius > /dev/null
    _rhel_env
    _epel_stubs
    RADIUS_PKG=no run bash "$OUT"
    assert_failure
    assert_output --partial "Could not install the RADIUS PAM module: pam_radius"
    assert_output --partial "It comes from EPEL."
    assert_output --partial "Nothing was changed"
    stub_called "dnf remove -y -q epel-release"
    [[ ! -e "$FAKE_DB/epel" ]]
    run grep -cE "useradd|groupadd|usermod" "$CALLS_LOG"
    assert_output "0"
    for f in sshd sudo; do cmp "$TACCTL_CLIENT_PAM_DIR/$f" "$BATS_TEST_TMPDIR/$f.orig"; done
    [[ ! -e "$TACCTL_CLIENT_STATE/packages" ]]

    # No EPEL to be had at all.
    EPEL_BY_NAME=no stub_cmd rpm 'exit 1'
    EPEL_BY_NAME=no run bash "$OUT"
    assert_failure
    assert_output --partial "Could not enable EPEL on this host"
    assert_output --partial "Nothing was changed"
}

@test "client install (radius): with SELinux on, the tacctl_pam_radius module is installed and later removed" {
    _gen_radius > /dev/null
    _rhel_env
    _epel_stubs
    stub_cmd selinuxenabled
    stub_cmd semodule
    stub_cmd restorecon
    run bash "$OUT"
    assert_success
    assert_output --partial "policy module tacctl_pam_radius installed"
    stub_called "semodule -i .*/tacctl_pam_radius.cil"
    stub_called "restorecon ${TACCTL_CLIENT_RADIUS_CONF} "
    run cat "$TACCTL_CLIENT_STATE/tacctl_pam_radius.cil"
    assert_line "(optional tacctl_pam_radius_login (allow local_login_t node_t (udp_socket (node_bind))))"
    assert_line "(optional tacctl_pam_radius_sudo (allow sudodomain node_t (udp_socket (node_bind))))"
    [[ ! -e "$TACCTL_CLIENT_STATE/tacctl_pam.cil" ]]

    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    stub_called "semodule -r tacctl_pam_radius"
    [[ ! -e "$TACCTL_CLIENT_STATE/tacctl_pam_radius.cil" ]]
}

@test "client install: switching tacplus -> radius -> tacplus leaves nothing of the method left behind" {
    _gen > /dev/null
    cp "$OUT" "$BATS_TEST_TMPDIR/tacplus.sh"
    _gen_radius > /dev/null
    cp "$OUT" "$BATS_TEST_TMPDIR/radius.sh"
    _rhel_env
    _epel_stubs
    stub_cmd selinuxenabled
    stub_cmd semodule
    stub_cmd restorecon

    run bash "$BATS_TEST_TMPDIR/tacplus.sh"
    assert_success
    [[ -f "$TACCTL_CLIENT_STATE/lib/security/pam_tacplus.so" && -f "$TACCTL_CLIENT_STATE/tacctl_pam.cil" ]]
    run cat "$TACCTL_CLIENT_STATE/method"
    assert_output "tacplus"
    # alice exists from here on, as an account this script created.
    grep -qx "alice:x:80000:80000:alice (TACACS+):.*" "$FAKE_DB/passwd"

    # tacplus -> radius
    run bash "$BATS_TEST_TMPDIR/radius.sh"
    assert_success
    assert_output --partial "This host used tacplus before: its PAM lines, shared secret and module configuration were removed."
    run grep -rl "pam_tacplus\|0123456789abcdef" "$TACCTL_CLIENT_PAM_DIR"
    assert_output ""
    [[ ! -e "$TACCTL_CLIENT_STATE/lib/security/pam_tacplus.so" && ! -e "$TACCTL_CLIENT_STATE/lib/libtac.so.5" \
        && ! -e "$TACCTL_CLIENT_STATE/lib/libtac.so.5.0.0" ]]
    [[ ! -e "$TACCTL_CLIENT_STATE/module" && ! -e "$TACCTL_CLIENT_STATE/files" && ! -e "$TACCTL_CLIENT_STATE/tacctl_pam.cil" ]]
    stub_called "semodule -r tacctl_pam$"
    grep -q "pam_radius_auth.so" "$TACCTL_CLIENT_PAM_DIR/tacctl-auth"
    [[ -f "$TACCTL_CLIENT_RADIUS_CONF" ]]
    run cat "$TACCTL_CLIENT_STATE/method"
    assert_output "radius"
    # The service files were not edited twice, and the account is renamed.
    run grep -c "tacctl-" "$TACCTL_CLIENT_PAM_DIR/sshd"
    assert_output "3"
    stub_called "usermod -c alice .RADIUS. alice"
    sed -i 's/^alice:.*/alice:x:80000:80000:alice (RADIUS):\/home\/alice:\/bin\/bash/' "$FAKE_DB/passwd"

    # radius -> tacplus
    run bash "$BATS_TEST_TMPDIR/tacplus.sh"
    assert_success
    assert_output --partial "This host used radius before"
    run grep -rl "pam_radius" "$TACCTL_CLIENT_PAM_DIR"
    assert_output ""
    [[ ! -e "$TACCTL_CLIENT_RADIUS_CONF" && ! -e "$TACCTL_CLIENT_STATE/tacctl_pam_radius.cil" ]]
    stub_called "semodule -r tacctl_pam_radius"
    grep -q "pam_tacplus.so server=192.0.2.10:49" "$TACCTL_CLIENT_PAM_DIR/tacctl-auth"
    [[ -f "$TACCTL_CLIENT_STATE/lib/security/pam_tacplus.so" ]]
    run cat "$TACCTL_CLIENT_STATE/method"
    assert_output "tacplus"
    stub_called "usermod -c alice .TACACS.. alice"

    # The removal script takes out whichever is there.
    "$TACCTL_BIN_SCRIPT" config linux remove-script --output "$BATS_TEST_TMPDIR/remove.sh" > /dev/null
    run bash "$BATS_TEST_TMPDIR/remove.sh"
    assert_success
    assert_output --partial "TACACS+ authentication removed."
    for f in sshd sudo sudo-i gdm-password; do cmp "$TACCTL_CLIENT_PAM_DIR/$f" "$BATS_TEST_TMPDIR/$f.orig"; done
}

@test "client install: a host enrolled before there were methods switches to radius cleanly" {
    _gen > /dev/null
    cp "$OUT" "$BATS_TEST_TMPDIR/tacplus.sh"
    _gen_radius > /dev/null
    _client_env
    bash "$BATS_TEST_TMPDIR/tacplus.sh" > /dev/null
    rm "$TACCTL_CLIENT_STATE/method"
    run bash "$OUT"
    assert_success
    assert_output --partial "This host used tacplus before"
    run grep -rl "pam_tacplus" "$TACCTL_CLIENT_PAM_DIR"
    assert_output ""
    [[ ! -e "$TACCTL_CLIENT_STATE/lib/security/pam_tacplus.so" && ! -e "$TACCTL_CLIENT_STATE/module" ]]
}

@test "client install (radius): a switch that cannot get the package leaves the tacplus setup working" {
    _gen > /dev/null
    cp "$OUT" "$BATS_TEST_TMPDIR/tacplus.sh"
    _gen_radius > /dev/null
    _client_env
    bash "$BATS_TEST_TMPDIR/tacplus.sh" > /dev/null
    cp "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" "$BATS_TEST_TMPDIR/auth.before"
    stub_cmd apt-get 'exit 100'
    run bash "$OUT"
    assert_failure
    assert_output --partial "Nothing was changed"
    cmp "$TACCTL_CLIENT_PAM_DIR/tacctl-auth" "$BATS_TEST_TMPDIR/auth.before"
    grep -q '^@include tacctl-auth$' "$TACCTL_CLIENT_PAM_DIR/sshd"
    [[ -f "$TACCTL_CLIENT_STATE/lib/security/pam_tacplus.so" ]]
    run cat "$TACCTL_CLIENT_STATE/method"
    assert_output "tacplus"
}

@test "client install (radius): on a Plasma host the lock-screen switch names RADIUS accounts" {
    _gen_radius > /dev/null
    _client_env
    mkdir -p "$TACCTL_CLIENT_XDG/plasma-workspace/env"
    run bash "$OUT"
    assert_success
    assert_output --partial "screen locking is switched off for RADIUS accounts"
    run cat "$TACCTL_CLIENT_XDG/tacctl/kscreenlockerrc"
    assert_line 'Autolock[$i]=false'
    grep -q '\*"(RADIUS)")' "$TACCTL_CLIENT_XDG/plasma-workspace/env/tacctl-nolock.sh"
}

# --- the scope's auth-method ---------------------------------------------------------

@test "config linux script: without --method the scope's auth-method picks the method; --method wins" {
    radius_on
    "$TACCTL_BIN_SCRIPT" scope auth-method lab radius > /dev/null
    run _gen
    assert_success
    assert_output --partial "Method radius: scope 'lab' has auth-method radius (tacctl scope auth-method)"
    grep -q '^TAC_METHOD=radius$' "$OUT"
    run _gen --method tacplus
    assert_success
    refute_output --partial "auth-method"
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_line "TAC_METHOD=tacplus"
}

@test "config linux script: a scope served over one protocol only picks the method when it has no auth-method" {
    # Limited before the RADIUS backend is enabled: with the backend on,
    # 'scope protocols' would render it, which needs the daemon's stand-in.
    "$TACCTL_BIN_SCRIPT" scope protocols lab set radius > /dev/null
    radius_on
    run _gen
    assert_success
    assert_output --partial "Method radius: scope 'lab' is served over radius only (tacctl scope protocols)"
    grep -q '^TAC_METHOD=radius$' "$OUT"
}

@test "config linux script: a scope's auth-method tacacs comes before host.default_method" {
    radius_on
    "$TACCTL_BIN_SCRIPT" host default-method radius > /dev/null
    run _gen
    assert_success
    grep -q '^TAC_METHOD=radius$' "$OUT"
    "$TACCTL_BIN_SCRIPT" scope auth-method lab tacacs > /dev/null
    run _gen
    assert_success
    assert_output --partial "Method tacplus: scope 'lab' has auth-method tacacs (tacctl scope auth-method)"
    run sed '/^__TARBALL__$/,$d' "$OUT"
    assert_line "TAC_METHOD=tacplus"
}
