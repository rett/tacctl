#!/usr/bin/env bats
# Integration tests for 'tacctl host provisioner <name> rotate' with ssh
# stubbed (the pattern of host.bats): the stub keeps every script copied to
# the host (one file each, in order), records each command that would have
# run there, answers the proof with the id and the host keys it is told to,
# and fails a create or a remove run when asked. Keys are real ones made by
# ssh-keygen in the test's directory; nothing reaches a host.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
OLD="admin@web1.example.net"
NEW="deploy2@web1.example.net"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_LINUX_DIR="${BATS_TEST_TMPDIR}/linux"
    export PUSHES="${BATS_TEST_TMPDIR}/pushes"
    export HOSTKEYS="${BATS_TEST_TMPDIR}/hostkeys"
    export OTHERKEYS="${BATS_TEST_TMPDIR}/otherkeys"
    export PASSWD_ON_HOST="${BATS_TEST_TMPDIR}/passwd-on-host"
    export STATE_ON_HOST="${BATS_TEST_TMPDIR}/state-on-host"
    export STATE_ON_HOST="${BATS_TEST_TMPDIR}/state-on-host"
    mkdir -p "$PUSHES" "$TACCTL_LINUX_DIR"
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    "$TACCTL_BIN_SCRIPT" scope secret lab set "0123456789abcdef0123456789abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$HASH" --scopes lab > /dev/null
    echo "not really a tarball" > "$TACCTL_LINUX_DIR/pam_tacplus-1.7.0.tar.gz"

    # The host's keys (the ones pinned at enrolment) and another machine's.
    ssh-keygen -q -t ed25519 -N '' -f "${BATS_TEST_TMPDIR}/hk1"
    ssh-keygen -q -t ed25519 -N '' -f "${BATS_TEST_TMPDIR}/hk2"
    cp "${BATS_TEST_TMPDIR}/hk1.pub" "$HOSTKEYS"
    cp "${BATS_TEST_TMPDIR}/hk2.pub" "$OTHERKEYS"
    printf 'root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\n' > "$PASSWD_ON_HOST"

    stub_cmd getent 'echo "192.0.2.50 STREAM web1"'
    stub_cmd ip 'echo "192.0.2.50 dev eth0 src 192.0.2.1 uid 0"'
    stub_cmd ssh-keyscan 'echo "web1.example.net $(cut -d" " -f1,2 "$HOSTKEYS")"'
    # Copy: keep the script as the next numbered file. Proof: the id and the
    # host's keys (PROOF_UID, PROOF_KEYS, PROOF_FAILS). Run: the script's
    # kind decides whether it fails (FAIL_CREATE, FAIL_REMOVE); a create run
    # says what it did (ORIGIN, SUDOERS_STATUS). The dry run reads root's
    # record of the account (STATE_ON_HOST).
    stub_cmd ssh 'case "$*" in
        *mktemp*) n=$(find "$PUSHES" -type f | wc -l); cat > "$PUSHES/$((n + 1))"; echo /tmp/tacctl.AbCd1234 ;;
        *tacctl-uid=*)
            [[ -z "${PROOF_FAILS:-}" ]] || exit 255
            echo "tacctl-uid=${PROOF_UID:-0}"
            cat "${PROOF_KEYS:-$HOSTKEYS}" ;;
        *"cat /etc/ssh/ssh_host_*_key.pub") cat "$HOSTKEYS" ;;
        *"trap '"'"'rm -f"*)
            last=$(ls -1 "$PUSHES" | sort -n | tail -1)
            if grep -q "create the provisioning account" "$PUSHES/$last"; then
                [[ -z "${FAIL_CREATE:-}" ]] || exit 1
                echo "[INFO] origin: ${ORIGIN:-created}"; echo "[INFO] sudoers-line: ${SUDOERS_STATUS:-added}"
            else [[ -z "${FAIL_REMOVE:-}" ]]; fi ;;
        *"cat /var/lib/tacctl-provisioner/deploy2"*) cat "$STATE_ON_HOST" ;;
        *"getent passwd") cat "$PASSWD_ON_HOST" ;;
        *"sshd)\" -T"*) echo "passwordauthentication ${SSHD_PW:-yes}" ;;
        *"echo root; elif sudo"*) echo sudo ;;
    esac'
    "$TACCTL_BIN_SCRIPT" host enroll "$OLD" --scope lab --build-on-host > /dev/null
    KEY="${BATS_TEST_TMPDIR}/deploy-key"
    ssh-keygen -q -t ed25519 -N '' -f "$KEY"
    : > "$CALLS_LOG"
    rm -f "$PUSHES"/*
}

_hosts() { cat "${TACCTL_STATE_DIR}/linux-hosts" 2>/dev/null; }
_push_kind() {
    if grep -q "create the provisioning account" "$PUSHES/$1"; then echo create
    elif grep -q "remove a provisioning account" "$PUSHES/$1"; then echo remove
    else echo other; fi
}
_pushes() { find "$PUSHES" -type f | wc -l; }
# _line <regex>: the number of the first line of the calls log that matches.
_line() { grep -nE -- "$1" "$CALLS_LOG" | head -1 | cut -d: -f1; }

# on_tty <stdin text> <args...>: tacctl on a pseudo-terminal fed the text.
on_tty() {
    local input="$1" cmd
    shift
    printf -v cmd '%q ' "$TACCTL_BIN_SCRIPT" "$@"
    run bash -c "printf '%b' '$input' | script -qec '$cmd' /dev/null"
    output=${output//$'\r'/}
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
}

@test "host provisioner rotate --key: creates the account, proves it in a new connection, then switches the registry" {
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --yes
    assert_success
    assert_output --partial "Host 'web1' is now reached at ${NEW}"
    assert_output --partial "The old login 'admin' is still on web1."
    run _hosts
    assert_output "web1|${NEW}||lab|192.0.2.1|${KEY}"
    # One script went to the host: the create script, with the public key.
    [[ "$(_pushes)" == 1 ]]
    [[ "$(_push_kind 1)" == create ]]
    grep -q '^ACCOUNT=deploy2$' "$PUSHES/1"
    grep -q '^AUTH=key$' "$PUSHES/1"
    grep -q "^PUBKEY=ssh-ed25519\\\\ $(cut -d' ' -f2 "${KEY}.pub")" "$PUSHES/1"
    grep -q '^UID_FIRST=80000$' "$PUSHES/1"
    # Order: the script ran over the old login, then the proof ran in a new
    # connection with the key and sudo -n, then the audit line.
    local run_n proof_n log_n
    run_n=$(_line "ssh .*-tt ${OLD} trap 'rm -f /tmp/tacctl.AbCd1234'.*sudo -n bash /tmp/tacctl.AbCd1234")
    proof_n=$(_line "ssh .*-o ControlMaster=no -o ControlPath=none .*-o GSSAPIAuthentication=no -o HostbasedAuthentication=no -o UserKnownHostsFile=[^ ]+ -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o HostKeyAlias=web1 -o UpdateHostKeys=no -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o BatchMode=yes -i ${KEY} -T ${NEW} u=\\\$\\(sudo -n id -u\\)")
    log_n=$(_line "^logger -t tacctl -p auth.info host provisioner rotate name=web1 old=admin new=deploy2 auth=key by=")
    [[ -n "$run_n" && -n "$proof_n" && -n "$log_n" ]] || { stub_calls; return 1; }
    (( run_n < proof_n && proof_n < log_n )) || { stub_calls; return 1; }
    # A snapshot was taken, and the old login is in the host's record.
    [[ -n "$(ls "${TACCTL_STATE_DIR}"/backups | grep -v password-dates | head -1)" ]]
    grep -q '"old": "admin"' "${TACCTL_STATE_DIR}/hosts/web1.json"
    grep -q '"new": "deploy2"' "${TACCTL_STATE_DIR}/hosts/web1.json"
}

@test "host provisioner rotate: a key that does not exist is refused without a terminal; a directory or a public key is no private key" {
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "${BATS_TEST_TMPDIR}/nokey" --yes
    assert_failure
    assert_output --partial "generating it needs a terminal"
    [[ "$(_pushes)" == 0 ]]
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "${BATS_TEST_TMPDIR}" --yes
    assert_failure
    assert_output --partial "is not a regular file"
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "${KEY}.pub" --yes
    assert_failure
    assert_output --partial "Could not read the public key of ${KEY}.pub (give the private key file)."
    run _hosts
    assert_output "web1|${OLD}||lab|192.0.2.1|"
}

@test "host provisioner rotate: refusals change nothing" {
    local before
    before=$(_hosts)
    "$TACCTL_BIN_SCRIPT" user add carol readonly --hash "$HASH" --scopes lab > /dev/null
    for c in \
        "nope rotate deploy2 --key $KEY --yes|No enrolled host named 'nope'." \
        "web1 rotate deploy2 --yes|Give --key <file> or --password" \
        "web1 rotate deploy2 --key $KEY --password --yes|Give --key <file> or --password" \
        "web1 rotate deploy2 --password --yes|--password needs a terminal" \
        "web1 rotate root --key $KEY --yes|cannot be 'root'" \
        "web1 rotate admin --key $KEY --yes|'admin' is the login tacctl uses for web1 now" \
        "web1 rotate carol --key $KEY --yes|'carol' is a tacctl user" \
        "web1 rotate deploy2 --key $KEY --remove-home --yes|--remove-home goes with --remove-old." \
        "web1 rotate deploy2 --key $KEY|Confirm with --yes." \
        "web1 bogus deploy2 --key $KEY|The only one is 'rotate'." \
        "web1 rotate|Usage: tacctl host provisioner <name> rotate <user>"; do
        run "$TACCTL_BIN_SCRIPT" host provisioner ${c%%|*}
        assert_failure 1
        assert_output --partial "${c#*|}"
    done
    # --remove-old needs an explicit user@ in the registry target.
    printf 'web2|web2.example.net||lab|192.0.2.1|\nrootbox|root@rootbox.example.net||lab|192.0.2.1|\n' >> "${TACCTL_STATE_DIR}/linux-hosts"
    before=$(_hosts)
    run "$TACCTL_BIN_SCRIPT" host provisioner web2 rotate deploy2 --key "$KEY" --remove-old --yes
    assert_failure
    assert_output --partial "--remove-old needs a registry target with an explicit user"
    run "$TACCTL_BIN_SCRIPT" host provisioner rootbox rotate deploy2 --key "$KEY" --remove-old --yes
    assert_failure
    assert_output --partial "The old login is 'root'; there is nothing to remove."
    [[ "$(_hosts)" == "$before" ]]
    [[ "$(_pushes)" == 0 ]]
    run grep -c 'host provisioner' "$CALLS_LOG"
    assert_output "0"
}

@test "host provisioner rotate: a proof that fails removes the new account again and leaves the registry" {
    PROOF_UID=1000 run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --yes
    assert_failure 1
    assert_output --partial "The proof failed: the new login reached sudo as UID 1000, not root."
    assert_output --partial "The new account 'deploy2' and its sudoers line were removed from web1; nothing is left there. The registry is unchanged."
    run _hosts
    assert_output "web1|${OLD}||lab|192.0.2.1|"
    [[ "$(_pushes)" == 2 ]]
    [[ "$(_push_kind 1)" == create && "$(_push_kind 2)" == remove ]]
    grep -q '^ACCOUNT=deploy2$' "$PUSHES/2"
    grep -q '^REMOVE_HOME=1$' "$PUSHES/2"
    grep -q '^SUDOERS_ONLY=0$' "$PUSHES/2"
    stub_called "^logger -t tacctl -p auth.warning host provisioner rotate name=web1 old=admin new=deploy2 auth=key step=prove by="
    if stub_called "auth.info host provisioner rotate"; then stub_calls; return 1; fi
    # The removal went over the old login, not the new one.
    stub_called "ssh .*-tt ${OLD} trap 'rm -f /tmp/tacctl.AbCd1234'"
    # Another machine behind the same name: the keys differ from the pin.
    : > "$CALLS_LOG"; rm -f "$PUSHES"/*
    PROOF_KEYS="$OTHERKEYS" run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --yes
    assert_failure 1
    assert_output --partial "The proof failed: the host reached is not 'web1' as pinned: its ssh keys differ."
    run _hosts
    assert_output "web1|${OLD}||lab|192.0.2.1|"
    # And a login that does not work at all.
    : > "$CALLS_LOG"; rm -f "$PUSHES"/*
    PROOF_FAILS=1 run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --yes
    assert_failure 1
    assert_output --partial "The proof failed: the new login did not work"
    [[ "$(_pushes)" == 2 ]]
}

@test "host provisioner rotate: a failed proof never deletes an adopted account; only the sudoers line this run added goes" {
    ORIGIN=adopted PROOF_UID=1000 run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --yes
    assert_failure 1
    assert_output --partial "The account 'deploy2' was made by an earlier run, not by this one, so it is not deleted."
    assert_output --partial "The sudoers line this run added for 'deploy2' was taken out of /etc/sudoers.d/tacctl-provisioner on web1."
    refute_output --partial "nothing is left there"
    [[ "$(_pushes)" == 2 && "$(_push_kind 2)" == remove ]]
    grep -q '^SUDOERS_ONLY=1$' "$PUSHES/2"
    grep -q '^REMOVE_HOME=0$' "$PUSHES/2"
    run _hosts
    assert_output "web1|${OLD}||lab|192.0.2.1|"
    # A line that was there before this run is left, and no script runs.
    rm -f "$PUSHES"/*
    ORIGIN=adopted SUDOERS_STATUS=unchanged PROOF_UID=1000 run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --yes
    assert_failure 1
    assert_output --partial "was there before this run and is left."
    [[ "$(_pushes)" == 1 ]]
}

@test "host provisioner rotate: one rotation of a host at a time; the second fails at once" {
    mkdir -p "${TACCTL_STATE_DIR}/locks"
    flock -x "${TACCTL_STATE_DIR}/locks/host-provisioner-web1.lock" sleep 30 &
    local holder=$!
    sleep 0.5
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --yes
    kill "$holder" 2> /dev/null || true
    assert_failure 1
    assert_output --partial "Another rotation of 'web1' is running; nothing was changed."
    [[ "$(_pushes)" == 0 ]]
    run _hosts
    assert_output "web1|${OLD}||lab|192.0.2.1|"
}

@test "host provisioner rotate: a creation that fails changes nothing; a removal that fails after a failed proof says what is left" {
    FAIL_CREATE=1 run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --yes
    assert_failure 1
    assert_output --partial "The account 'deploy2' could not be created on web1 (see above); the registry was not changed."
    [[ "$(_pushes)" == 1 ]]
    if stub_called "tacctl-uid="; then stub_calls; return 1; fi
    run _hosts
    assert_output "web1|${OLD}||lab|192.0.2.1|"
    : > "$CALLS_LOG"; rm -f "$PUSHES"/*
    PROOF_UID=5 FAIL_REMOVE=1 run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --yes
    assert_failure 1
    assert_output --partial "The new account 'deploy2' could not be removed from web1. Left there: the account 'deploy2' with its home, and its line in /etc/sudoers.d/tacctl-provisioner."
}

@test "host provisioner rotate --remove-old: the old account is removed last, over the new one; a re-run finishes an interrupted removal" {
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --remove-old --yes
    assert_success
    assert_output --partial "The old account 'admin' is removed from web1."
    [[ "$(_pushes)" == 2 ]]
    [[ "$(_push_kind 1)" == create && "$(_push_kind 2)" == remove ]]
    grep -q '^ACCOUNT=admin$' "$PUSHES/2"
    grep -q '^REMOVE_HOME=0$' "$PUSHES/2"
    local log_n rm_n
    log_n=$(_line "^logger -t tacctl -p auth.info host provisioner rotate ")
    rm_n=$(_line "ssh .*-i ${KEY} .*-tt ${NEW} trap 'rm -f /tmp/tacctl.AbCd1234'")
    [[ -n "$log_n" && -n "$rm_n" ]] && (( log_n < rm_n )) || { stub_calls; return 1; }
    stub_called "^logger -t tacctl -p auth.info host provisioner remove-old name=web1 old=admin new=deploy2 by="
    grep -q '"old_removed": true' "${TACCTL_STATE_DIR}/hosts/web1.json"

    # --remove-home deletes the home too.
    printf 'web1|%s||lab|192.0.2.1|\n' "$OLD" > "${TACCTL_STATE_DIR}/linux-hosts"
    rm -f "$PUSHES"/*
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --remove-old --remove-home --yes
    assert_success
    grep -q '^REMOVE_HOME=1$' "$PUSHES/2"

    # A removal that fails leaves the registry on the new account and says how
    # to finish; the re-run does only the removal.
    printf 'web1|%s||lab|192.0.2.1|\n' "$OLD" > "${TACCTL_STATE_DIR}/linux-hosts"
    rm -f "$PUSHES"/*
    FAIL_REMOVE=1 run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --remove-old --yes
    assert_failure 1
    assert_output --partial "The old account 'admin' could not be removed from web1 (see above). The registry already reaches the new account;"
    assert_output --partial "Try again: tacctl host provisioner web1 rotate deploy2 --key ${KEY} --remove-old"
    run _hosts
    assert_output "web1|${NEW}||lab|192.0.2.1|${KEY}"
    rm -f "$PUSHES"/*
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --remove-old --yes
    assert_success
    assert_output --partial "The old account 'admin' is removed from web1."
    [[ "$(_pushes)" == 1 && "$(_push_kind 1)" == remove ]]
    grep -q '^ACCOUNT=admin$' "$PUSHES/1"
}

@test "host provisioner rotate --password: typed into the host's own passwd; nothing of it reaches a log, a call or a file" {
    local secret="Sup3r-S3cret-Typed"
    on_tty "${secret}\n" host provisioner web1 rotate deploy2 --password --yes
    assert_success
    assert_output --partial "Host 'web1' is now reached at ${NEW}"
    run _hosts
    assert_output "web1|${NEW}||lab|192.0.2.1|"
    grep -q '^AUTH=password$' "$PUSHES/1"
    if grep -q '^PUBKEY=ssh-' "$PUSHES/1"; then return 1; fi
    grep -q "^SUDOERS_LINE=deploy2\\\\ ALL=\\\\(ALL:ALL\\\\)\\\\ ALL$" "$PUSHES/1"
    # The create run and the proof carry a terminal; the proof uses no key.
    stub_called "ssh .*-t ${OLD} .*sudo -p '\\[sudo\\] password for %u on %H: ' bash /tmp/tacctl.AbCd1234"
    stub_called "ssh .*-o ControlMaster=no -o ControlPath=none .*-o PubkeyAuthentication=no .* -t ${NEW} u=.*sudo -p"
    if grep -E -- "ssh .*(IdentitiesOnly|-i )" <(grep -- "-o ControlPath=none" "$CALLS_LOG"); then return 1; fi
    stub_called "^logger -t tacctl -p auth.info host provisioner rotate name=web1 old=admin new=deploy2 auth=password by="
    # The typed text is nowhere: not in a call, a pushed script, a state file
    # or a log.
    if grep -rqF -- "$secret" "$CALLS_LOG" "$PUSHES" "$TACCTL_STATE_DIR" "$TACCTL_LOG" 2> /dev/null; then
        grep -rlF -- "$secret" "$CALLS_LOG" "$PUSHES" "$TACCTL_STATE_DIR" "$TACCTL_LOG"
        return 1
    fi
}

@test "host provisioner rotate --dry-run: prints the plan, reads the host, changes and copies nothing" {
    printf 'deploy2:x:1500:1500:tacctl provisioning account,,,:/home/deploy2:/bin/bash\n' >> "$PASSWD_ON_HOST"
    printf 'account=deploy2\nuid=1500\nssh_dir=1\n' > "$STATE_ON_HOST"
    SSHD_PW=no run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --remove-old --dry-run
    assert_success
    assert_output --partial "useradd -m -U -s /bin/bash -c 'tacctl provisioning account' -K UID_MAX=79999 -K GID_MAX=79999 deploy2"
    assert_output --partial "/etc/sudoers.d/tacctl-provisioner: deploy2 ALL=(ALL:ALL) NOPASSWD: ALL"
    assert_output --partial "SHA256:"
    assert_output --partial "web1|${OLD}||lab|192.0.2.1|"
    assert_output --partial "web1|${NEW}||lab|192.0.2.1|${KEY}"
    assert_output --partial "remove the old account 'admin'"
    assert_output --partial "The account 'deploy2' (UID 1500) was made by tacctl (root's record on web1 agrees); the rotation adopts it and empties its ~/.ssh."
    assert_output --partial "sshd on web1: passwordauthentication no"
    assert_output --partial "Dry run: nothing was changed."
    [[ "$(_pushes)" == 0 ]]
    run _hosts
    assert_output "web1|${OLD}||lab|192.0.2.1|"
    if stub_called "^logger "; then stub_calls; return 1; fi
    # An account of that name that is not ours: the real run would refuse.
    printf 'other:x:1501:1501:Somebody:/home/other:/bin/bash\n' >> "$PASSWD_ON_HOST"
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate other --key "$KEY" --dry-run
    assert_success
    assert_output --partial "exists on web1 and no readable record shows that tacctl made it (the comment field is not proof); the rotation would refuse it."
}

@test "host provisioner rotate: the audit lines hold the names and the method, no secret" {
    run "$TACCTL_BIN_SCRIPT" host provisioner web1 rotate deploy2 --key "$KEY" --remove-old --yes
    assert_success
    run grep -E "^logger " "$CALLS_LOG"
    assert_line --index 0 --regexp "^logger -t tacctl -p auth.info host provisioner rotate name=web1 old=admin new=deploy2 auth=key by=[a-z0-9_-]+$"
    assert_line --index 1 --regexp "^logger -t tacctl -p auth.info host provisioner remove-old name=web1 old=admin new=deploy2 by=[a-z0-9_-]+$"
    refute_output --partial "0123456789abcdef"
}
