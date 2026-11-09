#!/usr/bin/env bats
# Integration tests for the console's file transfer: the binary started as
# `tacctl-console -c <sftp subsystem>` with a canned SFTP init on standard
# input (the version request every client opens with, then the end of the
# input). The root side's policy is the stub of console.bats, with the file
# transfer fields in policy.extra. The files of the home are never touched:
# the session ends before any request (the Go tests, internal/cli/
# console_sftp_test.go, drive the whole protocol with a real client).

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
    load_fixture tacquito.minimal.yaml
    stub_cmd sudo "while [[ \"\${1:-}\" == -n || \"\${1:-}\" == *=* ]]; do [[ \"\$1\" == *=* ]] && export \"\$1\"; shift; done
case \" \$* \" in *' _console-policy '*) echo 'shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no tier=readonly list_max=40'\"\$(cat '${BATS_TEST_TMPDIR}/policy.extra' 2>/dev/null)\"; exit 0 ;; esac
exec \"\$@\""
    stub_cmd id 'echo carol tac-users tac-readonly'
    export HOME="${BATS_TEST_TMPDIR}/home"
    export USER=carol LOGNAME=carol
    unset SSH_CLIENT SSH_CONNECTION SSH_TTY
    mkdir -p "$HOME"
    CONSOLE_BIN="${BATS_TEST_TMPDIR}/tacctl-console"
    ln -s "$TACCTL_BIN_SCRIPT" "$CONSOLE_BIN"
    export TACCTL_TEST_CONSOLE_ENV=1
    export TACCTL_TEST_RANDOM=0123456789ab
}

console_log() { grep '^logger -t tacctl-console ' "$CALLS_LOG" | sed 's/^logger -t tacctl-console //; s/ sid=[a-z0-9]\{8\}$//' || true; }

# init: the SSH_FXP_INIT packet of an sftp client (length 5, type 1, version 3).
init() { printf '\000\000\000\005\001\000\000\000\003'; }

@test "console -c sftp-server: with file transfer on, the session answers the client's init with the version packet and ends with status 0" {
    # the account's home comes from the account database (never $HOME): the
    # session needs the running user to have one
    home=$(getent passwd "$(/usr/bin/id -u)" | cut -d: -f6)
    [[ -n "$home" && -d "$home" ]] || skip "the running user has no home directory in the account database"
    printf ' file_transfer=yes ft_quota=0 ft_rate=0' > "${BATS_TEST_TMPDIR}/policy.extra"
    # a client keeps its input open until it has the answer (the real one waits for
    # the version packet); the second is the time the console has to write it
    { init; sleep 1; } | "$CONSOLE_BIN" -c /usr/lib/openssh/sftp-server > "${BATS_TEST_TMPDIR}/out.bin" 2> "${BATS_TEST_TMPDIR}/err.txt"
    # standard output holds SFTP packets only: the version packet (type 2) first
    [[ "$(od -An -tx1 -j4 -N1 "${BATS_TEST_TMPDIR}/out.bin" | tr -d ' \n')" == "02" ]]
    [[ ! -s "${BATS_TEST_TMPDIR}/err.txt" ]]
    run console_log
    assert_line --index 0 "-p auth.info console start session=0123456789ab user=carol from=- tty=- mode=sftp"
    assert_line --index 1 --regexp "^-p auth.info console sftp start session=0123456789ab user=carol tier=readonly from=- home=\".*\" quota=unlimited rate=off\$"
    assert_line --index 2 "-p auth.info console sftp end session=0123456789ab user=carol up=0 down=0 ops=0 refused=0"
    assert_line --index 3 "-p auth.info console end session=0123456789ab user=carol reason=sftp lines=0 status=0"
    [ "${#lines[@]}" -eq 4 ]
}

@test "console -c internal-sftp: refused with status 126, a text on standard error only and a DENY line, while file transfer is off" {
    run bash -c '"$0" -c internal-sftp > "$1/out.bin" 2> "$1/err.txt" < /dev/null' "$CONSOLE_BIN" "$BATS_TEST_TMPDIR"
    assert_failure 126
    [[ ! -s "${BATS_TEST_TMPDIR}/out.bin" ]]
    run cat "${BATS_TEST_TMPDIR}/err.txt"
    assert_output "file transfer is not enabled for this account; an administrator can switch it on (tacctl console file-transfer)"
    run console_log
    assert_line --index 1 "-p auth.warning console DENY session=0123456789ab user=carol reason=file-transfer subsystem=sftp"
    assert_line --index 2 "-p auth.info console end session=0123456789ab user=carol reason=sftp lines=0 status=126"
}

@test "console -c scp -f: still refused with the program text when file transfer is on" {
    printf ' file_transfer=yes ft_quota=0 ft_rate=0' > "${BATS_TEST_TMPDIR}/policy.extra"
    run "$CONSOLE_BIN" -c "scp -f x"
    assert_failure 126
    assert_output "the tacctl console does not run programs or shell commands; file transfer is SFTP only (sftp, scp of OpenSSH 9 or later)"
}
