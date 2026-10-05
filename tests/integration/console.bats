#!/usr/bin/env bats
# Integration tests for the login console: the binary started as
# `tacctl-console` (a symlink to dist/tacctl, as /usr/local/bin/tacctl-console
# is to the installed binary). The `sudo` stub records its argv, exports the
# NAME=value assignments it is given (as sudo's env_keep does), drops -n and
# runs the rest; `id` and `logger` are stubs. TACCTL_TEST_CONSOLE_ENV=1 keeps
# the sandbox's TACCTL_* variables and PATH through the console's scrub.
# The terminal side is covered by internal/cli/console_pty_test.go.

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
    # The policy line and where the stub keeps the environment it got are
    # written into the stub: the console's scrub drops the test's variables.
    stub_cmd sudo "while [[ \"\${1:-}\" == -n || \"\${1:-}\" == *=* ]]; do [[ \"\$1\" == *=* ]] && export \"\$1\"; shift; done
env > '${BATS_TEST_TMPDIR}/sudo.env'
case \" \$* \" in *' _console-policy '*) echo 'shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no tier=readonly list_max=40'; exit 0 ;; esac
exec \"\$@\""
    stub_cmd id 'echo carol tac-users tac-readonly'
    export HOME="${BATS_TEST_TMPDIR}/home"
    # Who the session is logged as (not whoever runs the suite).
    export USER=carol LOGNAME=carol
    # Not over ssh unless a test says so.
    unset SSH_CLIENT SSH_CONNECTION SSH_TTY
    mkdir -p "$HOME"
    CONSOLE_BIN="${BATS_TEST_TMPDIR}/tacctl-console"
    ln -s "$TACCTL_BIN_SCRIPT" "$CONSOLE_BIN"
    export TACCTL_TEST_CONSOLE_ENV=1
    # The session id: the first 6 bytes of the test random source.
    export TACCTL_TEST_RANDOM=0123456789ab
    EXE="$(readlink -f "$TACCTL_BIN_SCRIPT")"
}

# sudo_lines: the sudo calls of the run, one per line.
sudo_lines() { grep '^sudo ' "$CALLS_LOG" || true; }
# console_log: the console's own log lines.
console_log() { grep '^logger -t tacctl-console ' "$CALLS_LOG" | sed 's/^logger -t tacctl-console //' || true; }

@test "console -c: one tacctl line runs as 'sudo -n TACCTL_CONSOLE=<session> <exe> <words>', logged" {
    run "$CONSOLE_BIN" -c "user list"
    assert_success
    assert_output --partial "USERNAME"
    run sudo_lines
    assert_line --index 0 "sudo -n TACCTL_CONSOLE=0123456789ab ${EXE} _console-policy"
    assert_line --index 1 "sudo -n TACCTL_CONSOLE=0123456789ab ${EXE} user list"
    [ "${#lines[@]}" -eq 2 ]
    run console_log
    assert_line --index 0 "-p auth.info console start session=0123456789ab user=${USER} from=- tty=- mode=command"
    assert_line --index 1 "-p auth.info console end session=0123456789ab user=${USER} reason=command lines=1 status=0"
}

@test "console: a superuser's lines run plain sudo (the password prompt), others keep -n" {
    stub_cmd id 'echo alice tac-users tac-superuser'
    run "$CONSOLE_BIN" -c "user list"
    assert_success
    run sudo_lines
    assert_line --index 1 "sudo TACCTL_CONSOLE=0123456789ab ${EXE} user list"
    : > "$CALLS_LOG"
    stub_cmd id 'echo bob tac-users tac-operator'
    run "$CONSOLE_BIN" -c "user list"
    run sudo_lines
    assert_line --index 1 "sudo -n TACCTL_CONSOLE=0123456789ab ${EXE} user list"
}

@test "console -c: scp, sftp, rsync, programs and the shell's own words are refused, exit 126, nothing run" {
    local line
    while IFS= read -r line; do
        : > "$CALLS_LOG"
        run "$CONSOLE_BIN" -c "$line"
        assert_failure 126
        assert_output "the tacctl console does not run programs; file transfer is not available"
        run sudo_lines
        assert_output ""
        run console_log
        assert_line --index 1 --partial "-p auth.warning console DENY session=0123456789ab user="
        assert_line --index 1 --partial " reason=command first="
        assert_line --index 2 --partial "reason=command lines=0 status=126"
    done <<'LIST'
scp -t .
scp -f /etc/passwd
/usr/lib/openssh/sftp-server
rsync --server -vlogDtpre.iLsfxC . /tmp
bash
sh -c id
system-shell
exit
history

LIST
}

@test "console: the login form (-tacctl-console) and a refusal of any other option" {
    run bash -c 'exec -a -tacctl-console "$0" -c "user list"' "$CONSOLE_BIN"
    assert_success
    assert_output --partial "USERNAME"
    run "$CONSOLE_BIN" -x
    assert_failure 126
    assert_output "the tacctl console takes no options"
    run "$CONSOLE_BIN" -c "user list" extra
    assert_failure 126
    run sudo_lines
    [ "${#lines[@]}" -eq 2 ]
}

@test "console: the login environment does not reach the lines" {
    BASH_ENV=/nonexistent ENV=/nonexistent LD_LIBRARY_PATH=/nonexistent SSH_AUTH_SOCK=/tmp/agent FOO=bar \
        SSH_CLIENT="192.0.2.9 50000 22" SSH_TTY=/dev/pts/7 LC_TIME=C \
        run "$CONSOLE_BIN" -c "user list"
    assert_success
    run cat "${BATS_TEST_TMPDIR}/sudo.env"
    refute_line --regexp '^(BASH_ENV|ENV|LD_LIBRARY_PATH|SSH_AUTH_SOCK|FOO|BATS_TEST_TMPDIR)='
    assert_line "SHELL=/usr/local/bin/tacctl-console"
    assert_line "TACCTL_CONSOLE=0123456789ab"
    assert_line "LC_TIME=C"
    assert_line "SSH_TTY=/dev/pts/7"
    run console_log
    assert_line --index 0 --partial "from=192.0.2.9 tty=/dev/pts/7 mode=command"
}

@test "console < file: the lines run in order as a batch; system-shell is refused there" {
    run bash -c 'printf "user list\nsystem-shell\nuser list\n" | "$0"' "$CONSOLE_BIN"
    assert_failure 126
    assert_output --partial "the tacctl console does not run programs; file transfer is not available"
    run sudo_lines
    assert_line --index 1 "sudo -n TACCTL_CONSOLE=0123456789ab ${EXE} user list"
    [ "${#lines[@]}" -eq 2 ]
    run console_log
    assert_line --index 0 --partial "mode=batch"
    assert_line --index 1 --partial "console DENY session=0123456789ab user="
    assert_line --index 1 --partial "first=system-shell"
    assert_line --index 2 --partial "reason=failed lines=2 status=126"
}

@test "console: without an answer from _console-policy the defaults apply and the lines still run" {
    stub_cmd sudo 'while [[ "${1:-}" == -n || "${1:-}" == *=* ]]; do shift; done
case " $* " in *" _console-policy "*) echo "sudo: a password is required" >&2; exit 1 ;; esac
exec "$@"'
    run "$CONSOLE_BIN" -c "user list"
    assert_success
    assert_output --partial "USERNAME"
}

@test "console: help names system-shell; tacctl shell's does not" {
    run "$CONSOLE_BIN" -c "help"
    assert_success
    assert_output --partial "system-shell"
    run "$TACCTL_BIN_SCRIPT" shell -c "help"
    assert_success
    refute_output --partial "system-shell"
}

@test "console: the root side answers _console-policy for the caller" {
    # The stub runs the real _console-policy (sudo's assignments exported).
    stub_cmd sudo 'while [[ "${1:-}" == -n || "${1:-}" == *=* ]]; do [[ "$1" == *=* ]] && export "$1"; shift; done; exec "$@"'
    printf '/bin/sh\n/bin/bash\n' > "$TACCTL_SHELLS_FILE"
    run "$CONSOLE_BIN" -c "user list"
    assert_success
    run grep -F "logger -t tacctl -p auth.info console policy user=" "$CALLS_LOG"
    assert_output --partial "session=0123456789ab"
}
