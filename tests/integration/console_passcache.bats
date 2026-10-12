#!/usr/bin/env bats
# Integration tests for the password cache (docs/plans/0.2.4-plan.md D70):
# `console password-cache`, `console forget`, the policy line, and the
# console and `tacctl shell --password-cache` on a pseudo-terminal (script(1))
# with a `sudo` stub that records its argv and the environment it was given.
# The protocol, the lifetimes and the socket checks are internal/askpass's Go
# tests; the root side of a pull and of ssh are internal/cli's.

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
    load_store_fixture store.multiscope.yaml
    CONSOLE="${TACCTL_STATE_DIR}/console.yaml"
    printf '/bin/sh\n/bin/bash\n' > "$TACCTL_SHELLS_FILE"
    export HOME="${BATS_TEST_TMPDIR}/home"
    export USER=carol LOGNAME=carol
    unset SSH_CLIENT SSH_CONNECTION SSH_TTY
    mkdir -p "$HOME"
    CONSOLE_BIN="${BATS_TEST_TMPDIR}/tacctl-console"
    ln -s "$TACCTL_BIN_SCRIPT" "$CONSOLE_BIN"
    export TACCTL_TEST_CONSOLE_ENV=1
    export TACCTL_TEST_RANDOM=0123456789ab
    # The socket directory of a plain shell: short, since a socket path is
    # limited to 107 bytes (the console's scrubbed environment has none and
    # uses the user's /run/user/<uid>, or $HOME/.local/state/tacctl/run).
    XDG_RUNTIME_DIR="$(mktemp -d /tmp/pcache.XXXXXX)"
    export XDG_RUNTIME_DIR
    EXE="$(readlink -f "$TACCTL_BIN_SCRIPT")"
    # The sudo stub: the policy answer (the line plus policy.extra), the
    # environment of the stub itself per line (sudo.env.<n>), then the line
    # is not run (a pty test only looks at what the session handed it).
    stub_cmd sudo "while [[ \"\${1:-}\" == -n || \"\${1:-}\" == *=* ]]; do [[ \"\$1\" == *=* ]] && export \"\$1\"; shift; done
case \" \$* \" in *' _console-policy '*) echo 'shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no tier=operator list_max=40'\"\$(cat '${BATS_TEST_TMPDIR}/policy.extra' 2>/dev/null)\"; exit 0 ;; esac
n=\$(ls '${BATS_TEST_TMPDIR}'/sudo.env.* 2>/dev/null | wc -l)
env > '${BATS_TEST_TMPDIR}'/sudo.env.\$n
exit 0"
    stub_cmd id 'echo carol tac-users tac-operator'
}

plain() { output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output"); }

# on_pty <command...>: run the command with the input of $PTY_INPUT on a
# pseudo-terminal; the terminal's output is in $output.
on_pty() {
    run script -qec "$*" /dev/null < <(printf '%b' "$PTY_INPUT"; sleep 1)
}

# sudo_envs: the files of the environments the stub saw, in order.
sudo_envs() { ls "${BATS_TEST_TMPDIR}"/sudo.env.* 2>/dev/null | sort -V; }

teardown() { rm -rf "${XDG_RUNTIME_DIR:-/nonexistent}"; }

@test "console password-cache: tiers, idle and max, written only when set, shown by console show" {
    run "$TACCTL_BIN_SCRIPT" console password-cache
    assert_success
    assert_output $'tiers: none\nidle: 15 min\nmax: 8 h'
    [[ ! -e "$CONSOLE" ]]
    run "$TACCTL_BIN_SCRIPT" console password-cache tiers operator,superuser
    assert_success
    run "$TACCTL_BIN_SCRIPT" console password-cache idle 30
    assert_success
    run "$TACCTL_BIN_SCRIPT" console password-cache max 4
    assert_success
    run grep -A4 'password_cache:' "$CONSOLE"
    assert_output --partial "tiers: [operator, superuser]"
    assert_output --partial "idle: 30"
    assert_output --partial "max: 4"
    run "$TACCTL_BIN_SCRIPT" console password-cache
    assert_output $'tiers: operator,superuser\nidle: 30 min\nmax: 4 h'
    run "$TACCTL_BIN_SCRIPT" console show
    plain
    assert_output --partial "password-cache tiers: operator,superuser"
    assert_output --partial "password-cache idle: 30 min"
    assert_output --partial "password-cache max: 4 h"
    # Back to the defaults: the key is gone.
    run "$TACCTL_BIN_SCRIPT" console password-cache tiers none
    run "$TACCTL_BIN_SCRIPT" console password-cache idle 15
    run "$TACCTL_BIN_SCRIPT" console password-cache max 8
    run grep -c password_cache "$CONSOLE"
    assert_output 0
}

@test "console password-cache: the engineer is a candidate, readonly and bad numbers are refused with nothing written" {
    run "$TACCTL_BIN_SCRIPT" console password-cache tiers engineer
    assert_success
    local before; before="$(cat "$CONSOLE")"
    for args in "tiers readonly" "tiers operator,operator" "tiers wizard" "idle 0" "idle 121" "max 25" "max soon" "keep"; do
        run "$TACCTL_BIN_SCRIPT" console password-cache $args
        assert_failure 1
        [[ "$(cat "$CONSOLE")" == "$before" ]]
    done
}

@test "console password-cache: lower tiers do not set it" {
    stub_cmd id 'echo bob tac-users tac-operator'
    SUDO_USER=bob SUDO_UID="$(id -u)" run "$TACCTL_BIN_SCRIPT" console password-cache tiers operator
    assert_failure
}

@test "_console-policy: password_cache=yes pc_idle= pc_max= only for a tier that has it" {
    run "$TACCTL_BIN_SCRIPT" console password-cache tiers operator
    run "$TACCTL_BIN_SCRIPT" console password-cache idle 20
    stub_cmd id 'echo "$3 tac-users"'
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_success
    assert_output --regexp ' password_cache=yes pc_idle=20 pc_max=8$'
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_success
    refute_output --partial "password_cache"
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" _console-policy
    refute_output --partial "password_cache"
}

@test "console on a terminal, cache on: the lines that use it get TACCTL_ASKPASS in the sudo environment, never in its arguments" {
    printf ' password_cache=yes pc_idle=1 pc_max=1' > "${BATS_TEST_TMPDIR}/policy.extra"
    PTY_INPUT='ssh core-sw1\nuser list\ndevice config pull --all\nconsole forget\nexit\n'
    on_pty "$CONSOLE_BIN"
    assert_success
    plain
    assert_output --partial "no password is cached"
    # The policy question, then the three lines.
    run grep -c '^sudo ' "$CALLS_LOG"
    assert_output 4
    run grep '^sudo ' "$CALLS_LOG"
    refute_output --partial "TACCTL_ASKPASS"
    refute_output --regexp '[0-9a-f]{64}'
    local envs; mapfile -t envs < <(sudo_envs)
    [ "${#envs[@]}" -eq 3 ]
    # ssh and the pull carry it, the user list does not.
    grep -q '^TACCTL_ASKPASS=.*tacctl/ap-.*\.sock:[0-9a-f]\{64\}$' "${envs[0]}"
    ! grep -q '^TACCTL_ASKPASS=' "${envs[1]}"
    grep -q '^TACCTL_ASKPASS=' "${envs[2]}"
    # The socket is gone with the session.
    local sock; sock="$(sed -n 's/^TACCTL_ASKPASS=\(.*\):[0-9a-f]\{64\}$/\1/p' "${envs[0]}")"
    [[ -n "$sock" ]]
    [[ ! -e "$sock" ]]
}

@test "console on a terminal, cache off: no variable, and console forget says so" {
    PTY_INPUT='ssh core-sw1\nconsole forget\nexit\n'
    on_pty "$CONSOLE_BIN"
    assert_success
    plain
    assert_output --partial "no password is cached: the password cache is not on in this session"
    local envs; mapfile -t envs < <(sudo_envs)
    [ "${#envs[@]}" -eq 1 ]
    ! grep -q '^TACCTL_ASKPASS=' "${envs[0]}"
}

@test "tacctl shell --password-cache: a caller outside tac-users asks for it themselves; a tier without it is told" {
    stub_cmd id 'echo carol users'
    PTY_INPUT='ssh core-sw1\nexit\n'
    on_pty "$TACCTL_BIN_SCRIPT" shell --password-cache
    assert_success
    local envs; mapfile -t envs < <(sudo_envs)
    [ "${#envs[@]}" -eq 1 ]
    grep -q "^TACCTL_ASKPASS=${XDG_RUNTIME_DIR}/tacctl/ap-.*\.sock:[0-9a-f]\{64\}\$" "${envs[0]}"

    rm -f "${BATS_TEST_TMPDIR}"/sudo.env.*
    stub_cmd id 'echo carol tac-users tac-operator'
    PTY_INPUT='ssh core-sw1\nexit\n'
    on_pty "$TACCTL_BIN_SCRIPT" shell --password-cache
    assert_success
    plain
    assert_output --partial "password cache unavailable: it is not enabled for your tier"
    local envs2; mapfile -t envs2 < <(sudo_envs)
    # The policy question is the first stub call; the ssh line the last.
    ! grep -q '^TACCTL_ASKPASS=' "${envs2[-1]}"
}

@test "tacctl shell -c and batch: --password-cache applies to the interactive shell only, said once" {
    stub_cmd id 'echo carol users'
    run "$TACCTL_BIN_SCRIPT" shell --password-cache -c 'user list'
    assert_success
    assert_output --partial "--password-cache applies to the interactive shell only"
    run bash -c 'printf "user list\n" | "$0" shell --password-cache' "$TACCTL_BIN_SCRIPT"
    assert_output --partial "--password-cache applies to the interactive shell only"
    run bash -c 'printf "user list\n" | "$0" shell' "$TACCTL_BIN_SCRIPT"
    refute_output --partial "password-cache"
}

@test "_askpass: a prompt with no cache gets no output and exit 1, and nothing on stderr" {
    bats_require_minimum_version 1.5.0
    run --separate-stderr "$TACCTL_BIN_SCRIPT" _askpass "alice@host's password: "
    assert_failure 1
    assert_output ""
    [ -z "$stderr" ]
    # ssh's way: the tacctl binary, one argument, the marker in the environment.
    TACCTL_ASKPASS_HELPER=1 run --separate-stderr "$TACCTL_BIN_SCRIPT" "Password: "
    assert_failure 1
    assert_output ""
    [ -z "$stderr" ]
    # A malformed or foreign variable is no cache.
    TACCTL_ASKPASS_HELPER=1 TACCTL_ASKPASS=/tmp/x.sock:short run --separate-stderr "$TACCTL_BIN_SCRIPT" "Password: "
    assert_failure 1
    assert_output ""
    # Without the marker one argument is an unknown command, as ever.
    run "$TACCTL_BIN_SCRIPT" "Password: "
    assert_failure 1
    assert_output --partial "Usage:"
}
