#!/usr/bin/env bash
# no-shared-proc.sh
#
# Fails when a test reaches outside its own sandbox, so that tests and test
# runs can share a machine and run in parallel:
#   - a process-wide command, in tests/integration/*.bats, tests/e2e,
#     tests/helpers or a *_test.go file (it matches the processes of every
#     other run; keep the pid, or look for a name made unique by the test's
#     own directory):
#       pgrep or pkill with -f or --full, whatever the options before it;
#       killall;
#       pkill at the start of a shell command, or exec.Command("pkill", ...)
#       in Go, unless it signals the children of a pid (-P);
#     pgrep without -f and the -P (by parent) forms stay allowed;
#   - a shared temporary path: /dev/shm, a "/tmp" directory given to os.* or
#     filepath.*, a bare "/tmp" string, or a shell command (mktemp, mkdir,
#     touch, cp, mv, rm, ln, tee, a redirection) on /tmp, in a *_test.go file,
#     tests/integration/*.bats or tests/helpers (a test takes t.TempDir(),
#     BATS_TEST_TMPDIR or the TMPDIR of its environment). The name
#     /tmp/tacctl.* is the remote script path of the ssh stubs, and the
#     scripts of tests/tools (gate-*.sh) are not looked at.
# A line that must name a shared path (the TMPDIR fallback of a path that has
# to stay short, a socket path limit) carries the comment
# 'shared-proc-ok: <reason>', with a reason. The comment excuses a shared
# path only: it never excuses a process-wide command, and a comment without a
# reason excuses nothing. No file is excused whole.
set -euo pipefail
cd "$(dirname "$0")/../.."

# A word of a command is not part of a longer name or path.
pre='(^|[^[:alnum:]_-])'
post='([^[:alnum:]_-]|$)'
quote="'"
# Where a shell command starts: the start of the line, after ; & | ( { ` or
# $( , or after a word that runs another command (bats' run, sudo, ...) with
# its options.
cmdpos="((^|[;&|({\`]|\\\$\\()[[:space:]]*|[[:space:]](run|sudo|exec|env|nohup|time|then|do|else)[[:space:]]+(-[^[:space:]]+[[:space:]]+|![[:space:]]+)*)"

killall_re="${pre}killall${post}"
# -f or --full anywhere after pgrep or pkill in the same command: -af, -9 -f,
# -u "\$USER" -f, "-f" as a Go argument.
full_re="${pre}(pgrep|pkill)[[:space:]\"${quote}]([^;|&#]*[[:space:]\"${quote}])?(-[[:alpha:]]*f[[:alpha:]]*|--full)${post}"
# pkill by name in a shell command, and in Go through os/exec.
pkill_sh_re="${cmdpos}pkill([[:space:]]|\$)"
pkill_go_re='exec\.Command(Context)?\([^")]*"pkill"'
# What makes a pkill harmless: it signals the children of a pid.
parent_re="${pre}pkill[[:space:]\"${quote}]([^;|&#]*[[:space:]\"${quote}])?(-[[:alnum:]]*P[[:alnum:]]*|--parent)${post}"

shm_re='/dev/shm'
go_tmp_re='(os|ioutil|filepath)\.[A-Za-z]+\([[:space:]]*"/tmp|"/tmp"'
sh_tmp_re='(^|[^[:alnum:]_-])(mktemp|mkdir|touch|cp|mv|rm|ln|tee|install)[[:space:]][^|;&#]*[[:space:]"=]/tmp([/"[:space:]]|$)|>>?[[:space:]]*"?/tmp/'

# excused drops the lines that say why a shared path is fine (a reason after
# the colon) from a git grep -n result.
excused() {
    { grep -vE 'shared-proc-ok:[[:space:]]*[^[:space:]]' || true; } | sed '/^$/d'
}

proc_files=('tests/integration/*.bats' tests/e2e tests/helpers '*_test.go')
procs=$(
    {
        git grep -nIE "$killall_re" -- "${proc_files[@]}" || true
        git grep -nIE "$full_re" -- "${proc_files[@]}" || true
        {
            git grep -nIE "$pkill_sh_re" -- 'tests/integration/*.bats' tests/e2e tests/helpers || true
            git grep -nIE "$pkill_go_re" -- '*_test.go' || true
        } | { grep -vE "$parent_re" || true; }
    } | sed '/^$/d' | sort -u
)
tmps=$(
    {
        git grep -nIE "$shm_re" -- '*_test.go' 'tests/integration/*.bats' tests/helpers || true
        git grep -nIE "$go_tmp_re" -- '*_test.go' || true
        git grep -nIE "$sh_tmp_re" -- 'tests/integration/*.bats' tests/helpers || true
    } | { grep -v '/tmp/tacctl\.' || true; } | excused | sort -u
)

status=0
if [[ -n "$procs" ]]; then
    echo "no-shared-proc: a test names the processes of the whole machine:" >&2
    printf '%s\n' "$procs" | sed 's/^/  /' >&2
    echo "no-shared-proc: keep the pid of the process the test started (pkill -P signals its children), or match a name made unique by the test's directory; shared-proc-ok does not excuse this." >&2
    status=1
fi
if [[ -n "$tmps" ]]; then
    echo "no-shared-proc: a test uses a shared temporary path:" >&2
    printf '%s\n' "$tmps" | sed 's/^/  /' >&2
    echo "no-shared-proc: use t.TempDir(), BATS_TEST_TMPDIR or the TMPDIR of the environment; a line that must name one says 'shared-proc-ok: <reason>'." >&2
    status=1
fi
exit "$status"
