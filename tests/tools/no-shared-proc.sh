#!/usr/bin/env bash
# no-shared-proc.sh
#
# Fails when a test reaches outside its own sandbox, so that tests and test
# runs can share a machine and run in parallel:
#   - a process-wide command: pgrep -f, pkill -f or killall in
#     tests/integration/*.bats, tests/e2e, tests/helpers or a *_test.go file
#     (it matches the processes of every other run; keep the pid, or look
#     for a name made unique by the test's own directory);
#   - a shared temporary path: /dev/shm, a "/tmp" directory given to os.* or
#     filepath.*, a bare "/tmp" string, or a shell command (mktemp, mkdir,
#     touch, cp, mv, rm, ln, tee, a redirection) on /tmp, in a *_test.go file,
#     tests/integration/*.bats or tests/helpers (a test takes t.TempDir(),
#     BATS_TEST_TMPDIR or the TMPDIR of its environment). The name
#     /tmp/tacctl.* is the remote script path of the ssh stubs, and the
#     scripts of tests/tools (gate-*.sh) are not looked at.
# A line that must name one (the TMPDIR fallback of a path that has to stay
# short, a socket path limit) carries the comment 'shared-proc-ok: <reason>'.
# The files below are named whole; each has its reason.
set -euo pipefail
cd "$(dirname "$0")/../.."

allowed=(
    # Fixed by the shards task.
    tests/integration/gate_go.bats
    tests/integration/gate_ci.bats
    # os.MkdirTemp("/tmp", ...) for a short socket directory; to be moved to
    # a short path under TMPDIR like internal/askpass/agent_test.go.
    internal/cli/password_cache_test.go
)

proc_re='(pgrep|pkill)([[:space:]]+-[[:alnum:]]+)*[[:space:]]+(-[[:alpha:]]*f|--full)|(^|[^[:alnum:]_-])killall([^[:alnum:]_-]|$)'
shm_re='/dev/shm'
go_tmp_re='(os|ioutil|filepath)\.[A-Za-z]+\([[:space:]]*"/tmp|"/tmp"'
sh_tmp_re='(^|[^[:alnum:]_-])(mktemp|mkdir|touch|cp|mv|rm|ln|tee|install)[[:space:]][^|;&#]*[[:space:]"=]/tmp([/"[:space:]]|$)|>>?[[:space:]]*"?/tmp/'

# filter drops the lines of the allowed files and the lines that say why
# they are fine from a git grep -n result.
filter() {
    local lines a
    lines=$(grep -v 'shared-proc-ok:' || true)
    for a in "${allowed[@]}"; do
        lines=$(printf '%s\n' "$lines" | grep -v "^$a:" || true)
    done
    printf '%s\n' "$lines" | sed '/^$/d'
}

procs=$(git grep -nIE "$proc_re" -- 'tests/integration/*.bats' tests/e2e tests/helpers '*_test.go' | filter || true)
tmps=$(
    {
        git grep -nIE "$shm_re" -- '*_test.go' 'tests/integration/*.bats' tests/helpers || true
        git grep -nIE "$go_tmp_re" -- '*_test.go' || true
        git grep -nIE "$sh_tmp_re" -- 'tests/integration/*.bats' tests/helpers || true
    } | grep -v '/tmp/tacctl\.' | filter | sort -u || true
)

status=0
if [[ -n "$procs" ]]; then
    echo "no-shared-proc: a test names the processes of the whole machine:" >&2
    printf '%s\n' "$procs" | sed 's/^/  /' >&2
    echo "no-shared-proc: keep the pid of the process the test started, or match a name made unique by the test's directory." >&2
    status=1
fi
if [[ -n "$tmps" ]]; then
    echo "no-shared-proc: a test uses a shared temporary path:" >&2
    printf '%s\n' "$tmps" | sed 's/^/  /' >&2
    echo "no-shared-proc: use t.TempDir(), BATS_TEST_TMPDIR or the TMPDIR of the environment; a line that must name one says 'shared-proc-ok: <reason>'." >&2
    status=1
fi
exit "$status"
