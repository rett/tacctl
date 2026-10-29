#!/usr/bin/env bash
# gate-ci.sh [-o <log>] [-t <timeout>]
#
# Runs the Go tests the way the 'test' workflow (.github/workflows/test.yml)
# runs them, and ends with ONE verdict line, on standard output and as the
# last line of the log:
#
#   GATE-CI PASS|FAIL rc=<first failing go test status> jobs=<passed>/<all>
#           failures=<failing tests> races=<data races> secs=<n>
#           [failed=<job>:<test>,...] log=<path>
#
# 'make gate-go' runs ./internal/... once, without the race detector and
# without the test knobs; this runs what CI runs, so a data race or a test
# that exists only with '-tags testknobs' fails here and not on the pull
# request:
#
#   other, other/testknobs  every package but internal/cli, in one go test
#                           with -race, without and with -tags testknobs
#   cli<i>, cli<i>/testknobs  shard <i> of the two shards of internal/cli
#                           (tests/tools/go-test-shard.sh <i> 2), as CI has
#                           them: the run without tags with -race, the one
#                           with the test knobs without it
#
# The shard check ('go-test-shard.sh --check 2', the static job of CI) runs
# first: a test that no shard holds fails the run before any test runs.
# Every job runs, whatever the one before it did, so one run lists every
# failure; the failed= list names each failing test (or package, when no
# test failed) with its job. A job is a pass only when go test exited 0,
# printed an ok or no-test line for every package it was given and no FAIL,
# panic or DATA RACE line is in its output. A run that was killed or never
# finished is a FAIL, so "no verdict line" is never read as a pass. SIGTERM,
# SIGINT and SIGHUP stop the run and print a FAIL verdict ("interrupted").
#
# It needs cgo (a C compiler) for -race, and it takes a long time (the
# package tests of CI added up: several times the 'make gate-go' run). The
# tests need a session and no stdin: go test runs under setsid with standard
# input from /dev/null. Run the script in the foreground of a tool that
# tracks its exit status (for an agent: the Bash tool with
# run_in_background, which notifies when it exits); never with a trailing '&'
# inside another command, and never wait for it with pgrep -f.
#
# -t is the go test timeout of every job (default 40m; CI uses the go test
# default of 10m per package, so a slow machine does not fail here for time).
# GO names the go command (default: go on the PATH, else
# /usr/local/go/bin/go); GOCACHE defaults to the cache 'make gate-go' uses; LANG
# is C.UTF-8; a GOFLAGS of the caller is not passed on. GATE_TMPFS=1 puts
# $TMPDIR (the tests' sandboxes, not the log) on /dev/shm for the run, as
# gate-go.sh does. The number of shards and the tag sets are the ones of the
# workflow; the script stops with status 2 when the workflow no longer says
# 'shard: [0, 1]'.
# Exit status: 0 PASS, 1 FAIL, 2 usage.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2

if [[ -z "${GO:-}" ]]; then
    GO="$(command -v go || echo /usr/local/go/bin/go)"
fi
export GO
export LANG=C.UTF-8
export GOCACHE="${GOCACHE:-${TMPDIR:-/tmp}/tacctl-gate-go-cache-$(id -u)}"
logdir="${TMPDIR:-/tmp}"
if [[ "${GATE_TMPFS:-}" = 1 ]]; then
    if [[ -d /dev/shm && -w /dev/shm && "$(df -Pk /dev/shm | awk 'NR==2 {print $4}')" -ge 2097152 ]] \
        && shm="$(mktemp -d /dev/shm/tacctl-gate-ci.XXXXXX)"; then
        trap 'rm -rf "$shm"' EXIT
        export TMPDIR="$shm"
    else
        echo "gate-ci: GATE_TMPFS=1 ignored (no usable /dev/shm with 2 GiB free)" >&2
    fi
fi

log="" timeout="40m"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) log="${2:-}"; shift 2 || exit 2 ;;
        -t) timeout="${2:-}"; shift 2 || exit 2 ;;
        -h | --help) sed -n '2,/^set -/p' "$0" | sed '$d;s/^# \{0,1\}//' ; exit 0 ;;
        -*) echo "gate-ci: unknown option $1" >&2; exit 2 ;;
        *) echo "gate-ci: no argument is taken: $1" >&2; exit 2 ;;
    esac
done
[[ -n "$log" ]] || log="$(mktemp "$logdir/tacctl-gate-ci.XXXXXX.log")" || exit 2
: >"$log" || { echo "gate-ci: cannot write $log" >&2; exit 2; }

# What the workflow has: shard: [0, 1] and tags: ["", testknobs].
shards=2
tagsets=("" testknobs)
wf=.github/workflows/test.yml
if ! grep -qE '^[[:space:]]+shard: \[0, 1\]$' "$wf" 2>/dev/null \
    || ! grep -qE '^[[:space:]]+tags: \["", testknobs\]$' "$wf" 2>/dev/null; then
    echo "gate-ci: out of step with $wf (shard: [0, 1], tags: [\"\", testknobs])" >&2
    exit 2
fi

start=$(date +%s)
child=""
total=$((${#tagsets[@]} * (1 + shards)))
passed=0 failures=0 races=0 firstrc=0 ran=0
failed=()

say() { echo "$*" | tee -a "$log"; }

# job <label> <packages wanted> <command>...: runs the command with its
# output appended to the log, then judges that part of the log.
job() {
    local label=$1 want=$2 from got bad race rc jstart names pkgs n
    shift 2
    from=$(wc -l <"$log")
    jstart=$(date +%s)
    echo "=== $label: $*" >>"$log"
    "$@" </dev/null >>"$log" 2>&1 &
    child=$!
    wait "$child"
    rc=$?
    child=""
    ran=$((ran + 1))
    local out
    out=$(tail -n +"$((from + 2))" "$log")
    got=$(grep -cE '^(ok|\?)[[:space:]]' <<<"$out")
    bad=$(grep -cE '^(FAIL|--- FAIL|panic:)' <<<"$out")
    race=$(grep -c 'WARNING: DATA RACE' <<<"$out")
    races=$((races + race))
    if [[ "$rc" -eq 0 && "$got" -eq "$want" && "$want" -gt 0 && "$bad" -eq 0 && "$race" -eq 0 ]]; then
        passed=$((passed + 1))
        say "gate-ci: $label ok ($(($(date +%s) - jstart)) s)"
        return 0
    fi
    [[ "$firstrc" -ne 0 || "$rc" -eq 0 ]] || firstrc=$rc
    names=$(sed -n 's/^--- FAIL: \([^ ]*\).*/\1/p' <<<"$out" | sort -u)
    if [[ -z "$names" ]]; then
        # No failing test: a build failure, a timeout, a lost package.
        pkgs=$(sed -n 's/^FAIL[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p' <<<"$out" | sort -u)
        names=${pkgs:-"rc=$rc packages=$got/$want"}
    fi
    n=0
    while IFS= read -r name; do
        failed+=("$label:$name")
        n=$((n + 1))
    done <<<"$names"
    failures=$((failures + n))
    say "gate-ci: $label FAIL rc=$rc packages=$got/$want failing=$n ($(($(date +%s) - jstart)) s)"
    return 1
}

verdict() { # <note>
    local note=${1:-} v=FAIL secs list max=20
    secs=$(($(date +%s) - start))
    if [[ "$passed" -eq "$total" && "$failures" -eq 0 && "$races" -eq 0 && -z "$note" ]]; then v=PASS; fi
    list=""
    if [[ ${#failed[@]} -gt 0 ]]; then
        list=$(IFS=,; echo "${failed[*]:0:max}")
        [[ ${#failed[@]} -le $max ]] || list+=",+$((${#failed[@]} - max)) more"
    fi
    echo "GATE-CI $v rc=$firstrc jobs=$passed/$total failures=$failures races=$races secs=$secs${note:+ $note}${list:+ failed=$list} log=$log" | tee -a "$log"
    [[ "$v" = PASS ]]
}

# shellcheck disable=SC2317  # called through the trap
interrupted() {
    if [[ -n "$child" ]]; then
        kill -TERM -- "-$child" 2>/dev/null || kill -TERM "$child" 2>/dev/null
        wait "$child" 2>/dev/null
    fi
    [[ "$firstrc" -ne 0 ]] || firstrc=130
    verdict interrupted
    exit 130
}
trap interrupted TERM INT HUP

say "gate-ci: $total jobs, go $("$GO" env GOVERSION 2>/dev/null), log $log"

# The static job's shard check; with it failing no test runs.
if ! check=$(tests/tools/go-test-shard.sh --check "$shards" 2>&1); then
    echo "$check" >>"$log"
    firstrc=1 failures=1 failed=("shard-check:$(tail -n 1 <<<"$check")")
    say "gate-ci: shard check FAIL"
    verdict "" && exit 0
    exit 1
fi
say "gate-ci: $check"

for tags in "${tagsets[@]}"; do
    suffix="" cgo=(env CGO_ENABLED=1)
    [[ -z "$tags" ]] || suffix="/$tags"

    # Every package but internal/cli, with the race detector.
    pkgs=$(GOFLAGS="" "$GO" list -tags "$tags" ./... 2>/dev/null | grep -v '/internal/cli$')
    want=$(grep -c . <<<"$pkgs")
    # shellcheck disable=SC2086  # one word per package
    job "other$suffix" "$want" "${cgo[@]}" GOFLAGS="" setsid "$GO" test -timeout "$timeout" -race -tags "$tags" $pkgs

    # internal/cli, in shards: -race without tags, the test knobs without it.
    flags=-race
    [[ -z "$tags" ]] || flags="-tags=$tags"
    for ((i = 0; i < shards; i++)); do
        job "cli$i$suffix" 1 "${cgo[@]}" GOFLAGS="$flags" tests/tools/go-test-shard.sh "$i" "$shards" -timeout "$timeout"
    done
done

trap - TERM INT HUP
verdict "" && exit 0
exit 1
