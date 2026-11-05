#!/usr/bin/env bash
# gate-go.sh [-o <log>] [-t <timeout>] [--tags <tags>] [<package>...]
#
# Runs the Go tests (default ./internal/...) and ends with ONE verdict line,
# on standard output and as the last line of the log:
#
#   GATE-GO PASS|FAIL rc=<go test status> packages=<ok or no-test>/<listed>
#           failures=<FAIL and panic lines> secs=<n> skipped=<n> log=<path>
#
# skipped counts the '--- SKIP' lines of the log (go test runs with -v, the
# only way it reports a skip; a subtest counts as well as its parent). The
# names of the skipped tests (at most 20) are listed above the verdict line: a
# test that skips for a missing tool passes silently, so a green run whose
# skip count is not the expected one did not test what it should.
#
# Below the skipped names and still above the verdict line come the ten
# slowest top-level tests of the run, longest first, from the '--- PASS:
# TestX (N.NNs)' lines ('gate-go: slowest: TestX 47.1s'; a name that ran in
# several packages counts with its longest time): where the time went, and the
# input of 'tests/tools/go-test-shard.sh --regen'.
#
# A run is a PASS only when go test exited 0, every listed package printed an
# ok or no-test-files line and no FAIL or panic line is in the log. A run that
# was killed, never finished or lost a package is a FAIL, so "no verdict line"
# is never read as a pass. SIGTERM, SIGINT and SIGHUP stop the test run and
# print a FAIL verdict ("interrupted").
#
# The package tests need a session and no stdin (internal/cli): go test runs
# under setsid with standard input from /dev/null. Run this script in the
# foreground of a tool that tracks its exit status (for an agent: the Bash
# tool with run_in_background, which notifies when it exits); never with a
# trailing '&' inside another command, and never wait for it with pgrep -f
# (the pattern matches the waiting command itself).
#
# go test runs with -parallel 16 (the flag is one for the whole run, not for a
# package): the long parallel tests of internal/cli wait on timers and
# pseudo-terminals more than they use CPU, so more of them than the cores (go
# test's default) shorten the run; the other packages' parallel tests are
# short.
#
# GO names the go command (default: go on the PATH, else
# /usr/local/go/bin/go); GOCACHE defaults to a cache of the gates' own under
# ${XDG_CACHE_HOME:-~/.cache}/tacctl, on disk: /tmp may be a tmpfs, and a day of
# runs (the race and testknobs builds of gate-ci among them) grows the cache
# past 10 GiB (Go drops entries unused for five days; `rm -rf` the directory
# to clear it). Without a HOME, or when that directory cannot be written, it is
# ${TMPDIR:-/tmp}/tacctl-gate-go-cache-<uid>; 'make gate-go' may pass the
# Makefile's own. LANG is C.UTF-8. The default log is a new file under $TMPDIR.
#
# GATE_TMPFS=1 puts $TMPDIR (the tests' sandboxes, not the log) on /dev/shm for
# the run and removes it afterwards: the tests' fsync calls cost nothing there
# (the whole run takes a third of the time). It falls back to $TMPDIR when
# /dev/shm has under 2 GiB free. GOCACHE stays on disk.
# Exit status: 0 PASS, 1 FAIL, 2 usage.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2

if [[ -z "${GO:-}" ]]; then
    # As the Makefile has it: go from the PATH, else the toolchain's usual home.
    GO="$(command -v go || echo /usr/local/go/bin/go)"
fi
export LANG=C.UTF-8
if [[ -z "${GOCACHE:-}" ]]; then
    # On disk, the caller's own; the old place under TMPDIR when there is no
    # HOME, or the directory cannot be written (a root-owned one a 'sudo' run
    # with the caller's HOME left behind).
    base="${XDG_CACHE_HOME:-}"
    [[ $base == /* ]] || base="${HOME:+$HOME/.cache}"
    GOCACHE="$base/tacctl/gate-go-build"
    if [[ -z $base ]] || ! mkdir -p "$GOCACHE" 2>/dev/null || [[ ! -w $GOCACHE ]]; then
        GOCACHE="${TMPDIR:-/tmp}/tacctl-gate-go-cache-$(id -u)"
    fi
fi
export GOCACHE
logdir="${TMPDIR:-/tmp}"
if [[ "${GATE_TMPFS:-}" = 1 ]]; then
    if [[ -d /dev/shm && -w /dev/shm && "$(df -Pk /dev/shm | awk 'NR==2 {print $4}')" -ge 2097152 ]] \
        && shm="$(mktemp -d /dev/shm/tacctl-gate-go.XXXXXX)"; then
        trap 'rm -rf "$shm"' EXIT
        export TMPDIR="$shm"
    else
        echo "gate-go: GATE_TMPFS=1 ignored (no usable /dev/shm with 2 GiB free)" >&2
    fi
fi

log="" timeout="40m" tags=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) log="${2:-}"; shift 2 || exit 2 ;;
        -t) timeout="${2:-}"; shift 2 || exit 2 ;;
        --tags) tags="${2:-}"; shift 2 || exit 2 ;;
        -h | --help) sed -n '2,/^set -/p' "$0" | sed '$d;s/^# \{0,1\}//' ; exit 0 ;;
        --) shift; break ;;
        -*) echo "gate-go: unknown option $1" >&2; exit 2 ;;
        *) break ;;
    esac
done
pkgs=("$@")
[[ ${#pkgs[@]} -gt 0 ]] || pkgs=(./internal/...)
[[ -n "$log" ]] || log="$(mktemp "$logdir/tacctl-gate-go.XXXXXX.log")" || exit 2
: >"$log" || { echo "gate-go: cannot write $log" >&2; exit 2; }

tagflag=()
[[ -z "$tags" ]] || tagflag=(-tags "$tags")

want=$("$GO" list "${tagflag[@]}" "${pkgs[@]}" 2>/dev/null | wc -l)
start=$(date +%s)
child=""

verdict() { # <rc> <note>
    local rc=$1 note=${2:-} got bad v secs skipped names n max=20
    got=$(grep -cE '^(ok|\?)[[:space:]]' "$log")
    bad=$(grep -cE '^(FAIL|--- FAIL|panic:)' "$log")
    secs=$(($(date +%s) - start))
    skipped=$(grep -cE '^[[:space:]]*--- SKIP: ' "$log")
    if [[ "$skipped" -gt 0 ]]; then
        names=$(sed -n 's/^[[:space:]]*--- SKIP: \([^ ]*\).*/\1/p' "$log" | sort -u)
        n=$(grep -c . <<<"$names")
        head -n "$max" <<<"$names" | sed 's/^/gate-go: skipped: /' | tee -a "$log"
        if [[ "$n" -gt "$max" ]]; then
            echo "gate-go: skipped: +$((n - max)) more" | tee -a "$log"
        fi
    fi
    # The ten slowest top-level tests, from the '--- PASS: TestX (N.NNs)' lines
    # (a name that ran in several packages counts with its longest time).
    awk '/^--- PASS: Test/ {
            d = $4; gsub(/[()s]/, "", d)
            if (d ~ /^[0-9]+(\.[0-9]+)?$/ && (!($3 in m) || d + 0 > m[$3] + 0)) m[$3] = d
        }
        END { for (t in m) printf "%s %s\n", m[t], t }' "$log" |
        sort -k1,1nr -k2,2 | head -n 10 |
        awk '{ printf "gate-go: slowest: %s %.1fs\n", $2, $1 }' | tee -a "$log"
    v=FAIL
    if [[ "$rc" -eq 0 && "$got" -eq "$want" && "$want" -gt 0 && "$bad" -eq 0 && -z "$note" ]]; then v=PASS; fi
    echo "GATE-GO $v rc=$rc packages=$got/$want failures=$bad secs=$secs skipped=$skipped${note:+ $note} log=$log" | tee -a "$log"
    [[ "$v" = PASS ]]
}

# shellcheck disable=SC2317,SC2329  # called through the trap
interrupted() {
    if [[ -n "$child" ]]; then
        kill -TERM -- "-$child" 2>/dev/null || kill -TERM "$child" 2>/dev/null
        wait "$child" 2>/dev/null
    fi
    verdict 130 interrupted
    exit 130
}
trap interrupted TERM INT HUP

setsid "$GO" test -v -parallel 16 -timeout "$timeout" "${tagflag[@]}" "${pkgs[@]}" </dev/null >"$log" 2>&1 &
child=$!
wait "$child"
rc=$?
trap - TERM INT HUP
verdict "$rc" "" && exit 0
exit 1
