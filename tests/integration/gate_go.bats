#!/usr/bin/env bats
# tests/tools/gate-go.sh: the one verdict line a long Go test run ends with.
# A stub `go` stands in for the toolchain, so nothing here depends on the Go
# tests themselves.

bats_require_minimum_version 1.5.0

setup() {
    GATE="$BATS_TEST_DIRNAME/../tools/gate-go.sh"
    STUB="$BATS_TEST_TMPDIR/go"
    cat >"$STUB" <<'SH'
#!/bin/bash
case "$1" in
list) printf 'p/a\np/b\n' ;;
test) case "$STUB_MODE" in
    ok) printf 'ok  \tp/a\t0.1s\n?   \tp/b\t[no test files]\n' ;;
    lost) printf 'ok  \tp/a\t0.1s\n' ;;
    fail) printf -- '--- FAIL: TestX\nFAIL\tp/a\t0.1s\nok  \tp/b\t0.1s\n'; exit 1 ;;
    skip) printf -- '--- SKIP: TestY (0.00s)\n    --- SKIP: TestZ/sub (0.00s)\nok  \tp/a\t0.1s\n?   \tp/b\t[no test files]\n' ;;
    skipmany) for i in $(seq -w 25); do printf -- '--- SKIP: TestS%s (0.00s)\n' "$i"; done
        printf 'ok  \tp/a\t0.1s\n?   \tp/b\t[no test files]\n' ;;
    slow) printf -- '--- PASS: TestFast (0.01s)\n--- PASS: TestSlow (47.12s)\n    --- PASS: TestSlow/sub (60.00s)\n--- SKIP: TestY (0.00s)\n--- PASS: TestMid (3.50s)\n--- PASS: TestSlow (5.00s)\n'
        printf 'ok  \tp/a\t0.1s\n?   \tp/b\t[no test files]\n' ;;
    slowmany) for i in $(seq 12); do printf -- '--- PASS: TestT%02d (%d.00s)\n' "$i" "$i"; done
        printf 'ok  \tp/a\t0.1s\n?   \tp/b\t[no test files]\n' ;;
    failsub) printf -- '=== RUN   TestB\n--- FAIL: TestB (0.00s)\n    --- FAIL: TestB/sub (0.00s)\n--- FAIL: TestA (0.00s)\nFAIL\tp/a\t0.1s\n'
        printf -- '--- FAIL: TestB (0.00s)\nFAIL\tp/b\t0.1s\n'; exit 1 ;;
    failmany) for i in $(seq -w 12); do printf -- '--- FAIL: TestF%s (0.00s)\n' "$i"; done
        printf 'FAIL\tp/a\t0.1s\nok  \tp/b\t0.1s\n'; exit 1 ;;
    failslow) printf -- '--- SKIP: TestY (0.00s)\n--- PASS: TestSlow (47.12s)\n--- FAIL: TestX (0.00s)\nFAIL\tp/a\t0.1s\nok  \tp/b\t0.1s\n'; exit 1 ;;
    mixed) printf -- '--- FAIL: TestX (0.00s)\nFAIL\tp/a\t0.1s\nFAIL\tp/b [build failed]\n'; exit 1 ;;
    build) printf 'FAIL\tp/a [build failed]\nok  \tp/b\t0.1s\n'; exit 1 ;;
    panic) printf 'panic: boom [recovered]\nFAIL\tp/a\t0.1s\nFAIL\tp/b\t0.1s\nFAIL\n'; exit 1 ;;
    hang) exec sleep 30 ;;
    tmp) printf '%s\n' "$TMPDIR" >"$STUB_TMP_OUT"; printf 'ok  \tp/a\t0.1s\n?   \tp/b\t[no test files]\n' ;;
    args) printf '%s\n' "$*" >"$STUB_ARGS_OUT"; printf 'ok  \tp/a\t0.1s\n?   \tp/b\t[no test files]\n' ;;
    esac ;;
esac
SH
    chmod +x "$STUB"
    mkdir -p "$BATS_TEST_TMPDIR/bin"
    cat >"$BATS_TEST_TMPDIR/bin/make" <<'SH'
#!/bin/bash
# STUB_LINT: ok (the default) | fail (a finding, as golangci-lint prints it)
echo "make $*" >>"$MAKE_CALLS"
if [[ "${STUB_LINT:-ok}" = fail ]]; then
    printf "internal/x/x.go:12:5: QF1001: could apply De Morgan's law (staticcheck)\n1 issues:\nmake: *** [Makefile:225: lint-go] Error 1\n"
    exit 2
fi
SH
    chmod +x "$BATS_TEST_TMPDIR/bin/make"
    export PATH="$BATS_TEST_TMPDIR/bin:$PATH" MAKE_CALLS="$BATS_TEST_TMPDIR/make-calls"
    export GO="$STUB" GOCACHE="$BATS_TEST_TMPDIR/cache" LOG="$BATS_TEST_TMPDIR/gate.log"
}

# The `sleep` the hanging stub go has become, among the processes below pid $1
# (children, their children, ...): only the gate's own tree is looked at, so a
# `sleep 30` of another test running at the same time (bats --jobs) is no match.
sleeper_below() {
    local p
    for p in $(pgrep -P "$1"); do
        if [[ "$(ps -o comm= -p "$p")" == sleep ]]; then
            echo "$p"
            return 0
        fi
        sleeper_below "$p" && return 0
    done
    return 1
}

@test "every package ok or without tests is a PASS, the last line of stdout and of the log" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO PASS rc=0 packages=2/2 failures=0 secs="*" log=$LOG" ]]
    [[ "$(tail -n 1 "$LOG")" == "${lines[-1]}" ]]
}

@test "a run without a skipped test says skipped=0 and lists no names" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == *" skipped=0 log=$LOG" ]]
    [[ "$output" != *"gate-go: skipped:"* ]]
}

@test "skipped tests and subtests are counted and named above the PASS verdict, which stays the last line" {
    STUB_MODE=skip run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO PASS rc=0 packages=2/2 failures=0 secs="*" skipped=2 log=$LOG" ]]
    [[ "${lines[-2]}" == "gate-go: skipped: TestZ/sub" ]]
    [[ "${lines[-3]}" == "gate-go: skipped: TestY" ]]
    # the log ends the same way
    [[ "$(tail -n 1 "$LOG")" == "${lines[-1]}" ]]
    [[ "$(tail -n 3 "$LOG" | head -n 2)" == $'gate-go: skipped: TestY\ngate-go: skipped: TestZ/sub' ]]
}

@test "more than 20 skipped names list the first 20 and a +N more line, the count stays exact" {
    STUB_MODE=skipmany run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO PASS "*" skipped=25 log=$LOG" ]]
    [[ "${lines[-2]}" == "gate-go: skipped: +5 more" ]]
    [[ "${lines[-3]}" == "gate-go: skipped: TestS20" ]]
    [[ "$(printf '%s\n' "${lines[@]}" | grep -c '^gate-go: skipped: TestS')" -eq 20 ]]
    [[ "$output" != *"TestS21"* ]]
}

@test "the ten slowest top-level tests are listed above the verdict, below the skipped names, longest first" {
    STUB_MODE=slow run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO PASS rc=0 packages=2/2 failures=0 secs="*" skipped=1 log=$LOG" ]]
    # a subtest is not listed, a name seen twice counts with its longest time
    [[ "${lines[-2]}" == "gate-go: slowest: TestFast 0.0s" ]]
    [[ "${lines[-3]}" == "gate-go: slowest: TestMid 3.5s" ]]
    [[ "${lines[-4]}" == "gate-go: slowest: TestSlow 47.1s" ]]
    [[ "${lines[-5]}" == "gate-go: skipped: TestY" ]]
    [[ "$output" != *"TestSlow/sub"* ]]
    # the log ends the same way
    [[ "$(tail -n 1 "$LOG")" == "${lines[-1]}" ]]
    [[ "$(tail -n 5 "$LOG" | head -n 4)" == "$(printf '%s\n' "${lines[@]: -5:4}")" ]]
}

@test "no more than ten slowest tests are listed" {
    STUB_MODE=slowmany run -0 "$GATE" -o "$LOG"
    [[ "$(printf '%s\n' "${lines[@]}" | grep -c '^gate-go: slowest:')" -eq 10 ]]
    [[ "${lines[-11]}" == "gate-go: slowest: TestT12 12.0s" ]]
    [[ "${lines[-2]}" == "gate-go: slowest: TestT03 3.0s" ]]
    [[ "$output" != *"TestT02"* ]]
}

@test "a run without a passing test lists no slowest tests" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "$output" != *"gate-go: slowest:"* ]]
}

@test "a package that printed nothing is a FAIL although go test exited 0" {
    STUB_MODE=lost run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=0 packages=1/2 "* ]]
}

@test "a failing test is a FAIL with its status and failure lines" {
    STUB_MODE=fail run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=1 packages=1/2 failures=2 "* ]]
}

@test "a failing test is named in a FAIL: line above the FAIL verdict, which stays the last line" {
    STUB_MODE=fail run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=1 "* ]]
    [[ "${lines[-2]}" == "FAIL: TestX" ]]
    [[ "$(printf '%s\n' "${lines[@]}" | grep -c '^FAIL: ')" -eq 1 ]]
    # the log ends the same way
    [[ "$(tail -n 1 "$LOG")" == "${lines[-1]}" ]]
    [[ "$(tail -n 2 "$LOG" | head -n 1)" == "FAIL: TestX" ]]
}

@test "failing tests and subtests are each named once, in the order of the log" {
    STUB_MODE=failsub run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=1 packages=0/2 failures=5 "* ]]
    [[ "${lines[-2]}" == "FAIL: TestA" ]]
    [[ "${lines[-3]}" == "FAIL: TestB/sub" ]]
    [[ "${lines[-4]}" == "FAIL: TestB" ]]
    [[ "$(printf '%s\n' "${lines[@]}" | grep -c '^FAIL: ')" -eq 3 ]]
    # a package that has a failing test is not named
    [[ "$output" != *"FAIL: p/a"* ]]
}

@test "the failing tests come below the skipped names and the slowest tests, right above the verdict" {
    STUB_MODE=failslow run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL "*" skipped=1 log=$LOG" ]]
    [[ "${lines[-2]}" == "FAIL: TestX" ]]
    [[ "${lines[-3]}" == "gate-go: slowest: TestSlow 47.1s" ]]
    [[ "${lines[-4]}" == "gate-go: skipped: TestY" ]]
}

@test "no more than ten failing tests are named, the failures= count stays exact" {
    STUB_MODE=failmany run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=1 packages=1/2 failures=13 "* ]]
    [[ "$(printf '%s\n' "${lines[@]}" | grep -c '^FAIL: ')" -eq 10 ]]
    [[ "${lines[-2]}" == "FAIL: TestF10" ]]
    [[ "${lines[-11]}" == "FAIL: TestF01" ]]
    [[ "$output" != *"FAIL: TestF11"* ]]
}

@test "a package that failed to build or panicked, with no failing test, is named by its FAIL line" {
    STUB_MODE=build run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=1 packages=1/2 failures=1 "* ]]
    [[ "${lines[-2]}" == "FAIL: p/a" ]]
    STUB_MODE=panic run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=1 packages=0/2 failures=4 "* ]]
    [[ "${lines[-2]}" == "FAIL: p/b" ]]
    [[ "${lines[-3]}" == "FAIL: p/a" ]]
    [[ "$(printf '%s\n' "${lines[@]}" | grep -c '^FAIL: ')" -eq 2 ]]
}

@test "a failing test and a package that failed to build: only the test is named, the build failure is counted" {
    STUB_MODE=mixed run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=1 packages=0/2 failures=3 "* ]]
    [[ "${lines[-2]}" == "FAIL: TestX" ]]
    [[ "$(printf '%s\n' "${lines[@]}" | grep -c '^FAIL: ')" -eq 1 ]]
    [[ "$output" != *"FAIL: p/b"* ]]
    # the build failure is in the log
    grep -q '^FAIL	p/b \[build failed\]' "$LOG"
}

@test "a PASS names no failing test" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "$output" != *"FAIL: "* ]]
}

@test "SIGTERM stops the run, reaps go and prints a FAIL verdict" {
    STUB_MODE=hang "$GATE" -o "$LOG" >"$BATS_TEST_TMPDIR/out" 2>&1 &
    pid=$!
    sleeper=""
    for _ in $(seq 50); do sleeper=$(sleeper_below "$pid") && break; sleep 0.1; done
    [[ -n "$sleeper" ]]
    kill -TERM "$pid"
    rc=0
    wait "$pid" || rc=$?
    [ "$rc" -eq 130 ]
    grep -q '^GATE-GO FAIL rc=130 .* interrupted log=' "$BATS_TEST_TMPDIR/out"
    # the go the gate started is gone (not any `sleep 30` on the machine)
    run ! kill -0 "$sleeper"
}

@test "a usage error is status 2 and no verdict" {
    run -2 "$GATE" --bogus
    [[ "$output" != *GATE-GO* ]]
}

@test "GATE_TMPFS=1 runs the tests with TMPDIR on the shared-memory tmpfs and removes it, the log stays where it was" {
    [[ -d /dev/shm && -w /dev/shm ]] || skip "no writable /dev/shm" # shared-proc-ok: GATE_TMPFS is about /dev/shm
    export STUB_TMP_OUT="$BATS_TEST_TMPDIR/tmpdir"
    STUB_MODE=tmp GATE_TMPFS=1 run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO PASS "*" log=$LOG" ]]
    [[ "$(cat "$STUB_TMP_OUT")" == /dev/shm/tacctl-gate-go.* ]] # shared-proc-ok: GATE_TMPFS is about /dev/shm
    [[ ! -e "$(cat "$STUB_TMP_OUT")" ]]
}

@test "without GATE_TMPFS the tests keep the caller's TMPDIR" {
    export STUB_TMP_OUT="$BATS_TEST_TMPDIR/tmpdir"
    STUB_MODE=tmp TMPDIR="$BATS_TEST_TMPDIR" run -0 "$GATE" -o "$LOG"
    [[ "$(cat "$STUB_TMP_OUT")" == "$BATS_TEST_TMPDIR" ]]
}

@test "go test runs with -parallel 16 for the whole run" {
    export STUB_ARGS_OUT="$BATS_TEST_TMPDIR/args"
    STUB_MODE=args run -0 "$GATE" -o "$LOG"
    [[ "$(cat "$STUB_ARGS_OUT")" == "test -v -parallel 16 -timeout 40m ./internal/..." ]]
}

@test "a run of the whole suite runs make lint-go once before the tests" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "$(cat "$MAKE_CALLS")" == "make lint-go" ]]
    [[ "$output" == *"gate-go: lint ok ("*" s)"* ]]
    [[ "${lines[-1]}" == "GATE-GO PASS rc=0 packages=2/2 failures=0 secs="*" log=$LOG" ]]
}

@test "a lint finding fails the run before any test runs, with its output in the log and the verdict line" {
    STUB_LINT=fail STUB_MODE=ok run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=2 packages=0/2 failures=0 secs="*" skipped=0 lint-failed log=$LOG" ]]
    [[ "$output" == *"gate-go: lint: internal/x/x.go:12:5: QF1001"* ]]
    grep -q 'QF1001' "$LOG"
    ! grep -q $'^ok  \tp/a' "$LOG"
}

@test "--no-lint, a package list and --tags leave the lint out" {
    STUB_MODE=args STUB_ARGS_OUT="$BATS_TEST_TMPDIR/args" run -0 "$GATE" -o "$LOG" --no-lint
    [[ ! -e "$MAKE_CALLS" ]]
    STUB_MODE=args STUB_ARGS_OUT="$BATS_TEST_TMPDIR/args" run -0 "$GATE" -o "$LOG" p/a
    [[ ! -e "$MAKE_CALLS" ]]
    STUB_MODE=args STUB_ARGS_OUT="$BATS_TEST_TMPDIR/args" run -0 "$GATE" -o "$LOG" --tags testknobs
    [[ ! -e "$MAKE_CALLS" ]]
}
