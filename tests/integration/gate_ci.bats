#!/usr/bin/env bats
# tests/tools/gate-ci.sh: the one verdict line the CI-equivalent Go test run
# ends with. A stub `go` stands in for the toolchain, so nothing here depends
# on the Go tests themselves.

bats_require_minimum_version 1.5.0

setup() {
    GATE="$BATS_TEST_DIRNAME/../tools/gate-ci.sh"
    STUB="$BATS_TEST_TMPDIR/go"
    cat >"$STUB" <<'SH'
#!/bin/bash
# STUB_MODE: ok | race (a data race in the other packages, with -race only) |
# knobs (a test that fails only with -tags testknobs, in shard 1) | lost |
# build (a package that does not build) | skip (two skipped tests in the
# other packages, in both tag runs) | slow (passing tests with durations, a
# skipped one) | slowmany (twelve passing tests in the other packages) | hang
tagged=0
case " $* $GOFLAGS " in *" -tags testknobs "* | *" -tags=testknobs "*) tagged=1 ;; esac
raced=0
case " $* $GOFLAGS " in *" -race "*) raced=1 ;; esac
case "$1" in
env) echo go1.27.0 ;;
list) printf 'p/a\np/b\np/internal/cli\n' ;;
test)
    case " $* " in
    *" -list "*) printf 'TestA\nTestB\nTestC\nTestD\nok  \tp/internal/cli\t0.1s\n'; exit 0 ;;
    esac
    [[ "$STUB_MODE" != hang ]] || exec sleep 30
    par=0
    case " $* " in *" -parallel 16 "*) par=1 ;; esac
    echo "flags: race=$raced tags=$tagged env-flags=$GOFLAGS cgo=$CGO_ENABLED parallel16=$par" >>"$STUB_CALLS"
    case " $* " in
    *" p/a p/b "*)
        case "$STUB_MODE" in
        race) if [[ $raced = 1 ]]; then
                printf 'WARNING: DATA RACE\n--- FAIL: TestRacy (0.00s)\nFAIL\tp/a\t0.1s\nok  \tp/b\t0.1s\n'; exit 1; fi ;;
        build) printf 'FAIL\tp/a [build failed]\nok  \tp/b\t0.1s\n'; exit 1 ;;
        lost) printf 'ok  \tp/a\t0.1s\n'; exit 0 ;;
        skip) printf -- '--- SKIP: TestY (0.00s)\n    --- SKIP: TestZ/sub (0.00s)\n' ;;
        slow) printf -- '--- SKIP: TestY (0.00s)\n--- PASS: TestO (%s)\n' "$([[ $tagged = 1 ]] && echo 15.00s || echo 12.34s)" ;;
        slowmany) for i in $(seq 12); do printf -- '--- PASS: TestT%02d (%d.00s)\n' "$i" "$i"; done ;;
        esac
        printf 'ok  \tp/a\t0.1s\nok  \tp/b\t0.1s\n' ;;
    *)
        if [[ "$STUB_MODE" = slow ]]; then
            case " $* " in *TestA*) echo '--- PASS: TestA (1.50s)' ;; esac
            case " $* " in *TestB*) [[ $tagged = 1 ]] && echo '--- PASS: TestB (70.00s)' || echo '--- PASS: TestB (83.00s)' ;; esac
        fi
        if [[ "$STUB_MODE" = knobs && $tagged = 1 && " $* " == *"TestB"* ]]; then
            printf -- '--- FAIL: TestB (0.00s)\nFAIL\tp/internal/cli\t0.1s\n'; exit 1
        fi
        printf 'ok  \tp/internal/cli\t0.1s\n' ;;
    esac ;;
esac
SH
    chmod +x "$STUB"
    export GO="$STUB" GOCACHE="$BATS_TEST_TMPDIR/cache" LOG="$BATS_TEST_TMPDIR/gate.log"
    export STUB_CALLS="$BATS_TEST_TMPDIR/calls"
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

@test "six jobs ok is a PASS, the last line of stdout and of the log" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-CI PASS rc=0 jobs=6/6 failures=0 races=0 secs="*" log=$LOG" ]]
    [[ "$(tail -n 1 "$LOG")" == "${lines[-1]}" ]]
}

@test "a run without a skipped test says skipped=0 and lists no names" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == *" skipped=0 log=$LOG" ]]
    [[ "$output" != *"gate-ci: skipped:"* ]]
}

@test "a test skipped in two jobs is counted once per job and listed once, above the PASS verdict" {
    # TestY and TestZ/sub skip in other and in other/testknobs: four SKIP lines, two names
    STUB_MODE=skip run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-CI PASS rc=0 jobs=6/6 failures=0 races=0 secs="*" skipped=4 log=$LOG" ]]
    [[ "${lines[-2]}" == "gate-ci: skipped: TestZ/sub" ]]
    [[ "${lines[-3]}" == "gate-ci: skipped: TestY" ]]
    [[ "$(printf '%s\n' "${lines[@]}" | grep -c '^gate-ci: skipped:')" -eq 2 ]]
    [[ "$(tail -n 1 "$LOG")" == "${lines[-1]}" ]]
}

@test "the ten slowest top-level tests are listed with their job above the verdict, below the skipped names" {
    # TestO is slower in the knobs run of the other packages, TestB in the untagged shard 1
    STUB_MODE=slow run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-CI PASS rc=0 jobs=6/6 failures=0 races=0 secs="*" skipped=2 log=$LOG" ]]
    [[ "${lines[-2]}" == "gate-ci: slowest: TestA 1.5s (cli0)" ]]
    [[ "${lines[-3]}" == "gate-ci: slowest: TestO 15.0s (other/testknobs)" ]]
    [[ "${lines[-4]}" == "gate-ci: slowest: TestB 83.0s (cli1)" ]]
    [[ "${lines[-5]}" == "gate-ci: skipped: TestY" ]]
    # the log ends the same way
    [[ "$(tail -n 1 "$LOG")" == "${lines[-1]}" ]]
    [[ "$(tail -n 5 "$LOG" | head -n 4)" == "$(printf '%s\n' "${lines[@]: -5:4}")" ]]
}

@test "no more than ten slowest tests are listed" {
    STUB_MODE=slowmany run -0 "$GATE" -o "$LOG"
    [[ "$(printf '%s\n' "${lines[@]}" | grep -c '^gate-ci: slowest:')" -eq 10 ]]
    [[ "${lines[-11]}" == "gate-ci: slowest: TestT12 12.0s (other)" ]]
    [[ "${lines[-2]}" == "gate-ci: slowest: TestT03 3.0s (other)" ]]
    [[ "$output" != *"TestT02"* ]]
}

@test "a run without a passing test lists no slowest tests" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "$output" != *"gate-ci: slowest:"* ]]
}

@test "the race detector and cgo are on for the other packages and the untagged shards, the knobs run has no -race; the shards run with -parallel 16" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    # untagged: the other packages, the two shards; then the same with the knobs
    mapfile -t calls <"$STUB_CALLS"
    [[ "${#calls[@]}" -eq 6 ]]
    [[ "${calls[0]}" == "flags: race=1 tags=0 env-flags= cgo=1 parallel16=0" ]]
    [[ "${calls[1]}" == "flags: race=1 tags=0 env-flags=-race cgo=1 parallel16=1" ]]
    [[ "${calls[2]}" == "flags: race=1 tags=0 env-flags=-race cgo=1 parallel16=1" ]]
    [[ "${calls[3]}" == "flags: race=1 tags=1 env-flags= cgo=1 parallel16=0" ]]
    [[ "${calls[4]}" == "flags: race=0 tags=1 env-flags=-tags=testknobs cgo=1 parallel16=1" ]]
    [[ "${calls[5]}" == "flags: race=0 tags=1 env-flags=-tags=testknobs cgo=1 parallel16=1" ]]
}

@test "a data race fails both tag runs of the other packages, named, and the other jobs still run" {
    STUB_MODE=race run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-CI FAIL rc=1 jobs=4/6 failures=2 races=2 secs="*" failed=other:TestRacy,other/testknobs:TestRacy log=$LOG" ]]
    [[ "$(wc -l <"$STUB_CALLS")" -eq 6 ]]
}

@test "a test that fails only with the test knobs is named with its shard" {
    STUB_MODE=knobs run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-CI FAIL rc=1 jobs=5/6 failures=1 races=0 secs="*" failed=cli1/testknobs:TestB log=$LOG" ]]
}

@test "a package that does not build is named by its package" {
    STUB_MODE=build run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-CI FAIL rc=1 jobs=4/6 failures=2 races=0 secs="*" failed=other:p/a,other/testknobs:p/a log=$LOG" ]]
}

@test "a package that printed nothing is a FAIL although go test exited 0" {
    STUB_MODE=lost run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-CI FAIL rc=0 jobs=4/6 failures=2 "*"failed=other:rc=0 packages=1/2,other/testknobs:rc=0 packages=1/2 log=$LOG" ]]
}

@test "SIGTERM stops the run, reaps go and prints a FAIL verdict" {
    STUB_MODE=hang "$GATE" -o "$LOG" >"$BATS_TEST_TMPDIR/out" 2>&1 &
    pid=$!
    sleeper=""
    for _ in $(seq 100); do sleeper=$(sleeper_below "$pid") && break; sleep 0.1; done
    [[ -n "$sleeper" ]]
    kill -TERM "$pid"
    rc=0
    wait "$pid" || rc=$?
    [ "$rc" -eq 130 ]
    grep -q '^GATE-CI FAIL rc=130 .* interrupted .*log=' "$BATS_TEST_TMPDIR/out"
    # the go the gate started is gone (not any `sleep 30` on the machine)
    run ! kill -0 "$sleeper"
}

@test "a usage error is status 2 and no verdict" {
    run -2 "$GATE" --bogus
    [[ "$output" != *GATE-CI* ]]
    run -2 "$GATE" p/a
    [[ "$output" != *GATE-CI* ]]
}
