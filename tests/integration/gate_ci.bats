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
# build (a package that does not build) | hang
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
    echo "flags: race=$raced tags=$tagged env-flags=$GOFLAGS cgo=$CGO_ENABLED" >>"$STUB_CALLS"
    case " $* " in
    *" p/a p/b "*)
        case "$STUB_MODE" in
        race) if [[ $raced = 1 ]]; then
                printf 'WARNING: DATA RACE\n--- FAIL: TestRacy (0.00s)\nFAIL\tp/a\t0.1s\nok  \tp/b\t0.1s\n'; exit 1; fi ;;
        build) printf 'FAIL\tp/a [build failed]\nok  \tp/b\t0.1s\n'; exit 1 ;;
        lost) printf 'ok  \tp/a\t0.1s\n'; exit 0 ;;
        esac
        printf 'ok  \tp/a\t0.1s\nok  \tp/b\t0.1s\n' ;;
    *)
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

@test "six jobs ok is a PASS, the last line of stdout and of the log" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-CI PASS rc=0 jobs=6/6 failures=0 races=0 secs="*" log=$LOG" ]]
    [[ "$(tail -n 1 "$LOG")" == "${lines[-1]}" ]]
}

@test "the race detector and cgo are on for the other packages and the untagged shards, the knobs run has no -race" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    # untagged: the other packages, the two shards; then the same with the knobs
    mapfile -t calls <"$STUB_CALLS"
    [[ "${#calls[@]}" -eq 6 ]]
    [[ "${calls[0]}" == "flags: race=1 tags=0 env-flags= cgo=1" ]]
    [[ "${calls[1]}" == "flags: race=1 tags=0 env-flags=-race cgo=1" ]]
    [[ "${calls[2]}" == "flags: race=1 tags=0 env-flags=-race cgo=1" ]]
    [[ "${calls[3]}" == "flags: race=1 tags=1 env-flags= cgo=1" ]]
    [[ "${calls[4]}" == "flags: race=0 tags=1 env-flags=-tags=testknobs cgo=1" ]]
    [[ "${calls[5]}" == "flags: race=0 tags=1 env-flags=-tags=testknobs cgo=1" ]]
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
    for _ in $(seq 100); do pgrep -f "sleep 30" >/dev/null && break; sleep 0.1; done
    kill -TERM "$pid"
    rc=0
    wait "$pid" || rc=$?
    [ "$rc" -eq 130 ]
    grep -q '^GATE-CI FAIL rc=130 .* interrupted .*log=' "$BATS_TEST_TMPDIR/out"
}

@test "a usage error is status 2 and no verdict" {
    run -2 "$GATE" --bogus
    [[ "$output" != *GATE-CI* ]]
    run -2 "$GATE" p/a
    [[ "$output" != *GATE-CI* ]]
}
