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
    hang) exec sleep 30 ;;
    esac ;;
esac
SH
    chmod +x "$STUB"
    export GO="$STUB" GOCACHE="$BATS_TEST_TMPDIR/cache" LOG="$BATS_TEST_TMPDIR/gate.log"
}

@test "every package ok or without tests is a PASS, the last line of stdout and of the log" {
    STUB_MODE=ok run -0 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO PASS rc=0 packages=2/2 failures=0 secs="*" log=$LOG" ]]
    [[ "$(tail -n 1 "$LOG")" == "${lines[-1]}" ]]
}

@test "a package that printed nothing is a FAIL although go test exited 0" {
    STUB_MODE=lost run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=0 packages=1/2 "* ]]
}

@test "a failing test is a FAIL with its status and failure lines" {
    STUB_MODE=fail run -1 "$GATE" -o "$LOG"
    [[ "${lines[-1]}" == "GATE-GO FAIL rc=1 packages=1/2 failures=2 "* ]]
}

@test "SIGTERM stops the run, reaps go and prints a FAIL verdict" {
    STUB_MODE=hang "$GATE" -o "$LOG" >"$BATS_TEST_TMPDIR/out" 2>&1 &
    pid=$!
    for _ in $(seq 50); do pgrep -P "$pid" >/dev/null && break; sleep 0.1; done
    kill -TERM "$pid"
    rc=0
    wait "$pid" || rc=$?
    [ "$rc" -eq 130 ]
    grep -q '^GATE-GO FAIL rc=130 .* interrupted log=' "$BATS_TEST_TMPDIR/out"
    run ! pgrep -f "sleep 30"
}

@test "a usage error is status 2 and no verdict" {
    run -2 "$GATE" --bogus
    [[ "$output" != *GATE-GO* ]]
}
