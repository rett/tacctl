#!/usr/bin/env bats
# tests/tools/go-test-shard.sh: how the tests of internal/cli are dealt into
# shards (longest first, by the recorded durations), the exact-cover check
# and the regeneration of the durations file from a log. A stub `go` lists a
# few made-up tests, so nothing here depends on the Go tests themselves.

bats_require_minimum_version 1.5.0

setup() {
    SHARD="$BATS_TEST_DIRNAME/../tools/go-test-shard.sh"
    STUB="$BATS_TEST_TMPDIR/go"
    cat >"$STUB" <<'SH'
#!/bin/bash
# `go test -list` lists the tests of STUB_TESTS; any other `go test` prints
# its arguments, so the test sees which tests the shard was given.
[[ "$1" == test ]] || exit 0
case " $* " in
*" -list "*)
    for t in $STUB_TESTS; do echo "$t"; done
    echo "ok  	p/internal/cli	0.1s" ;;
*) echo "go $*" ;;
esac
SH
    chmod +x "$STUB"
    export GO="$STUB" STUB_TESTS="TestF TestA TestE TestB TestD TestC"
    export SHARD_DURATIONS="$BATS_TEST_TMPDIR/durations.txt"
}

@test "the tests are dealt longest first, each to the least loaded shard" {
    cat >"$SHARD_DURATIONS" <<'EOF'
# a comment
TestA 9
TestB 8.00
TestC 5

TestD 4
TestE 3
TestF 1
EOF
    # A to 0, B to 1, C to 1 (8 < 9), D to 0 (9 < 13), E to 0 (a tie, as many tests), F to 1:
    # round-robin by name would give A C E and B D F
    run --separate-stderr -0 "$SHARD" 0 2
    [[ "$output" == 'go test ./internal/cli -run ^(TestA|TestD|TestE)$ -count=1 -parallel 16' ]]
    run --separate-stderr -0 "$SHARD" 1 2 -v
    [[ "$output" == 'go test ./internal/cli -run ^(TestB|TestC|TestF)$ -count=1 -parallel 16 -v' ]]
}

@test "the shard runs with -parallel 16, and a -parallel among its flags comes after it and wins" {
    run --separate-stderr -0 "$SHARD" 0 2 -parallel 4
    [[ "$output" == *" -count=1 -parallel 16 -parallel 4" ]]
}

@test "the shard says how many tests it holds and about how long they should take" {
    printf 'TestA 9\nTestB 8\nTestC 5\nTestD 4\nTestE 3\nTestF 1\n' >"$SHARD_DURATIONS"
    # parallel tests weigh a quarter of their duration: A D E add up to 16 s, 4 s of the run
    run --separate-stderr -0 "$SHARD" 0 2
    [[ "$stderr" == "go-test-shard: shard 0 of 2: 3 tests, about 4 s planned" ]]
}

@test "a serial test weighs four times a parallel one of the same duration" {
    printf 'TestA 2 serial\nTestB 4\nTestC 3\nTestD 1\n' >"$SHARD_DURATIONS"
    STUB_TESTS="TestA TestB TestC TestD" run --separate-stderr -0 "$SHARD" 0 2
    # A weighs 8: alone in shard 0; B C D weigh 4 + 3 + 1
    [[ "$output" == 'go test ./internal/cli -run ^(TestA)$ -count=1 -parallel 16' ]]
    STUB_TESTS="TestA TestB TestC TestD" run --separate-stderr -0 "$SHARD" 1 2
    [[ "$output" == 'go test ./internal/cli -run ^(TestB|TestC|TestD)$ -count=1 -parallel 16' ]]
}

@test "--plan prints the tests and the planned seconds of each shard" {
    printf 'TestA 8 serial\nTestB 8\nTestC 8\nTestD 8\nTestE 8\nTestF 8\n' >"$SHARD_DURATIONS"
    run -0 "$SHARD" --plan 2
    # A weighs 32: alone against B C D E (8 each), then F goes to the shard with fewer tests
    [[ "${lines[0]}" == "shard 0: 2 tests (1 serial), 10.00 s planned" ]]
    [[ "${lines[1]}" == "shard 1: 4 tests (0 serial), 8.00 s planned" ]]
}

@test "without a durations file, or with one that lists none of the tests, the tests are dealt round-robin by name" {
    rm -f "$SHARD_DURATIONS"
    run --separate-stderr -0 "$SHARD" 0 2
    [[ "$output" == 'go test ./internal/cli -run ^(TestA|TestC|TestE)$ -count=1 -parallel 16' ]]
    run --separate-stderr -0 "$SHARD" 1 2
    [[ "$output" == 'go test ./internal/cli -run ^(TestB|TestD|TestF)$ -count=1 -parallel 16' ]]
    printf '# nothing\nTestOther 5\n' >"$SHARD_DURATIONS"
    run --separate-stderr -0 "$SHARD" 0 2
    [[ "$output" == 'go test ./internal/cli -run ^(TestA|TestC|TestE)$ -count=1 -parallel 16' ]]
}

@test "a test the file does not list counts as a short parallel one and lands in a shard" {
    printf 'TestA 9\nTestB 8\n' >"$SHARD_DURATIONS"
    run --separate-stderr -0 "$SHARD" 0 2
    [[ "$output" == *"TestA"* ]]
    # all six tests are dealt, each once
    run -0 "$SHARD" --check 2
    [[ "$output" == "go-test-shard: 6 tests in 2 shards, each once" ]]
    all=""
    for i in 0 1 2; do
        run --separate-stderr -0 "$SHARD" "$i" 3
        all+="$(sed 's/.*-run ^(\(.*\))\$ .*/\1/' <<<"$output" | tr '|' '\n')"$'\n'
    done
    [[ "$(sort <<<"${all%$'\n'}" | paste -sd' ')" == "TestA TestB TestC TestD TestE TestF" ]]
}

@test "--check passes for any number of shards and fails on a bad count" {
    printf 'TestA 9\nTestB 8\nTestC 5\n' >"$SHARD_DURATIONS"
    for n in 1 2 3 4 7; do
        run -0 "$SHARD" --check "$n"
        [[ "$output" == "go-test-shard: 6 tests in $n shards, each once" ]]
    done
    run -2 "$SHARD" --check 0
    run -2 "$SHARD" --check
}

@test "a shard that would hold no test, and a bad index, are usage errors" {
    STUB_TESTS="TestA" run -2 "$SHARD" 1 2
    [[ "$output" == *"shard 1 of 2 holds no test"* ]]
    run -2 "$SHARD" 2 2
    [[ "$output" == *"usage:"* ]]
}

@test "a malformed durations line is an error naming the line, not a silent round-robin" {
    printf 'TestA 9\nTestB soon\n' >"$SHARD_DURATIONS"
    run -2 "$SHARD" --check 2
    [[ "$output" == *"durations.txt:2: want"* ]]
    printf 'TestA 9 parallel\n' >"$SHARD_DURATIONS"
    run -2 "$SHARD" 0 2
    [[ "$output" == *"durations.txt:1: want"* ]]
}

@test "the committed durations file is well formed and every line names a test" {
    SHARD_DURATIONS="$BATS_TEST_DIRNAME/../tools/cli-durations.txt"
    [[ -s "$SHARD_DURATIONS" ]]
    run -0 awk '!/^#/ && !/^[[:space:]]*$/ && !($0 ~ /^Test[A-Za-z0-9_]* [0-9]+(\.[0-9]+)?( serial)?$/) { bad++; print NR ": " $0 } END { exit (bad > 0) }' "$SHARD_DURATIONS"
    run -0 "$SHARD" --check 2
}

# A gate-ci log: three jobs with durations, and a test of another package.
make_ci_log() {
    cat >"$1" <<'EOF'
gate-ci: 6 jobs, go go1.27.0, log /x
=== other: env CGO_ENABLED=1 go test -v
=== RUN   TestOther
--- PASS: TestOther (99.00s)
gate-ci: other ok (99 s)
=== cli0: env GOFLAGS=-race tests/tools/go-test-shard.sh 0 2 -v
=== RUN   TestA
--- PASS: TestA (1.50s)
=== RUN   TestB
=== PAUSE TestB
=== RUN   TestB/sub
=== PAUSE TestB/sub
=== CONT  TestB
    --- PASS: TestB/sub (7.00s)
--- PASS: TestB (3.25s)
gate-ci: cli0 ok (10 s)
=== cli1/testknobs: env GOFLAGS=-tags=testknobs tests/tools/go-test-shard.sh 1 2 -v
=== RUN   TestA
--- PASS: TestA (0.50s)
=== RUN   TestC
=== PAUSE TestC
--- PASS: TestC (0.03s)
gate-ci: cli1/testknobs ok (4 s)
EOF
}

@test "--regen from a gate-ci log keeps the cli jobs, the larger duration of each test and which tests are serial" {
    make_ci_log "$BATS_TEST_TMPDIR/ci.log"
    run -0 "$SHARD" --regen "$BATS_TEST_TMPDIR/ci.log"
    [[ "$output" == "go-test-shard: 3 tests written to $SHARD_DURATIONS" ]]
    [[ "$(grep '^#' "$SHARD_DURATIONS" | head -n 1)" == "# Durations of the top-level tests of internal/cli"* ]]
    [[ "$(grep -v '^#' "$SHARD_DURATIONS")" == $'TestB 3.25\nTestA 1.50 serial\nTestC 0.03' ]]
}

@test "--regen from a log without job headers keeps the tests go lists in internal/cli" {
    cat >"$BATS_TEST_TMPDIR/go.log" <<'EOF'
=== RUN   TestA
--- PASS: TestA (2.00s)
=== RUN   TestOther
=== PAUSE TestOther
--- PASS: TestOther (50.00s)
=== RUN   TestB
=== PAUSE TestB
--- PASS: TestB (4.00s)
ok  	p/internal/cli	6.0s
EOF
    out="$BATS_TEST_TMPDIR/out.txt"
    run -0 "$SHARD" --regen "$BATS_TEST_TMPDIR/go.log" "$out"
    [[ "$(grep -v '^#' "$out")" == $'TestB 4.00\nTestA 2.00 serial' ]]
}

@test "the file --regen writes deals the same tests to the same shards as it was made from" {
    make_ci_log "$BATS_TEST_TMPDIR/ci.log"
    "$SHARD" --regen "$BATS_TEST_TMPDIR/ci.log" >/dev/null
    STUB_TESTS="TestA TestB TestC" run -0 "$SHARD" --plan 2
    [[ "${lines[0]}" == "shard 0: 1 tests (1 serial), 1.50 s planned" ]]
    [[ "${lines[1]}" == "shard 1: 2 tests (0 serial), 0.82 s planned" ]]
}

@test "--regen without a readable log, or with a log that has no passing test, is a usage error" {
    run -2 "$SHARD" --regen
    run -2 "$SHARD" --regen "$BATS_TEST_TMPDIR/missing.log"
    printf 'nothing here\n' >"$BATS_TEST_TMPDIR/empty.log"
    run -2 "$SHARD" --regen "$BATS_TEST_TMPDIR/empty.log"
    [[ ! -e "$SHARD_DURATIONS" ]]
}
