#!/usr/bin/env bats
# tests/tools/no-shared-proc.sh: the lint that keeps a test off the processes
# and the temporary paths of the whole machine. Each case runs the script on a
# throwaway git repository, so what it finds is exactly the fixture. The
# names the lint forbids are put together in setup, so that this file is
# itself clean under the lint.

bats_require_minimum_version 1.5.0

setup() {
    LINT="$BATS_TEST_DIRNAME/../tools/no-shared-proc.sh"
    REPO="$BATS_TEST_TMPDIR/repo"
    mkdir -p "$REPO/tests/tools"
    cp "$LINT" "$REPO/tests/tools/no-shared-proc.sh"
    git -C "$REPO" init -q
    PG="pg""rep"
    PK="pk""ill"
    KA="kill""all"
    SHARED="/t""mp"
    SHM="/dev/""shm"
}

# put FILE LINE: add a tracked file with one line.
put() {
    mkdir -p "$REPO/$(dirname "$1")"
    printf '%s\n' "$2" >"$REPO/$1"
    git -C "$REPO" add "$1"
}

lint() {
    run "$@" "$REPO/tests/tools/no-shared-proc.sh"
}

@test "the repository itself is clean" {
    run -0 "$LINT"
    [[ -z "$output" ]]
}

@test "a tree of tests that stay in their sandbox passes" {
    put internal/x/a_test.go '	dir := t.TempDir(); p := os.TempDir(); env := "LD_LIBRARY_PATH='"$SHARED"'"'
    put tests/integration/a.bats '    d="$(mktemp -d "${BATS_TEST_TMPDIR}/x.XXXXXX")"; '"$PG"' -P "$pid"; '"$PG"' sleep'
    put tests/integration/b.bats '    stub_called "ssh .*rm -f '"$SHARED"'/tacctl.AbCd1234"; rm -f '"$SHARED"'/tacctl.AbCd1234'
    put tests/helpers/h.bash 'tmpdir() { mktemp -d "${BATS_TEST_TMPDIR}/h.XXXXXX"; }'
    put tests/e2e/e.bats '    '"$PK"' -P "$pid"'
    put internal/x/data.go 'var p = "'"$SHARED"'"'
    lint -0
    [[ -z "$output" ]]
}

@test "the process-wide commands fail in a Go test, a bats file, a helper and e2e" {
    for where in internal/x/a_test.go tests/integration/a.bats tests/helpers/h.bash tests/e2e/e.bats; do
        for cmd in "$PG -f sleep" "$PG -af sleep" "$PK -9 -f sleep" "$PK --full sleep" "$KA sleep" "x; $KA -9 sleep"; do
            git -C "$REPO" rm -rq --cached . 2>/dev/null || true
            put "$where" "    $cmd"
            run -1 "$REPO/tests/tools/no-shared-proc.sh"
            [[ "$output" == *"$where:1:"* ]] || { echo "$where: $cmd: $output"; false; }
            [[ "$output" == *"processes of the whole machine"* ]]
        done
    done
}

@test "a name that only contains the command is not a hit" {
    put tests/integration/a.bats '    run '"$PG"'x -f; mykillall; '"$PK"' -P 1'
    lint -0
}

@test "a command outside the tests is not looked at" {
    put tests/tools/gate-x.sh "$PG -f sleep; echo $SHARED $SHM"
    put internal/x/a.go "// $KA $SHARED $SHM"
    lint -0
}

@test "the shared memory directory fails in a Go test, a bats file and a helper" {
    for where in internal/x/a_test.go tests/integration/a.bats tests/helpers/h.bash; do
        git -C "$REPO" rm -rq --cached . 2>/dev/null || true
        put "$where" "    x=$SHM/work"
        run -1 "$REPO/tests/tools/no-shared-proc.sh"
        [[ "$output" == *"$where:1:"* ]] || { echo "$where: $output"; false; }
        [[ "$output" == *"shared temporary path"* ]]
    done
}

@test "a Go test that gives /tmp to os or filepath, or names it whole, fails" {
    for line in "d, _ := os.MkdirTemp(\"$SHARED\", \"x\")" "p := filepath.Join(\"$SHARED\", \"x\")" "base = \"$SHARED\""; do
        git -C "$REPO" rm -rq --cached . 2>/dev/null || true
        put internal/x/a_test.go "	$line"
        run -1 "$REPO/tests/tools/no-shared-proc.sh"
        [[ "$output" == *"internal/x/a_test.go:1:"* ]] || { echo "$line: $output"; false; }
    done
}

@test "a shell command or a redirection on /tmp fails in a bats file and a helper" {
    for where in tests/integration/a.bats tests/helpers/h.bash; do
        for line in "d=\$(mktemp -d $SHARED/x.XXXXXX)" "mkdir -p $SHARED/x" "echo y > $SHARED/x" "echo y >>\"$SHARED/x\"" "cp a \"$SHARED/x\"" "mktemp -d -p $SHARED"; do
            git -C "$REPO" rm -rq --cached . 2>/dev/null || true
            put "$where" "    $line"
            run -1 "$REPO/tests/tools/no-shared-proc.sh"
            [[ "$output" == *"$where:1:"* ]] || { echo "$line: $output"; false; }
        done
    done
}

@test "a line that says shared-proc-ok with a reason is allowed" {
    put internal/x/a_test.go "	base = \"$SHARED\" // shared-proc-ok: TMPDIR is too long for a socket path"
    put tests/integration/a.bats "    mkdir -p $SHARED/x # shared-proc-ok: the test of the fallback"
    put tests/integration/b.bats "    $PG -f sleep # shared-proc-ok: the process is named by the test"
    lint -0
}

@test "the files the script excuses whole are allowed, another file is not" {
    put tests/integration/gate_go.bats "    run ! $PG -f 'sleep 30'; x=$SHM/y"
    put tests/integration/gate_ci.bats "    $PG -f 'sleep 30'"
    put internal/cli/password_cache_test.go "	dir, err := os.MkdirTemp(\"$SHARED\", \"pc\")"
    lint -0
    put tests/integration/other.bats "    $PG -f 'sleep 30'"
    lint -1
    [[ "$output" == *"tests/integration/other.bats:1:"* ]]
    [[ "$output" != *"gate_go.bats"* ]]
}

@test "both kinds of hit are reported in one run, with a hint each" {
    put tests/integration/a.bats "    $PG -f sleep"
    put internal/x/a_test.go "	base = \"$SHARED\""
    lint -1
    [[ "$output" == *"processes of the whole machine"* ]]
    [[ "$output" == *"shared temporary path"* ]]
    [[ "$output" == *"shared-proc-ok: <reason>"* ]]
}
