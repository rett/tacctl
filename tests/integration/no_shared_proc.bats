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
    put tests/integration/a.bats '    d="$(mktemp -d "${BATS_TEST_TMPDIR}/x.XXXXXX")"; '"$PG"' -P "$pid"; '"$PG"' sleep; cd "$d"'
    put tests/integration/b.bats '    stub_called "ssh .*rm -f '"$SHARED"'/tacctl.AbCd1234"; rm -f '"$SHARED"'/tacctl.AbCd1234'
    put tests/helpers/h.bash 'tmpdir() { mktemp -d "${BATS_TEST_TMPDIR}/h.XXXXXX"; }'
    put tests/e2e/e.bats '    '"$PK"' -P "$pid"; '"$PK"' -9 -P "$pid"; stub_cmd '"$PK"' "exit 1"; grep -cE "^(loginctl|'"$PK"')" "$LOG"'
    put internal/x/b_test.go '	exec.Command("'"$PG"'", "-P", pid); exec.Command("'"$PK"'", "-P", pid); calls = "'"$PK"' -TERM -u old"'
    put internal/x/data.go 'var p = "'"$SHARED"'"'
    lint -0
    [[ -z "$output" ]]
}

@test "the process-wide commands fail in a Go test, a bats file, a helper and e2e" {
    for where in internal/x/a_test.go tests/integration/a.bats tests/helpers/h.bash tests/e2e/e.bats; do
        for cmd in "$PG -f sleep" "$PG -af sleep" "$PK -9 -f sleep" "$PK --full sleep" "$KA sleep" "x; $KA -9 sleep" \
            "$PG -u \"\$USER\" -f x" "$PG -x -u 0 -f x" "$PK -u root -9 -f x" "$PG -l --full x" "x | $PG -fa y"; do
            git -C "$REPO" rm -rq --cached . 2>/dev/null || true
            put "$where" "    $cmd"
            run -1 "$REPO/tests/tools/no-shared-proc.sh"
            [[ "$output" == *"$where:1:"* ]] || { echo "$where: $cmd: $output"; false; }
            [[ "$output" == *"processes of the whole machine"* ]]
        done
    done
}

@test "killing by name, with or without options, fails in a bats file, a helper and e2e" {
    for where in tests/integration/a.bats tests/helpers/h.bash tests/e2e/e.bats; do
        for cmd in "$PK tacquito" "$PK -x tacquito" "$PK -9 tacquito" "$PK -TERM -u root tacquito" "sudo $PK tacquito" \
            "run $PK tacquito" "run -0 $PK -x tacquito" "run ! $PK tacquito" "x; $PK tacquito" "x && $PK -x tacquito" \
            "x | $PK tacquito" "\$($PK tacquito)" "if x; then $PK tacquito; fi"; do
            git -C "$REPO" rm -rq --cached . 2>/dev/null || true
            put "$where" "    $cmd"
            run -1 "$REPO/tests/tools/no-shared-proc.sh"
            [[ "$output" == *"$where:1:"* ]] || { echo "$where: $cmd: $output"; false; }
            [[ "$output" == *"processes of the whole machine"* ]]
        done
    done
}

@test "the same commands run through Go's os/exec fail, with their options" {
    for line in "exec.Command(\"$PK\", \"-f\", \"x\")" "exec.Command(\"$PG\", \"-f\", \"x\")" "exec.Command(\"$KA\", \"x\")" \
        "exec.CommandContext(ctx, \"$PK\", \"-f\", \"x\")" "exec.CommandContext(ctx, \"$KA\", \"-9\", \"x\")" \
        "exec.Command(\"$PG\", \"-u\", \"x\", \"-f\", \"y\")" "exec.Command(\"$PG\", \"-af\", \"y\")" \
        "exec.Command(\"$PG\", \"--full\", \"y\")" "exec.Command(\"$PK\", \"tacquito\")" "exec.Command(\"$PK\", \"-x\", \"tacquito\")" \
        "exec.CommandContext(ctx, \"$PK\", \"-9\", \"tacquito\")"; do
        git -C "$REPO" rm -rq --cached . 2>/dev/null || true
        put internal/x/a_test.go "	$line"
        run -1 "$REPO/tests/tools/no-shared-proc.sh"
        [[ "$output" == *"internal/x/a_test.go:1:"* ]] || { echo "$line: $output"; false; }
        [[ "$output" == *"processes of the whole machine"* ]]
    done
}

@test "looking for or signalling the children of a pid is allowed, in shell and in Go" {
    put tests/integration/a.bats "    for p in \$($PG -P \"\$1\"); do $PK -P \"\$p\"; $PK -9 -P \"\$p\"; done; $PG sleep; $PG -x sleep"
    put tests/e2e/e.bats "    run $PK -TERM -P \"\$pid\""
    put internal/x/a_test.go "	exec.Command(\"$PG\", \"-P\", pid); exec.CommandContext(ctx, \"$PK\", \"-P\", pid); exec.Command(\"$PG\", \"-x\", \"sleep\")"
    lint -0
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

@test "the shared memory directory fails in a Go test, a bats file, a helper and e2e" {
    for where in internal/x/a_test.go tests/integration/a.bats tests/helpers/h.bash tests/e2e/e.bats; do
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

@test "a Go string literal that starts with /tmp/ fails, in quotes or backquotes, wherever it stands" {
    for line in "dir := \"$SHARED/x\"" "run(\"touch\", \"$SHARED/x\")" "return \"$SHARED/a\"" "sock := \`$SHARED/s.sock\`" \
        "{\"-L\", \"$SHARED/l.sock:h:443\"}," "cmd.Dir = \"$SHARED/\""; do
        git -C "$REPO" rm -rq --cached . 2>/dev/null || true
        put internal/x/a_test.go "	$line"
        run -1 "$REPO/tests/tools/no-shared-proc.sh"
        [[ "$output" == *"internal/x/a_test.go:1:"* ]] || { echo "$line: $output"; false; }
        [[ "$output" == *"shared temporary path"* ]]
    done
}

@test "a Go string that only contains /tmp, or names a longer directory, is no hit" {
    put internal/x/a_test.go "	a := \"LD_LIBRARY_PATH=$SHARED\"; b := \"$SHARED""dir/x\"; c := \"x$SHARED/y\"; d := '$SHARED/z'"
    lint -0
}

@test "a shell command or a redirection on /tmp fails in a bats file, a helper and e2e" {
    for where in tests/integration/a.bats tests/helpers/h.bash tests/e2e/e.bats; do
        for line in "d=\$(mktemp -d $SHARED/x.XXXXXX)" "mkdir -p $SHARED/x" "echo y > $SHARED/x" "echo y >>\"$SHARED/x\"" "cp a \"$SHARED/x\"" \
            "mktemp -d -p $SHARED" "mktemp -p $SHARED" "d=\$(mktemp -p $SHARED x.XXXXXX)" "mktemp --tmpdir=$SHARED" "mktemp -p '$SHARED'" \
            "cd $SHARED" "cd \"$SHARED\" || exit 1" "x && cd $SHARED/x" "pushd $SHARED" "TMPDIR=$SHARED mktemp -d" "export TMPDIR=$SHARED" \
            "touch '$SHARED/x'" "install -d $SHARED/x"; do
            git -C "$REPO" rm -rq --cached . 2>/dev/null || true
            put "$where" "    $line"
            run -1 "$REPO/tests/tools/no-shared-proc.sh"
            [[ "$output" == *"$where:1:"* ]] || { echo "$line: $output"; false; }
            [[ "$output" == *"shared temporary path"* ]]
        done
    done
}

@test "a shell command that only mentions /tmp, or a longer name, is no hit" {
    put tests/integration/a.bats "    cd \"\$BATS_TEST_TMPDIR\"; mktemp -p \"\$BATS_TEST_TMPDIR\"; echo $SHARED/ok; cd $SHARED""dir; TMPDIR=\$BATS_TEST_TMPDIR mktemp -d"
    put tests/e2e/e.bats "    ssh x 'rm -f $SHARED/tacctl.AbCd1234'; stub_called \"scp .* $SHARED/tacctl.AbCd1234\""
    lint -0
}

@test "a line that says shared-proc-ok with a reason excuses a shared path" {
    put internal/x/a_test.go "	base = \"$SHARED\" // shared-proc-ok: TMPDIR is too long for a socket path"
    put tests/integration/a.bats "    mkdir -p $SHARED/x # shared-proc-ok: the test of the fallback"
    put tests/e2e/e.bats "    cd $SHARED # shared-proc-ok: the test of the fallback"
    lint -0
}

@test "shared-proc-ok never excuses a process-wide command, with a reason or without" {
    for where in internal/x/a_test.go tests/integration/a.bats tests/helpers/h.bash tests/e2e/e.bats; do
        for line in "$PG -f sleep # shared-proc-ok: the process is named by the test" "$KA sleep # shared-proc-ok: x" \
            "$PK -f sleep # shared-proc-ok:" "$PK -f sleep // shared-proc-ok: why"; do
            git -C "$REPO" rm -rq --cached . 2>/dev/null || true
            put "$where" "    $line"
            run -1 "$REPO/tests/tools/no-shared-proc.sh"
            [[ "$output" == *"$where:1:"* ]] || { echo "$where: $line: $output"; false; }
            [[ "$output" == *"processes of the whole machine"* ]]
        done
    done
    for where in tests/integration/a.bats tests/e2e/e.bats; do
        git -C "$REPO" rm -rq --cached . 2>/dev/null || true
        put "$where" "    $PK tacquito # shared-proc-ok: the test of the fallback"
        run -1 "$REPO/tests/tools/no-shared-proc.sh"
        [[ "$output" == *"$where:1:"* ]]
    done
}

@test "shared-proc-ok without a reason excuses nothing" {
    for line in "base = \"$SHARED\" // shared-proc-ok:" "base = \"$SHARED\" // shared-proc-ok:   " "base = \"$SHARED\" // shared-proc-ok"; do
        git -C "$REPO" rm -rq --cached . 2>/dev/null || true
        put internal/x/a_test.go "	$line"
        run -1 "$REPO/tests/tools/no-shared-proc.sh"
        [[ "$output" == *"internal/x/a_test.go:1:"* ]] || { echo "$line: $output"; false; }
        [[ "$output" == *"shared temporary path"* ]]
    done
    put tests/integration/a.bats "    mkdir -p $SHARED/x # shared-proc-ok:"
    lint -1
    [[ "$output" == *"tests/integration/a.bats:1:"* ]]
}

@test "no file is excused whole: the files once excused are checked like any other" {
    put tests/integration/gate_go.bats "    run ! $PG -f 'sleep 30'; x=$SHM/y"
    put tests/integration/gate_ci.bats "    $PG -f 'sleep 30'"
    put internal/cli/password_cache_test.go "	dir, err := os.MkdirTemp(\"$SHARED\", \"pc\")"
    lint -1
    [[ "$output" == *"tests/integration/gate_go.bats:1:"* ]]
    [[ "$output" == *"tests/integration/gate_ci.bats:1:"* ]]
    [[ "$output" == *"internal/cli/password_cache_test.go:1:"* ]]
}

@test "both kinds of hit are reported in one run, with a hint each" {
    put tests/integration/a.bats "    $PG -f sleep"
    put internal/x/a_test.go "	base = \"$SHARED\""
    lint -1
    [[ "$output" == *"processes of the whole machine"* ]]
    [[ "$output" == *"shared temporary path"* ]]
    [[ "$output" == *"shared-proc-ok: <reason>"* ]]
}
