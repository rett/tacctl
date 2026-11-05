#!/usr/bin/env bash
# go-test-shard.sh <index> <count> [<go test flags>...]
# go-test-shard.sh --check <count>
# go-test-shard.sh --plan <count>
# go-test-shard.sh --regen <log> [<durations file>]
#
# Runs shard <index> (0-based) of <count> of the Go tests of ./internal/cli,
# the package whose serial run takes over twenty minutes: the top-level
# tests are dealt so that the shards take about the same time. Every test is
# in exactly one shard (TestShardsCoverEveryTest in CI:
# 'go-test-shard.sh --check <count>' lists the dealt names and fails when
# they are not the package's tests, each once).
#
# The dealing is longest-processing-time first: the tests sorted by their
# weight, the heaviest first, each to the shard with the least weight so far
# (on a tie the one with fewest tests, then the lowest index). The weight
# estimates the seconds a test adds to the run of its shard: the tests run in
# parallel inside the process (about four at a time on the machines measured),
# so a parallel test weighs a quarter of its duration, while a serial test (one
# that never calls t.Parallel; Go runs those one by one before the first
# parallel one) weighs all of it. The durations are in
# tests/tools/cli-durations.txt: 'TestName seconds', followed by 'serial' for a
# serial test, one test per line, '#' lines are comments; SHARD_DURATIONS names
# another file. A test the file does not list counts as a parallel one of 0.1
# s; without a file, or when it lists no test, the tests are dealt round-robin
# in name order. The dealing is a function of the test names and that file
# only, so every machine and every job deals the same.
#
# --plan <count> prints the shards the dealing makes: the number of tests (and
# how many of them are serial) and the planned seconds, the sum of the
# weights, of each.
#
# --regen <log> [<file>] rewrites the durations file (default: the committed
# one) from the log of a 'go test -v' run: the '--- PASS: TestX (N.NNs)' lines
# of the top-level tests. A gate-ci log (tests/tools/gate-ci.sh) has the lines
# of every job: only those of the cli<i> jobs count, with the larger value
# where a test ran in several of them (the runs with -race are the slow ones;
# the testknobs runs add the tests that exist only with that tag). A log
# without job headers (a gate-go log, or a plain 'go test -v ./internal/cli')
# counts as a whole, and only the tests that 'go test -list' finds in
# internal/cli are kept. A test is serial when no '=== PAUSE TestX' line is in
# the counted part of the log. The durations are those of tests running in
# parallel with others, so they are no wall-clock times; regenerate the file
# when the tests change much, from the log of a quiet run: it only affects the
# balance of the shards, never which tests run.
#
# The package's tests need a session (setsid) and no stdin; the script gives
# both. GO names the go command (default: go); GOFLAGS (for example
# -tags=testknobs) is passed through.
set -euo pipefail

GO="${GO:-go}"
pkg=./internal/cli
src="${BASH_SOURCE[0]}"
[[ "$src" == */* ]] || src="./$src"
here="$(cd "${src%/*}" && pwd)"
durations="${SHARD_DURATIONS:-$here/cli-durations.txt}"

die() { echo "go-test-shard: $*" >&2; exit 2; }

tests() { "$GO" test -list '^Test' "$pkg" | grep '^Test' | LC_ALL=C sort; }

# deal <count>: reads the test names on standard input and prints
# 'shard<TAB>weight<TAB>name<TAB>serial or -', one line per test; the weight is
# in quarter milliseconds of wall time: a parallel test counts its duration in
# ms, a serial one four times that.
deal() {
    local file=/dev/null tab
    tab="$(printf '\t')"
    [[ ! -f "$durations" ]] || file="$durations"
    awk -v file="$file" '
        function ms(s) { return int(s * 100 + 0.5) * 10 }
        BEGIN {
            while ((getline line < file) > 0) {
                lineno++
                if (line ~ /^[[:space:]]*(#|$)/) continue
                n = split(line, f)
                if (n < 2 || n > 3 || f[1] !~ /^Test/ || f[2] !~ /^[0-9]+(\.[0-9]+)?$/ || (n == 3 && f[3] != "serial")) {
                    printf "go-test-shard: %s:%d: want \"TestName seconds [serial]\"\n", file, lineno > "/dev/stderr"
                    bad = 1; exit 2
                }
                known[f[1]] = ms(f[2]); serial[f[1]] = (n == 3)
            }
        }
        {
            w = ($0 in known) ? known[$0] : 100
            if (serial[$0]) w *= 4
            printf "%d\t%s\t%s\n", w, $0, serial[$0] ? "serial" : "-"
        }
        END { exit bad }
    ' |
        LC_ALL=C sort -t "$tab" -k1,1nr -k2,2 |
        awk -F '\t' -v n="$1" '
            {
                best = 0
                for (i = 1; i < n; i++)
                    if (load[i] < load[best] || (load[i] == load[best] && cnt[i] < cnt[best])) best = i
                load[best] += $1; cnt[best]++
                printf "%d\t%d\t%s\t%s\n", best, $1, $2, $3
            }'
}

case "${1:-}" in
--check)
    count="${2:-}"
    [[ "$count" =~ ^[1-9][0-9]*$ ]] || die "usage: go-test-shard.sh --check <count>"
    all="$(tests)"
    [[ -n "$all" ]] || die "no tests listed in $pkg"
    plan="$(deal "$count" <<<"$all")" || die "cannot deal the tests"
    dealt="$(cut -f3 <<<"$plan" | LC_ALL=C sort)"
    if [[ "$dealt" != "$all" ]]; then
        die "the shards do not cover the tests exactly once"
    fi
    echo "go-test-shard: $(wc -l <<<"$all") tests in $count shards, each once"
    exit 0
    ;;
--plan)
    count="${2:-}"
    [[ "$count" =~ ^[1-9][0-9]*$ ]] || die "usage: go-test-shard.sh --plan <count>"
    all="$(tests)"
    [[ -n "$all" ]] || die "no tests listed in $pkg"
    plan="$(deal "$count" <<<"$all")" || die "cannot deal the tests"
    awk -F '\t' -v n="$count" '
        { t[$1] += $2; c[$1]++; if ($4 == "serial") k[$1]++ }
        END { for (i = 0; i < n; i++) printf "shard %d: %d tests (%d serial), %.2f s planned\n", i, c[i], k[i], t[i] / 4000 }
    ' <<<"$plan"
    exit 0
    ;;
--regen)
    log="${2:-}"
    out="${3:-$durations}"
    [[ -n "$log" && -r "$log" ]] || die "usage: go-test-shard.sh --regen <log> [<durations file>]"
    keep=/dev/null
    if ! grep -qE '^=== (other|cli[0-9]+)(/[A-Za-z0-9_]+)?: ' "$log"; then
        keep="$(mktemp)"
        trap 'rm -f "$keep"' EXIT
        tests >"$keep"
        [[ -s "$keep" ]] || die "no tests listed in $pkg"
    fi
    body="$(awk -v keep="$keep" '
        BEGIN { while ((getline line < keep) > 0) want[line] = 1; nojobs = (keep != "/dev/null") }
        /^=== (other|cli[0-9]+)(\/[A-Za-z0-9_]+)?: / { job = $2; next }
        /^=== PAUSE Test[^\/]*$/ {
            if (nojobs ? ($3 in want) : job ~ /^cli/) paused[$3] = 1
            next
        }
        /^--- PASS: Test/ {
            d = $4; gsub(/[()s]/, "", d)
            if (d !~ /^[0-9]+(\.[0-9]+)?$/) next
            if (nojobs ? !($3 in want) : job !~ /^cli/) next
            if (!($3 in m) || d + 0 > m[$3] + 0) m[$3] = d
        }
        END { for (t in m) printf "%s %s%s\n", t, m[t], (t in paused) ? "" : " serial" }
    ' "$log")"
    [[ -n "$body" ]] || die "no top-level '--- PASS: Test...' line of internal/cli in $log"
    tmp="$(mktemp "$out.XXXXXX")"
    {
        cat <<'HDR'
# Durations of the top-level tests of internal/cli, in seconds: the weights
# tests/tools/go-test-shard.sh deals the shards by (longest first, each to the
# least loaded shard). One 'TestName seconds [serial]' line per test, the
# longest first; 'serial' marks a test that never calls t.Parallel (it counts
# four times a parallel one). A test not listed counts as a parallel one of
# 0.1 s. The dealing never changes which tests run.
#
# Regenerate (a quiet machine; GATE_TMPFS=1 is fine):
#   make gate-ci        # or make gate-go; keep the log it names
#   tests/tools/go-test-shard.sh --regen <log>
# From a gate-ci log: the larger '--- PASS: TestX (N.NNs)' value over the
# cli<i> jobs (-race, and the testknobs runs); serial when no job paused it.
# From a gate-go log: the tests 'go test -list' finds in internal/cli.
HDR
        LC_ALL=C sort -k2,2nr -k1,1 <<<"$body"
    } >"$tmp"
    chmod 644 "$tmp"
    mv "$tmp" "$out"
    echo "go-test-shard: $(grep -cv '^#' "$out") tests written to $out"
    exit 0
    ;;
esac

idx="${1:-}"
count="${2:-}"
[[ "$idx" =~ ^[0-9]+$ && "$count" =~ ^[1-9][0-9]*$ && "$idx" -lt "$count" ]] ||
    die "usage: go-test-shard.sh <index> <count> [<go test flags>...]"
shift 2

plan="$(tests | deal "$count")" || die "cannot deal the tests"
names="$(awk -F '\t' -v i="$idx" '$1 == i { print $3 }' <<<"$plan" | LC_ALL=C sort)"
[[ -n "$names" ]] || die "shard $idx of $count holds no test"
planned="$(awk -F '\t' -v i="$idx" '$1 == i { t += $2 } END { printf "%.0f", t / 4000 }' <<<"$plan")"
regex="^($(paste -sd'|' <<<"$names"))\$"
echo "go-test-shard: shard $idx of $count: $(wc -l <<<"$names") tests, about $planned s planned" >&2
exec setsid -w "$GO" test "$pkg" -run "$regex" -count=1 "$@" </dev/null
