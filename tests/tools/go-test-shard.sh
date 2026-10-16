#!/usr/bin/env bash
# go-test-shard.sh <index> <count> [<go test flags>...]
#
# Runs shard <index> (0-based) of <count> of the Go tests of ./internal/cli,
# the package whose serial run takes over twenty minutes: the top-level
# tests, sorted by name, are dealt round-robin, so every shard holds a mix.
# Every test is in exactly one shard (TestShardsCoverEveryTest in CI:
# 'go-test-shard.sh --check <count>' lists the dealt names and fails when
# they are not the package's tests, each once).
#
# The package's tests need a session (setsid) and no stdin; the script gives
# both. GO names the go command (default: go); GOFLAGS (for example
# -tags=testknobs) is passed through.
set -euo pipefail

GO="${GO:-go}"
pkg=./internal/cli

die() { echo "go-test-shard: $*" >&2; exit 2; }

tests() { "$GO" test -list '^Test' "$pkg" | grep '^Test' | LC_ALL=C sort; }

if [[ "${1:-}" == "--check" ]]; then
    count="${2:-}"
    [[ "$count" =~ ^[1-9][0-9]*$ ]] || die "usage: go-test-shard.sh --check <count>"
    all="$(tests)"
    [[ -n "$all" ]] || die "no tests listed in $pkg"
    dealt=""
    for ((i = 0; i < count; i++)); do
        dealt+="$(awk -v i="$i" -v n="$count" '(NR - 1) % n == i' <<<"$all")"$'\n'
    done
    if [[ "$(LC_ALL=C sort <<<"${dealt%$'\n'}")" != "$all" ]]; then
        die "the shards do not cover the tests exactly once"
    fi
    echo "go-test-shard: $(wc -l <<<"$all") tests in $count shards, each once"
    exit 0
fi

idx="${1:-}"
count="${2:-}"
[[ "$idx" =~ ^[0-9]+$ && "$count" =~ ^[1-9][0-9]*$ && "$idx" -lt "$count" ]] ||
    die "usage: go-test-shard.sh <index> <count> [<go test flags>...]"
shift 2

names="$(tests | awk -v i="$idx" -v n="$count" '(NR - 1) % n == i')"
[[ -n "$names" ]] || die "shard $idx of $count holds no test"
regex="^($(paste -sd'|' <<<"$names"))\$"
echo "go-test-shard: shard $idx of $count: $(wc -l <<<"$names") tests" >&2
exec setsid -w "$GO" test "$pkg" -run "$regex" -count=1 "$@" </dev/null
