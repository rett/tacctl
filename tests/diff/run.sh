#!/usr/bin/env bash
# run.sh [options] <corpus>...        (docs/plans/go-rewrite.md 2.5)
#
# The differential runner: runs every command of a corpus under two
# implementations of tacctl, each against its own copy of the same fixture
# state, and reports any difference in stdout, stderr, exit code, the calls
# made to the stubbed system commands and the resulting state tree.
#
#   A  the reference: bin/tacctl.sh of a git tag (--against, default 0.1.18,
#      the parity baseline), checked out into a temp dir once per run, never
#      the working tree, so a result does not depend on which bash files a
#      package touched.
#   B  what is being checked (--b): go (default; dist/tacctl, which 'make
#      build' writes, with TACCTL_TREE pointing at this tree the way
#      tests/helpers/setup.bash does), bash (the tag again: the self-test, a
#      runner that reports a difference here is broken), or the path of any
#      executable.
#
# A corpus is tests/diff/corpus/<name>.txt (or a path). One command per
# line; the program name is left out:
#
#   user add alice superuser --hash 2432... --scopes lab
#   user passwd alice <<< CorrectHorse99\nCorrectHorse99     stdin; \n is a line break
#   user list ;; user show alice                  several commands, one state
#
# Placeholders in a line: {HASH} a valid hex bcrypt hash (cost 10), {FIXTURES}
# this tree's tests/fixtures, {DATE} and {TS} today's date (YYYYMMDD) and the
# snapshot id the fixed clock gives (YYYYMMDD_120000_000).
#
# '#' starts a comment line. A command without '<<<' has a closed stdin
# (/dev/null). Each line starts from a fresh copy of the fixture; commands
# chained with ' ;; ' share it and are compared one by one. Arguments are
# split like a shell does (quotes, backslashes), nothing is expanded.
# Directives (they apply to the lines after them):
#
#   @fixture <name>     tests/fixtures/<name>: tacquito.*.yaml is placed as
#                       tacquito.yaml and imported into the store (what
#                       tests/helpers/fixtures.bash load_fixture does), store.*.yaml
#                       is the store only, any other file is placed as
#                       tacquito.yaml only, a directory is copied into the
#                       etc dir; none is an empty state. Default tacquito.minimal.yaml.
#   @env KEY=VALUE      set a variable for the commands (inside tacctl's TACCTL_*
#                       sandbox); @unenv KEY removes it again
#   @stub <name> <rc>   make the stubbed system command <name> (systemctl,
#                       logger) exit <rc>; the default is 0
#   @known <reason>     the next command line is a known difference (an
#                       intended change of plan 3.9): reported, not a failure
#   @path <dir>         put this tree's <dir> on PATH after the standard stubs
#                       (stand-ins for more system commands: ssh, podman, ...)
#   @root <dir>         copy the contents of this tree's <dir> into the state
#                       root before each command line (files a fixture lacks)
#
# Commands run with the state root as their working directory, so a file a
# command writes to a relative path is part of the state compared.
#
# Both sides run in 'env -i' with the same sandbox: TACCTL_* paths under a
# per-side root, LANG=C.UTF-8, TZ=UTC, TACCTL_SKIP_SUDO=1, and PATH stubs
# (systemctl and logger record their argv, chown and sleep do nothing, date
# is the real one at TACCTL_TEST_NOW, openssl rand answers from
# TACCTL_TEST_RANDOM). The stubs are how bash is made deterministic; the Go
# binary reads TACCTL_TEST_NOW and TACCTL_TEST_RANDOM itself (the test knobs
# of 'make build') where it does not call the commands. Because the random
# bytes and the clock are fixed, a generated password or secret is the same
# on both sides and needs no masking. What is still normalised: ANSI colours
# (unless --colour), timestamps (<TS>, <ISO>), mktemp names (<RAND>), the version, the sandbox and
# tree paths, and bcrypt hashes the commands generated (not the ones given
# in the command line), whose salt is random.
#
# Options: --against <tag>  --b <go|bash|path>  --go <path>  --filter <regex>
#          --colour  --keep (keep the work dir)  --list  --all  --self-test  -h
# Exit: 0 no unexplained difference, 1 a difference, 2 usage or setup error.
set -euo pipefail

here="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
src="$(cd "${here}/../.." && pwd)"

tag=0.1.18 side_b=go go_bin="${src}/dist/tacctl" filter="" colour=0 keep=0 list=0 all=0 selftest=0
corpora=()

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }
die() { echo "diff/run.sh: $*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --against) tag="${2:?--against needs a tag}"; shift 2 ;;
        --b) side_b="${2:?--b needs go, bash or a path}"; shift 2 ;;
        --go) go_bin="${2:?--go needs a path}"; shift 2 ;;
        --filter) filter="${2:?--filter needs a regex}"; shift 2 ;;
        --colour|--color) colour=1; shift ;;
        --keep) keep=1; shift ;;
        --list) list=1; shift ;;
        --all) all=1; shift ;;
        --self-test) selftest=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) die "unknown option $1 (--help)" ;;
        *) corpora+=("$1"); shift ;;
    esac
done

if ((all)); then
    for f in "${here}"/corpus/*.txt; do
        [[ "$(basename "$f" .txt)" == selftest ]] || corpora+=("$f")
    done
fi
((selftest)) && corpora=("${here}/corpus/selftest.txt")
[[ ${#corpora[@]} -gt 0 ]] || { usage >&2; exit 2; }

resolve_corpus() {
    if [[ -f "$1" ]]; then echo "$1"; elif [[ -f "${here}/corpus/$1.txt" ]]; then echo "${here}/corpus/$1.txt"; else die "no corpus '$1' (tests/diff/corpus/$1.txt)"; fi
}
for i in "${!corpora[@]}"; do corpora[i]="$(resolve_corpus "${corpora[i]}")"; done

if ((list)); then
    for c in "${corpora[@]}"; do
        echo "== ${c}"
        grep -vE '^[[:space:]]*(#|$)' "$c"
    done
    exit 0
fi

real_date="$(command -v date)" || die "date not found"
real_openssl="$(command -v openssl || true)"
real_python="$(command -v python3)" || die "python3 not found (the bash side needs it, and so does the openssl stub)"

work="$(mktemp -d "${TMPDIR:-/tmp}/tacctl-diff.XXXXXX")"
cleanup() { if ((keep)); then echo "work dir kept: ${work}" >&2; else rm -rf "$work"; fi; }
trap cleanup EXIT

# --- the two implementations ----------------------------------------------------
tag_tree="${work}/tag-tree"
mkdir -p "$tag_tree"
git -C "$src" rev-parse --verify --quiet "${tag}^{commit}" > /dev/null || die "no tag or commit '${tag}' in ${src}"
# A shared clone checked out at the tag (nothing in the source repo changes),
# so the tree knows its version as the working tree does. Without git history
# to clone (a tarball, say) a plain export does.
common_git="$(git -C "$src" rev-parse --path-format=absolute --git-common-dir)"
rm -rf "$tag_tree"
if ! { git clone --quiet --shared --no-checkout "$common_git" "$tag_tree" 2> /dev/null \
    && git -C "$tag_tree" -c advice.detachedHead=false checkout --quiet --detach "$tag" 2> /dev/null; }; then
    rm -rf "$tag_tree"
    mkdir -p "$tag_tree"
    git -C "$src" archive "$tag" | tar -x -C "$tag_tree"
fi
bash_tag="${tag_tree}/bin/tacctl.sh"
[[ -f "$bash_tag" ]] || die "${tag} has no bin/tacctl.sh"
src_version="$(git -C "$src" describe --tags --always --dirty 2> /dev/null || echo unknown)"
tag_version="$(git -C "$tag_tree" describe --tags --always --dirty 2> /dev/null || echo unknown)"

bin_a="$bash_tag"
declare -a impl_env_a=() impl_env_b=()
case "$side_b" in
    go)
        bin_b="$go_bin"
        [[ -x "$bin_b" ]] || die "no Go binary at ${bin_b} (make build, or --go <path>)"
        impl_env_b=("TACCTL_TREE=${src}")
        ;;
    bash) bin_b="$bash_tag" ;;
    *) bin_b="$side_b"; [[ -x "$bin_b" ]] || die "--b ${side_b}: not an executable" ;;
esac
label_b="$side_b"
# The version B prints: the binary's own build stamp, which is not the working
# tree's 'git describe' once the tree has changed since 'make build' (a
# -dirty suffix, or a commit since).
b_version=""
if [[ "$side_b" == go ]]; then
    b_version="$(env -i TACCTL_SKIP_SUDO=1 PATH=/usr/bin:/bin "$bin_b" version 2> /dev/null | sed -n '1s/^tacctl //p')"
fi

# The fixed inputs of both sides.
test_now="$("$real_date" -u +%Y-%m-%dT12:00:00Z)"
test_random="a1b2c3d4e5f60718293a4b5c6d7e8f90"
today="${test_now%%T*}"
today="${today//-/}"
test_hash="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

# Python's bcrypt draws its salt from os.urandom; the bash side runs with a
# sitecustomize that answers from TACCTL_TEST_RANDOM, repeated, from the
# first byte in every process: the same rule as the Go knob (each Rand() of
# app.Knobs starts at the first byte), so a generated hash is the same on
# both sides when the Go code takes its salt from the knob's source.
mkdir -p "${work}/pysite"
cat > "${work}/pysite/sitecustomize.py" <<'PY'
import os

_seed = bytes.fromhex(os.environ.get("TACCTL_TEST_RANDOM") or "00")
_pos = 0


def _urandom(n):
    global _pos
    out = bytearray()
    for _ in range(n):
        out.append(_seed[_pos % len(_seed)])
        _pos += 1
    return bytes(out)


os.urandom = _urandom
PY

# --- stubs -----------------------------------------------------------------------
# make_stubs <dir> <calls log> [name rc]...
make_stubs() {
    local dir="$1" calls="$2"
    shift 2
    mkdir -p "$dir"
    local -A codes=([systemctl]=0 [logger]=0)
    while [[ $# -ge 2 ]]; do codes[$1]="$2"; shift 2; done
    local name
    for name in systemctl logger; do
        printf '#!/bin/sh\necho "%s $*" >> "%s"\nexit %s\n' "$name" "$calls" "${codes[$name]}" > "${dir}/${name}"
    done
    for name in chown sleep; do
        printf '#!/bin/sh\nexit 0\n' > "${dir}/${name}"
    done
    cat > "${dir}/date" <<STUB
#!/bin/sh
# The real date, at the fixed time unless the caller names one.
for a in "\$@"; do
    case "\$a" in -d|--date|--date=*|-r|--reference|--reference=*|-f|--file=*) exec "${real_date}" "\$@" ;; esac
done
exec "${real_date}" -d "\$TACCTL_TEST_NOW" "\$@"
STUB
    cat > "${dir}/openssl" <<STUB
#!/bin/sh
# 'openssl rand -hex|-base64 N' from TACCTL_TEST_RANDOM, repeated to N bytes
# (the same rule as the Go test knob); everything else is the real openssl.
if [ "\$1" = rand ] && [ -n "\${TACCTL_TEST_RANDOM:-}" ] && { [ "\$2" = -hex ] || [ "\$2" = -base64 ]; }; then
    exec "${real_python}" -c '
import base64, os, sys
seed = bytes.fromhex(os.environ["TACCTL_TEST_RANDOM"])
n = int(sys.argv[2])
b = (seed * (n // len(seed) + 1))[:n]
if sys.argv[1] == "-hex":
    print(b.hex())
else:
    s = base64.b64encode(b).decode()
    for i in range(0, len(s), 64):
        print(s[i:i + 64])
' "\$2" "\$3"
fi
exec "${real_openssl:-/usr/bin/openssl}" "\$@"
STUB
    chmod +x "${dir}"/*
}

# --- state roots -------------------------------------------------------------------
root_dirs=(etc state/backups/password-dates log bin systemd-dropin systemd sudoers.d raddb radius-log radius-bin radius-share logrotate.d linux tmp)

# sandbox_env <root>: the TACCTL_* variables of one root, one per line.
sandbox_env() {
    local r="$1"
    cat <<ENV
TACCTL_ETC=${r}/etc
TACCTL_STATE_DIR=${r}/state
TACCTL_LOG=${r}/log
TACCTL_BIN=${r}/bin
TACCTL_CONFIG=${r}/etc/tacquito.yaml
TACCTL_OVERRIDE_DIR=${r}/systemd-dropin
TACCTL_SYSTEMD_DIR=${r}/systemd
TACCTL_SUDOERS_FILE=${r}/sudoers.d/tacctl
TACCTL_TIER_SUDOERS_FILE=${r}/sudoers.d/tacctl-tiers
TACCTL_RADIUS_DIR=${r}/raddb
TACCTL_RADIUS_LOG=${r}/radius-log
TACCTL_RADIUS_BIN=${r}/radius-bin/radiusd
TACCTL_RADIUS_DICT=${r}/radius-share/dictionary
TACCTL_LOGROTATE_DIR=${r}/logrotate.d
TACCTL_LINUX_DIR=${r}/linux
TACCTL_SETTLE_SECONDS=0
TACCTL_SKIP_SUDO=1
TACCTL_TEST_NOW=${test_now}
TACCTL_TEST_RANDOM=${test_random}
TMPDIR=${r}/tmp
ENV
}

# exec_in <root> <stubs dir> <bin> <extra env...> -- <args...>: run bin once
# in the sandbox, stdin from $RUN_STDIN, stdout/stderr/status into
# $RUN_OUT, $RUN_ERR, $RUN_RC.
exec_in() {
    local root="$1" stubs="$2" bin="$3"
    shift 3
    local -a extra=()
    while [[ "$1" != -- ]]; do extra+=("$1"); shift; done
    shift
    local -a envv
    mapfile -t envv < <(sandbox_env "$root")
    local rc=0
    (
        cd "$root" || exit 2
        exec env -i "PATH=${stubs}:${EXTRA_PATH:+${EXTRA_PATH}:}${PATH}" "HOME=${root}/../home" LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC TERM=dumb \
            "PYTHONPATH=${work}/pysite" PYTHONDONTWRITEBYTECODE=1 \
            "${envv[@]}" "${extra[@]}" \
            timeout 300 "$bin" "$@" < "${RUN_STDIN}" > "${RUN_OUT}" 2> "${RUN_ERR}"
    ) || rc=$?
    echo "$rc" > "${RUN_RC}"
}

fixture_dir="${work}/fixtures"
mkdir -p "$fixture_dir"

# build_fixture <name>: the state root of a fixture, made once with side A's
# implementation (a fixture is never made by the code under test).
build_fixture() {
    local name="$1" r="${fixture_dir}/${1}/root"
    [[ -d "$r" ]] && return 0
    mkdir -p "$r"
    local d
    for d in "${root_dirs[@]}"; do mkdir -p "${r}/${d}"; done
    : > "${r}/radius-share/dictionary"
    [[ "$name" == none ]] && return 0
    local f="${src}/tests/fixtures/${name}"
    [[ -e "$f" ]] || die "no fixture ${name} (tests/fixtures/${name})"
    if [[ -d "$f" ]]; then
        cp -r "${f}/." "${r}/etc/"
        return 0
    fi
    case "$name" in
        store.*)
            cp "$f" "${r}/state/store.yaml"
            chmod 600 "${r}/state/store.yaml"
            ;;
        tacquito.*.yaml)
            cp "$f" "${r}/etc/tacquito.yaml"
            # Import in a scratch state dir and keep the store file alone, as
            # fixtures.bash does for its seed cache.
            local scratch="${fixture_dir}/${name}/scratch"
            cp -a "$r" "$scratch"
            local out
            RUN_STDIN=/dev/null RUN_OUT="${fixture_dir}/${name}/import.out" RUN_ERR="${fixture_dir}/${name}/import.err" RUN_RC="${fixture_dir}/${name}/import.rc"
            export RUN_STDIN RUN_OUT RUN_ERR RUN_RC
            make_stubs "${fixture_dir}/${name}/stubs" "${fixture_dir}/${name}/calls.log"
            exec_in "$scratch" "${fixture_dir}/${name}/stubs" "$bash_tag" -- store import "$f"
            if [[ "$(cat "$RUN_RC")" != 0 || ! -f "${scratch}/state/store.yaml" ]]; then
                out="$(cat "$RUN_OUT" "$RUN_ERR")"
                die "fixture ${name}: store import failed: ${out}"
            fi
            cp "${scratch}/state/store.yaml" "${r}/state/store.yaml"
            chmod 600 "${r}/state/store.yaml"
            rm -rf "$scratch"
            ;;
        *) cp "$f" "${r}/etc/tacquito.yaml" ;;
    esac
}

# --- normalisation ---------------------------------------------------------------------
# normalise_script <side dir> <command text>: a sed script for one command.
normalise_script() {
    local sidedir="$1" cmdtext="$2" s="${work}/norm.sed" i=0 h
    : > "$s"
    # Hashes that are part of the command line stay as they are.
    local -a keep=()
    # shellcheck disable=SC2016  # the $ are regex text
    mapfile -t keep < <(printf '%s' "$cmdtext" | grep -oE '2432(61|62|79)24[0-9a-f]+|\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}' | sort -u || true)
    for h in "${keep[@]}"; do
        [[ -n "$h" ]] || continue
        i=$((i + 1))
        printf 's|%s|@@KEEP%d@@|g\n' "$(printf '%s' "$h" | sed 's/[][\.*^$|&/]/\\&/g')" "$i" >> "$s"
    done
    {
        ((colour)) || printf 's/\\x1b\\[[0-9;]*[A-Za-z]//g\n'
        printf 's|%s|<ROOT>|g\n' "${sidedir}/root"
        printf 's|%s|<SIDE>|g\n' "$work"
        printf 's|%s|<TREE>|g\n' "$tag_tree" "$src"
        # Longest first, so a version that extends another (a -dirty suffix,
        # commits since the tag) is replaced whole.
        printf '%s\n' "$src_version" "$b_version" "$tag_version" | awk 'NF { print length($0) "\t" $0 }' \
            | sort -rn | cut -f2- | while IFS= read -r v; do printf 's|%s|<VERSION>|g\n' "$v"; done
        printf 's/(tacctl(\\x1b\\[0m)?) \\((unknown|<VERSION>)\\) /\\1 (<VERSION>) /\n'
        printf 's/^tacctl (unknown|<VERSION>)$/tacctl <VERSION>/\n'
        printf 's/[0-9]{8}[_-][0-9]{6}(_[0-9]{3})?/<TS>/g\n'
        printf 's/tmp\\.[A-Za-z0-9]{10}/tmp.<RAND>/g\n'
        printf 's/[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z/<ISO>/g\n'
        printf 's/2432(61|62|79)24[0-9a-f]{4}24[0-9a-f]{100,}/<HASH>/g\n'
        # shellcheck disable=SC2016
        printf 's/\\$2[aby]\\$[0-9]{2}\\$[.\\/A-Za-z0-9]{53}/<HASH>/g\n'
    } >> "$s"
    i=0
    for h in "${keep[@]}"; do
        [[ -n "$h" ]] || continue
        i=$((i + 1))
        printf 's|@@KEEP%d@@|%s|g\n' "$i" "$(printf '%s' "$h" | sed 's/[\&|]/\\&/g')" >> "$s"
    done
    echo "$s"
}

norm() { sed -E -f "$1"; }

# state_dump <side dir> <sed script>: the tree under the root, then the
# contents of its regular files, normalised.
state_dump() {
    local sidedir="$1" script="$2" root="${1}/root" f p t m
    (
        cd "$root"
        find . -mindepth 1 -printf '%P\t%y\t%m\t%l\n' | LC_ALL=C sort | while IFS=$'\t' read -r p t m l; do
            case "$t" in
                f) printf '%s\tfile\t%s\t%s bytes\n' "$(printf '%s' "$p" | norm "$script")" "$m" "$(norm "$script" < "$p" | wc -c)" ;;
                d) printf '%s/\tdir\t%s\n' "$(printf '%s' "$p" | norm "$script")" "$m" ;;
                l) printf '%s\tlink\t%s\n' "$(printf '%s' "$p" | norm "$script")" "$(printf '%s' "$l" | norm "$script")" ;;
                *) printf '%s\t%s\t%s\n' "$(printf '%s' "$p" | norm "$script")" "$t" "$m" ;;
            esac
        done
        echo "--- contents"
        find . -mindepth 1 -type f -print | LC_ALL=C sort | while IFS= read -r f; do
            printf '== %s\n' "$(printf '%s' "${f#./}" | norm "$script")"
            norm "$script" < "$f"
            echo
        done
    )
}

# --- corpus lines ------------------------------------------------------------------------
# unescape <text>: printf %b without treating a leading '-' as an option.
unescape() { printf '%b' "$1"; }

total=0 same=0 differ=0 known=0 failing=0
failed_lines=()

# prepare_side <fixture> <stub args...>: the one sandbox root, fresh from the
# fixture. Both sides run in the same place, one after the other, so a path
# a command writes into a file (a unit's ExecStart, a snapshot's manifest, a
# cached checksum) is the same on both sides and a difference is a real one.
prepare_side() {
    local fx="$1"
    shift
    rm -rf "${work}/side"
    mkdir -p "${work}/side/cwd" "${work}/side/home"
    cp -a "${fixture_dir}/${fx}/root" "${work}/side/root"
    if [[ -n "$EXTRA_ROOT" ]]; then cp -R "${EXTRA_ROOT}/." "${work}/side/root/"; fi
    : > "${work}/side/calls.log"
    make_stubs "${work}/side/stubs" "${work}/side/calls.log" "$@"
}

# expand <line>: the placeholders.
expand() {
    local l="$1"
    l="${l//\{HASH\}/${test_hash}}"
    l="${l//\{FIXTURES\}/${src}/tests/fixtures}"
    l="${l//\{TS\}/${today}_120000_000}"
    l="${l//\{DATE\}/${today}}"
    printf '%s' "$l"
}

# run_line <corpus name> <number> <raw line> <fixture> <known reason or ''> <stubs...>
run_line() {
    local cname="$1" num="$2" raw="$3" fx="$4" knownwhy="$5"
    shift 5
    build_fixture "$fx"

    local -a parts=()
    local expanded
    expanded="$(expand "$raw")"
    local rest="$expanded"
    while [[ "$rest" == *" ;; "* ]]; do
        parts+=("${rest%% ;; *}")
        rest="${rest#* ;; }"
    done
    parts+=("$rest")

    local s idx part args_text stdin_text has_stdin nscript bin last_rc=0
    local -a ie args
    export RUN_OUT="${work}/run.out" RUN_ERR="${work}/run.err" RUN_RC="${work}/run.rc"
    for s in a b; do
        prepare_side "$fx" "$@"
        bin="$bin_a"
        ie=("${impl_env_a[@]}")
        if [[ "$s" == b ]]; then bin="$bin_b"; ie=("${impl_env_b[@]}"); fi
        nscript="$(normalise_script "${work}/side" "$expanded")"
        : > "${work}/cmp-${s}.txt"
        idx=0
        for part in "${parts[@]}"; do
            idx=$((idx + 1))
            args_text="$part"
            stdin_text=""
            has_stdin=0
            if [[ "$part" == *" <<<"* ]]; then
                args_text="${part%% <<<*}"
                stdin_text="${part#*<<<}"
                stdin_text="${stdin_text# }"
                has_stdin=1
            fi
            args=()
            mapfile -d '' -t args < <(printf '%s' "$args_text" | xargs -r printf '%s\0')
            if ((has_stdin)); then
                { unescape "$stdin_text"; printf '\n'; } > "${work}/stdin.txt"
                RUN_STDIN="${work}/stdin.txt"
            else
                RUN_STDIN=/dev/null
            fi
            export RUN_STDIN
            exec_in "${work}/side/root" "${work}/side/stubs" "$bin" "${ie[@]}" "${EXTRA_ENV[@]}" -- "${args[@]}"
            {
                echo "### command ${idx}: tacctl ${part}"
                echo "--- exit"
                cat "$RUN_RC"
                echo "--- stdout"
                norm "$nscript" < "$RUN_OUT"
                echo "--- stderr"
                norm "$nscript" < "$RUN_ERR"
            } >> "${work}/cmp-${s}.txt"
            last_rc="$(cat "$RUN_RC")"
        done
        if [[ "$s" == a && "$last_rc" != 0 ]]; then failing=$((failing + 1)); fi
        {
            echo "### after the last command"
            echo "--- system commands called"
            norm "$nscript" < "${work}/side/calls.log"
            echo "--- state"
            state_dump "${work}/side" "$nscript"
        } >> "${work}/cmp-${s}.txt"
    done

    local cmp_a="${work}/cmp-a.txt" cmp_b="${work}/cmp-b.txt"
    total=$((total + 1))
    local tagline="${cname}:${num}"
    if diff -q "$cmp_a" "$cmp_b" > /dev/null; then
        same=$((same + 1))
        if [[ -n "$knownwhy" ]]; then
            printf 'ok     %-14s %s   (marked @known, but no difference: drop the marker)\n' "$tagline" "$raw"
        else
            printf 'ok     %-14s %s\n' "$tagline" "$raw"
        fi
        return 0
    fi
    if [[ -n "$knownwhy" ]]; then
        known=$((known + 1))
        printf 'known  %-14s %s   [%s]\n' "$tagline" "$raw" "$knownwhy"
        return 0
    fi
    differ=$((differ + 1))
    failed_lines+=("${tagline}: ${raw}")
    printf 'DIFF   %-14s %s\n' "$tagline" "$raw"
    diff -u --label "A: ${tag}" --label "B: ${label_b}" "$cmp_a" "$cmp_b" | sed 's/^/    /' || true
    return 0
}

declare -a EXTRA_ENV=()
EXTRA_PATH="" EXTRA_ROOT=""
run_corpus() {
    local file="$1" cname
    cname="$(basename "$file" .txt)"
    local fx=tacquito.minimal.yaml knownwhy="" num=0 raw
    local -a stubargs=()
    EXTRA_ENV=()
    EXTRA_PATH="" EXTRA_ROOT=""
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        num=$((num + 1))
        raw="${raw%"${raw##*[![:space:]]}"}"   # trailing blanks
        case "$raw" in
            ""|\#*) continue ;;
            @fixture\ *) fx="${raw#@fixture }"; continue ;;
            @env\ *) EXTRA_ENV+=("${raw#@env }"); continue ;;
            @unenv\ *)
                local k="${raw#@unenv }" kept=() e
                for e in "${EXTRA_ENV[@]}"; do [[ "${e%%=*}" == "$k" ]] || kept+=("$e"); done
                EXTRA_ENV=("${kept[@]}")
                continue
                ;;
            @stub\ *)
                local -a sp
                read -ra sp <<< "${raw#@stub }"
                [[ ${#sp[@]} -eq 2 ]] || die "${file}:${num}: @stub <name> <rc>"
                stubargs+=("${sp[0]}" "${sp[1]}")
                continue
                ;;
            @known\ *) knownwhy="${raw#@known }"; continue ;;
            @path\ *)
                [[ -d "${src}/${raw#@path }" ]] || die "${file}:${num}: no directory ${raw#@path }"
                EXTRA_PATH="${EXTRA_PATH:+${EXTRA_PATH}:}${src}/${raw#@path }"
                continue
                ;;
            @root\ *)
                [[ -d "${src}/${raw#@root }" ]] || die "${file}:${num}: no directory ${raw#@root }"
                EXTRA_ROOT="${src}/${raw#@root }"
                continue
                ;;
            @*) die "${file}:${num}: unknown directive ${raw%% *}" ;;
        esac
        if [[ -n "$filter" ]] && ! [[ "$raw" =~ $filter ]]; then
            knownwhy=""
            continue
        fi
        run_line "$cname" "$num" "$raw" "$fx" "$knownwhy" "${stubargs[@]}"
        knownwhy=""
    done < "$file"
}

summary() {
    echo
    echo "A: ${tag} (bin/tacctl.sh)    B: ${label_b}    ${total} command lines: ${same} same, ${differ} differ, ${known} known"
    echo "lines whose last command fails under A: ${failing} of ${total} (a corpus wants at least as many failing lines as succeeding ones)"
    if ((differ)); then
        echo "unexplained differences:"
        printf '  %s\n' "${failed_lines[@]}"
    fi
}

if ((selftest)); then
    # 1. Both sides bash: no difference, whatever the clock and the salts do.
    echo "== self-test 1: A and B both ${tag} bash, expect no difference"
    out1="$("$0" --against "$tag" --b bash "${here}/corpus/selftest.txt")" || { echo "$out1"; echo "SELF-TEST FAILED: bash against bash reports a difference" >&2; exit 1; }
    echo "$out1" | tail -n 2
    # 2. A side that misbehaves in three ways is caught, and @known holds.
    echo "== self-test 2: a mutant B, expect four differing lines and one known"
    mutant="${work}/mutant.sh"
    cat > "$mutant" <<MUT
#!/bin/sh
"${bash_tag}" "\$@"; rc=\$?
case "\$1 \$2" in
    "user list") echo MUTANT-OUTPUT ;;
    "scope list") touch "\$TACCTL_STATE_DIR/stray-file" ;;
    "hash commands") exit 3 ;;
    "config defaults") echo MUTANT-KNOWN ;;
esac
exit \$rc
MUT
    chmod +x "$mutant"
    rc2=0
    out2="$("$0" --against "$tag" --b "$mutant" --filter '^(user list|scope list|hash commands|config defaults)' "${here}/corpus/selftest.txt")" || rc2=$?
    ok=1
    [[ "$rc2" -eq 1 ]] || { echo "expected exit 1 from the mutant run, got ${rc2}"; ok=0; }
    for needle in 'DIFF   selftest:.*user list' 'DIFF   selftest:.*scope list' 'DIFF   selftest:.*hash commands' 'known  selftest:.*config defaults' '^    \+MUTANT-OUTPUT$' 'stray-file' '^    \+3$'; do
        grep -qE -- "$needle" <<< "$out2" || { echo "mutant run: no '${needle}' in the report"; ok=0; }
    done
    grep -qE 'DIFF   selftest:.*config defaults' <<< "$out2" && { echo "mutant run: @known line reported as DIFF"; ok=0; }
    ((ok)) || { echo "$out2"; echo "SELF-TEST FAILED" >&2; exit 1; }
    echo "$out2" | tail -n 8
    echo "self-test passed"
    exit 0
fi

for c in "${corpora[@]}"; do
    run_corpus "$c"
done
summary
((differ == 0))
