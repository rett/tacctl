#!/bin/bash
# The whole container matrix, unattended, one case after another, ending in a
# PASS/FAIL table with a log and a duration per case (tests/README.md, "The
# whole container matrix"):
#
#   tests/containers/run-all.sh [--only <case>]... [--skip <case>]... [--list]
#                               [--keep] [--logs <dir>] [--timeout <seconds>]
#                               [--min-free-gb <n>] [--jobs 1] [--no-preflight]
#
#   --list           print the cases (name, command, images) and stop
#   --only, --skip   run only / leave out the named cases; repeatable, or a
#                    comma list. A name is a case's name or a prefix of it
#                    ('hosts-rotate' is both rotate cases)
#   --keep           pass --keep to the scripts: the containers of a case are
#                    left (thc-server, thc-client-<client>, tacctl-fresh...)
#                    until the next case replaces them; with one case, for a look
#   --logs <dir>     where the logs and summary.txt go (default
#                    ${TMPDIR:-/tmp}/tacctl-containers.<time>)
#   --timeout <s>    per case (default 3000)
#   --min-free-gb    free space the preflight wants where podman keeps its
#                    images (default 6)
#   --jobs 1         the only value: the cases share container names and the
#                    network tacctl-host-check, so they never run in parallel
#   --no-preflight   skip the checks of the machine (not the images)
#
# Needs rootless podman, /usr/local/bin/tacquito, Go, python3 with bcrypt,
# ssh-keygen and git on this machine, and network access for the images that
# are not built yet (package mirrors, dl.google.com, GitHub for tacquito's
# source in the fresh case). Nothing on this machine is touched outside
# podman and temp directories. Containers the scripts make are named thc-*,
# tacctl-fresh*, tacctl-radius-check-*; images localhost/tacctl-host-check:*,
# tacctl-radius-check:*, tacctl-fresh:*; network tacctl-host-check. The
# preflight refuses to start when containers of those names exist already
# (another run on this machine would be killed by these scripts).
#
# A case that fails without a single FAIL line (an image build, a mirror, a
# crash) is run once more as an infrastructure flake; both logs are kept
# (<case>.attempt1.log, <case>.log) and the table says "retry". A case with a
# FAIL line is a result and is not run again.
#
# Exit 0 only when every case that ran passed.
# shellcheck disable=SC2016  # the commands are text, run by 'bash -c'
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"

ONLY=(); SKIP=(); LIST=""; KEEP=""; LOGS=""; TIMEOUT=3000; MINFREE=6; PREFLIGHT=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --only) IFS=, read -r -a _a <<< "${2:?--only needs a case}"; ONLY+=("${_a[@]}"); shift 2 ;;
        --skip) IFS=, read -r -a _a <<< "${2:?--skip needs a case}"; SKIP+=("${_a[@]}"); shift 2 ;;
        --list) LIST=yes; shift ;;
        --keep) KEEP="--keep"; shift ;;
        --logs) LOGS="${2:?--logs needs a directory}"; shift 2 ;;
        --timeout) TIMEOUT="${2:?--timeout needs seconds}"; shift 2 ;;
        --min-free-gb) MINFREE="${2:?--min-free-gb needs a number}"; shift 2 ;;
        --jobs) [[ "${2:-}" == 1 ]] || { echo "--jobs: only 1 (the cases share container names)" >&2; exit 2; }; shift 2 ;;
        --no-preflight) PREFLIGHT=""; shift ;;
        -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1 (see --help)" >&2; exit 2 ;;
    esac
done

# --- the cases ------------------------------------------------------------------
NAMES=(); CMDS=(); IMGS=(); WHAT=()
H=localhost/tacctl-host-check
case_() { NAMES+=("$1"); CMDS+=("$2"); IMGS+=("$3"); WHAT+=("$4"); } # name command images what
case_ hosts-tacplus      "hosts/run.sh ubuntu-noble tacplus"   "$H:server-ubuntu-noble $H:client-ubuntu-noble"   "Ubuntu client, pam_tacplus: login, sudo, sync, engineer tier, unenroll"
case_ hosts-switch       "hosts/run.sh ubuntu-noble switch"    "$H:server-ubuntu-noble $H:client-ubuntu-noble"   "Ubuntu client, tacplus -> radius -> tacplus"
case_ hosts-radius-alma  "hosts/run.sh almalinux-9 radius"     "$H:server-ubuntu-noble $H:client-almalinux-9"    "AlmaLinux 9 client, pam_radius_auth"
case_ hosts-radius-fr30  "hosts/run.sh almalinux-9 radius --server almalinux-9" "$H:server-almalinux-9 $H:client-almalinux-9" "AlmaLinux 9 client, AlmaLinux 9 server (FreeRADIUS 3.0.27)"
case_ hosts-rotate       "hosts/run.sh ubuntu-noble rotate"    "$H:server-ubuntu-noble $H:client-ubuntu-noble"   "provisioning-account rotation on Ubuntu"
case_ hosts-rotate-alma  "hosts/run.sh almalinux-9 rotate"     "$H:server-ubuntu-noble $H:client-almalinux-9"    "provisioning-account rotation on AlmaLinux 9 (restorecon)"
case_ hosts-rollback     "hosts/run.sh ubuntu-noble rollback"  "$H:server-ubuntu-noble $H:client-ubuntu-noble"   "tacctl rollback 0.2.2 --hosts: the engineer loses sudo, nobody else changes"
case_ hosts-server       "hosts/run.sh ubuntu-noble server"    "$H:server-ubuntu-noble $H:client-ubuntu-noble"   "real tacquito answers the baseline rules of the four roles (permcheck); this server enrolled as a host: engineer group, sudoers, sshd drop-ins"
case_ radius             "radius/run.sh ubuntu-noble"          "localhost/tacctl-radius-check:ubuntu-noble"      "real FreeRADIUS: enable, cases, mutations, listeners, uninstall"
case_ fresh              "fresh/run.sh --worktree"             "localhost/tacctl-fresh:noble"                    "fresh install of this working tree on a server without Go"
case_ upgrade           "fresh/upgrade.sh"                    "localhost/tacctl-fresh:noble"                    "0.2.2 server with state, tacctl upgrade to this tree, rollback 0.2.2, the 0.2.2 binary on the result"

selected() { # selected <name>
    local n="$1" p ok=1
    if [[ ${#ONLY[@]} -gt 0 ]]; then
        ok=""
        for p in "${ONLY[@]}"; do [[ "$n" == "$p" || "$n" == "$p"-* ]] && ok=1; done
    fi
    for p in "${SKIP[@]}"; do [[ "$n" == "$p" || "$n" == "$p"-* ]] && ok=""; done
    [[ -n "$ok" ]]
}
for p in "${ONLY[@]}" "${SKIP[@]}"; do
    found=""
    for n in "${NAMES[@]}"; do [[ "$n" == "$p" || "$n" == "$p"-* ]] && found=1; done
    [[ -n "$found" ]] || { echo "no case named ${p} (see --list)" >&2; exit 2; }
done

if [[ -n "$LIST" ]]; then
    printf '%-18s %-62s %s\n' CASE COMMAND WHAT
    for i in "${!NAMES[@]}"; do
        selected "${NAMES[$i]}" || continue
        printf '%-18s %-62s %s\n' "${NAMES[$i]}" "tests/containers/${CMDS[$i]}" "${WHAT[$i]}"
        printf '%-18s   images: %s\n' "" "${IMGS[$i]}"
    done
    exit 0
fi

# --- preflight --------------------------------------------------------------------
pre_fail=0
pre() { # pre <description> <command...>
    local d="$1"; shift
    if "$@" > /dev/null 2>&1; then echo "  ok    ${d}"; else echo "  FAIL  ${d}"; pre_fail=1; fi
}
GO="$(command -v go || echo /usr/local/go/bin/go)"
if [[ -n "$PREFLIGHT" ]]; then
    echo "preflight"
    pre "not root (the scripts are for rootless podman)" test "$(id -u)" -ne 0
    pre "podman works (podman info)" podman info
    pre "podman is rootless" test "$(podman info --format '{{.Host.Security.Rootless}}' 2> /dev/null)" = true
    pre "/usr/local/bin/tacquito is executable (the server image takes it)" test -x /usr/local/bin/tacquito
    pre "go is installed (${GO})" test -x "$GO"
    pre "python3 can import bcrypt (radius/make-store.py)" python3 -c 'import bcrypt'
    pre "ssh-keygen and git are installed" bash -c 'command -v ssh-keygen && command -v git'
    pre "the repository is a git checkout (fresh/run.sh makes a bare clone of it)" git -C "$REPO" rev-parse --git-dir
    graph="$(podman info --format '{{.Store.GraphRoot}}' 2> /dev/null)"
    free=$(df --output=avail -BG "${graph:-/}" 2> /dev/null | tail -1 | tr -dc '0-9')
    pre "free space under podman's storage ${free:-?} GB (wants ${MINFREE})" test "${free:-0}" -ge "$MINFREE"
    foreign=$(podman ps -a --format '{{.Names}}' 2> /dev/null | grep -E '^(thc-|tacctl-fresh|tacctl-radius-check-)' | paste -sd' ')
    if [[ -n "$foreign" ]]; then
        echo "  FAIL  containers of the scripts' names exist already (${foreign}): another run? Remove them (podman rm -f ...) or wait"
        pre_fail=1
    else
        echo "  ok    no container of the scripts' names exists"
    fi
    if (( pre_fail )); then echo "preflight failed: nothing was run"; exit 2; fi
fi
echo "images"
need_net=""; img_lines=()
for i in "${!NAMES[@]}"; do
    selected "${NAMES[$i]}" || continue
    for img in ${IMGS[$i]}; do
        if podman image exists "$img" 2> /dev/null; then img_lines+=("  present   ${img}"); else img_lines+=("  to build  ${img}   (${NAMES[$i]})"); need_net=1; fi
    done
done
printf '%s\n' "${img_lines[@]}" | sort -u
[[ -z "$need_net" ]] || echo "  (images that are not present are built by the case's script, with network access)"

LOGS="${LOGS:-${TMPDIR:-/tmp}/tacctl-containers.$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$LOGS"
echo "logs: ${LOGS}"
echo "tree: $(git -C "$REPO" log -1 --format=%h) + $(git -C "$REPO" status --porcelain | wc -l) changed paths"
echo

# --- run -----------------------------------------------------------------------------
sweep() { # remove what a killed case may have left (exact names, ours only)
    local n
    for n in $(podman ps -a --format '{{.Names}}' 2> /dev/null | grep -E '^(thc-|tacctl-fresh|tacctl-radius-check-)'); do
        podman rm -f -t 0 "$n" > /dev/null 2>&1 || true
    done
}
RES=(); DUR=(); NFAIL=(); NPASS=(); ATT=(); LOGF=()
rc_all=0; t_all=$(date +%s)
run_one() { # run_one <command> <log> -> exit status
    local cmd="$1" log="$2"
    # shellcheck disable=SC2086  # the command is words
    timeout -k 60 "$TIMEOUT" "${HERE}/"${cmd} ${KEEP} > "$log" 2>&1
}
for i in "${!NAMES[@]}"; do
    n="${NAMES[$i]}"
    selected "$n" || continue
    log="${LOGS}/${n}.log"
    echo "=== ${n}: tests/containers/${CMDS[$i]}"
    t0=$(date +%s); att=1
    run_one "${CMDS[$i]}" "$log"; rc=$?
    nf=$(grep -c '^FAIL' "$log")
    if [[ $rc -ne 0 && $nf -eq 0 ]]; then
        echo "    no FAIL line (exit ${rc}): an infrastructure problem? one more try; the first log is ${n}.attempt1.log"
        tail -3 "$log" | sed 's/^/    | /'
        mv "$log" "${LOGS}/${n}.attempt1.log"
        sweep
        att=2
        run_one "${CMDS[$i]}" "$log"; rc=$?
        nf=$(grep -c '^FAIL' "$log")
    fi
    [[ -n "$KEEP" ]] || sweep
    t1=$(date +%s)
    np=$(grep -c '^PASS' "$log")
    if [[ $rc -eq 0 && $nf -eq 0 ]]; then r=PASS; else r=FAIL; rc_all=1; fi
    [[ $rc -eq 124 || $rc -eq 137 ]] && r="FAIL (timeout)"
    RES+=("$r"); DUR+=("$((t1 - t0))"); NFAIL+=("$nf"); NPASS+=("$np"); ATT+=("$att"); LOGF+=("$log")
    printf '    %s: %s PASS, %s FAIL lines, exit %s, %ss\n' "$r" "$np" "$nf" "$rc" "$((t1 - t0))"
    [[ $nf -eq 0 ]] || grep '^FAIL' "$log" | head -8 | sed 's/^/    | /'
done

# --- the table ---------------------------------------------------------------------------
fmt() { printf '%dm%02ds' "$(($1 / 60))" "$(($1 % 60))"; }
{
    echo
    printf '%-18s %-15s %6s %6s %6s %9s  %s\n' CASE RESULT PASS FAIL TRIES TIME LOG
    k=0
    for i in "${!NAMES[@]}"; do
        selected "${NAMES[$i]}" || continue
        printf '%-18s %-15s %6s %6s %6s %9s  %s\n' "${NAMES[$i]}" "${RES[$k]}" "${NPASS[$k]}" "${NFAIL[$k]}" "${ATT[$k]}" "$(fmt "${DUR[$k]}")" "${LOGF[$k]}"
        k=$((k + 1))
    done
    echo
    echo "total $(fmt $(( $(date +%s) - t_all ))), $([[ $rc_all -eq 0 ]] && echo 'all passed' || echo 'FAILED')"
    echo "(TRIES 2: the first attempt failed without a FAIL line and was run again; its log is <case>.attempt1.log)"
} | tee "${LOGS}/summary.txt"
exit "$rc_all"
