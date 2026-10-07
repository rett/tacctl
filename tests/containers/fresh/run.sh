#!/bin/bash
# Fresh install of tacctl on a clean server, the release gate's item 8
# (docs/plans/go-rewrite.md 6.6): rootless podman, an ubuntu:noble container
# with systemd and nothing a server would not have before tacctl (no Go, no
# Python), nothing on this machine touched outside podman and a temp dir.
#
#   tests/containers/fresh/run.sh [--rev <commit> | --worktree | --release <tag>] [--rollback] [--keep]
#
# The container installs with the README one-liner, but its git fetches
# https://github.com/rett/tacctl.git from a bare clone of this repository
# made in the temp dir, whose master is <commit> (default HEAD), or, with
# --worktree, this checkout's tracked files as they are (a 'git stash
# create' commit; no ref of this repository changes). Then: the shim installs Go (downloaded from dl.google.com and
# checked against its published SHA-256) and builds /usr/local/bin/tacctl;
# 'version --long'; 'user passwd engineer' answered through a pty;
# 'config cisco --scope lab'; 'uninstall -y'; and what is left on the
# container's filesystem that was not there before the install and is not
# there either in a second container that only installed the same packages.
#
# --release <tag> installs a published release (docs/releasing.md): the bare
# clone's master is the tag's commit and the tag is pushed into it too, so
# the clone is at the tag and the shim downloads the release assets from
# GitHub (the real ones: it can only run after the release is published, and
# the tag must be in this repository). openssh-client (ssh-keygen) is
# installed in the container first; the check is that the install says
# 'Installing the <tag> release binary (linux/amd64, verified)' and builds
# no tacctl. Without it a server with no ssh-keygen builds from source, which
# the default run covers.
#
# --rollback adds, before the uninstall, the way back to the last bash
# release and forward again: 'upgrade --branch <bash release tag>' (the
# hand-over, which must first install python3, python3-yaml and
# python3-bcrypt: the bash release cannot start without them), 'upgrade' on
# the tag, 'upgrade --branch master', 'upgrade'.
#
# Needs network access (Ubuntu mirrors, dl.google.com, GitHub for tacquito,
# the Go module proxy). Prints PASS/FAIL lines and exits non-zero on a FAIL.
# The image (localhost/tacctl-fresh:noble) is built once and kept.
# shellcheck disable=SC2016  # the single-quoted scripts run inside the container
set -uo pipefail
export LC_ALL=C  # one collation for sort and comm, here and in the containers
REV="HEAD"; KEEP=""; ROLLBACK=""; RELEASE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --rev) REV="${2:?--rev needs a commit}"; shift 2 ;;
        --worktree) REV="worktree"; shift ;;
        --release) RELEASE="${2:?--release needs a tag}"; REV="$RELEASE"; shift 2 ;;
        --rollback) ROLLBACK="yes"; shift ;;
        --keep) KEEP="yes"; shift ;;
        *) echo "usage: run.sh [--rev <commit> | --worktree | --release <tag>] [--rollback] [--keep]" >&2; exit 2 ;;
    esac
done
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../../.." && pwd)"
IMAGE=localhost/tacctl-fresh:noble
C=tacctl-fresh
PW='Fresh-Install-Pw-7319'

WORK=$(mktemp -d)
cleanup() {
    [[ -n "$KEEP" ]] || podman rm -f -t 0 "$C" > /dev/null 2>&1 || true
    podman rm -f -t 0 "${C}-control" > /dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "PASS  $1"; }
bad() { fail=$((fail + 1)); echo "FAIL  $1"; }
section() { echo; echo "=== $1"; }
q() { podman exec -e LC_ALL=C "$C" bash -c "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; return "${PIPESTATUS[0]}"; }
# timed <label> <command>: run in the container, print the output and the time.
timed() {
    local t0 rc
    section "$1"
    t0=$(date +%s)
    q "$2"; rc=$?
    echo "--- exit ${rc}, $(( $(date +%s) - t0 )) s"
    return "$rc"
}

# --- the commit, as the master of a scratch bare clone -------------------------
if [[ "$REV" == "worktree" ]]; then
    COMMIT=$(git -C "$REPO" stash create "fresh-install check: the working tree")
    [[ -n "$COMMIT" ]] || COMMIT=$(git -C "$REPO" rev-parse HEAD)
else
    COMMIT=$(git -C "$REPO" rev-parse --verify "${REV}^{commit}") || exit 2
fi
git clone -q --bare "$REPO" "${WORK}/tacctl.git" || exit 1
# A push carries the commit even when no ref of this repository names it.
git -C "$REPO" push -q --force --no-verify "${WORK}/tacctl.git" "${COMMIT}:refs/heads/master" || exit 1
if [[ -n "$RELEASE" ]]; then
    git -C "$REPO" rev-parse -q --verify "refs/tags/${RELEASE}" > /dev/null || { echo "no tag ${RELEASE} in ${REPO}" >&2; exit 2; }
    git -C "$REPO" push -q --force --no-verify "${WORK}/tacctl.git" "refs/tags/${RELEASE}:refs/tags/${RELEASE}" || exit 1
fi
git -C "${WORK}/tacctl.git" symbolic-ref HEAD refs/heads/master
echo "installing $(git -C "$REPO" describe --tags --always "$COMMIT") (${COMMIT})"

# --- image: systemd, what the README asks for (git, wget), sudo, iproute2 ----
if ! podman image exists "$IMAGE"; then
    echo "--- building ${IMAGE}"
    podman rm -f -t 0 "${C}-build" > /dev/null 2>&1 || true
    podman run -d --name "${C}-build" docker.io/library/ubuntu:noble sleep infinity > /dev/null || exit 1
    podman exec "${C}-build" bash -c 'export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus sudo git wget ca-certificates iproute2 > /dev/null' || exit 1
    podman commit -q "${C}-build" "$IMAGE" > /dev/null
    podman rm -f -t 0 "${C}-build" > /dev/null
fi

podman rm -f -t 0 "$C" > /dev/null 2>&1 || true
# SYS_ADMIN: systemd's unit sandboxing in a rootless container.
podman run -d --name "$C" --hostname "$C" --systemd=always --cap-add SYS_ADMIN \
    -v "${WORK}/tacctl.git:/srv/tacctl.git:ro" "$IMAGE" /sbin/init > /dev/null || exit 1
sleep 5
podman exec "$C" git config --global url./srv/tacctl.git.insteadOf https://github.com/rett/tacctl.git
BASH_RELEASE=$(sed -n 's/^TACCTL_BASH_RELEASE="\(.*\)"$/\1/p' "${REPO}/bin/tacctl.sh")

if [[ -n "$RELEASE" ]]; then
    podman exec "$C" bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-client > /dev/null' || exit 1
fi

section "before the install"
q 'for p in go python3 tacctl; do printf "%s: %s\n" "$p" "$(command -v "$p" || echo absent)"; done; ls -d /usr/local/go 2>&1'
if q 'command -v go || command -v python3 || test -e /usr/local/go' > /dev/null; then
    bad "the container is clean (no Go, no Python)"
else
    ok "the container is clean (no Go, no Python)"
fi
# What is on the filesystem now, the packages and the accounts.
snap() { # snap <name>
    q "find / -xdev \\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp \\) -prune -o -print | sort > /var/tmp/files.$1
        dpkg-query -W -f '\${Package}\n' | sort > /var/tmp/pkgs.$1
        cut -d: -f1 /etc/passwd | sort > /var/tmp/users.$1" > /dev/null
}
snap before

# --- install: the README one-liner ----------------------------------------------
out=$(timed "install (README one-liner, answering y)" \
    "echo y | sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl && /opt/tacctl/bin/tacctl.sh install'"); rc=$?
echo "$out"
if [[ $rc == 0 ]]; then ok "install"; else bad "install"; fi
if [[ -n "$RELEASE" ]]; then
    if grep -q "Installing the ${RELEASE} release binary (linux/amd64, verified)" <<< "$out" \
        && ! grep -q 'Building /usr/local/bin/tacctl' <<< "$out"; then
        ok "the ${RELEASE} release binary was downloaded, verified and installed (nothing built)"
    else
        bad "the ${RELEASE} release binary was downloaded, verified and installed: $(grep -E 'Release binary|Building /usr' <<< "$out" | head -2)"
    fi
fi
out=$(q '/usr/local/go/bin/go version')
if [[ "$out" == "go version go1."* ]]; then ok "the shim installed Go: ${out}"; else bad "the shim installed Go (got: ${out})"; fi
check() { if q "$2" > /dev/null; then ok "$1"; else bad "$1"; fi; }
check "/usr/local/bin/tacctl is a regular file, not a link" 'test -f /usr/local/bin/tacctl && ! test -L /usr/local/bin/tacctl'
check "python3 is still absent" '! command -v python3'
check "tacquito is active" 'systemctl is-active --quiet tacquito'

section "tacctl version --long"
out=$(q 'tacctl version --long'); echo "$out"
short=$(git -C "$REPO" rev-parse "$COMMIT")
if grep -q "commit: *${short}" <<< "$out" && grep -q 'test knobs: off' <<< "$out" && grep -q 'go: *go1.26.2' <<< "$out"; then
    ok "version --long: this commit, go1.26.2, test knobs off"
else
    bad "version --long: this commit, go1.26.2, test knobs off"
fi

# --- user passwd engineer through a pty -----------------------------------------
# The answers are typed after a pause, as a person would, so they reach the
# prompts and not the terminal before the prompt turned echo off.
timed "user passwd engineer (through a pty)" \
    "{ sleep 2; printf '%s\r' '${PW}'; sleep 1; printf '%s\r' '${PW}'; sleep 3; } | script -qfec 'tacctl user passwd engineer' /dev/null"
out=$(q 'tacctl user list'); echo "$out"
if [[ $(grep -E '^ *engineer ' <<< "$out") == *active* ]]; then ok "engineer is enabled"; else bad "engineer is enabled"; fi
out=$(q "{ sleep 2; printf '%s\r' '${PW}'; sleep 3; } | script -qfec 'tacctl user verify engineer' /dev/null")
echo "$out" | tail -2
if grep -q 'Password is correct' <<< "$out"; then ok "user verify engineer accepts the new password"; else bad "user verify engineer accepts the new password"; fi

# --- a device config --------------------------------------------------------------
out=$(q 'tacctl config cisco --scope lab'); rc=$?
echo "$out" | grep -E 'tacacs server|Using template|address ipv4' | head -5
# install put the shipped templates in /etc/tacctl/templates, so that copy is
# the one used; the server address comes from the route lookup.
if [[ $rc == 0 ]] && grep -q 'Using template: /etc/tacctl/templates/cisco.template' <<< "$out" \
    && ! grep -q '<TACQUITO_SERVER_IP>' <<< "$out"; then
    ok "config cisco --scope lab (installed template, the server's address)"
else
    bad "config cisco --scope lab (exit ${rc})"
fi
check "status" 'tacctl status'
out=$(q 'tacctl config validate'); rc=$?; echo "$out" | tail -2
if [[ $rc == 0 ]]; then ok "config validate"; else bad "config validate (exit ${rc})"; fi

# --- the way back to the bash release and forward again -------------------------
verify_pw() { [[ $(q "{ sleep 2; printf '%s\r' '${PW}'; sleep 3; } | script -qfec 'tacctl user verify engineer' /dev/null") == *'Password is correct'* ]]; }
if [[ -n "$ROLLBACK" ]]; then
    # The bash release runs python3 (with yaml and bcrypt) from its first
    # line; a server installed with 0.2.0 has none of them, so the hand-over
    # installs them.
    check "python3 is absent before the way back" '! command -v python3'
    store=$(q 'sha256sum /etc/tacctl/store.yaml')
    out=$(timed "upgrade --branch ${BASH_RELEASE} (back to the bash release)" "tacctl upgrade --branch ${BASH_RELEASE}"); rc=$?
    echo "$out" | grep -E 'Switched|bash release needs|handing over|Management scripts|Restarting|restart|ERROR|--- exit'
    if [[ $rc == 0 ]] && grep -q 'Target branch is a bash release of tacctl; handing over.' <<< "$out"; then ok "upgrade --branch ${BASH_RELEASE} hands over"; else bad "upgrade --branch ${BASH_RELEASE} hands over (exit ${rc})"; fi
    if grep -q 'Installing packages the bash release needs: python3 python3-yaml python3-bcrypt' <<< "$out"; then ok "the hand-over installed python3, python3-yaml, python3-bcrypt first"; else bad "the hand-over installed python3, python3-yaml, python3-bcrypt first"; fi
    check "python3 imports yaml and bcrypt" 'python3 -c "import yaml, bcrypt"'
    q "ls -l /usr/local/bin/tacctl; tacctl version; git -C /opt/tacctl describe --tags; git -C /opt/tacctl status -sb | head -1"
    check "the command is the link to the bash release's entrypoint" '[[ $(readlink /usr/local/bin/tacctl) == /opt/tacctl/bin/tacctl.sh ]]'
    check "tacctl version is ${BASH_RELEASE}" "[[ \$(tacctl version) == 'tacctl ${BASH_RELEASE}' ]]"
    check "tacquito is active" 'systemctl is-active --quiet tacquito'
    check "status (bash)" 'tacctl status'
    check "config validate (bash)" 'tacctl config validate'
    check "the store is unchanged" "[[ \$(sha256sum /etc/tacctl/store.yaml) == '${store}' ]]"
    if verify_pw; then ok "user verify engineer (bash)"; else bad "user verify engineer (bash)"; fi
    out=$(timed "upgrade on the tag" 'tacctl upgrade'); rc=$?
    echo "$out" | grep -E 'Management scripts|Restarting|ERROR|--- exit'
    if [[ $rc == 0 && $(q 'tacctl version') == "tacctl ${BASH_RELEASE}" ]]; then ok "upgrade on the tag stays on ${BASH_RELEASE}"; else bad "upgrade on the tag stays on ${BASH_RELEASE} (exit ${rc})"; fi
    out=$(timed "upgrade --branch master (forward again)" 'tacctl upgrade --branch master'); rc=$?
    echo "$out" | grep -E 'Switched|Building|restarting upgrade|Management scripts|ERROR|--- exit'
    if [[ $rc == 0 ]]; then ok "upgrade --branch master"; else bad "upgrade --branch master (exit ${rc})"; fi
    check "/usr/local/bin/tacctl is a regular file again" 'test -f /usr/local/bin/tacctl && ! test -L /usr/local/bin/tacctl'
    check "version --long: this commit" "tacctl version --long | grep -q 'commit: *${short}'"
    check "tacquito is active" 'systemctl is-active --quiet tacquito'
    check "status" 'tacctl status'
    check "config validate" 'tacctl config validate'
    check "the store is unchanged" "[[ \$(sha256sum /etc/tacctl/store.yaml) == '${store}' ]]"
    if verify_pw; then ok "user verify engineer"; else bad "user verify engineer"; fi
    out=$(timed "upgrade again (expect nothing built)" 'tacctl upgrade'); rc=$?
    echo "$out" | grep -E 'Building|restarting upgrade|Restarting|Management scripts|ERROR|--- exit'
    if [[ $rc == 0 ]] && ! grep -q 'Building' <<< "$out"; then ok "a second upgrade builds nothing"; else bad "a second upgrade builds nothing (exit ${rc})"; fi
fi

# --- uninstall -y and what is left ------------------------------------------------
if timed "uninstall -y" 'tacctl uninstall -y'; then ok "uninstall -y"; else bad "uninstall -y"; fi
snap after
section "left behind"
# A second container from the same image that only installs the packages
# the install added: whatever is in it too belongs to the packages
# (alternatives, caches, generated configuration), not to tacctl.
pkgs=$(q 'comm -13 /var/tmp/pkgs.before /var/tmp/pkgs.after' | paste -sd' ')
podman rm -f -t 0 "${C}-control" > /dev/null 2>&1 || true
podman run -d --name "${C}-control" --systemd=always --cap-add SYS_ADMIN "$IMAGE" /sbin/init > /dev/null || exit 1
sleep 5
podman exec -e LC_ALL=C "${C}-control" bash -c "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq ${pkgs} > /dev/null 2>&1
    find / -xdev \\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp \\) -prune -o -print | sort" > "${WORK}/files.control"
podman rm -f -t 0 "${C}-control" > /dev/null
q 'cat /var/tmp/files.before' > "${WORK}/files.before"
q 'cat /var/tmp/files.after' > "${WORK}/files.after"
# Not counted besides: logs and the package and service managers' state,
# this check's own git configuration (/root/.gitconfig) and lists.
left=$(sort -u "${WORK}/files.before" "${WORK}/files.control" | comm -13 - "${WORK}/files.after" \
    | grep -vE '^/(var/lib/(dpkg|apt|systemd)|var/cache|var/log)(/|$)|^/(root/\.gitconfig|var/tmp/[^/]*)$')
# Collapse the expected roots to one line each.
summ=$(awk '
    /^\/usr\/local\/go(\/|$)/              { k["/usr/local/go"]++; next }
    /^\/opt\/tacquito-src(\/|$)/           { k["/opt/tacquito-src"]++; next }
    /^\/root\/go(\/|$)/                    { k["/root/go"]++; next }
    /^\/root\/\.cache\/go-build(\/|$)/     { k["/root/.cache/go-build"]++; next }
    /^\/root\/\.config\/go(\/|$)/          { k["/root/.config/go (the Go toolchain'"'"'s telemetry counters)"]++; next }
    /^\/root\/\.(cache|config)$/            { next }
    { o[++n] = $0 }
    END {
        for (r in k) printf "%s (%d entries)\n", r, k[r]
        for (i = 1; i <= n; i++) printf "OTHER %s\n", o[i]
    }' <<< "$left" | sort)
echo "$summ"
if grep -qx 'OTHER /etc/gitconfig' <<< "$summ"; then
    echo "/etc/gitconfig after the uninstall ($(q 'wc -c < /etc/gitconfig') bytes):"; q 'cat /etc/gitconfig'
fi
for r in /usr/local/go /opt/tacquito-src /root/go /root/.cache/go-build; do
    if grep -q "^${r} (" <<< "$summ"; then ok "kept, as documented: ${r}"; else bad "kept, as documented: ${r}"; fi
done
others=$(grep '^OTHER' <<< "$summ" | grep -cvx 'OTHER /etc/gitconfig')
if [[ $others != 0 ]]; then
    bad "uninstall leaves nothing else (${others} other paths above)"
else
    ok "uninstall leaves nothing else (apart from the Go toolchain's own files and /etc/gitconfig, if listed above)"
fi
echo "packages the install added (kept): $(wc -w <<< "$pkgs")"
users=$(q 'comm -13 /var/tmp/users.before /var/tmp/users.after' | paste -sd' ')
echo "accounts added and not removed: ${users:-none}"
check "/opt/tacctl, /etc/tacctl, /usr/local/bin/tacctl, the tacquito account are gone" \
    '! test -e /opt/tacctl && ! test -e /etc/tacctl && ! test -e /usr/local/bin/tacctl && ! id tacquito'

echo
echo "${pass} passed, ${fail} failed"
[[ $fail == 0 ]]
