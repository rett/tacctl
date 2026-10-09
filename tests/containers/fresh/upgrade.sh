#!/bin/bash
# The way from the release before this one: a 0.2.2 server (the README
# one-liner on the 0.2.2 commit), some state made with its own tacctl (users,
# groups, a scope, a device, the role preset), then 'tacctl upgrade' to this
# working tree, then 'tacctl rollback 0.2.2 --apply --yes' and the 0.2.2
# binary reading the converted state. Rootless podman, an ubuntu:noble
# container with systemd (the image of fresh/run.sh), nothing on this machine
# touched outside podman and a temp dir.
#
#   tests/containers/fresh/upgrade.sh [--from <tag>] [--keep]
#
# Like fresh/run.sh the container's git fetches the GitHub URL from a bare
# clone made in the temp dir. Its master is first <tag>'s commit (the tag
# itself is not pushed: a clone at a tag would download the release binary
# from GitHub instead of building the commit), then this checkout as it is
# (HEAD plus every change and new file, from a scratch index; no ref and no
# index of this repository changes), as a merge with the tag's commit so that the
# pull of the upgrade is a fast-forward, as it is for a release.
#
# Needs network access (Ubuntu mirrors, dl.google.com, GitHub for tacquito,
# the Go module proxy), python3 with bcrypt here (password hashes). Prints
# PASS/FAIL lines and exits non-zero on a FAIL.
# shellcheck disable=SC2016  # the single-quoted scripts run inside the container
set -uo pipefail
export LC_ALL=C
FROM="0.2.2"; KEEP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --from) FROM="${2:?--from needs a tag}"; shift 2 ;;
        --keep) KEEP="yes"; shift ;;
        *) echo "usage: upgrade.sh [--from <tag>] [--keep]" >&2; exit 2 ;;
    esac
done
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../../.." && pwd)"
IMAGE=localhost/tacctl-fresh:noble
C=tacctl-fresh
WORK=$(mktemp -d)
cleanup() {
    [[ -n "$KEEP" ]] || podman rm -f -t 0 "$C" > /dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "PASS  $1"; }
bad() { fail=$((fail + 1)); echo "FAIL  $1"; }
section() { echo; echo "=== $1"; }
q() { podman exec -e LC_ALL=C "$C" bash -c "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; return "${PIPESTATUS[0]}"; }
check() { if q "$2" > /dev/null; then ok "$1"; else bad "$1"; fi; }
expect() { if grep -qE -- "$2" <<< "$3"; then ok "$1"; else bad "$1   (wanted /$2/, got: $(tr '\n' ' ' <<< "$3" | cut -c1-300))"; fi; }

OLD=$(git -C "$REPO" rev-parse --verify "${FROM}^{commit}") || { echo "no tag ${FROM} in ${REPO}" >&2; exit 2; }
export GIT_INDEX_FILE="${WORK}/worktree.index"
git -C "$REPO" read-tree HEAD && git -C "$REPO" add -A \
    && TREE=$(git -C "$REPO" write-tree) \
    && NEW=$(GIT_AUTHOR_NAME=check GIT_AUTHOR_EMAIL=check@example.invalid GIT_COMMITTER_NAME=check GIT_COMMITTER_EMAIL=check@example.invalid \
        git -C "$REPO" commit-tree "$TREE" -p HEAD -p "$OLD" -m "upgrade check: the working tree") || exit 1
unset GIT_INDEX_FILE
git clone -q --bare "$REPO" "${WORK}/tacctl.git" || exit 1
git -C "$REPO" push -q --force --no-verify "${WORK}/tacctl.git" "${OLD}:refs/heads/master" || exit 1
git -C "$REPO" push -q --force --no-verify "${WORK}/tacctl.git" "${NEW}:refs/heads/new-tree" || exit 1
git -C "${WORK}/tacctl.git" symbolic-ref HEAD refs/heads/master
echo "from ${FROM} (${OLD}) to the working tree (${NEW})"

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
podman run -d --name "$C" --hostname "$C" --systemd=always --cap-add SYS_ADMIN \
    -v "${WORK}/tacctl.git:/srv/tacctl.git" "$IMAGE" /sbin/init > /dev/null || exit 1
sleep 5
podman exec "$C" git config --global url./srv/tacctl.git.insteadOf https://github.com/rett/tacctl.git

section "install ${FROM} (README one-liner)"
out=$(q "echo y | sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl && /opt/tacctl/bin/tacctl.sh install'"); rc=$?
echo "$out" | tail -5
if [[ $rc == 0 ]]; then ok "install of ${FROM}"; else bad "install of ${FROM} (exit ${rc})"; exit 1; fi
expect "tacctl is ${FROM}" "commit: *${OLD}|${FROM}" "$(q 'tacctl version --long')"
check "tacquito is active" 'systemctl is-active --quiet tacquito'

section "state made with ${FROM}'s own tacctl"
H=$(python3 -c 'import bcrypt; print(bcrypt.hashpw(b"Upgrade-Pw-7319", bcrypt.gensalt(rounds=10)).decode())')
q "tacctl scope add lab --prefixes 192.0.2.0/24 --secret generate" | tail -2
q "printf 'y\n' | tacctl group preset roles" | tail -2
q "tacctl user add alice superuser --hash '${H}' --scopes lab; tacctl user add eve engineer --hash '${H}' --scopes lab; tacctl user add opie operator --hash '${H}' --scopes lab; tacctl user add rory readonly --hash '${H}' --scopes lab" | tail -4
q "tacctl device add sw1 192.0.2.10 --vendor cisco --no-host-key; tacctl device add rt1 192.0.2.11 --vendor juniper --no-host-key" | tail -2
q 'tacctl config validate' | tail -2
q 'tacctl user list' > "${WORK}/users.before"; cat "${WORK}/users.before"
q 'tacctl device list' > "${WORK}/devices.before"
q 'tacctl group list' > "${WORK}/groups.before"
q 'tacctl config cisco --scope lab' > "${WORK}/cisco.before"
q 'sha256sum /etc/tacctl/store.yaml' > "${WORK}/store.before"
expect "alice, eve, opie and rory exist" 'alice.*eve|eve.*alice' "$(tr '\n' ' ' < "${WORK}/users.before")"
q 'tacctl group show engineer' | head -12

section "tacctl upgrade to the working tree"
git -C "${WORK}/tacctl.git" update-ref refs/heads/master "$NEW" || exit 1
out=$(q 'echo y | tacctl upgrade'); rc=$?
echo "$out" | tail -25
if [[ $rc == 0 ]]; then ok "tacctl upgrade exits 0"; else bad "tacctl upgrade exits 0 (exit ${rc})"; fi
expect "the binary is built from the working tree's commit" "commit: *${NEW}" "$(q 'tacctl version --long')"
check "tacquito is active" 'systemctl is-active --quiet tacquito'
check "tacctl status" 'tacctl status'
out=$(q 'tacctl config validate'); rc=$?; echo "$out" | tail -4
if [[ $rc == 0 ]]; then ok "config validate"; else bad "config validate (exit ${rc})"; fi
q 'tacctl user list' > "${WORK}/users.after"
if diff "${WORK}/users.before" "${WORK}/users.after" > "${WORK}/users.diff"; then ok "user list is as before the upgrade"; else bad "user list is as before the upgrade"; cat "${WORK}/users.diff"; fi
q 'tacctl device list' > "${WORK}/devices.after"
if diff "${WORK}/devices.before" "${WORK}/devices.after" > /dev/null; then ok "device list is as before the upgrade"; else bad "device list is as before the upgrade"; diff "${WORK}/devices.before" "${WORK}/devices.after"; fi
check "the store still verifies alice's password hash form (user show alice)" 'tacctl user show alice'
out=$(q 'tacctl config cisco --scope lab'); rc=$?
if [[ $rc == 0 ]]; then ok "config cisco --scope lab renders"; else bad "config cisco --scope lab renders (exit ${rc})"; fi
q 'tacctl group list'
out=$(q 'tacctl group show engineer'); echo "$out" | head -14
out=$(q 'echo y | tacctl upgrade'); rc=$?
if [[ $rc == 0 ]] && ! grep -q 'Building' <<< "$out"; then ok "a second upgrade builds nothing"; else bad "a second upgrade builds nothing (exit ${rc})"; fi
out=$(q 'tacctl console check'); rc=$?; echo "$out" | tail -8
echo "(console check exit ${rc}; no console is installed by the upgrade alone)"

section "0.2.3-only settings, then ${FROM}'s own binary on the state (it refuses them)"
q 'tacctl config linux engineer-sudo /usr/bin/systemctl' | tail -1
q 'tacctl console space-completion off' | tail -1
check "tacctl.yaml has linux.engineer_sudo and console.yaml settings.space_completion" 'grep -q engineer_sudo /etc/tacctl/tacctl.yaml && grep -q space_completion /etc/tacctl/console.yaml'
# The release binary of the tag, built from the commit in the clone (vendored modules).
out=$(q "mkdir -p /tmp/old && git -C /opt/tacctl archive ${OLD} | tar -x -C /tmp/old && cd /tmp/old && /usr/local/go/bin/go build -trimpath -buildvcs=false -o /tmp/tacctl-old ./cmd/tacctl && /tmp/tacctl-old version"); rc=$?
echo "$out" | tail -3
if [[ $rc == 0 ]]; then ok "${FROM} built from its commit"; else bad "${FROM} built from its commit (exit ${rc})"; fi
out=$(q '/tmp/tacctl-old config validate'); rc=$?
echo "$out" | tail -4
if [[ $rc != 0 ]] || grep -qiE 'engineer_sudo|unknown' <<< "$out"; then ok "${FROM}'s config validate reports the 0.2.3 key before the rollback"; else bad "${FROM}'s config validate reports the 0.2.3 key before the rollback (exit ${rc})"; fi
out=$(q '/tmp/tacctl-old console show'); rc=$?
echo "$out" | tail -3
if [[ $rc != 0 ]]; then ok "${FROM}'s console show refuses console.yaml before the rollback"; else bad "${FROM}'s console show refuses console.yaml before the rollback"; fi

section "tacctl rollback ${FROM}"
out=$(q "tacctl rollback ${FROM}"); rc=$?
echo "$out" | head -40
if [[ $rc == 0 ]] && grep -q 'This was a dry run: nothing was changed.' <<< "$out"; then ok "rollback ${FROM}: the dry run exits 0 and changes nothing"; else bad "rollback ${FROM}: the dry run (exit ${rc})"; fi
check "the dry run left tacctl.yaml and console.yaml as they were (both still hold the 0.2.3 settings)" 'grep -q engineer_sudo /etc/tacctl/tacctl.yaml && grep -q space_completion /etc/tacctl/console.yaml'
out=$(q "tacctl rollback ${FROM} --apply --yes"); rc=$?
echo "$out" | tail -25
if [[ $rc == 0 ]]; then ok "rollback ${FROM} --apply --yes exits 0"; else bad "rollback ${FROM} --apply --yes (exit ${rc})"; fi
check "tacctl.yaml no longer has linux.engineer_sudo, console.yaml no longer has space_completion" '! grep -q engineer_sudo /etc/tacctl/tacctl.yaml && ! grep -q space_completion /etc/tacctl/console.yaml'
check "a snapshot of the state before was taken (tacctl backup list)" 'tacctl backup list | grep -qi .'
section "${FROM}'s own binary on the converted state"
out=$(q '/tmp/tacctl-old config validate'); rc=$?; echo "$out" | tail -6
if ! grep -qiE 'engineer_sudo|unknown key' <<< "$out"; then ok "${FROM}'s config validate no longer reports a key it does not know (exit ${rc}: the rendered config may be out of date until its own config render)"; else bad "${FROM}'s config validate still reports a key it does not know"; fi
out=$(q '/tmp/tacctl-old console show'); rc=$?
if [[ $rc == 0 ]]; then ok "${FROM}'s console show reads console.yaml"; else bad "${FROM}'s console show reads console.yaml (exit ${rc}): $(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
q '/tmp/tacctl-old user list' > "${WORK}/users.old"
if diff <(awk '{print $1, $2}' "${WORK}/users.before") <(awk '{print $1, $2}' "${WORK}/users.old") > "${WORK}/users.olddiff"; then ok "${FROM}'s user list: the same users and groups"; else bad "${FROM}'s user list: the same users and groups"; cat "${WORK}/users.olddiff"; fi
out=$(q '/tmp/tacctl-old device list'); rc=$?
if [[ $rc == 0 ]] && grep -q sw1 <<< "$out" && grep -q rt1 <<< "$out"; then ok "${FROM}'s device list shows both devices"; else bad "${FROM}'s device list shows both devices (exit ${rc}): $(tr '\n' ' ' <<< "$out" | cut -c1-200)"; fi
out=$(q '/tmp/tacctl-old config render'); rc=$?; echo "$out" | tail -4
if [[ $rc == 0 ]]; then ok "${FROM}'s config render on the converted state"; else bad "${FROM}'s config render on the converted state (exit ${rc})"; fi
check "tacquito is still active" 'systemctl is-active --quiet tacquito'

echo
echo "${pass} passed, ${fail} failed"
[[ $fail == 0 ]]
