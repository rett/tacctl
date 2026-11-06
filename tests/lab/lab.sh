#!/usr/bin/env bash
# Live lab suite: registers real lab devices in a throwaway tacctl sandbox,
# pulls them as the invoking user and checks what the pull recorded.
#
#   tests/lab/lab.sh run     build state, pull every lab device, check
#   tests/lab/lab.sh pull    pull again in the existing sandbox
#   tests/lab/lab.sh list    the sandbox's device configuration table
#   tests/lab/lab.sh clean   remove the sandbox
#
# The devices are not in the repository (no private address or login may
# be): they are read from $TACCTL_LAB_ENV, default ~/.config/tacctl/lab.env
# (tests/lab/README.md). Nothing here touches an installed tacctl, a
# production host or a device's configuration: the pull only reads.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
src=$(cd "$here/../.." && pwd)
envfile=${TACCTL_LAB_ENV:-$HOME/.config/tacctl/lab.env}
bin=${TACCTL_LAB_BIN:-$src/dist/tacctl}
sandbox=${TACCTL_LAB_DIR:-${TMPDIR:-/tmp}/tacctl-lab-$(id -u)}

die() { echo "lab: $*" >&2; exit 1; }

[[ -r $envfile ]] || die "no $envfile (see tests/lab/README.md)"
# shellcheck source=/dev/null
. "$envfile"
: "${LAB_PASSWORD:?LAB_PASSWORD is not set in $envfile}"
: "${LAB_DEVICES:?LAB_DEVICES is not set in $envfile}"
[[ -x $bin ]] || die "no $bin (run: make build)"

export TACCTL_ETC=$sandbox/etc TACCTL_STATE_DIR=$sandbox/state
export TACCTL_VAR_LIB=$sandbox/var-lib TACCTL_LOG=$sandbox/log TACCTL_BIN=$sandbox/bin
export TACCTL_CONFIG=$sandbox/etc/tacquito.yaml TACCTL_SKIP_SUDO=1
export TACCTL_SSH_DIR=$sandbox/ssh TACCTL_SUDOERS_FILE=$sandbox/sudoers.d/tacctl
export TACCTL_OVERRIDE_DIR=$sandbox/dropin
# The pull logs in as the invoking user, taken from sudo's variables.
SUDO_USER=$(id -un)
SUDO_UID=$(id -u)
export SUDO_USER SUDO_UID

t() { "$bin" "$@" 2> >(grep -v '^\[WARN\]' >&2) </dev/null; }

setup() {
	rm -rf "$sandbox"
	mkdir -p "$sandbox"/{etc,state,var-lib,log,bin}
	install -m 600 "$src/tests/fixtures/store.minimal.yaml" "$sandbox/state/store.yaml"
	local d name addr vendor flags
	for d in $LAB_DEVICES; do
		IFS=: read -r name addr vendor flags <<<"$d"
		t scope prefixes lab add "$addr/32" >/dev/null || true
	done
	t user add "$SUDO_USER" superuser >/dev/null
	t user scope "$SUDO_USER" add lab >/dev/null || true
	# Emulated devices share a small host: a slow image times out when read with others.
	t config devices timeout 300 >/dev/null
	t config devices max-concurrency 2 >/dev/null
	for d in $LAB_DEVICES; do
		IFS=: read -r name addr vendor flags <<<"$d"
		t device add "$name" "$addr" --vendor "$vendor" >/dev/null
		[[ $flags == *legacy* ]] && t device legacy-ssh "$name" enable >/dev/null
		true
	done
}

pull() {
	python3 "$here/pty-run.py" "$LAB_PASSWORD" "$bin" device config pull --all |
		grep -v '^\[WARN\]' | sed 's/\x1b\[[0-9;]*[A-Za-z]//g'
}

# check: every device pulled ('ok') and recorded a release.
check() {
	local bad=0 d name addr vendor flags row
	for d in $LAB_DEVICES; do
		IFS=: read -r name addr vendor flags <<<"$d"
		row=$(t device config list | awk -v n="$name" '$1 == n')
		if [[ -z $row ]]; then
			echo "FAIL $name: not listed"
			bad=1
			continue
		fi
		if awk '{exit !($4 == "-")}' <<<"$row" || [[ $row == *failed* ]]; then
			echo "FAIL $name: $row"
			bad=1
		else
			echo "ok   $name: $row"
		fi
	done
	return "$bad"
}

case ${1:-run} in
run)
	setup
	# A failed device makes the pull exit non-zero: check names which.
	pull || true
	check
	;;
pull) pull ;;
list) t device config list ;;
clean) rm -rf "$sandbox" ;;
*) die "usage: lab.sh run|pull|list|clean" ;;
esac
