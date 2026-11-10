#!/usr/bin/env bash
# doctor.sh
#
# Checks this checkout and this machine for what the project's tooling needs
# ('make doctor'). It only looks: it installs nothing, runs no test, uses no
# network and no sudo, and finishes in a second or two. One line per item,
# in one of three forms:
#
#   ok <item>: <version or detail>
#   missing <item>: <how to install it, in one line>
#   expected <item>: <why this host may lack it>
#
# 'missing' is a tool or file that make lint, make gate-go or make build needs,
# or whose absence makes tests skip silently (the list in the comment at the
# top of .github/workflows/test.yml); 'expected' is optional, with what you
# lose without it. The exit status is 1 when any line starts with 'missing',
# else 0.
#
# The pins are read where they live, never copied here: the Go version
# (GO_VERSION) from bin/tacctl.sh, the golangci-lint version
# (GOLANGCI_LINT_VERSION) and the default GO from the Makefile. GO, GOFMT and
# GOLANGCI_LINT in the environment override the Makefile's choice, as they do
# for make; TACCTL_PRIVATE_PATTERNS names the private-name pattern file, as for
# tests/tools/no-private.sh.
set -uo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd) || exit 1
status=0

ok() { printf 'ok %s: %s\n' "$1" "$2"; }
expected() { printf 'expected %s: %s\n' "$1" "$2"; }
missing() {
    printf 'missing %s: %s\n' "$1" "$2"
    status=1
}

# first_line <command...>: the first line of its output, "" when it fails.
first_line() { "$@" 2> /dev/null | head -n 1; }

# have_tool <item> <command> <install hint> <version command...>: ok with the
# version line (or the path when the command prints none), or missing.
have_tool() {
    local item="$1" cmd="$2" hint="$3" path ver
    shift 3
    if ! path=$(command -v "$cmd" 2> /dev/null); then
        missing "$item" "$hint"
        return
    fi
    ver=""
    [[ $# -eq 0 ]] || ver=$(first_line "$@")
    ok "$item" "${ver:-$path}"
}

# --- 1. Go: the Makefile's GO, at exactly the version bin/tacctl.sh pins ------
go_pin=$(sed -n 's/^GO_VERSION="\([0-9.]*\)"$/\1/p' "$root/bin/tacctl.sh" 2> /dev/null)
GO="${GO:-$(sed -n 's/^GO ?= *//p' "$root/Makefile" 2> /dev/null | head -n 1)}"
GO="${GO:-/usr/local/go/bin/go}"
go_fix="run bin/tacctl.sh as root (it installs the pinned Go ${go_pin:-?} in /usr/local/go; --build only uses it), or set GO=<path to go ${go_pin:-?}>"
if [[ -z "$go_pin" ]]; then
    missing go "no GO_VERSION in bin/tacctl.sh, so the pinned Go cannot be known"
elif ! go_path=$(command -v "$GO" 2> /dev/null); then
    missing go "$GO does not exist: $go_fix"
else
    go_have=$("$go_path" version 2> /dev/null | awk '{print $3}')
    go_have="${go_have#go}"
    if [[ "$go_have" == "$go_pin" ]]; then
        ok go "$go_have ($go_path)"
    else
        missing go "$go_path is ${go_have:-of an unknown version}, bin/tacctl.sh pins $go_pin: $go_fix"
    fi
fi

# --- 2. gofmt beside that go, and a C compiler (cgo, the race detector) -------
gofmt="${GOFMT:-$(dirname "$GO")/gofmt}"
if [[ -x "$gofmt" ]]; then
    ok gofmt "$gofmt"
else
    missing gofmt "$gofmt does not exist; it comes with the Go toolchain (see go)"
fi
if cc_path=$(command -v cc 2> /dev/null || command -v gcc 2> /dev/null); then
    ok cc "$(first_line "$cc_path" --version) ($cc_path)"
else
    missing cc "install a C compiler for cgo and the race detector (apt install gcc, pacman -S gcc)"
fi

# --- 3. golangci-lint, found as the lint-go target finds it -------------------
lint_pin=$(sed -n 's/^GOLANGCI_LINT_VERSION := \(v[0-9.]*\)$/\1/p' "$root/Makefile" 2> /dev/null)
lint_install="GOBIN=\$HOME/.local/bin $GO install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${lint_pin:-?}"
lint=""
if [[ -n "${GOLANGCI_LINT:-}" ]]; then
    lint="$GOLANGCI_LINT"
else
    lint=$(command -v golangci-lint 2> /dev/null)
    for cand in "$HOME/go/bin/golangci-lint" "$HOME/.local/bin/golangci-lint"; do
        [[ -n "$lint" || ! -x "$cand" ]] || lint="$cand"
    done
fi
if [[ -z "$lint_pin" ]]; then
    missing golangci-lint "no GOLANGCI_LINT_VERSION in the Makefile, so the pinned version cannot be known"
elif [[ -z "$lint" ]] || ! lint_path=$(command -v "$lint" 2> /dev/null); then
    missing golangci-lint "not found; install $lint_pin for your user (no root): $lint_install"
else
    lint_have=$("$lint_path" version --short 2> /dev/null)
    if [[ "v${lint_have#v}" == "$lint_pin" ]]; then
        ok golangci-lint "$lint_pin ($lint_path)"
    else
        missing golangci-lint "$lint_path is '${lint_have:-unknown}', the Makefile pins $lint_pin: $lint_install"
    fi
fi

# --- 4. what the tests of internal/cli skip without (test.yml) ----------------
apt_hint() { echo "apt install $1 (pacman -S $2)"; }
if command -v shellcheck > /dev/null 2>&1; then
    ok shellcheck "$(shellcheck --version 2> /dev/null | sed -n 's/^version: //p')"
else
    missing shellcheck "$(apt_hint shellcheck shellcheck)"
fi
have_tool groff groff "$(apt_hint groff groff)" groff --version
have_tool less less "$(apt_hint less less)" less --version
have_tool man man "$(apt_hint man-db man-db)" man --version
have_tool setsid setsid "$(apt_hint util-linux util-linux)" setsid --version

# --- 5. what the tests of internal/console skip without (test.yml) ------------
# sshd lives in /usr/sbin, which an ordinary user's PATH may not list; the
# tests look there too.
if sshd=$(command -v sshd 2> /dev/null) || { [[ -x /usr/sbin/sshd ]] && sshd=/usr/sbin/sshd; }; then
    ok sshd "$sshd"
else
    missing sshd "$(apt_hint openssh-server openssh)"
fi
have_tool ssh-keygen ssh-keygen "$(apt_hint openssh-client openssh)"

# --- 6. the bats submodules ---------------------------------------------------
bats_bad=""
[[ -x "$root/tests/bats/bats-core/bin/bats" ]] || bats_bad=" bats-core/bin/bats"
for d in bats-support bats-assert bats-file; do
    [[ -n "$(ls -A "$root/tests/bats/$d" 2> /dev/null)" ]] || bats_bad="$bats_bad $d"
done
if [[ -z "$bats_bad" ]]; then
    ok bats "the four submodules under tests/bats are in place"
else
    missing bats "not initialised:$bats_bad; run make bootstrap (git submodule update --init --recursive)"
fi

# --- 7. the 0.2.2 tag: two Go tests skip without it ---------------------------
if git -C "$root" rev-parse -q --verify refs/tags/0.2.2 > /dev/null 2>&1; then
    ok tag-0.2.2 "present"
else
    missing tag-0.2.2 "two Go tests skip without it (the rollback build, the 0.2.2 schema): git fetch --tags"
fi

# --- 8. optional tools --------------------------------------------------------
parallel_ver=$(first_line parallel --version)
if [[ "$parallel_ver" == *"GNU parallel"* ]]; then
    ok parallel "$parallel_ver"
else
    expected parallel "not GNU parallel, so bats runs serially (apt install parallel)"
fi
if ! command -v python3 > /dev/null 2>&1; then
    expected python3 "not installed; the PyYAML corpus check (make test-pyyaml) says so and passes"
elif yaml_ver=$(python3 -c 'import yaml; print(yaml.__version__)' 2> /dev/null); then
    ok python3 "PyYAML $yaml_ver"
else
    expected python3 "no PyYAML; the corpus check passes without it (apt install python3-yaml)"
fi
if podman_ver=$(first_line podman --version) && [[ -n "$podman_ver" ]]; then
    ok podman "$podman_ver"
else
    expected podman "the container tests are maintainer-only (tests/containers)"
fi
if weasy_ver=$(first_line weasyprint --version) && [[ -n "$weasy_ver" ]]; then
    ok weasyprint "$weasy_ver"
else
    expected weasyprint "the tests of the pdf report format skip without it (apt install weasyprint)"
fi

# --- 9. this host -------------------------------------------------------------
if [[ -d /dev/shm && -w /dev/shm ]]; then
    ok /dev/shm "writable (GATE_TMPFS=1 can use it)"
else
    expected /dev/shm "not writable here, so GATE_TMPFS=1 cannot be used"
fi
if [[ $EUID -eq 0 || -n "${SUDO_USER:-}" ]]; then
    expected user "running as root or in a sudo session; bats must run as an ordinary user (tests/README.md)"
else
    ok user "an ordinary user (uid $EUID), as bats needs (tests/README.md)"
fi
patterns="${TACCTL_PRIVATE_PATTERNS:-$HOME/.config/tacctl/private-patterns}"
if [[ -f "$patterns" ]]; then
    ok private-patterns "$patterns"
else
    expected private-patterns "$patterns is absent; tests/tools/no-private.sh then checks only its built-in patterns"
fi

exit "$status"
