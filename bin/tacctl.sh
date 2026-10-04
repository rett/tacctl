#!/usr/bin/env bash
#
# tacctl — management CLI for network-device AAA servers
#
# Manages users, groups, scopes and filters once, and serves them over
# TACACS+ (tacquito) and, when enabled, RADIUS (FreeRADIUS).
# Users, groups, scopes and filters live in /etc/tacctl/store.yaml; every
# change is rendered into each enabled backend's config (for TACACS+
# /etc/tacquito/tacquito.yaml) and the backends whose files changed restarted.
#
# Usage (every command prints its own help when run without arguments):
#   ./tacctl.sh user list
#   ./tacctl.sh user add <username> <group> [--scopes <name>[,<name>...]]
#   ./tacctl.sh user remove <username>
#   ./tacctl.sh user passwd <username>
#   ./tacctl.sh user disable <username>
#   ./tacctl.sh user enable <username>
#   ./tacctl.sh user verify <username>
#   ./tacctl.sh user scope <username> {list|add|remove|replace|remove --all}
#   ./tacctl.sh scope {list|show|add|remove|rename|default}
#   ./tacctl.sh scope prefixes <name> {list|add|remove|remove --all [--force]}
#   ./tacctl.sh scope secret   <name> {show|set|generate}
#   ./tacctl.sh backend {list|status [<id>]|enable <id>|disable <id>}
#   ./tacctl.sh store {show|import|rollback}
#   ./tacctl.sh host {list|enroll|sync|unenroll|default-method}
#   ./tacctl.sh config show
#   ./tacctl.sh config cisco   [--scope <name>] [--legacy] [--protocol tacacs|radius]
#   ./tacctl.sh config juniper [--scope <name>] [--protocol tacacs|radius]
#   ./tacctl.sh config wti     [--scope <name>] [--protocol tacacs|radius]
#
set -euo pipefail

# tacctl.sh --build <out> [--tags <tags>]: compile the Go implementation in
# this script's tree (cmd/tacctl, vendored modules, no network) into <out>,
# atomically, and exit. Needs no root and installs nothing: 'make build' uses
# it, and the 0.2.0 bootstrap shim and upgrade share the same recipe
# (docs/plans/go-rewrite.md 5.1; bin/tacctl.sh.new holds the shim, and
# tests/integration/shim.bats keeps the two copies identical). The version stamped in is 'git describe'
# of the tree; GOCACHE as root defaults to /root/.cache/go-build.
tacctl_go_build() {
    local out="${1:-}" tags="" tree version commit date
    local go_bin="${TACCTL_TEST_ROOT:-}/usr/local/go/bin/go"
    if [[ -z "$out" || "$out" == -* ]]; then
        echo "Usage: tacctl.sh --build <out> [--tags <tags>]" >&2
        return 1
    fi
    shift
    if [[ "${1:-}" == "--tags" ]]; then
        tags="${2:-}"
        [[ -n "$tags" ]] || { echo "Usage: tacctl.sh --build <out> [--tags <tags>]" >&2; return 1; }
        shift 2
    fi
    if [[ $# -gt 0 ]]; then
        echo "Usage: tacctl.sh --build <out> [--tags <tags>]" >&2
        return 1
    fi
    tree="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)" || return 1
    if [[ ! -f "${tree}/go.mod" ]]; then
        echo -e "\033[0;31m[ERROR]\033[0m No Go module in ${tree} (go.mod missing)." >&2
        return 1
    fi
    if [[ ! -x "$go_bin" ]]; then
        echo -e "\033[0;31m[ERROR]\033[0m Go toolchain not found at ${go_bin}." >&2
        return 1
    fi
    [[ "$out" == /* ]] || out="${PWD}/${out}"
    mkdir -p "$(dirname "$out")" || return 1
    version=$(git -C "$tree" describe --tags --always --dirty 2> /dev/null) || version="unknown"
    commit=$(git -C "$tree" rev-parse HEAD 2> /dev/null) || commit="unknown"
    date=$(git -C "$tree" log -1 --format=%cI 2> /dev/null) || date="unknown"
    if [[ -z "${GOCACHE:-}" && $EUID -eq 0 ]]; then
        export GOCACHE=/root/.cache/go-build
    fi
    local -a build=(build -trimpath -buildvcs=false)
    [[ -z "$tags" ]] || build+=(-tags "$tags")
    build+=(-ldflags "-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${date}")
    build+=(-o "${out}.new" ./cmd/tacctl)
    # A subshell for cd and umask; the trap drops a half-written binary on
    # failure or Ctrl-C. <out> itself changes only by the final rename.
    (
        trap 'rm -f "${out}.new"' EXIT
        cd "$tree" \
            && umask 022 \
            && GOTOOLCHAIN=local GOFLAGS=-mod=vendor CGO_ENABLED=0 "$go_bin" "${build[@]}" \
            && chmod 755 "${out}.new" \
            && mv -f "${out}.new" "$out"
    )
}
if [[ "${BASH_SOURCE[0]}" == "$0" && "${1:-}" == "--build" ]]; then
    shift
    tacctl_go_build "$@" || exit 1
    exit 0
fi

# Re-exec under sudo only when invoked as a script. When sourced (e.g. by bats
# tests), skip re-exec so tests can call functions directly as any user.
# TACCTL_SKIP_SUDO=1 is a test-only escape for subprocess invocations from
# integration tests; prod never sets it.
if [[ "${BASH_SOURCE[0]}" == "$0" \
    && "${TACCTL_SKIP_SUDO:-0}" != "1" \
    && $EUID -ne 0 \
    && "${1:-}" != "hash" ]]; then
    # 'host' runs ssh as the invoking user; carry their agent socket across
    # sudo's environment reset so agent-held keys work.
    if [[ "${1:-}" == "host" && -n "${SSH_AUTH_SOCK:-}" ]]; then
        exec sudo SSH_AUTH_SOCK="$SSH_AUTH_SOCK" "$0" "$@"
    fi
    exec sudo "$0" "$@"
fi
umask 077

# tacquito source patches (git-apply diffs) re-applied on install/upgrade after
# the upstream pull; see patches/README.md. Derived from the script's own
# location so it works for both the deployed clone and a dev checkout.
PATCH_DIR="${TACCTL_PATCH_DIR:-$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/../patches}"
# Use BASH_SOURCE so the path resolves to tacctl.sh itself even when sourced
# (e.g. by bats tests), not to the sourcing binary.
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# --- Load the library ---
# SCRIPT_DIR (above) is this file's real directory with symlinks resolved, so
# lib/ is found the same way through the /usr/local/bin/tacctl symlink, under
# the sudo re-exec, from a dev checkout, and when sourced by the test harness.
# Order: core.sh must come before conf.sh (conf.sh's source-time tunables
# overwrite the built-in defaults core.sh assigns and need
# TACCTL_OVERRIDES_FILE); render_devices.sh and linux_hosts.sh read SCRIPT_DIR.
# model.sh and store.sh define functions plus STORE_FILE, which depend on
# nothing in the later files, so their position is not load-bearing.
# backend.sh must come before every lib/backends/*.sh: it declares
# BACKEND_IDS, to which each module appends itself when sourced. A module
# may use TACCTL_BIN and the other base paths of core.sh at source time.
# shellcheck source=lib/core.sh
source "${SCRIPT_DIR}/../lib/core.sh"
# shellcheck source=lib/conf.sh
source "${SCRIPT_DIR}/../lib/conf.sh"
# shellcheck source=lib/model.sh
source "${SCRIPT_DIR}/../lib/model.sh"
# shellcheck source=lib/store.sh
source "${SCRIPT_DIR}/../lib/store.sh"
# shellcheck source=lib/policy.sh
source "${SCRIPT_DIR}/../lib/policy.sh"
# shellcheck source=lib/users.sh
source "${SCRIPT_DIR}/../lib/users.sh"
# shellcheck source=lib/groups.sh
source "${SCRIPT_DIR}/../lib/groups.sh"
# shellcheck source=lib/scopes.sh
source "${SCRIPT_DIR}/../lib/scopes.sh"
# shellcheck source=lib/render_devices.sh
source "${SCRIPT_DIR}/../lib/render_devices.sh"
# shellcheck source=lib/linux_hosts.sh
source "${SCRIPT_DIR}/../lib/linux_hosts.sh"
# shellcheck source=lib/backend.sh
source "${SCRIPT_DIR}/../lib/backend.sh"
# shellcheck source=lib/backends/tacacs.sh
source "${SCRIPT_DIR}/../lib/backends/tacacs.sh"
# shellcheck source=lib/backends/radius.sh
source "${SCRIPT_DIR}/../lib/backends/radius.sh"
# shellcheck source=lib/service.sh
source "${SCRIPT_DIR}/../lib/service.sh"
# shellcheck source=lib/lifecycle.sh
source "${SCRIPT_DIR}/../lib/lifecycle.sh"
# shellcheck source=lib/dispatch.sh
source "${SCRIPT_DIR}/../lib/dispatch.sh"

# Dispatch runs only when invoked as a script. Sourced imports (tests) get
# function definitions without triggering CLI dispatch.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    COMMAND="${1:-}"
    shift || true

    enforce_tier "$COMMAND" "${1:-}"

    case "$COMMAND" in
        passwd)
            preflight
            cmd_passwd_self "$@"
            ;;
        install)
            cmd_install "$@"
            ;;
        upgrade)
            cmd_upgrade "$@"
            ;;
        uninstall)
            cmd_uninstall "$@"
            ;;
        status)
            preflight
            cmd_status
            ;;
        user)
            preflight
            cmd_user "$@"
            ;;
        group)
            preflight
            cmd_group "$@"
            ;;
        config)
            # 'config render' rebuilds tacquito.yaml from the store: with a
            # store it skips preflight, which would warn that the file it is
            # about to write is missing.
            if [[ "${1:-}" != "render" || ! -f "$STORE_FILE" ]]; then
                preflight
            fi
            cmd_config "$@"
            ;;
        scope)
            preflight
            cmd_scope "$@"
            ;;
        host)
            preflight
            cmd_host "$@"
            ;;
        log)
            preflight
            cmd_log "$@"
            ;;
        backup)
            preflight
            cmd_backup "$@"
            ;;
        backend)
            preflight
            cmd_backend "$@"
            ;;
        store)
            # No preflight: 'store import <file>' and 'store show' must work
            # on a file other than the live config, and need no bcrypt.
            cmd_store "$@"
            ;;
        hash)
            cmd_hash "$@"
            ;;
        _completion-names)
            # Hidden helper used by bash completion to enumerate scope, user,
            # group, or backup-timestamp names (the first three from the
            # model). Completion runs in the user's shell where the store and
            # the config are unreadable; `sudo -n tacctl
            # _completion-names <kind>` bridges that when a NOPASSWD sudoers
            # rule for tacctl is installed. Not shown in `tacctl` help or the
            # man page — deliberate low-surface interface, behavior subject to
            # change.
            preflight
            case "${1:-}" in
                scopes) model_scopes 2>/dev/null ;;
                users)  model_users 2>/dev/null ;;
                groups) model_groups 2>/dev/null ;;
                # Backup timestamps: snapshots newest first, then old-style
                # backups, capped at 50 so the completion menu stays usable
                # on hosts with hundreds of backups. `config diff` /
                # `backup diff|restore` take one.
                backups) backup_names | head -50 || true ;;
                # Backend ids: every registered one ('backend enable <id>',
                # '--backend <id>'), or only the enabled ones ('backend
                # disable <id>'). 'listeners [<backend>]' is the listener
                # names of that backend (every backend's without one).
                backends) printf '%s\n' "${BACKEND_IDS[@]}" ;;
                enabled-backends) backends_enabled 2>/dev/null || true ;;
                listeners) _completion_listeners "${2:-}" ;;
            esac
            ;;
        version|--version|-v)
            echo "tacctl $(get_version)"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
fi
