#!/usr/bin/env bash
#
# Tacquito TACACS+ Server — Management Script
#
# Manage local TACACS+ users and server configuration.
# Users, groups, scopes and filters live in /etc/tacctl/store.yaml; every
# change is rendered into /etc/tacquito/tacquito.yaml and the daemon restarted.
#
# Usage:
#   ./tacctl.sh user list
#   ./tacctl.sh user add <username> <group> [--scopes <name>[,<name>...]]
#   ./tacctl.sh user remove <username>
#   ./tacctl.sh user passwd <username>
#   ./tacctl.sh user disable <username>
#   ./tacctl.sh user enable <username>
#   ./tacctl.sh user verify <username>
#   ./tacctl.sh user scope <username> {list|add|remove|set|clear}
#   ./tacctl.sh scope {list|show|add|remove|rename|default}
#   ./tacctl.sh scope prefixes <name> {list|add|remove|clear}
#   ./tacctl.sh scope secret   <name> {show|set|generate}
#   ./tacctl.sh config show
#   ./tacctl.sh config cisco   [--scope <name>] [--legacy]
#   ./tacctl.sh config juniper [--scope <name>]
#   ./tacctl.sh config wti     [--scope <name>]
#
set -euo pipefail

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
            # 'config render' rebuilds tacquito.yaml from the store, so it
            # must work when that file is the thing that is missing.
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
