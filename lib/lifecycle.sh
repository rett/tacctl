# shellcheck shell=bash
# shellcheck disable=SC2164  # errexit is set by bin/tacctl.sh before this file is sourced
# tacctl lib/lifecycle.sh -- deploy-repo helpers, config branch, dependencies, state migration, config seeding, install/upgrade/uninstall (each backend's own steps are its phases: lib/backend.sh)
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# Normalize DEPLOY_DIR perms after git clone/pull. The script runs with
# umask 077 by default, so git creates files 0600 -- which blocks non-root
# users from reading README.md and templates. `a+rX` adds world read and
# directory traversal without granting exec on data files.
normalize_deploy_perms() {
    [[ -d "$DEPLOY_DIR" ]] || return 0
    chmod -R a+rX "$DEPLOY_DIR" 2>/dev/null || true
}

# Register root-owned git repos as safe for every user on the host via
# /etc/gitconfig. Without this, an unprivileged operator running
# `git -C /opt/tacctl log` gets "fatal: detected dubious ownership".
# Idempotent: each path is only added if not already present.
ensure_safe_directory() {
    local path existing
    existing=$(git config --system --get-all safe.directory 2>/dev/null || true)
    for path in "$@"; do
        if ! printf '%s\n' "$existing" | grep -qxF "$path"; then
            git config --system --add safe.directory "$path" 2>/dev/null || true
        fi
    done
}

# Install the man page from <src> to /usr/share/man/man1/tacctl.1.gz and
# refresh mandb. Silent no-op if the source file is missing (keeps older
# repo checkouts working) or if mandb is unavailable (`man tacctl` still
# works directly without mandb).
install_man_page() {
    local src="$1"
    [[ -f "$src" ]] || return 0
    mkdir -p /usr/share/man/man1
    gzip -c "$src" > /usr/share/man/man1/tacctl.1.gz
    chmod 644 /usr/share/man/man1/tacctl.1.gz
    mandb -q 2>/dev/null || true
}

# --- CONFIG BRANCH ---
cmd_config_branch() {
    local new_branch="${1:-}"

    if [[ ! -d "${DEPLOY_DIR}/.git" ]]; then
        error "Deploy directory not found at ${DEPLOY_DIR}."
        exit 1
    fi

    local current_branch
    current_branch=$(git -C "$DEPLOY_DIR" branch --show-current 2>/dev/null)

    if [[ -z "$new_branch" ]]; then
        echo ""
        echo -e "  ${BOLD}Current branch:${NC} ${current_branch}"
        echo ""
        echo "  Available remote branches:"
        git -C "$DEPLOY_DIR" fetch --quiet 2>/dev/null || true
        git -C "$DEPLOY_DIR" branch -r 2>/dev/null | grep -v HEAD | sed 's|origin/||' | while IFS= read -r b; do
            b=$(echo "$b" | xargs)
            if [[ "$b" == "$current_branch" ]]; then
                echo -e "    ${GREEN}* ${b}${NC}"
            else
                echo "      ${b}"
            fi
        done
        echo ""
        return
    fi

    if [[ "$new_branch" == "$current_branch" ]]; then
        info "Already on branch '${new_branch}'."
        return
    fi

    # Fetch and switch
    git -C "$DEPLOY_DIR" fetch --quiet 2>/dev/null || true
    if ! git -C "$DEPLOY_DIR" rev-parse --verify "origin/${new_branch}" &>/dev/null; then
        error "Branch '${new_branch}' does not exist on remote."
        exit 1
    fi

    git -C "$DEPLOY_DIR" checkout -- . 2>/dev/null || true
    git -C "$DEPLOY_DIR" checkout "$new_branch" &>/dev/null || git -C "$DEPLOY_DIR" checkout -b "$new_branch" "origin/${new_branch}" &>/dev/null
    git -C "$DEPLOY_DIR" pull --quiet 2>/dev/null || true
    normalize_deploy_perms
    chmod 755 "${DEPLOY_DIR}/bin/tacctl.sh"

    info "Switched to branch '${new_branch}'."
    info "Run 'tacctl upgrade' to apply any changes."
    echo ""
}

# =====================================================================
#  SYSTEM LIFECYCLE COMMANDS
# =====================================================================

# --- INSTALL ---
# Packages tacctl needs on the server. The core set is required; the rest
# serve 'tacctl host' (preparing the pam_tacplus source, building it in
# containers, reaching hosts over ssh), so failing to get them only warns.
DEPS_CORE="git wget python3 python3-yaml python3-bcrypt"
DEPS_LINUX_HOSTS="openssh-client autoconf automake libtool gnulib gcc make libpam0g-dev podman uidmap"

_pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

_apt_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null && return 0
    # A stale package index is the usual cause: refresh it once and retry.
    apt-get update -qq >/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
}

# Install whatever is missing from the lists above. Run by 'tacctl install'
# and at the end of every 'tacctl upgrade', so a release that needs a new
# package brings it along.
ensure_dependencies() {
    if ! command -v apt-get &>/dev/null || ! command -v dpkg-query &>/dev/null; then
        warn "Not a Debian/Ubuntu system; make sure the equivalents of these are installed:"
        warn "  ${DEPS_CORE} ${DEPS_LINUX_HOSTS}"
        return 0
    fi
    local pkg
    local -a core=() extra=()
    for pkg in $DEPS_CORE; do _pkg_installed "$pkg" || core+=("$pkg"); done
    for pkg in $DEPS_LINUX_HOSTS; do _pkg_installed "$pkg" || extra+=("$pkg"); done
    if [[ ${#core[@]} -eq 0 && ${#extra[@]} -eq 0 ]]; then
        info "Required packages: all present."
        return 0
    fi
    if [[ ${#core[@]} -gt 0 ]]; then
        info "Installing required packages: ${core[*]}"
        if ! _apt_install "${core[@]}"; then
            error "Could not install: ${core[*]}. Install them and re-run."
            return 1
        fi
    fi
    if [[ ${#extra[@]} -gt 0 ]]; then
        info "Installing packages for Linux host support: ${extra[*]}"
        if ! _apt_install "${extra[@]}"; then
            warn "Could not install: ${extra[*]}. 'tacctl host' and 'tacctl config linux' need them; everything else works."
        fi
    fi
    return 0
}

# --- State directory migration ---
# tacctl-owned state (tacctl.yaml, linux-hosts, linux-uids, backups/,
# templates/) used to live beside the daemon's config in TACCTL_ETC. It now
# lives in TACCTL_STATE_DIR, and each old path becomes a symlink to the new
# one so the previous release still finds its files after a rollback.
#
# The previous release replaces files by rename (conf_set), so a rolled-back
# release turns a symlink at an old path back into a regular file. state_migrate
# is therefore idempotent and runs on every install and upgrade: a regular
# file at an old path that is newer than the file at the new path wins, the
# displaced file is kept under backups/legacy/, and the symlink is restored.
# Symlinks are never followed when deciding what to move. Backups go first so
# backups/legacy exists in the new location before anything is displaced.
STATE_MIGRATE_ITEMS=(backups templates tacctl.yaml linux-hosts linux-uids)

# Unused name for a displaced item under backups/legacy (created on demand).
_state_legacy_path() {
    local label="$1" dir="${TACCTL_STATE_DIR}/backups/legacy" ts dest n=0
    mkdir -p "$dir" || return 1
    ts=$(date +%Y%m%d-%H%M%S)
    dest="${dir}/${label}.${ts}"
    while [[ -e "$dest" || -L "$dest" ]]; do
        n=$((n + 1))
        dest="${dir}/${label}.${ts}.${n}"
    done
    echo "$dest"
}

# Merge the entries of real directory $1 into real directory $2. Missing
# entries move over; directories present in both recurse; for a file present
# in both the newer one stays and the other goes to backups/legacy. Anything
# else (symlinks, mixed types) is left in place with a warning. Succeeds only
# when $1 ends up empty (and is removed).
_state_merge_dir() {
    local src="$1" dst="$2" rel="$3" entry name legacy
    while IFS= read -r -d '' entry; do
        name="${entry##*/}"
        if [[ ! -e "${dst}/${name}" && ! -L "${dst}/${name}" ]]; then
            mv "$entry" "${dst}/${name}" || return 1
        elif [[ -L "$entry" || -L "${dst}/${name}" ]]; then
            warn "State migration: not merging symlink ${entry}"
        elif [[ -d "$entry" && -d "${dst}/${name}" ]]; then
            _state_merge_dir "$entry" "${dst}/${name}" "${rel}_${name}" || true
        elif [[ -f "$entry" && -f "${dst}/${name}" ]]; then
            legacy=$(_state_legacy_path "${rel}_${name}") || return 1
            if [[ "$entry" -nt "${dst}/${name}" ]]; then
                cp -p "${dst}/${name}" "$legacy" || return 1
                mv "$entry" "${dst}/${name}" || return 1
            else
                mv "$entry" "$legacy" || return 1
            fi
        else
            warn "State migration: type mismatch, left in place: ${entry}"
        fi
    done < <(find "$src" -mindepth 1 -maxdepth 1 -print0)
    rmdir "$src" 2>/dev/null
}

# Bring one item up to date: old = ${TACCTL_ETC}/<name>, new = ${TACCTL_STATE_DIR}/<name>.
_state_migrate_item() {
    local name="$1"
    local old="${TACCTL_ETC}/${name}" new="${TACCTL_STATE_DIR}/${name}"
    local old_real new_real legacy
    old_real=$(readlink -f "$old")
    new_real=$(readlink -f "$new")

    # Never move something into itself.
    if [[ "${new_real}/" == "${old_real}/"* || "${old_real}/" == "${new_real}/"* ]]; then
        return 0
    fi

    if [[ -L "$old" ]]; then
        # A link to the new path is the settled state. Any other link is the
        # operator's; leave it.
        warn "State migration: ${old} is a symlink elsewhere; left alone"
        return 0
    fi

    if [[ ! -e "$old" ]]; then
        # Interrupted run, or state created fresh in the new location: restore
        # the compatibility link, but only on hosts that have an old directory.
        if [[ ( -e "$new" || -L "$new" ) && -d "$TACCTL_ETC" ]]; then
            ln -s "$new" "$old" || return 1
        fi
        return 0
    fi

    if [[ ! -e "$new" && ! -L "$new" ]]; then
        mv "$old" "$new" || return 1
        ln -s "$new" "$old" || return 1
        info "State migrated: ${old} -> ${new}"
        return 0
    fi

    # Both exist (old is a real file or directory, never a symlink here).
    if [[ -L "$new" ]]; then
        warn "State migration: ${new} is a symlink; ${old} left alone"
        return 0
    elif [[ -d "$old" && -d "$new" ]]; then
        if ! _state_merge_dir "$old" "$new" "$name"; then
            warn "State migration: ${old} not fully merged into ${new}; left in place"
            return 0
        fi
    elif [[ -f "$old" && -f "$new" ]]; then
        if cmp -s "$old" "$new"; then
            rm -f "$old" || return 1
        else
            legacy=$(_state_legacy_path "$name") || return 1
            if [[ "$old" -nt "$new" ]]; then
                # Rolled-back code wrote the old path: its content is newer.
                cp -p "$new" "$legacy" || return 1
                mv "$old" "$new" || return 1
            else
                mv "$old" "$legacy" || return 1
            fi
            warn "State migration: ${name} existed in both places; the displaced copy is ${legacy}"
        fi
    else
        warn "State migration: ${old} and ${new} are different kinds of file; left alone"
        return 0
    fi
    ln -s "$new" "$old" || return 1
    info "State migrated: ${old} -> ${new}"
}

state_migrate() {
    local item rc=0
    if [[ "$(readlink -f "$TACCTL_STATE_DIR")" == "$(readlink -f "$TACCTL_ETC")" ]]; then
        return 0
    fi
    mkdir -p "$TACCTL_STATE_DIR" || return 1
    [[ "$(stat -c %a "$TACCTL_STATE_DIR")" == 700 ]] || chmod 700 "$TACCTL_STATE_DIR" || return 1
    if [[ $EUID -eq 0 ]]; then chown root:root "$TACCTL_STATE_DIR" || return 1; fi
    for item in "${STATE_MIGRATE_ITEMS[@]}"; do
        _state_migrate_item "$item" || { error "State migration failed for ${item}"; rc=1; }
    done
    return "$rc"
}

# What the shipped tacquito.yaml template listed for the first scope (RFC 1918).
INSTALL_SCOPE_PREFIXES="10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
# Set by install_seed_config. Mode is one of:
#   fresh    store seeded and rendered; INSTALL_SHARED_SECRET holds the new secret
#   store    a store was already there and was kept
#   flipped  a legacy tacquito.yaml was already there and moved into the store
#   legacy   a legacy tacquito.yaml was already there and the gate stopped
INSTALL_CONFIG_MODE=""
INSTALL_SHARED_SECRET=""

# install_seed_config: give the install its configuration. Needs the state
# and config directories (state_migrate, install step 4).
#
# A fresh install gets a store holding the built-in groups, the scope
# $DEFAULT_SCOPE_FRESH (RFC 1918 prefixes, a generated secret) and the seed
# users (lib/store.sh: SEED_USERS), and tacquito.yaml rendered from it.
#
# Existing data is never replaced: a store is kept as it is, and a legacy
# tacquito.yaml goes through the same migrations and gate as on upgrade.
# Returns 1 when a fresh configuration could not be written.
install_seed_config() {
    INSTALL_CONFIG_MODE=""
    INSTALL_SHARED_SECRET=""
    mkdir -p "$BACKUP_DIR" "${BACKUP_DIR}/disabled" "$PASSWORD_DATES_DIR" || return 1
    chmod 750 "$BACKUP_DIR" "$PASSWORD_DATES_DIR"
    chmod 700 "${BACKUP_DIR}/disabled"
    chown tacquito:tacquito "$BACKUP_DIR" "$PASSWORD_DATES_DIR" || return 1

    if [[ -f "$STORE_FILE" ]]; then
        info "Existing store found at ${STORE_FILE}: its users, groups and scopes are kept (no new shared secret)."
        _backends_load || return 1
        backends_run upgrade config
        INSTALL_CONFIG_MODE="store"
        return 0
    fi
    if [[ -f "$CONFIG" ]]; then
        info "Existing ${CONFIG} found: it is kept, not replaced by a fresh configuration."
        config_sync_existing
        local rc=0
        upgrade_store_flip || rc=$?
        if (( rc == 0 )); then
            INSTALL_CONFIG_MODE="flipped"
        else
            INSTALL_CONFIG_MODE="legacy"
        fi
        return 0
    fi

    local secret
    secret=$(openssl rand -hex 16) || secret=""
    if [[ -z "$secret" ]]; then
        error "Could not generate a shared secret (openssl rand failed)."
        return 1
    fi
    info "Seeding the store at ${STORE_FILE}..."
    # The secret travels on stdin, never on argv (/proc/<pid>/cmdline).
    store_seed_fresh "$DEFAULT_SCOPE_FRESH" "$INSTALL_SCOPE_PREFIXES" \
        < <(printf '%s\n' "$secret") || return 1

    # 'tacctl user add <u> <g>' without --scopes lands new users in this
    # scope (least privilege by default). It is also tacctl's shipped
    # default, so no override is persisted. Operators who want a production
    # scope create it:
    #   tacctl scope add prod --prefixes ... --secret generate
    #   tacctl scope default prod   (if they want prod-default posture)
    write_default_scope "$DEFAULT_SCOPE_FRESH" || return 1
    info "Default scope seeded: ${DEFAULT_SCOPE_FRESH} (new users land here unless --scopes given)"
    # A tacctl.yaml adopted from an earlier install may still carry
    # pre-0.1.11 dead match regexes (no-op otherwise).
    conf_migrate_dead_command_matches

    info "Writing configuration to $(backends_artifact_names)..."
    if ! backends_render_all; then
        error "Could not render $(backends_artifact_names) from the store."
        return 1
    fi
    INSTALL_SHARED_SECRET="$secret"
    INSTALL_CONFIG_MODE="fresh"
    info "Built-in users seeded (disabled — set a password to activate):"
    info "  engineer (superuser) — disabled"
    info "  operator (operator)  — disabled"
    info "  viewer   (readonly)  — disabled"
    info "  root     (readonly)  — disabled (accounting sink for Junos internal daemons)"
}

cmd_install() {
    # Parse optional --branch flag
    local INSTALL_BRANCH=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --branch) INSTALL_BRANCH="${2:-}"; shift 2 ;;
            *) shift ;;
        esac
    done

    for cmd in git wget python3; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command '$cmd' not found. Install it first."
            exit 1
        fi
    done

    local PROJECT_DIR
    PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

    echo ""
    echo "============================================"
    echo "  tacctl Installer"
    echo "============================================"
    echo ""
    echo "This will:"
    echo "  - Install tacctl (${DEPLOY_DIR}, /usr/local/bin/tacctl) and its state directory (${TACCTL_STATE_DIR})"
    echo "  - Install the TACACS+ backend: Go ${GO_VERSION} (if not present), tacquito built from"
    echo "    source, a 'tacquito' service user, the service on port 49/tcp"
    echo "  - Seed the store: scope '${DEFAULT_SCOPE_FRESH}' with a generated shared secret, built-in"
    echo "    users created disabled (an existing configuration is kept instead)"
    echo ""
    echo "RADIUS (FreeRADIUS) is not installed; add it later with: tacctl backend enable radius"
    echo ""

    read -rp "Continue with installation? [y/N]: " confirm || true
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    echo ""

    # --- Steps 1-2: each backend's daemon (for tacquito: Go, source, build) ---
    _backends_load || exit 1
    backends_run install build "$PROJECT_DIR"

    # Clone management repo for future upgrades
    local branch_flag=()
    [[ -n "$INSTALL_BRANCH" ]] && branch_flag=(--branch "$INSTALL_BRANCH")
    if [[ -d "${DEPLOY_DIR}/.git" ]]; then
        info "Management repo already cloned at ${DEPLOY_DIR}, pulling latest..."
        cd "$DEPLOY_DIR"
        if [[ -n "$INSTALL_BRANCH" ]]; then
            git checkout "$INSTALL_BRANCH" &>/dev/null || true
        fi
        git pull --quiet 2>/dev/null || true
    else
        [[ -d "$DEPLOY_DIR" ]] && rm -rf "$DEPLOY_DIR"
        git clone --quiet "${branch_flag[@]}" "$MANAGE_REPO" "$DEPLOY_DIR"
        info "Management repo cloned to ${DEPLOY_DIR}"
    fi
    normalize_deploy_perms
    # Whitelist the repo as safe for every user on the box (not just root).
    # /opt/tacctl is a root-owned clone; without a --system entry, an
    # unprivileged operator running `git -C /opt/tacctl log` hits "fatal:
    # detected dubious ownership". --system writes to /etc/gitconfig so all
    # users inherit the exception. Idempotent: skip if the entry is already
    # present, since --add would otherwise duplicate. (A backend built from
    # source does the same for its checkout.)
    ensure_safe_directory "$DEPLOY_DIR"

    # Symlink management CLI (755 so non-root users can exec into sudo)
    chmod 755 "${DEPLOY_DIR}/bin/tacctl.sh"
    ln -sf "${DEPLOY_DIR}/bin/tacctl.sh" /usr/local/bin/tacctl
    # Create the state directory (and adopt any state from /etc/tacquito) before anything writes to it
    state_migrate || exit 1
    # Install default config templates
    if [[ -d "${PROJECT_DIR}/config/templates" ]]; then
        mkdir -p "${TEMPLATE_DIR_LOCAL}"
        cp -n "${PROJECT_DIR}/config/templates/"*.template "${TEMPLATE_DIR_LOCAL}/" 2>/dev/null || true
        info "Config templates installed: ${TEMPLATE_DIR_LOCAL}/"
    fi
    # Each backend's system files (logrotate config)
    backends_run install files "$PROJECT_DIR"
    # Install bash completion
    if [[ -f "${PROJECT_DIR}/config/tacctl.bash-completion" ]]; then
        cp "${PROJECT_DIR}/config/tacctl.bash-completion" /etc/bash_completion.d/tacctl
        chmod 644 /etc/bash_completion.d/tacctl
        info "Bash completion installed: /etc/bash_completion.d/tacctl"
    fi
    # Install man page
    if [[ -f "${PROJECT_DIR}/man/tacctl.1" ]]; then
        install_man_page "${PROJECT_DIR}/man/tacctl.1"
        info "Man page installed: /usr/share/man/man1/tacctl.1.gz"
    fi

    info "Management CLI installed:"
    info "  tacctl — user, config, and system management"
    info "  Deploy source: ${DEPLOY_DIR}"

    # --- Step 3: Install packages (python3-bcrypt and the rest) ---
    if command -v apt-get &>/dev/null; then
        ensure_dependencies || exit 1
    fi
    if ! python3 -c "import bcrypt" 2>/dev/null; then
        info "Installing python3-bcrypt..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y -qq python3-bcrypt
        elif command -v dnf &>/dev/null; then
            dnf install -y -q python3-bcrypt
        elif command -v yum &>/dev/null; then
            yum install -y -q python3-bcrypt
        else
            error "Cannot install python3-bcrypt automatically. Install it manually."
            exit 1
        fi
    fi

    # --- Step 4: Create service users and directories ---
    backends_run install account "$PROJECT_DIR"

    # --- Steps 5-6: Shared secret, store, configuration ---
    local CONFIG_FILE="$CONFIG"
    install_seed_config || exit 1

    # --- Steps 7-9: Install, start and verify each backend's service ---
    backends_run install start "$PROJECT_DIR"

    # --- Summary ---
    echo ""
    echo "============================================"
    echo "  Installation Complete"
    echo "============================================"
    echo ""
    echo "  TACACS+:        tacquito.service (enabled, running)"
    echo "  Store:          ${STORE_FILE}"
    echo "  Config:         ${CONFIG_FILE} (rendered from the store)"
    echo "  Accounting log: ${LOG_DIR}/accounting.log"
    echo ""
    if [[ "$INSTALL_CONFIG_MODE" != "fresh" ]]; then
        # Existing data was kept: no new secret, no seeded users.
        case "$INSTALL_CONFIG_MODE" in
            store)   echo "  Existing store kept: users, groups, scopes and shared secrets are unchanged." ;;
            flipped) echo "  Existing tacquito.yaml kept and moved into the store: users, scopes and shared secrets are unchanged." ;;
            *)       echo -e "  ${YELLOW}Existing tacquito.yaml kept, NOT moved into the store: legacy read-only mode (see the report above).${NC}" ;;
        esac
        echo "  Show a scope's shared secret: tacctl scope secret <scope> show"
        echo ""
        return 0
    fi
    echo "  Shared Secret:  ${INSTALL_SHARED_SECRET}"
    echo ""
    echo -e "  ${RED}SAVE THE SHARED SECRET${NC} (shown again by: tacctl scope secret ${DEFAULT_SCOPE_FRESH} show)."
    echo -e "  ${YELLOW}Clear your terminal after recording: history -c && clear${NC}"
    echo ""
    echo "  Built-in users:"
    echo "    engineer (superuser)   — disabled; tacctl user passwd engineer"
    echo "    operator (operator)    — disabled; tacctl user passwd operator"
    echo "    viewer   (readonly)    — disabled; tacctl user passwd viewer"
    echo "    root     (readonly)    — permanent accounting-only sink (never authenticates)"
    echo ""
    echo "  Next steps:"
    echo "    1. Activate a built-in:    tacctl user passwd engineer"
    echo "       (or add your own:       tacctl user add <username> <group>)"
    echo "    2. Configure devices:      tacctl config cisco / tacctl config juniper"
    echo "    3. Narrow scope prefixes:  tacctl scope prefixes ${DEFAULT_SCOPE_FRESH} <your-subnets>"
    echo "    4. Add a prod scope:       tacctl scope add prod --prefixes <cidrs> --secret generate"
    echo "    5. Open port 49/tcp in your firewall if needed"
    echo "    6. RADIUS as well (optional): tacctl backend enable radius"
    echo ""
    echo "  Security hardening:"
    echo "    7. Bind to a specific IP:  tacctl config listen tcp <mgmt-ip>:49"
    echo "    8. Add connection ACL:     tacctl config allow add <cidr>"
    echo "    9. Review config:          tacctl config show"
    echo ""
}

# --- UPGRADE ---
# Files 'tacctl upgrade' replaced; counted by update_if_changed and by the
# backends' 'files' phase, read by their 'finish' phase and the summary.
SCRIPTS_UPDATED=0

# update_if_changed <src> <dest> <label>: copy a shipped file over the
# installed one when they differ. No-op when <src> does not exist.
update_if_changed() {
    local src="$1" dest="$2" label="$3"
    if [[ ! -f "$src" ]]; then return; fi
    if diff -q "$src" "$dest" &>/dev/null; then
        info "  Unchanged: ${label}"
    else
        cp "$src" "$dest"
        info "  Updated: ${label}"
        SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
    fi
}

# "tacacs (tacquito), radius (freeradius)": the enabled backends, for the banner.
upgrade_backend_names() {
    local _b impl out=""
    for _b in "${BACKENDS_ENABLED[@]}"; do
        impl=$(backend_describe "$_b" impl 2> /dev/null) || impl=""
        out+="${out:+, }${_b}${impl:+ (${impl})}"
    done
    echo "$out"
}

# NOTE: Git pulls rely on HTTPS transport security. Commit signature verification
# is not enforced. The self-update exec re-runs the script after a git pull — the
# pulled code runs as root. Verify the repo's integrity in sensitive environments.
cmd_upgrade() {
    # Parse optional --branch flag
    local UPGRADE_BRANCH=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --branch) UPGRADE_BRANCH="${2:-}"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Each backend checks that it can be upgraded at all, before anything is touched.
    _backends_load || exit 1
    backends_run upgrade preflight

    # Whitelist the repo as safe for every user on the box (not just root).
    # /opt/tacctl is a root-owned clone; without a --system entry, an
    # unprivileged operator running `git -C /opt/tacctl log` hits "fatal:
    # detected dubious ownership". --system writes to /etc/gitconfig so all
    # users inherit the exception. Idempotent: skip if the entry is already
    # present, since --add would otherwise duplicate. (A backend built from
    # source does the same for its checkout.)
    ensure_safe_directory "$DEPLOY_DIR"

    local PROJECT_DIR
    PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

    echo ""
    echo "============================================"
    echo "  tacctl Upgrade"
    echo "============================================"
    echo ""

    # --- Move tacctl state out of /etc/tacquito (idempotent; before anything reads tacctl.yaml) ---
    state_migrate || exit 1
    # tacctl.yaml may just have moved: read backends.enabled where it is now.
    _conf_invalidate
    _backends_load || exit 1
    info "Backends: $(upgrade_backend_names)"

    # --- Pull and rebuild each backend's daemon ---
    backends_run upgrade build

    # --- Update management repo ---
    if [[ -d "${DEPLOY_DIR}/.git" ]]; then
        info "Pulling latest management scripts..."
        cd "$DEPLOY_DIR"
        # Discard local tracked-file edits so the pull can fast-forward.
        # Errors here are rare but not silenced — a failure would leave
        # local mods that block the pull a few lines later.
        git checkout -- . || {
            error "Failed to discard local modifications in ${DEPLOY_DIR}."
            error "Run 'sudo git -C ${DEPLOY_DIR} status' to investigate."
            exit 1
        }
        # Remove tacctl-managed untracked backup files that would otherwise
        # survive `git checkout -- .` and clutter the tree indefinitely.
        rm -f "${DEPLOY_DIR}"/bin/tacctl.sh.*-bak \
              "${DEPLOY_DIR}"/config/templates/*.template.*-bak 2>/dev/null || true
        if [[ -n "$UPGRADE_BRANCH" ]]; then
            # --tags --force so force-pushed tags (e.g. after a history rewrite) update locally.
            git fetch --tags --force || {
                error "git fetch failed. Check network / credentials."
                exit 1
            }
            git checkout "$UPGRADE_BRANCH" &>/dev/null || git checkout -b "$UPGRADE_BRANCH" "origin/${UPGRADE_BRANCH}" &>/dev/null
            info "Switched to branch '${UPGRADE_BRANCH}'."
        fi
        git fetch --tags --force || {
            error "git fetch failed. Check network / credentials."
            exit 1
        }
        local LOCAL_MANAGE REMOTE_MANAGE
        LOCAL_MANAGE=$(git rev-parse HEAD 2>/dev/null)
        REMOTE_MANAGE=$(git rev-parse '@{u}' 2>/dev/null || echo "")
        if [[ -n "$REMOTE_MANAGE" && "$LOCAL_MANAGE" != "$REMOTE_MANAGE" ]]; then
            # Stderr NOT silenced so failures surface (conflicts, diverged
            # branches, overwrite-would-happen, etc.). --ff-only refuses any
            # merge scenario; upgrades should be fast-forward only.
            if ! git pull --ff-only; then
                error "git pull failed. Common causes:"
                error "  - local commits on ${DEPLOY_DIR} diverging from origin"
                error "  - untracked files that would be overwritten"
                error "Run 'sudo git -C ${DEPLOY_DIR} status' to investigate."
                exit 1
            fi
            info "Management scripts updated: $(git rev-parse --short HEAD)"

            # If tacctl's own code changed (entrypoint or lib/), re-run the new version
            if ! git diff --quiet "$LOCAL_MANAGE" HEAD -- bin lib; then
                info "tacctl updated — restarting upgrade with new version..."
                exec "${DEPLOY_DIR}/bin/tacctl.sh" upgrade
            fi
        else
            info "Management scripts already up to date."
        fi
    elif [[ ! -d "$DEPLOY_DIR" ]]; then
        info "Cloning management repo..."
        git clone --quiet "$MANAGE_REPO" "$DEPLOY_DIR" || warn "Failed to clone management repo."
    fi
    # Always normalize, even when nothing was pulled -- self-healing for
    # prior installs whose files were left at 0600 by the script's umask.
    normalize_deploy_perms

    # A newer tacctl may need packages the last one did not.
    ensure_dependencies || exit 1

    # --- Ensure symlink exists (755 so non-root users can exec into sudo) ---
    if [[ -d "$DEPLOY_DIR" ]]; then
        chmod 755 "${DEPLOY_DIR}/bin/tacctl.sh"
        ln -sf "${DEPLOY_DIR}/bin/tacctl.sh" /usr/local/bin/tacctl
    fi

    # --- Bring the existing config in line with this release ---
    # Legacy migrations of tacquito.yaml, or a re-render once the store
    # exists (RADIUS: re-render, drop-in, restart). The store gate in
    # 'finish' judges the file as this leaves it. Here, after the pull and
    # its re-exec, so that it runs once and with the code being installed,
    # and its output (a backend restart among it) follows the build and the
    # scripts update instead of preceding them.
    backends_run upgrade config

    # --- Update system config files ---
    info "Updating system files..."
    SCRIPTS_UPDATED=0
    local ACTIVE_DEPLOY_DIR="$DEPLOY_DIR"

    if [[ ! -d "$ACTIVE_DEPLOY_DIR" ]]; then
        # Fall back to script's own project dir
        ACTIVE_DEPLOY_DIR="$PROJECT_DIR"
    fi

    if [[ -z "$ACTIVE_DEPLOY_DIR" ]]; then
        warn "Deploy directory not found. Skipping updates."
        warn "To fix: clone the repo to ${DEPLOY_DIR}"
    fi

    # Each backend's unit and system files (for tacquito also README.md in
    # its config directory).
    backends_run upgrade files "$ACTIVE_DEPLOY_DIR"

    update_if_changed "${ACTIVE_DEPLOY_DIR}/config/tacctl.bash-completion" "/etc/bash_completion.d/tacctl" "bash completion"
    chmod 644 /etc/bash_completion.d/tacctl 2>/dev/null || true
    # Man page: unconditional re-gzip (cheap, <10 KB) also heals hosts where the file is missing.
    install_man_page "${ACTIVE_DEPLOY_DIR}/man/tacctl.1"

    # Update default config templates (only if user hasn't customized them)
    if [[ -d "${ACTIVE_DEPLOY_DIR}/config/templates" ]]; then
        mkdir -p "${TEMPLATE_DIR_LOCAL}"
        for tmpl in "${ACTIVE_DEPLOY_DIR}/config/templates/"*.template; do
            [[ -f "$tmpl" ]] || continue
            local tmpl_name dest
            tmpl_name=$(basename "$tmpl")
            dest="${TEMPLATE_DIR_LOCAL}/${tmpl_name}"
            if [[ ! -f "$dest" ]]; then
                cp "$tmpl" "$dest"
                info "  Installed: ${tmpl_name}"
                SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
            else
                update_if_changed "$tmpl" "$dest" "template: ${tmpl_name}"
            fi
        done
    fi

    info "${SCRIPTS_UPDATED} file(s) updated."

    # --- Each backend finishes ---
    # For tacquito: move a legacy install into the store (gated; see
    # upgrade_store_flip), then one restart if its binary, its unit, a system
    # file or the rendered config changed. A stopped store migration is not
    # an upgrade failure: the code is installed and the daemon keeps its config.
    UPGRADE_SUMMARY_HEAD=""
    UPGRADE_SUMMARY_NOTES=()
    backends_run upgrade finish

    echo ""
    echo "============================================"
    echo "  ${UPGRADE_SUMMARY_HEAD:-Upgrade Complete}"
    echo "  Managed scripts: ${SCRIPTS_UPDATED} updated"
    local note
    for note in ${UPGRADE_SUMMARY_NOTES[@]+"${UPGRADE_SUMMARY_NOTES[@]}"}; do
        echo "  ${note}"
    done
    echo "============================================"
    echo ""
}

# --- UNINSTALL ---
# uninstall_remove_access: remove what grants or serves access through a
# tacctl that is about to be gone. Both sudoers drop-ins go: the tier rules
# allow commands of the removed binary to the tier groups, and must not
# outlive it. So does the Linux host data (pam_tacplus source and prebuilt
# modules), and its parent directory when that leaves it empty.
uninstall_remove_access() {
    rm -f "$SUDOERS_FILE" "$TIER_SUDOERS_FILE"
    rm -rf "${LINUX_DIR:?}"
    rmdir "$(dirname "$LINUX_DIR")" 2>/dev/null || true
}

cmd_uninstall() {
    # Every backend that is enabled or still installed is removed.
    backends_select_present

    echo ""
    echo "============================================"
    echo -e "  ${RED}tacctl Uninstaller${NC}"
    echo "============================================"
    echo ""
    echo "Backends: $(upgrade_backend_names)"
    echo ""
    echo "This will remove:"
    echo "  - Management CLI (tacctl), its state directory (${TACCTL_STATE_DIR}: store, tacctl.yaml, backups)"
    echo "  - Sudoers rules (${SUDOERS_FILE}, ${TIER_SUDOERS_FILE})"
    echo "  - Bash completion (/etc/bash_completion.d/tacctl) and man page"
    echo "  - Linux host build data (${LINUX_DIR})"
    echo "  - Management repo (${DEPLOY_DIR})"
    echo "  - TACACS+ (tacquito): service and units, binary, password hash generator (tacquito-hashgen),"
    echo "    configuration directory (/etc/tacquito), log directory (/var/log/tacquito), logrotate config,"
    echo "    service user (tacquito)"
    if [[ " ${BACKENDS_ENABLED[*]} " == *" radius "* ]]; then
        echo "  - RADIUS (FreeRADIUS): tacctl's instance (its config files, unit drop-in, logs, logrotate config);"
        echo "    the FreeRADIUS package stays installed, with its own configuration as shipped"
    fi
    echo ""
    echo -e "${YELLOW}The tacquito source (/opt/tacquito-src) and Go installation"
    echo -e "(/usr/local/go) will NOT be removed.${NC}"
    echo ""

    read -rp "Are you sure you want to uninstall tacctl? [y/N]: " confirm || true
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    echo ""

    # --- Stop and disable services ---
    backends_run uninstall stop

    # --- Ask about preserving data ---
    local PRESERVE_BACKUPS=false _b logs
    local -A KEEP_LOGS=()

    echo ""
    read -rp "Preserve config backups (${BACKUP_DIR})? [y/N]: " keep_backups || true
    if [[ "$keep_backups" == "y" || "$keep_backups" == "Y" ]]; then
        PRESERVE_BACKUPS=true
    fi

    for _b in "${BACKENDS_ENABLED[@]}"; do
        logs=$(backend_describe "$_b" log_dir) || continue
        read -rp "Preserve accounting logs (${logs})? [y/N]: " keep_logs || true
        if [[ "$keep_logs" == "y" || "$keep_logs" == "Y" ]]; then
            KEEP_LOGS[$_b]=1
        fi
    done

    echo ""

    # --- Remove symlinks and binaries, then each backend's unit ---
    info "Removing binaries and symlinks..."
    rm -f /usr/local/bin/tacctl
    backends_run uninstall program

    # --- Remove sudoers rules and Linux host build data ---
    info "Removing sudoers rules and Linux host build data..."
    uninstall_remove_access

    # --- Remove logrotate config and bash completion ---
    # (each backend removes its logrotate file with its data, below)
    info "Removing logrotate config and bash completion..."
    rm -f /etc/bash_completion.d/tacctl

    # --- Remove man page ---
    info "Removing man page..."
    rm -f /usr/share/man/man1/tacctl.1.gz
    mandb -q 2>/dev/null || true

    # --- Remove configuration ---
    local BACKUP_ARCHIVE=""
    if [[ "$PRESERVE_BACKUPS" == "true" ]]; then
        # Backups of a host that never ran state_migrate are still under /etc/tacquito.
        local backups_parent=""
        if [[ -d "${TACCTL_STATE_DIR}/backups" ]]; then
            backups_parent="$TACCTL_STATE_DIR"
        elif [[ -d /etc/tacquito/backups && ! -L /etc/tacquito/backups ]]; then
            backups_parent=/etc/tacquito
        fi
        if [[ -n "$backups_parent" ]]; then
            BACKUP_ARCHIVE="/root/tacquito-backups-$(date +%Y%m%d_%H%M%S).tar.gz"
            tar czf "$BACKUP_ARCHIVE" -C "$backups_parent" backups/ 2>/dev/null || true
            info "Config backups saved to ${BACKUP_ARCHIVE}"
        fi
    fi
    info "Removing configuration and state directories..."
    rm -rf "${TACCTL_STATE_DIR:?}"

    # --- Each backend's config directory and logs ---
    UNINSTALL_SAVED=()
    for _b in "${BACKENDS_ENABLED[@]}"; do
        if [[ -n "${KEEP_LOGS[$_b]:-}" ]]; then
            backend_call "$_b" uninstall data --keep-logs
        else
            backend_call "$_b" uninstall data
        fi
    done

    # --- Remove management repo ---
    info "Removing management repo..."
    rm -rf "$DEPLOY_DIR"

    # --- Drop the system-wide git safe.directory entry for the removed repo ---
    # Best-effort: git may complain if no entries exist; silent on failure.
    git config --system --unset-all safe.directory "$(printf '^%s$' "$DEPLOY_DIR")" 2>/dev/null || true

    # --- Each backend's source-checkout entry and service user ---
    backends_run uninstall account

    echo ""
    echo "============================================"
    echo "  Uninstall Complete"
    echo "============================================"
    echo ""
    echo "  Removed:"
    echo "    - TACACS+ (tacquito) service and binary"
    echo "    - Management CLI and symlinks"
    echo "    - Configuration and systemd unit"
    echo "    - Logrotate config, sudoers rules, bash completion"
    echo "    - Service user"
    if [[ "$PRESERVE_BACKUPS" == "true" && -n "$BACKUP_ARCHIVE" ]]; then
        echo "    - Config backups saved to: ${BACKUP_ARCHIVE}"
    fi
    local saved
    for saved in ${UNINSTALL_SAVED[@]+"${UNINSTALL_SAVED[@]}"}; do
        echo "    - ${saved}"
    done
    echo ""
    echo "  Not removed:"
    echo "    - Go installation (/usr/local/go)"
    echo "    - tacquito source (/opt/tacquito-src)"
    echo "    - python3-bcrypt package"
    echo ""
}

