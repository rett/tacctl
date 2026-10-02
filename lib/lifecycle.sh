# shellcheck shell=bash
# shellcheck disable=SC2164  # errexit is set by bin/tacctl.sh before this file is sourced
# tacctl lib/lifecycle.sh -- tacquito patch overlay, deploy-repo helpers, config branch, state migration, config seeding and the store gate, install/upgrade/uninstall
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# --- tacquito source patch overlay (see patches/README.md) ---
# tacquito is built from an upstream checkout; behaviors we depend on but that
# are not upstream live as git-apply diffs in $PATCH_DIR and are re-applied
# after every upstream pull so they survive updates.

# tacquito_patches_applied succeeds only when EVERY patch is already applied to
# the working tree (reverse-check). Lets an upgrade that found no upstream change
# still decide to rebuild when a newly-shipped patch isn't in the binary yet.
# No patches at all counts as satisfied.
tacquito_patches_applied() {
    local patch
    shopt -s nullglob
    for patch in "$PATCH_DIR"/*.patch; do
        if ! git -C "$TACQUITO_SRC" apply --reverse --check "$patch" 2>/dev/null; then
            shopt -u nullglob
            return 1
        fi
    done
    shopt -u nullglob
    return 0
}

# apply_tacquito_patches applies every patch in $PATCH_DIR onto the tacquito
# source tree. Callers run `git checkout -- .` before the upstream pull, so the
# tree is pristine upstream when we apply. Idempotent: an already-applied patch
# (reverse-check passes) is skipped. Aborts the run if a patch will not apply
# (upstream drift) rather than silently building an unpatched binary. Returns 0
# if it applied at least one patch, 1 if there was nothing to do.
apply_tacquito_patches() {
    [[ -d "$PATCH_DIR" ]] || return 1
    local patch applied=0
    shopt -s nullglob
    for patch in "$PATCH_DIR"/*.patch; do
        if git -C "$TACQUITO_SRC" apply --reverse --check "$patch" 2>/dev/null; then
            continue  # already applied
        fi
        if ! git -C "$TACQUITO_SRC" apply --check "$patch" 2>/dev/null; then
            shopt -u nullglob
            error "tacquito patch will not apply cleanly: $(basename "$patch")."
            error "Upstream likely changed the patched file; refresh the diff in patches/."
            exit 1
        fi
        git -C "$TACQUITO_SRC" apply "$patch"
        info "Applied tacquito patch: $(basename "$patch")"
        applied=$((applied + 1))
    done
    shopt -u nullglob
    [[ $applied -gt 0 ]]
}

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
DEPS_CORE="git wget python3 python3-bcrypt"
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

# --- The daemon's config: seeding, syncing, and the move into the store ---
#
# Users, groups, scopes and filters live in the store and tacquito.yaml is
# rendered from it. A fresh install is created that way (install_seed_config).
# An install from before the store still has a tacquito.yaml that is its own
# source of truth; upgrade moves it into the store through a gate
# (upgrade_store_flip) and otherwise leaves it exactly as it is.

# The daemon runs as the 'tacquito' user and must be able to read its config.
# The renderer's own chown is best-effort because the test suite runs
# unprivileged; install and upgrade run as root, where a failure is real.
config_service_access() {
    [[ $EUID -eq 0 && -f "$CONFIG" ]] || return 0
    chown tacquito:tacquito "$CONFIG" && chmod 640 "$CONFIG"
}

# Set by config_sync_existing: 1 when it changed the rendered tacquito.yaml,
# so the caller knows the daemon has to be restarted.
CONFIG_SYNC_RENDERED=0

# config_sync_existing: bring an existing install's config in line with this
# release. Idempotent; run by every upgrade before anything else looks at the
# config.
#
# Without a store, these are the in-place migrations of the legacy
# tacquito.yaml that upgrades have always run. They must stay ahead of the
# store gate: it judges the file as they leave it.
#
# With a store the legacy migrations are no-ops and the config is re-rendered
# (a new release can ship new default command rules). One case gets finished
# here: a store beside a tacquito.yaml tacctl never rendered -- an upgrade
# interrupted between writing the store and rendering, or a manual
# 'tacctl store import'. When the render passes what the gate asks for
# (equivalent to that file, and the daemon loads it) it replaces the file;
# when it does not, the file is the operator's to resolve and is left alone.
config_sync_existing() {
    CONFIG_SYNC_RENDERED=0
    # Pre-unified-commands installs kept operator-customized commands:
    # blocks in tacquito.yaml; scrape those back into tacctl.yaml as
    # overrides (idempotent: no-op once scraped).
    conf_migrate_command_rules
    # tacctl <= 0.1.10 shipped match regexes that repeated the command word
    # (`^show .*$`); tacquito tests match against the arguments only, so
    # operator/readonly users were denied every `show`. Heal overrides that
    # still carry that shape.
    conf_migrate_dead_command_matches
    # Legacy installs named the Cisco exec service `name: exec`; devices request
    # `service=shell`, so authorization silently failed post-auth. Heal in place.
    conf_migrate_exec_service_name
    if [[ ! -f "$STORE_FILE" ]]; then
        regenerate_tacquito_commands
        return 0
    fi

    local force=() result rc=0
    rendered_check "$CONFIG" > /dev/null || rc=$?
    if (( rc == 3 )); then
        if ! ( _config_render_is_proven ); then
            warn "${CONFIG} was not rendered by tacctl, and what the store renders is not proven equivalent to it; it was left as it is."
            warn "To keep what the file says: 'tacctl store import --replace', then 'tacctl config render --force'."
            warn "To replace it with the store's content: 'tacctl config render --force'."
            return 0
        fi
        info "${CONFIG} is equivalent to what the store renders; replacing it with the rendered file."
        force=(--force)
    fi
    rc=0
    result=$(tacacs_render_apply "${force[@]}") || rc=$?
    if (( rc != 0 )); then
        warn "tacquito.yaml was not re-rendered; run 'tacctl config render' once the problem above is fixed."
    elif [[ "$result" == "CHANGED" ]]; then
        CONFIG_SYNC_RENDERED=1
    fi
    return 0
}

# Run in a subshell (it owns a temp dir holding a rendered config): succeeds
# when what the store renders is equivalent to the live tacquito.yaml and the
# daemon loads it. As at the gate, a load-smoke that cannot run is not a pass.
_config_render_is_proven() {
    local tmpd
    tmpd=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064  # expand tmpd now; the subshell owns this trap
    trap "rm -rf '${tmpd}'" EXIT
    _tacacs_render_live "${tmpd}/tacquito.yaml" > /dev/null || exit 1
    store_equiv_check "$CONFIG" "${tmpd}/tacquito.yaml" > /dev/null 2>&1 || exit 1
    store_smoke_hook "${tmpd}/tacquito.yaml" || exit 1
    exit 0
}

# upgrade_store_flip: move a legacy install into the store, if and only if
# that is proven not to change what the daemon does.
#   return 0   flipped: store written, tacquito.yaml rendered from it and
#              recorded. The caller restarts the daemon.
#          10  nothing to do: a store exists. It is never re-imported.
#          20  stopped: nothing was changed, the install stays in legacy
#              read-only mode, the daemon must not be restarted on our account.
#
# The gate is 'tacctl store import --check': import, validate, render,
# equivalence with the live file, and the daemon loading the rendered file.
# Only its "proven" verdict (exit 0) passes; a failed check (1) and a clean
# import whose equivalence was not proven (3) both stop. So does a missing
# daemon binary: the check would skip the load-smoke and still report
# success, and an upgrade always has the binary it just built or kept.
# Nothing is forced and the legacy file is not rewritten to make it pass.
#
# Order after the gate, and what an interruption leaves behind:
#   1. the legacy file is kept as backups/legacy/tacquito.yaml.pre-store.<ts>
#      (interrupted here: still legacy mode; the next run reuses the copy);
#   2. the store is written (interrupted here: store mode with the legacy
#      file still live and equivalent; config_sync_existing finishes the
#      render on the next upgrade, and so does any mutating command);
#   3. tacquito.yaml is rendered and its checksum recorded;
#   4. the installed file is compared with the kept one once more. If 3 or 4
#      fails the store is removed again and the legacy file is live as before.
upgrade_store_flip() {
    if [[ -f "$STORE_FILE" ]]; then
        return 10
    fi
    echo ""
    info "Store migration: ${STORE_FILE} does not exist yet."
    if [[ ! -f "$CONFIG" ]]; then
        _upgrade_flip_stopped "there is no ${CONFIG} to import"
        return 20
    fi
    if [[ ! -x "$TACQUITO_BIN" ]] || ! command -v timeout > /dev/null 2>&1; then
        _upgrade_flip_stopped "the daemon load-smoke cannot run (${TACQUITO_BIN} or 'timeout' is missing), so the rendered config cannot be proven to load"
        return 20
    fi

    info "Checking that ${CONFIG} can move into the store without changing what tacquito does (the check writes nothing)..."
    local rc=0
    store_import --check || rc=$?
    case "$rc" in
        0) ;;
        3)
            _upgrade_flip_stopped "the import is clean but its equivalence with ${CONFIG} was not proven"
            return 20
            ;;
        *)
            _upgrade_flip_stopped "the check above did not pass"
            return 20
            ;;
    esac

    info "Gate passed: writing the store and rendering ${CONFIG} from it..."
    # The report was printed by the check; errors still reach stderr.
    if ! store_import > /dev/null; then
        _upgrade_flip_stopped "the import failed after a clean check"
        return 20
    fi
    local pre
    if ! pre=$(store_pre_store_latest); then
        rm -f "$STORE_FILE"
        _model_invalidate
        _upgrade_flip_stopped "the pre-store copy of ${CONFIG} is missing"
        return 20
    fi
    # --force, deliberately: this is the first render over a file tacctl
    # never rendered, and that file is the pre-store copy just kept.
    if ! tacacs_render_apply --force > /dev/null; then
        _store_unflip "$pre" || true
        _upgrade_flip_stopped "${CONFIG} could not be rendered from the store (the store was removed again)"
        return 20
    fi
    if ! store_equiv_check "$pre" "$CONFIG" > /dev/null 2>&1; then
        _store_unflip "$pre" || true
        _upgrade_flip_stopped "the rendered ${CONFIG} was not equivalent to the file it replaced (that file is back and the store was removed again)"
        return 20
    fi
    config_service_access \
        || warn "Could not make ${CONFIG} readable by the tacquito service user (expected tacquito:tacquito, 0640); fix that before the service restarts."

    info "Store migration complete: users, groups, scopes and filters now live in ${STORE_FILE}."
    info "  ${CONFIG} is rendered from the store; change it with tacctl commands."
    info "  'tacctl store rollback' returns to the kept pre-store file."
    return 0
}

# Said when the daemon does not come back after an upgrade that flipped.
_upgrade_flip_hint() {
    [[ "$1" == "flipped" ]] || return 0
    error "This upgrade moved the configuration into the store. If the rendered ${CONFIG} is the cause, 'tacctl store rollback' restores the previous file."
}

_upgrade_flip_stopped() {
    echo ""
    warn "Store migration stopped: $1."
    warn "${CONFIG} and the running daemon were left as they are."
    warn "tacctl stays in legacy read-only mode: read commands work; commands that change users, groups, scopes or filters are refused."
    warn "To proceed: 'tacctl store import --check' prints the report again. Fix what it lists in ${CONFIG} and run 'tacctl upgrade' again,"
    warn "or accept the difference yourself: 'tacctl store import' (--force drops what the store cannot hold), then 'tacctl config render --force'."
    echo ""
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
        config_sync_existing
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

    info "Writing configuration to ${CONFIG}..."
    if ! tacacs_render_apply > /dev/null; then
        error "Could not render ${CONFIG} from the store."
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

# install_readme <src>: put README.md in the config directory, readable by
# everyone (the script's umask would leave it 0600). No-op without <src>.
install_readme() {
    local src="$1" dest="${CONFIG_DIR}/README.md"
    [[ -f "$src" ]] || return 0
    cp "$src" "$dest" && chmod 644 "$dest"
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
    echo "  Tacquito TACACS+ Server Installer"
    echo "============================================"
    echo ""
    echo "This will:"
    echo "  - Install Go ${GO_VERSION} (if not present)"
    echo "  - Clone and build tacquito from source"
    echo "  - Create a 'tacquito' service user"
    echo "  - Configure and start the TACACS+ service on port 49"
    echo "  - Prompt for shared secret and user passwords"
    echo ""

    read -rp "Continue with installation? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    echo ""

    # --- Step 1: Install Go ---
    if command -v /usr/local/go/bin/go &>/dev/null; then
        local CURRENT_GO
        CURRENT_GO=$(/usr/local/go/bin/go version | awk '{print $3}')
        if [[ "$CURRENT_GO" == "go${GO_VERSION}" ]]; then
            info "Go ${GO_VERSION} already installed, skipping."
        else
            warn "Go ${CURRENT_GO} found, upgrading to ${GO_VERSION}..."
            rm -rf /usr/local/go
        fi
    fi

    if ! command -v /usr/local/go/bin/go &>/dev/null; then
        info "Installing Go ${GO_VERSION}..."
        cd /tmp
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
        # Verify checksum
        local GO_SHA256
        GO_SHA256=$(wget -qO- "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz.sha256" 2>/dev/null || true)
        if [[ -n "$GO_SHA256" ]]; then
            local ACTUAL_SHA256
            ACTUAL_SHA256=$(sha256sum "go${GO_VERSION}.linux-amd64.tar.gz" | awk '{print $1}')
            if [[ "$GO_SHA256" != "$ACTUAL_SHA256" ]]; then
                error "Go tarball checksum mismatch!"
                error "  Expected: ${GO_SHA256}"
                error "  Got:      ${ACTUAL_SHA256}"
                rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
                exit 1
            fi
            info "Go tarball checksum verified."
        else
            warn "Could not fetch Go checksum for verification."
        fi
        tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
        rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
        info "Go ${GO_VERSION} installed."
    fi

    export PATH=$PATH:/usr/local/go/bin

    # --- Step 2: Clone and build tacquito ---
    if [[ -d "$TACQUITO_SRC" ]]; then
        info "Tacquito source already exists at ${TACQUITO_SRC}, pulling latest..."
        cd "$TACQUITO_SRC"
        # Drop any previously-applied source patches so the pull stays clean.
        git checkout -- . 2>/dev/null || true
        git pull --quiet
    else
        info "Cloning tacquito..."
        git clone --quiet "$TACQUITO_REPO" "$TACQUITO_SRC"
    fi

    # Re-apply our source patch overlay on top of pristine upstream (see
    # patches/README.md). Aborts on a patch that no longer applies.
    apply_tacquito_patches || true

    info "Building tacquito server..."
    cd "${TACQUITO_SRC}/cmds/server"
    go build -o "$TACQUITO_BIN" .

    info "Building password hash generator..."
    cd "${TACQUITO_SRC}/cmds/server/config/authenticators/bcrypt/generator"
    go build -o "$HASHGEN_BIN" .

    # go build honors umask (often 022 → 755), but stricter umask settings
    # (077) or existing 700 binaries from prior builds leave the tacquito
    # binary unreadable/unexecutable by the service user. Pin 755 so
    # systemd's User=tacquito can always exec.
    chmod 755 "$TACQUITO_BIN" "$HASHGEN_BIN"

    info "Binaries installed:"
    info "  Server:  ${TACQUITO_BIN}"
    info "  Hashgen: ${HASHGEN_BIN}"

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
    # Whitelist the two repos as safe for every user on the box (not just
    # root). /opt/tacctl and /opt/tacquito-src are root-owned clones; without
    # a --system entry, an unprivileged operator running `git -C /opt/tacctl
    # log` hits "fatal: detected dubious ownership". --system writes to
    # /etc/gitconfig so all users inherit the exception. Idempotent: skip if
    # the entry is already present, since --add would otherwise duplicate.
    ensure_safe_directory "$DEPLOY_DIR" "$TACQUITO_SRC"

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
    # Install logrotate config
    if [[ -f "${PROJECT_DIR}/config/tacquito.logrotate" ]]; then
        cp "${PROJECT_DIR}/config/tacquito.logrotate" /etc/logrotate.d/tacquito
        info "Log rotation installed: /etc/logrotate.d/tacquito"
    fi
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

    # --- Step 4: Create service user and directories ---
    if ! id tacquito &>/dev/null; then
        info "Creating tacquito service user..."
        useradd --system --no-create-home --shell /usr/sbin/nologin tacquito
    else
        info "Service user 'tacquito' already exists."
    fi

    mkdir -p "$CONFIG_DIR" "$LOG_DIR"
    chown tacquito:tacquito "$CONFIG_DIR" "$LOG_DIR"
    # CONFIG_DIR is world-traversable so everyone can read README.md; sensitive files inside (tacquito.yaml, backups) are 0640 and stay protected by their own perms. LOG_DIR stays 0750.
    chmod 755 "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"
    install_readme "${PROJECT_DIR}/README.md" || warn "Could not install ${CONFIG_DIR}/README.md."

    # --- Steps 5-6: Shared secret, store, configuration ---
    local CONFIG_FILE="$CONFIG"
    install_seed_config || exit 1
    if ! config_service_access; then
        error "Could not make ${CONFIG_FILE} readable by the tacquito service user."
        exit 1
    fi

    # --- Step 7: Install systemd service ---
    info "Installing systemd service..."
    cp "${PROJECT_DIR}/config/tacquito.service" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable tacquito.service

    # --- Step 8: Start the service ---
    info "Starting tacquito..."
    systemctl start tacquito.service
    sleep 2

    if systemctl is-active --quiet tacquito.service; then
        info "Tacquito is running!"
    else
        error "Tacquito failed to start. Check: journalctl -u tacquito"
        exit 1
    fi

    # --- Step 9: Verify ---
    local LISTEN_CHECK
    LISTEN_CHECK=$(ss -tlnp | grep ":49 " || true)
    if [[ -n "$LISTEN_CHECK" ]]; then
        info "Listening on port 49/tcp"
    else
        warn "Port 49 not detected — check logs."
    fi

    # --- Summary ---
    echo ""
    echo "============================================"
    echo "  Installation Complete"
    echo "============================================"
    echo ""
    echo "  Service:        tacquito.service (enabled, running)"
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
    echo ""
    echo "  Security hardening:"
    echo "    6. Bind to a specific IP:  edit ${SERVICE_FILE}"
    echo "       Change '-address :49' to '-address <mgmt-ip>:49'"
    echo "       Then: systemctl daemon-reload && systemctl restart tacquito"
    echo "    7. Add connection ACL:     tacctl config allow add <cidr>"
    echo "    8. Review config:          tacctl config show"
    echo ""
}

# --- UPGRADE ---
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

    if [[ ! -d "$TACQUITO_SRC" ]]; then
        error "Tacquito source not found at ${TACQUITO_SRC}. Run 'tacctl install' first."
        exit 1
    fi

    if [[ ! -x "$GO_BIN" ]]; then
        error "Go not found at ${GO_BIN}. Install Go first."
        exit 1
    fi

    export PATH=$PATH:/usr/local/go/bin

    # Whitelist the two repos as safe for every user on the box (not just
    # root). /opt/tacctl and /opt/tacquito-src are root-owned clones; without
    # a --system entry, an unprivileged operator running `git -C /opt/tacctl
    # log` hits "fatal: detected dubious ownership". --system writes to
    # /etc/gitconfig so all users inherit the exception. Idempotent: skip if
    # the entry is already present, since --add would otherwise duplicate.
    ensure_safe_directory "$DEPLOY_DIR" "$TACQUITO_SRC"

    local PROJECT_DIR
    PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

    echo ""
    echo "============================================"
    echo "  Tacquito Upgrade"
    echo "============================================"
    echo ""

    # --- Move tacctl state out of /etc/tacquito (idempotent; before anything reads tacctl.yaml) ---
    state_migrate || exit 1

    # --- Bring the existing config in line with this release ---
    # Legacy migrations of tacquito.yaml, or a re-render once the store
    # exists. The store gate further down judges the file as this leaves it.
    config_sync_existing

    # --- Record current version ---
    local CURRENT_COMMIT
    CURRENT_COMMIT=$(cd "$TACQUITO_SRC" && git rev-parse --short HEAD)
    info "Current commit: ${CURRENT_COMMIT}"

    # --- Pull latest source ---
    info "Pulling latest source..."
    cd "$TACQUITO_SRC"
    git fetch --quiet
    local LOCAL REMOTE SKIP_BUILD
    # Default to the current commit so the summary is always defined even when a
    # rebuild is driven by a patch overlay change rather than an upstream pull.
    local NEW_COMMIT="$CURRENT_COMMIT"
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse '@{u}')

    # Rebuild when upstream advanced, OR a shipped source patch isn't applied
    # yet (a new patch can land with unchanged upstream), OR the binary is
    # missing. patches/ lives in the management repo; on an upgrade that ships a
    # new patch, tacctl self-updates and re-execs (below) before reaching here,
    # so PATCH_DIR is current by this point.
    if [[ "$LOCAL" == "$REMOTE" ]] && tacquito_patches_applied && [[ -f "$TACQUITO_BIN" ]]; then
        info "Tacquito source already up to date (${CURRENT_COMMIT}); patches applied."
        SKIP_BUILD=true
    else
        SKIP_BUILD=false
        if [[ -f "$TACQUITO_BIN" ]]; then
            cp "$TACQUITO_BIN" "${TACQUITO_BIN}.bak"
            info "Backed up current binary to ${TACQUITO_BIN}.bak"
        fi
    fi

    if [[ "$SKIP_BUILD" == "false" ]]; then
        # Drop previously-applied patches so the pull is clean, then rebuild from
        # pristine upstream + our patch overlay (see patches/README.md).
        git checkout -- . 2>/dev/null || true
        if [[ "$LOCAL" != "$REMOTE" ]]; then
            git pull --quiet
            NEW_COMMIT=$(git rev-parse --short HEAD)
            info "Updated: ${CURRENT_COMMIT} -> ${NEW_COMMIT}"

            echo ""
            info "Changes:"
            git log --oneline "${CURRENT_COMMIT}..${NEW_COMMIT}" | head -20
            echo ""
        fi
        apply_tacquito_patches || true

        info "Building tacquito server..."
        cd "${TACQUITO_SRC}/cmds/server"
        if ! go build -o "$TACQUITO_BIN" . ; then
            error "Build failed. Restoring previous binary."
            mv "${TACQUITO_BIN}.bak" "$TACQUITO_BIN"
            exit 1
        fi

        info "Building password hash generator..."
        cd "${TACQUITO_SRC}/cmds/server/config/authenticators/bcrypt/generator"
        go build -o "$HASHGEN_BIN" . || warn "Hashgen build failed (non-critical)."

        # Same rationale as install: pin 755 so the service user can exec.
        chmod 755 "$TACQUITO_BIN"
        [[ -x "$HASHGEN_BIN" ]] && chmod 755 "$HASHGEN_BIN"
    fi

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

    # --- Update system config files ---
    info "Updating system files..."
    local SCRIPTS_UPDATED=0
    local ACTIVE_DEPLOY_DIR="$DEPLOY_DIR"

    if [[ ! -d "$ACTIVE_DEPLOY_DIR" ]]; then
        # Fall back to script's own project dir
        ACTIVE_DEPLOY_DIR="$PROJECT_DIR"
    fi

    if [[ -z "$ACTIVE_DEPLOY_DIR" ]]; then
        warn "Deploy directory not found. Skipping updates."
        warn "To fix: clone the repo to ${DEPLOY_DIR}"
    fi

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

    if [[ -f "${ACTIVE_DEPLOY_DIR}/config/tacquito.service" ]]; then
        if ! diff -q "${ACTIVE_DEPLOY_DIR}/config/tacquito.service" "$SERVICE_FILE" &>/dev/null; then
            # Before replacing the installed unit with the new template, rescue
            # any hand-edited -network/-address/-level flags into the drop-in.
            # Only the pre-drop-in schema hardcoded these in ExecStart; the
            # new template references them via TACQUITO_* env vars. We only
            # migrate values that (a) are present AND (b) differ from the
            # template's defaults -- otherwise there's nothing to preserve.
            local mig_net mig_addr mig_level migrated=0
            # `grep | head` under pipefail + set -e: when grep finds nothing
            # it exits 1 and kills the subshell. `|| true` on each keeps the
            # migration pass best-effort for installs whose unit file uses
            # ${TACQUITO_*} env-var placeholders (no literal values to scrape).
            mig_net=$(grep -oP '\-network \K\S+' "$SERVICE_FILE" 2>/dev/null | head -1 || true)
            mig_addr=$(grep -oP '\-address \K\S+' "$SERVICE_FILE" 2>/dev/null | head -1 || true)
            mig_level=$(grep -oP '\-level \K\d+' "$SERVICE_FILE" 2>/dev/null | head -1 || true)
            if [[ -n "$mig_net" && "$mig_net" != "tcp" && "$mig_net" != "\${TACQUITO_NETWORK}" ]]; then
                [[ -z "$(read_service_override TACQUITO_NETWORK)" ]] && { set_service_override TACQUITO_NETWORK "$mig_net"; migrated=1; }
            fi
            if [[ -n "$mig_addr" && "$mig_addr" != ":49" && "$mig_addr" != "\${TACQUITO_ADDRESS}" ]]; then
                [[ -z "$(read_service_override TACQUITO_ADDRESS)" ]] && { set_service_override TACQUITO_ADDRESS "$mig_addr"; migrated=1; }
            fi
            if [[ -n "$mig_level" && "$mig_level" != "20" ]]; then
                [[ -z "$(read_service_override TACQUITO_LEVEL)" ]] && { set_service_override TACQUITO_LEVEL "$mig_level"; migrated=1; }
            fi

            cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"
            cp "${ACTIVE_DEPLOY_DIR}/config/tacquito.service" "$SERVICE_FILE"
            systemctl daemon-reload
            info "  Updated: tacquito.service (previous backed up to ${SERVICE_FILE}.bak)"
            if [[ "$migrated" == "1" ]]; then
                info "  Migrated custom -network/-address/-level flags to ${OVERRIDE_FILE}"
            fi
            SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
        else
            info "  Unchanged: tacquito.service"
        fi
    fi

    update_if_changed "${ACTIVE_DEPLOY_DIR}/README.md" "${CONFIG_DIR}/README.md" "README.md"
    # Installs before the README fix have it 0600 root, or not at all.
    chmod 644 "${CONFIG_DIR}/README.md" 2>/dev/null || true
    update_if_changed "${ACTIVE_DEPLOY_DIR}/config/tacquito.logrotate" "/etc/logrotate.d/tacquito" "logrotate config"
    update_if_changed "${ACTIVE_DEPLOY_DIR}/config/tacctl.bash-completion" "/etc/bash_completion.d/tacctl" "bash completion"
    chmod 644 /etc/bash_completion.d/tacctl 2>/dev/null || true
    # Man page: unconditional re-gzip (cheap, <10 KB) also heals hosts where the file is missing.
    install_man_page "${ACTIVE_DEPLOY_DIR}/man/tacctl.1"
    # Older installs left CONFIG_DIR at 0750, which blocks non-root reads of README.md; normalize to 0755 (sensitive files inside stay 0640).
    chmod 755 "$CONFIG_DIR" 2>/dev/null || true

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

    # --- Move a legacy install into the store (gated; see upgrade_store_flip) ---
    # Here rather than next to the migrations above, so the gate's load-smoke
    # runs the daemon binary this upgrade leaves in place, and so one restart
    # below covers the new binary and the rendered config. A stop is not an
    # upgrade failure: the code is installed and the daemon keeps its config.
    local STORE_STATE="present" flip_rc=0
    upgrade_store_flip || flip_rc=$?
    case "$flip_rc" in
        0)  STORE_STATE="flipped" ;;
        10) ;;
        *)  STORE_STATE="stopped" ;;
    esac

    # --- Restart service (if binaries, service file or the rendered config changed) ---
    if [[ "$SKIP_BUILD" == "false" ]] || [[ "$SCRIPTS_UPDATED" -gt 0 ]] \
        || [[ "$STORE_STATE" == "flipped" ]] || [[ "$CONFIG_SYNC_RENDERED" == "1" ]]; then
        info "Restarting tacquito service..."
        systemctl restart tacquito.service
        sleep 2

        if systemctl is-active --quiet tacquito.service; then
            info "Tacquito is running."
            rm -f "${TACQUITO_BIN}.bak"
        else
            if [[ "$SKIP_BUILD" == "false" ]]; then
                error "Tacquito failed to start after upgrade. Rolling back binary..."
                mv "${TACQUITO_BIN}.bak" "$TACQUITO_BIN"
                systemctl restart tacquito.service
                sleep 2
                if systemctl is-active --quiet tacquito.service; then
                    warn "Rolled back to previous binary. Service is running."
                else
                    error "Rollback failed. Check: journalctl -u tacquito"
                fi
                _upgrade_flip_hint "$STORE_STATE"
                exit 1
            else
                error "Tacquito failed to start. Check: journalctl -u tacquito"
                _upgrade_flip_hint "$STORE_STATE"
                exit 1
            fi
        fi

        local LISTEN_CHECK
        LISTEN_CHECK=$(ss -tlnp | grep ":49 " || true)
        if [[ -n "$LISTEN_CHECK" ]]; then
            info "Listening on port 49/tcp"
        else
            warn "Port 49 not detected — check logs."
        fi
    fi

    echo ""
    echo "============================================"
    if [[ "$SKIP_BUILD" == "false" && "$CURRENT_COMMIT" != "$NEW_COMMIT" ]]; then
        echo "  Upgrade Complete: ${CURRENT_COMMIT} -> ${NEW_COMMIT}"
    elif [[ "$SKIP_BUILD" == "false" ]]; then
        echo "  Upgrade Complete: rebuilt at ${CURRENT_COMMIT} (patch overlay refreshed)"
    else
        echo "  Scripts Updated (source unchanged at ${CURRENT_COMMIT})"
    fi
    echo "  Managed scripts: ${SCRIPTS_UPDATED} updated"
    case "$STORE_STATE" in
        flipped) echo "  Store: migrated from tacquito.yaml ('tacctl store rollback' undoes it)" ;;
        stopped) echo "  Store: NOT migrated — legacy read-only mode (see 'Store migration stopped' above)" ;;
    esac
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

    echo ""
    echo "============================================"
    echo -e "  ${RED}Tacquito Uninstaller${NC}"
    echo "============================================"
    echo ""
    echo "This will remove:"
    echo "  - Tacquito service and binary"
    echo "  - Management CLI (tacctl)"
    echo "  - Password hash generator (tacquito-hashgen)"
    echo "  - Configuration directory (/etc/tacquito)"
    echo "  - State directory (${TACCTL_STATE_DIR})"
    echo "  - Log directory (/var/log/tacquito)"
    echo "  - Logrotate config"
    echo "  - Sudoers rules (${SUDOERS_FILE}, ${TIER_SUDOERS_FILE})"
    echo "  - Bash completion (/etc/bash_completion.d/tacctl)"
    echo "  - Linux host build data (${LINUX_DIR})"
    echo "  - Service user (tacquito)"
    echo "  - Management repo (${DEPLOY_DIR})"
    echo ""
    echo -e "${YELLOW}The tacquito source (/opt/tacquito-src) and Go installation"
    echo -e "(/usr/local/go) will NOT be removed.${NC}"
    echo ""

    read -rp "Are you sure you want to uninstall tacquito? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    echo ""

    # --- Stop and disable service ---
    if systemctl is-active --quiet tacquito 2>/dev/null; then
        info "Stopping tacquito service..."
        systemctl stop tacquito
    fi
    if systemctl is-enabled --quiet tacquito 2>/dev/null; then
        systemctl disable tacquito 2>/dev/null || true
    fi

    # --- Ask about preserving data ---
    local PRESERVE_BACKUPS=false PRESERVE_LOGS=false

    echo ""
    read -rp "Preserve config backups (${BACKUP_DIR})? [y/N]: " keep_backups
    if [[ "$keep_backups" == "y" || "$keep_backups" == "Y" ]]; then
        PRESERVE_BACKUPS=true
    fi

    read -rp "Preserve accounting logs (/var/log/tacquito)? [y/N]: " keep_logs
    if [[ "$keep_logs" == "y" || "$keep_logs" == "Y" ]]; then
        PRESERVE_LOGS=true
    fi

    echo ""

    # --- Remove symlinks and binaries ---
    info "Removing binaries and symlinks..."
    rm -f /usr/local/bin/tacctl
    rm -f /usr/local/bin/tacquito
    rm -f /usr/local/bin/tacquito.bak
    rm -f /usr/local/bin/tacquito-hashgen

    # --- Remove systemd unit ---
    info "Removing systemd unit..."
    rm -f /etc/systemd/system/tacquito.service
    rm -f /etc/systemd/system/tacquito.service.bak
    rm -rf /etc/systemd/system/tacquito.service.d
    systemctl daemon-reload

    # --- Remove sudoers rules and Linux host build data ---
    info "Removing sudoers rules and Linux host build data..."
    uninstall_remove_access

    # --- Remove logrotate config and bash completion ---
    info "Removing logrotate config and bash completion..."
    rm -f /etc/logrotate.d/tacquito
    rm -f /etc/bash_completion.d/tacctl

    # --- Remove man page ---
    info "Removing man page..."
    rm -f /usr/share/man/man1/tacctl.1.gz
    mandb -q 2>/dev/null || true

    # --- Remove configuration ---
    local BACKUP_ARCHIVE="" LOG_ARCHIVE=""
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
    # rm -rf does not follow the compatibility symlinks left in /etc/tacquito.
    rm -rf /etc/tacquito "${TACCTL_STATE_DIR:?}"

    # --- Remove logs ---
    if [[ "$PRESERVE_LOGS" == "true" ]]; then
        if [[ -d /var/log/tacquito ]]; then
            LOG_ARCHIVE="/root/tacquito-logs-$(date +%Y%m%d_%H%M%S).tar.gz"
            tar czf "$LOG_ARCHIVE" -C /var/log tacquito/ 2>/dev/null || true
            info "Accounting logs saved to ${LOG_ARCHIVE}"
        fi
    fi
    info "Removing log directory..."
    rm -rf /var/log/tacquito

    # --- Remove management repo ---
    info "Removing management repo..."
    rm -rf "$DEPLOY_DIR"

    # --- Drop system-wide git safe.directory entries for the removed repos ---
    # Best-effort: git may complain if no entries exist; silent on failure.
    git config --system --unset-all safe.directory "$(printf '^%s$' "$DEPLOY_DIR")" 2>/dev/null || true
    git config --system --unset-all safe.directory "$(printf '^%s$' "$TACQUITO_SRC")" 2>/dev/null || true

    # --- Remove service user ---
    if id tacquito &>/dev/null; then
        info "Removing tacquito service user..."
        userdel tacquito 2>/dev/null || true
    fi

    echo ""
    echo "============================================"
    echo "  Uninstall Complete"
    echo "============================================"
    echo ""
    echo "  Removed:"
    echo "    - Tacquito service and binary"
    echo "    - Management CLI and symlinks"
    echo "    - Configuration and systemd unit"
    echo "    - Logrotate config, sudoers rules, bash completion"
    echo "    - Service user"
    if [[ "$PRESERVE_BACKUPS" == "true" && -n "$BACKUP_ARCHIVE" ]]; then
        echo "    - Config backups saved to: ${BACKUP_ARCHIVE}"
    fi
    if [[ "$PRESERVE_LOGS" == "true" && -n "$LOG_ARCHIVE" ]]; then
        echo "    - Accounting logs saved to: ${LOG_ARCHIVE}"
    fi
    echo ""
    echo "  Not removed:"
    echo "    - Go installation (/usr/local/go)"
    echo "    - Tacquito source (/opt/tacquito-src)"
    echo "    - python3-bcrypt package"
    echo ""
}

