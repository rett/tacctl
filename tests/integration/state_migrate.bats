#!/usr/bin/env bats
# state_migrate: moves tacctl-owned state from $TACCTL_ETC (the TACACS+ daemon's
# directory) into $TACCTL_STATE_DIR and leaves symlinks at the old paths. It
# runs on every install and upgrade, so it must be idempotent, and it must heal
# the rollback case where older code replaced a symlink with a regular file.
load ../helpers/setup
load ../helpers/tmpenv

setup() {
    tacctl_tmpenv_init
    # The harness pre-creates the state dir; these tests start without it.
    rm -rf "$TACCTL_STATE_DIR"
    tacctl_source_lib
}

# --- helpers ---

# Lay down state the way a pre-state-dir release left it in $TACCTL_ETC.
seed_legacy() {
    mkdir -p "$TACCTL_ETC/backups/password-dates" "$TACCTL_ETC/backups/disabled" "$TACCTL_ETC/templates"
    printf 'bcrypt:\n  cost: 10\n' > "$TACCTL_ETC/tacctl.yaml"
    printf 'host1|10.0.0.1|22|lab\n' > "$TACCTL_ETC/linux-hosts"
    printf 'alice:20000\n' > "$TACCTL_ETC/linux-uids"
    printf 'old snapshot\n' > "$TACCTL_ETC/backups/tacquito.yaml.20250101-000000"
    printf '2025-01-01\n' > "$TACCTL_ETC/backups/password-dates/alice.date"
    printf 'hash\n' > "$TACCTL_ETC/backups/disabled/bob.hash"
    printf 'custom cisco\n' > "$TACCTL_ETC/templates/cisco.template"
    printf 'daemon config\n' > "$TACCTL_CONFIG"
}

# Fingerprint of both trees: path, type, mtime, symlink target. Equal before
# and after means nothing was touched.
tree_state() {
    find "$TACCTL_ETC" "$TACCTL_STATE_DIR" -printf '%p %y %T@ %l\n' 2>/dev/null | sort
}

# True when $1 is a symlink to the state-dir copy of the same name.
points_into_state() {
    [[ -L "$TACCTL_ETC/$1" && "$(readlink "$TACCTL_ETC/$1")" == "$TACCTL_STATE_DIR/$1" ]]
}

# --- paths ---

@test "state paths: tacctl-owned files live in TACCTL_STATE_DIR, the daemon config stays in TACCTL_ETC" {
    [[ "$TACCTL_OVERRIDES_FILE" == "$TACCTL_STATE_DIR/tacctl.yaml" ]]
    [[ "$LINUX_UID_FILE" == "$TACCTL_STATE_DIR/linux-uids" ]]
    [[ "$LINUX_HOSTS_FILE" == "$TACCTL_STATE_DIR/linux-hosts" ]]
    [[ "$BACKUP_DIR" == "$TACCTL_STATE_DIR/backups" ]]
    [[ "$PASSWORD_DATES_DIR" == "$TACCTL_STATE_DIR/backups/password-dates" ]]
    [[ "$TEMPLATE_DIR_LOCAL" == "$TACCTL_STATE_DIR/templates" ]]
    [[ "$CONFIG" == "$TACCTL_ETC/tacquito.yaml" ]]
}

@test "state paths: default state dir is /etc/tacctl" {
    run env -u TACCTL_STATE_DIR bash -c 'source "$1"; echo "$TACCTL_STATE_DIR"' _ "$TACCTL_BIN_SCRIPT"
    assert_success
    assert_output "/etc/tacctl"
}

# --- fresh system ---

@test "fresh system: creates a 0700 state dir and links nothing" {
    run state_migrate
    assert_success
    assert_output ""
    [[ -d "$TACCTL_STATE_DIR" ]]
    [[ "$(stat -c %a "$TACCTL_STATE_DIR")" == "700" ]]
    run find "$TACCTL_ETC" -type l
    assert_output ""
}

@test "fresh system: a missing old directory is not created by the migration" {
    rm -rf "$TACCTL_ETC"
    run state_migrate
    assert_success
    [[ ! -e "$TACCTL_ETC" ]]
    [[ -d "$TACCTL_STATE_DIR" ]]
}

@test "fresh system: tightens a state dir that exists with looser permissions" {
    mkdir -p "$TACCTL_STATE_DIR"
    chmod 755 "$TACCTL_STATE_DIR"
    run state_migrate
    assert_success
    [[ "$(stat -c %a "$TACCTL_STATE_DIR")" == "700" ]]
}

# --- existing system ---

@test "legacy system: every item moves and the old path becomes a symlink" {
    seed_legacy
    run state_migrate
    assert_success
    local item
    for item in backups templates tacctl.yaml linux-hosts linux-uids; do
        points_into_state "$item"
        [[ -e "$TACCTL_STATE_DIR/$item" && ! -L "$TACCTL_STATE_DIR/$item" ]]
    done
    [[ "$(cat "$TACCTL_STATE_DIR/tacctl.yaml")" == $'bcrypt:\n  cost: 10' ]]
    [[ "$(cat "$TACCTL_STATE_DIR/linux-uids")" == "alice:20000" ]]
    [[ -f "$TACCTL_STATE_DIR/backups/tacquito.yaml.20250101-000000" ]]
    [[ -f "$TACCTL_STATE_DIR/backups/password-dates/alice.date" ]]
    [[ -f "$TACCTL_STATE_DIR/backups/disabled/bob.hash" ]]
    [[ -f "$TACCTL_STATE_DIR/templates/cisco.template" ]]
    [[ "$(stat -c %a "$TACCTL_STATE_DIR")" == "700" ]]
}

@test "legacy system: the daemon config and unknown files stay where they are" {
    seed_legacy
    printf 'readme\n' > "$TACCTL_ETC/README.md"
    run state_migrate
    assert_success
    [[ -f "$TACCTL_CONFIG" && ! -L "$TACCTL_CONFIG" ]]
    [[ -f "$TACCTL_ETC/README.md" && ! -L "$TACCTL_ETC/README.md" ]]
    [[ ! -e "$TACCTL_STATE_DIR/tacquito.yaml" && ! -e "$TACCTL_STATE_DIR/README.md" ]]
}

@test "legacy system: the old paths still read through to the data" {
    seed_legacy
    run state_migrate
    assert_success
    [[ "$(cat "$TACCTL_ETC/linux-hosts")" == "host1|10.0.0.1|22|lab" ]]
    [[ -f "$TACCTL_ETC/backups/password-dates/alice.date" ]]
    [[ -f "$TACCTL_ETC/templates/cisco.template" ]]
}

@test "legacy system: only the items present are moved" {
    printf 'bcrypt:\n  cost: 10\n' > "$TACCTL_ETC/tacctl.yaml"
    run state_migrate
    assert_success
    points_into_state tacctl.yaml
    [[ ! -e "$TACCTL_ETC/linux-hosts" && ! -L "$TACCTL_ETC/linux-hosts" ]]
    [[ ! -e "$TACCTL_STATE_DIR/linux-hosts" ]]
}

# --- idempotence ---

@test "idempotent: a second run changes nothing and prints nothing" {
    seed_legacy
    run state_migrate
    assert_success
    local before after
    before=$(tree_state)
    run state_migrate
    assert_success
    assert_output ""
    after=$(tree_state)
    [[ "$before" == "$after" ]]
}

@test "idempotent: fresh system run twice is stable" {
    state_migrate
    local before
    before=$(tree_state)
    run state_migrate
    assert_success
    assert_output ""
    [[ "$before" == "$(tree_state)" ]]
}

# --- half-migrated ---

@test "half-migrated: items moved without their symlink get the link back" {
    seed_legacy
    mkdir -p "$TACCTL_STATE_DIR"
    mv "$TACCTL_ETC/tacctl.yaml" "$TACCTL_STATE_DIR/tacctl.yaml"
    mv "$TACCTL_ETC/backups" "$TACCTL_STATE_DIR/backups"
    run state_migrate
    assert_success
    local item
    for item in backups templates tacctl.yaml linux-hosts linux-uids; do
        points_into_state "$item"
    done
    [[ "$(cat "$TACCTL_STATE_DIR/tacctl.yaml")" == $'bcrypt:\n  cost: 10' ]]
    [[ -f "$TACCTL_STATE_DIR/backups/tacquito.yaml.20250101-000000" ]]
    # Nothing was displaced, so no legacy backup was made.
    [[ ! -e "$TACCTL_STATE_DIR/backups/legacy" ]]
}

@test "half-migrated: converges to the same state as a clean migration" {
    seed_legacy
    mkdir -p "$TACCTL_STATE_DIR"
    mv "$TACCTL_ETC/linux-uids" "$TACCTL_STATE_DIR/linux-uids"
    run state_migrate
    assert_success
    local before
    before=$(tree_state)
    run state_migrate
    assert_success
    assert_output ""
    [[ "$before" == "$(tree_state)" ]]
}

@test "half-migrated: old data is merged into a state directory that already exists" {
    mkdir -p "$TACCTL_ETC/backups/password-dates" "$TACCTL_STATE_DIR/backups/password-dates"
    printf 'a\n' > "$TACCTL_ETC/backups/tacquito.yaml.1"
    printf 'b\n' > "$TACCTL_STATE_DIR/backups/tacquito.yaml.2"
    printf 'old\n' > "$TACCTL_ETC/backups/password-dates/alice.date"
    touch -d '2 hours ago' "$TACCTL_ETC/backups/password-dates/alice.date"
    printf 'new\n' > "$TACCTL_STATE_DIR/backups/password-dates/alice.date"
    run state_migrate
    assert_success
    points_into_state backups
    [[ -f "$TACCTL_STATE_DIR/backups/tacquito.yaml.1" ]]
    [[ -f "$TACCTL_STATE_DIR/backups/tacquito.yaml.2" ]]
    # The newer file won; the other is kept in legacy/.
    [[ "$(cat "$TACCTL_STATE_DIR/backups/password-dates/alice.date")" == "new" ]]
    run grep -rl '^old$' "$TACCTL_STATE_DIR/backups/legacy"
    assert_success
}

# --- regressed after rollback ---

@test "rollback: older code writing through the symlink leaves the symlink alone" {
    seed_legacy
    state_migrate
    printf 'host2|10.0.0.2|22|lab\n' >> "$TACCTL_ETC/linux-hosts"
    run state_migrate
    assert_success
    assert_output ""
    points_into_state linux-hosts
    run cat "$TACCTL_STATE_DIR/linux-hosts"
    assert_line "host2|10.0.0.2|22|lab"
}

@test "rollback: a file replaced by rename is moved over the new one, which is backed up" {
    seed_legacy
    state_migrate
    touch -d '1 hour ago' "$TACCTL_STATE_DIR/tacctl.yaml"
    # What conf_set in the previous release does: write a temp file, rename it
    # over the old path. The symlink is replaced by a regular file.
    printf 'bcrypt:\n  cost: 14\n' > "$TACCTL_ETC/tacctl.yaml.tmp"
    mv "$TACCTL_ETC/tacctl.yaml.tmp" "$TACCTL_ETC/tacctl.yaml"
    [[ ! -L "$TACCTL_ETC/tacctl.yaml" ]]

    run state_migrate
    assert_success
    points_into_state tacctl.yaml
    # Newer content kept.
    [[ "$(cat "$TACCTL_STATE_DIR/tacctl.yaml")" == $'bcrypt:\n  cost: 14' ]]
    # Displaced content kept under backups/legacy/.
    local backup
    backup=$(find "$TACCTL_STATE_DIR/backups/legacy" -name 'tacctl.yaml.*' | head -1)
    [[ -n "$backup" ]]
    [[ "$(cat "$backup")" == $'bcrypt:\n  cost: 10' ]]
}

@test "rollback: after healing, a second run is a no-op" {
    seed_legacy
    state_migrate
    touch -d '1 hour ago' "$TACCTL_STATE_DIR/linux-uids"
    printf 'alice:20000\nbob:20001\n' > "$TACCTL_ETC/linux-uids.tmp"
    mv "$TACCTL_ETC/linux-uids.tmp" "$TACCTL_ETC/linux-uids"
    state_migrate
    local before
    before=$(tree_state)
    run state_migrate
    assert_success
    assert_output ""
    [[ "$before" == "$(tree_state)" ]]
    [[ "$(cat "$TACCTL_STATE_DIR/linux-uids")" == $'alice:20000\nbob:20001' ]]
}

@test "rollback: several rounds of rename, migrate keep the newest content and every displaced copy" {
    seed_legacy
    state_migrate
    local i
    for i in 1 2 3; do
        touch -d "$((10 - i)) minutes ago" "$TACCTL_STATE_DIR/tacctl.yaml"
        printf 'round: %s\n' "$i" > "$TACCTL_ETC/tacctl.yaml.tmp"
        mv "$TACCTL_ETC/tacctl.yaml.tmp" "$TACCTL_ETC/tacctl.yaml"
        state_migrate
        points_into_state tacctl.yaml
        [[ "$(cat "$TACCTL_STATE_DIR/tacctl.yaml")" == "round: $i" ]]
    done
    run find "$TACCTL_STATE_DIR/backups/legacy" -name 'tacctl.yaml.*'
    [[ "${#lines[@]}" -eq 3 ]]
}

@test "rollback: an old-path file that is not newer loses; it is kept and the link restored" {
    seed_legacy
    state_migrate
    rm "$TACCTL_ETC/linux-hosts"
    printf 'stale|1.1.1.1|22|lab\n' > "$TACCTL_ETC/linux-hosts"
    touch -d '1 day ago' "$TACCTL_ETC/linux-hosts"
    run state_migrate
    assert_success
    points_into_state linux-hosts
    [[ "$(cat "$TACCTL_STATE_DIR/linux-hosts")" == "host1|10.0.0.1|22|lab" ]]
    run grep -rl 'stale' "$TACCTL_STATE_DIR/backups/legacy"
    assert_success
}

@test "rollback: an identical regular file is replaced by the link without a backup" {
    seed_legacy
    state_migrate
    rm "$TACCTL_ETC/linux-uids"
    cp "$TACCTL_STATE_DIR/linux-uids" "$TACCTL_ETC/linux-uids"
    run state_migrate
    assert_success
    points_into_state linux-uids
    [[ ! -e "$TACCTL_STATE_DIR/backups/legacy" ]]
}

@test "rollback: a directory recreated at the old path is merged back" {
    seed_legacy
    state_migrate
    rm "$TACCTL_ETC/templates"
    mkdir "$TACCTL_ETC/templates"
    printf 'added by old code\n' > "$TACCTL_ETC/templates/juniper.template"
    run state_migrate
    assert_success
    points_into_state templates
    [[ -f "$TACCTL_STATE_DIR/templates/cisco.template" ]]
    [[ -f "$TACCTL_STATE_DIR/templates/juniper.template" ]]
}

# --- never follow symlinks, never move into itself ---

@test "symlinks: a link to somewhere else is left alone and its target untouched" {
    mkdir -p "$BATS_TEST_TMPDIR/elsewhere"
    printf 'operator file\n' > "$BATS_TEST_TMPDIR/elsewhere/hosts"
    ln -s "$BATS_TEST_TMPDIR/elsewhere/hosts" "$TACCTL_ETC/linux-hosts"
    run state_migrate
    assert_success
    assert_output --partial "symlink elsewhere"
    [[ "$(readlink "$TACCTL_ETC/linux-hosts")" == "$BATS_TEST_TMPDIR/elsewhere/hosts" ]]
    [[ "$(cat "$BATS_TEST_TMPDIR/elsewhere/hosts")" == "operator file" ]]
    [[ ! -e "$TACCTL_STATE_DIR/linux-hosts" ]]
}

@test "symlinks: a dangling link at the old path is not followed or replaced" {
    ln -s "$BATS_TEST_TMPDIR/nowhere" "$TACCTL_ETC/linux-uids"
    run state_migrate
    assert_success
    [[ -L "$TACCTL_ETC/linux-uids" ]]
    [[ ! -e "$BATS_TEST_TMPDIR/nowhere" ]]
    [[ ! -e "$TACCTL_STATE_DIR/linux-uids" ]]
}

@test "symlinks: a link inside an old directory is not followed while merging" {
    mkdir -p "$TACCTL_ETC/templates" "$TACCTL_STATE_DIR/templates" "$BATS_TEST_TMPDIR/outside"
    printf 'x\n' > "$BATS_TEST_TMPDIR/outside/file"
    ln -s "$BATS_TEST_TMPDIR/outside" "$TACCTL_ETC/templates/linked"
    printf 'kept\n' > "$TACCTL_STATE_DIR/templates/cisco.template"
    run state_migrate
    assert_success
    # The link moved as a link; the target is intact.
    [[ -L "$TACCTL_STATE_DIR/templates/linked" ]]
    [[ "$(cat "$BATS_TEST_TMPDIR/outside/file")" == "x" ]]
    points_into_state templates
}

@test "symlinks: a symlinked state dir entry is not replaced" {
    mkdir -p "$TACCTL_STATE_DIR" "$BATS_TEST_TMPDIR/real"
    ln -s "$BATS_TEST_TMPDIR/real" "$TACCTL_STATE_DIR/templates"
    mkdir -p "$TACCTL_ETC/templates"
    printf 'x\n' > "$TACCTL_ETC/templates/a.template"
    run state_migrate
    assert_success
    [[ -L "$TACCTL_STATE_DIR/templates" ]]
    [[ -f "$TACCTL_ETC/templates/a.template" && ! -L "$TACCTL_ETC/templates" ]]
    [[ ! -e "$BATS_TEST_TMPDIR/real/a.template" ]]
}

@test "self-move: state dir equal to the daemon dir is a no-op" {
    export TACCTL_STATE_DIR="$TACCTL_ETC"
    chmod 755 "$TACCTL_ETC"
    seed_legacy
    run state_migrate
    assert_success
    assert_output ""
    [[ "$(stat -c %a "$TACCTL_ETC")" == "755" ]]
    run find "$TACCTL_ETC" -type l
    assert_output ""
    [[ -f "$TACCTL_ETC/tacctl.yaml" ]]
}

@test "self-move: state dir reached through a symlink to the daemon dir is a no-op" {
    ln -s "$TACCTL_ETC" "$BATS_TEST_TMPDIR/etc-alias"
    export TACCTL_STATE_DIR="$BATS_TEST_TMPDIR/etc-alias"
    seed_legacy
    run state_migrate
    assert_success
    assert_output ""
    run find "$TACCTL_ETC" -type l
    assert_output ""
}

@test "self-move: a state dir nested inside the daemon dir migrates without moving a directory into itself" {
    export TACCTL_STATE_DIR="$TACCTL_ETC/state"
    seed_legacy
    run state_migrate
    assert_success
    points_into_state backups
    points_into_state tacctl.yaml
    [[ -d "$TACCTL_STATE_DIR/backups/password-dates" ]]
    run state_migrate
    assert_success
    assert_output ""
}

# --- the migrated layout works with the tool ---

@test "migrated layout: conf_set writes into the state dir and leaves the old path alone" {
    seed_legacy
    state_migrate
    conf_set bcrypt.cost 14
    points_into_state tacctl.yaml
    run grep 'cost: 14' "$TACCTL_STATE_DIR/tacctl.yaml"
    assert_success
}
