#!/usr/bin/env bats
# Integration tests for `tacctl backup`: snapshots, list, diff, restore.
#
# A backup is a snapshot directory backups/<ts>/{store.yaml,tacctl.yaml,manifest}
# taken before every mutation. Old-style tacquito.yaml.<ts> files (what the
# state migration leaves in backups/, what the renderer and the upgrade keep in
# backups/legacy/) are listed after the snapshots and restore with --legacy.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

TEST_HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    BACKUPS="${TACCTL_STATE_DIR}/backups"
    load_fixture tacquito.minimal.yaml
}

# Snapshot ids under backups/, oldest first. Only directories whose name is
# shaped YYYYMMDD_HHMMSS[_mmm][-N]: password-dates/, disabled/ and legacy/ are
# not snapshots.
snapshots() {
    find "$BACKUPS" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' \
        | grep -E '^[0-9]{8}_[0-9]{6}(_[0-9]{3})?(-[0-9]+)?$' | sort || true
}

newest_snapshot() { snapshots | tail -n 1; }
oldest_snapshot() { snapshots | head -n 1; }

# mk_snapshot <id> [<store-text>]: a snapshot directory made by hand.
mk_snapshot() {
    mkdir -p "${BACKUPS}/$1"
    printf '%s\n' "${2:-# hand-made snapshot $1}" > "${BACKUPS}/$1/store.yaml"
    chmod 700 "${BACKUPS}/$1"
    chmod 600 "${BACKUPS}/$1/store.yaml"
}

add_user() {
    "$TACCTL_BIN_SCRIPT" user add "$1" "${2:-operator}" --hash "$TEST_HASH" --scopes lab > /dev/null
}

# The live state, one line each, for before/after comparisons.
state_files() {
    local f
    for f in "${TACCTL_STATE_DIR}/store.yaml" "${TACCTL_STATE_DIR}/tacctl.yaml" \
             "$TACCTL_CONFIG" "${TACCTL_STATE_DIR}/rendered.json"; do
        if [[ -f "$f" ]]; then
            echo "$(basename "$f") $(sha256sum < "$f")"
        else
            echo "$(basename "$f") absent"
        fi
    done
}

# 0 when tacquito.yaml is what rendered.json says it is, and rendering the
# store again would change nothing.
assert_rendered_consistent() {
    python3 - "${TACCTL_STATE_DIR}/rendered.json" "$TACCTL_CONFIG" <<'PY'
import hashlib, json, sys
records = json.load(open(sys.argv[1]))
digest = hashlib.sha256(open(sys.argv[2], 'rb').read()).hexdigest()
sys.exit(0 if records.get(sys.argv[2]) == digest else 1)
PY
    run "$TACCTL_BIN_SCRIPT" config render
    assert_success
    assert_output --partial "already up to date"
}

# --- Snapshot contents and modes ---------------------------------------------

@test "snapshot: holds store.yaml, tacctl.yaml and a manifest, root-only modes" {
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 11 > /dev/null
    add_user alice
    add_user bob
    local snap="${BACKUPS}/$(newest_snapshot)"

    [[ -f "${snap}/store.yaml" && -f "${snap}/tacctl.yaml" && -f "${snap}/manifest" ]]
    [[ "$(stat -c %a "$snap")" == "700" ]]
    [[ "$(stat -c %a "${snap}/store.yaml")" == "600" ]]
    [[ "$(stat -c %a "${snap}/tacctl.yaml")" == "600" ]]
    [[ "$(stat -c %a "${snap}/manifest")" == "600" ]]
    # What was snapshotted is the state before the second add.
    run grep -c 'bob' "${snap}/store.yaml"
    assert_output "0"
    run grep -c 'alice' "${snap}/store.yaml"
    [[ "$output" -ge 1 ]]
    run grep 'cost' "${snap}/tacctl.yaml"
    assert_output --partial "11"
}

@test "snapshot: the manifest carries the version and rendered.json of that moment" {
    add_user alice
    add_user bob
    local snap="${BACKUPS}/$(newest_snapshot)"
    run python3 - "${snap}/manifest" "$TACCTL_CONFIG" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
assert m["tacctl_version"], m
assert m["created"], m
# The first add rendered tacquito.yaml; the snapshot before the second add
# records that.
assert sys.argv[2] in m["rendered"], m
PY
    assert_success
    # The snapshot before the very first mutation predates any render.
    local first="${BACKUPS}/$(oldest_snapshot)"
    run python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["rendered"] == {}' "${first}/manifest"
    assert_success
}

@test "snapshot: without a tacctl.yaml there is none in the snapshot" {
    add_user alice
    [[ ! -e "${BACKUPS}/$(newest_snapshot)/tacctl.yaml" ]]
    [[ -f "${BACKUPS}/$(newest_snapshot)/manifest" ]]
}

@test "snapshot: a mutation that cannot be snapshotted is refused, nothing written" {
    [[ $EUID -ne 0 ]] || skip "permissions do not bind root"
    chmod 500 "$BACKUPS"
    local before
    before=$(state_files)
    run "$TACCTL_BIN_SCRIPT" user add alice operator --hash "$TEST_HASH" --scopes lab
    chmod 700 "$BACKUPS"
    assert_failure
    assert_output --partial "Nothing was changed"
    [[ "$(state_files)" == "$before" ]]
}

@test "snapshot: a failed command leaves no stray temporary directory" {
    add_user alice
    run "$TACCTL_BIN_SCRIPT" user add alice operator --hash "$TEST_HASH" --scopes lab
    [[ -z "$(find "$BACKUPS" -maxdepth 1 -name '.snap.*')" ]]
}

# --- Naming: same-second mutations never collide ------------------------------

@test "snapshot: names taken by an earlier snapshot get a numeric suffix" {
    stub_cmd date 'echo 19990101_000000_000'
    add_user alice
    add_user bob
    add_user carol
    run snapshots
    assert_output "19990101_000000_000
19990101_000000_000-1
19990101_000000_000-2"
    # Three distinct pre-change states, so three distinct contents.
    [[ "$(sha256sum < "${BACKUPS}/19990101_000000_000/store.yaml")" != "$(sha256sum < "${BACKUPS}/19990101_000000_000-1/store.yaml")" ]]
}

@test "snapshot: mutations in quick succession each get their own" {
    add_user alice
    add_user bob
    add_user carol
    [[ "$(snapshots | wc -l)" -eq 3 ]]
    [[ "$(snapshots | sort -u | wc -l)" -eq 3 ]]
}

# --- No-op mutations -----------------------------------------------------------

@test "snapshot: nothing is added while the files equal the newest snapshot" {
    tacctl_source_lib
    backup_snapshot > /dev/null
    backup_snapshot > /dev/null
    backup_snapshot > /dev/null
    [[ "$(snapshots | wc -l)" -eq 1 ]]
    # A change to either canonical file makes the next one real.
    printf '# note\n' >> "${TACCTL_STATE_DIR}/store.yaml"
    backup_snapshot > /dev/null
    [[ "$(snapshots | wc -l)" -eq 2 ]]
    printf 'bcrypt:\n  cost: 11\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    backup_snapshot > /dev/null
    [[ "$(snapshots | wc -l)" -eq 3 ]]
    backup_snapshot > /dev/null
    [[ "$(snapshots | wc -l)" -eq 3 ]]
}

@test "snapshot: one command with several store writes takes one snapshot" {
    tacctl_source_lib
    two_writes() {
        store_user_set alice "group=operator" "hash=${TEST_HASH}" "scopes=lab" || return 1
        store_user_set bob "group=operator" "hash=${TEST_HASH}" "scopes=lab"
    }
    store_apply two_writes > /dev/null
    [[ "$(snapshots | wc -l)" -eq 1 ]]
    # It holds the state before either write.
    run grep -c 'alice\|bob' "${BACKUPS}/$(newest_snapshot)/store.yaml"
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" user list
    assert_output --partial "alice"
    assert_output --partial "bob"
}

# --- Retention ------------------------------------------------------------------

@test "retention: keeps the newest 30 snapshots and nothing else is touched" {
    local i
    for i in $(seq -w 1 35); do
        mk_snapshot "20200101_000000_0${i}"
    done
    mkdir -p "${BACKUPS}/legacy" "${BACKUPS}/disabled" "${BACKUPS}/20200101_000000_000.keep"
    printf 'pre-store\n' > "${BACKUPS}/legacy/tacquito.yaml.pre-store.20250101_000000"
    printf 'drift\n' > "${BACKUPS}/legacy/tacquito.yaml.drift.20250101_000001"
    printf 'old\n' > "${BACKUPS}/tacquito.yaml.20250101_000002"
    printf 'hash\n' > "${BACKUPS}/disabled/bob.hash"
    printf '2026-01-01\n' > "${BACKUPS}/password-dates/alice.date"
    printf 'note\n' > "${BACKUPS}/notes.txt"

    add_user alice
    local new
    new=$(newest_snapshot)
    # 35 hand-made + the new one, minus the 6 oldest of them.
    [[ "$(snapshots | grep -c '^20200101_000000_0[0-9][0-9]$')" -eq 29 ]]
    [[ "$(snapshots | grep -cv '^20200101_000000_0[0-9][0-9]$')" -eq 1 ]]
    [[ "$new" != 20200101* ]]
    [[ ! -d "${BACKUPS}/20200101_000000_001" && ! -d "${BACKUPS}/20200101_000000_006" ]]
    [[ -d "${BACKUPS}/20200101_000000_007" && -d "${BACKUPS}/20200101_000000_035" ]]
    # Not snapshots: left alone.
    [[ -d "${BACKUPS}/20200101_000000_000.keep" ]]
    [[ -f "${BACKUPS}/legacy/tacquito.yaml.pre-store.20250101_000000" ]]
    [[ -f "${BACKUPS}/legacy/tacquito.yaml.drift.20250101_000001" ]]
    [[ -f "${BACKUPS}/tacquito.yaml.20250101_000002" ]]
    [[ -f "${BACKUPS}/disabled/bob.hash" ]]
    [[ -f "${BACKUPS}/password-dates/alice.date" ]]
    [[ -f "${BACKUPS}/notes.txt" ]]
}

@test "retention: never deletes the snapshot just taken, even when the clock ran backwards" {
    local i
    for i in $(seq -w 1 35); do
        mk_snapshot "20300101_000000_0${i}"
    done
    # A name older than every existing one.
    stub_cmd date 'echo 19990101_000000_000'
    add_user alice
    [[ -d "${BACKUPS}/19990101_000000_000" ]]
    [[ -f "${BACKUPS}/19990101_000000_000/store.yaml" ]]
    # The excess went from the other end: 36 snapshots -> 30 means 6 removed,
    # one of them not the new one.
    [[ "$(snapshots | wc -l)" -eq 30 ]]
}

@test "retention: never deletes the snapshot a restore reads from" {
    local i
    for i in $(seq -w 1 30); do
        mk_snapshot "20200101_000000_0${i}"
    done
    # The oldest of thirty is the one to restore: a valid store. Taking the
    # snapshot of the current state makes thirty-one, and the oldest is the
    # one retention would take.
    cp "${TACCTL_STATE_DIR}/store.yaml" "${BACKUPS}/20200101_000000_001/store.yaml"
    run "$TACCTL_BIN_SCRIPT" backup restore 20200101_000000_001 <<< "y"
    assert_success
    [[ -d "${BACKUPS}/20200101_000000_001" ]]
    [[ "$(snapshots | wc -l)" -eq 31 ]]
}

# --- List ----------------------------------------------------------------------

@test "backup list: reports 'No backups found' on a fresh install" {
    run "$TACCTL_BIN_SCRIPT" backup list
    assert_success
    assert_output --partial "No backups found"
}

@test "backup list: enumerates the snapshots mutating commands took" {
    add_user alice
    add_user bob
    run "$TACCTL_BIN_SCRIPT" backup list
    assert_success
    local id
    for id in $(snapshots); do
        assert_output --partial "$id"
    done
    assert_output --partial "snapshot"
    # The adoption of the fixture left one old-style file in legacy/.
    assert_output --partial "old-style"
}

@test "backup list: snapshots newest first, then old-style files newest first" {
    mk_snapshot 20260101_000000_000
    mk_snapshot 20260301_000000_000
    mk_snapshot 20260201_000000_000
    mkdir -p "${BACKUPS}/legacy"
    printf 'a\n' > "${BACKUPS}/tacquito.yaml.20250101_000000"
    printf 'b\n' > "${BACKUPS}/legacy/tacquito.yaml.pre-store.20250601_000000"
    printf 'c\n' > "${BACKUPS}/legacy/tacquito.yaml.drift.20250301_000000"
    touch -d '2025-01-01 00:00:00' "${BACKUPS}/tacquito.yaml.20250101_000000"
    touch -d '2025-06-01 00:00:00' "${BACKUPS}/legacy/tacquito.yaml.pre-store.20250601_000000"
    touch -d '2025-03-01 00:00:00' "${BACKUPS}/legacy/tacquito.yaml.drift.20250301_000000"
    # Not listed: not snapshots, not tacquito.yaml.* files.
    printf 'x\n' > "${BACKUPS}/notes.txt"
    printf 'x\n' > "${BACKUPS}/legacy/tacctl.yaml.20250101-000000"

    run "$TACCTL_BIN_SCRIPT" backup list
    assert_success
    local ids
    ids=$(printf '%s\n' "$output" | grep -oE '^  (20[0-9_]+|pre-store\.[0-9_]+|drift\.[0-9_]+) ' | tr -d ' ')
    [[ "$ids" == "20260301_000000_000
20260201_000000_000
20260101_000000_000
pre-store.20250601_000000
drift.20250301_000000
20250101_000000" ]]
    refute_output --partial "notes.txt"
    refute_output --partial "tacctl.yaml.2025"
}

@test "backup list: shows names and sizes only, never file contents" {
    add_user alice
    run "$TACCTL_BIN_SCRIPT" backup list
    assert_success
    refute_output --partial "$TEST_HASH"
    refute_output --partial "alice"
}

# --- Diff ----------------------------------------------------------------------

@test "backup diff: shows the diff between current and the last snapshot" {
    add_user alice
    run "$TACCTL_BIN_SCRIPT" backup diff
    assert_success
    assert_output --partial "Diff:"
    assert_output --partial "store.yaml"
    # The snapshot predates alice; the diff shows her.
    assert_output --partial "alice"
}

@test "backup diff: names a snapshot, and covers tacctl.yaml too" {
    add_user alice
    local first
    first=$(oldest_snapshot)
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 11 > /dev/null
    add_user bob
    run "$TACCTL_BIN_SCRIPT" backup diff "$first"
    assert_success
    assert_output --partial "snapshot ${first}"
    assert_output --partial "bob"
    assert_output --partial "tacctl.yaml"
    assert_output --partial "cost"
}

@test "backup diff: says so when nothing differs" {
    tacctl_source_lib
    backup_snapshot > /dev/null
    run "$TACCTL_BIN_SCRIPT" backup diff
    assert_success
    assert_output --partial "store.yaml: no differences"
    assert_output --partial "tacctl.yaml: absent in the snapshot and now"
}

@test "backup diff: with no snapshots, says so" {
    run "$TACCTL_BIN_SCRIPT" backup diff
    assert_failure
    assert_output --partial "No snapshots found"
}

@test "backup diff: an old-style id diffs that file against the rendered tacquito.yaml" {
    add_user alice
    printf '# an old backup\n' > "${BACKUPS}/tacquito.yaml.20250101_000000"
    run "$TACCTL_BIN_SCRIPT" backup diff 20250101_000000
    assert_success
    assert_output --partial "backup 20250101_000000"
    assert_output --partial "an old backup"
}

@test "backup diff: rejects an unknown timestamp and a path-like one" {
    add_user alice
    run "$TACCTL_BIN_SCRIPT" backup diff 19990101_000000
    assert_failure
    assert_output --partial "not found"
    run "$TACCTL_BIN_SCRIPT" backup diff ../store.yaml
    assert_failure
    assert_output --partial "not found"
}

@test "config diff and config restore are aliases of the backup verbs" {
    add_user alice
    local id
    id=$(newest_snapshot)
    run "$TACCTL_BIN_SCRIPT" config diff "$id"
    assert_success
    assert_output --partial "snapshot ${id}"
    assert_output --partial "alice"
    run "$TACCTL_BIN_SCRIPT" config restore "$id" <<< "y"
    assert_success
    assert_output --partial "Restored snapshot ${id}"
    run "$TACCTL_BIN_SCRIPT" user list
    refute_output --partial "alice"
}

# --- Restore -------------------------------------------------------------------

@test "backup restore: round trip, the model equals the snapshot and tacquito.yaml follows" {
    "$TACCTL_BIN_SCRIPT" store show --json > "${BATS_TEST_TMPDIR}/model.before"
    add_user alice
    add_user bob superuser
    local first
    first=$(oldest_snapshot)

    run "$TACCTL_BIN_SCRIPT" backup restore "$first" <<< "y"
    assert_success
    assert_output --partial "Restored snapshot ${first}"

    "$TACCTL_BIN_SCRIPT" store show --json > "${BATS_TEST_TMPDIR}/model.after"
    cmp "${BATS_TEST_TMPDIR}/model.before" "${BATS_TEST_TMPDIR}/model.after"
    cmp "${BACKUPS}/${first}/store.yaml" "${TACCTL_STATE_DIR}/store.yaml"
    run grep -c '^  - name: \(alice\|bob\)$' "$TACCTL_CONFIG"
    assert_output "0"
    assert_rendered_consistent
    stub_called 'systemctl restart tacquito'
    # The next change is not refused as a hand edit.
    run "$TACCTL_BIN_SCRIPT" user add carol operator --hash "$TEST_HASH" --scopes lab
    assert_success
}

@test "backup restore: restores tacctl.yaml with the store, or removes it" {
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 11 > /dev/null
    add_user alice                       # snapshot A: cost 11, no alice
    local with_cost
    with_cost=$(newest_snapshot)
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 13 > /dev/null
    add_user bob

    run "$TACCTL_BIN_SCRIPT" backup restore "$with_cost" <<< "y"
    assert_success
    cmp "${BACKUPS}/${with_cost}/tacctl.yaml" "${TACCTL_STATE_DIR}/tacctl.yaml"
    [[ "$("$TACCTL_BIN_SCRIPT" config get bcrypt.cost)" == "11" ]]
    run "$TACCTL_BIN_SCRIPT" user list
    refute_output --partial "bob"
    assert_rendered_consistent
}

@test "backup restore: a snapshot without tacctl.yaml removes the live one" {
    add_user alice                       # snapshot A: no tacctl.yaml
    local plain
    plain=$(newest_snapshot)
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 11 > /dev/null
    [[ -f "${TACCTL_STATE_DIR}/tacctl.yaml" ]]
    run "$TACCTL_BIN_SCRIPT" backup restore "$plain" <<< "y"
    assert_success
    [[ ! -e "${TACCTL_STATE_DIR}/tacctl.yaml" ]]
    assert_rendered_consistent
}

@test "backup restore: snapshots the current state first, so the restore can be undone" {
    add_user alice
    local first
    first=$(oldest_snapshot)
    cp "${TACCTL_STATE_DIR}/store.yaml" "${BATS_TEST_TMPDIR}/with-alice.yaml"
    local count
    count=$(snapshots | wc -l)

    run "$TACCTL_BIN_SCRIPT" backup restore "$first" <<< "y"
    assert_success
    [[ "$(snapshots | wc -l)" -eq $((count + 1)) ]]
    local undo
    undo=$(newest_snapshot)
    cmp "${BACKUPS}/${undo}/store.yaml" "${BATS_TEST_TMPDIR}/with-alice.yaml"

    run "$TACCTL_BIN_SCRIPT" backup restore "$undo" <<< "y"
    assert_success
    run "$TACCTL_BIN_SCRIPT" user list
    assert_output --partial "alice"
}

@test "backup restore: declining changes nothing" {
    add_user alice
    local first before
    first=$(oldest_snapshot)
    before=$(state_files)
    run "$TACCTL_BIN_SCRIPT" backup restore "$first" <<< "n"
    assert_success
    assert_output --partial "Cancelled"
    [[ "$(state_files)" == "$before" ]]
}

@test "backup restore: a hand-edited tacquito.yaml is overwritten, and kept under legacy/" {
    add_user alice
    local first
    first=$(oldest_snapshot)
    printf '# hand edit\n' >> "$TACCTL_CONFIG"
    run "$TACCTL_BIN_SCRIPT" backup restore "$first" <<< "y"
    assert_success
    assert_output --partial "saved to"
    run grep -rl 'hand edit' "${BACKUPS}/legacy"
    assert_success
    assert_rendered_consistent
}

@test "backup restore: an invalid store in the snapshot restores nothing" {
    add_user alice
    mk_snapshot 20250101_000000_000 'users: [this is not a store'
    local before ids
    before=$(state_files)
    ids=$(snapshots)
    run "$TACCTL_BIN_SCRIPT" backup restore 20250101_000000_000 <<< "y"
    assert_failure
    assert_output --partial "cannot be restored"
    assert_output --partial "Nothing was changed"
    [[ "$(state_files)" == "$before" ]]
    # Not even the pre-restore snapshot was taken.
    [[ "$(snapshots)" == "$ids" ]]
}

@test "backup restore: a store that is valid YAML but not a valid store restores nothing" {
    add_user alice
    add_user bob
    local with_alice before ids
    with_alice=$(newest_snapshot)
    mk_snapshot 20250101_000000_000
    # alice now belongs to a group that does not exist.
    sed 's/^    group: operator$/    group: nosuchgroup/' "${BACKUPS}/${with_alice}/store.yaml" \
        > "${BACKUPS}/20250101_000000_000/store.yaml"
    grep -q nosuchgroup "${BACKUPS}/20250101_000000_000/store.yaml"
    before=$(state_files)
    ids=$(snapshots)
    run "$TACCTL_BIN_SCRIPT" backup restore 20250101_000000_000 <<< "y"
    assert_failure
    assert_output --partial "cannot be restored"
    [[ "$(state_files)" == "$before" ]]
    [[ "$(snapshots)" == "$ids" ]]
}

@test "backup restore: an invalid tacctl.yaml in the snapshot restores nothing" {
    add_user alice
    local first before ids
    first=$(oldest_snapshot)
    mk_snapshot 20250101_000000_000
    cp "${BACKUPS}/${first}/store.yaml" "${BACKUPS}/20250101_000000_000/store.yaml"
    printf 'bcrypt:\n  cost: 99\n' > "${BACKUPS}/20250101_000000_000/tacctl.yaml"
    before=$(state_files)
    ids=$(snapshots)
    run "$TACCTL_BIN_SCRIPT" backup restore 20250101_000000_000 <<< "y"
    assert_failure
    assert_output --partial "tacctl.yaml is not valid"
    [[ "$(state_files)" == "$before" ]]
    [[ "$(snapshots)" == "$ids" ]]
}

@test "backup restore: a snapshot with no store.yaml restores nothing" {
    add_user alice
    mkdir -m 700 "${BACKUPS}/20250101_000000_000"
    local before
    before=$(state_files)
    run "$TACCTL_BIN_SCRIPT" backup restore 20250101_000000_000 <<< "y"
    assert_failure
    assert_output --partial "no store.yaml"
    [[ "$(state_files)" == "$before" ]]
}

@test "backup restore: a render that fails partway puts all four files back" {
    add_user alice
    add_user bob
    local snap before
    snap="${BACKUPS}/$(oldest_snapshot)"
    "$TACCTL_BIN_SCRIPT" config bcrypt-cost 11 > /dev/null
    before=$(state_files)
    tacctl_source_lib
    # A backend whose commit gets as far as replacing tacquito.yaml and
    # rendered.json, then fails: the worst case for consistency.
    # backends_render_all puts the rendered config and its record back,
    # _backup_apply the store and tacctl.yaml.
    backend_tacacs_render_commit() {
        printf '# half a render\n' > "$TACCTL_CONFIG"
        printf '{}\n' > "$RENDERED_FILE"
        return 1
    }
    run _backup_apply _backup_install_snapshot "$snap"
    assert_failure
    [[ "$(state_files)" == "$before" ]]
    [[ -z "$(find "$TACCTL_STATE_DIR" -maxdepth 1 -name '.restore.*')" ]]
}

@test "backup restore: a failing writer also puts the files back" {
    add_user alice
    local before
    before=$(state_files)
    tacctl_source_lib
    half_writer() { printf 'garbage\n' > "$STORE_FILE"; rm -f "$TACCTL_OVERRIDES_FILE"; return 1; }
    run _backup_apply half_writer
    assert_failure
    [[ "$(state_files)" == "$before" ]]
}

@test "backup restore: rejects an unknown timestamp, extra arguments and unknown options" {
    run "$TACCTL_BIN_SCRIPT" backup restore 19990101_000000 <<< "y"
    assert_failure
    assert_output --partial "not found"
    run "$TACCTL_BIN_SCRIPT" backup restore
    assert_failure
    assert_output --partial "Usage"
    run "$TACCTL_BIN_SCRIPT" backup restore a b
    assert_failure
    run "$TACCTL_BIN_SCRIPT" backup restore a --frob
    assert_failure
    assert_output --partial "Unknown option"
}

# --- Restore --legacy ----------------------------------------------------------

@test "backup restore --legacy: an old-style file goes through the importer's check, then in" {
    add_user alice
    cp "${TACCTL_SRC}/tests/fixtures/golden/tacquito.minimal.rendered.yaml" \
        "${BACKUPS}/tacquito.yaml.20250101_000000"
    local count
    count=$(snapshots | wc -l)

    run "$TACCTL_BIN_SCRIPT" backup restore 20250101_000000 --legacy <<< "y"
    assert_success
    assert_output --partial "equivalence"
    assert_output --partial "Check passed"
    assert_output --partial "Restored old-style backup 20250101_000000"

    run "$TACCTL_BIN_SCRIPT" user list
    refute_output --partial "alice"
    assert_rendered_consistent
    # alice was in the store until now: a snapshot of that state exists.
    [[ "$(snapshots | wc -l)" -eq $((count + 1)) ]]
    grep -q 'alice' "${BACKUPS}/$(newest_snapshot)/store.yaml"
}

@test "backup restore --legacy: finds files under legacy/, and the flag may come first" {
    add_user alice
    mkdir -p "${BACKUPS}/legacy"
    cp "${TACCTL_SRC}/tests/fixtures/golden/tacquito.minimal.rendered.yaml" \
        "${BACKUPS}/legacy/tacquito.yaml.pre-store.20250101_000000"
    run "$TACCTL_BIN_SCRIPT" backup restore --legacy pre-store.20250101_000000 <<< "y"
    assert_success
    run "$TACCTL_BIN_SCRIPT" user list
    refute_output --partial "alice"
}

@test "backup restore --legacy: a backup the store cannot represent restores nothing" {
    add_user alice
    cp "${TACCTL_SRC}/tests/fixtures/legacy.unrepresentable.yaml" \
        "${BACKUPS}/tacquito.yaml.19990101_000000"
    local before ids
    before=$(state_files)
    ids=$(snapshots)
    run "$TACCTL_BIN_SCRIPT" backup restore 19990101_000000 --legacy <<< "y"
    assert_failure
    assert_output --partial "cannot be restored"
    assert_output --partial "store import --replace"
    [[ "$(state_files)" == "$before" ]]
    [[ "$(snapshots)" == "$ids" ]]
}

@test "backup restore --legacy: a file the check finds not equivalent restores nothing" {
    add_user alice
    # Valid and representable, but tacquito would behave differently than
    # the render of what it imports (the hand-built fixture lacks the command
    # rules the product writes).
    cp "${TACCTL_SRC}/tests/fixtures/tacquito.minimal.yaml" "${BACKUPS}/tacquito.yaml.19990101_000000"
    local before
    before=$(state_files)
    run "$TACCTL_BIN_SCRIPT" backup restore 19990101_000000 --legacy <<< "y"
    assert_failure
    assert_output --partial "not equivalent"
    [[ "$(state_files)" == "$before" ]]
}

@test "backup restore --legacy: a failing render after the import puts everything back" {
    add_user alice
    cp "${TACCTL_SRC}/tests/fixtures/golden/tacquito.minimal.rendered.yaml" \
        "${BACKUPS}/tacquito.yaml.20250101_000000"
    local before
    before=$(state_files)
    tacctl_source_lib
    backend_tacacs_render_stage() { return 1; }
    run _backup_apply _backup_import_legacy "${BACKUPS}/tacquito.yaml.20250101_000000"
    assert_failure
    [[ "$(state_files)" == "$before" ]]
}

@test "backup restore: an old-style id without --legacy points at the flag" {
    add_user alice
    printf '# old\n' > "${BACKUPS}/tacquito.yaml.20250101_000000"
    local before
    before=$(state_files)
    run "$TACCTL_BIN_SCRIPT" backup restore 20250101_000000 <<< "y"
    assert_failure
    assert_output --partial "--legacy"
    [[ "$(state_files)" == "$before" ]]
}

@test "backup restore --legacy: a snapshot id is not an old-style backup" {
    add_user alice
    run "$TACCTL_BIN_SCRIPT" backup restore "$(newest_snapshot)" --legacy <<< "y"
    assert_failure
    assert_output --partial "not found"
}

# --- Legacy mode: no store yet -----------------------------------------------

# An install the store has not been imported on. place_fixture leaves the state
# dir alone; backups made by the previous release are plain tacquito.yaml.<ts>.
legacy_install() {
    rm -f "${TACCTL_STATE_DIR}/store.yaml"
    place_fixture tacquito.minimal.yaml
    printf '# older config\n' > "${BACKUPS}/tacquito.yaml.20250101_000000"
}

@test "legacy mode: backup list shows the old-style backups and says what works" {
    legacy_install
    run "$TACCTL_BIN_SCRIPT" backup list
    assert_success
    assert_output --partial "20250101_000000"
    assert_output --partial "old-style"
    assert_output --partial "No store yet"
}

@test "legacy mode: backup diff compares the newest old-style backup with tacquito.yaml" {
    legacy_install
    run "$TACCTL_BIN_SCRIPT" backup diff
    assert_success
    assert_output --partial "backup 20250101_000000"
    assert_output --partial "older config"
}

@test "legacy mode: backup restore copies the old file back as it always did" {
    legacy_install
    run "$TACCTL_BIN_SCRIPT" backup restore 20250101_000000 <<< "y"
    assert_success
    cmp "${BACKUPS}/tacquito.yaml.20250101_000000" "$TACCTL_CONFIG"
    stub_called 'systemctl restart tacquito'
    # The file it replaced was backed up first, old-style.
    [[ "$(find "$BACKUPS" -maxdepth 1 -name 'tacquito.yaml.*' | wc -l)" -eq 2 ]]
    # No store was created behind the importer's back.
    [[ ! -e "${TACCTL_STATE_DIR}/store.yaml" ]]
}

@test "legacy mode: --legacy is accepted and means the same" {
    legacy_install
    run "$TACCTL_BIN_SCRIPT" backup restore 20250101_000000 --legacy <<< "y"
    assert_success
    cmp "${BACKUPS}/tacquito.yaml.20250101_000000" "$TACCTL_CONFIG"
}

@test "legacy mode: a snapshot is listed but neither diffed nor restored" {
    legacy_install
    mk_snapshot 20260101_000000_000
    run "$TACCTL_BIN_SCRIPT" backup list
    assert_output --partial "20260101_000000_000"
    local before
    before=$(sha256sum < "$TACCTL_CONFIG")
    run "$TACCTL_BIN_SCRIPT" backup diff 20260101_000000_000
    assert_failure
    assert_output --partial "store not initialised"
    run "$TACCTL_BIN_SCRIPT" backup restore 20260101_000000_000 <<< "y"
    assert_failure
    assert_output --partial "store not initialised"
    [[ ! -e "${TACCTL_STATE_DIR}/store.yaml" ]]
    [[ "$(sha256sum < "$TACCTL_CONFIG")" == "$before" ]]
}

@test "legacy mode: a refused mutation takes no snapshot" {
    legacy_install
    run "$TACCTL_BIN_SCRIPT" user add alice operator --hash "$TEST_HASH" --scopes lab
    assert_failure
    assert_output --partial "store not initialised"
    [[ -z "$(snapshots)" ]]
}

@test "legacy mode: an unknown timestamp is not found" {
    legacy_install
    run "$TACCTL_BIN_SCRIPT" backup restore 19990101_000000 <<< "y"
    assert_failure
    assert_output --partial "not found"
}

# --- Status and completion ---------------------------------------------------

@test "status: counts snapshots, and old-style files separately" {
    add_user alice
    add_user bob
    run "$TACCTL_BIN_SCRIPT" status
    assert_success
    assert_line --regexp 'Config backups:.* 2 \(\+1 old-style\)$'
}

@test "status: without a store the old-style files are the count" {
    legacy_install
    run "$TACCTL_BIN_SCRIPT" status
    assert_success
    assert_line --regexp 'Config backups:.* 1$'
}

@test "completion: backup names are snapshots newest first, then old-style ids" {
    mk_snapshot 20260101_000000_000
    mk_snapshot 20260201_000000_000
    mkdir -p "${BACKUPS}/legacy"
    printf 'a\n' > "${BACKUPS}/tacquito.yaml.20250101_000000"
    printf 'b\n' > "${BACKUPS}/legacy/tacquito.yaml.pre-store.20250601_000000"
    touch -d '2025-01-01' "${BACKUPS}/tacquito.yaml.20250101_000000"
    touch -d '2025-06-01' "${BACKUPS}/legacy/tacquito.yaml.pre-store.20250601_000000"
    run "$TACCTL_BIN_SCRIPT" _completion-names backups
    assert_success
    assert_output "20260201_000000_000
20260101_000000_000
pre-store.20250601_000000
20250101_000000"
}

@test "completion: backup names are capped at 50" {
    local i
    for i in $(seq -w 1 60); do
        mk_snapshot "20200101_000000_0${i}"
    done
    run "$TACCTL_BIN_SCRIPT" _completion-names backups
    assert_success
    [[ "${#lines[@]}" -eq 50 ]]
}
