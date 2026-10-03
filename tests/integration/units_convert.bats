#!/usr/bin/env bats
# The systemd side of install, upgrade and uninstall for the TACACS+ backend:
# unit files, the template for further listeners, the rendered drop-ins, and
# the conversion of an install from before the listener model, whose
# hand-managed drop-in (tacquito.service.d/tacctl-overrides.conf) was the
# source of truth for the listen address, log level and metrics address.
#
# cmd_install, cmd_upgrade and cmd_uninstall are not run (they shell out to
# git, go and apt); the functions they call for the units are, against a
# scratch unit directory ($TACCTL_SYSTEMD_DIR) with systemctl stubbed:
#
#   _tacacs_units_install   install start, upgrade files
#   _tacacs_upgrade_units   upgrade: what it reports and counts (the unit
#                           part of the 'files' phase; the rest of that phase
#                           writes /etc/logrotate.d and is not run)
#   _tacacs_upgrade_finish  upgrade: the restart, and the way back when the
#                           unit does not come up
#   _tacacs_uninstall_stop, _tacacs_uninstall_units
#
# The running daemon is never touched by the unit install itself: the tests
# pin that it makes no systemctl call other than daemon-reload and a 'show'.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

FIX="${BATS_TEST_DIRNAME}/../fixtures"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    # The layout of a real machine: the default listener's drop-in directory
    # sits beside the unit files.
    export TACCTL_SYSTEMD_DIR="${BATS_TEST_TMPDIR}/systemd"
    export TACCTL_OVERRIDE_DIR="${TACCTL_SYSTEMD_DIR}/tacquito.service.d"
    export TACCTL_SETTLE_SECONDS=0
    mkdir -p "$TACCTL_SYSTEMD_DIR"
    stub_cmd chown
    stub_cmd logger
    stub_cmd systemctl
    stub_cmd sleep
    stub_cmd ss 'echo "LISTEN 0 128 *:49 *:*"'
    load_fixture tacquito.multiscope.yaml
    tacctl_source_lib
    UNIT="${TACCTL_SYSTEMD_DIR}/tacquito.service"
    TMPL="${TACCTL_SYSTEMD_DIR}/tacquito@.service"
    DROPIN="${TACCTL_OVERRIDE_DIR}/tacctl.conf"
    OLD_DROPIN="${TACCTL_OVERRIDE_DIR}/tacctl-overrides.conf"
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    SHIPPED="${TACCTL_SRC}/${TACACS_SHARE}"
}

# --- helpers ---

# An install from before the listener model: the unit of that release, and
# (with arguments) its hand-managed drop-in holding KEY=VALUE settings.
old_install() {
    cp "${FIX}/systemd/tacquito.service.pre-listeners" "$UNIT"
    (( $# )) || return 0
    mkdir -p "$TACCTL_OVERRIDE_DIR"
    {
        echo "[Service]"
        local kv
        for kv in "$@"; do
            echo "Environment=\"${kv}\""
        done
    } > "$OLD_DROPIN"
}

units_install() {
    _tacacs_units_install "$TACCTL_SRC"
}

# Everything the conversion may write, as checksums (a missing file says so).
tree_state() {
    local f
    for f in "$UNIT" "$TMPL" "$DROPIN" "$OLD_DROPIN" "$OVERRIDES"; do
        if [[ -f "$f" ]]; then
            echo "${f##*/} $(sha256sum < "$f")"
        else
            echo "${f##*/} absent"
        fi
    done
    find "$TACCTL_SYSTEMD_DIR" -name 'tacquito@*.service.d' | sort
}

env_of() { # <drop-in> <KEY>
    grep -oP "^Environment=\"$2=\\K[^\"]*" "$1" | tail -1
}

refute_stub_called() {
    run stub_called "$1"
    assert_failure
}

# No rollback copies are left in the state directory.
assert_no_keep() {
    run bash -c 'ls -d "$1"/.units.* 2>/dev/null' _ "$TACCTL_STATE_DIR"
    assert_output ""
}

# --- fresh machine -----------------------------------------------------------

@test "install: a fresh machine gets the unit, the template and the default listener's drop-in" {
    run units_install
    assert_success
    units_install
    [[ "$TACACS_UNITS_STATE" == "" ]]
    cmp "$UNIT" "${SHIPPED}/tacquito.service"
    cmp "$TMPL" "${SHIPPED}/tacquito@.service"
    [[ "$(stat -c %a "$UNIT")" == "644" && "$(stat -c %a "$DROPIN")" == "644" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_NETWORK)" == "tcp" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_ADDRESS)" == ":49" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "20" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_METRICS_ADDRESS)" == "127.0.0.1:8080" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_ACCT_LOG)" == "${TACCTL_LOG}/accounting.log" ]]
    # Nothing to import, nothing to back up, nothing written to tacctl.yaml.
    [[ ! -e "$OVERRIDES" && ! -e "${UNIT}.bak" && ! -e "$OLD_DROPIN" ]]
    stub_called '^systemctl daemon-reload$'
    refute_stub_called '^systemctl (restart|start|stop|enable|disable)'
}

@test "install: the first run reports 'changed' and keeps copies until the caller has restarted" {
    units_install
    [[ "$TACACS_UNITS_STATE" == "changed" ]]
    [[ -d "$TACACS_UNITS_KEEP" ]]
    printf '%s\n' "${TACACS_UNITS_NOTES[@]}" > "${BATS_TEST_TMPDIR}/notes"
    grep -qxF "Installed: tacquito.service" "${BATS_TEST_TMPDIR}/notes"
    grep -qxF "Installed: tacquito@.service" "${BATS_TEST_TMPDIR}/notes"
    grep -qxF "Rendered: the listener drop-in of tacquito.service" "${BATS_TEST_TMPDIR}/notes"
    _tacacs_units_keep_discard
    assert_no_keep
}

# --- conversion --------------------------------------------------------------

@test "convert: the drop-in's custom values move into tacctl.yaml and the unit sees the same flags" {
    old_install TACQUITO_NETWORK=tcp TACQUITO_ADDRESS=10.1.0.1:4949 TACQUITO_LEVEL=30 TACQUITO_METRICS_ADDRESS=:9090
    cp "$OLD_DROPIN" "${BATS_TEST_TMPDIR}/old-dropin"
    run units_install
    assert_success
    assert_output --partial "settings moved from ${OLD_DROPIN} into ${OVERRIDES}"

    # tacctl.yaml is the source of truth now...
    run conf_get_json listeners.tacacs.default
    assert_output '{"network": "tcp", "address": "10.1.0.1:4949"}'
    [[ "$(conf_get backends.tacacs.level)" == "30" ]]
    [[ "$(conf_get backends.tacacs.metrics_address)" == ":9090" ]]
    # ...the rendered drop-in says what the hand-managed one said...
    [[ "$(env_of "$DROPIN" TACQUITO_NETWORK)" == "tcp" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_ADDRESS)" == "10.1.0.1:4949" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "30" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_METRICS_ADDRESS)" == ":9090" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_ACCT_LOG)" == "${TACCTL_LOG}/accounting.log" ]]
    # ...and the old one is gone, with a copy kept and the old unit backed up.
    [[ ! -e "$OLD_DROPIN" ]]
    cmp "${BATS_TEST_TMPDIR}/old-dropin" "${BACKUP_DIR}"/legacy/tacctl-overrides.conf.*
    cmp "${UNIT}.bak" "${FIX}/systemd/tacquito.service.pre-listeners"
    cmp "$UNIT" "${SHIPPED}/tacquito.service"
    cmp "$TMPL" "${SHIPPED}/tacquito@.service"

    run "$TACCTL_BIN_SCRIPT" config listen show
    assert_line "  Current listener: tcp 10.1.0.1:4949"
    assert_line "  (override in ${OVERRIDES})"
    run "$TACCTL_BIN_SCRIPT" config loglevel
    assert_output --partial "debug (30)"
    run "$TACCTL_BIN_SCRIPT" config metrics
    assert_output --partial ":9090  (override)"
}

@test "convert: only what the drop-in set is written (a log level alone, as on the dev server)" {
    old_install TACQUITO_LEVEL=30
    run units_install
    assert_success
    run sed '/^#/d;/^$/d' "$OVERRIDES"
    assert_output "backends:
  tacacs:
    level: 30"
    [[ "$(env_of "$DROPIN" TACQUITO_ADDRESS)" == ":49" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "30" ]]
}

@test "convert: an install without a drop-in just gets the new files" {
    old_install
    run units_install
    assert_success
    refute_output --partial "settings moved"
    [[ ! -e "$OVERRIDES" ]]
    cmp "$UNIT" "${SHIPPED}/tacquito.service"
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "20" ]]
}

@test "convert: the drop-in is the truth while it exists; values tacctl.yaml held for those keys give way" {
    old_install TACQUITO_ADDRESS=10.1.0.1:49
    conf_set backends.tacacs.level 30
    conf_set password.max_age_days 45
    run units_install
    assert_success
    # level was not in the drop-in: it was 20 in effect, and stays 20.
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "20" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_ADDRESS)" == "10.1.0.1:49" ]]
    run grep -c level "$OVERRIDES"
    assert_output "0"
    # Unrelated keys are untouched.
    [[ "$(conf_get password.max_age_days)" == "45" ]]
}

@test "convert: needs no store (an install still in legacy mode converts too)" {
    rm -f "${TACCTL_STATE_DIR}/store.yaml"
    old_install TACQUITO_ADDRESS=10.1.0.1:49 TACQUITO_LEVEL=10
    run units_install
    assert_success
    [[ "$(env_of "$DROPIN" TACQUITO_ADDRESS)" == "10.1.0.1:49" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "10" ]]
    [[ ! -e "$OLD_DROPIN" && ! -e "${TACCTL_STATE_DIR}/store.yaml" ]]
}

@test "convert: unquoted and multi-assignment Environment= lines are read as systemd reads them" {
    old_install
    mkdir -p "$TACCTL_OVERRIDE_DIR"
    printf '[Service]\n# by hand\nEnvironment=TACQUITO_LEVEL=30\nEnvironment="TACQUITO_NETWORK=tcp6" "TACQUITO_ADDRESS=[::]:49"\n' > "$OLD_DROPIN"
    run units_install
    assert_success
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "30" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_NETWORK)" == "tcp6" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_ADDRESS)" == "[::]:49" ]]
}

@test "convert: literal flags of a unit from before the drop-in are kept" {
    cp "${FIX}/systemd/tacquito.service.literal-flags" "$UNIT"
    run units_install
    assert_success
    assert_output --partial "Migrated custom -network/-address flags"
    assert_output --partial "Migrated the custom -level flag"
    [[ "$(env_of "$DROPIN" TACQUITO_ADDRESS)" == "10.1.0.1:49" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "30" ]]
    cmp "$UNIT" "${SHIPPED}/tacquito.service"
}

@test "convert: the daemon is not touched; only systemd's view of the files is reloaded" {
    old_install TACQUITO_LEVEL=30
    units_install
    run grep '^systemctl' "$CALLS_LOG"
    assert_line "systemctl daemon-reload"
    refute_line --regexp '^systemctl (restart|start|stop|enable|disable|kill|reload)'
}

# --- already converted, and re-runs ------------------------------------------

@test "converted: a second run changes nothing and reloads nothing" {
    old_install TACQUITO_ADDRESS=10.1.0.1:49 TACQUITO_LEVEL=30
    units_install
    _tacacs_units_keep_discard
    local before
    before=$(tree_state; sha256sum "$RENDERED_FILE"; ls -la --time-style=full-iso "$TACCTL_SYSTEMD_DIR" "$TACCTL_OVERRIDE_DIR")
    : > "$CALLS_LOG"
    run units_install
    assert_success
    assert_output ""
    units_install
    [[ "$TACACS_UNITS_STATE" == "" && -z "$TACACS_UNITS_KEEP" && ${#TACACS_UNITS_NOTES[@]} -eq 0 ]]
    [[ "$(tree_state; sha256sum "$RENDERED_FILE"; ls -la --time-style=full-iso "$TACCTL_SYSTEMD_DIR" "$TACCTL_OVERRIDE_DIR")" == "$before" ]]
    refute_stub_called '^systemctl daemon-reload'
    assert_no_keep
}

@test "converted: a reload that never happened is caught by asking systemd" {
    units_install
    _tacacs_units_keep_discard
    stub_cmd systemctl 'if [[ "$1" == show && "$*" == *NeedDaemonReload* ]]; then echo "NeedDaemonReload=yes"; fi'
    : > "$CALLS_LOG"
    units_install
    [[ "$TACACS_UNITS_STATE" == "" ]]
    stub_called '^systemctl daemon-reload$'
}

# What a straight conversion of this install ends as.
reference_state() {
    old_install TACQUITO_ADDRESS=10.1.0.1:49 TACQUITO_LEVEL=30
    units_install > /dev/null
    _tacacs_units_keep_discard
    tree_state > "${BATS_TEST_TMPDIR}/reference"
    rm -rf "$TACCTL_SYSTEMD_DIR" "$OVERRIDES" "$RENDERED_FILE" "${BACKUP_DIR}/legacy"
    mkdir -p "$TACCTL_SYSTEMD_DIR"
    _conf_invalidate
    old_install TACQUITO_ADDRESS=10.1.0.1:49 TACQUITO_LEVEL=30
}

assert_converged() {
    units_install > /dev/null
    _tacacs_units_keep_discard
    diff "${BATS_TEST_TMPDIR}/reference" <(tree_state)
    [[ ! -e "$OLD_DROPIN" ]]
    assert_no_keep
    run backends_check_drift
    assert_success
}

@test "interrupted: after the import, before any file was replaced" {
    reference_state
    _tacacs_legacy_import
    grep -q 'level: 30' "$OVERRIDES"
    # Readers still show the drop-in, which is what is in effect.
    run "$TACCTL_BIN_SCRIPT" config listen show
    assert_line "  (override in ${OLD_DROPIN})"
    assert_converged
}

@test "interrupted: the new unit files are in place, the hand-managed drop-in still there" {
    reference_state
    _tacacs_legacy_import
    cp "${SHIPPED}/tacquito.service" "$UNIT"
    cp "${SHIPPED}/tacquito@.service" "$TMPL"
    assert_converged
}

@test "interrupted: both drop-ins exist (the rendered one was written, the old one not yet retired)" {
    reference_state
    _tacacs_legacy_import
    cp "${SHIPPED}/tacquito.service" "$UNIT"
    mkdir -p "${BATS_TEST_TMPDIR}/stage"
    _tacacs_units_stage "${BATS_TEST_TMPDIR}/stage"
    _tacacs_units_commit "${BATS_TEST_TMPDIR}/stage" > /dev/null
    [[ -f "$DROPIN" && -f "$OLD_DROPIN" ]]
    assert_converged
}

@test "interrupted: a run that died leaves copies behind; the next run removes them" {
    reference_state
    mkdir -p "${TACCTL_STATE_DIR}/.units.DEAD01/keep"
    echo stale > "${TACCTL_STATE_DIR}/.units.DEAD01/keep/1"
    assert_converged
}

# --- failures leave the old unit and its files in place ----------------------

# The old install is exactly as it was and nothing new exists.
assert_untouched() { # <tree_state before>
    [[ "$(tree_state)" == "$1" ]] || { tree_state; false; }
    [[ ! -e "$TMPL" && ! -e "$DROPIN" ]]
    assert_no_keep
    refute_stub_called '^systemctl (restart|start|stop|enable|disable)'
}

@test "failure: a drop-in line tacctl did not write stops the conversion, by line" {
    old_install TACQUITO_LEVEL=30
    echo 'LimitNOFILE=65536' >> "$OLD_DROPIN"
    echo 'Environment="HTTP_PROXY=http://proxy:3128"' >> "$OLD_DROPIN"
    local before
    before=$(tree_state)
    run units_install
    assert_failure
    assert_output --partial "holds lines tacctl did not write and cannot carry over"
    assert_output --partial "line 3: LimitNOFILE=65536"
    assert_output --partial "line 4: Environment=\"HTTP_PROXY=http://proxy:3128\""
    assert_output --partial "Unit update stopped: its settings could not be moved into ${OVERRIDES}."
    assert_output --partial "the running daemon were left as they are"
    assert_untouched "$before"
    refute_stub_called '^systemctl'
    # The install keeps working from the old files, and says so.
    units_install > /dev/null 2>&1 || true
    [[ "$TACACS_UNITS_STATE" == "stopped" ]]
    run "$TACCTL_BIN_SCRIPT" config loglevel
    assert_output --partial "debug (30)"
}

@test "failure: a value the schema refuses stops the conversion" {
    old_install TACQUITO_ADDRESS=not-an-address TACQUITO_LEVEL=30
    conf_set password.max_age_days 45
    local before
    before=$(tree_state)
    run units_install
    assert_failure
    assert_output --partial "listeners.tacacs.default: address 'not-an-address'"
    assert_output --partial "Unit update stopped"
    assert_untouched "$before"
    run grep -c level "$OVERRIDES"
    assert_output "0"
}

@test "failure: a listener model that cannot be served stops before any file is replaced" {
    old_install
    printf 'listeners:\n  tacacs:\n    tls: {network: tcp, address: ":300", tls: {enabled: true}}\n' > "$OVERRIDES"
    local before
    before=$(tree_state)
    run units_install
    assert_failure
    assert_output --partial "tls.enabled: true is reserved for a future release"
    assert_output --partial "Unit update stopped: the drop-ins could not be rendered"
    assert_untouched "$before"
}

@test "failure: an error after files were replaced puts every one of them back" {
    old_install TACQUITO_ADDRESS=10.1.0.1:49
    local before
    before=$(tree_state)
    # The unit and the template are written, then recording the drop-in fails.
    rendered_record() { return 1; }
    run units_install
    assert_failure
    assert_output --partial "Unit update stopped: a drop-in could not be installed."
    [[ "$(tree_state)" == "$before" ]] || { tree_state; false; }
    cmp "$UNIT" "${FIX}/systemd/tacquito.service.pre-listeners"
    [[ -f "$OLD_DROPIN" && ! -e "$DROPIN" && ! -e "$TMPL" ]]
    assert_no_keep
    # systemd is told about the restored files; the daemon is not touched.
    stub_called '^systemctl daemon-reload$'
    refute_stub_called '^systemctl (restart|start|stop)'
}

@test "failure: a tacctl.yaml that does not parse is not written into" {
    old_install TACQUITO_LEVEL=30
    printf 'password: [unterminated\n' > "$OVERRIDES"
    local before
    before=$(tree_state)
    run units_install
    assert_failure
    assert_output --partial "${OVERRIDES} is not valid YAML"
    assert_output --partial "Unit update stopped"
    assert_untouched "$before"
    # The same for a settings command.
    run "$TACCTL_BIN_SCRIPT" config loglevel error
    assert_failure
    assert_output --partial "is not valid YAML"
    [[ "$(tree_state)" == "$before" ]]
}

@test "failure: shipped unit files that are missing stop it before anything is read" {
    old_install TACQUITO_LEVEL=30
    local before
    before=$(tree_state)
    run _tacacs_units_install "${BATS_TEST_TMPDIR}/no-such-tree"
    assert_failure
    assert_output --partial "Unit update stopped: the unit files are not under"
    assert_untouched "$before"
}

# --- upgrade: report, restart, and the way back ------------------------------

upgrade_units() {
    SCRIPTS_UPDATED=0
    UPGRADE_SUMMARY_NOTES=()
    _tacacs_upgrade_units "$TACCTL_SRC"
}

# The phases share shell state, so they run in one shell; 'finish' may exit.
upgrade_units_and_finish() {
    SKIP_BUILD=true
    CURRENT_COMMIT=abc1234
    NEW_COMMIT=abc1234
    CONFIG_SYNC_RENDERED=0
    upgrade_units
    _tacacs_upgrade_finish
    printf '%s\n' "$UPGRADE_SUMMARY_HEAD" ${UPGRADE_SUMMARY_NOTES[@]+"${UPGRADE_SUMMARY_NOTES[@]}"}
}

@test "upgrade: a conversion is reported, counted, and followed by one restart" {
    old_install TACQUITO_LEVEL=30
    run upgrade_units_and_finish
    assert_success
    assert_output --partial "Updated: tacquito.service (previous backed up to ${UNIT}.bak)"
    assert_output --partial "Installed: tacquito@.service"
    assert_output --partial "Rendered: the listener drop-in of tacquito.service"
    assert_output --partial "Restarting tacquito service..."
    assert_output --partial "Tacquito is running."
    assert_output --partial "Listening on port 49/tcp"
    assert_output --partial "Units: tacquito.service and its listener drop-in are current"
    run grep -c '^systemctl restart tacquito.service$' "$CALLS_LOG"
    assert_output "1"
    # The reload comes before the restart.
    run grep -n -E '^systemctl (daemon-reload|restart tacquito.service)$' "$CALLS_LOG"
    assert_line --index 0 --partial "daemon-reload"
    [[ ! -e "$OLD_DROPIN" && -f "$DROPIN" ]]
    assert_no_keep
}

@test "upgrade: an install that is already converted is 'Unchanged' and is not restarted" {
    units_install > /dev/null
    _tacacs_units_keep_discard
    : > "$CALLS_LOG"
    run upgrade_units_and_finish
    assert_success
    assert_output --partial "Unchanged: tacquito.service"
    refute_output --partial "Restarting"
    refute_stub_called '^systemctl (restart|daemon-reload)'
}

@test "upgrade: other files updated (README, logrotate, templates) do not restart an unchanged unit" {
    units_install > /dev/null
    _tacacs_units_keep_discard
    : > "$CALLS_LOG"
    upgrade_other_files_and_finish() {
        SKIP_BUILD=true CURRENT_COMMIT=abc1234 NEW_COMMIT=abc1234 CONFIG_SYNC_RENDERED=0
        upgrade_units
        SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 3))
        _tacacs_upgrade_finish
    }
    run upgrade_other_files_and_finish
    assert_success
    refute_output --partial "Restarting"
    refute_stub_called '^systemctl restart'
}

@test "upgrade: a re-rendered config restarts an unchanged unit" {
    units_install > /dev/null
    _tacacs_units_keep_discard
    : > "$CALLS_LOG"
    upgrade_rendered_and_finish() {
        SKIP_BUILD=true CURRENT_COMMIT=abc1234 NEW_COMMIT=abc1234
        upgrade_units
        CONFIG_SYNC_RENDERED=1
        _tacacs_upgrade_finish
    }
    run upgrade_rendered_and_finish
    assert_success
    assert_output --partial "Restarting tacquito service..."
    run grep -c '^systemctl restart tacquito.service$' "$CALLS_LOG"
    assert_output "1"
}

@test "upgrade: a unit that will not start gets the old unit, drop-in and settings back, and is restarted on them" {
    old_install TACQUITO_ADDRESS=10.1.0.1:49 TACQUITO_LEVEL=30
    local before
    before=$(tree_state)
    # is-active: down after the first restart, up after the second.
    stub_cmd systemctl '
case "$1" in
  restart) echo x >> "'"${BATS_TEST_TMPDIR}"'/restarts" ;;
  is-active) [[ "$(wc -l < "'"${BATS_TEST_TMPDIR}"'/restarts" 2>/dev/null || echo 0)" -ge 2 ]] || exit 3 ;;
esac
exit 0'
    run upgrade_units_and_finish
    assert_failure 1
    assert_output --partial "Tacquito failed to start after upgrade. The previous unit files and settings were restored."
    assert_output --partial "Rolled back to the previous unit files. Service is running."
    refute_output --partial "Rolling back binary"

    [[ "$(tree_state)" == "$before" ]] || { tree_state; false; }
    cmp "$UNIT" "${FIX}/systemd/tacquito.service.pre-listeners"
    [[ -f "$OLD_DROPIN" && ! -e "$DROPIN" && ! -e "$TMPL" && ! -e "$OVERRIDES" ]]
    assert_no_keep
    # restart (new files), reload (old files back), restart.
    run grep -E '^systemctl (daemon-reload|restart tacquito.service)$' "$CALLS_LOG"
    assert_line --index 0 "systemctl daemon-reload"
    assert_line --index 1 "systemctl restart tacquito.service"
    assert_line --index 2 "systemctl daemon-reload"
    assert_line --index 3 "systemctl restart tacquito.service"
    # The readers are back on the hand-managed drop-in.
    run "$TACCTL_BIN_SCRIPT" config listen show
    assert_line "  Current listener: tcp 10.1.0.1:49"
    assert_line "  (override in ${OLD_DROPIN})"
}

@test "upgrade: when even the old files do not start it, that is said and nothing is half-converted" {
    old_install TACQUITO_LEVEL=30
    local before
    before=$(tree_state)
    stub_cmd systemctl 'if [[ "$1" == is-active ]]; then exit 3; fi; exit 0'
    run upgrade_units_and_finish
    assert_failure 1
    assert_output --partial "Rollback failed. Check: journalctl -u tacquito"
    [[ "$(tree_state)" == "$before" ]]
}

@test "upgrade: a stopped conversion does not fail the upgrade and is in the summary" {
    old_install TACQUITO_LEVEL=30
    echo 'LimitNOFILE=65536' >> "$OLD_DROPIN"
    local before
    before=$(tree_state)
    run upgrade_units_and_finish
    assert_success
    assert_output --partial "Unit update stopped"
    assert_output --partial "Units: NOT updated"
    [[ "$(tree_state)" == "$before" ]]
}

# --- a settings command on an install that is not converted ------------------

@test "not converted: readers show the drop-in; user mutations leave it alone and render no second one" {
    old_install TACQUITO_ADDRESS=10.1.0.1:49 TACQUITO_LEVEL=30
    run "$TACCTL_BIN_SCRIPT" config listen show
    assert_line "  Current listener: tcp 10.1.0.1:49"
    assert_line "  (override in ${OLD_DROPIN})"
    run backend_call tacacs listeners list
    assert_output "default tcp 10.1.0.1:49"
    run backend_call tacacs artifacts
    assert_output "$CONFIG"

    local before
    before=$(tree_state)
    run "$TACCTL_BIN_SCRIPT" user disable alice
    assert_success
    [[ "$(tree_state)" == "$before" ]]
    [[ ! -e "$DROPIN" ]]
}

@test "not converted: the first settings change converts, keeping the other settings" {
    old_install TACQUITO_ADDRESS=10.1.0.1:49 TACQUITO_LEVEL=30
    run "$TACCTL_BIN_SCRIPT" config metrics disable
    assert_success
    assert_output --partial "settings moved from ${OLD_DROPIN} into ${OVERRIDES}"
    [[ ! -e "$OLD_DROPIN" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_ADDRESS)" == "10.1.0.1:49" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "30" ]]
    [[ "$(env_of "$DROPIN" TACQUITO_METRICS_ADDRESS)" == "127.0.0.1:0" ]]
    # A later upgrade has nothing left to import.
    run units_install
    assert_success
    refute_output --partial "settings moved"
    [[ "$(env_of "$DROPIN" TACQUITO_LEVEL)" == "30" ]]
}

@test "not converted: a settings change whose unit does not come up puts the drop-in back" {
    old_install TACQUITO_ADDRESS=10.1.0.1:49
    local before
    before=$(tree_state)
    stub_cmd systemctl 'if [[ "$1" == is-active ]]; then exit 3; fi; exit 0'
    run "$TACCTL_BIN_SCRIPT" config loglevel debug
    assert_failure
    [[ "$(tree_state)" == "$before" ]] || { tree_state; false; }
}

# --- uninstall ---------------------------------------------------------------

@test "uninstall: the layout from before the listener model is removed" {
    old_install TACQUITO_LEVEL=30
    cp "$UNIT" "${UNIT}.bak"
    touch "${TACCTL_SYSTEMD_DIR}/sshd.service"
    stub_cmd systemctl 'if [[ "$1" == is-active || "$1" == is-enabled ]]; then exit 0; fi; exit 0'
    _tacacs_uninstall_stop
    stub_called '^systemctl stop tacquito$'
    stub_called '^systemctl disable tacquito$'
    _tacacs_uninstall_units
    run find "$TACCTL_SYSTEMD_DIR" -mindepth 1
    assert_output "${TACCTL_SYSTEMD_DIR}/sshd.service"
    stub_called '^systemctl daemon-reload$'
}

@test "uninstall: unit, template, instances, their drop-ins and enablement links are removed" {
    units_install > /dev/null
    _tacacs_units_keep_discard
    "$TACCTL_BIN_SCRIPT" config listen --listener mgmt tcp 127.0.0.1:4949 > /dev/null
    "$TACCTL_BIN_SCRIPT" config listen --listener oob tcp 127.0.0.1:4950 > /dev/null
    # What 'systemctl enable' would have left, plus an instance tacctl.yaml no longer knows.
    mkdir -p "${TACCTL_SYSTEMD_DIR}/tacquito.service.wants" "${TACCTL_SYSTEMD_DIR}/multi-user.target.wants" \
             "${TACCTL_SYSTEMD_DIR}/tacquito@stale.service.d"
    ln -s "$TMPL" "${TACCTL_SYSTEMD_DIR}/tacquito.service.wants/tacquito@mgmt.service"
    ln -s "$TMPL" "${TACCTL_SYSTEMD_DIR}/tacquito.service.wants/tacquito@oob.service"
    ln -s "$UNIT" "${TACCTL_SYSTEMD_DIR}/multi-user.target.wants/tacquito.service"
    ln -s /x "${TACCTL_SYSTEMD_DIR}/multi-user.target.wants/other.service"
    echo keep > "${TACCTL_SYSTEMD_DIR}/tacquito.service.d/local.conf"
    cp "$UNIT" "${UNIT}.bak"

    run _tacacs_instance_units
    assert_output "tacquito@mgmt.service
tacquito@oob.service
tacquito@stale.service"

    : > "$CALLS_LOG"
    stub_cmd systemctl 'if [[ "$1" == is-active || "$1" == is-enabled ]]; then exit 0; fi; exit 0'
    run _tacacs_uninstall_stop
    assert_success
    stub_called '^systemctl disable --quiet --now tacquito@mgmt.service$'
    stub_called '^systemctl disable --quiet --now tacquito@oob.service$'
    stub_called '^systemctl disable --quiet --now tacquito@stale.service$'
    stub_called '^systemctl stop tacquito$'
    stub_called '^systemctl disable tacquito$'

    _tacacs_uninstall_units
    run find "$TACCTL_SYSTEMD_DIR" -mindepth 1 -not -name multi-user.target.wants
    assert_output "${TACCTL_SYSTEMD_DIR}/multi-user.target.wants/other.service"
    stub_called '^systemctl daemon-reload$'
}

@test "uninstall: nothing installed is not an error" {
    stub_cmd systemctl 'if [[ "$1" == is-active || "$1" == is-enabled ]]; then exit 3; fi; exit 0'
    run _tacacs_uninstall_stop
    assert_success
    refute_stub_called '^systemctl (stop|disable)'
    run _tacacs_uninstall_units
    assert_success
}
