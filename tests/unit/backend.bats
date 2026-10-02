#!/usr/bin/env bats
# Unit tests for the backend contract (lib/backend.sh): the registry, the
# completeness of every registered module, backend_call, the list of enabled
# backends (backends.enabled in tacctl.yaml), and the read-only verbs of the
# TACACS+ module. What a mutation does across backends is in
# tests/integration/backend_mutation.bats.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    tacctl_source_lib
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
}

# --- The contract ------------------------------------------------------------

@test "contract: tacacs is registered, exactly once" {
    run printf '%s\n' "${BACKEND_IDS[@]}"
    assert_output "tacacs"
    backend_registered tacacs
    ! backend_registered radius
    ! backend_registered ""
}

@test "contract: every registered backend defines every required verb" {
    local id verb missing=""
    (( ${#BACKEND_IDS[@]} > 0 && ${#BACKEND_VERBS[@]} > 0 ))
    for id in "${BACKEND_IDS[@]}"; do
        for verb in "${BACKEND_VERBS[@]}"; do
            declare -F "backend_${id}_${verb}" > /dev/null || missing+=" backend_${id}_${verb}"
        done
    done
    [[ -z "$missing" ]] || fail "missing:${missing}"
}

@test "contract: a module defines no backend_<id>_* function that is not a verb" {
    local id fn verb extra=""
    for id in "${BACKEND_IDS[@]}"; do
        while read -r fn; do
            verb="${fn#"backend_${id}_"}"
            [[ " ${BACKEND_VERBS[*]} " == *" ${verb} "* ]] || extra+=" ${fn}"
        done < <(declare -F | awk '{print $3}' | grep "^backend_${id}_")
    done
    [[ -z "$extra" ]] || fail "not in BACKEND_VERBS:${extra}"
}

@test "contract: every module in lib/backends/ is sourced by the entrypoint and registers its file name" {
    local f id
    for f in "$TACCTL_SRC"/lib/backends/*.sh; do
        id=$(basename "$f" .sh)
        backend_registered "$id"
        grep -qF "source \"\${SCRIPT_DIR}/../lib/backends/${id}.sh\"" "$TACCTL_BIN_SCRIPT"
    done
}

@test "contract: lifecycle phases a module does not know are a no-op, not an error" {
    local id
    for id in "${BACKEND_IDS[@]}"; do
        run backend_call "$id" install no-such-phase /nonexistent
        assert_success
        assert_output ""
        run backend_call "$id" upgrade no-such-phase /nonexistent
        assert_success
        run backend_call "$id" uninstall no-such-phase
        assert_success
    done
}

# The phase lists in lib/backend.sh are what the generic commands really run.
phases_called() { # <command function> <install|upgrade|uninstall>
    declare -f "$1" | grep -oE "(backends_run|backend_call \"\\\$_b\") $2 [a-z]+" | awk '{print $NF}' | awk '!seen[$0]++' | paste -sd' '
}

@test "contract: install, upgrade and uninstall run the documented phases, in order" {
    run phases_called cmd_install install
    assert_output "${BACKEND_INSTALL_PHASES[*]}"
    run phases_called cmd_upgrade upgrade
    assert_output "${BACKEND_UPGRADE_PHASES[*]}"
    run phases_called cmd_uninstall uninstall
    assert_output "${BACKEND_UNINSTALL_PHASES[*]}"
}

@test "backend_call: runs the verb with its arguments and returns its status" {
    BACKEND_IDS+=(fake)
    backend_fake_service() { echo "fake service $*"; return 7; }
    run backend_call fake service restart now
    assert_failure 7
    assert_output "fake service restart now"
}

@test "backend_call: an unknown backend or verb is an error (2), not a silent no-op" {
    run backend_call radius describe
    assert_failure 2
    assert_output --partial "Unknown backend 'radius'"
    run backend_call tacacs no_such_verb
    assert_failure 2
    assert_output --partial "does not implement 'no_such_verb'"
    run backend_call
    assert_failure 2
}

@test "backend_describe: one value by key; an unknown key prints nothing and fails" {
    run backend_describe tacacs protocol
    assert_output "tacacs"
    run backend_describe tacacs impl
    assert_output "tacquito"
    run backend_describe tacacs units
    assert_output "tacquito.service"
    run backend_describe tacacs log_dir
    assert_output "$TACCTL_LOG"
    run backend_describe tacacs nope
    assert_failure
    assert_output ""
}

# --- Enabled backends --------------------------------------------------------

@test "backends_enabled: tacacs by default, with and without a tacctl.yaml" {
    run backends_enabled
    assert_success
    assert_output "tacacs"
    conf_set password.max_age_days 30
    [[ -f "$OVERRIDES" ]]
    run backends_enabled
    assert_output "tacacs"
}

@test "backends_enabled: the default needs no read of the merged config" {
    stub_cmd python3 'exit 97'
    run backends_enabled
    assert_success
    assert_output "tacacs"
}

@test "backends_enabled: the shipped default is the schema's default" {
    run python3 - <(_conf_schema_py) <<'PY'
import sys
exec(open(sys.argv[1]).read())
rule = SCHEMA['backends.enabled']
print(' '.join(rule['default']))
print(' '.join(rule['values']))
PY
    assert_success
    assert_line --index 0 "${BACKENDS_DEFAULT_ENABLED[*]}"
    # Every id the schema accepts has a module, and every module is accepted.
    assert_line --index 1 "${BACKEND_IDS[*]}"
}

@test "backends_enabled: reads backends.enabled, in its order, from tacctl.yaml" {
    BACKEND_IDS+=(fake)
    printf 'backends:\n  enabled: [fake, tacacs]\n' > "$OVERRIDES"
    run backends_enabled
    assert_success
    assert_line --index 0 "fake"
    assert_line --index 1 "tacacs"
    printf 'backends:\n  enabled: [fake, fake]\n' > "$OVERRIDES"
    _conf_invalidate
    run backends_enabled
    assert_output "fake"
}

@test "backends_enabled: a backend this tacctl does not have is refused, by name" {
    printf 'backends:\n  enabled: [tacacs, radius]\n' > "$OVERRIDES"
    run backends_enabled
    assert_failure 1
    assert_output --partial "backends.enabled names 'radius'"
    refute_line "tacacs"
}

@test "backends_enabled: follows a tacctl.yaml write in the same shell" {
    BACKEND_IDS+=(fake)
    _backends_load
    [[ "${BACKENDS_ENABLED[*]}" == "tacacs" ]]
    printf 'backends:\n  enabled: [tacacs, fake]\n' > "$OVERRIDES"
    # Every conf write ends in _conf_invalidate.
    _conf_invalidate
    _backends_load
    [[ "${BACKENDS_ENABLED[*]}" == "tacacs fake" ]]
}

@test "schema: backends.enabled takes known backends only, non-empty, no duplicates" {
    run conf_set_list backends.enabled <<< "radius"
    assert_failure
    assert_output --partial "'radius' is not a backend"
    run conf_set_list backends.enabled < /dev/null
    assert_failure
    assert_output --partial "non-empty"
    run conf_set_list backends.enabled <<< $'tacacs\ntacacs'
    assert_failure
    assert_output --partial "listed twice"
    run conf_set backends.enabled tacacs
    assert_failure
    assert_output --partial "requires list input"
    [[ ! -e "$OVERRIDES" ]]
}

@test "schema: setting backends.enabled to the default writes no override, and is not a shipped default line" {
    conf_set_list backends.enabled <<< "tacacs"
    [[ ! -e "$OVERRIDES" ]]
    run conf_emit_defaults
    refute_output --partial "backends"
}

@test "schema: a hand-written backends.enabled is checked by the overrides walk" {
    printf 'backends:\n  enabled: [tacacs]\n' > "$OVERRIDES"
    run _conf_validate_overrides_file
    assert_output ""
    printf 'backends:\n  enabled: [tacacs, bogus]\n' > "$OVERRIDES"
    run _conf_validate_overrides_file
    assert_output --partial "backends.enabled: element 1: 'bogus' is not a backend"
}

# --- The TACACS+ module's read-only verbs ------------------------------------

@test "tacacs artifacts: the rendered tacquito.yaml, then the default listener's drop-in" {
    local dropin="${TACCTL_OVERRIDE_DIR}/tacctl.conf"
    run backend_call tacacs artifacts
    assert_line --index 0 "$CONFIG"
    assert_line --index 1 "$dropin"
    run backends_artifacts
    assert_output "${CONFIG}
${dropin}"
    run backends_artifact_names
    assert_output "${CONFIG}, ${dropin}"
}

@test "tacacs artifacts: an install whose hand-managed drop-in is still there has no rendered one" {
    mkdir -p "$TACCTL_OVERRIDE_DIR"
    printf '[Service]\nEnvironment="TACQUITO_LEVEL=30"\n' > "${TACCTL_OVERRIDE_DIR}/tacctl-overrides.conf"
    run backend_call tacacs artifacts
    assert_output "$CONFIG"
}

@test "tacacs installed: needs the daemon binary and the unit file" {
    SERVICE_FILE="${BATS_TEST_TMPDIR}/tacquito.service"
    run backend_call tacacs installed
    assert_failure
    touch "$SERVICE_FILE"
    run backend_call tacacs installed
    assert_failure
    printf '#!/bin/sh\n' > "$TACQUITO_BIN"
    chmod +x "$TACQUITO_BIN"
    run backend_call tacacs installed
    assert_success
}

@test "tacacs listeners list: the built-in default, then what tacctl.yaml says" {
    run backend_call tacacs listeners list
    assert_output "default tcp :49"
    # ...without reading the merged config when tacctl.yaml names no listener.
    stub_cmd python3 'exit 97'
    run backend_call tacacs listeners list
    assert_output "default tcp :49"
    rm -f "${STUB_BIN}/python3"
    conf_set_json listeners.tacacs.default '{"network": "tcp6", "address": "[::]:4949"}'
    run backend_call tacacs listeners list
    assert_output "default tcp6 [::]:4949"
}

@test "tacacs listeners list: an install that is not converted shows its hand-managed drop-in" {
    mkdir -p "$TACCTL_OVERRIDE_DIR"
    printf '[Service]\nEnvironment="TACQUITO_NETWORK=tcp6"\nEnvironment="TACQUITO_ADDRESS=[::]:4949"\n' \
        > "${TACCTL_OVERRIDE_DIR}/tacctl-overrides.conf"
    conf_set_json listeners.tacacs.default '{"network": "tcp", "address": "10.1.0.1:49"}'
    run backend_call tacacs listeners list
    assert_output "default tcp6 [::]:4949"
}

@test "tacacs listeners: list, show, set and reset; 'tacctl config listen' did not grow a 'list'" {
    run backend_call tacacs listeners show
    assert_success
    assert_line "  Current listener: tcp :49"
    run backend_call tacacs listeners frobnicate
    assert_failure 2
    # The CLI did not grow a 'list' subcommand.
    touch "$TACCTL_CONFIG"
    run "$TACCTL_BIN_SCRIPT" config listen list
    assert_failure 1
    assert_output --partial "Invalid subcommand: 'list'"
}

@test "tacacs service: restart reports and never fails; other actions pass systemctl through" {
    run backend_call tacacs service restart
    assert_success
    assert_output --partial "Service restarted."
    stub_called '^systemctl restart tacquito$'
    stub_cmd systemctl 'if [[ "$1" == "is-active" ]]; then echo inactive; exit 3; fi; exit 1'
    run backend_call tacacs service restart
    assert_success
    assert_output --partial "Service restart failed"
    run backend_call tacacs service is-active
    assert_failure 3
    assert_output "inactive"
    run backend_call tacacs service frobnicate
    assert_failure 2
}

@test "tacacs last_login: newest cmd=login of the user in the accounting log, else never" {
    run backend_call tacacs last_login alice
    assert_output "never"
    cat > "$ACCT_LOG" <<'LOG'
2026/04/20 09:00:00 {"User":"alice","Args":["cmd=login"]}
2026/04/21 10:11:12 {"User":"alice","Args":["cmd=login"]}
2026/04/22 08:00:00 {"User":"alice","Args":["cmd=logout"]}
2026/04/23 08:00:00 {"User":"bob","Args":["cmd=login"]}
LOG
    run backend_call tacacs last_login alice
    assert_output "2026-04-21 10:11:12"
    run backends_last_login alice
    assert_output "2026-04-21 10:11:12"
    run backends_last_login carol
    assert_output "never"
}

@test "backends_last_login: the most recent across enabled backends" {
    BACKEND_IDS+=(fake)
    printf 'backends:\n  enabled: [tacacs, fake]\n' > "$OVERRIDES"
    backend_fake_last_login() { echo "2026-05-01 00:00:00"; }
    printf '2026/04/21 10:11:12 {"User":"alice","Args":["cmd=login"]}\n' > "$ACCT_LOG"
    run backends_last_login alice
    assert_output "2026-05-01 00:00:00"
    backend_fake_last_login() { echo "never"; }
    run backends_last_login alice
    assert_output "2026-04-21 10:11:12"
}

@test "tacacs secret_constraints and device_vars: no limit, no variables" {
    run backend_call tacacs secret_constraints
    assert_success
    assert_line --index 0 "max_len="
    assert_line --index 1 "charset="
    run backend_call tacacs device_vars cisco lab
    assert_success
    assert_output ""
}

@test "tacacs status and log: an unknown part is refused (2)" {
    run backend_call tacacs status nope
    assert_failure 2
    run backend_call tacacs log nope
    assert_failure 2
    run backend_call tacacs accounting nope
    assert_failure 2
}

# --- Where things live -------------------------------------------------------

@test "layout: the TACACS+ backend's shipped files are under config/backends/tacacs" {
    local f
    for f in tacquito.service tacquito.logrotate tacquito.yaml; do
        [[ -f "${TACCTL_SRC}/${TACACS_SHARE}/${f}" ]]
        [[ ! -e "${TACCTL_SRC}/config/${f}" ]]
    done
    [[ "$TACACS_SHARE" == "config/backends/tacacs" ]]
}

@test "layout: no lib file outside the module calls tacquito's unit or its drop-in directly" {
    # Text printed for the operator (echo/warn lines) and comments may name them.
    run bash -c 'grep -nE "systemctl [a-z-]+ (--quiet )?tacquito|journalctl .*-u tacquito|read_service_override|tacacs_render_apply|restart_service" \
        "$1"/bin/tacctl.sh "$1"/lib/*.sh | grep -vE "^[^:]+:[0-9]+:[[:space:]]*(#|echo |warn |error |info )"' _ "$TACCTL_SRC"
    assert_output ""
}

@test "deps: python3-yaml is a core dependency" {
    [[ " $DEPS_CORE " == *" python3-yaml "* ]]
}
