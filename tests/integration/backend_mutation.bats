#!/usr/bin/env bats
# The mutation path with more than one backend (lib/backend.sh: backends_gate,
# backends_render_all, backends_restart_changed, store_apply), before a second
# real backend exists. A stand-in backend 'fake' is registered in the test
# shell next to tacacs and enabled in tacctl.yaml. It renders one artifact
# (the user names, one per line) and can be told to refuse at its gate, to
# fail while staging, or to fail in its commit after damaging its artifact.
#
# What must hold whichever backend fails, and wherever:
#   - every rendered artifact and rendered.json are as they were;
#   - store.yaml and tacctl.yaml are as they were;
#   - no daemon was restarted.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    STORE="${TACCTL_STATE_DIR}/store.yaml"
    RENDERED="${TACCTL_STATE_DIR}/rendered.json"
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    FAKE_CONF="${TACCTL_ETC}/fake.conf"
    FAKE_LOG="${BATS_TEST_TMPDIR}/fake.log"
    # Staging directories land here, so a leak is visible.
    export TMPDIR="${BATS_TEST_TMPDIR}/tmp"
    mkdir -p "$TMPDIR"

    # tacacs alone first: a store and the tacquito.yaml rendered from it.
    cp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    chmod 600 "$STORE"
    "$TACCTL_BIN_SCRIPT" config render > /dev/null
    : > "$CALLS_LOG"

    tacctl_source_lib
    fake_backend_define
    printf 'backends:\n  enabled: [tacacs, fake]\n' > "$OVERRIDES"
    _conf_invalidate
    : > "$FAKE_LOG"
}

# The stand-in. FAKE_GATE is its gate's answer; FAKE_FAIL names the step that
# fails (stage | commit).
fake_backend_define() {
    BACKEND_IDS+=(fake)
    FAKE_GATE=0
    FAKE_FAIL=""
    backend_fake_describe() { printf '%s\n' "protocol=fake" "impl=fake" "units=fake.service"; }
    backend_fake_artifacts() { printf '%s\n' "$FAKE_CONF"; }
    backend_fake_render_gate() { echo "gate" >> "$FAKE_LOG"; return "$FAKE_GATE"; }
    backend_fake_render_stage() {
        echo "stage ${2:-}" >> "$FAKE_LOG"
        # Has any other backend's artifact been replaced yet?
        if [[ -n "${FAKE_REF:-}" ]] && cmp -s "$TACCTL_CONFIG" "$FAKE_REF"; then
            echo "tacquito.yaml untouched at stage" >> "$FAKE_LOG"
        fi
        if [[ "$FAKE_FAIL" == "stage" ]]; then
            error "fake: cannot express this model"
            return 1
        fi
        model_users > "${1}/fake.conf"
    }
    backend_fake_render_commit() {
        echo "commit" >> "$FAKE_LOG"
        if [[ "$FAKE_FAIL" == "commit" ]]; then
            # The worst case: its artifact and the records already damaged.
            printf 'half a fake render\n' > "$FAKE_CONF"
            printf '{}\n' > "$RENDERED_FILE"
            return 1
        fi
        if cmp -s "${1}/fake.conf" "$FAKE_CONF"; then
            echo "UNCHANGED"
            return 0
        fi
        cp "${1}/fake.conf" "$FAKE_CONF" || return 1
        rendered_record "$FAKE_CONF" || return 1
        echo "CHANGED"
    }
    backend_fake_render_check() { echo "current"; }
    backend_fake_render_notes() { :; }
    backend_fake_service() { echo "service $*" >> "$FAKE_LOG"; }
}

state() {
    local f
    for f in "$STORE" "$OVERRIDES" "$TACCTL_CONFIG" "$FAKE_CONF" "$RENDERED"; do
        if [[ -f "$f" ]]; then
            echo "$(basename "$f") $(sha256sum < "$f")"
        else
            echo "$(basename "$f") absent"
        fi
    done
}

no_leftovers() {
    [[ -z "$(find "$TMPDIR" -mindepth 1 -maxdepth 1)" ]]
    [[ -z "$(find "$TACCTL_STATE_DIR" -maxdepth 1 -name '.apply.*')" ]]
    [[ -z "$(find "$TACCTL_ETC" -name '*.tacctl-new')" ]]
}

# --- Both succeed ------------------------------------------------------------

@test "two backends: a mutation renders both, records both, restarts both" {
    store_apply store_user_set bob disabled=true
    [[ "${BACKENDS_CHANGED[*]}" == "tacacs fake" ]]
    grep -q '^bob$' "$FAKE_CONF"
    run rendered_check "$FAKE_CONF"
    assert_output "ok"
    run rendered_check "$TACCTL_CONFIG"
    assert_output "ok"
    stub_called '^systemctl restart tacquito$'
    grep -qx 'service restart' "$FAKE_LOG"
    no_leftovers
}

@test "two backends: every backend is gated and staged before any is committed" {
    # tacacs is listed first, so it commits first -- but only after fake staged.
    FAKE_REF="${BATS_TEST_TMPDIR}/tacquito.before"
    cp "$TACCTL_CONFIG" "$FAKE_REF"
    store_apply store_user_set bob disabled=true
    ! cmp -s "$TACCTL_CONFIG" "$FAKE_REF"
    run cat "$FAKE_LOG"
    assert_line --index 0 "gate"
    assert_line --index 1 "stage "
    assert_line --index 2 "tacquito.yaml untouched at stage"
    assert_line --index 3 "commit"
}

@test "two backends: only the backend whose artifact changed is restarted" {
    store_apply store_user_set bob disabled=true
    : > "$CALLS_LOG"
    : > "$FAKE_LOG"
    # The fake artifact holds names only: a group change leaves it as it is.
    store_apply store_user_set bob group=readonly
    [[ "${BACKENDS_CHANGED[*]}" == "tacacs" ]]
    stub_called '^systemctl restart tacquito$'
    ! grep -q 'service restart' "$FAKE_LOG"
}

@test "two backends: a change that alters no artifact restarts nothing" {
    store_apply store_user_set bob disabled=true
    : > "$CALLS_LOG"
    : > "$FAKE_LOG"
    store_apply store_user_set bob password_changed=2026-01-01
    [[ "${#BACKENDS_CHANGED[@]}" -eq 0 ]]
    ! stub_called 'systemctl restart'
    ! grep -q 'service restart' "$FAKE_LOG"
}

# --- One refuses or fails ----------------------------------------------------

@test "two backends: one gate refusing refuses the command before anything is written" {
    FAKE_GATE=3
    local before
    before=$(state)
    run store_apply store_user_set bob disabled=true
    assert_failure 3
    [[ "$(state)" == "$before" ]]
    run cat "$FAKE_LOG"
    assert_output "gate"
    ! stub_called 'systemctl restart'
    [[ -z "$(find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -type d -name '2*')" ]]
}

@test "two backends: a gate answering 'adopt' forces that backend only" {
    FAKE_GATE=10
    store_apply store_user_set bob disabled=true
    grep -qx 'stage --force' "$FAKE_LOG"
    [[ "${BACKENDS_ADOPT[*]}" == "--force=fake" ]]
    # tacacs was not forced: a hand edit of its file would have refused.
    FAKE_GATE=0
    echo "# hand edit" >> "$TACCTL_CONFIG"
    run store_apply store_user_set bob disabled=false
    assert_failure 3
    assert_output --partial "was edited since tacctl rendered it"
}

@test "two backends: a backend that cannot stage leaves the other's artifact and the store untouched" {
    FAKE_FAIL=stage
    local before
    before=$(state)
    run store_apply store_user_set bob disabled=true
    assert_failure 1
    assert_output --partial "fake: cannot express this model"
    assert_output --partial "The change was not applied: ${TACCTL_CONFIG}, ${TACCTL_OVERRIDE_DIR}/tacctl.conf, ${FAKE_CONF} could not be rendered. Store and tacctl.yaml are as they were."
    [[ "$(state)" == "$before" ]]
    # tacacs staged, and was never committed.
    ! grep -q 'commit' "$FAKE_LOG"
    run rendered_check "$TACCTL_CONFIG"
    assert_output "ok"
    ! stub_called 'systemctl restart'
    no_leftovers
}

@test "two backends: a commit failing after the other's succeeded puts every artifact, the records and the store back" {
    # First a good render, so the fake artifact exists and is recorded.
    store_apply store_user_set bob disabled=true
    : > "$CALLS_LOG"
    : > "$FAKE_LOG"
    FAKE_FAIL=commit
    local before
    before=$(state)
    run store_apply store_user_set bob disabled=false
    assert_failure 1
    assert_output --partial "could not be rendered"
    # tacacs had committed: tacquito.yaml was the new render and recorded.
    grep -qx 'commit' "$FAKE_LOG"
    [[ "$(state)" == "$before" ]]
    run rendered_check "$TACCTL_CONFIG"
    assert_output "ok"
    run rendered_check "$FAKE_CONF"
    assert_output "ok"
    ! stub_called 'systemctl restart'
    ! grep -q 'service restart' "$FAKE_LOG"
    no_leftovers
    # And nothing is stuck: the same change goes through once the fault is gone.
    FAKE_FAIL=""
    run store_apply store_user_set bob disabled=false
    assert_success
}

@test "two backends: a failed first commit removes an artifact that did not exist before" {
    [[ ! -e "$FAKE_CONF" ]]
    FAKE_FAIL=commit
    local before
    before=$(state)
    run backends_render_all
    assert_failure 1
    [[ ! -e "$FAKE_CONF" ]]
    [[ "$(state)" == "$before" ]]
}

@test "one backend: a commit that fails after replacing tacquito.yaml puts it and its record back" {
    printf 'backends:\n  enabled: [tacacs]\n' > "$OVERRIDES"
    _conf_invalidate
    rendered_record() { return 1; }
    local before
    before=$(state)
    run store_apply store_user_set bob disabled=true
    assert_failure 1
    [[ "$(state)" == "$before" ]]
    unset -f rendered_record
    tacctl_source_lib
    run rendered_check "$TACCTL_CONFIG"
    assert_output "ok"
}

# --- backends_render_all and the commands built on it ------------------------

@test "backends_render_all: --force reaches every backend, --force=<id> one" {
    backends_render_all --force
    grep -qx 'stage --force' "$FAKE_LOG"
    : > "$FAKE_LOG"
    backends_render_all --force=tacacs
    grep -qx 'stage ' "$FAKE_LOG"
    run backends_render_all --bogus
    assert_failure 1
    assert_output --partial "Usage"
}

@test "backends_render_all: needs the store, and an enabled list it can resolve" {
    printf 'backends:\n  enabled: [tacacs, gone]\n' > "$OVERRIDES"
    _conf_invalidate
    local before
    before=$(state)
    run backends_render_all
    assert_failure 1
    assert_output --partial "backends.enabled names 'gone'"
    [[ "$(state)" == "$before" ]]
    rm "$STORE"
    run backends_render_all
    assert_failure 1
    assert_output --partial "store not initialised"
}

@test "config render: reports each backend, restarts the ones it changed" {
    run cmd_config_render
    assert_success
    assert_line --partial "${TACCTL_CONFIG}, ${TACCTL_OVERRIDE_DIR}/tacctl.conf is already up to date."
    assert_line --partial "Rendered ${FAKE_CONF}."
    ! stub_called 'systemctl restart'
    grep -qx 'service restart' "$FAKE_LOG"
}

@test "drift: an edited artifact of any backend is reported" {
    backends_render_all
    echo "intruder" >> "$FAKE_CONF"
    run backends_check_drift
    assert_failure 1
    assert_output "drift	${FAKE_CONF}"
    run print_drift_lines
    assert_output --partial "${FAKE_CONF} — edited since tacctl rendered it"
}

@test "backup restore: a backend that cannot stage leaves all files as they were" {
    store_apply store_user_set bob disabled=true > /dev/null
    local snap before
    snap=$(find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -type d -name '2*' | sort | head -n 1)
    before=$(state)
    FAKE_FAIL=stage
    run _backup_apply _backup_install_snapshot "$snap"
    assert_failure
    [[ "$(state)" == "$before" ]]
}
