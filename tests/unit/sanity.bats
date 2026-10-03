#!/usr/bin/env bats
load ../helpers/setup
load ../helpers/tmpenv

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
}

@test "sanity: tacctl.sh sources without dispatching" {
    [[ -n "$TACCTL_SRC" ]]
    [[ "$CONFIG" == "${TACCTL_ETC}/tacquito.yaml" ]]
    [[ "$BACKUP_DIR" == "${TACCTL_STATE_DIR}/backups" ]]
    [[ "$ACCT_LOG" == "${TACCTL_LOG}/accounting.log" ]]
}

@test "sanity: tmpenv points at tmpdir, not host" {
    [[ "$TACCTL_ETC" == "${BATS_TEST_TMPDIR}/etc" ]]
    [[ "$TACCTL_STATE_DIR" == "${BATS_TEST_TMPDIR}/state" ]]
    [[ "$TACCTL_CONFIG" != "/etc/tacquito/tacquito.yaml" ]]
}

@test "sanity: core functions are defined after sourcing" {
    declare -f cmd_user > /dev/null
    declare -f cmd_list > /dev/null
    declare -f cmd_add > /dev/null
    declare -f cmd_scope > /dev/null
}

@test "sanity: entrypoint and every lib file pass bash -n" {
    local f
    for f in "$TACCTL_SRC"/bin/tacctl.sh "$TACCTL_SRC"/lib/*.sh "$TACCTL_SRC"/lib/backends/*.sh; do
        run bash -n "$f"
        assert_success
    done
}

@test "sanity: no function is defined twice across bin/ and lib/" {
    run bash -c 'grep -hoE "^[a-zA-Z_][a-zA-Z0-9_]*\(\)" "$1"/bin/tacctl.sh "$1"/lib/*.sh "$1"/lib/backends/*.sh | sort | uniq -d' _ "$TACCTL_SRC"
    assert_success
    assert_output ""
}
