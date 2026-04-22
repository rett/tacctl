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
    [[ "$BACKUP_DIR" == "${TACCTL_ETC}/backups" ]]
    [[ "$ACCT_LOG" == "${TACCTL_LOG}/accounting.log" ]]
}

@test "sanity: tmpenv points at tmpdir, not host" {
    [[ "$TACCTL_ETC" == "${BATS_TEST_TMPDIR}/etc" ]]
    [[ "$TACCTL_CONFIG" != "/etc/tacquito/tacquito.yaml" ]]
}

@test "sanity: core functions are defined after sourcing" {
    declare -f cmd_user > /dev/null
    declare -f cmd_list > /dev/null
    declare -f cmd_add > /dev/null
    declare -f cmd_scope > /dev/null
}
