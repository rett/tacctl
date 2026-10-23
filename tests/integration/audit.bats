#!/usr/bin/env bats
# The central audit lines (docs/plans/0.2.17-plan.md D249-D251) on the real
# binary: a state-changing command writes `cmd start` and `cmd end` with one
# session id, a read writes none, a secret on the command line is
# redacted, a refusal inside a verb writes `cmd DENY`. `logger` is a stub
# that appends its arguments to the calls log.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

TEST_HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
SECRET="marker-secret-0123456789abcdef"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
    "$TACCTL_BIN_SCRIPT" user add ro readonly --hash "$TEST_HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" user add op operator --hash "$TEST_HASH" --scopes lab > /dev/null
    "$TACCTL_BIN_SCRIPT" group edit operator tier engineer > /dev/null
}

# as_user <name> <managed:yes|no> <engineer:yes|no> -- <tacctl args...>:
# `sudo tacctl ...` by <name>, with the calls log emptied first.
as_user() {
    local name="$1" managed="$2" eng="$3"; shift 4
    : > "$CALLS_LOG"
    if [[ "$managed" == yes && "$eng" == yes ]]; then
        stub_cmd id 'echo "users tac-users tac-engineer"'
    elif [[ "$managed" == yes ]]; then
        stub_cmd id 'echo "users tac-users"'
    else
        stub_cmd id 'echo "users sudo"'
    fi
    SUDO_USER="$name" run "$TACCTL_BIN_SCRIPT" "$@"
}

# The audit lines of the run, one per logger call.
audit_calls() { grep -E '^logger -t tacctl ' "$CALLS_LOG" || true; }

@test "audit: a write verb writes the start and the end line with one session id" {
    as_user ops no no -- user disable ro
    assert_success
    run audit_calls
    assert_line --regexp '^logger -t tacctl -p auth.info cmd start v=1 user=ops uid=- origin=sudo tier=unrestricted tty=[^ ]+ console=- cmd="user disable" args=ro sid=[a-z0-9]{8}$'
    assert_line --regexp '^logger -t tacctl -p auth.info cmd end v=1 user=ops cmd="user disable" result=ok status=0 duration=[0-9]+\.[0-9]{3}s snapshot=[0-9]{8}_[0-9]{6}_[0-9]{3} sid=[a-z0-9]{8}$'
    # One id for every line of the command.
    [ "$(audit_calls | grep -oE 'sid=[a-z0-9]{8}$' | sort -u | wc -l)" -eq 1 ]
    # The start comes first and the end last.
    [[ "$(audit_calls | head -1)" == *"cmd start "* ]]
    [[ "$(audit_calls | tail -1)" == *"cmd end "* ]]
}

@test "audit: a failed command ends in result=failed with its status" {
    as_user ops no no -- user disable nosuchuser
    assert_failure
    run audit_calls
    assert_line --regexp 'cmd start v=1 user=ops .* cmd="user disable" args=nosuchuser sid='
    assert_line --regexp 'p auth.warning cmd end v=1 user=ops cmd="user disable" result=failed status=1 duration=[0-9]+\.[0-9]{3}s snapshot=- sid='
}

@test "audit: a command run as root without sudo says so" {
    : > "$CALLS_LOG"
    run env -u SUDO_USER -u SUDO_UID "$TACCTL_BIN_SCRIPT" user enable ro
    assert_success
    run audit_calls
    assert_line --regexp 'cmd start v=1 user=root uid=0 origin=root tier=unrestricted '
}

@test "audit: a read verb writes no central line" {
    as_user ops no no -- user list
    assert_success
    as_user ops no no -- user show ro
    assert_success
    as_user ops no no -- scope show lab
    assert_success
    run audit_calls
    refute_output --partial "cmd "
}

@test "audit: a mixed verb writes the pair only when it writes" {
    as_user ops no no -- scope secret lab show
    assert_success
    run audit_calls
    refute_output --partial "cmd "
    as_user ops no no -- scope secret lab generate
    assert_success
    run audit_calls
    assert_line --regexp 'cmd start v=1 user=ops .* cmd="scope secret" args="lab generate" sid='
    assert_line --regexp 'cmd end v=1 user=ops cmd="scope secret" result=ok status=0 '
}

@test "audit: a secret on the command line is redacted" {
    as_user ops no no -- scope secret lab set "$SECRET"
    assert_success
    run audit_calls
    assert_line --regexp 'cmd start .* cmd="scope secret" args="lab set <redacted>" sid='
    refute_output --partial "$SECRET"
    as_user ops no no -- user add dave operator --hash "$TEST_HASH" --scopes lab
    assert_success
    run audit_calls
    assert_line --regexp 'cmd start .* cmd="user add" args="dave operator --hash <redacted> --scopes lab" sid='
    refute_output --partial "$TEST_HASH"
    # Nothing logged by any command of the file holds the value.
    ! grep -q "$SECRET" "$CALLS_LOG"
}

@test "audit: a refusal inside a verb writes cmd DENY and no start line" {
    as_user op yes yes -- scope secret lab set "$SECRET"
    assert_failure
    assert_output --partial "The engineer tier reads a scope's secret"
    run audit_calls
    assert_line --regexp '^logger -t tacctl -p auth.warning cmd DENY v=1 user=op uid=- tier=engineer cmd="scope secret" args="lab set <redacted>" reason=superuser sid=[a-z0-9]{8}$'
    refute_output --partial "cmd start"
    refute_output --partial "cmd end"
    refute_output --partial "$SECRET"
}

@test "audit: the gate's refusal keeps its words, has the session id and writes no central line" {
    as_user ro yes no -- user remove op
    assert_failure
    run audit_calls
    assert_line --regexp '^logger -t tacctl -p auth.warning tier DENY user=ro tier=readonly cmd=user remove sid=[a-z0-9]{8}$'
    refute_output --partial "cmd "
}
