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

@test "audit: a password typed in the place of the prompt is redacted" {
    as_user ops no no -- user passwd dave "$SECRET"
    assert_failure
    run audit_calls
    assert_line --regexp 'cmd start .* cmd="user passwd" args="dave <redacted>" sid='
    refute_output --partial "$SECRET"
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

@test "audit: a write verb writes its detail line between the start and the end" {
    as_user ops no no -- user add dave operator --hash "$TEST_HASH" --scopes lab
    assert_success
    run audit_calls
    assert_line --regexp '^logger -t tacctl -p auth.info user add name=dave group=operator scopes=lab by=ops sid=[a-z0-9]{8}$'
    [[ "$(audit_calls | sed -n 1p)" == *"cmd start "* ]]
    [[ "$(audit_calls | sed -n 2p)" == *"user add name=dave "* ]]
    [[ "$(audit_calls | sed -n 3p)" == *"cmd end "* ]]
    refute_output --partial "$TEST_HASH"
}

@test "audit: a list in a value is one unquoted word" {
    as_user ops no no -- scope add x1 --prefixes 10.5.0.0/16,10.6.0.0/16
    assert_success
    run audit_calls
    assert_line --regexp 'scope add name=x1 prefixes=10\.5\.0\.0/16,10\.6\.0\.0/16 default=no by=ops sid='
    refute_output --partial 'prefixes="'
}

@test "audit: a setting's detail line has the value before and after" {
    as_user ops no no -- config password-age 77
    assert_success
    run audit_calls
    assert_line --regexp 'config password-age from=[0-9]+ to=77 by=ops sid='
}

@test "audit: a secret shown is a secret-read line for the superuser too, and no pair" {
    as_user ops no no -- scope secret lab show
    assert_success
    run audit_calls
    assert_line --regexp '^logger -t tacctl -p auth.info secret-read kind=scope name=lab by=ops sid=[a-z0-9]{8}$'
    refute_output --partial "cmd "
}

@test "audit: a line that existed keeps its words and ends in result=ok" {
    as_user ops no no -- scope breakglass lab add labadmin
    assert_success
    run audit_calls
    assert_line --regexp 'scope breakglass add scope=lab name=labadmin role=[a-z]+ by=ops result=ok sid='
}
