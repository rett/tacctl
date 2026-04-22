#!/usr/bin/env bats
# E2E tests for `tacctl log`: tail, search, failures, accounting.
# journalctl is stubbed to return canned entries.

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
    # journalctl stub: deterministic log entries.
    stub_cmd journalctl 'cat <<LOG
2026-04-21 10:00:00 tacquito[1]: INFO auth OK user=alice
2026-04-21 10:01:00 tacquito[1]: ERROR bad secret from 10.0.0.5
2026-04-21 10:02:00 tacquito[1]: INFO auth OK user=bob
2026-04-21 10:03:00 tacquito[1]: FAIL auth user=carol: bcrypt mismatch
LOG'
    load_fixture tacquito.minimal.yaml
}

@test "log tail: shells out to journalctl -u tacquito" {
    run "$TACCTL_BIN_SCRIPT" log tail 20
    assert_success
    assert_output --partial "Recent TACACS+ Log Entries"
    assert_output --partial "auth OK user=alice"
    stub_called 'journalctl -u tacquito'
}

@test "log tail: default count is 20" {
    run "$TACCTL_BIN_SCRIPT" log tail
    assert_success
    stub_called 'journalctl -u tacquito --no-pager -n 20'
}

@test "log search: filters journal output by keyword" {
    run "$TACCTL_BIN_SCRIPT" log search alice
    assert_success
    assert_output --partial "auth OK user=alice"
    refute_output --partial "auth OK user=bob"
}

@test "log search: rejects missing argument" {
    run "$TACCTL_BIN_SCRIPT" log search
    assert_failure
}

@test "log search: reports 'No matches found' when empty" {
    run "$TACCTL_BIN_SCRIPT" log search "no-such-user-xyz"
    assert_success
    assert_output --partial "No matches found"
}

@test "log failures: reports entries matching ERROR|fail|bad secret" {
    run "$TACCTL_BIN_SCRIPT" log failures
    assert_success
    assert_output --partial "ERROR bad secret"
    assert_output --partial "FAIL auth user=carol"
}

@test "log accounting: reads from \$ACCT_LOG when present" {
    mkdir -p "$(dirname "$TACCTL_LOG/accounting.log")"
    cat > "$TACCTL_LOG/accounting.log" <<EOF
2026-04-21T10:00:00Z START user=alice task_id=1
2026-04-21T10:00:05Z STOP  user=alice task_id=1 elapsed=5
EOF
    run "$TACCTL_BIN_SCRIPT" log accounting 10
    assert_success
    assert_output --partial "user=alice"
    assert_output --partial "START"
    assert_output --partial "STOP"
}

@test "log accounting: reports helpful message when file missing" {
    run "$TACCTL_BIN_SCRIPT" log accounting
    assert_success
    assert_output --partial "No accounting log found"
}

# --- log clear ---------------------------------------------------------------

@test "log clear: cancels on empty/n response and leaves logs intact" {
    # Seed an accounting file so we can verify it survives the cancel.
    mkdir -p "$TACCTL_LOG"
    echo "keepme" > "$TACCTL_LOG/accounting.log"

    run bash -c 'echo | "'"$TACCTL_BIN_SCRIPT"'" log clear'
    assert_success
    assert_output --partial "Cancelled"
    # journalctl should not have been invoked at all on cancel.
    run stub_called '^journalctl --rotate'
    assert_failure
    [[ "$(cat "$TACCTL_LOG/accounting.log")" == "keepme" ]]
}

@test "log clear: with --force skips prompt and rotates+vacuums+truncates" {
    mkdir -p "$TACCTL_LOG"
    echo "old-accounting-entry" > "$TACCTL_LOG/accounting.log"

    run "$TACCTL_BIN_SCRIPT" log clear --force
    assert_success
    assert_output --partial "Logs cleared"
    stub_called '^journalctl --rotate'
    stub_called '^journalctl --vacuum-time=1s -u tacquito'
    # File still exists but is now empty (logrotate-safe truncate).
    [[ -f "$TACCTL_LOG/accounting.log" ]]
    [[ ! -s "$TACCTL_LOG/accounting.log" ]]
}

@test "log clear: with 'y' confirmation proceeds" {
    mkdir -p "$TACCTL_LOG"
    echo "old" > "$TACCTL_LOG/accounting.log"

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" log clear'
    assert_success
    assert_output --partial "Logs cleared"
    [[ ! -s "$TACCTL_LOG/accounting.log" ]]
}

@test "log clear: usage listing mentions the new subcommand" {
    run "$TACCTL_BIN_SCRIPT" log
    assert_failure
    assert_output --partial "clear"
}
