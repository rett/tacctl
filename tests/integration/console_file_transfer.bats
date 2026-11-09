#!/usr/bin/env bats
# Integration tests for `tacctl console file-transfer`: the switch of a tier
# and of a user, the quota and the rate, the refusals, clear, and the line of
# `_console-policy` that carries them to the console.

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
    # sshd -T: no sftp subsystem unless a test says so (never the machine's sshd)
    stub_cmd sshd 'printf "port 22\nallowtcpforwarding no\nallowagentforwarding no\n"'
    load_fixture tacquito.minimal.yaml
    # alice (superuser), bob (operator), carol (readonly), all in scope lab.
    load_store_fixture store.multiscope.yaml
    CONSOLE="${TACCTL_STATE_DIR}/console.yaml"
}

snapshot_count() { find "${TACCTL_STATE_DIR}/backups" -mindepth 1 -maxdepth 1 -name '2*' | wc -l; }

# ft: tacctl console file-transfer ...
ft() { "$TACCTL_BIN_SCRIPT" console file-transfer "$@"; }

@test "console file-transfer: off by default, the superuser tier always has it; a tier is switched, snapshotted, and written as a list" {
    run ft
    assert_success
    assert_output $'readonly: disabled\noperator: disabled\nengineer: disabled\nsuperuser: enabled (always)\n\nsshd sftp subsystem: none'
    [[ ! -e "$CONSOLE" ]]
    run ft operator
    assert_output "disabled"

    local n
    n=$(snapshot_count)
    run ft operator enable
    assert_success
    assert_output --partial "File transfer is enabled for the operator tier. It applies from the next console login."
    (( $(snapshot_count) == n + 1 ))
    [[ "$(stat -c %a "$CONSOLE")" == 600 ]]
    # unlike the system shell, the engineer tier is not closed to it
    run ft engineer enable
    assert_success
    run ft
    assert_output --partial $'readonly: disabled\noperator: enabled\nengineer: enabled\nsuperuser: enabled (always)\n'
    run grep -c '^    tiers: \[operator, engineer, superuser\]$' "$CONSOLE"
    assert_output "1"
    run ft operator
    assert_output "enabled"

    run ft engineer disable
    assert_success
    run ft operator disable
    assert_success
    # everything is the built-in setting again: the key is gone from the file
    run grep -c file_transfer "$CONSOLE"
    assert_output "0"

    # the superuser tier cannot be disabled; enabling it changes nothing
    run ft superuser disable
    assert_failure 1
    assert_output --partial "The superuser tier always has file transfer; it cannot be disabled. Nothing was changed."
    n=$(snapshot_count)
    run ft superuser enable
    assert_success
    assert_output --partial "The superuser tier always has file transfer. Nothing was changed."
    (( $(snapshot_count) == n ))
}

@test "console file-transfer user: a user's setting wins over the tier's, clear gives it back, a superuser cannot be disabled" {
    run ft user carol enable
    assert_success
    assert_output --partial "File transfer is enabled for 'carol' while they are in the readonly tier"
    run ft user carol
    assert_output "enabled (user setting)"
    run ft user bob
    assert_output "disabled (tier operator)"
    run ft user alice
    assert_output "enabled (always)"

    run ft operator enable
    run ft user bob disable
    assert_success
    run ft user bob
    assert_output "disabled (user setting)"
    run ft
    assert_success
    assert_output --partial $'operator: enabled\n'
    assert_output --partial $'\n\nUsers with a setting of their own:\n  bob: disabled (operator)\n  carol: enabled (readonly)'
    run grep -c "^    users: {bob: disable, carol: 'enable:readonly'}\$" "$CONSOLE"
    assert_output "1"

    run ft user bob clear
    assert_success
    assert_output --partial "The file transfer setting of 'bob' is cleared: the tier decides."
    run ft user bob
    assert_output "enabled (tier operator)"
    run ft user bob clear
    assert_success
    assert_output --partial "'bob' has no file transfer setting of their own."
    run ft user carol clear
    run ft operator disable
    run grep -c file_transfer "$CONSOLE"
    assert_output "0"

    run ft user alice disable
    assert_failure 1
    assert_output --partial "'alice' is a superuser, and superusers always have file transfer; it cannot be disabled. Nothing was changed."
    run ft user alice enable
    assert_success
    assert_output --partial "'alice' is a superuser, who always has file transfer. Nothing was changed."
    run grep -c file_transfer "$CONSOLE"
    assert_output "0"
}

@test "console file-transfer quota and rate: the defaults, a tier's value, a user's over it, the words, clear" {
    run ft quota
    assert_success
    assert_output $'readonly: 256M (default)\noperator: 256M (default)\nengineer: 256M (default)\nsuperuser: unlimited (default)'
    run ft rate
    assert_output $'readonly: off (default)\noperator: off (default)\nengineer: off (default)\nsuperuser: off (default)'

    # a size in any form is printed back in the largest exact unit
    run ft quota operator 1024M
    assert_success
    assert_output --partial "The quota of the operator tier is 1G. It applies from the next console login."
    run ft quota operator
    assert_output "1G (set for the operator tier)"
    run ft quota engineer 1500K
    run ft quota engineer
    assert_output "1500K (set for the engineer tier)"
    run ft rate operator 512k
    assert_success
    assert_output --partial "The rate limit of the operator tier is 512K a second."
    run ft rate operator
    assert_output "512K (set for the operator tier)"
    run grep -c '^    quota: {operator: 1G, engineer: 1500K}$' "$CONSOLE"
    assert_output "1"
    run grep -c '^    rate: {operator: 512K}$' "$CONSOLE"
    assert_output "1"

    # unlimited, off and default
    run ft quota operator unlimited
    assert_success
    assert_output --partial "The operator tier has no quota."
    run ft quota operator
    assert_output "unlimited (set for the operator tier)"
    run ft quota operator default
    assert_success
    assert_output --partial "The quota of the operator tier is back to its default (256M)."
    run ft quota superuser 2G
    run ft quota superuser default
    assert_output --partial "back to its default (unlimited)"
    run ft rate operator off
    assert_success
    assert_output --partial "The operator tier has no rate limit."
    run ft quota engineer default
    run grep -cE '^    (quota|rate):' "$CONSOLE"
    assert_output "0"

    # a user's own value wins over the tier's, unlimited and off included
    run ft quota operator 1G
    run ft rate operator 10M
    run ft quota user bob 64M
    assert_success
    assert_output --partial "The quota of 'bob' is 64M."
    run ft rate user bob off
    assert_success
    assert_output --partial "'bob' has no rate limit, whatever their tier has."
    run ft quota user carol unlimited
    run ft rate user carol 2M
    run ft quota user bob
    assert_output "64M (user setting)"
    run ft rate user bob
    assert_output "off (user setting)"
    run ft quota user alice
    assert_output "unlimited (default)"
    run ft rate user dave
    assert_failure 1
    assert_output --partial "User 'dave' does not exist."
    run ft quota
    assert_output --partial $'\n\nUsers with a quota of their own:\n  bob: 64M (operator)\n  carol: unlimited (readonly)'
    run ft rate
    assert_output --partial $'operator: 10M (set for the operator tier)'
    assert_output --partial $'\n\nUsers with a rate limit of their own:\n  bob: off (operator)\n  carol: 2M (readonly)'
    run grep -c "^    quota_users: {bob: 64M, carol: unlimited}\$" "$CONSOLE"
    assert_output "1"
    run grep -c "^    rate_users: {bob: 'off', carol: 2M}\$" "$CONSOLE"
    assert_output "1"

    run ft quota user bob clear
    assert_success
    assert_output --partial "The quota of 'bob' is cleared: the tier decides."
    run ft quota user bob
    assert_output "1G (set for the operator tier)"
    run ft quota user bob clear
    assert_success
    assert_output --partial "'bob' has no quota of their own."
    run ft rate user bob clear
    run ft rate user carol clear
    run ft quota user carol clear
    run ft quota operator default
    run ft rate operator off
    run grep -c file_transfer "$CONSOLE"
    assert_output "0"
}

@test "console file-transfer: console show lists the tiers' state, quota and rate and each user's next to the system shell" {
    printf 'authsrv|local||lab|127.0.0.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    ft operator enable
    ft quota operator 1G
    ft user carol enable
    ft rate user carol 1M
    run "$TACCTL_BIN_SCRIPT" console show
    assert_success
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    assert_output --partial $'File transfer (off by default; a user\'s own setting wins over the tier\'s):\n  readonly: disabled, quota 256M (default), rate off (default)\n  operator: enabled, quota 1G, rate off (default)'
    assert_output --partial "SYSTEM SHELL"
    assert_output --regexp "FILE TRANSFER +QUOTA +RATE"
    assert_output --regexp "alice +superuser .*enabled \(always\) +unlimited +off"
    assert_output --regexp "bob +operator .*enabled \(tier operator\) +1G +off"
    assert_output --regexp "carol +readonly .*enabled \(user setting\) +256M +1M"
}

@test "console file-transfer: bad arguments exit 1 with the usage or the reason and write nothing" {
    local args
    while IFS= read -r args; do
        run ft $args
        assert_failure 1
    done <<'LIST'
mode
root enable
operator maybe
operator enable extra
user
user bob maybe
user bob enable extra
user nobody enable
quota mode 1G
quota operator 0
quota operator 1.5G
quota operator 12X
quota operator 2T
quota operator 99999999999999999999
quota operator off
quota operator 1G extra
quota user
quota user nobody 1G
quota user bob default
quota user bob 0
quota user bob 1G extra
rate operator 0
rate operator unlimited
rate operator default
rate operator 2T
rate user bob fast
rate user bob unlimited
rate user nobody 1M
LIST
    [[ ! -e "$CONSOLE" ]]
    (( $(snapshot_count) == 0 ))

    # the reasons
    run ft quota operator 0
    assert_output --partial "Size '0' is zero: give a size above zero, or unlimited for no limit."
    run ft quota operator 2T
    assert_output --partial "Size '2T' is too large: at most 1T."
    run ft quota operator 1.5G
    assert_output --partial "Invalid size '1.5G': expected a number of bytes or a number with K, M, G or T"
    run ft quota operator -- -5M
    assert_failure 1
    assert_output --partial "Invalid size '-5M'"
    [[ ! -e "$CONSOLE" ]]
}

@test "_console-policy: file transfer for the caller, off unless the settings give it" {
    stub_cmd id 'echo "$3 tac-users"'
    # a superuser has it, with no quota; the others do not; root has none
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_success
    assert_output --partial " file_transfer=yes ft_quota=0 ft_rate=0"
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" _console-policy
    refute_output --partial "file_transfer"
    run "$TACCTL_BIN_SCRIPT" _console-policy
    refute_output --partial "file_transfer"

    ft operator enable
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output --partial " file_transfer=yes ft_quota=268435456 ft_rate=0"
    ft quota operator 1G
    ft rate operator 512K
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output --partial " file_transfer=yes ft_quota=1073741824 ft_rate=524288"
    ft quota user bob unlimited
    ft rate user bob 2M
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output --partial " file_transfer=yes ft_quota=0 ft_rate=2097152"
    # the user's own disable beats the tier's enable; carol's enable the tier's silence
    ft user bob disable
    SUDO_USER=bob run "$TACCTL_BIN_SCRIPT" _console-policy
    refute_output --partial "file_transfer"
    ft user carol enable
    SUDO_USER=carol run "$TACCTL_BIN_SCRIPT" _console-policy
    assert_output --partial " file_transfer=yes ft_quota=268435456 ft_rate=0"
}

@test "console file-transfer: the list form and console show say whether sshd defines an sftp subsystem, and warn when it is on and there is none" {
    printf 'authsrv|local||lab|127.0.0.1|\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    stub_cmd sshd 'printf "port 22\nallowtcpforwarding no\nallowagentforwarding no\nsubsystem sftp /usr/lib/openssh/sftp-server\n"'
    run ft
    assert_success
    assert_output --partial $'\nsshd sftp subsystem: /usr/lib/openssh/sftp-server'
    refute_output --partial "WARNING"
    # none, and only the superuser tier has it: said, quiet
    stub_cmd sshd 'printf "port 22\nallowtcpforwarding no\nallowagentforwarding no\n"'
    run ft
    assert_output --partial $'\nsshd sftp subsystem: none'
    refute_output --partial "WARNING"
    # none, and a tier has it: warned
    ft operator enable
    run ft
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    assert_output --partial $'\nsshd sftp subsystem: none\nWARNING: sshd defines no sftp subsystem: file transfer cannot start; add `Subsystem sftp ...` to sshd_config.'
    run "$TACCTL_BIN_SCRIPT" console show
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    assert_output --partial "WARNING: sshd defines no sftp subsystem"
}
