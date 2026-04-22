#!/usr/bin/env bats
# End-to-end smoke test: scope → user → config render → user remove → scope remove.
# Every external shell-out (systemctl, chown, ip, logger) is stubbed.

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
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'
    load_fixture tacquito.minimal.yaml
}

@test "smoke: fresh install → add scope → add user → render → remove → verify clean" {
    # 1. Starting state: only the 'lab' scope from the minimal fixture.
    run "$TACCTL_BIN_SCRIPT" scope list
    assert_success
    assert_output --partial "lab"
    refute_output --partial "prod"

    # 2. Add a 'prod' scope and mark it default.
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 \
        --secret "prod-secret-0123456789abcdef" \
        --default
    assert_success

    # 3. Add a user into prod.
    run "$TACCTL_BIN_SCRIPT" user add alice superuser \
        --hash "$TEST_HASH" --scopes prod
    assert_success

    # 4. user list sees alice.
    run "$TACCTL_BIN_SCRIPT" user list
    assert_success
    assert_output --partial "alice"

    # 5. scopes show sees alice's membership.
    run "$TACCTL_BIN_SCRIPT" scope show prod
    assert_success
    assert_output --partial "10.0.0.0/8"

    # 6. Render Cisco config for prod — should be non-empty and include the secret.
    run "$TACCTL_BIN_SCRIPT" config cisco --scope prod
    assert_success
    assert_output --partial "prod-secret-0123456789abcdef"
    assert_output --partial "10.0.0.42"

    # 7. Remove alice.
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" user remove alice'
    assert_success
    run "$TACCTL_BIN_SCRIPT" user list
    refute_output --partial "alice"

    # 8. Switch default back to lab so prod is deletable.
    run "$TACCTL_BIN_SCRIPT" scope default lab
    assert_success

    # 9. Remove prod.
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove prod'
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope list
    refute_output --partial "prod"

    # 10. All the expected stubs were called at least once.
    stub_called 'systemctl restart tacquito'
}
