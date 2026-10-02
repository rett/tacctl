#!/usr/bin/env bats
# Integration tests for the dead-match healing that runs on upgrade/install.
#
# tacctl <= 0.1.10 shipped operator/readonly command rules whose match
# regexes repeated the command word (`^show .*$`). tacquito's command
# authorizer tests match against the command's ARGUMENTS only (`show
# running-config` is tested as 'running-config'), so those rules never
# fired and every operator/readonly `show` fell through to the deny
# catch-all ("not authorized" on the device). Two paths must heal:
#   1. conf_migrate_command_rules must not scrape a stale tacquito.yaml
#      block into an override (it normalizes the dead regexes away first).
#   2. conf_migrate_dead_command_matches must strip the dead regexes from
#      any override already in tacctl.yaml.

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
    # These migrations heal a legacy (pre-store) tacquito.yaml, which is what
    # an upgrade runs them on; place_fixture leaves the install without a
    # store. The last tests cover the store case, where they must not touch
    # the rendered file.
    place_fixture tacquito.dead-matches.yaml
    tacctl_source_lib
}

operator_block() {
    awk '/^operator: &operator/,/^  accounter:/' "$TACCTL_CONFIG"
}

@test "scrape: a stale tacquito.yaml block with dead regexes is NOT written as an override" {
    run conf_migrate_command_rules
    assert_success
    refute_output --partial "Migrated"
    # No override for the built-ins; shipped defaults answer.
    run conf_has_override commands.operator
    assert_failure
    run conf_has_override commands.readonly
    assert_failure
}

@test "scrape: a genuinely customized block keeps its non-dead rules as an override" {
    # Add a real customization to the stale block: deny 'clear' outright.
    python3 - "$TACCTL_CONFIG" <<'PY'
import sys, re
p = sys.argv[1]; s = open(p).read()
s = s.replace('    - name: "terminal"\n      match: ["^terminal .*$"]\n      action: *action_permit\n',
              '    - name: "terminal"\n      match: ["^terminal .*$"]\n      action: *action_permit\n'
              '    - name: "clear"\n      action: *action_deny\n', 1)
open(p, 'w').write(s)
PY
    run conf_migrate_command_rules
    assert_success
    assert_output --partial "Migrated tacquito.yaml commands: block for group 'operator'"
    run conf_get_json commands.operator
    assert_output --partial '"clear"'
    refute_output --partial '^show'
    refute_output --partial 'match'
}

@test "heal: an override equal to the default once dead regexes are dropped is removed" {
    # The write-time validator rejects dead regexes now, so plant the
    # legacy override by hand the way an older tacctl would have left it.
    cat >> "$TACCTL_OVERRIDES_FILE" <<'YAML'
commands:
  operator:
    - { name: show,       action: permit, match: ["^show .*$"] }
    - { name: ping,       action: permit, match: ["^ping( .*)?$"] }
    - { name: traceroute, action: permit, match: ["^traceroute( .*)?$"] }
    - { name: terminal,   action: permit, match: ["^terminal .*$"] }
    - { name: "*",        action: deny }
YAML
    run conf_has_override commands.operator
    assert_success

    run conf_migrate_dead_command_matches
    assert_success
    assert_output --partial "Dropped commands.operator override"
    run conf_has_override commands.operator
    assert_failure
}

@test "heal: a customized override keeps its rules but loses the dead regexes" {
    cat >> "$TACCTL_OVERRIDES_FILE" <<'YAML'
commands:
  operator:
    - { name: show,       action: permit, match: ["^show .*$", "running-config.*"] }
    - { name: ping,       action: permit, match: ["^ping( .*)?$"] }
    - { name: clear,      action: deny }
    - { name: "*",        action: deny }
YAML
    run conf_migrate_dead_command_matches
    assert_success
    assert_output --partial "Rewrote commands.operator override"
    run conf_has_override commands.operator
    assert_success
    run conf_get_json commands.operator
    # Dead regexes gone; the real argument regex and the custom deny survive.
    refute_output --partial '^show .*$'
    refute_output --partial '^ping'
    assert_output --partial '"running-config.*"'
    assert_output --partial '"clear"'
    # ping lost its only regex, so the key disappears (name-only rule).
    run python3 -c 'import json,sys; r=json.loads(sys.argv[1]); print([x for x in r if x["name"]=="ping"][0].get("match","ABSENT"))' "$(conf_get_json commands.operator)"
    assert_output "ABSENT"
}

@test "heal: no-op when overrides carry no dead regexes" {
    cat >> "$TACCTL_OVERRIDES_FILE" <<'YAML'
commands:
  operator:
    - { name: show,  action: permit, match: ["running-config.*"] }
    - { name: "*",   action: deny }
YAML
    run conf_migrate_dead_command_matches
    assert_success
    assert_output ""
    run conf_get_json commands.operator
    assert_output --partial '"running-config.*"'
}

@test "end to end: scrape + heal + regenerate leaves show as a name-only permit in tacquito.yaml" {
    run operator_block
    assert_output --partial '^show .*$'

    conf_migrate_command_rules
    conf_migrate_dead_command_matches
    regenerate_tacquito_commands

    run operator_block
    assert_output --partial 'name: "show"'
    assert_output --partial 'name: "terminal"'
    assert_output --partial 'name: "*"'
    refute_output --partial 'match:'
}

# --- with a store -------------------------------------------------------------

@test "with a store: the scrape ingests nothing from the rendered file" {
    load_fixture tacquito.dead-matches.yaml
    # Even a block that differs from tacctl.yaml is not an operator
    # customization once the file is an artifact.
    python3 - "$TACCTL_CONFIG" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
s = s.replace('    - name: "terminal"\n      match: ["^terminal .*$"]\n      action: *action_permit\n',
              '    - name: "terminal"\n      match: ["^terminal .*$"]\n      action: *action_permit\n'
              '    - name: "clear"\n      action: *action_deny\n', 1)
open(p, 'w').write(s)
PY
    grep -q '"clear"' "$TACCTL_CONFIG"
    run conf_migrate_command_rules
    assert_success
    assert_output ""
    run conf_has_override commands.operator
    assert_failure
}

@test "with a store: heal + regenerate re-renders tacquito.yaml from tacctl.yaml" {
    load_fixture tacquito.dead-matches.yaml
    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null 2>&1
    cat >> "$TACCTL_OVERRIDES_FILE" <<'YAML'
commands:
  operator:
    - { name: show,  action: permit, match: ["^show .*$", "running-config.*"] }
    - { name: clear, action: deny }
    - { name: "*",   action: deny }
YAML
    conf_migrate_dead_command_matches
    run regenerate_tacquito_commands
    assert_success
    assert_output ""

    run operator_block
    assert_output --partial 'name: "show"'
    assert_output --partial '"running-config.*"'
    assert_output --partial 'name: "clear"'
    refute_output --partial '^show .*$'
    # Rendered and recorded: no drift, nothing left to render.
    run "$TACCTL_BIN_SCRIPT" config render
    assert_output --partial "already up to date"
}

@test "with a store: regenerate does not overwrite a hand-edited file, and does not fail the upgrade" {
    load_fixture tacquito.dead-matches.yaml
    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null 2>&1
    echo "# hand edit" >> "$TACCTL_CONFIG"
    "$TACCTL_BIN_SCRIPT" group commands list operator > /dev/null
    printf 'commands:\n  operator:\n    - { name: "*", action: permit }\n' >> "$TACCTL_OVERRIDES_FILE"
    local before
    before=$(cksum "$TACCTL_CONFIG")
    run regenerate_tacquito_commands
    assert_success
    assert_output --partial "was edited since tacctl rendered it"
    assert_output --partial "was not re-rendered"
    [ "$(cksum "$TACCTL_CONFIG")" = "$before" ]
}

@test "config validate: flags a hand-edited override whose match regex can never fire" {
    load_fixture tacquito.dead-matches.yaml
    cat >> "$TACCTL_OVERRIDES_FILE" <<'YAML'
commands:
  operator:
    - { name: show,  action: permit, match: ["^show .*$"] }
    - { name: "*",   action: deny }
YAML
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_failure
    assert_output --partial "commands.operator"
    assert_output --partial "can never match"
}
