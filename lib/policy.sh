# shellcheck shell=bash
# tacctl lib/policy.sh -- command-authorization rules and priv-exec mappings (commands.<group>, privileges.<group>), migrations, tacquito.yaml regeneration
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# --- Validate a regex pattern ---
# Used to gate user-supplied --match values for command rules.
validate_regex() {
    local pattern="$1"
    if ! python3 -c "import re,sys; re.compile(sys.argv[1])" "$pattern" 2>/dev/null; then
        error "Invalid regex: '${pattern}'"
        exit 1
    fi
}

# --- Detect a command-rule --match regex that can never match ---
# Exit 0 when <regex> repeats the rule's own command word (`^show .*$`
# for rule 'show'). tacquito tests --match against the command's
# arguments only, so such a rule silently denies every invocation.
# Logic lives in the schema module (command_match_is_dead) so the
# write-time validator, this CLI gate, and the upgrade migration agree.
command_match_is_dead() {
    local name="$1" pattern="$2"
    python3 -c "$(_conf_schema_py)
import sys
sys.exit(0 if command_match_is_dead(sys.argv[1], sys.argv[2]) else 1)
" "$name" "$pattern"
}

# --- Validate a Cisco privilege-exec command string ---
# Cisco command paths can contain spaces ("show running-config",
# "terminal monitor"). Allow letters, digits, spaces, '-', '_'. Reject
# leading/trailing whitespace, control chars, and shell metacharacters
# that could break the emitted device config.
validate_priv_command_string() {
    local cmd="$1"
    if [[ -z "$cmd" ]]; then
        error "Privilege command must not be empty."
        exit 1
    fi
    if [[ "$cmd" =~ ^[[:space:]] || "$cmd" =~ [[:space:]]$ ]]; then
        error "Privilege command has leading/trailing whitespace: '${cmd}'"
        exit 1
    fi
    if [[ ! "$cmd" =~ ^[a-zA-Z][a-zA-Z0-9\ _-]+$ ]]; then
        error "Invalid privilege command '${cmd}'."
        error "Use letters, digits, spaces, '-', '_' (e.g. 'show running-config', 'terminal monitor')."
        exit 1
    fi
    if [[ ${#cmd} -gt 64 ]]; then
        error "Privilege command too long (${#cmd} chars; max 64)."
        exit 1
    fi
}

# --- Read all `<group>|<cmd>` mappings ---
# Emits one 'group|cmd' line per mapping. Backed by privileges.<group> lists
# under the unified config. Missing key / empty map yields no output.
read_all_privileges() {
    local groups group
    groups=$(conf_get_keys privileges)
    while IFS= read -r group; do
        [[ -z "$group" ]] && continue
        while IFS= read -r cmd; do
            [[ -z "$cmd" ]] && continue
            printf '%s|%s\n' "$group" "$cmd"
        done < <(conf_get_list "privileges.${group}")
    done <<< "$groups"
}

# --- Read the priv-exec command list for one group ---
# Emits one cmd per line. Empty output = group has no explicit mappings
# (caller decides whether to fall back to a default set or emit nothing).
read_group_privileges() {
    conf_get_list "privileges.$1"
}

# --- Default priv-exec command set per built-in group ---
# Pulled from conf_emit_defaults() (the single source of truth for shipped
# defaults), not hardcoded here. Conservative: only move-DOWN cases
# (priv-15 commands pushed to a lower level so operator-class users can
# run them). Move-UP cases (e.g. ping at default priv 1 → priv 7) are
# deliberately omitted — they would silently restrict commands from
# lower-priv groups. Unknown / custom groups → empty list.
default_privileges_for_group() {
    local group="$1"
    python3 - <(conf_emit_defaults) "$group" <<'PY'
import sys, yaml
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
for item in ((d.get('privileges') or {}).get(sys.argv[2], []) or []):
    print(item)
PY
}

# --- Replace a group's full priv-exec list ---
# new_list is a newline-separated set of command strings (or empty to
# wipe the group). Writes to privileges.<group> in tacctl.yaml.
write_group_privileges() {
    local group="$1"
    local new_list="$2"
    printf '%s\n' "$new_list" | conf_set_list "privileges.${group}"
}

# --- Validate a TACACS+ command name (the cmd= value sent by the device) ---
# Allow * (wildcard / catchall) plus typical Cisco / Junos verb tokens.
validate_command_name() {
    local name="$1"
    if [[ "$name" == "*" ]]; then
        return 0
    fi
    if [[ ! "$name" =~ ^[A-Za-z][A-Za-z0-9_-]{0,31}$ ]]; then
        error "Invalid command name '${name}'."
        error "Use a literal cmd token (e.g. 'show', 'configure') or '*' for the catchall."
        exit 1
    fi
}

# --- Read a group's command rules from tacctl config ---
# Source of truth is tacctl.yaml's commands.<group> (merged over
# conf_emit_defaults). Emits one rule per line as
# `name|action|match1,match2,...` so existing callers (cmd_config_cisco,
# cmd_config_juniper, cmd_group_commands) don't need to change their
# parsing. Empty output = group has no rules at all.
read_group_commands() {
    local group="$1"
    local json
    json=$(conf_get_json "commands.${group}")
    [[ "$json" == "null" ]] && return 0
    python3 -c '
import json, sys
rules = json.loads(sys.argv[1])
if not isinstance(rules, list):
    sys.exit(0)
for r in rules:
    if not isinstance(r, dict):
        continue
    name = r.get("name", "")
    action = r.get("action", "permit")
    matches = r.get("match") or []
    joined = ",".join(matches)
    print(f"{name}|{action}|{joined}")
' "$json"
}

# --- Read a group's default action ---
# The action of the trailing `name: "*"` rule. With defaults shipping a
# catch-all for every built-in group, this effectively always returns a
# meaningful value. Custom groups without a commands entry → "permit".
read_group_default_action() {
    local group="$1"
    local last_rule
    last_rule=$(read_group_commands "$group" | tail -1)
    if [[ -z "$last_rule" ]]; then
        echo "permit"
        return
    fi
    local last_name="${last_rule%%|*}"
    if [[ "$last_name" == "*" ]]; then
        echo "$last_rule" | awk -F'|' '{print $2}'
    else
        # Group has rules but no catch-all — shouldn't happen under the
        # schema validator, but treat as "deny" since tacquito returns
        # FAIL on no-match.
        echo "deny"
    fi
}

# --- Return 0 if any group has commands rules (always true under defaults) ---
# Built-in groups all ship with defaults, so this is effectively always
# true. Retained as a predicate for callers that want the explicit check.
any_group_has_commands() {
    local keys
    keys=$(conf_get_keys commands)
    [[ -n "$keys" ]]
}

# --- One-shot: ingest existing tacquito.yaml `commands:` blocks into tacctl.yaml ---
# On upgrade from the pre-unified-commands model, tacquito.yaml is the
# source of operator customizations. We scrape each group's commands: block,
# compare to the shipped default, and write an override in tacctl.yaml when
# the scraped rules diverge. Silent no-op when scrape matches the default
# (no override is written — defaults already produce the right state).
# Idempotent: a second run scrapes the same (now-regenerated) blocks and
# sees no divergence.
conf_migrate_command_rules() {
    [[ -r "$CONFIG" ]] || return 0
    _conf_load_cache
    # One python invocation emits "<group>\t<rules-json>" per group whose
    # scraped commands: block differs from the current merged view. Silent
    # when everything already matches.
    local group rules_json
    while IFS=$'\t' read -r group rules_json; do
        [[ -z "$group" ]] && continue
        conf_set_json "commands.${group}" "$rules_json"
        info "Migrated tacquito.yaml commands: block for group '${group}' → commands.${group}"
    done < <(python3 - "$CONFIG" "$_TACCTL_CFG_CACHE" <(_conf_schema_py) <<'PY'
import json, re, sys
exec(open(sys.argv[3]).read())  # command_match_is_dead
cfg = open(sys.argv[1]).read()
merged = json.loads(sys.argv[2])
current_commands = (merged.get('commands') or {})
for gm in re.finditer(
    r'^(\w+): &\1\n(?:[ \t].*\n)+',
    cfg, re.MULTILINE,
):
    block = gm.group(0)
    group = gm.group(1)
    cm = re.search(r'^  commands:\n((?:    -.*\n(?:      .*\n)*)+)', block, re.MULTILINE)
    if not cm:
        continue
    rules_text = cm.group(1)
    rules = []
    for rm in re.finditer(
        r'    - name:\s*(?P<name>"[^"]*"|\S+)\s*\n'
        r'(?:      match:\s*\[(?P<match>[^\]]*)\]\s*\n)?'
        r'      action:\s*\*action_(?P<action>permit|deny)\s*\n',
        rules_text,
    ):
        name = rm.group('name').strip().strip('"')
        matches_str = (rm.group('match') or '').strip()
        matches = [m.strip().strip('"') for m in re.findall(r'"([^"]+)"', matches_str)] if matches_str else []
        # Drop match regexes that can never fire (they repeat the command
        # word; tacquito tests match against the arguments only). Older
        # shipped defaults had this shape, so a stale block normalizes to
        # the current default instead of being scraped into an override.
        matches = [m for m in matches if not command_match_is_dead(name, m)]
        rule = {'name': name, 'action': rm.group('action')}
        if matches:
            rule['match'] = matches
        rules.append(rule)
    if rules and current_commands.get(group) != rules:
        print(f"{group}\t{json.dumps(rules)}")
PY
)
}

# --- One-shot: strip dead `match` regexes from commands.<group> overrides ---
# tacctl <= 0.1.10 shipped operator/readonly defaults whose match regexes
# repeated the command word (`^show .*$`). tacquito tests match against the
# command's ARGUMENTS only ('running-config' for `show running-config`),
# so those rules never matched and every operator/readonly `show ...` fell
# through to the deny catch-all -- "not authorized" on the device. The
# shipped defaults are fixed; this heals overrides in tacctl.yaml that
# carry the same dead shape (scraped from an older tacquito.yaml, or
# hand-copied). A healed override that now equals the shipped default is
# dropped so the default applies. Idempotent: silent when nothing is dead.
conf_migrate_dead_command_matches() {
    [[ -f "$TACCTL_OVERRIDES_FILE" ]] || return 0
    local group verb rules_json
    while IFS=$'\t' read -r group verb rules_json; do
        [[ -z "$group" ]] && continue
        case "$verb" in
            unset)
                conf_unset "commands.${group}"
                info "Dropped commands.${group} override: its match regexes could never fire; shipped defaults now apply"
                ;;
            set)
                conf_set_json "commands.${group}" "$rules_json"
                info "Rewrote commands.${group} override: removed match regexes that could never fire"
                ;;
        esac
    done < <(python3 - "$TACCTL_OVERRIDES_FILE" <(conf_emit_defaults) <(_conf_schema_py) <<'PY'
import json, sys, yaml
exec(open(sys.argv[3]).read())  # command_match_is_dead
try:
    overrides = yaml.safe_load(open(sys.argv[1])) or {}
except Exception:
    sys.exit(0)
defaults = yaml.safe_load(open(sys.argv[2])) or {}
default_cmds = defaults.get('commands') or {}
for group, rules in sorted((overrides.get('commands') or {}).items()):
    if not isinstance(rules, list):
        continue
    changed = False
    healed = []
    for r in rules:
        if isinstance(r, dict) and r.get('match'):
            kept = [m for m in r['match'] if not command_match_is_dead(r.get('name'), m)]
            if len(kept) != len(r['match']):
                changed = True
                r = dict(r)
                if kept:
                    r['match'] = kept
                else:
                    del r['match']
        healed.append(r)
    if not changed:
        continue
    if healed == default_cmds.get(group):
        print(f"{group}\tunset\t")
    else:
        print(f"{group}\tset\t{json.dumps(healed)}")
PY
)
}

# --- One-shot: migrate legacy Cisco exec service name `exec` -> `shell` ---
# Pre-a1e39e6 installs named the Cisco exec service `name: exec`, but real
# devices request `service=shell` for EXEC authorization (Cisco
# `aaa authorization exec`, Peplink Balance, etc.). tacquito's session
# authorizer only returns AVPs for a service whose name matches the requested
# service, so legacy `name: exec` blocks never match `service=shell`:
# authorization fails AFTER a successful authentication, which clients surface
# as "invalid password". `tacctl group add` now emits `name: shell`, but
# already-deployed configs are never rewritten by regenerate_tacquito_commands
# (it only touches `commands:` blocks). This rewrites the `exec_*` service
# anchors in place.
# Idempotent: silent no-op once every exec anchor already says `name: shell`.
conf_migrate_exec_service_name() {
    [[ -r "$CONFIG" ]] || return 0
    # Count eligible legacy lines first so we only back up / write when there's
    # something to do. Only the service-name line directly under a Cisco
    # `exec_<group>: &exec_<group>` anchor matches; the `^exec_` anchor and
    # trailing `$` keep junos blocks (`junos_exec_*` / `name: junos-exec`) and
    # group bodies untouched.
    local n
    n=$(python3 -c "
import re, sys
cfg = open(sys.argv[1]).read()
print(len(re.findall(r'(?m)^exec_\w+: &exec_\w+\n  name: exec\$', cfg)))
" "$CONFIG" 2>/dev/null) || return 0
    [[ "${n:-0}" -gt 0 ]] || return 0

    # Snapshot before mutating so the backup is the pre-migration file, then
    # rewrite atomically (mirrors regenerate_tacquito_commands).
    backup_config
    python3 - "$CONFIG" <<'PY'
import re, sys, tempfile, os
cfg_path = sys.argv[1]
cfg = open(cfg_path).read()
new_cfg = re.sub(r'(?m)^(exec_\w+: &exec_\w+\n  name: )exec$', r'\1shell', cfg)
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(cfg_path) or '.', delete=False)
tmp.write(new_cfg)
tmp.close()
os.chmod(tmp.name, 0o640)
os.rename(tmp.name, cfg_path)
PY
    chown tacquito:tacquito "$CONFIG" 2>/dev/null || true
    info "Migrated tacquito.yaml service name(s) exec → shell for ${n} group(s)"
}

# --- Regenerate tacquito.yaml's per-group `commands:` blocks from tacctl ---
# tacctl.yaml (merged with defaults) is the single source of truth. This
# function rewrites every group's commands: block in tacquito.yaml to match.
# Called after every command-rule mutation and from install/upgrade.
# Idempotent: a second call with the same tacctl state is a no-op.
#
# If `$1` is given, only that group's block is regenerated (cheaper).
# With no argument, every group present in tacctl.yaml OR tacquito.yaml
# is synced.
regenerate_tacquito_commands() {
    local only_group="${1:-}"
    _conf_load_cache
    python3 - "$CONFIG" "$_TACCTL_CFG_CACHE" "$only_group" <<'PY'
import json, re, sys, tempfile, os
cfg_path, merged_json, only_group = sys.argv[1], sys.argv[2], sys.argv[3]
if not os.path.isfile(cfg_path):
    sys.exit(0)
cfg = open(cfg_path).read()
merged = json.loads(merged_json)
commands = merged.get('commands') or {}

def render_block(rules):
    """Emit a tacquito-shaped `  commands:` block for a rule list."""
    if not rules:
        return ""
    lines = ["  commands:\n"]
    for r in rules:
        name = r.get("name", "")
        action = r.get("action", "permit")
        match = r.get("match") or []
        lines.append(f'    - name: "{name}"\n')
        if match:
            quoted = ", ".join(f'"{m}"' for m in match)
            lines.append(f"      match: [{quoted}]\n")
        lines.append(f"      action: *action_{action}\n")
    return "".join(lines)

def splice_group(cfg, group, new_block):
    """Replace (or insert/delete) the `commands:` section of <group>."""
    # Match from "<group>: &<group>\n" to the line before "  accounter:"
    # (every tacctl-managed group has exactly one accounter: line at the
    # bottom — that's the block's terminal sentinel).
    hdr = re.escape(group) + r': &' + re.escape(group)
    m = re.search(
        r'(^' + hdr + r'\n(?:[ \t].*\n)*?)'
        r'(^  commands:\n(?:    -.*\n(?:      .*\n)*)+)?'
        r'(^  accounter:.*\n)',
        cfg, re.MULTILINE,
    )
    if not m:
        return cfg  # group absent or shape unexpected; leave alone
    pre, _old_commands, accounter = m.group(1), m.group(2) or "", m.group(3)
    return cfg[:m.start()] + pre + new_block + accounter + cfg[m.end():]

# Figure out which groups to sync. Under -g (only_group) mode, just that
# one. Otherwise walk every group that either has a tacctl rule list OR
# has a commands: block in tacquito.yaml today.
if only_group:
    groups_to_sync = [only_group]
else:
    tacquito_groups = set(re.findall(r'^(\w+): &\1\n  name: \1\n', cfg, re.MULTILINE))
    groups_to_sync = sorted(set(commands.keys()) | tacquito_groups)

new_cfg = cfg
for g in groups_to_sync:
    rules = commands.get(g) or []
    new_cfg = splice_group(new_cfg, g, render_block(rules))

# Normalize runs of blank lines the splicing might leave behind.
new_cfg = re.sub(r'\n{3,}', '\n\n', new_cfg)

if new_cfg == cfg:
    sys.exit(0)

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(cfg_path) or '.', delete=False)
tmp.write(new_cfg)
tmp.close()
os.chmod(tmp.name, 0o640)
os.rename(tmp.name, cfg_path)
PY
    chown tacquito:tacquito "$CONFIG" 2>/dev/null || true
}

# --- Write/replace a group's command rules in tacctl.yaml ---
# rules_arg format (kept for backward compat with callers): pipe-separated
# rules joined with newlines, each rule `name|action|match1,match2,...`.
# An empty rules_arg means "no overrides for this group" — if the group
# has no defaults either, the commands: block disappears from tacquito.yaml
# on the next regenerate.
write_group_commands() {
    local group="$1"
    local rules_arg="$2"
    if [[ -z "$(printf '%s' "$rules_arg" | awk 'NF')" ]]; then
        conf_unset "commands.${group}"
    else
        # Parse pipe-format → JSON array of rule dicts, validate+write.
        local json
        json=$(printf '%s\n' "$rules_arg" | python3 -c '
import json, sys
rules = []
for line in sys.stdin:
    line = line.rstrip("\n")
    if not line.strip():
        continue
    parts = line.split("|", 2)
    name = parts[0]
    action = parts[1] if len(parts) > 1 else "permit"
    matches = [m for m in (parts[2].split(",") if len(parts) > 2 else []) if m]
    rule = {"name": name, "action": action}
    if matches:
        rule["match"] = matches
    rules.append(rule)
print(json.dumps(rules))
')
        conf_set_json "commands.${group}" "$json" || return 1
    fi
    regenerate_tacquito_commands "$group"
}

