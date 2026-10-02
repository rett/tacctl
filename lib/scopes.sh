# shellcheck shell=bash
# tacctl lib/scopes.sh -- scope (secrets[]) helpers, allow/deny prefix filters, scope commands
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# --- CONFIG SECRET ---
# --- Read the current shared secret from the YAML (may be empty) ---
# =====================================================================
#  SCOPE HELPERS — multi-scope YAML access
# =====================================================================
#
# A "scope" in tacctl corresponds to one `secrets:` list entry in
# /etc/tacquito/tacquito.yaml. Each scope is a named (prefixes,
# shared-secret) bundle; users carry a list of scope names in their
# `scopes:` YAML field and can auth only from devices matching a scope
# they're a member of.
#
# These helpers use yaml.safe_load for reads (robust against anchor
# expansion, field reordering, etc.) and regex-based surgical edits for
# writes (to preserve YAML anchors like *authenticator_type_bcrypt that
# safe_dump would otherwise inline).

# --- Read scope.default from the merged tacctl config ---
# Returns the configured default scope name (tacctl.yaml's scope.default,
# layered over the shipped 'lab' default). Falls back to the name of the
# sole secrets: entry if the merged value doesn't name an existing scope
# and there's exactly one scope in tacquito.yaml. Empty output if no
# scopes exist yet.
read_default_scope() {
    local v
    v=$(conf_get scope.default)
    if [[ -n "$v" ]] && scope_exists "$v"; then
        echo "$v"
        return
    fi
    # Fallback: if there's exactly one scope, it's the implicit default.
    local names
    names=$(list_scopes)
    if [[ -n "$names" && $(printf '%s\n' "$names" | wc -l) -eq 1 ]]; then
        echo "$names"
    fi
}

# --- Write scope.default to tacctl.yaml ---
# Sets the scope.default override; reverts to the shipped default when the
# value equals 'lab' (conf_set's revert-to-default semantics). Caller is
# responsible for verifying the name exists as a scope first.
write_default_scope() {
    conf_set scope.default "$1"
}

# --- List all scope names (one per line) ---
list_scopes() {
    [[ -r "$CONFIG" ]] || return 0
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
# Under flat emission one logical scope spans N secrets[] entries; dedupe
# by name preserving first-appearance order so callers see the logical view.
seen = set()
for s in (d.get('secrets') or []):
    name = s.get('name')
    if name and name not in seen:
        seen.add(name)
        print(name)
" "$CONFIG" 2>/dev/null
}

# --- Return 0 if the named scope exists ---
scope_exists() {
    local name="$1"
    [[ -n "$name" ]] || return 1
    list_scopes | grep -qxF "$name"
}

# --- Read one scope's CIDR prefixes (canonical, one per line) ---
# Aggregates across every secrets[] entry whose name matches (flat emission
# can spread a scope's prefixes across multiple entries). Output is sorted
# by the standard (version, broadcast, network) key so the caller sees a
# stable, specificity-ordered list.
read_scope_prefixes() {
    local name="$1"
    python3 -c "
import yaml, json, ipaddress, re, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
collected = []
for s in (d.get('secrets') or []):
    if s.get('name') != target:
        continue
    opts = s.get('options') or {}
    pfx = opts.get('prefixes')
    if not pfx:
        continue
    try:
        arr = json.loads(pfx)
    except Exception:
        arr = re.findall(r'\"([^\"]+)\"', pfx)
    for c in arr:
        try:
            collected.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
seen = set()
uniq = []
for n in collected:
    if n not in seen:
        seen.add(n)
        uniq.append(n)
# Sort specificity-first: prefix length DESC, then IPv4 before IPv6,
# then network address ASC for a stable tie-break among prefixes of
# the same length. Mirrors tacquito routing semantics — most-specific
# prefix wins for any given client IP, so the display reads
# top-to-bottom as 'most likely match first'.
uniq.sort(key=lambda n: (-n.prefixlen, n.version, int(n.network_address)))
for n in uniq:
    print(n)
" "$CONFIG" "$name" 2>/dev/null
}

# --- Read one scope's shared-secret key (raw value) ---
read_scope_secret() {
    local name="$1"
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
for s in (d.get('secrets') or []):
    if s.get('name') == target:
        sec = s.get('secret') or {}
        print(sec.get('key') or '')
        break
" "$CONFIG" "$name" 2>/dev/null
}

# --- Read one user's scope list (one scope name per line) ---
read_user_scopes() {
    local username="$1"
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
for u in (d.get('users') or []):
    if u.get('name') == target:
        for s in (u.get('scopes') or []):
            print(s)
        break
" "$CONFIG" "$username" 2>/dev/null
}

# --- Count users referencing a given scope ---
count_users_in_scope() {
    local scope="$1"
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
c = 0
for u in (d.get('users') or []):
    if target in (u.get('scopes') or []):
        c += 1
print(c)
" "$CONFIG" "$scope" 2>/dev/null
}

# --- List users referencing a given scope (one per line) ---
list_users_in_scope() {
    local scope="$1"
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
for u in (d.get('users') or []):
    if target in (u.get('scopes') or []):
        print(u.get('name'))
" "$CONFIG" "$scope" 2>/dev/null
}

# --- Return the scope that currently owns a given canonical CIDR, or empty ---
# Canonical here means input is already normalized (e.g. 10.1.0.0/16, lowercase).
# Matches on canonical ip_network equality — two string variants that canonicalize
# to the same network compare equal. First match wins (scopes are unique by name,
# and the point of this helper is to enforce one-scope-per-prefix).
scope_owning_prefix() {
    local cidr="$1"
    [[ -n "$cidr" ]] || return 0
    python3 - "$CONFIG" "$cidr" <<'PY' 2>/dev/null
import yaml, json, ipaddress, re, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
try:
    target = ipaddress.ip_network(sys.argv[2], strict=False)
except ValueError:
    sys.exit(0)
for s in (d.get('secrets') or []):
    name = s.get('name')
    pfx = (s.get('options') or {}).get('prefixes') or ''
    try:
        arr = json.loads(pfx) if pfx else []
    except Exception:
        arr = re.findall(r'"([^"]+)"', pfx)
    for c in arr:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if n == target:
            print(name)
            sys.exit(0)
PY
}

# --- Reorder secrets: entries globally by prefix specificity ---
# Tacquito walks the secrets: slice in YAML order and returns the first
# provider whose prefix contains the client IP (loader.go:212-220). To get
# "narrowest wins" across scopes, we emit one entry per (scope, prefix) and
# sort every entry by its single prefix's (version, broadcast, network)
# key ascending. v4 before v6; smaller broadcast first (= narrower / more
# specific / subnets above supernets); network address tiebreaks.
#
# Assumes flat form — one prefix per entry (enforced by flatten_secrets_if_needed
# and by the add/set writers). Entries without a parseable prefix sort last.
# Idempotent; no-op when already in order.
reorder_secrets_by_prefix_specificity() {
    python3 - "$CONFIG" <<'PY'
import re, sys, tempfile, os, ipaddress
path = sys.argv[1]
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.exit(0)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)
lead, entries = [], []
for ch in chunks:
    if re.search(r'^  -\s+name:\s*\S+', ch, re.MULTILINE):
        entries.append(ch)
    else:
        lead.append(ch)

SENTINEL = (99, 2**128, 2**128)

def chunk_key(ch):
    pm = re.search(r'prefixes:\s*\|\s*\n\s*\[(.*?)\]', ch, re.DOTALL)
    if not pm:
        return SENTINEL
    cidrs = re.findall(r'"([^"]+)"', pm.group(1))
    # Under flat emission each chunk has exactly one prefix. Take the first
    # if we somehow see more (pre-flatten state): behaves as before (min).
    best = None
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        k = (n.version, int(n.broadcast_address), int(n.network_address))
        if best is None or k < best:
            best = k
    return best if best is not None else SENTINEL

entries.sort(key=chunk_key)
new_body = ''.join(lead) + ''.join(entries)
if new_body == body:
    sys.exit(0)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- One-time migration: flatten multi-prefix entries to one entry per prefix ---
# Any `secrets:` entry with more than one prefix is split into N entries, all
# sharing the original name + secret.key + handler + type + options skeleton,
# each carrying one prefix. After splitting, the global specificity sort is
# applied so the on-disk order matches tacquito's first-match walk.
#
# Called at install-time (after template copy) and upgrade-time. Idempotent.
flatten_secrets_if_needed() {
    python3 - "$CONFIG" <<'PY'
import re, sys, tempfile, os
path = sys.argv[1]
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.exit(0)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)
lead, entries = [], []
for ch in chunks:
    if re.search(r'^  -\s+name:\s*\S+', ch, re.MULTILINE):
        entries.append(ch)
    else:
        lead.append(ch)

def split_entry(ch):
    # Extract the prefix list and the surrounding template.
    pm = re.search(r'(prefixes:\s*\|\s*\n\s*\[)(.*?)(\])', ch, re.DOTALL)
    if not pm:
        return [ch]  # no prefixes block — leave as-is
    cidrs = re.findall(r'"([^"]+)"', pm.group(2))
    if len(cidrs) <= 1:
        return [ch]  # already flat (or empty)
    pre, _, post = ch[:pm.start(2)], pm.group(2), ch[pm.end(3):]
    out = []
    for c in cidrs:
        new_list = f'\n          "{c}"\n        '
        # Reassemble: `prefixes: |\n        [` + new_list + `]` + post
        new_chunk = pre + new_list + pm.group(3) + post
        out.append(new_chunk)
    return out

flat = []
changed = False
for e in entries:
    parts = split_entry(e)
    if len(parts) != 1:
        changed = True
    flat.extend(parts)

if not changed:
    sys.exit(0)

new_body = ''.join(lead) + ''.join(flat)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
    # Apply specificity sort in a second pass; cheap and idempotent.
    reorder_secrets_by_prefix_specificity
}

# --- Write: replace every entry for a scope with one-per-prefix chunks ---
# Flat emission: remove every secrets[] entry whose name matches <scope>,
# then insert a fresh chunk per prefix in <csv>, all sharing the scope's
# existing key + the standard handler/type skeleton. Key is read from the
# first existing entry before deletion. Empty csv deletes the scope from
# the secrets block entirely (callers should gate this via the user-ref
# guard for non-destructive semantics).
set_scope_prefixes() {
    local scope="$1"
    local csv="$2"
    python3 - "$CONFIG" "$scope" "$csv" <<'PY'
import re, sys, tempfile, os, ipaddress
path, scope, csv = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = open(path).read()

raw = [c.strip() for c in csv.split(',') if c.strip()]
nets = []
seen = set()
for c in raw:
    try:
        n = ipaddress.ip_network(c, strict=False)
    except ValueError:
        continue
    if n in seen:
        continue
    seen.add(n)
    nets.append(n)
nets.sort(key=lambda n: (n.version, int(n.broadcast_address), int(n.network_address)))

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.stderr.write("no secrets: block\n")
    sys.exit(1)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)

# Preserve the first matching chunk's key (invariant: all entries for a scope
# share the same key). Also capture lead (non-entry) chunks to keep leading
# whitespace / comments.
existing_key = None
lead, other_entries = [], []
for ch in chunks:
    if re.search(r'^  -\s+name:\s*' + re.escape(scope) + r'\s*$', ch, re.MULTILINE):
        if existing_key is None:
            km = re.search(r'key:\s*"([^"]*)"', ch)
            if km:
                existing_key = km.group(1)
        continue  # drop this chunk
    if re.search(r'^  -\s+name:\s*\S+', ch, re.MULTILINE):
        other_entries.append(ch)
    else:
        lead.append(ch)

if existing_key is None:
    sys.stderr.write(f"scope '{scope}' not found\n")
    sys.exit(1)

def build_entry(name, key, cidr):
    return (
        f'  - name: {name}\n'
        f'    secret:\n'
        f'      group: tacquito\n'
        f'      key: "{key}"\n'
        f'    handler:\n'
        f'      type: *handler_type_start\n'
        f'    type: *provider_type_prefix\n'
        f'    options:\n'
        f'      prefixes: |\n'
        f'        [\n'
        f'          "{cidr}"\n'
        f'        ]\n'
    )

new_entries = [build_entry(scope, existing_key, str(n)) for n in nets]
new_body = ''.join(lead) + ''.join(other_entries) + ''.join(new_entries)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Write: replace shared-secret key on every entry whose name matches ---
# Flat emission spreads one logical scope across N entries; every one of
# them must carry the same key. A single-match update would leave the
# scope's other entries on the old key — auth would then non-deterministically
# succeed or fail depending on which (scope, prefix) entry tacquito matched
# first.
set_scope_secret() {
    local scope="$1"
    local value="$2"
    # Keep the secret off argv AND off the environment — both leak via /proc
    # (cmdline and environ) and via `ps e`. Pass the value through an
    # anonymous pipe via process substitution: /proc/<pid>/cmdline sees only
    # the ephemeral /dev/fd/N path, not the content, and the content is
    # scoped to this python subprocess (no other process inherits it).
    # Stdin stays free for the heredoc that carries the script.
    python3 - "$CONFIG" "$scope" <(printf '%s' "$value") <<'PY'
import re, sys, tempfile, os
path, scope, secret_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(secret_path) as f:
    value = f.read()
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.stderr.write("no secrets: block\n")
    sys.exit(1)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)
updated = 0
for i, ch in enumerate(chunks):
    if re.search(r'^  -\s+name:\s*' + re.escape(scope) + r'\s*$', ch, re.MULTILINE):
        new_ch, n = re.subn(
            r'(key:\s*")[^"]*(")',
            lambda _m: _m.group(1) + value + _m.group(2),
            ch, count=1,
        )
        if n > 0:
            chunks[i] = new_ch
            updated += 1
if updated == 0:
    sys.stderr.write(f"scope '{scope}' not found\n")
    sys.exit(1)

new_body = ''.join(chunks)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Add a new scope to the secrets: list (flat form) ---
# Emits one entry per prefix, all with the same name + key. Entries are
# appended at the end; the caller is expected to run
# reorder_secrets_by_prefix_specificity afterward so the global slice
# order matches the first-match-wins invariant.
add_scope() {
    local name="$1"
    local prefixes_csv="$2"  # canonical + validated by caller
    local secret_key="$3"
    # Secret goes through /dev/fd via process substitution; argv only carries
    # the ephemeral fd path. Protects /proc/<pid>/cmdline from the raw key.
    python3 - "$CONFIG" "$name" "$prefixes_csv" <(printf '%s' "$secret_key") <<'PY'
import re, sys, tempfile, os, ipaddress
path, name, pfx_csv, secret_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(secret_path) as f:
    secret_key = f.read()
cfg = open(path).read()

raw = [c.strip() for c in pfx_csv.split(',') if c.strip()]
nets = []
seen = set()
for c in raw:
    try:
        n = ipaddress.ip_network(c, strict=False)
    except ValueError:
        continue
    if n in seen:
        continue
    seen.add(n)
    nets.append(n)
nets.sort(key=lambda n: (n.version, int(n.broadcast_address), int(n.network_address)))

def build_entry(cidr):
    return (
        f'  - name: {name}\n'
        f'    secret:\n'
        f'      group: tacquito\n'
        f'      key: "{secret_key}"\n'
        f'    handler:\n'
        f'      type: *handler_type_start\n'
        f'    type: *provider_type_prefix\n'
        f'    options:\n'
        f'      prefixes: |\n'
        f'        [\n'
        f'          "{cidr}"\n'
        f'        ]\n'
    )

entry_block = ''.join(build_entry(str(n)) for n in nets)

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    new_cfg = cfg.rstrip() + '\n\nsecrets:\n' + entry_block
else:
    header, body = m.group(1), m.group(2)
    if body.endswith('\n') and not body.endswith('\n\n'):
        new_body = body + entry_block
    else:
        new_body = body.rstrip('\n') + '\n' + entry_block
    new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Delete every entry whose name matches (flat form may span N chunks) ---
remove_scope() {
    local name="$1"
    python3 - "$CONFIG" "$name" <<'PY'
import re, sys, tempfile, os
path, name = sys.argv[1], sys.argv[2]
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.exit(0)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)
new_chunks = []
dropped = 0
for ch in chunks:
    if re.search(r'^  -\s+name:\s*' + re.escape(name) + r'\s*$', ch, re.MULTILINE):
        dropped += 1
        continue
    new_chunks.append(ch)

if dropped == 0:
    sys.stderr.write(f"scope '{name}' not found\n")
    sys.exit(1)

new_body = ''.join(new_chunks)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Rename every matching entry + rewrite every user's scopes: reference ---
# Global re_sub in the secrets block covers all flat chunks that share the
# old name; a single count=1 substitution would leave stragglers behind.
rename_scope() {
    local old_name="$1"
    local new_name="$2"
    python3 - "$CONFIG" "$old_name" "$new_name" <<'PY'
import re, sys, tempfile, os
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.stderr.write("no secrets: block\n")
    sys.exit(1)
header, body = m.group(1), m.group(2)
new_body, n = re.subn(
    r'^(  -\s+name:\s*)' + re.escape(old) + r'(\s*)$',
    r'\g<1>' + new + r'\2',
    body, flags=re.MULTILINE,
)
if n == 0:
    sys.stderr.write(f"scope '{old}' not found\n")
    sys.exit(1)

cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]

# Update every user's scopes: list — only the old name is replaced.
def repl(match):
    inside = match.group(1)
    items = re.findall(r'"([^"]+)"', inside)
    items = [new if it == old else it for it in items]
    return 'scopes: [' + ', '.join(f'"{it}"' for it in items) + ']'
cfg = re.sub(r'scopes:\s*\[([^\]]*)\]', repl, cfg)

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Replace one user's scopes: field with a new CSV ---
set_user_scopes() {
    local username="$1"
    local csv="$2"  # comma-separated scope names; empty wipes to []
    python3 - "$CONFIG" "$username" "$csv" <<'PY'
import re, sys, tempfile, os
path, username, csv = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = open(path).read()

items = [c.strip() for c in csv.split(',') if c.strip()]
new_line = 'scopes: [' + ', '.join(f'"{s}"' for s in items) + ']'

# Find the user entry and replace its scopes: line.
# User entry shape:
#   - name: <username>\n    scopes: [...]\n    groups: [...]\n    ...
# Scope to that user's block before doing the scopes: replace.
pattern = re.compile(
    r'(-\s+name:\s*' + re.escape(username) + r'\s*\n(?:\s+[^\n]*\n)*?\s+)scopes:\s*\[[^\]]*\]',
)
new_cfg, n = pattern.subn(r'\1' + new_line.replace('\\', r'\\'), cfg, count=1)
if n == 0:
    # User exists but has no scopes: field — insert one immediately after `- name:`
    ins_pattern = re.compile(r'(-\s+name:\s*' + re.escape(username) + r'\s*\n)(\s+)')
    im = ins_pattern.search(cfg)
    if not im:
        sys.stderr.write(f"user '{username}' not found\n")
        sys.exit(1)
    indent = im.group(2)
    new_cfg = cfg[:im.end(1)] + indent + new_line + '\n' + cfg[im.end(2):]

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- CONFIG ALLOW/DENY PREFIX FILTERS ---
cmd_config_prefix_filter() {
    local key="$1"
    local subcmd="${2:-}"
    local cidr="${3:-}"
    local label
    [[ "$key" == "prefix_allow" ]] && label="allow" || label="deny"

    case "$subcmd" in
        ""|-h|--help|help)
            local entries
            entries=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^' + sys.argv[2] + r':\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    print(len(re.findall(r'\"([^\"]+)\"', m.group(1))))
else:
    print(0)
" "$CONFIG" "$key" 2>/dev/null || echo 0)
            echo ""
            echo -e "${BOLD}tacctl config ${label}${NC} — connection IP ACL (${label} list)"
            echo ""
            echo "Usage:"
            echo "  tacctl config ${label} list                          Show current ${label} list"
            echo "  tacctl config ${label} add    <cidr>[,<cidr>...]     Add one or more CIDRs"
            echo "  tacctl config ${label} remove <cidr>[,<cidr>...]     Remove one or more CIDRs"
            echo "  tacctl config ${label} clear                         Wipe all (confirms)"
            echo ""
            echo "Current entries: ${entries}"
            echo "Note: 'deny' takes precedence over 'allow'. Both empty = all connections accepted."
            echo ""
            return
            ;;
        list)
            echo ""
            echo -e "${BOLD}Connection ${label} list${NC}"
            echo "--------------------------------------------"
            local entries
            entries=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^' + sys.argv[2] + r':\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    for c in re.findall(r'\"([^\"]+)\"', m.group(1)):
        print(c)
else:
    print('EMPTY')
" "$CONFIG" "$key" || true)
            if [[ "$entries" == "EMPTY" ]]; then
                if [[ "$label" == "allow" ]]; then
                    echo "  (empty — all connections allowed)"
                else
                    echo "  (empty — no connections denied)"
                fi
            else
                echo "$entries" | while IFS= read -r entry; do
                    echo "  - ${entry}"
                done
            fi
            echo ""
            echo -e "  ${CYAN}Note: deny takes precedence over allow.${NC}"
            echo ""
            ;;
        add)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config ${label} add <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested added="" skipped=""
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(read_prefix_list "$key")
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    skipped+="${skipped:+ }${c}"
                else
                    added+="${added:+$'\n'}${c}"
                    current=$(printf '%s\n%s\n' "$current" "$c")
                fi
            done <<< "$requested"
            if [[ -z "$added" ]]; then
                info "No new CIDRs to add to ${label} list (already present: ${skipped})."
                echo ""
                return
            fi
            backup_config
            write_prefix_list "$key" "$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            local n
            n=$(printf '%s\n' "$added" | wc -l)
            info "Added ${n} to ${label} list: $(printf '%s\n' "$added" | paste -sd' ')"
            [[ -n "$skipped" ]] && info "(Already present, unchanged: ${skipped})"
            echo ""
            ;;
        remove)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config ${label} remove <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested removed="" missing=""
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(read_prefix_list "$key")
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    removed+="${removed:+$'\n'}${c}"
                    current=$(printf '%s\n' "$current" | grep -vxF "$c" || true)
                else
                    missing+="${missing:+ }${c}"
                fi
            done <<< "$requested"
            if [[ -z "$removed" ]]; then
                warn "Nothing to remove from ${label} list (not present: ${missing})."
                exit 0
            fi
            backup_config
            write_prefix_list "$key" "$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            local n
            n=$(printf '%s\n' "$removed" | wc -l)
            info "Removed ${n} from ${label} list: $(printf '%s\n' "$removed" | paste -sd' ')"
            [[ -n "$missing" ]] && info "(Not present, skipped: ${missing})"
            echo ""
            ;;
        clear)
            local current n
            current=$(read_prefix_list "$key")
            if [[ -z "$current" ]]; then
                info "${label} list is already empty."
                return
            fi
            n=$(printf '%s\n' "$current" | wc -l)
            # Clearing either list removes a restriction — be explicit
            # about what the resulting posture is.
            if [[ "$label" == "allow" ]]; then
                warn "Clearing the allow list fails open: all source IPs become eligible"
                warn "to connect (subject to 'deny' and the secret-provider prefixes)."
            else
                warn "Clearing the deny list removes all per-IP deny overrides;"
                warn "any source matching 'allow' (or all, if allow is empty) can connect."
            fi
            read -rp "  Clear all ${n} ${label}-list entr$( [[ $n -eq 1 ]] && echo "y" || echo "ies" )? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            backup_config
            write_prefix_list "$key" ""
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Cleared ${label} list (${n} entr$( [[ $n -eq 1 ]] && echo "y" || echo "ies" ) removed)."
            echo ""
            ;;
        *)
            echo ""
            echo "Usage: tacctl config ${label} <list|add|remove|clear> [cidr[,cidr...]]"
            echo ""
            exit 1
            ;;
    esac
}

# --- Read a prefix_allow / prefix_deny inline list (canonical CIDR per line) ---
read_prefix_list() {
    local key="$1"
    python3 -c "
import ipaddress, re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^' + sys.argv[2] + r':\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    for c in re.findall(r'\"([^\"]+)\"', m.group(1)):
        try:
            print(ipaddress.ip_network(c, strict=False))
        except ValueError:
            print(c)
" "$CONFIG" "$key"
}

# --- Write/replace a prefix_allow / prefix_deny inline list ---
# csv may be empty — in that case the key line is removed entirely.
# Entries are canonicalized and sorted by specificity (most-specific
# prefix first) before being emitted, matching the storage convention
# used by set_scope_prefixes.
write_prefix_list() {
    local key="$1"
    local csv="$2"
    python3 -c "
import ipaddress, re, sys, tempfile, os
config = open(sys.argv[1]).read()
key = sys.argv[2]
raw = [c.strip() for c in sys.argv[3].split(',') if c.strip()]
# Canonicalize + sort by specificity
def key_fn(c):
    n = ipaddress.ip_network(c, strict=False)
    # Primary: version (v4 before v6). Secondary: broadcast address
    # ascending — disjoint ranges sort by end-of-range, and overlapping
    # subnets naturally fall just above their supernet (the subnet
    # ends earlier than the range containing it). Tertiary: network
    # address, for determinism across same-end-address edge cases.
    return (n.version, int(n.broadcast_address), int(n.network_address))
entries = []
for c in raw:
    try:
        entries.append(str(ipaddress.ip_network(c, strict=False)))
    except ValueError:
        pass
entries = sorted(set(entries), key=key_fn)
m = re.search(r'^' + key + r':\s*\[(.*?)\]', config, re.MULTILINE)
if entries:
    new_val = ', '.join('\"' + e + '\"' for e in entries)
    new_line = key + ': [' + new_val + ']'
    if m:
        config = config.replace(m.group(0), new_line)
    else:
        config = config.rstrip() + '\n\n' + new_line + '\n'
else:
    if m:
        config = config.replace(m.group(0) + '\n', '')
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
" "$CONFIG" "$key" "$csv"
}

# =====================================================================
#  SCOPE COMMANDS (tacctl scope ...)
# =====================================================================

cmd_scope() {
    local subcmd="${1:-}"
    shift 2>/dev/null || true
    case "$subcmd" in
        ""|-h|--help|help) cmd_scope_usage ;;
        list)              cmd_scope_list ;;
        routing)           cmd_scope_routing ;;
        show)              cmd_scope_show "$@" ;;
        add)               cmd_scope_add "$@" ;;
        remove)            cmd_scope_remove "$@" ;;
        rename)            cmd_scope_rename "$@" ;;
        default)           cmd_scope_default "$@" ;;
        lookup)            cmd_scope_lookup "$@" ;;
        prefixes)          cmd_scope_prefixes_dispatch "$@" ;;
        secret)            cmd_scope_secret_dispatch "$@" ;;
        aaa-order)         cmd_scope_aaa_order "$@" ;;
        exec-timeout)      cmd_scope_exec_timeout "$@" ;;
        tacacs-group)      cmd_scope_tacacs_group "$@" ;;
        mgmt-acl)          cmd_scope_mgmt_acl "$@" ;;
        *)
            error "Unknown subcommand: '${subcmd}'"
            cmd_scope_usage
            exit 1
            ;;
    esac
}

cmd_scope_usage() {
    local count=0 default_val
    count=$(list_scopes | wc -l)
    default_val=$(read_default_scope)
    echo ""
    echo -e "${BOLD}tacctl scope${NC} — named (CIDR-prefixes, shared-secret) bundles"
    echo ""
    echo "Usage:"
    echo "  tacctl scope list                                        One row per scope (aggregated prefix list)"
    echo "  tacctl scope routing                                     One row per (scope, prefix) — first-match order"
    echo "  tacctl scope show <name>                                 Detailed view"
    echo "  tacctl scope add <name> --prefixes <cidrs>               Create a new scope"
    echo "                       [--secret <value>|--secret generate]"
    echo "                       [--default]"
    echo "  tacctl scope remove <name> [--force]                     Delete a scope (confirms)"
    echo "  tacctl scope rename <old> <new>                          Rename (updates user references)"
    echo "  tacctl scope default [<name>]                            Show or set the default scope"
    echo "  tacctl scope lookup <ip|cidr>                            Show which scope owns an address"
    echo ""
    echo "  tacctl scope prefixes <scope> list|add|remove|clear      Manage a scope's CIDR list"
    echo "  tacctl scope secret   <scope> show|set|generate          Manage a scope's shared secret"
    echo "  tacctl scope aaa-order <scope> [tacacs-first|local-first] AAA method-list order in this scope's rendered device configs (default tacacs-first)"
    echo "  tacctl scope exec-timeout <scope> [minutes]              Per-scope idle-session timeout in rendered device configs (0..60 min; default 60; 0 = never expire)"
    echo "  tacctl scope tacacs-group <scope> [name]                 Per-scope Cisco aaa-group-server label (default TACACS-GROUP)"
    echo "  tacctl scope mgmt-acl <scope> list|add|remove|clear      Per-scope permit list (fallback: global mgmt_acl.permits)"
    echo "  tacctl scope mgmt-acl <scope> cisco-name|juniper-name [name]  Per-scope ACL / filter name (defaults VTY-ACL / MGMT-ACL)"
    echo ""
    echo "Current scopes: ${count}"
    echo "Default scope:  ${default_val:-<unset>}"
    echo ""
}

cmd_scope_list() {
    echo ""
    echo -e "${BOLD}Scopes${NC} ${CYAN}(one block per scope; see 'tacctl scope routing' for first-match prefix order)${NC}"
    echo "--------------------------------------------------------------"
    local default_val
    default_val=$(read_default_scope)
    # One block per scope. First prefix sits on the scope's summary
    # row (name / users / default marker); subsequent prefixes indent
    # under the PREFIXES column so the list reads top-to-bottom as
    # "this scope owns these CIDRs". Detailed first-match resolution
    # order is `tacctl scope routing`; per-scope secret + knobs land
    # in `tacctl scope show <name>`.
    local rows
    rows=$(python3 -c "
import ipaddress, json, re, sys, yaml
cfg_path = sys.argv[1]
default_val = sys.argv[2]
with open(cfg_path) as f:
    d = yaml.safe_load(f) or {}
ucount = {}
for u in (d.get('users') or []):
    for s in (u.get('scopes') or []):
        ucount[s] = ucount.get(s, 0) + 1
prefixes = {}
order = []
for s in (d.get('secrets') or []):
    name = s.get('name') or '(unnamed)'
    pfx = (s.get('options') or {}).get('prefixes') or ''
    try:
        arr = json.loads(pfx) if pfx else []
    except Exception:
        arr = re.findall(r'\"([^\"]+)\"', pfx)
    if name not in prefixes:
        prefixes[name] = []
        order.append(name)
    for cidr in arr:
        if cidr not in prefixes[name]:
            prefixes[name].append(cidr)

def spec_key(cidr):
    # Specificity-first sort: prefix length DESC (narrower = more
    # specific first) with network-address ASC as tie-break among
    # equal-length prefixes. Matches the most-specific-wins routing
    # semantic tacquito applies to any given client IP.
    try:
        n = ipaddress.ip_network(cidr, strict=False)
        return (-n.prefixlen, n.version, int(n.network_address))
    except ValueError:
        return (1, 0, 0)

# Emit one line per (scope, prefix) pair, '|'-separated. First row
# per scope carries users + default; continuation rows leave those
# columns empty. Within each scope the prefixes are sorted by
# specificity (narrower first) so the block mirrors how operators
# think about overlap. Using '|' (not \t) because bash's read -r
# with IFS=\t strips leading tabs when reassembling empty fields.
for name in order:
    pfx_list = sorted(prefixes[name] or ['(no prefix)'], key=spec_key)
    is_default = 'yes' if name == default_val else ''
    for idx, cidr in enumerate(pfx_list):
        if idx == 0:
            print(f'{name}|{cidr}|{ucount.get(name, 0)}|{is_default}')
        else:
            print(f'|{cidr}||')
" "$CONFIG" "$default_val" 2>/dev/null)

    if [[ -z "$rows" ]]; then
        echo "  (no scopes configured)"
        echo ""
        return
    fi

    printf "  ${BOLD}%-18s %-20s %5s  %s${NC}\n" "NAME" "PREFIXES" "USERS" "DEFAULT"
    echo "  --------------------------------------------------------------"
    while IFS='|' read -r name cidr users is_default; do
        if [[ -z "$name" ]]; then
            # Continuation row — blank NAME column, prefix only.
            [[ -z "$cidr" ]] && continue
            printf "  %-18s %-20s\n" "" "$cidr"
            continue
        fi
        local dfl=""
        [[ "$is_default" == "yes" ]] && dfl="${CYAN}yes${NC}"
        printf "  ${BOLD}%-18s${NC} %-20s %5s  %b\n" "$name" "$cidr" "$users" "$dfl"
    done <<< "$rows"
    echo ""
}

# --- tacctl scope routing — the old per-(scope, prefix) view ---
# Surfaces the tacquito first-match walk order for operator debugging:
# each row is one secrets[] slot as tacquito sees it. Multi-prefix
# scopes repeat their name so the display literally mirrors how a
# connecting client gets routed. `tacctl scope list` is the dedup'd
# per-scope view for day-to-day work.
cmd_scope_routing() {
    echo ""
    echo -e "${BOLD}Scope routing${NC} ${CYAN}(tacquito first-match order — narrower prefixes win)${NC}"
    echo "--------------------------------------------------------------"
    local default_val
    default_val=$(read_default_scope)
    local rows
    rows=$(python3 -c "
import ipaddress, json, re, sys, yaml
cfg_path = sys.argv[1]
default_val = sys.argv[2]
with open(cfg_path) as f:
    d = yaml.safe_load(f) or {}
ucount = {}
for u in (d.get('users') or []):
    for s in (u.get('scopes') or []):
        ucount[s] = ucount.get(s, 0) + 1
# Collect every (scope, prefix) pair and sort specificity-first:
# prefix length DESC so the most-specific row lands at the top
# (matches tacquito's most-specific-wins routing), with
# network-address ASC as tie-break. Entries with an unparseable
# prefix (rare, malformed YAML) sort to the end.
pairs = []
for s in (d.get('secrets') or []):
    name = s.get('name') or '(unnamed)'
    pfx = (s.get('options') or {}).get('prefixes') or ''
    try:
        arr = json.loads(pfx) if pfx else []
    except Exception:
        arr = re.findall(r'\"([^\"]+)\"', pfx)
    if not arr:
        arr = ['(no prefix)']
    for cidr in arr:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            sort_key = (-net.prefixlen, net.version, int(net.network_address))
        except ValueError:
            sort_key = (1, 0, 0)  # sink unparseable to the end
        pairs.append((sort_key, name, cidr))
pairs.sort(key=lambda x: x[0])
for _, name, cidr in pairs:
    is_default = 'yes' if name == default_val else ''
    print(f'{name}|{cidr}|{ucount.get(name, 0)}|{is_default}')
" "$CONFIG" "$default_val" 2>/dev/null)

    if [[ -z "$rows" ]]; then
        echo "  (no scopes configured)"
        echo ""
        return
    fi

    printf "  ${BOLD}%3s  %-18s %-20s %5s  %s${NC}\n" "#" "NAME" "PREFIX" "USERS" "DEFAULT"
    echo "  --------------------------------------------------------------"
    local i=0
    while IFS='|' read -r name cidr users is_default; do
        [[ -z "$name" ]] && continue
        i=$((i + 1))
        local dfl=""
        [[ "$is_default" == "yes" ]] && dfl="${CYAN}yes${NC}"
        printf "  %3d  ${BOLD}%-18s${NC} %-20s %5s  %b\n" "$i" "$name" "$cidr" "$users" "$dfl"
    done <<< "$rows"
    echo ""
}

cmd_scope_show() {
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        error "Usage: tacctl scope show <name>"
        exit 1
    fi
    if ! scope_exists "$name"; then
        error "Scope '${name}' does not exist."
        exit 1
    fi
    local secret_val secret_len secret_line
    secret_val=$(read_scope_secret "$name")
    secret_len=${#secret_val}
    if [[ -z "$secret_val" ]]; then
        secret_line="${RED}(unset)${NC}"
    elif [[ "$secret_val" == *REPLACE* ]]; then
        secret_line="${secret_val}  ${RED}(PLACEHOLDER — run 'tacctl scope secret ${name} generate')${NC}"
    elif [[ "$secret_len" -lt "$SECRET_MIN_LENGTH" ]]; then
        secret_line="${secret_val}  ${RED}(${secret_len} chars, below min ${SECRET_MIN_LENGTH})${NC}"
    else
        secret_line="${secret_val}  ${GREEN}(${secret_len} chars)${NC}"
    fi
    local default_val
    default_val=$(read_default_scope)
    local is_default="no"
    [[ "$name" == "$default_val" ]] && is_default="yes"
    # Per-scope device-render knobs. Absence of an override falls back
    # through the per-scope -> global -> shipped-default chain,
    # matching what `tacctl config cisco|juniper --scope <name>` emits.
    local aaa_order_val exec_timeout_val exec_timeout_display tacacs_group_val cisco_acl_val juniper_acl_val
    aaa_order_val=$(conf_get "aaa.order.${name}" tacacs-first)
    exec_timeout_val=$(conf_get "exec_timeout.${name}" 60)
    tacacs_group_val=$(conf_get "tacacs_group.${name}" TACACS-GROUP)
    cisco_acl_val=$(read_mgmt_acl_name cisco "$name")
    juniper_acl_val=$(read_mgmt_acl_name juniper "$name")
    if [[ "$exec_timeout_val" == "0" ]]; then
        exec_timeout_display="0 min (never expire)"
    else
        exec_timeout_display="${exec_timeout_val} min"
    fi

    echo ""
    echo -e "${BOLD}Scope:${NC} ${name}"
    echo "--------------------------------------------"
    echo -e "  ${BOLD}Default:${NC}       ${is_default}"
    echo -e "  ${BOLD}Secret:${NC}        ${secret_line}"
    echo -e "  ${BOLD}AAA order:${NC}     ${aaa_order_val}"
    echo -e "  ${BOLD}Exec timeout:${NC}  ${exec_timeout_display}"
    echo -e "  ${BOLD}TACACS group:${NC}  ${tacacs_group_val}"
    echo -e "  ${BOLD}Cisco ACL:${NC}     ${cisco_acl_val}"
    echo -e "  ${BOLD}Juniper ACL:${NC}   ${juniper_acl_val}"
    echo -e "  ${BOLD}Prefixes:${NC}"
    local pfx
    pfx=$(read_scope_prefixes "$name")
    if [[ -z "$pfx" ]]; then
        echo "    (none — no clients can match this scope)"
    else
        echo "$pfx" | while IFS= read -r c; do
            [[ -z "$c" ]] && continue
            echo "    - ${c}"
        done
    fi
    echo -e "  ${BOLD}Users:${NC}"
    local users
    users=$(list_users_in_scope "$name")
    if [[ -z "$users" ]]; then
        echo "    (none)"
    else
        echo "$users" | while IFS= read -r u; do
            echo "    - ${u}"
        done
    fi
    echo ""
}

cmd_scope_add() {
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        error "Usage: tacctl scope add <name> --prefixes <cidrs> [--secret <value>|generate] [--default]"
        exit 1
    fi
    shift
    if ! [[ "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,31}$ ]]; then
        error "Invalid scope name '${name}'. Use letters/digits/_-, starting with a letter."
        exit 1
    fi
    if scope_exists "$name"; then
        error "Scope '${name}' already exists."
        exit 1
    fi

    local prefixes="" secret_arg="" make_default="false"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --prefixes) prefixes="${2:-}"; shift 2 ;;
            --secret)   secret_arg="${2:-}"; shift 2 ;;
            --default)  make_default="true"; shift ;;
            *) error "Unknown flag: '$1'"; exit 1 ;;
        esac
    done

    if [[ -z "$prefixes" ]]; then
        error "--prefixes <cidrs> is required (comma-separated list)."
        exit 1
    fi
    local canon
    canon=$(parse_cidr_list "$prefixes")
    [[ -z "$canon" ]] && { error "No valid CIDRs in --prefixes."; exit 1; }

    # One-scope-per-prefix invariant: every CIDR must belong to exactly one
    # scope, otherwise tacquito's first-match-wins selector makes the losing
    # scope's users silently unable to auth from that device. Abort before
    # writing anything.
    local collisions=""
    while IFS= read -r c; do
        [[ -z "$c" ]] && continue
        local owner
        owner=$(scope_owning_prefix "$c")
        if [[ -n "$owner" ]]; then
            collisions+="${collisions:+$'\n'}    - ${c}  (already in scope '${owner}')"
        fi
    done <<< "$canon"
    if [[ -n "$collisions" ]]; then
        error "Cannot create scope '${name}': prefix(es) already claimed:"
        while IFS= read -r line; do error "$line"; done <<< "$collisions"
        error "Each CIDR belongs to exactly one scope. Remove it from the owning"
        error "scope first with 'tacctl scope prefixes <owner> remove <cidr>'."
        exit 1
    fi

    local csv
    csv=$(printf '%s\n' "$canon" | paste -sd,)

    local secret_value=""
    if [[ -z "$secret_arg" || "$secret_arg" == "generate" ]]; then
        secret_value=$(openssl rand -base64 24)
        info "Generated secret: ${BOLD}${secret_value}${NC}"
    else
        secret_value="$secret_arg"
        if [[ "${#secret_value}" -lt "$SECRET_MIN_LENGTH" ]]; then
            error "Secret is ${#secret_value} characters; minimum is ${SECRET_MIN_LENGTH}."
            exit 1
        fi
    fi

    backup_config
    add_scope "$name" "$csv" "$secret_value"
    reorder_secrets_by_prefix_specificity
    chown tacquito:tacquito "$CONFIG"

    if [[ "$make_default" == "true" ]]; then
        write_default_scope "$name"
        info "Scope '${name}' added and set as default."
    else
        info "Scope '${name}' added."
    fi
    restart_service
    echo ""
}

cmd_scope_remove() {
    local name="${1:-}" force="false"
    if [[ -z "$name" ]]; then
        error "Usage: tacctl scope remove <name> [--force]"
        exit 1
    fi
    shift 2>/dev/null || true
    [[ "${1:-}" == "--force" ]] && force="true"

    if ! scope_exists "$name"; then
        error "Scope '${name}' does not exist."
        exit 1
    fi

    local user_count
    user_count=$(count_users_in_scope "$name")
    if [[ "$user_count" -gt 0 && "$force" != "true" ]]; then
        error "Cannot remove '${name}': ${user_count} user(s) still reference it."
        error "Remove them first:"
        list_users_in_scope "$name" | sed 's/^/    tacctl user scope /' | sed 's/$/ remove '"${name}"'/'
        error "Or pass --force to strip the scope from those users AND delete it."
        exit 1
    fi

    local default_val
    default_val=$(read_default_scope)
    if [[ "$name" == "$default_val" ]]; then
        error "Cannot remove '${name}': it is the default scope."
        error "Point the default at another scope first: tacctl scope default <other>"
        exit 1
    fi

    warn "About to remove scope '${name}'."
    [[ "$user_count" -gt 0 ]] && warn "This will also strip '${name}' from ${user_count} user(s)."
    read -rp "  Confirm removal? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        info "Aborted."
        return
    fi

    backup_config

    # Strip the scope from any users still referencing it.
    if [[ "$user_count" -gt 0 ]]; then
        while IFS= read -r u; do
            [[ -z "$u" ]] && continue
            local current
            current=$(read_user_scopes "$u" | grep -vxF "$name" | paste -sd,)
            set_user_scopes "$u" "$current"
        done < <(list_users_in_scope "$name")
    fi

    remove_scope "$name"
    reorder_secrets_by_prefix_specificity
    chown tacquito:tacquito "$CONFIG"
    restart_service
    info "Scope '${name}' removed."
    echo ""
}

cmd_scope_rename() {
    local old="${1:-}" new="${2:-}"
    if [[ -z "$old" || -z "$new" ]]; then
        error "Usage: tacctl scope rename <old> <new>"
        exit 1
    fi
    if ! scope_exists "$old"; then
        error "Scope '${old}' does not exist."
        exit 1
    fi
    if scope_exists "$new"; then
        error "Scope '${new}' already exists."
        exit 1
    fi
    if ! [[ "$new" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,31}$ ]]; then
        error "Invalid new name '${new}'."
        exit 1
    fi
    backup_config
    rename_scope "$old" "$new"
    reorder_secrets_by_prefix_specificity
    # Update scope.default if it pointed at the old name.
    local default_val
    default_val=$(conf_get scope.default)
    if [[ "$default_val" == "$old" ]]; then
        write_default_scope "$new"
        info "Default-scope marker updated: ${old} -> ${new}"
    fi
    chown tacquito:tacquito "$CONFIG"
    restart_service
    local user_count
    user_count=$(count_users_in_scope "$new")
    info "Scope renamed: ${old} -> ${new} (${user_count} user(s) updated)."
    echo ""
}

cmd_scope_default() {
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        local current
        current=$(read_default_scope)
        echo ""
        if [[ -z "$current" ]]; then
            echo "  No default scope set (no scopes configured yet?)."
        else
            echo "  Default scope: ${current}"
        fi
        echo ""
        echo "  Usage: tacctl scope default <name>    # set default to <name>"
        echo "  The default scope is used when:"
        echo "    - 'tacctl user add <u> <g>' is run without --scopes"
        echo "    - 'tacctl config cisco/juniper' is run without --scope"
        echo ""
        return
    fi
    if ! scope_exists "$name"; then
        error "Scope '${name}' does not exist."
        exit 1
    fi
    write_default_scope "$name"
    info "Default scope set to '${name}'."
    echo ""
}

# --- Resolve an IP or CIDR to the scope that would own it ---
# Matches tacquito's selection logic: walks the live secrets[] list in
# slice order (specificity-sorted) and returns the first scope whose
# prefix contains the query. Emits the owning scope name, the matching
# prefix, and (when the query is an IP inside a broader covering supernet)
# any additional scopes whose prefixes also contain the address — handy
# when debugging unexpected auth routing.
cmd_scope_lookup() {
    local query="${1:-}"
    if [[ -z "$query" ]]; then
        error "Usage: tacctl scope lookup <ip|cidr>"
        error "Examples:"
        error "  tacctl scope lookup 10.5.1.2"
        error "  tacctl scope lookup 10.5.0.0/16"
        exit 1
    fi
    python3 - "$CONFIG" "$query" <<'PY'
import yaml, json, ipaddress, re, sys
path, query = sys.argv[1], sys.argv[2]

# Parse query as either a single address or a CIDR network.
q_net = None
q_host = None
try:
    if '/' in query:
        q_net = ipaddress.ip_network(query, strict=False)
    else:
        q_host = ipaddress.ip_address(query)
except ValueError as e:
    print(f"ERROR: invalid address or CIDR: {e}")
    sys.exit(2)

with open(path) as f:
    d = yaml.safe_load(f) or {}

# Walk secrets[] in YAML slice order (= tacquito's match order).
matches = []  # list of (scope_name, prefix_net) in iteration order
for s in (d.get('secrets') or []):
    name = s.get('name')
    pfx = (s.get('options') or {}).get('prefixes') or ''
    try:
        arr = json.loads(pfx) if pfx else []
    except Exception:
        arr = re.findall(r'"([^"]+)"', pfx)
    for c in arr:
        try:
            pnet = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        # For IP queries: match if the prefix contains the host.
        # For CIDR queries: match if the prefix equals or strictly contains
        # the query (i.e. the query is within the scope's address space).
        if q_host is not None and q_host in pnet:
            matches.append((name, pnet))
        elif q_net is not None and (pnet == q_net or q_net.subnet_of(pnet)):
            matches.append((name, pnet))

if not matches:
    if q_host is not None:
        print(f"No scope owns {q_host} — no prefix in any scope contains it.")
    else:
        print(f"No scope owns {q_net} — no prefix covers the full range.")
    sys.exit(1)

# Winner: first match in slice order (matches tacquito's selector).
winner_scope, winner_pfx = matches[0]
if q_host is not None:
    print(f"  {q_host} -> scope '{winner_scope}' (via prefix {winner_pfx})")
else:
    print(f"  {q_net} -> scope '{winner_scope}' (via prefix {winner_pfx})")

# If multiple prefixes cover the query (overlapping supernets across scopes),
# show the shadow — operators often want to confirm that tacquito would
# actually pick the scope they expect.
if len(matches) > 1:
    print("")
    print("  Also covered by (shadowed — tacquito's first-match picks the one above):")
    for name, pnet in matches[1:]:
        print(f"    - scope '{name}' via prefix {pnet}")
PY
}

# --- Per-scope prefix management: tacctl scope prefixes <scope> ... ---
cmd_scope_prefixes_dispatch() {
    local scope="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"
    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope prefixes <scope> {list|add|remove|clear} [<cidrs>]"
        exit 1
    fi
    if ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist."
        exit 1
    fi
    case "$sub" in
        ""|-h|--help|help)
            local count=0
            count=$(read_scope_prefixes "$scope" | wc -l)
            echo ""
            echo -e "${BOLD}tacctl scope prefixes ${scope}${NC} — CIDR prefix list for scope '${scope}'"
            echo ""
            echo "Usage:"
            echo "  tacctl scope prefixes ${scope} list                        Show entries"
            echo "  tacctl scope prefixes ${scope} add    <cidr>[,<cidr>...]   Add one or more"
            echo "  tacctl scope prefixes ${scope} remove <cidr>[,<cidr>...]   Remove one or more"
            echo "  tacctl scope prefixes ${scope} clear [--force]             Wipe all (confirms; --force proceeds when users still reference)"
            echo ""
            echo "Current entries: ${count}"
            echo ""
            ;;
        list)
            echo ""
            echo -e "${BOLD}Prefixes for scope '${scope}'${NC}"
            echo "--------------------------------------------"
            local entries
            entries=$(read_scope_prefixes "$scope")
            if [[ -z "$entries" ]]; then
                echo "  (empty — no clients can match this scope)"
            else
                echo "$entries" | while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    echo "  - ${c}"
                done
            fi
            echo ""
            ;;
        add|remove)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope prefixes ${scope} ${sub} <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested
            requested=$(parse_cidr_list "$arg")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(read_scope_prefixes "$scope")
            local changed="" missing_or_present=""
            if [[ "$sub" == "add" ]]; then
                # Cross-scope collision check BEFORE any mutation. A CIDR owned
                # by another scope can't be silently stolen — operator must
                # remove it from the owning scope first.
                local collisions=""
                while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    local owner
                    owner=$(scope_owning_prefix "$c")
                    if [[ -n "$owner" && "$owner" != "$scope" ]]; then
                        collisions+="${collisions:+$'\n'}    - ${c}  (already in scope '${owner}')"
                    fi
                done <<< "$requested"
                if [[ -n "$collisions" ]]; then
                    error "Cannot add prefix(es) to scope '${scope}':"
                    while IFS= read -r line; do error "$line"; done <<< "$collisions"
                    error "Remove them from the owning scope first:"
                    error "  tacctl scope prefixes <owner> remove <cidr>"
                    exit 1
                fi
                while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF "$c"; then
                        missing_or_present+="${missing_or_present:+ }${c}"
                    else
                        changed+="${changed:+$'\n'}${c}"
                        current=$(printf '%s\n%s\n' "$current" "$c")
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { info "No new CIDRs (already present in '${scope}': ${missing_or_present})."; echo ""; return; }
            else
                while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF "$c"; then
                        changed+="${changed:+$'\n'}${c}"
                        current=$(printf '%s\n' "$current" | grep -vxF "$c" || true)
                    else
                        missing_or_present+="${missing_or_present:+ }${c}"
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { warn "Nothing to remove (not present: ${missing_or_present})."; exit 0; }
            fi
            backup_config
            set_scope_prefixes "$scope" "$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)"
            reorder_secrets_by_prefix_specificity
            chown tacquito:tacquito "$CONFIG"
            restart_service
            local n
            n=$(printf '%s\n' "$changed" | wc -l)
            local verb="Added"; [[ "$sub" == "remove" ]] && verb="Removed"
            info "${verb} ${n} prefix(es) for scope '${scope}': $(printf '%s\n' "$changed" | paste -sd' ')"
            [[ -n "$missing_or_present" ]] && info "(Skipped: ${missing_or_present})"
            echo ""
            ;;
        clear)
            # Flat emission: clearing all prefixes removes every entry for
            # this scope from secrets[]; the scope vanishes from YAML and
            # any users with it in their scopes[] become orphans. Mirror
            # the scopes-remove guard: refuse when users reference the
            # scope unless --force is given.
            local force="false"
            [[ "$arg" == "--force" ]] && force="true"
            local cur
            cur=$(read_scope_prefixes "$scope")
            if [[ -z "$cur" ]]; then
                info "Scope '${scope}' prefix list is already empty."
                return
            fi
            local user_count
            user_count=$(count_users_in_scope "$scope")
            if [[ "$user_count" -gt 0 && "$force" != "true" ]]; then
                error "Cannot clear prefixes for '${scope}': ${user_count} user(s) still reference it."
                error "Clearing every prefix removes the scope from the secrets list"
                error "and leaves those users with orphan scope references."
                error "Detach users first:"
                list_users_in_scope "$scope" | sed 's/^/    tacctl user scope /' | sed 's/$/ remove '"${scope}"'/'
                error "Or pass --force to proceed and leave orphan refs (use 'tacctl config validate' to find them)."
                exit 1
            fi
            local n
            n=$(printf '%s\n' "$cur" | wc -l)
            warn "Clearing all ${n} prefix(es) from '${scope}' removes it from tacquito.yaml."
            if [[ "$user_count" -gt 0 ]]; then
                warn "${user_count} user(s) will have orphan refs to '${scope}' after this."
            fi
            read -rp "  Confirm? [y/N]: " confirm
            [[ ! "$confirm" =~ ^[Yy] ]] && { info "Aborted."; return; }
            backup_config
            set_scope_prefixes "$scope" ""
            reorder_secrets_by_prefix_specificity
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Cleared prefixes for scope '${scope}'."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl scope prefixes ${scope}' for usage."
            exit 1
            ;;
    esac
}

# --- Per-scope secret management: tacctl scope secret <scope> ... ---
cmd_scope_secret_dispatch() {
    local scope="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"
    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope secret <scope> {show|set <value>|generate}"
        exit 1
    fi
    if ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist."
        exit 1
    fi
    case "$sub" in
        ""|-h|--help|help)
            local s_len=0
            local cur
            cur=$(read_scope_secret "$scope")
            s_len=${#cur}
            echo ""
            echo -e "${BOLD}tacctl scope secret ${scope}${NC} — shared secret for scope '${scope}'"
            echo ""
            echo "Usage:"
            echo "  tacctl scope secret ${scope} show                Print raw value + length/posture"
            echo "  tacctl scope secret ${scope} set <value>         Set to <value> (validated)"
            echo "  tacctl scope secret ${scope} generate            Auto-generate + apply"
            echo ""
            echo "Current length: ${s_len} chars (min ${SECRET_MIN_LENGTH})"
            echo ""
            ;;
        show)
            local cur s_len
            cur=$(read_scope_secret "$scope")
            s_len=${#cur}
            echo ""
            echo -e "${BOLD}Scope '${scope}' — shared secret${NC}"
            echo "--------------------------------------------"
            if [[ -z "$cur" ]]; then
                echo -e "  ${RED}(unset)${NC}"
            elif [[ "$cur" == *REPLACE* ]]; then
                echo -e "  Value:  ${BOLD}${cur}${NC}"
                echo -e "  ${RED}Length: ${s_len} chars — PLACEHOLDER (run 'tacctl scope secret ${scope} generate')${NC}"
            elif [[ "$s_len" -lt "$SECRET_MIN_LENGTH" ]]; then
                echo -e "  Value:  ${BOLD}${cur}${NC}"
                echo -e "  ${RED}Length: ${s_len} chars (below min ${SECRET_MIN_LENGTH})${NC}"
            else
                echo -e "  Value:  ${BOLD}${cur}${NC}"
                echo -e "  ${GREEN}Length: ${s_len} chars${NC}"
            fi
            echo ""
            ;;
        set)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope secret ${scope} set <value>"
                exit 1
            fi
            if [[ "${#arg}" -lt "$SECRET_MIN_LENGTH" ]]; then
                error "Secret is ${#arg} characters; minimum is ${SECRET_MIN_LENGTH}."
                exit 1
            fi
            if [[ "$arg" =~ ^[a-z]+$ ]] || [[ "$arg" =~ ^[A-Z]+$ ]] || [[ "$arg" =~ ^[0-9]+$ ]]; then
                error "Secret is single-character-class (low entropy)."
                exit 1
            fi
            backup_config
            set_scope_secret "$scope" "$arg"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Scope '${scope}' secret updated."
            warn "Update ALL devices in scope '${scope}' with the new secret: ${arg}"
            echo ""
            ;;
        generate)
            local new_val
            new_val=$(openssl rand -base64 24)
            echo -e "  Generated: ${BOLD}${new_val}${NC}"
            backup_config
            set_scope_secret "$scope" "$new_val"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Scope '${scope}' secret updated."
            warn "Update ALL devices in scope '${scope}' with the new secret above."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl scope secret ${scope}' for usage."
            exit 1
            ;;
    esac
}

# --- Per-scope AAA method-list order: tacctl scope aaa-order <scope> [value] ---
# Flips the order of methods in the Cisco `aaa authentication/authorization`
# and Junos `system authentication-order` lines that `tacctl config
# cisco --scope <name>` / `tacctl config juniper --scope <name>` emit.
# Per-scope so a lab scope can favor local break-glass access while a
# prod scope keeps TACACS+ authoritative. Absent an override, each
# scope defaults to tacacs-first.
cmd_scope_aaa_order() {
    local scope="${1:-}"
    local new_order="${2:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope aaa-order <scope> [tacacs-first|local-first]"
        exit 1
    fi
    if ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist. Available: $(list_scopes | paste -sd' ')"
        exit 1
    fi

    local current source
    current=$(conf_get "aaa.order.${scope}")
    if [[ -z "$current" ]]; then
        current="tacacs-first"
        source="default"
    else
        source="override (tacctl.yaml: aaa.order.${scope})"
    fi

    if [[ -z "$new_order" ]]; then
        echo ""
        echo "  Scope '${scope}' AAA method-list order: ${current}"
        echo "  Source: ${source}"
        echo ""
        echo "    tacacs-first  TACACS+ is authoritative; local used only on server outage."
        echo "    local-first   Local DB checked first; TACACS+ used for names not found locally."
        echo ""
        echo "  Usage: tacctl scope aaa-order ${scope} <tacacs-first|local-first>"
        echo ""
        return
    fi

    conf_set "aaa.order.${scope}" "$new_order" || exit 1
    info "Scope '${scope}' AAA method-list order set to ${new_order}."
    if [[ "$new_order" == "local-first" ]]; then
        warn "Local usernames that collide with TACACS+ users will win locally on devices in this scope."
        warn "Scope local accounts to break-glass / emergency use only."
    fi
    echo ""
    echo "  Re-run 'tacctl config cisco --scope ${scope}' / 'tacctl config juniper --scope ${scope}'"
    echo "  and push the updated method-lists to each device in this scope — the change is not"
    echo "  applied until the device receives the new AAA stanzas."
    echo ""
}

# --- Per-scope exec-timeout: tacctl scope exec-timeout <scope> [minutes] ---
# Sets the idle-session timeout in minutes for devices in this scope.
# Cisco substitutes into `line con 0 / line vty 0 15 ... exec-timeout
# <n> 0`; Junos renders `set system login idle-timeout <n>`. 0 means
# never expire (both vendors). Upper bound 60 matches Junos's max;
# Cisco accepts higher but we cap for cross-vendor portability.
cmd_scope_exec_timeout() {
    local scope="${1:-}"
    local new_mins="${2:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope exec-timeout <scope> [minutes]"
        exit 1
    fi
    if ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist. Available: $(list_scopes | paste -sd' ')"
        exit 1
    fi

    local current source
    current=$(conf_get "exec_timeout.${scope}")
    if [[ -z "$current" ]]; then
        current="60"
        source="default"
    else
        source="override (tacctl.yaml: exec_timeout.${scope})"
    fi

    if [[ -z "$new_mins" ]]; then
        echo ""
        echo "  Scope '${scope}' exec-timeout: ${current} minute(s)"
        echo "  Source: ${source}"
        echo ""
        echo "    0..60 minutes. 0 = never expire (both Cisco and Junos)."
        echo ""
        echo "  Usage: tacctl scope exec-timeout ${scope} <minutes>"
        echo ""
        return
    fi

    conf_set "exec_timeout.${scope}" "$new_mins" || exit 1
    info "Scope '${scope}' exec-timeout set to ${new_mins} minute(s)."
    if [[ "$new_mins" == "0" ]]; then
        warn "exec-timeout 0 disables idle-session expiry on devices in this scope."
        warn "Long-lived sessions on unattended terminals become a security risk."
    fi
    echo ""
    echo "  Re-run 'tacctl config cisco --scope ${scope}' / 'tacctl config juniper --scope ${scope}'"
    echo "  and push the updated line-config / login stanzas to each device in this scope."
    echo ""
}

# --- Per-scope Cisco aaa-group-server label: tacctl scope tacacs-group <scope> [name] ---
# Rendered into every Cisco `aaa group server tacacs+ <NAME>` and the
# method-lists/accounting lines that reference the group. Per-scope so
# each environment can match site naming conventions. Junos has no
# equivalent (its AAA doesn't group named servers this way).
cmd_scope_tacacs_group() {
    local scope="${1:-}"
    local new_name="${2:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope tacacs-group <scope> [name]"
        exit 1
    fi
    if ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist. Available: $(list_scopes | paste -sd' ')"
        exit 1
    fi

    local current source
    current=$(conf_get "tacacs_group.${scope}")
    if [[ -z "$current" ]]; then
        current="TACACS-GROUP"
        source="default"
    else
        source="override (tacctl.yaml: tacacs_group.${scope})"
    fi

    if [[ -z "$new_name" ]]; then
        echo ""
        echo "  Scope '${scope}' Cisco aaa-group-server name: ${current}"
        echo "  Source: ${source}"
        echo ""
        echo "    Rendered into every 'aaa group server tacacs+ <NAME>' and the method-list"
        echo "    / accounting lines that reference the group (Cisco only; Junos has no"
        echo "    equivalent)."
        echo ""
        echo "  Usage: tacctl scope tacacs-group ${scope} <name>"
        echo ""
        return
    fi

    conf_set "tacacs_group.${scope}" "$new_name" || exit 1
    info "Scope '${scope}' aaa-group-server label set to ${new_name}."
    echo ""
    echo "  Re-run 'tacctl config cisco --scope ${scope}' and push the updated AAA"
    echo "  stanzas to each device in this scope — the change is not applied until"
    echo "  the device receives the new group name. Leaving a stale local group"
    echo "  reference on the device will break authentication."
    echo ""
}

# --- Per-scope mgmt-ACL: tacctl scope mgmt-acl <scope> <sub> [args] ---
# Subcommand shape mirrors the global `tacctl config mgmt-acl` so
# operators who know one form immediately know the other:
#   list | add <cidrs> | remove <cidrs> | clear   → permit CIDR list
#   cisco-name   [label]                          → Cisco VTY-ACL name
#   juniper-name [label]                          → Junos filter name
#
# Permit list fallback chain at render time is per-scope -> global
# (mgmt_acl.permits) -> empty. An explicit empty per-scope list
# prunes the override so the scope falls back through the chain.
# Name fallback chain is per-scope -> global (mgmt_acl.names.*) ->
# shipped default (VTY-ACL / MGMT-ACL).
cmd_scope_mgmt_acl() {
    local scope="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"

    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scope mgmt-acl <scope> <list|add|remove|clear|cisco-name|juniper-name> [args]"
        exit 1
    fi
    if ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist. Available: $(list_scopes | paste -sd' ')"
        exit 1
    fi

    case "$sub" in
        ""|-h|--help|help)
            local n_scope n_global
            n_scope=$(read_mgmt_acl_cidrs "$scope" | awk 'NF' | wc -l)
            n_global=$(read_mgmt_acl_cidrs          | awk 'NF' | wc -l)
            echo ""
            echo -e "${BOLD}tacctl scope mgmt-acl ${scope}${NC} — per-scope Cisco VTY-ACL + Juniper lo0-filter"
            echo ""
            echo "Usage:"
            echo "  tacctl scope mgmt-acl ${scope} list                          Show effective permits for this scope"
            echo "  tacctl scope mgmt-acl ${scope} add    <cidr>[,<cidr>...]     Add one or more CIDRs to the per-scope list"
            echo "  tacctl scope mgmt-acl ${scope} remove <cidr>[,<cidr>...]     Remove one or more CIDRs from the per-scope list"
            echo "  tacctl scope mgmt-acl ${scope} clear                         Wipe the per-scope list (confirms; render falls back to global)"
            echo "  tacctl scope mgmt-acl ${scope} cisco-name   [label]          Per-scope Cisco VTY-ACL name"
            echo "  tacctl scope mgmt-acl ${scope} juniper-name [label]          Per-scope Junos filter name"
            echo ""
            echo "Current entries: ${n_scope} (per-scope) / ${n_global} (global fallback)"
            echo ""
            return
            ;;
        list)
            local scope_entries global_entries
            scope_entries=$(conf_get_list "scope_mgmt_acl.permits.${scope}")
            global_entries=$(conf_get_list mgmt_acl.permits)
            echo ""
            echo -e "${BOLD}Management ACL for scope '${scope}'${NC}"
            echo "--------------------------------------------"
            if [[ -n "$scope_entries" ]]; then
                echo "  Source: per-scope override (scope_mgmt_acl.permits.${scope})"
                echo "$scope_entries" | while IFS= read -r e; do
                    [[ -z "$e" ]] && continue
                    echo "  - ${e}"
                done
            elif [[ -n "$global_entries" ]]; then
                echo "  Source: global (mgmt_acl.permits) — per-scope list is empty"
                echo "$global_entries" | while IFS= read -r e; do
                    [[ -z "$e" ]] && continue
                    echo "  - ${e}"
                done
            else
                echo "  (empty — both per-scope and global lists are unset)"
                echo ""
                echo "  Add to this scope only:  tacctl scope mgmt-acl ${scope} add <cidr>"
                echo "  Add to the global list:  tacctl config mgmt-acl add <cidr>"
            fi
            echo ""
            ;;
        add)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope mgmt-acl ${scope} add <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested added="" skipped=""
            requested=$(parse_cidr_list "$arg")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(conf_get_list "scope_mgmt_acl.permits.${scope}")
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    skipped+="${skipped:+ }${c}"
                else
                    added+="${added:+$'\n'}${c}"
                    current=$(printf '%s\n%s\n' "$current" "$c")
                fi
            done <<< "$requested"
            if [[ -z "$added" ]]; then
                info "No new CIDRs to add to scope '${scope}' (already present: ${skipped})."
                echo ""
                return
            fi
            write_mgmt_acl_cidrs "$current" "$scope"
            local n
            n=$(printf '%s\n' "$added" | wc -l)
            info "Added ${n} to scope '${scope}' mgmt-acl: $(printf '%s\n' "$added" | paste -sd' ')"
            [[ -n "$skipped" ]] && info "(Already present, unchanged: ${skipped})"
            info "Re-run 'tacctl config cisco --scope ${scope}' / 'tacctl config juniper --scope ${scope}' to see the new output."
            echo ""
            ;;
        remove)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scope mgmt-acl ${scope} remove <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested removed="" missing=""
            requested=$(parse_cidr_list "$arg")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(conf_get_list "scope_mgmt_acl.permits.${scope}")
            if [[ -z "$current" ]]; then
                warn "Nothing to remove — scope '${scope}' has no per-scope permits (rendering from the global list)."
                exit 0
            fi
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    removed+="${removed:+$'\n'}${c}"
                    current=$(printf '%s\n' "$current" | grep -vxF "$c" || true)
                else
                    missing+="${missing:+ }${c}"
                fi
            done <<< "$requested"
            if [[ -z "$removed" ]]; then
                warn "Nothing to remove (not present in per-scope list: ${missing})."
                exit 0
            fi
            write_mgmt_acl_cidrs "$current" "$scope"
            local n
            n=$(printf '%s\n' "$removed" | wc -l)
            info "Removed ${n} from scope '${scope}' mgmt-acl: $(printf '%s\n' "$removed" | paste -sd' ')"
            [[ -n "$missing" ]] && info "(Not present, skipped: ${missing})"
            echo ""
            ;;
        clear)
            local current
            current=$(conf_get_list "scope_mgmt_acl.permits.${scope}")
            if [[ -z "$current" ]]; then
                info "Per-scope list for '${scope}' is already empty (render falls back to global)."
                echo ""
                return
            fi
            read -rp "  Clear all per-scope mgmt-acl entries for '${scope}'? Render will fall back to global. [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            conf_unset "scope_mgmt_acl.permits.${scope}"
            info "Per-scope mgmt-acl cleared for '${scope}'."
            echo ""
            ;;
        cisco-name|juniper-name)
            local vendor="${sub%-name}"
            local new_name="$arg"
            local current source effective
            current=$(conf_get "scope_mgmt_acl.names.${vendor}.${scope}")
            effective=$(read_mgmt_acl_name "$vendor" "$scope")
            if [[ -z "$current" ]]; then
                local global_val shipped
                case "$vendor" in
                    cisco)   global_val=$(conf_get mgmt_acl.names.cisco   "$CISCO_ACL_NAME_DEFAULT");   shipped="$CISCO_ACL_NAME_DEFAULT" ;;
                    juniper) global_val=$(conf_get mgmt_acl.names.juniper "$JUNIPER_ACL_NAME_DEFAULT"); shipped="$JUNIPER_ACL_NAME_DEFAULT" ;;
                esac
                if [[ "$global_val" == "$shipped" ]]; then
                    source="default"
                else
                    source="global (tacctl config mgmt-acl ${vendor}-name)"
                fi
            else
                source="override (tacctl.yaml: scope_mgmt_acl.names.${vendor}.${scope})"
            fi

            if [[ -z "$new_name" ]]; then
                echo ""
                echo "  Scope '${scope}' ${vendor} mgmt-acl name: ${effective}"
                echo "  Source: ${source}"
                echo ""
                echo "    Rendered into ${vendor} device configs for this scope only."
                echo "    Clear the per-scope override by setting it to the global value."
                echo ""
                echo "  Usage: tacctl scope mgmt-acl ${scope} ${sub} <name>"
                echo ""
                return
            fi

            conf_set "scope_mgmt_acl.names.${vendor}.${scope}" "$new_name" || exit 1
            info "Scope '${scope}' ${vendor} mgmt-acl name set to ${new_name}."
            echo ""
            echo "  Re-run 'tacctl config ${vendor} --scope ${scope}' and push the updated"
            echo "  ACL / filter block to each device in this scope. A stale ACL name on"
            echo "  the device will still reference the old filter until replaced."
            echo ""
            ;;
        *)
            error "Unknown subcommand '${sub}'. Use: list | add | remove | clear | cisco-name | juniper-name."
            exit 1
            ;;
    esac
}

