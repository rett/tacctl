#!/usr/bin/env bash
# Regenerate internal/model/testdata/legacy/ from the 0.1.16 tag (needs git,
# python3 with PyYAML and bcrypt, bash). Nothing here runs at test time.
#
#   variants/   tacquito.yaml variants the equivalence tests compare
#               (tests/unit/store_import.bats builds them with python
#               at run time; here they are written once)
#   migrated/   tacquito.{minimal,legacy-exec,dead-matches,multiscope}.yaml
#               after upgrade's migrations (render_tacacs.bats
#               upgrade_migrations)
#   renders/    what 'store import --check' renders for each raw and each
#               migrated fixture (render_tacacs_config, default tacctl.yaml)
#   expected/equiv.<pair>.out   equiv_check's stdout and 'rc=' for each
#               line of pairs (fingerprints numbered by first appearance:
#               <redacted:1>, <redacted:2>, ...)
#   expected/check.<case>.out   'store_import --check' stdout+stderr and
#               'rc=' for each raw and migrated fixture, its render as the
#               render hook's output (the daemon load-smoke skipped), with
#               the source path written as SRC
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
top=$(git -C "$here" rev-parse --show-toplevel)
fix="${top}/tests/fixtures"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git -C "$top" archive 0.1.16 bin lib config | tar -x -C "$tmp"

export TACCTL_ETC="${tmp}/env/etc" TACCTL_STATE_DIR="${tmp}/env/state" TACCTL_LOG="${tmp}/env/log"
export TACCTL_BIN="${tmp}/env/bin" TACCTL_CONFIG="${tmp}/env/etc/tacquito.yaml"
export TACCTL_OVERRIDE_DIR="${tmp}/env/dropin" TACCTL_SUDOERS_FILE="${tmp}/env/sudoers"
export TACCTL_SKIP_SUDO=1
mkdir -p "$TACCTL_ETC" "$TACCTL_LOG" "$TACCTL_BIN" "${TACCTL_STATE_DIR}/backups/password-dates"

rm -rf "${here}/variants" "${here}/migrated" "${here}/renders" "${here}/expected"
mkdir -p "${here}/variants" "${here}/migrated" "${here}/renders" "${here}/expected"

# ---- variants (python of store_import.bats, verbatim) ----
ms="${fix}/tacquito.multiscope.yaml"
variant() {  # variant <name> <python statements on d, users, s>
    python3 - "$ms" "${here}/variants/$1.yaml" "$2" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
d = {k: d[k] for k in ('users', 'secrets')}
users = {u['name']: u for u in d['users']}
s = d['secrets']
exec(sys.argv[3])
yaml.safe_dump(d, open(sys.argv[2], 'w'))
PY
}
python3 - "$ms" "${here}/variants/noalias-reversed.yaml" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for u in d['users']:
    u['scopes'] = list(reversed(u['scopes']))
class NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True
yaml.dump({k: d[k] for k in ('users', 'secrets')}, open(sys.argv[2], 'w'), Dumper=NoAlias)
PY
append_secret() {  # append_secret <file> <name> <key> <prefix>
    cat >> "$1" <<YAML
  - name: ${2}
    secret:
      group: tacquito
      key: ${3}
    handler:
      type: *handler_type_start
    type: *provider_type_prefix
    options:
      prefixes: |
        [
          "${4}"
        ]
YAML
}
cp "${fix}/tacquito.minimal.yaml" "${here}/variants/minimal-multi.yaml"
sed -i 's|"192.168.0.0/16"|"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"|' "${here}/variants/minimal-multi.yaml"
cp "${fix}/tacquito.minimal.yaml" "${here}/variants/minimal-split.yaml"
append_secret "${here}/variants/minimal-split.yaml" lab '"lab-secret-placeholder-16chars"' 172.16.0.0/12
append_secret "${here}/variants/minimal-split.yaml" lab '"lab-secret-placeholder-16chars"' 10.0.0.0/8
variant reroute-a "users['bob']['scopes'].append('prod-inner')"
variant reroute-b "users['bob']['scopes'].append('prod-inner'); s[0], s[1] = s[1], s[0]"
variant swapped "s[0], s[1] = s[1], s[0]"
entry="dict(s[2], name='%s', options={'prefixes': '[\"%s\"]'})"
# shellcheck disable=SC2059  # $entry is a format, as in store_import.bats
setup="users['carol']['scopes'].append('inner')
s.insert(0, $(printf "$entry" spare 192.168.0.0/16))
wide, narrow = $(printf "$entry" lab 192.168.0.0/16), $(printf "$entry" inner 192.168.7.0/24)
del s[3]"
variant spare-a "${setup}; s[1:1] = [wide, narrow]"
variant spare-b "${setup}; s[1:1] = [narrow, wide]"
variant user-accounter "
for u in d['users']:
    u['accounter'] = {'name': 'tacquito_accounter', 'type': 3}"
variant no-accounter "
for u in d['users']:
    for g in u['groups']:
        g.pop('accounter', None)"
variant bare-address "s[3]['options']['prefixes'] = '[\"203.0.113.9\"]'; d['prefix_deny'] = ['10.1.1.1']"
variant bare-address-32 "s[3]['options']['prefixes'] = '[\"203.0.113.9/32\"]'; d['prefix_deny'] = ['10.1.1.1/32']"
variant trailing-comma "s[3]['options']['prefixes'] = '[\"203.0.113.0/24\",]'"
sed 's/values: \[15\]/values: ["15"]/' "$ms" > "${here}/variants/quoted-15.yaml"
sed 's/values: \[15\]/values: [015]/' "$ms" > "${here}/variants/octal-15.yaml"
variant secrets-everywhere "
users['bob']['groups'][0]['authenticator'] = {'type': 1, 'options': {'hash': '2432deadbeef', 'key': 'grpkey'}}
s[0]['secret']['extra'] = 'side-secret'"
sed '0,/646f6e7463617265/s//646f6e7463617266/' "$ms" > "${here}/variants/changed-hash.yaml"
marker="24326224313224$(printf '2e%.0s' {1..53})"
sed "s/hash: DISABLED\$/hash: ${marker}/" "${fix}/legacy.import-edge.yaml" > "${here}/variants/edge-marker.yaml"
sed "s/^  name: exec\$/  name: shell/" "${fix}/legacy.import-edge.yaml" > "${here}/variants/edge-shell.yaml"
sed 's|^prefix_allow: .*|prefix_allow: ["192.168.0.0/16", "10.0.0.0/8"]|' "${fix}/legacy.import-edge.yaml" > "${here}/variants/edge-allow.yaml"
sed 's|^prefix_deny: .*|prefix_deny: ["10.67.0.0/16"]|' "${fix}/legacy.import-edge.yaml" > "${here}/variants/edge-deny.yaml"
printf '# an empty document\n' > "${here}/variants/empty.yaml"
# Two large files (JSON forms over 200 lines: difflib's autojunk applies).
python3 - "${here}/variants" <<'PY'
import sys, yaml
def doc(n, edit):
    users, secrets = [], []
    for i in range(n):
        users.append({'name': f'user{i:03d}', 'scopes': [f'site{i % 7}', 'core'],
                      'groups': [{'name': 'operator', 'services': [
                          {'name': 'shell', 'set_values': [{'name': 'priv-lvl', 'values': [7]}]}]}],
                      'authenticator': {'type': 1, 'options': {'hash': f'2432622431322441{i:04d}'}},
                      'accounter': {'name': 'tacquito_accounter', 'type': 3}})
    for i in range(7):
        secrets.append({'name': f'site{i}', 'secret': {'group': 'tacquito', 'key': f'site-secret-{i}'},
                        'handler': {'type': 1}, 'type': 1,
                        'options': {'prefixes': f'["10.{i}.0.0/16", "10.{i}.128.0/17"]'}})
    secrets.append({'name': 'core', 'secret': {'group': 'tacquito', 'key': 'core-secret'},
                    'handler': {'type': 1}, 'type': 1, 'options': {'prefixes': '["10.0.0.0/8"]'}})
    d = {'users': users, 'secrets': secrets}
    edit(d)
    return d
def edit_b(d):
    del d['users'][10:14]
    d['users'][3]['authenticator']['options']['hash'] = 'DISABLED'
    d['users'][20]['scopes'] = ['core']
    d['users'][40]['groups'][0]['services'][0]['set_values'][0]['values'] = [15]
    d['users'].append(dict(d['users'][0], name='zed'))
    d['secrets'][2], d['secrets'][3] = d['secrets'][3], d['secrets'][2]
    d['secrets'][-1]['options']['prefixes'] = '["10.0.0.0/8", "172.16.0.0/12"]'
yaml.safe_dump(doc(60, lambda d: None), open(sys.argv[1] + '/big-a.yaml', 'w'))
yaml.safe_dump(doc(60, edit_b), open(sys.argv[1] + '/big-b.yaml', 'w'))
PY

# ---- migrated fixtures and renders (0.1.16 bash) ----
# shellcheck disable=SC1091
source "${tmp}/bin/tacctl.sh"
set +e +u +o pipefail
chown() { :; }
render_of() {  # render_of <tacquito.yaml> <out>
    local m="${tmp}/model.json"
    rm -f "$STORE_FILE"
    _store_python import-load "$1" "$PASSWORD_DATES_DIR" "${BACKUP_DIR}/disabled" "" 0 "$m" > /dev/null
    render_tacacs_config "$m" "$2"
}
check_of() {  # check_of <case> <tacquito.yaml> <render>
    cp "$2" "$CONFIG"
    rm -f "$STORE_FILE"
    _conf_invalidate
    _model_invalidate
    store_render_hook() { cp "$RENDER_FOR_CHECK" "$2"; }
    local out rc=0
    out=$(RENDER_FOR_CHECK="$3" store_import --check 2>&1) || rc=$?
    printf '%s\nrc=%s\n' "$out" "$rc" | python3 -c '
import re, sys
t = sys.stdin.read().replace(sys.argv[1], "SRC")
seen = {}
t = re.sub(r"<redacted:[0-9a-f]{10}>", lambda m: "<redacted:%d>" % seen.setdefault(m.group(0), len(seen) + 1), t)
sys.stdout.write(t)' "$CONFIG" > "${here}/expected/check.$1.out"
}
for f in minimal legacy-exec dead-matches multiscope; do
    render_of "${fix}/tacquito.${f}.yaml" "${here}/renders/${f}.raw.yaml"
    cp "${fix}/tacquito.${f}.yaml" "$CONFIG"
    _conf_invalidate
    rm -f "$TACCTL_OVERRIDES_FILE"
    conf_migrate_exec_service_name > /dev/null
    conf_migrate_command_rules > /dev/null
    regenerate_tacquito_commands
    cp "$CONFIG" "${here}/migrated/${f}.yaml"
    render_of "${here}/migrated/${f}.yaml" "${here}/renders/${f}.migrated.yaml"
done
for f in minimal legacy-exec dead-matches multiscope; do
    check_of "${f}.raw" "${fix}/tacquito.${f}.yaml" "${here}/renders/${f}.raw.yaml"
    check_of "${f}.migrated" "${here}/migrated/${f}.yaml" "${here}/renders/${f}.migrated.yaml"
done
check_of golden-multiscope "${fix}/golden/tacquito.multiscope.rendered.yaml" "${fix}/golden/tacquito.multiscope.rendered.yaml"

# ---- equivalence pairs (python of 0.1.16) ----
{ _store_py; _model_py; } > "${tmp}/prog.py"
python3 - "${tmp}/prog.py" "$here" "$fix" <<'PY'
import contextlib, importlib.util, io, os, re, sys
spec = importlib.util.spec_from_file_location('prog', sys.argv[1])
prog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prog)
here, fix = sys.argv[2], sys.argv[3]
os.chdir(here)
for line in open('pairs'):
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    name, a, b = line.split()
    path = lambda p: os.path.join(fix, p[len('FIXTURES/'):]) if p.startswith('FIXTURES/') else p
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = prog.equiv_check(path(a), path(b))
    t = out.getvalue().replace(fix + '/', 'FIXTURES/') + f'rc={rc}\n'
    seen = {}
    t = re.sub(r'<redacted:[0-9a-f]{10}>', lambda m: '<redacted:%d>' % seen.setdefault(m.group(0), len(seen) + 1), t)
    open(os.path.join('expected', f'equiv.{name}.out'), 'w').write(t)
PY
