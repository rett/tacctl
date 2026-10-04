#!/usr/bin/env python3
"""Regenerate internal/render/tacacs/testdata/corpus.jsonl from tacctl 0.1.16.

    python3 internal/render/tacacs/testdata/gen.py      (from the repository root)

Needs git (the 0.1.16 tag), bash and PyYAML 6.0.1. Nothing outside a
temporary directory is touched: every case runs the tag's own render
program (_tacacs_render_live of lib/backends/tacacs.sh, i.e. 'render-live'
with the listeners' drop-ins) through bin/tacctl.sh, extracted with
'git archive', against a throwaway state directory.

Each line of corpus.jsonl is one case:

  name      what it is
  store     the store.yaml text ('@fixture:<name>': tests/fixtures/<name>)
  tacctl    the tacctl.yaml text, or null for none
  log       LOG_DIR (only drop-in text depends on it)
  files     {relative path: text} placed before the run (a live
            tacquito.yaml, live drop-ins, rendered.json); in a text '@W@'
            stands for the case directory, '@CONFIG@' for
            tests/fixtures/golden/tacquito.multiscope.rendered.yaml and
            '@DROPIN@' for the default drop-in of case store.multiscope.yaml
  rc        exit status of the program
  status    the word it printed (the live config against the render)
  stderr    what it wrote on stderr, '@W@' for the case directory
  config    the rendered tacquito.yaml, or null when nothing was rendered
            ('@golden:<name>': tests/fixtures/golden/<name>)
  index     the units index, '@W@' for the case directory, or null
  dropins   {listener: drop-in text} staged, or null

The Go test (corpus_test.go) replays every case through Renderer.RenderLive
with its own read-back loader and compares all of it.
"""
import copy
import hashlib
import json
import os
import random
import shutil
import subprocess
import tempfile

import yaml

TAG = '0.1.16'
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = subprocess.check_output(['git', '-C', HERE, 'rev-parse', '--show-toplevel'], text=True).strip()
FIX = os.path.join(ROOT, 'tests', 'fixtures')
STORE_HEADER = ("# tacctl canonical store: users, groups, scopes, prefix filters.\n"
                "# Managed by tacctl -- change it with tacctl commands. Contains shared\n"
                "# secrets and password hashes; keep it 0600.\n\n")
HASH = '24326224313224' + '646f6e74636172652e' + '2e' * 45
DIGITS = '24326224313224' + '31' * 53
MARK = '@W@'


def fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return yaml.safe_load(f)


def dump_store(doc):
    return STORE_HEADER + yaml.safe_dump(doc, sort_keys=False, default_flow_style=None, width=4096)


def dump_conf(doc):
    return yaml.safe_dump(doc, default_flow_style=False, sort_keys=False)


CASES = []


def case(name, store, tacctl=None, log='/var/log/tacquito', files=None):
    CASES.append({'name': name, 'store': store if isinstance(store, str) else dump_store(store),
                  'tacctl': tacctl if tacctl is None or isinstance(tacctl, str) else dump_conf(tacctl),
                  'log': log, 'files': files or {}})


def edit(base, fn):
    d = copy.deepcopy(fixture(base))
    fn(d)
    # No shared objects: PyYAML would write them as anchors and aliases,
    # which no store tacctl writes holds (and 0.2.0 refuses).
    return copy.deepcopy(json.loads(json.dumps(d)))


MULTI = 'store.multiscope.yaml'

# --- the fixtures ---
FIXTURE_TEXT = {}
for f in ('store.minimal.yaml', MULTI, 'store.radius.yaml'):
    with open(os.path.join(FIX, f)) as fh:
        FIXTURE_TEXT[f] = fh.read()
        case(f, FIXTURE_TEXT[f])


# --- the bats edits (tests/unit/render_tacacs.bats) ---
def disabled(d):
    d['users']['alice']['disabled'] = True
    d['users']['bob']['hash'] = None
    d['users']['bob']['disabled'] = True
    d['users']['root'] = {'group': 'readonly', 'scopes': ['lab'], 'hash': None, 'disabled': True,
                          'accounting_sink': True}


case('disabled-and-sink', edit(MULTI, disabled))


def protocols(d):
    d['scopes']['dmz']['protocols'] = ['radius']
    d['scopes']['lab']['protocols'] = ['tacacs', 'radius']


case('protocols', edit(MULTI, protocols))


def custom_groups(d):
    d['groups']['helpdesk'] = {'priv_lvl': 5, 'juniper_class': 'HELPDESK-CLASS', 'builtin': False}
    d['groups']['auditor'] = {'priv_lvl': 2, 'juniper_class': 'AUDIT', 'builtin': False}
    d['users']['bob']['group'] = 'helpdesk'


case('custom-groups', edit(MULTI, custom_groups))
case('command-rules', edit(MULTI, lambda d: None),
     "commands:\n  operator:\n    - {name: show, action: permit, match: ['^running-config\\s*$', 'say \"hi\"', 'back\\\\slash']}\n"
     "    - {name: \"*\", action: deny}\n  superuser: []\n")


def filters(d):
    d['filters']['allow'] = ['10.0.0.0/8', '10.9.0.0/16', '2001:db8::/32', '192.168.1.0/24']
    d['filters']['deny'] = ['10.9.9.0/24']


case('filters', edit(MULTI, filters))
case('secret-quoting', edit(MULTI, lambda d: d['scopes']['lab'].__setitem__(
    'secret', 'a"b\\c: #d \u00e9\u2028\U0001f511 {e}\x7e\u0080\u00ff\u0100')))


def weird_names(d):
    g = {'priv_lvl': 3, 'juniper_class': 'C', 'builtin': False}
    for n in ('no', 'users', 'exec_operator', 'file_accounter', 'action_deny', 'group_x', 'on', 'bcrypt_y'):
        d['groups'][n] = dict(g)
    d['scopes']['on'] = {'prefixes': ['198.51.100.0/24'], 'secret': 'on-secret-0123456789abcdef'}
    d['scopes']['Null'] = {'prefixes': ['198.51.101.0/24'], 'secret': 'null-secret-0123456789abcdef'}
    u = d['users']['alice']
    d['users']['123'] = dict(u, group='no', scopes=['on', 'Null'])
    d['users']['null'] = dict(u, group='users')
    d['users']['Yes'] = dict(u, group='exec_operator')
    d['users']['-dash'] = dict(u, group='file_accounter')
    d['users']['_x'] = dict(u, group='on')
    d['users']['1e3'] = dict(u, group='group_x')


case('weird-names', edit(MULTI, weird_names))
case('digit-hash', edit(MULTI, lambda d: d['users']['bob'].__setitem__('hash', DIGITS)))
case('invalid-model', edit(MULTI, lambda d: d['users']['bob'].__setitem__('group', 'nosuch')))


def ipv6(d):
    d['scopes']['v6'] = {'prefixes': ['2001:db8::/32', 'fd00:10::/64', '2001:db8:1::/48'],
                         'secret': 'v6-secret-0123456789abcdef'}
    d['scopes']['lab']['prefixes'] = ['172.16.0.0/12', '192.168.0.0/16', '10.10.0.0/16']
    d['users']['carol']['scopes'] = ['v6', 'lab', 'dmz']


case('ipv6-and-overlap', edit(MULTI, ipv6))

# --- tacctl.yaml that cannot be used, or rules that are not rules ---
case('conf-unparsable', fixture(MULTI), 'commands:\n  operator: [oops\n')
case('conf-not-mapping', fixture(MULTI), '- a\n- b\n')
case('conf-tab', fixture(MULTI), 'commands:\n\toperator: []\n')
case('rule-unknown-action', fixture(MULTI), {'commands': {'operator': [{'name': 'show', 'action': 'allow'}]}})
case('rule-null-action', fixture(MULTI), 'commands:\n  operator:\n  - {name: show, action: null}\n')
case('rule-no-name', fixture(MULTI), {'commands': {'operator': [{'action': 'permit'}]}})
case('rule-empty-name', fixture(MULTI), {'commands': {'readonly': [{'name': '', 'action': 'permit'}]}})
case('rule-int-name', fixture(MULTI), 'commands:\n  readonly:\n  - {name: 5}\n')
case('rule-not-mapping', fixture(MULTI), 'commands:\n  readonly:\n  - show\n')
case('rule-match-string', fixture(MULTI), {'commands': {'operator': [{'name': 'show', 'match': 'x'}]}})
case('rule-match-int', fixture(MULTI), {'commands': {'operator': [{'name': 'show', 'match': ['a', 5]}]}})
case('rule-match-empty', fixture(MULTI), {'commands': {'operator': [{'name': 'show', 'match': [], 'action': 'deny'}]}})
case('rules-not-list', fixture(MULTI), {'commands': {'operator': {'name': 'show'}}})
case('rules-empty-mapping', fixture(MULTI), 'commands:\n  operator: {}\n  readonly: ""\n')
case('rules-unicode', fixture(MULTI), {'commands': {'operator': [
    {'name': 'sh\u00f6w', 'match': ['\u2028', '\U0001f511', 'tab\there', "it's"]},
    {'name': 'q"uote', 'action': 'deny', 'match': ['\\\\']}]}})
case('rules-for-unknown-group', fixture(MULTI), {'commands': {'nosuch': [{'name': 'x'}], 'operator': []}})

# --- listeners and the drop-ins ---
case('listener-instance', fixture(MULTI), {'backends': {'tacacs': {'level': 30}}, 'listeners': {'tacacs': {
    'default': {'network': 'tcp', 'address': '10.1.0.1:49'},
    'mgmt': {'network': 'tcp', 'address': '127.0.0.1:4949'},
    'alt6': {'network': 'tcp6', 'address': '[::1]:4950', 'metrics_address': '[::1]:9100'}}}})
case('listener-metrics-default', fixture(MULTI), {'backends': {'tacacs': {'metrics_address': ':9200'}}, 'listeners': {'tacacs': {
    'mgmt': {'network': 'tcp', 'address': '127.0.0.1:4949', 'metrics_address': ':9200'}}}})
case('listener-metrics-default-sink', fixture(MULTI), {'backends': {'tacacs': {'metrics_address': '127.0.0.1:0'}}, 'listeners': {'tacacs': {
    'mgmt': {'network': 'tcp', 'address': '127.0.0.1:4949'}}}})
case('listener-tls', fixture(MULTI), 'listeners:\n  tacacs:\n    tls: {network: tcp, address: ":300", tls: {enabled: true}}\n')
case('listener-collide', fixture(MULTI), 'listeners:\n  tacacs:\n    a: {network: tcp, address: ":49"}\n')
case('listener-invalid-default', fixture(MULTI), 'listeners:\n  tacacs:\n    default: {address: nonsense}\n')
case('listener-tcp6-default', fixture(MULTI), {'listeners': {'tacacs': {'default': {'network': 'tcp6', 'address': '[::]:49'}}}})
case('level-string', fixture(MULTI), 'backends:\n  tacacs:\n    level: debug\n')
case('level-null', fixture(MULTI), 'backends:\n  tacacs:\n    level: null\n')
case('level-bool', fixture(MULTI), 'backends:\n  tacacs:\n    level: true\n')
case('level-101', fixture(MULTI), 'backends:\n  tacacs:\n    level: 101\n')
case('level-0', fixture(MULTI), 'backends:\n  tacacs:\n    level: 0\n')
case('metrics-bad', fixture(MULTI), 'backends:\n  tacacs:\n    metrics_address: nonsense\n')
case('metrics-int', fixture(MULTI), 'backends:\n  tacacs:\n    metrics_address: 8080\n')
case('backends-tacacs-list', fixture(MULTI), 'backends:\n  tacacs: [1]\n')
case('backends-tacacs-empty', fixture(MULTI), 'backends:\n  tacacs: ""\n')
case('backends-list', fixture(MULTI), 'backends: [1]\n')
case('log-dir-percent', fixture(MULTI), None, log='/var/log/ta%cquito/')
case('log-dir-relative', fixture(MULTI), None, log='logs')

# --- the live files against the render: the drift matrix ---
# The live tacquito.yaml and drop-in are 'render' (what the case renders),
# 'edited' (that plus a line) or absent; rendered.json records them as
# rendered ('match'), with another sum ('other'), not at all, is corrupt or
# is a list.
with open(os.path.join(FIX, 'golden', 'tacquito.multiscope.rendered.yaml')) as fh:
    GOLDEN = fh.read()


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def matrix():
    """tacquito.yaml (no drop-in on disk), then the default drop-in (no
    tacquito.yaml on disk), each absent, as rendered or edited, against
    every kind of records: none, the render's sum ('match'), the live
    file's sum ('live'), another sum, not JSON, not a mapping, not a
    mapping of strings."""
    out = []
    lives = {'absent': None, 'render': '@CONFIG@', 'edited': '@CONFIG@# hand edit\n'}
    for what, rel in (('config', 'etc/tacquito.yaml'), ('dropin', 'systemd/tacquito.service.d/tacctl.conf')):
        for live_name, live in lives.items():
            for rec in ('none', 'match', 'live', 'other', 'corrupt', 'list', 'nonstring'):
                files = {}
                if live is not None:
                    text = live if what == 'config' else live.replace('@CONFIG@', '@DROPIN@')
                    files[rel] = text
                    if rec in ('match', 'live', 'other'):
                        want = {'match': '@SHA@', 'live': '@SHALIVE@', 'other': sha('x')}[rec]
                        files['state/rendered.json'] = json.dumps({MARK + '/' + rel: want}, indent=2, sort_keys=True) + '\n'
                if rec in ('match', 'live') and live is None:
                    files['state/rendered.json'] = json.dumps({MARK + '/' + rel: sha('gone')}, indent=2, sort_keys=True) + '\n'
                elif rec == 'corrupt':
                    files['state/rendered.json'] = '{not json\n'
                elif rec == 'list':
                    files['state/rendered.json'] = '[]\n'
                elif rec == 'nonstring':
                    files['state/rendered.json'] = '{"/x": 1}\n'
                out.append((f'matrix-{what}-{live_name}-{rec}', files))
    return out


for name, files in matrix():
    case(name, FIXTURE_TEXT[MULTI], None, files=files)


# --- seeded random stores and rules ---
def rand_stores(n):
    rnd = random.Random(20261003)
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'
    secret_chars = (' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~abcXYZ019'
                    '\u00e9\u00fc\u2026\u2028\u2029\U0001f511\u00a0\u0085\u00ad\ufeff')
    nets4 = ['10.0.0.0/8', '10.1.0.0/16', '10.1.2.0/24', '172.16.0.0/12', '192.168.0.0/16', '192.168.7.0/24',
             '203.0.113.0/24', '198.51.100.7/32', '0.0.0.0/0', '100.64.0.0/10']
    nets6 = ['2001:db8::/32', 'fd00::/8', '::1/128', 'fd00:10::/64', '2001:db8:aa::/48', '::/0']
    for i in range(n):
        groups = {'readonly': {'priv_lvl': 1, 'juniper_class': 'RO-CLASS', 'builtin': True},
                  'operator': {'priv_lvl': 7, 'juniper_class': 'OP-CLASS', 'builtin': True},
                  'superuser': {'priv_lvl': 15, 'juniper_class': 'RW-CLASS', 'builtin': True}}
        for _ in range(rnd.randint(0, 4)):
            name = rnd.choice('abcdefghijklmnopqrstuvwxyz') + ''.join(rnd.choice('abcdefghijklmnopqrstuvwxyz0123456789_-') for _ in range(rnd.randint(0, 12)))
            groups[name] = {'priv_lvl': rnd.randint(0, 15), 'juniper_class': ''.join(rnd.choice(chars) for _ in range(rnd.randint(1, 10))), 'builtin': False}
        scopes = {}
        pool = nets4 + nets6
        rnd.shuffle(pool)
        for _ in range(rnd.randint(1, 4)):
            name = rnd.choice('abcdefghijklmnopqrstuvwxyzAB') + ''.join(rnd.choice(chars) for _ in range(rnd.randint(0, 8)))
            k = rnd.randint(1, 3)
            prefixes, pool = pool[:k], pool[k:]
            if not prefixes:
                break
            s = {'prefixes': prefixes, 'secret': ''.join(rnd.choice(secret_chars) for _ in range(rnd.randint(16, 40)))}
            if rnd.random() < 0.3:
                s['protocols'] = rnd.choice([['radius'], ['tacacs'], ['tacacs', 'radius']])
            scopes[name] = s
        users = {}
        for _ in range(rnd.randint(0, 6)):
            name = ''.join(rnd.choice(chars) for _ in range(rnd.randint(1, 10)))
            if rnd.random() < 0.15:
                name = rnd.choice(['yes', 'No', 'ON', 'true', 'Null', '0', '0x1f', '1_000', '1.5', '-', '_', 'y', 'root'])
            sc = rnd.sample(sorted(scopes), rnd.randint(0, len(scopes)))
            h = rnd.choice([HASH, HASH, DIGITS, None])
            u = {'group': rnd.choice(sorted(groups)), 'scopes': sc, 'hash': h,
                 'disabled': h is None or rnd.random() < 0.2}
            if name == 'root':
                u.update(hash=None, disabled=True, accounting_sink=True)
            users[name] = u
        filt = {'allow': rnd.sample(nets4 + nets6, rnd.randint(0, 3)), 'deny': rnd.sample(nets4, rnd.randint(0, 2))}
        doc = {'version': 1, 'groups': dict(sorted(groups.items())), 'users': dict(sorted(users.items())),
               'scopes': dict(sorted(scopes.items())), 'filters': filt}
        rules = {}
        for g in sorted(groups):
            if rnd.random() < 0.5:
                rules[g] = [{'name': ''.join(rnd.choice(secret_chars + 'abc') for _ in range(rnd.randint(1, 8))),
                             'action': rnd.choice(['permit', 'deny']),
                             **({'match': [''.join(rnd.choice(secret_chars) for _ in range(rnd.randint(0, 6)))
                                           for _ in range(rnd.randint(1, 3))]} if rnd.random() < 0.6 else {})}
                            for _ in range(rnd.randint(0, 3))]
        case(f'random-{i:02d}', doc, {'commands': rules} if rules else None)


rand_stores(40)


# --- running the 0.1.16 program ---
SCRIPT = r'''
set -u
source "$TREE/bin/tacctl.sh" 2> "$OUT/source.err"
set +e +o pipefail
_tacacs_render_live "$W/out/tacquito.yaml" "$W/out/units" > "$OUT/status" 2> "$OUT/stderr"
echo $? > "$OUT/rc"
'''


def run(tree, work, c, dropin_text):
    w = os.path.join(work, c['name'])
    out = os.path.join(w, 'result')
    for d in ('etc', 'state/backups/password-dates', 'systemd/tacquito.service.d', 'out', 'result', 'bin'):
        os.makedirs(os.path.join(w, d), exist_ok=True)
    with open(os.path.join(w, 'state', 'store.yaml'), 'w') as f:
        f.write(c['store'])
    if c['tacctl'] is not None:
        with open(os.path.join(w, 'state', 'tacctl.yaml'), 'w') as f:
            f.write(c['tacctl'])
    def expand(t):
        return t.replace('@DROPIN@', dropin_text or '').replace('@CONFIG@', GOLDEN)
    for rel, text in c['files'].items():
        if '@SHALIVE@' in text:
            live = [t for r, t in c['files'].items() if r != rel][0]
            text = text.replace('@SHALIVE@', sha(expand(live)))
        if '@SHA@' in text:
            text = text.replace('@SHA@', sha(dropin_text if 'tacctl.conf' in text else GOLDEN))
        c['files'][rel] = text
        text = expand(text).replace(MARK, w)
        with open(os.path.join(w, rel), 'w') as f:
            f.write(text)
    env = dict(os.environ, TREE=tree, W=w, OUT=out, TACCTL_ETC=os.path.join(w, 'etc'),
               TACCTL_STATE_DIR=os.path.join(w, 'state'), TACCTL_LOG=c['log'], TACCTL_BIN=os.path.join(w, 'bin'),
               TACCTL_CONFIG=os.path.join(w, 'etc', 'tacquito.yaml'),
               TACCTL_OVERRIDE_DIR=os.path.join(w, 'systemd', 'tacquito.service.d'),
               TACCTL_SYSTEMD_DIR=os.path.join(w, 'systemd'), TACCTL_SKIP_SUDO='1', LC_ALL='C.UTF-8')
    subprocess.run(['bash', '-c', SCRIPT], env=env, check=True, cwd=w)

    def read(p):
        try:
            with open(p, encoding='utf-8', errors='surrogateescape') as f:
                return f.read()
        except FileNotFoundError:
            return None
    rec = dict(c)
    rec['rc'] = int(read(os.path.join(out, 'rc')))
    rec['status'] = read(os.path.join(out, 'status')).rstrip('\n')
    rec['stderr'] = read(os.path.join(out, 'stderr')).replace(w, MARK)
    rec['config'] = read(os.path.join(w, 'out', 'tacquito.yaml'))
    idx = read(os.path.join(w, 'out', 'units', 'index'))
    rec['index'] = None if idx is None else idx.replace(w, MARK)
    if idx is None:
        rec['dropins'] = None
    else:
        rec['dropins'] = {}
        for line in idx.splitlines():
            name = line.split('\t')[0]
            rec['dropins'][name] = read(os.path.join(w, 'out', 'units', name + '.conf'))
    leftovers = [n for n in os.listdir(os.path.join(w, 'out')) if n.startswith('.tacquito.')]
    if leftovers:
        raise SystemExit(f'gen.py: {c["name"]}: temp files left behind: {leftovers}')
    return rec


def main():
    work = tempfile.mkdtemp(prefix='tacctl-gen-')
    try:
        tree = os.path.join(work, 'tree')
        os.makedirs(tree)
        archive = subprocess.run(['git', '-C', ROOT, 'archive', TAG, 'bin', 'lib', 'config', 'patches'],
                                 check=True, capture_output=True).stdout
        subprocess.run(['tar', '-x', '-C', tree], input=archive, check=True)
        # The default drop-in of the multiscope fixture without tacctl.yaml,
        # for the matrix cases.
        first = run(tree, work, dict(CASES[1], name='first-dropin', files={}), None)
        dropin = first['dropins']['default']
        records = [run(tree, work, c, dropin) for c in CASES]
    finally:
        shutil.rmtree(work)
    with open(os.path.join(HERE, 'corpus.jsonl'), 'w') as f:
        for r in records:
            for k, v in FIXTURE_TEXT.items():
                if r['store'] == v:
                    r['store'] = '@fixture:' + k
            if r['config'] == GOLDEN:
                r['config'] = '@golden:tacquito.multiscope.rendered.yaml'
            f.write(json.dumps(r, sort_keys=True) + '\n')
    print(f'gen.py: {len(records)} cases')


if __name__ == '__main__':
    main()
