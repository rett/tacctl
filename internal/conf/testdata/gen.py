#!/usr/bin/env python3
"""Regenerate internal/conf/testdata from tacctl 0.1.16, the parity baseline.

    python3 internal/conf/testdata/gen.py        (from the repository root)

Needs git (the 0.1.16 tag), bash and PyYAML 6.0.1. Nothing outside a
temporary directory is touched: the bash cases run the tag's own
bin/tacctl.sh, extracted with 'git archive', against a throwaway state
directory (TACCTL_STATE_DIR, TACCTL_SKIP_SUDO=1).

What it writes (each line of a .jsonl file is one case; a deterministic seed
keeps the files stable):

- parse.jsonl: what load_overrides (lib/conf.sh) makes of a file: the
  problem line, a Python exception other than YAMLError ("crash"), or the
  value; hand-written documents and seeded mutations of tacctl.yaml-like
  ones. internal/pyyaml must agree on every one.
- validate.jsonl: validate(path, value, is_list) of the schema, for every
  schema path against many values; coerce_scalar of command-line words.
- listeners.jsonl: listeners_effective and listeners_problems of documents.
- py.jsonl: repr(), str() and json.dumps() of values (internal/py).
- bash.jsonl: end-to-end runs of the 0.1.16 functions (conf_set,
  conf_set_list, conf_set_json, conf_unset, conf_get*, conf_has_override,
  _conf_validate_overrides_file, cmd_config_dump, the source-time
  tunables and the warning) on a file, with their exact output and the
  file they leave.
- golden-ops.json and ../../../tests/fixtures/golden/tacctl.overrides.yaml:
  a sequence of writes that sets every schema key, and the file 0.1.16
  leaves; pyyaml/every-key.json is that file's value for
  tests/tools/pyyaml-corpus.py (run it with that directory afterwards).

The defaults text internal/conf/defaults.yaml is checked against the tag.
"""
import base64
import datetime
import json
import math
import os
import random
import shutil
import subprocess
import sys
import tempfile

TAG = '0.1.16'
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = subprocess.check_output(['git', '-C', HERE, 'rev-parse', '--show-toplevel'], text=True).strip()
FILE = '@FILE@'  # stands for the overrides path in recorded messages

import yaml  # noqa: E402

if yaml.__version__ != '6.0.1':
    print(f'gen.py: note: PyYAML {yaml.__version__}, the corpus is from 6.0.1', file=sys.stderr)

CONF_SH = subprocess.check_output(['git', '-C', ROOT, 'show', f'{TAG}:lib/conf.sh'], text=True)


def heredoc(func, opener, end):
    """The body of the first heredoc opened by a line containing `opener`
    after the line 'func() {'."""
    lines = CONF_SH.split('\n')
    i = lines.index(func + '() {')
    while opener not in lines[i]:
        i += 1
    out = []
    i += 1
    while lines[i] != end:
        out.append(lines[i])
        i += 1
    return '\n'.join(out) + '\n'


DEFAULTS = heredoc('conf_emit_defaults', "<<'YAML'", 'YAML')
LISTENER_PY = heredoc('_listener_py', "<<'PY'", 'PY')
SCHEMA_PY = heredoc('_conf_schema_py', "<<'PY'", 'PY').replace('@BACKEND_IDS@', "['tacacs', 'radius']")
OVERRIDES_PY = heredoc('_conf_overrides_py', "<<'PY'", 'PY')

with open(os.path.join(HERE, '..', 'defaults.yaml'), encoding='utf-8') as f:
    if f.read() != DEFAULTS:
        sys.exit('gen.py: internal/conf/defaults.yaml differs from conf_emit_defaults at ' + TAG)

NS = {}
exec(LISTENER_PY + SCHEMA_PY + OVERRIDES_PY, NS)
rng = random.Random(20261003)


# --- JSON conventions (as tests/tools/pyyaml-corpus.py) ---------------------

class Unrepresentable(Exception):
    pass


def to_json(v, big=False):
    """A loaded value as JSON: {"$date": ...}, {"$float": "nan"|"inf"|"-inf"};
    Unrepresentable for what tacctl's value types cannot hold (an integer
    past 64 bits too, unless big)."""
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, int):
        if not big and not -2**63 <= v < 2**63:
            raise Unrepresentable('big int')
        return v
    if isinstance(v, float):
        if v != v:
            return {'$float': 'nan'}
        if v in (math.inf, -math.inf):
            return {'$float': 'inf' if v > 0 else '-inf'}
        return v
    if isinstance(v, datetime.datetime):
        raise Unrepresentable('datetime')
    if isinstance(v, datetime.date):
        return {'$date': v.isoformat()}
    if isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise Unrepresentable('key')
        return {k: to_json(x, big) for k, x in v.items()}
    if isinstance(v, list):
        return [to_json(x, big) for x in v]
    raise Unrepresentable(type(v).__name__)


def from_json(v):
    if isinstance(v, dict):
        if len(v) == 1 and '$date' in v:
            return datetime.date.fromisoformat(v['$date'])
        if len(v) == 1 and '$float' in v:
            return float(v['$float'])
        return {k: from_json(x) for k, x in v.items()}
    if isinstance(v, list):
        return [from_json(x) for x in v]
    return v


def text_field(data):
    """A document for a record: text when it is valid UTF-8, else hex."""
    try:
        return {'yaml': data.decode('utf-8')}
    except UnicodeDecodeError:
        return {'yaml_hex': data.hex()}


def write_jsonl(name, records):
    with open(os.path.join(HERE, name), 'w', encoding='utf-8', newline='\n') as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=True) + '\n')
    print(f'gen.py: {name}: {len(records)} cases')


# --- parse.jsonl --------------------------------------------------------------

PARSE_HAND = [
    '', '\n', '# only a comment\n', '---\n', '...\n', '--- \n...\n', '~\n', 'null\n',
    'bcrypt:\n  cost: 14\n', 'bcrypt: {cost: 14}\n', 'commands: [unterminated\n',
    'bcrypt:\n  cost: 14\ncommands: [unterminated\n',
    'password:\n  max_age_days: 30\nbcrypt:\n  cost: 14\ncommands: [unterminated\n',
    'commands: [unterminated', 'a: {b: 1\n', 'a: {b: 1,\n  c: 2\n', 'bcrypt:\n  cost: 14\n   x: 1\n',
    'a: b: c\n', 'bcrypt:\n\tcost: 14\n', 'a: "abc\n', "a: 'abc\n", 'a\nb: 1\n', 'a:\n  - 1\n b: 2\n',
    'a: 1\n- b\n', 'a: *x\n', 'a: !foo x\n', 'a: !!int abc\n', 'a: b\x01\n', 'a: 1\n---\nb: 2\n',
    'bcrypt:\n  cost 14\n  x: 1\n', '%FOO\na: 1\n', 'a: @x\n', 'a: `x\n', '? [a]\n: b\n', 'a:\n  b: 1\n\t\n',
    'a: [b, c]: d\n', '- bcrypt\n', 'just a string\n', '42\n', '1.5\n', 'true\n', '2026-10-01\n',
    '2026-10-01 10:00:00\n', '!!set {a, b}\n', '!!omap [a: 1]\n', '!!binary aGVsbG8=\n', '[1, 2]\n',
    'a: &x 1\nb: *x\n', 'a: &x [1]\nb: *x\n', 'base: &b {x: 1}\nother:\n  <<: *b\n  y: 2\n',
    'a:\n  <<: {x: 1}\n', 'a:\n  <<: [1]\n', 'a:\n  <<: 1\n', '1: a\n', 'yes: a\n', '~: a\n', '"x": 1\n',
    "'on': local-first\n", 'a: 99999999999999999999999\n', 'a: 0b_\n', 'a: 2026-02-30\n', 'a: 2026-13-01\n',
    'a: !!bool maybe\n', 'a: !!timestamp nope\n', 'a: !!float x\n', 'a: !!str [1]\n', 'a: !!map x\n',
    'a: !!seq x\n', 'a: !!null [1]\n', 'a: !!binary "!!!"\n', 'a: !!binary abc\n', 'a: !!binary "é"\n',
    'a: !!python/tuple [1]\n', 'a: !<tag:yaml.org,2002:str> x\n', 'a: !e!x y\n', '%TAG !e! tag:e.com,2000:\n---\na: !e!x y\n',
    '%YAML 1.1\n---\na: 1\n', '%YAML 2.0\n---\na: 1\n', '%YAML 1.1\n%YAML 1.1\n---\na: 1\n', 'a: =\n', '=: a\n',
    'a: |\n  text\n  more\n', 'a: >-\n  folded\n  text\n\n', 'a: |0\n  x\n', 'a: |x\n', 'a: "\\q"\n', 'a: "\\x4"\n',
    'a: "\\u00e9"\n', 'a: "\\U0001F600"\n', 'a: "\\UFFFFFFFF"\n', 'a: "x\n---\ny"\n', 'a: "x\n...\n"\n',
    '\ufeffa: 1\n', 'a: 1\r\nb: 2\r\n', 'a: 1\rb: 2\r', 'a: caf\u00e9\n', 'a: \u2028\n', 'a:\x85b\n',
    'a: [1,\n2]\n', 'a: {x: 1, x: 2}\n', 'a: 1\na: 2\n', '&a [*a]\n', 'a: &x\n  b: *x\n', 'a: &x 1\na2: &x 2\n',
    'key: value # comment\n', 'key: value#notcomment\n', 'k: v\n  w\n', 'k: - x\n', '- - x\n', '? a\n? b\n',
    '{a: 1}\n', '{a: 1}}\n', '[a]]\n', 'a: [b}\n', 'a: {b]\n', ': a\n', '- : a\n', 'a: b\n c\n', 'a:\n- b\n- c\n',
    'listeners:\n  tacacs:\n    a: {address: ":49"}\n', '!!map\na: 1\n', '!foo\na: 1\n', 'a: ! 12\n', 'a: ! x\n',
    'x' * 1100 + ': 1\n', 'a: ' + 'b' * 5000 + '\n', ('k: v\n' * 1200) + 'z: \x01\n', ('k: v\n' * 1200) + 'z: [\n',
    'a: !!int 0x1F\n', 'a: !!int 0o17\n', 'a: !!int 1:30\n', 'a: 1:30\n', 'a: -0x1A\n', 'a: 0777\n', 'a: 1_000\n',
    'a: .inf\n', 'a: -.Inf\n', 'a: .NaN\n', 'a: 1e3\n', 'a: 1.0e+3\n', 'a: 6.8523015e+5\n', 'a: 190:20:30.15\n',
    # directives, block scalars, flow-sequence pairs, tags and anchors in odd places
    '%YAML 1.1 # c\n---\na: 1\n', '%YAML 1.1 x\n---\na: 1\n', '%YAML 1\n---\n', '%YAML a.1\n---\n', '%YAML 1.a\n---\n',
    '%TAG ! tag:x,1:\n---\na: !y z\n', '%TAG !e!x tag:x\n---\n', '%TAG !e! tag:x junk\n---\n', '%TAG x\n---\n',
    '%TAG !e! tag:a\n%TAG !e! tag:b\n---\na: 1\n', '% \n---\n', '%Y@ML\n---\n', '%YAML 1.1\na: 1\n',
    'a: |-\n  x\n\nb: 1\n', 'a: |+\n  x\n\nb: 1\n', 'a: |2\n   x\n  y\n', 'a: >2-\n  x\n', 'a: |-2\n  x\n',
    'a: |-0\n x\n', 'a: |+x\n', 'a: | # c\n  x\n', 'a: | x\n', 'a: >\n  a\n  b\n\n  c\n   d\n  e\n',
    'a: |\n\n  \n  x\n', '- |\n x\n- >\n y\n', 'a: [b: 1, ? c, d: , : e]\n', 'a: [? b : c, ? ]\n',
    'a: [b: [c: d]]\n', 'a: {? b, c: , : d}\n', 'a: {b: 1, c}\n', 'a: {b: c: d}\n', 'a: [b, c: d, e]\n',
    'a: !<!x> y\n', 'a: !<tag:x> y\n', 'a: !<x y\n', 'a: !<> y\n', 'a: !e!x y\n', 'a: !! x\n', 'a: !e! x\n',
    'a: !a!b!c x\n', 'a: !x&y z\n', 'a: &a !!str x\n', 'a: !!str &a x\n', 'a: &a\nb: *a\n', 'a: &\n', 'a: *\n',
    'a: &a@ x\n', 'a: *a@\n', '&a a: b\n', '? &a x\n: *a\n', 'a: !!str\nb: 1\n', 'a: !%20 x\n', 'a: !<%zz> x\n',
    'a: !<%e2%82> x\n', 'a: !<%41%42> x\n', 'a: "x\\\n  y"\n', 'a: "x\n\n  y"\n', "a: 'x\n\n  y'\n", 'a: "\\x41\\u0042"\n',
    'a: "\\N\\_\\L\\P\\e\\0"\n', 'a: "\\xZ1"\n', '- a\n -b\n', '-\n- \n-  - x\n', '? a\n? b\n: c\n',
    '? |\n  x\n: y\n', 'a:\n  ? b\n  : c\n', 'a: b\n? c\n', 'a:\n- b\nc: d\n- e\n', 'a: - b\n', '[a, b]: c\n',
    '{a: b}: c\n', '"a": b\n"c" : d\n', "'a'\n: b\n", 'a: b #c\n#d\ne: f\n', 'a: b#c\n', 'a:\n  # c\n  b: 1\n',
    '--- !!map\na: 1\n', '--- |\n x\n', '--- a\n...\n--- b\n', '...\n...\na: 1\n', '---\n...\n', 'a: ---\n',
    'a: !!set\n  ? b\n  ? c\n', 'a: !!set [b]\n', 'a: !!omap\n- b: 1\n- c: 2\n', 'a: !!omap {b: 1}\n',
    'a: !!omap [b]\n', 'a: !!omap [{b: 1, c: 2}]\n', 'a: !!pairs [b: 1, b: 2]\n', 'a: !!pairs x\n',
    '<<: {a: 1}\nb: 2\n', 'a:\n  <<: [{x: 1}, {y: 2}]\n  z: 3\n', 'a:\n  <<: [{x: 1}, 2]\n', '=: x\n',
    'a: !!timestamp 2026-10-01T10:00:00Z\n', 'a: 2026-10-01t10:00:00.5+02:00\n', 'a: 2026-10-01 25:00:00\n',
    'a: 2026-1-1 10:00:00\n', 'a: !!timestamp 2026-10-01 10:00:00 +25\n', 'a: !!float 1:30.5\n', 'a: !!float .5\n',
    'a: !!int -0b101\n', 'a: !!int +0x_1F\n', 'a: !!int 0o17\n', 'a: !!int 09\n', 'a: !!bool YES\n', 'a: !!null x\n',
    'a: 2026-10-01 10:00:00\na: x\n', 'a: !!set {b}\na: 1\n', 'a: {x: !!binary aGk=}\na: 2\n',
    'a: !!binary |\n  aGVs\n  bG8=\n', 'a: !!binary aGVsbG8\n', 'a: !!binary a\n', 'a: !!binary "aGk==x"\n',
]

SEEDS = [
    DEFAULTS[:DEFAULTS.index('commands:')],
    DEFAULTS[DEFAULTS.index('commands:'):DEFAULTS.index('  readonly:')],
    'password:\n  max_age_days: 180\nbcrypt:\n  cost: 13\nscope:\n  default: prod\nmgmt_acl:\n  names:\n'
    '    cisco: CUSTOM\n  permits:\n  - 10.0.0.0/8\n  - 192.168.1.0/24\naaa:\n  order:\n    lab: local-first\n',
    'commands:\n  operator:\n  - name: show\n    action: permit\n    match:\n    - ^running-config$\n'
    '  - name: \'*\'\n    action: deny\nlisteners:\n  tacacs:\n    mgmt:\n      network: tcp\n'
    '      address: 10.1.0.1:4949\n',
    'listeners: {tacacs: {a: {network: tcp, address: ":300", tls: {cert: /a, require_client_cert: true}}}}\n'
    'backends: {enabled: [tacacs, radius], tacacs: {level: 30, metrics_address: "127.0.0.1:9090"}}\n',
    'privileges:\n  operator:\n    - show running-config\n    - "show version"\n    - \'show ip route\'\n'
    'exec_timeout:\n  lab: 15\ntacacs_group: {lab: TACACS_PROD}\nscope_auth_method:\n  lab: radius\n',
    'a: |\n  block\n  text\nb: >\n  folded\nc: "dq \\t x"\nd: \'sq \'\'x\'\'\'\ne: &x 1\nf: *x\ng: !!str 12\n',
]
SNIPPETS = ['{', '}', '[', ']', ': ', ':', '- ', '-', ',', '"', "'", '&a ', '*a', '!!str ', '!x ', '? ', '|', '>',
            '%YAML 1.1\n', '---\n', '...\n', '\t', '#', '@', '`', '\\', '\x01', '\x7f', 'é', '\u2028', '\x85',
            '\r', '\r\n', '\ufeff', '<<: ', '=', '~', '\n', '  ', ' ', 'null', 'yes', '0x', '1.5', '2026-10-01']


def mutate(text):
    s = text
    for _ in range(rng.randint(1, 3)):
        op = rng.random()
        pos = rng.randint(0, len(s))
        if op < 0.45:
            s = s[:pos] + rng.choice(SNIPPETS) + s[pos:]
        elif op < 0.65 and s:
            n = rng.randint(1, 3)
            s = s[:pos] + s[pos + n:]
        elif op < 0.8:
            lines = s.split('\n')
            i = rng.randrange(len(lines))
            lines[i] = (' ' * rng.randint(1, 3)) + lines[i] if rng.random() < 0.5 else lines[i].lstrip(' ')
            s = '\n'.join(lines)
        elif op < 0.9:
            lines = s.split('\n')
            i = rng.randrange(len(lines))
            lines.insert(i, lines[rng.randrange(len(lines))])
            s = '\n'.join(lines)
        else:
            lines = s.split('\n')
            if len(lines) > 1:
                del lines[rng.randrange(len(lines))]
            s = '\n'.join(lines)
    return s


def parse_record(data, tmp):
    path = os.path.join(tmp, 'tacctl.yaml')
    with open(path, 'wb') as f:
        f.write(data)
    rec = text_field(data)
    try:
        doc, problem = NS['load_overrides'](path)
    except Exception as e:  # what escaped load_overrides in 0.1.16
        rec['crash'] = type(e).__name__
        return rec
    rec['why'] = problem.replace(path, FILE)
    if not problem and doc:
        try:
            plain_yaml(data)
            rec['value'] = to_json(doc)
        except Unrepresentable as e:
            rec['unsupported'] = str(e)
    return rec


def plain_yaml(data):
    """Unrepresentable for an alias or a merge key anywhere in the document
    (the loaded value no longer shows them)."""
    text = data.decode('utf-8')
    if any(isinstance(e, yaml.AliasEvent) for e in yaml.parse(text, Loader=yaml.SafeLoader)):
        raise Unrepresentable('alias')
    todo = [yaml.compose(text, Loader=yaml.SafeLoader)]
    while todo:
        n = todo.pop()
        if isinstance(n, yaml.MappingNode):
            for k, v in n.value:
                if k.tag == 'tag:yaml.org,2002:merge':
                    raise Unrepresentable('merge')
                todo += [k, v]
        elif isinstance(n, yaml.SequenceNode):
            todo += n.value


def gen_parse():
    tmp = tempfile.mkdtemp(prefix='tacctl-gen-')
    try:
        docs, seen = [], set()

        def add(b):
            if b not in seen:
                seen.add(b)
                docs.append(b)
        for t in PARSE_HAND:
            add(t.encode('utf-8'))
        for b in [b'a: \xff\n', b'\xe2\x82', b'a: \xe2\x82x\n', b'a: \xed\xa0\x80\n', b'a: \xc0\xaf\n',
                  b'a: \xf4\x90\x80\x80\n', b'k: v\n' * 2000 + b'z: \xff\n', b'\xef\xbb\xbfa: 1\n']:
            add(b)
        while len(docs) < 2000:
            add(mutate(rng.choice(SEEDS)).encode('utf-8', 'surrogatepass'))
        records = [parse_record(d, tmp) for d in docs]
    finally:
        shutil.rmtree(tmp)
    write_jsonl('parse.jsonl', records)


# --- validate.jsonl -------------------------------------------------------------

PATHS = sorted(NS['SCHEMA']) + [
    'privileges.operator', 'commands.operator', 'commands.superuser', 'aaa.order.lab', 'exec_timeout.lab',
    'tacacs_group.lab', 'radius_group.lab', 'scope_auth_method.lab', 'scope_mgmt_acl.names.cisco.lab',
    'scope_mgmt_acl.names.juniper.lab', 'scope_mgmt_acl.permits.lab', 'listeners.tacacs.default',
    'listeners.tacacs.mgmt', 'listeners.radius.auth', 'listeners.radius.acct', 'listeners.radius.x',
    'listeners.ldap.auth', 'listeners.tacacs.Bad', 'listeners.tacacs.' + 'a' * 33,
    # not schema paths
    'bcrypt.cst', 'aaa.order', 'aaa.order.a.b', 'aaa.order.', 'listeners.tacacs', 'listeners.tacacs.a.b',
    'privileges.', 'exec_timeout..x', 'scope_mgmt_acl.names.cisco', 'scope_mgmt_acl.permits', '', 'x',
    'listeners..x', 'commands.a.b',
]

SCALARS = [
    None, True, False, 0, 1, -1, 7, 8, 9, 10, 12, 14, 15, 16, 20, 30, 59, 60, 61, 64, 65, 100, 101, 128, 129,
    2**70, 1.5, 12.0, float('nan'), float('inf'), datetime.date(2026, 10, 1), '', ' ', 'lab', 'prod', 'Lab',
    'lab\n', '1bad', 'a' * 32, 'a' * 33, 'tacplus', 'radius', 'tacacs', 'TACPLUS', 'tacacs-first', 'local-first',
    'VTY-ACL', 'A' * 63, 'A' * 64, 'bad name', 'ACL\n', 'ACL_1-x', 'é', "it's", 'x"y', 'back\\slash',
    '127.0.0.1:8080', ':8080', ':0', ':65535', ':65536', '[::1]:9090', 'localhost:9090', '127.0.0.1',
    '127.0.0.1:99999', 'host name:1', '[zz]:1', '10.0.0.0/8', 'garbage', 'show version', 'show; rm',
]
LISTS = [
    [], ['10.0.0.0/8'], ['10.0.0.0/8', 'garbage'], ['10.0.0.0/33'], ['fd00:10::/64', '192.168.1.0/24'], [1],
    [None], ['10.0.0.1'], [' 10.0.0.0/8'], ['show version'], ['show version', 'show; rm'], ['s'],
    ['show ' + 'x' * 60], ['show running-config\n'], ['tacacs'], ['radius', 'tacacs'], ['tacacs', 'tacacs'],
    ['ldap'], [True], [[1]], [{'name': '*', 'action': 'deny'}],
]
MAPPINGS = [
    {}, {'a': 1}, {'network': 'tcp', 'address': ':49'}, {'network': 'udp', 'address': ':1812', 'role': 'auth'},
    {'name': '*', 'action': 'deny'},
]

LISTENER_VALUES = [
    {'network': 'tcp', 'address': '10.1.0.1:4949'}, {'network': 'tcp', 'address': '10.1.0.1:4949', 'role': 'both',
                                                     'tls': {'enabled': False}},
    {'network': 'tcp6', 'address': '[::1]:4949'}, {'network': 'tcp', 'address': '[::1]:4952'},
    {'network': 'tcp6', 'address': '127.0.0.1:4952'}, {'network': 'tcp6', 'address': ':4951'},
    {'network': 'tcp', 'address': 'nonsense'}, {'network': 'tcp', 'address': ':0'},
    {'network': 'tcp', 'address': ':70000'}, {'network': 'tcp', 'address': 'host.example:49'},
    {'network': 'tcp'}, {'network': 'sctp', 'address': ':300'}, {'network': 'udp', 'address': ':300'},
    {'network': 'tcp', 'address': ':300', 'role': 'auth'}, {'network': 'tcp', 'address': ':300', 'role': 'bogus'},
    {'network': 'tcp', 'address': ':300', 'port': 49}, {'network': 'tcp', 'address': ':300', 'tls': {'cipher': 'x'}},
    {'network': 'tcp', 'address': ':300', 'tls': {'enabled': 'yes'}},
    {'network': 'tcp', 'address': ':300', 'metrics_address': 'nope'},
    {'network': 'tcp', 'address': ':300', 'metrics_address': ''}, {'network': 'tcp', 'address': ':300', 'metrics_address': None},
    {'network': 'tcp', 'address': ':300', 'metrics_address': 0},
    {'network': 'tcp', 'address': ':300', 'tls': {'enabled': True, 'cert': '/a', 'key': '/b'}},
    {'network': 'tcp', 'address': ':300', 'tls': {'enabled': False, 'cert': '/etc/c.pem', 'key': '/k',
                                                  'ca': '/ca', 'require_client_cert': True}},
    {'network': 'tcp', 'address': ':300', 'tls': None}, {'network': 'tcp', 'address': ':300', 'tls': []},
    {'network': 'tcp', 'address': ':300', 'tls': {'cert': 5}}, {'network': 'tcp', 'address': ':300', 'tls': {'cert': None}},
    {'network': 'tcp', 'address': ':300', 'tls': {'require_client_cert': None}},
    {'address': ':49'}, {'address': 49}, {'address': None}, {'network': None, 'address': ':49'}, {'network': 1.5},
    {'network': ['tcp'], 'address': ':49'}, {'network': 'udp6', 'address': '[fe80::1%eth0]:1812'},
    {'network': 'udp', 'address': ':1813', 'role': 'acct'}, {'network': 'udp', 'address': ':1812'},
    {'network': 'udp', 'address': '[10.0.0.1]:1812'}, {'network': 'udp', 'address': '0.0.0.0:1812', 'role': 'both'},
    {'network': 'tcp', 'address': '01.2.3.4:49'}, {'network': 'tcp', 'address': '1.2.3.4:049'},
    {'network': 'tcp', 'address': ':' + '9' * 30}, {'network': 'tcp', 'address': ' :49'},
    {'network': 'tcp', 'address': ':300', 'metrics_address': '[::1]:0'}, 'tcp :300', None, [],
    {'z': 1, 'b': 2, 'network': 'tcp'},
]

RULES = [
    [], 'x', [1], [{'name': '*', 'action': 'deny'}], [{'name': '*', 'action': 'permit'}],
    [{'name': 'show', 'action': 'permit'}, {'name': '*', 'action': 'deny'}],
    [{'name': 'show', 'action': 'permit'}], [{'name': '*', 'action': 'deny'}, {'name': 'show', 'action': 'permit'}],
    [{'name': 'show', 'action': 'allow'}, {'name': '*', 'action': 'deny'}],
    [{'name': '1show', 'action': 'permit'}, {'name': '*', 'action': 'deny'}],
    [{'name': None, 'action': 'permit'}], [{'name': 'show\n', 'action': 'permit'}, {'name': '*', 'action': 'deny'}],
    [{'name': 'show', 'action': 'permit', 'match': ['^running-config$']}, {'name': '*', 'action': 'deny'}],
    [{'name': 'show', 'action': 'permit', 'match': ['^show .*$']}, {'name': '*', 'action': 'deny'}],
    [{'name': 'show', 'action': 'permit', 'match': ['^show$']}, {'name': '*', 'action': 'deny'}],
    [{'name': 'ping', 'action': 'permit', 'match': ['^ping( .*)?$']}, {'name': '*', 'action': 'deny'}],
    [{'name': 'show', 'action': 'permit', 'match': 'x'}, {'name': '*', 'action': 'deny'}],
    [{'name': 'show', 'action': 'permit', 'match': [1]}, {'name': '*', 'action': 'deny'}],
    [{'name': 'show', 'action': 'permit', 'match': None}, {'name': '*', 'action': 'deny'}],
    [{'name': 'show', 'action': 'permit', 'extra': 1, 'zz': 2}, {'name': '*', 'action': 'deny'}],
    [{'name': 'show', 'action': 'permit'}, {'name': 'ping', 'action': 'deny'}],
    [{'name': '*', 'action': None}], ['show'], [{'name': 'x' * 33, 'action': 'deny'}, {'name': '*', 'action': 'deny'}],
]

COERCE = ['', ' ', '14', ' 14 ', '+14', '-1', '1_4', '1__4', '_14', '14_', '0x10', '012', '١٤', '1.5', ' 1.5 ',
          '1.', '.5', '1.2.3', '10.0.0.1', '1e5', '1.5e3', 'nan', 'nan.', 'inf', 'inf.', 'Infinity.', 'true', 'True',
          'TRUE', 'tRuE', 'false', 'null', 'NULL', 'None', 'yes', 'no', '~', 'lab', 'lab ', '127.0.0.1:8080',
          '99999999999999999999999', '-0', '٣.٥', '1_000.5', '1_.5', '1._5', '0.0', 'x.y']


def gen_validate():
    validate = NS['validate']
    records = []
    values = SCALARS + LISTS + MAPPINGS
    for path in PATHS:
        for v in values:
            # set_list always passes a list, conf_set never does; a list
            # read from a file or JSON is checked as a list.
            for is_list in ((False, True) if isinstance(v, list) else (False,)):
                ok, msg = validate(path, v, is_list)
                records.append({'path': path, 'value': to_json(v, True), 'is_list': is_list, 'msg': msg})
    for path in ('listeners.tacacs.default', 'listeners.tacacs.mgmt', 'listeners.radius.auth', 'listeners.radius.y'):
        for v in LISTENER_VALUES:
            ok, msg = validate(path, v, isinstance(v, list))
            rec = {'path': path, 'value': to_json(v), 'is_list': isinstance(v, list), 'msg': msg}
            if ok:
                rec['compact'] = to_json(NS['listener_compact'](path.split('.')[1], v))
                rec['implicit'] = to_json(NS['implicit_default'](path))
            records.append(rec)
    for v in RULES:
        ok, msg = validate('commands.operator', v, isinstance(v, list))
        records.append({'path': 'commands.operator', 'value': to_json(v), 'is_list': isinstance(v, list), 'msg': msg})
    write_jsonl('validate.jsonl', records)

    coerce = NS.get('coerce_scalar')
    if coerce is None:
        # coerce_scalar lives in _conf_write's body; take it from there.
        body = heredoc('_conf_write', '<<PY', 'PY')
        start = body.index('def coerce_scalar')
        end = body.index('\n# ---', start)
        exec(body[start:end], NS)
        coerce = NS['coerce_scalar']
    recs = []
    for s in COERCE:
        v = coerce(s)
        recs.append({'in': s, 'type': type(v).__name__, 'repr': repr(v)})
    write_jsonl('coerce.jsonl', recs)


# --- listeners.jsonl --------------------------------------------------------------

def rand_listener():
    net = rng.choice(['tcp', 'tcp6', 'udp', 'udp6', 'tcp', 'udp', None])
    host = rng.choice(['', '', '10.1.0.1', '10.1.0.2', '0.0.0.0', '[::]', '[::1]', '[10.1.0.1]', '127.0.0.1', 'x'])
    port = rng.choice([49, 300, 301, 1812, 1813, 4949])
    v = {}
    if net is not None:
        v['network'] = net
    v['address'] = f'{host}:{port}'
    r = rng.random()
    if r < 0.2:
        v['role'] = rng.choice(['auth', 'acct', 'both'])
    if rng.random() < 0.25:
        v['metrics_address'] = rng.choice(['127.0.0.1:9100', '127.0.0.1:9101', '127.0.0.1:0', ''])
    if rng.random() < 0.1:
        v['tls'] = {'cert': '/c', 'require_client_cert': rng.random() < 0.5}
    if rng.random() < 0.05:
        v = rng.choice(['x', 5, None, []])
    return v


def gen_listeners():
    records = []
    docs = [{}, {'listeners': None}, {'listeners': []}, {'listeners': 'x'}, {'listeners': {'tacacs': None}},
            {'listeners': {'tacacs': {'a': {'address': ':49'}, 'b': 5}}},
            {'listeners': {'tacacs': {'default': {'address': 'nonsense'}, 'bad': {'network': 'udp', 'address': ':300'},
                                      'good': {'address': ':301'}}}},
            {'listeners': {'radius': {'auth': {'network': 'udp6', 'address': ':1812'}}}},
            {'listeners': {'ldap': {'x': {'address': ':1'}}}}]
    for _ in range(300):
        doc = {'listeners': {}}
        for backend in rng.sample(['tacacs', 'radius', 'tacacs'], rng.randint(1, 2)):
            names = rng.sample(['default', 'auth', 'acct', 'mgmt', 'a', 'b', 'zeta', 'Bad'], rng.randint(1, 4))
            doc['listeners'][backend] = {n: rand_listener() for n in names}
        docs.append(doc)
    for doc in docs:
        rec = {'doc': to_json(doc), 'effective': {}, 'problems': NS['listeners_problems'](doc), 'only': {}}
        for backend in ('tacacs', 'radius', 'ldap'):
            rec['effective'][backend] = [dict(v, name=k) for k, v in NS['listeners_effective'](doc, backend).items()]
        sec = doc.get('listeners')
        if isinstance(sec, dict):
            for b, mine in sec.items():
                if isinstance(mine, dict):
                    for n in mine:
                        p = f'listeners.{b}.{n}'
                        rec['only'][p] = NS['listeners_problems'](doc, only=p)
        records.append(rec)
    write_jsonl('listeners.jsonl', records)


# --- py.jsonl ----------------------------------------------------------------------

def gen_py():
    recs = []
    floats = [0.0, -0.0, 1.0, 1.5, 0.1, 1e16, 1e15, 123456789012345678.0, 1e22, 1e-5, 0.0001, 5e-324, 1.7976931348623157e308,
              float('inf'), float('-inf'), float('nan'), 100.0, 12345.678, 1e-4, 9.999999999999999e15, 2.5e-7]
    for _ in range(300):
        floats.append(rng.choice([rng.uniform(-1e6, 1e6), rng.uniform(-1, 1) * 10 ** rng.randint(-30, 30),
                                  float(rng.randint(-10**17, 10**17)), rng.random()]))
    for f in floats:
        recs.append({'value': to_json(f), 'repr': repr(f), 'str': str(f), 'json': json.dumps(f)})
    strings = ['', 'a', "it's", 'x"y', 'both\'"', 'back\\slash', 'tab\there', 'nl\nx', 'cr\rx', '\x00\x01\x1f\x7f',
               'é', '\x85\xa0', '\u2028\u2029', '\ufeff', '\U0001F600', '\u0378', '\ue000', '\u200b', 'ÿ\u0100']
    for _ in range(200):
        strings.append(''.join(chr(rng.choice([rng.randint(0x20, 0x7e), rng.randint(0, 0x20), rng.randint(0x80, 0x3000),
                                               rng.randint(0x10000, 0x1F9FF)])) for _ in range(rng.randint(0, 6))))
    for s in strings:
        recs.append({'value': s, 'repr': repr(s), 'str': s, 'json': json.dumps(s)})
    others = [None, True, False, 0, -7, 2**64, [], [1, 'a', None, True, 1.5], {}, {'a': [1, {'b': None}], "c'": 'd'},
              datetime.date(2026, 10, 1)]
    for v in others:
        rec = {'value': to_json(v) if not (isinstance(v, int) and v >= 2**63) else {'$bigint': str(v)},
               'repr': repr(v), 'str': str(v)}
        try:
            rec['json'] = json.dumps(v)
        except TypeError:
            rec['json'] = None
        recs.append(rec)
    write_jsonl('py.jsonl', recs)


# --- bash.jsonl and the golden -------------------------------------------------------

GOLDEN_OPS = [
    ['set', 'password.max_age_days', '180'],
    ['set', 'password.min_length', '14'],
    ['set', 'secret.min_length', '24'],
    ['set', 'bcrypt.cost', '13'],
    ['set', 'scope.default', 'prod'],
    ['set', 'host.default_method', 'radius'],
    ['set', 'mgmt_acl.names.cisco', 'MGMT-VTY'],
    ['set', 'mgmt_acl.names.juniper', 'MGMT-LO0'],
    ['set_list', 'mgmt_acl.permits', ['10.0.0.0/8', '192.168.1.0/24', 'fd00:10::/64']],
    ['set_list', 'backends.enabled', ['tacacs', 'radius']],
    ['set', 'backends.tacacs.level', '30'],
    ['set', 'backends.tacacs.metrics_address', '127.0.0.1:9090'],
    ['set_list', 'privileges.operator', ['show running-config', 'show version']],
    ['set_json', 'commands.operator', json.dumps([
        {'name': 'show', 'action': 'permit', 'match': ['^running-config$', '^version$']},
        {'name': 'ping', 'action': 'permit'}, {'name': '*', 'action': 'deny'}])],
    ['set', 'aaa.order.lab', 'local-first'],
    ['set', 'aaa.order.on', 'local-first'],
    ['set', 'exec_timeout.lab', '15'],
    ['set', 'tacacs_group.lab', 'TACACS_PROD'],
    ['set', 'radius_group.lab', 'RADIUS_PROD'],
    ['set', 'scope_auth_method.lab', 'radius'],
    ['set', 'scope_mgmt_acl.names.cisco.lab', 'LAB-VTY'],
    ['set', 'scope_mgmt_acl.names.juniper.lab', 'LAB-MGMT'],
    ['set_list', 'scope_mgmt_acl.permits.lab', ['10.99.0.0/16']],
    ['set_json', 'listeners.tacacs.mgmt', json.dumps({
        'network': 'tcp', 'address': '10.1.0.1:4949', 'role': 'both', 'metrics_address': '127.0.0.1:9100',
        'tls': {'enabled': False, 'cert': '/etc/tacctl/tls/cert.pem', 'require_client_cert': True}})],
    ['set_json', 'listeners.radius.acct', json.dumps({'network': 'udp', 'address': ':1814', 'role': 'acct'})],
    ['set', 'mgmt_acl.names.cisco', 'VTY-ACL'],
    ['set', 'mgmt_acl.names.cisco', 'CUSTOM-VTY'],
    ['unset', 'exec_timeout.nonexistent'],
]

BROKEN = 'bcrypt:\n  cost: 14\ncommands: [unterminated\n'

BASH_CASES = [
    # (before, ops)
    (None, [['get', 'bcrypt.cost'], ['get', 'nonexistent.key'], ['get', 'nonexistent.key', 'my-fallback'],
            ['get', 'mgmt_acl.names.cisco'], ['get', 'mgmt_acl.permits'], ['get_list', 'privileges.operator'],
            ['get_list', 'commands.operator'], ['get_keys', 'mgmt_acl.names'], ['get_keys', 'bcrypt.cost'],
            ['get_keys', ''], ['get', ''], ['get_json', 'commands.readonly'], ['get_json', 'nonexistent'],
            ['get_json', ''], ['get_json', 'mgmt_acl'], ['has_override', 'bcrypt.cost'], ['validate'], ['dump']]),
    (None, [['set', 'bcrypt.cost', '14'], ['get', 'bcrypt.cost'], ['set', 'bcrypt.cost', '12'],
            ['has_override', 'bcrypt.cost']]),
    (None, [['set', 'password.max_age_days', '180'], ['get', 'password.min_length'], ['dump']]),
    (None, [['set', 'bcrypt.cost', '14'], ['set', 'scope.default', 'prod']]),
    (None, [['set', 'mgmt_acl.names.cisco', 'CUSTOM'], ['unset', 'mgmt_acl.names.cisco']]),
    (None, [['set', 'bcrypt.cost', '14'], ['unset', 'nonexistent.key'], ['get', 'bcrypt.cost']]),
    (None, [['set_list', 'mgmt_acl.permits', ['10.0.0.0/8', '192.168.1.0/24']], ['get_list', 'mgmt_acl.permits'],
            ['set_list', 'mgmt_acl.permits', []]]),
    (None, [['set_raw_list', 'mgmt_acl.permits', '10.0.0.0/8\n\n  \n 192.168.1.0/24 \r\n10.1.0.0/16\r10.2.0.0/16']]),
    (None, [['set', 'bcrypt.cost', '99'], ['set', 'bcrypt.cost', 'abc'], ['set', 'bcrypt.cst', '14'],
            ['set', 'mgmt_acl.names.cisco', '1bad-start'], ['set', 'aaa.order.lab', 'garbage'],
            ['set', 'aaa.order', 'tacacs-first'], ['set_list', 'mgmt_acl.permits', ['10.0.0.0/8', 'garbage']],
            ['set_list', 'privileges.operator', ['show version', 'show; rm']], ['set', 'mgmt_acl.permits', '10.0.0.0/8'],
            ['set_list', 'bcrypt.cost', ['12']], ['set', 'scope.default', '1.5'], ['set', 'scope.default', 'TRUE'],
            ['set', 'scope.default', 'null'], ['get', 'scope.default', 'fb'], ['set', 'exec_timeout.lab', '-1'],
            ['set', 'exec_timeout.lab', '61'], ['set', 'exec_timeout.lab', 'forever'], ['set', 'tacacs_group.lab', ''],
            ['set', 'tacacs_group.lab', 'A' * 64], ['set', 'scope_auth_method.lab', 'tacplus'],
            ['set', 'scope_auth_method', 'radius'], ['set', 'password.max_age_days', ' 1_80 ']]),
    (None, [['set', 'aaa.order.lab', 'local-first'], ['set', 'aaa.order.prod', 'local-first'],
            ['set', 'aaa.order.lab', 'tacacs-first'], ['get', 'aaa.order.lab'], ['get', 'aaa.order.prod'],
            ['set', 'aaa.order.prod', 'tacacs-first']]),
    (None, [['set', 'exec_timeout.lab', '15'], ['set', 'exec_timeout.lab', '60'], ['set', 'tacacs_group.lab', 'TACACS_PROD'],
            ['set', 'radius_group.lab', 'RADIUS_PROD'], ['get', 'tacacs_group.lab'], ['set', 'tacacs_group.lab', 'TACACS-GROUP'],
            ['set', 'radius_group.lab', 'RADIUS-GROUP']]),
    (None, [['set', 'scope_mgmt_acl.names.cisco.lab', 'LAB-VTY'], ['set', 'scope_mgmt_acl.names.cisco.lab', 'VTY-ACL'],
            ['set_list', 'mgmt_acl.permits', ['10.0.0.0/8']], ['set_list', 'scope_mgmt_acl.permits.lab', ['10.99.0.0/16']],
            ['get_list', 'mgmt_acl.permits'], ['set_list', 'scope_mgmt_acl.permits.lab', []]]),
    (None, [['set', 'scope_auth_method.lab', 'tacacs'], ['set', 'scope_auth_method.lab', 'radius'],
            ['unset', 'scope_auth_method.lab']]),
    (None, [['set_json', 'listeners.tacacs.mgmt', '{"network": "tcp", "address": "10.1.0.1:4949", "role": "both", "tls": {"enabled": false}}'],
            ['set_json', 'listeners.tacacs.default', '{"network": "tcp", "address": "10.1.0.1:49"}'],
            ['set_json', 'listeners.tacacs.default', '{"network": "tcp", "address": ":49"}'],
            ['set_json', 'listeners.tacacs.a', '{"network": "tcp", "address": "10.1.0.1:4949"}'],
            ['set_json', 'listeners.tacacs.b', '{"network": "tcp", "address": "10.1.0.2:4949"}'],
            ['set_json', 'listeners.tacacs.default', '{"network": "tcp", "address": "10.1.0.2:4949"}'],
            ['set_json', 'listeners.tacacs.c', '{"network": "tcp", "address": ":300", "metrics_address": "127.0.0.1:9100"}'],
            ['set_json', 'listeners.tacacs.d', '{"network": "tcp", "address": ":301", "metrics_address": "127.0.0.1:9100"}'],
            ['set_json', 'listeners.radius.auth', '{"network": "udp", "address": ":1812", "role": "auth"}'],
            ['set_json', 'listeners.radius.acct', '{"network": "udp", "address": ":1813", "role": "acct"}'],
            ['set_json', 'listeners.radius.x', '{"network": "udp", "address": ":49"}'],
            ['set_json', 'listeners.tacacs.tls', '{"network": "tcp", "address": ":302", "tls": {"enabled": true}}'],
            ['set_json', 'listeners.tacacs.e', ''], ['set_json', 'listeners.tacacs.e', '{bad json'],
            ['set_json', 'listeners.tacacs', '{"x": {"address": ":300"}}'], ['set', 'listeners.tacacs.x', ':300'],
            ['unset', 'listeners.tacacs.a'], ['validate'], ['get_json', 'listeners'], ['dump']]),
    (None, [['set', 'backends.tacacs.level', '30'], ['set', 'backends.tacacs.level', '20'],
            ['set', 'backends.tacacs.level', 'debug'], ['set', 'backends.tacacs.level', '101'],
            ['set', 'backends.tacacs.metrics_address', ':9090'], ['set', 'backends.tacacs.metrics_address', 'localhost:9090'],
            ['set', 'backends.tacacs.metrics_address', '[::1]:9090'], ['set', 'backends.tacacs.metrics_address', '127.0.0.1:8080'],
            ['set', 'backends.tacacs.metrics_address', '127.0.0.1'], ['set_list', 'backends.enabled', ['tacacs']],
            ['set_list', 'backends.enabled', ['radius']], ['set_list', 'backends.enabled', []],
            ['set_list', 'backends.enabled', ['ldap']], ['get_list', 'backends.enabled']]),
    (None, [['set_json', 'commands.operator', '[{"name": "show", "action": "permit", "match": ["^show .*$"]}, {"name": "*", "action": "deny"}]'],
            ['set_json', 'commands.operator', '[{"name": "show", "action": "permit"}, {"name": "*", "action": "deny"}]'],
            ['set_json', 'commands.operator', '[{"name": "show", "action": "permit"}, {"name": "ping", "action": "permit"}, {"name": "traceroute", "action": "permit"}, {"name": "terminal", "action": "permit"}, {"name": "*", "action": "deny"}]'],
            ['set_json', 'commands.lab', '[{"name": "*", "action": "deny"}]'], ['get_list', 'commands.lab'],
            ['get_json', 'commands.lab'], ['get_keys', 'commands']]),
    (BROKEN, [['get', 'bcrypt.cost'], ['set', 'password.max_age_days', '30'], ['unset', 'bcrypt.cost'],
              ['set_list', 'mgmt_acl.permits', ['10.0.0.0/8']], ['set_json', 'commands.operator', '[{"name": "*", "action": "deny"}]'],
              ['set', 'bcrypt.cost', '99'], ['has_override', 'bcrypt.cost'], ['validate'], ['dump']]),
    ('- bcrypt\n', [['set', 'bcrypt.cost', '13'], ['get', 'bcrypt.cost'], ['validate']]),
    ('', [['set', 'bcrypt.cost', '13'], ['get', 'bcrypt.cost']]),
    ('# only comments\n', [['unset', 'nonexistent']]),
    ('bcrypt:\n\tcost: 14\n', [['get', 'bcrypt.cost'], ['set', 'bcrypt.cost', '13'], ['validate']]),
    ('a: b\x01\n', [['get', 'bcrypt.cost'], ['set', 'bcrypt.cost', '13'], ['validate']]),
    ('a: "\\q"\n', [['set', 'bcrypt.cost', '13'], ['validate']]),
    ('bcrypt:\n  cost: 99\n', [['validate'], ['get', 'bcrypt.cost']]),
    ('bcrypt:\n  cst: 14\n', [['validate']]),
    ('mgmt_acl:\n  permits:\n    - 10.0.0.0/8\n    - garbage\n', [['validate'], ['get_list', 'mgmt_acl.permits']]),
    ('listeners:\n  tacacs:\n    tls: {network: tcp, address: ":300", tls: {enabled: true}}\n', [['validate']]),
    ('listeners:\n  tacacs:\n    a: {address: ":49"}\n    b: 5\n', [['validate']]),
    ('listeners:\n  tacacs:\n    default: {address: "nonsense"}\n    bad: {network: udp, address: ":300"}\n    good: {address: ":301"}\n',
     [['validate'], ['get_json', 'listeners']]),
    ('bcrypt:\n  cost: 8\n', [['tunables']]),
    ('bcrypt:\n  cost: 99\n', [['tunables']]),
    ('bcrypt:\n  cost: hello\n', [['tunables']]),
    ('bcrypt:\n  cost: 11\n', [['tunables']]),
    ('bcrypt:\n  cost: 14\npassword:\n  min_length: 8\nsecret:\n  min_length: 128\n', [['tunables']]),
    ('password:\n  min_length: 64\n', [['tunables']]),
    ('password:\n  min_length: 7\n', [['tunables']]),
    ('password:\n  min_length: 65\n', [['tunables']]),
    ('secret:\n  min_length: 15\n', [['tunables']]),
    ('secret:\n  min_length: 129\n', [['tunables']]),
    ('secret:\n  min_length: 16\n', [['tunables']]),
    ('password:\n  max_age_days: 0\n', [['tunables']]),
    ('password:\n  max_age_days: 5000\n', [['tunables']]),
    ('password:\n  max_age_days: 1.5\nbcrypt:\n  cost: "13"\n', [['tunables']]),
    ('bcrypt:\n  cost: [13]\n', [['tunables'], ['get', 'bcrypt.cost', 'fb']]),
    ('bcrypt:\n  cost: null\n', [['tunables'], ['get', 'bcrypt.cost', 'fb']]),
    ('bcrypt:\n  cost: true\n', [['tunables'], ['get', 'bcrypt.cost']]),
    ('bcrypt: 5\n', [['get', 'bcrypt.cost', 'fb'], ['validate'], ['set', 'bcrypt.cost', '13']]),
    ('mgmt_acl:\n  permits: 5\n', [['set_list', 'scope_mgmt_acl.permits.lab', ['10.0.0.0/8']], ['set', 'mgmt_acl.names.cisco', 'X']]),
    ('x: {y: {}}\nbcrypt: {cost: 13}\n', [['unset', 'x.y.z'], ['unset', 'x.y'], ['unset', 'bcrypt.cost']]),
    ('privileges:\n  operator: []\n', [['get_list', 'privileges.operator'], ['set_list', 'privileges.operator',
                                        ['show running-config', 'show startup-config', 'show tech-support', 'show archive',
                                         'show access-list', 'show ip route']]]),
    # (A date anywhere in tacctl.yaml makes 0.1.16 exit at start-up: json.dumps
    # of the merged view fails. tacctl 0.2.0 reads it; not recorded here.)
    ('a: 1.5\nb: .inf\nc: "2026-10-01"\nd: 0x1F\ne: "x"\nf: yes\n', [['get', 'a'], ['get', 'b'], ['get', 'd'],
                                                                  ['get', 'f'], ['get', 'e'], ['get_json', 'a'], ['validate']]),
    ('a: [x, 1, null, true, {k: v}, [1]]\n', [['get_list', 'a'], ['get_json', 'a']]),
    ('commands:\n  operator:\n  - name: show\n    action: permit\n    match: ["(unclosed"]\n  - {name: "*", action: deny}\n', [['validate']]),
    ('scope:\n  default: null\n', [['get', 'scope.default', 'fb'], ['has_override', 'scope.default'], ['validate']]),
    ("aaa:\n  order:\n    'on': local-first\n", [['get', 'aaa.order.on'], ['set', 'aaa.order.on', 'tacacs-first']]),
    ('bcrypt:\n  cost: 14\n# trailing comment\n', [['set', 'secret.min_length', '20'], ['dump']]),
]


def gen_bash():
    work = tempfile.mkdtemp(prefix='tacctl-gen-')
    try:
        tree = os.path.join(work, 'tree')
        os.makedirs(tree)
        archive = subprocess.run(['git', '-C', ROOT, 'archive', TAG, 'bin', 'lib', 'config', 'patches'],
                                 check=True, capture_output=True).stdout
        subprocess.run(['tar', '-x', '-C', tree], input=archive, check=True)
        records = [run_bash_case(tree, work, i, before, ops) for i, (before, ops) in enumerate(BASH_CASES)]
        write_jsonl('bash.jsonl', records)
        golden = run_bash_case(tree, work, 'golden', None, GOLDEN_OPS)
        for r in golden['results']:
            if r['rc'] != 0:
                sys.exit(f'gen.py: golden op failed: {r}')
        with open(os.path.join(HERE, 'golden-ops.json'), 'w', encoding='utf-8') as f:
            json.dump(GOLDEN_OPS, f, indent=1)
            f.write('\n')
        out = os.path.join(ROOT, 'tests', 'fixtures', 'golden', 'tacctl.overrides.yaml')
        with open(out, 'w', encoding='utf-8', newline='') as f:
            f.write(golden['after'])
        value = yaml.safe_load(golden['after'])
        os.makedirs(os.path.join(HERE, 'pyyaml'), exist_ok=True)
        with open(os.path.join(HERE, 'pyyaml', 'every-key.json'), 'w', encoding='utf-8') as f:
            json.dump(to_json(value), f, indent=1, ensure_ascii=True)
            f.write('\n')
        with open(os.path.join(HERE, 'pyyaml', 'PYYAML_VERSION'), 'w', encoding='ascii') as f:
            f.write(yaml.__version__ + '\n')
        print('gen.py: wrote tests/fixtures/golden/tacctl.overrides.yaml and testdata/pyyaml/every-key.json; '
              'now run: python3 tests/tools/pyyaml-corpus.py internal/conf/testdata/pyyaml')
    finally:
        shutil.rmtree(work)


def run_bash_case(tree, work, name, before, ops):
    case = os.path.join(work, f'case-{name}')
    state = os.path.join(case, 'state')
    out = os.path.join(case, 'out')
    for d in (state, out, os.path.join(case, 'etc')):
        os.makedirs(d)
    path = os.path.join(state, 'tacctl.yaml')
    if before is not None:
        with open(path, 'wb') as f:
            f.write(before.encode('utf-8'))
    lines = ['set -u', f'source {tree}/bin/tacctl.sh 2> {out}/source.err', 'set +e +o pipefail',
             f'printf "%s %s %s %s" "$PASSWORD_MAX_AGE_DAYS" "$BCRYPT_COST" "$PASSWORD_MIN_LENGTH" '
             f'"$SECRET_MIN_LENGTH" > {out}/tunables']
    for i, op in enumerate(ops):
        argf = []
        for j, a in enumerate(op[1:]):
            p = f'{out}/{i}.arg{j}'
            with open(p, 'w', encoding='utf-8') as f:
                f.write('\n'.join(a) + ('\n' if a else '') if isinstance(a, list) else a)
            argf.append(p)
        rd = lambda k: f'"$(cat {argf[k]}; printf x)"'  # noqa: E731
        redir = f'> {out}/{i}.out 2> {out}/{i}.err; echo $? > {out}/{i}.rc'
        kind = op[0]
        if kind in ('set', 'set_json'):
            lines.append(f'a0={rd(0)}; a1={rd(1)}; conf_{kind} "${{a0%x}}" "${{a1%x}}" {redir}')
        elif kind in ('set_list', 'set_raw_list'):
            lines.append(f'a0={rd(0)}; conf_set_list "${{a0%x}}" < {argf[1]} {redir}')
        elif kind in ('unset', 'get_list', 'get_keys', 'get_json', 'has_override'):
            lines.append(f'a0={rd(0)}; conf_{kind} "${{a0%x}}" {redir}')
        elif kind == 'get':
            if len(op) > 2:
                lines.append(f'a0={rd(0)}; a1={rd(1)}; conf_get "${{a0%x}}" "${{a1%x}}" {redir}')
            else:
                lines.append(f'a0={rd(0)}; conf_get "${{a0%x}}" {redir}')
        elif kind == 'validate':
            lines.append(f'_conf_validate_overrides_file {redir}')
        elif kind == 'dump':
            lines.append(f'cmd_config_dump {redir}')
        elif kind == 'tunables':
            lines.append(f'cat {out}/tunables {redir}')
        else:
            raise ValueError(kind)
    env = {'PATH': '/usr/bin:/bin', 'HOME': work, 'LANG': 'C.UTF-8', 'TACCTL_STATE_DIR': state,
           'TACCTL_ETC': os.path.join(case, 'etc'), 'TACCTL_SKIP_SUDO': '1'}
    subprocess.run(['bash', '-c', '\n'.join(lines)], env=env, check=False, cwd=case)

    def read(p):
        with open(p, 'rb') as f:
            return f.read().decode('utf-8', 'surrogateescape').replace(path, FILE)
    if not os.path.exists(f'{out}/tunables'):
        sys.exit(f'gen.py: case {name}: sourcing tacctl.sh failed: {read(f"{out}/source.err")}')
    rec = {'before': before, 'ops': ops, 'source_err': read(f'{out}/source.err'), 'results': []}
    for i in range(len(ops)):
        rec['results'].append({'rc': int(read(f'{out}/{i}.rc')), 'out': read(f'{out}/{i}.out'),
                               'err': read(f'{out}/{i}.err')})
    rec['after'] = read(path) if os.path.exists(path) else None
    return rec


if __name__ == '__main__':
    gen_parse()
    gen_validate()
    gen_listeners()
    gen_py()
    gen_bash()
