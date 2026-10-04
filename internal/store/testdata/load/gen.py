#!/usr/bin/env python3
"""Write internal/store/testdata/load/expected.jsonl: what tacctl 0.1.16
says when it loads a store.yaml, for files that load and for every way a
file can fail to (internal/store's TestLoadErrorsAs0116 replays them).

    internal/store/testdata/load/gen.sh

runs it with the program _store_python runs at the 0.1.16 tag
(lib/store.sh _store_py, lib/model.sh _model_py, _store_main_py). Each
line is one case:

    {"name": ..., "yaml": text | "yaml_hex": bytes | "fixture": name
                | "kind": "missing" | "directory",
     "unreadable": true (the file is mode 000),
     "dump": {"rc": N, "stdout": ..., "stderr": ...},
     "validate": {"rc": N, "stderr": ...} | {"not_found": true}}

dump is 'dump-store <file>' (model_load's store branch), validate is
'validate <file>' behind store_validate's '[[ -f ]]' test (not_found:
store_validate prints "Store not found at <file>." without running
python). The file's path is written as FILE in stderr. When 0.1.16 dies
with a Python traceback, stderr is replaced by {"crash": <its last line>}:
those cases are go-rewrite plan 3.9 items 15 and 16, which the Go test
words itself.
"""
import json
import os
import subprocess
import sys

prog, work, fixtures = sys.argv[1], sys.argv[2], sys.argv[3]
os.makedirs(work)
FILE = os.path.join(work, 'store.yaml')
ENV = dict(os.environ, TACCTL_STORE_NOT_INITIALISED_MSG='store not initialised', LC_ALL='C.UTF-8')

BUILTINS = ('groups:\n'
            '  readonly: {priv_lvl: 1, juniper_class: READ-ONLY, builtin: true}\n'
            '  operator: {priv_lvl: 7, juniper_class: OPERATOR, builtin: true}\n'
            '  superuser: {priv_lvl: 15, juniper_class: SUPER-USER, builtin: true}\n')
HASH = '$2b$12$' + 'A' * 53
DIGITS = '2432622431322441414141414141414141414141414141414141414141414141'

CASES = [
    # Files that load.
    ('fixture-minimal', {'fixture': 'store.minimal.yaml'}),
    ('fixture-multiscope', {'fixture': 'store.multiscope.yaml'}),
    ('fixture-radius', {'fixture': 'store.radius.yaml'}),
    ('empty', {'yaml': ''}),
    ('comments-only', {'yaml': '# nothing here\n\n'}),
    ('explicit-document', {'yaml': '---\nversion: 1\n...\n'}),
    ('null-document', {'yaml': '~\n'}),
    ('unquoted-date', {'yaml': 'version: 1\n' + BUILTINS + 'users:\n  alice: {group: readonly, scopes: [], hash: null, '
                                'disabled: true, password_changed: 2026-10-01}\n'}),
    ('crlf', {'yaml': 'version: 1\r\nfilters: {allow: [10.0.0.0/8], deny: []}\r\n'}),
    ('yaml11-scalars', {'yaml': 'version: 0x1\nextra: [yes, No, ~, 0o12, 012, 1_000, 1:30, .5, +.inf, 2026-1-2]\n'}),
    # A top level that is not a mapping.
    ('top-list', {'yaml': '- version\n- 1\n'}),
    ('top-scalar', {'yaml': 'just some text\n'}),
    ('top-int', {'yaml': '42\n'}),
    ('top-date', {'yaml': '2026-10-01\n'}),
    ('top-set', {'yaml': '!!set {a, b}\n'}),
    ('section-not-mapping', {'yaml': 'version: 1\ngroups: [readonly]\n'}),
    ('entry-not-mapping', {'yaml': 'version: 1\nscopes:\n  lab: 10.0.0.0/8\n'}),
    ('filters-not-mapping', {'yaml': 'version: 1\nfilters: [10.0.0.0/8]\n'}),
    # YAML errors: yaml_problem's '<path>: <problem> (line L, column C)'.
    ('unclosed-flow', {'yaml': 'version: 1\nscopes: {lab: {secret: "leaky-secret-0123456789"\n'}),
    ('unclosed-flow-seq', {'yaml': 'version: 1\nfilters: {allow: [10.0.0.0/8\n'}),
    ('unclosed-quote', {'yaml': "version: 1\nscopes:\n  lab: {secret: 'leaky-secret\n"}),
    ('mapping-values', {'yaml': 'version: 1\nusers: alice: bob\n'}),
    ('tab-indent', {'yaml': 'version: 1\nusers:\n\talice: {}\n'}),
    ('bad-indent', {'yaml': 'version: 1\nusers:\n    alice: {}\n  bob: {}\n'}),
    ('block-end', {'yaml': 'version: 1\n- x\n'}),
    ('two-documents', {'yaml': 'version: 1\n---\nversion: 1\n'}),
    ('undefined-alias', {'yaml': 'version: 1\nfilters: *nowhere\n'}),
    ('duplicate-anchor', {'yaml': 'a: &x 1\nb: &x 2\n'}),
    ('unknown-tag', {'yaml': 'version: 1\nscopes: !secret {lab: {}}\n'}),
    ('unhashable-key', {'yaml': 'version: 1\n? [a, b]\n: 1\n'}),
    ('unknown-escape', {'yaml': 'version: 1\nscopes: {lab: {secret: "s\\qx"}}\n'}),
    ('control-char', {'yaml': 'version: 1\nscopes: {lab: {secret: s\x01x}}\n'}),
    ('bom-inside', {'yaml': 'version: 1\nnote: a\ufeffb\n'}),
    ('directive', {'yaml': '%YAML 1.1\n%YAML 1.1\n---\na: 1\n'}),
    ('anchor-no-name', {'yaml': 'a: & x\n'}),
    ('at-sign', {'yaml': 'a: @x\n'}),
    # Unreadable files.
    ('missing', {'kind': 'missing'}),
    ('directory', {'kind': 'directory'}),
    ('unreadable', {'yaml': 'version: 1\n', 'unreadable': True}),
    # What 0.1.16 died on (go-rewrite plan 3.9 item 16).
    ('not-utf8', {'yaml_hex': ('version: 1\nnote: caf\xe9\n').encode('latin-1').hex()}),
    ('not-utf8-late', {'yaml_hex': ('version: 1\n# ' + 'x' * 9000 + '\nnote: \xff\n').encode('latin-1').hex()}),
    ('bad-int', {'yaml': 'version: !!int one\n'}),
    ('bad-bool', {'yaml': 'version: 1\nusers: {alice: {disabled: !!bool maybe}}\n'}),
    ('bad-float', {'yaml': 'version: !!float abc\n'}),
    ('impossible-date', {'yaml': 'version: 1\n' + BUILTINS + 'users:\n  alice: {group: readonly, scopes: [], hash: null, '
                                  'disabled: true, password_changed: 2026-02-30}\n'}),
    ('bad-unicode-escape', {'yaml': 'version: 1\nnote: "\\UFFFFFFFF"\n'}),
    # What 0.1.16 read and tacctl refuses (go-rewrite plan 3.9 item 15).
    ('alias', {'yaml': 'version: 1\nscopes:\n  lab: &x {prefixes: [10.0.0.0/8], secret: s3cret-value}\n  lab2: *x\n'}),
    ('merge-key', {'yaml': 'version: 1\nscopes:\n  lab: &x {prefixes: [10.0.0.0/8], secret: s3cret-value}\n'
                            '  lab2: {<<: *x, secret: other}\n'}),
    ('merge-key-only', {'yaml': 'version: 1\nbase: {a: 1}\nextra:\n  <<: {b: 2}\n'}),
    ('int-key', {'yaml': 'version: 1\nscopes:\n  1: {prefixes: [10.0.0.0/8], secret: s3cret-value}\n'}),
    ('bool-key', {'yaml': 'version: 1\nfilters: {yes: [10.0.0.0/8]}\n'}),
    ('set', {'yaml': 'version: 1\nextra: !!set {a, b}\n'}),
    ('omap', {'yaml': 'version: 1\nextra: !!omap [a: 1]\n'}),
    ('pairs', {'yaml': 'version: 1\nextra: !!pairs [a: 1]\n'}),
    ('binary', {'yaml': 'version: 1\nscopes: {lab: {secret: !!binary czNjcmV0}}\n'}),
    ('datetime', {'yaml': 'version: 1\n' + BUILTINS + 'users:\n  alice: {group: readonly, scopes: [], hash: null, '
                           'disabled: true, password_changed: 2026-10-01 10:00:00}\n'}),
    ('big-int', {'yaml': 'version: 1\nusers:\n  bob: {group: readonly, scopes: [], hash: ' + DIGITS + DIGITS +
                          ', disabled: false}\n'}),
]


def run(*args):
    p = subprocess.run(['python3', prog, *args], capture_output=True, text=True, env=ENV, check=False)
    out = {'rc': p.returncode}
    err = p.stderr
    if 'Traceback (most recent call last):' in err:
        out['crash'] = err.rstrip('\n').split('\n')[-1].replace(FILE, 'FILE')
        return out, p.stdout
    out['stderr'] = err.replace(FILE, 'FILE')
    return out, p.stdout


def place(spec):
    if os.path.isdir(FILE):
        os.rmdir(FILE)
    elif os.path.lexists(FILE):
        os.chmod(FILE, 0o600)
        os.remove(FILE)
    kind = spec.get('kind')
    if kind == 'missing':
        return
    if kind == 'directory':
        os.mkdir(FILE)
        return
    if 'fixture' in spec:
        with open(os.path.join(fixtures, spec['fixture']), 'rb') as f:
            data = f.read()
    elif 'yaml_hex' in spec:
        data = bytes.fromhex(spec['yaml_hex'])
    else:
        data = spec['yaml'].encode('utf-8')
    with open(FILE, 'wb') as f:
        f.write(data)
    if spec.get('unreadable'):
        os.chmod(FILE, 0)


if os.geteuid() == 0:
    sys.exit('gen.py: run as an ordinary user (root reads a mode-000 file)')
for name, spec in CASES:
    place(spec)
    dump, stdout = run('dump-store', FILE)
    dump['stdout'] = stdout
    if os.path.isfile(FILE):
        validate, _ = run('validate', FILE)
    else:
        validate = {'not_found': True}
    rec = {'name': name, **spec, 'dump': dump, 'validate': validate}
    print(json.dumps(rec, ensure_ascii=True, sort_keys=False))
