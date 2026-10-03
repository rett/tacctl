#!/usr/bin/env python3
"""Write the expected/*.out files of internal/store's import tests from the
0.1.16 python (lib/store.sh + lib/model.sh: _store_py, _model_py).

    internal/store/testdata/import/gen.sh

runs it with the program extracted from the 0.1.16 tag. Each .out file
holds, for one tacquito.yaml (and, for the carry-over cases, an existing
store):

    == dump-legacy           the model JSON, or the error line; rc=
    == import-load force=0   import_load's stdout, '-- stderr', its stderr,
    == import-load force=1   rc=, and the model JSON when the load passed

expected/index lists the cases: name, source and existing store, tab
separated, with the fixtures directory written as FIXTURES/ and paths
below this directory relative to it (the Go test makes the same
replacements in what it prints). The sidecar directories are side/dates and side/disabled for every case.
A case whose run crashes the python is an error here (it would be a
traceback in 0.1.16, which no test should pin).
"""
import contextlib
import importlib.util
import io
import json
import os
import sys

prog_path, here, fixtures = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location('tacctl_store', prog_path)
prog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prog)

dates = os.path.join(here, 'side', 'dates')
disabled = os.path.join(here, 'side', 'disabled')


def rel(p):
    return os.path.relpath(p, here)


def run(fn):
    out, err = io.StringIO(), io.StringIO()
    rc = 0
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = fn()
        except prog.StoreError as e:
            print(f'tacctl store: {e}', file=sys.stderr)
            rc = 1
    return out.getvalue(), err.getvalue(), rc


index = []


def case(name, src, existing=''):
    index.append('\t'.join((name, src, existing)))
    parts = []

    def dump():
        model, _rep = prog.legacy_load(src, dates, disabled)
        print(json.dumps(prog.store_canonicalize(model), sort_keys=True))
        return 0
    o, e, rc = run(dump)
    parts.append(f'== dump-legacy\n{o}{e}rc={rc}\n')
    for force in (0, 1):
        box = {}

        def load():
            ok, model = prog.import_load(src, dates, disabled, existing, bool(force))
            box['model'] = model if ok else None
            return 0 if ok else 1
        o, e, rc = run(load)
        parts.append(f'== import-load force={force}\n{o}-- stderr\n{e}rc={rc}\n')
        if box.get('model') is not None:
            parts.append(json.dumps(box['model'], sort_keys=True) + '\n')
    text = ''.join(parts)
    # The Go test makes the same replacements in what it prints.
    text = text.replace(fixtures + '/', 'FIXTURES/').replace(here + '/', '')
    with open(os.path.join(here, 'expected', name + '.out'), 'w') as f:
        f.write(text)


os.makedirs(os.path.join(here, 'expected'), exist_ok=True)
os.chdir(here)
for fn in sorted(os.listdir('cases')):
    if fn.endswith('.yaml'):
        case(fn[:-5], os.path.join(here, 'cases', fn))
for fn in sorted(os.listdir(fixtures)):
    if fn.startswith(('tacquito.', 'legacy.')) and fn.endswith('.yaml'):
        case('fixture.' + fn[:-5], os.path.join(fixtures, fn))
for fn in sorted(os.listdir(os.path.join(fixtures, 'golden'))):
    if fn.startswith('tacquito.') and fn.endswith('.yaml'):
        case('golden.' + fn[:-5], os.path.join(fixtures, 'golden', fn))
for src, existing in (('legacy.import-edge.yaml', 'edge-extras.yaml'),
                      ('legacy.import-edge.yaml', 'list.yaml'),
                      ('tacquito.multiscope.yaml', 'edge-extras.yaml')):
    case(f'carry.{src[:-5]}.{existing[:-5]}', os.path.join(fixtures, src),
         os.path.join(here, 'existing', existing))
# expected/index: <case>\t<source>\t<existing store>, paths as above.
with open(os.path.join(here, 'expected', 'index'), 'w') as f:
    for line in index:
        f.write(line.replace(fixtures + '/', 'FIXTURES/').replace(here + '/', '') + '\n')
