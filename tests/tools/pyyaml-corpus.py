#!/usr/bin/env python3
"""pyyaml-corpus.py [--check] [<corpus dir> [<decode dir>]]

Writes the expected results of internal/yamlpy's corpus tests:

- emitter: for every <case>.json in <corpus dir> (default
  internal/yamlpy/testdata/corpus), the bytes PyYAML's yaml.safe_dump gives
  for its data in each mode below, as <case>.<mode>.yaml.
  internal/yamlpy/corpus_test.go emits the same data with the Go emitter and
  compares byte for byte;
- decoder: for every <case>.yaml in <decode dir> (default
  internal/yamlpy/testdata/decode), what yaml.safe_load makes of it, as
  <case>.json. internal/yamlpy/decode_test.go compares yamlpy.Decode with it;
- store fixtures (only with the default directories): tests/fixtures/
  store.<name>.yaml read with safe_load and written again as lib/store.sh
  writes a store (header dropped), as internal/yamlpy/testdata/fixtures/
  store.<name>.yaml. internal/yamlpy/fixtures_test.go re-emits each fixture
  from its parsed form and compares with it.

Modes (sort_keys=False throughout, as tacctl dumps):
  store   default_flow_style=None, width=4096   (lib/store.sh, store.yaml)
  conf    default_flow_style=False, width 80    (lib/conf.sh, tacctl.yaml)
  flow80  default_flow_style=None, width 80     (flow collections that wrap)

JSON cannot say everything a YAML value can; two conventions fill the gap:
  {"$date": "2026-10-01"}  a datetime.date (yamlpy.Date)
  {"$float": "nan"}        float('nan'), also "inf" and "-inf"
A JSON number with a fraction or exponent is a float, any other an int.

--check regenerates in memory and compares with the files on disk instead
of writing them: exit 0 when all match, 1 (with the differing files named)
otherwise. Without PyYAML it prints why and exits 0, so 'make test-pyyaml'
is a no-op on a host without python3-yaml. The corpus was generated with
PyYAML 6.0.1 (the version in <corpus dir>/PYYAML_VERSION); another version
is reported, since a difference may then be PyYAML's own.
"""

import datetime
import difflib
import json
import os
import sys

MODES = {
    'store': dict(default_flow_style=None, width=4096),
    'conf': dict(default_flow_style=False),
    'flow80': dict(default_flow_style=None),
}


def convert(v):
    """JSON value -> the Python value the case stands for."""
    if isinstance(v, dict):
        if len(v) == 1 and '$date' in v:
            return datetime.date.fromisoformat(v['$date'])
        if len(v) == 1 and '$float' in v:
            return float(v['$float'])
        return {k: convert(x) for k, x in v.items()}
    if isinstance(v, list):
        return [convert(x) for x in v]
    return v


def to_json(v):
    """safe_load result -> JSON with the conventions above (inverse of convert)."""
    if isinstance(v, datetime.date) and not isinstance(v, datetime.datetime):
        return {'$date': v.isoformat()}
    if isinstance(v, float) and (v != v or v in (float('inf'), float('-inf'))):
        return {'$float': 'nan' if v != v else ('inf' if v > 0 else '-inf')}
    if isinstance(v, dict):
        if not all(isinstance(k, str) for k in v):
            raise ValueError('non-string key')
        return {k: to_json(x) for k, x in v.items()}
    if isinstance(v, list):
        return [to_json(x) for x in v]
    if v is None or isinstance(v, (str, bool, int, float)):
        return v
    raise ValueError(f'cannot express {type(v).__name__} in the corpus')


def decoded(yaml, path):
    with open(path, encoding='utf-8') as f:
        data = yaml.safe_load(f)
    return json.dumps(to_json(data), indent=1, ensure_ascii=True) + '\n'


def expected(yaml, path):
    with open(path, encoding='utf-8') as f:
        data = convert(json.load(f))
    return {mode: yaml.safe_dump(data, sort_keys=False, **kw) for mode, kw in MODES.items()}


def main(argv):
    check = False
    args = argv[1:]
    if args and args[0] == '--check':
        check = True
        args = args[1:]
    root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
    corpus = args[0] if args else os.path.join(root, 'internal', 'yamlpy', 'testdata', 'corpus')
    decode = args[1] if len(args) > 1 else (
        None if args else os.path.join(root, 'internal', 'yamlpy', 'testdata', 'decode'))

    try:
        import yaml
    except ImportError:
        print('pyyaml-corpus: PyYAML is not installed (apt install python3-yaml); nothing checked')
        return 0
    pinned = None
    try:
        with open(os.path.join(corpus, 'PYYAML_VERSION'), encoding='ascii') as f:
            pinned = f.read().strip()
    except FileNotFoundError:
        pass
    if pinned and yaml.__version__ != pinned:
        print(f'pyyaml-corpus: note: PyYAML {yaml.__version__} here, the corpus is from {pinned}')

    cases = sorted(n[:-5] for n in os.listdir(corpus) if n.endswith('.json'))
    if not cases:
        print(f'pyyaml-corpus: no cases in {corpus}', file=sys.stderr)
        return 1
    bad = 0
    written = 0
    for case in cases:
        for mode, text in expected(yaml, os.path.join(corpus, case + '.json')).items():
            out = os.path.join(corpus, f'{case}.{mode}.yaml')
            if not check:
                with open(out, 'w', encoding='utf-8', newline='') as f:
                    f.write(text)
                written += 1
                continue
            try:
                with open(out, encoding='utf-8', newline='') as f:
                    have = f.read()
            except FileNotFoundError:
                print(f'missing: {out}')
                bad += 1
                continue
            if have != text:
                bad += 1
                print(f'differs: {out}')
                sys.stdout.writelines(difflib.unified_diff(
                    have.splitlines(True), text.splitlines(True), 'committed', 'pyyaml', n=1))
    targets = []  # (path, text): decode and fixture results
    if not args:
        fixdir = os.path.join(root, 'internal', 'yamlpy', 'testdata', 'fixtures')
        for name in ('minimal', 'multiscope', 'radius'):
            with open(os.path.join(root, 'tests', 'fixtures', f'store.{name}.yaml'), encoding='utf-8') as f:
                text = yaml.safe_dump(yaml.safe_load(f), sort_keys=False, **MODES['store'])
            targets.append((os.path.join(fixdir, f'store.{name}.yaml'), text))
    dcases = sorted(n[:-5] for n in os.listdir(decode) if n.endswith('.yaml')) if decode else []
    targets += [(os.path.join(decode, case + '.json'), decoded(yaml, os.path.join(decode, case + '.yaml')))
                for case in dcases]
    for out, text in targets:
        if not check:
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, 'w', encoding='utf-8', newline='') as f:
                f.write(text)
            written += 1
            continue
        try:
            with open(out, encoding='utf-8', newline='') as f:
                have = f.read()
        except FileNotFoundError:
            print(f'missing: {out}')
            bad += 1
            continue
        if have != text:
            bad += 1
            print(f'differs: {out}')
            sys.stdout.writelines(difflib.unified_diff(
                have.splitlines(True), text.splitlines(True), 'committed', 'pyyaml', n=1))
    if check:
        known = {f'{c}.{m}.yaml' for c in cases for m in MODES}
        for n in sorted(os.listdir(corpus)):
            if n.endswith('.yaml') and n not in known:
                print(f'stale (no .json): {os.path.join(corpus, n)}')
                bad += 1
        if bad:
            print(f'pyyaml-corpus: {bad} file(s) differ from PyYAML {yaml.__version__}; '
                  f'regenerate with {os.path.relpath(__file__, root)} and review the diff')
            return 1
        print(f'pyyaml-corpus: {len(cases)} cases x {len(MODES)} modes and {len(dcases)} decode cases '
              f'and {len(targets) - len(dcases)} fixtures match PyYAML {yaml.__version__}')
        return 0
    print(f'pyyaml-corpus: wrote {written} files for {len(cases)} emitter and {len(dcases)} decode cases '
          f'(PyYAML {yaml.__version__})')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
