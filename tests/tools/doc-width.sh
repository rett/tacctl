#!/usr/bin/env bash
# Fenced code blocks of the user documentation are shown by GitHub with a
# horizontal scroll bar and cut off at the width of the page: no line of one
# may be longer than MAX characters (docs/plans and the release notes are
# not user reference pages and are left out).
set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 -I - 100 << 'PY'
import glob, os, sys

MAX = int(sys.argv[1])
files = ['README.md'] + glob.glob('docs/**/*.md', recursive=True)
bad = 0
for f in sorted(files):
    if f.startswith('docs/plans/') or os.path.basename(f).startswith('release-notes-'):
        continue
    infence = False
    with open(f, encoding='utf-8') as fh:
        for n, line in enumerate(fh.read().split('\n'), 1):
            if line.startswith('```'):
                infence = not infence
            elif infence and len(line) > MAX:
                print('%s:%d: %d characters in a code block (the most is %d)' % (f, n, len(line), MAX))
                bad = 1
if bad:
    print('doc-width: wrap the lines above (a trailing comment onto its own line; a reference '
          'entry is its command line at the margin and its description indented under it)',
          file=sys.stderr)
sys.exit(bad)
PY
