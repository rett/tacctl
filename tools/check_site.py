"""Check the site source before a build.

Usage: python3 tools/check_site.py [site-dir]     (default: site)

For every page in site-dir:
- links to other pages ('page.md' or 'page.md#anchor') point to an existing page;
- '[Page](page.md) §N' and '[Page](page.md) R<N>' references name an existing section;
- no wiki-style '[Text](Page-Name)' links and no Liquid tags ('{{', '{%');
- fenced code lines are at most 100 characters (the repository's doc-width rule);
- no example names outside the repository's examples table (retired names below).
For every content page (one with a '[Printable PDF]' line):
- front matter 'title' equals the H1 and 'description' equals the subtitle;
- front matter 'doctype' is one of tutorial, how-to, reference, explanation (Diataxis);
- the line under the H1 is '*<subtitle> · Checked against ...*', followed by the PDF line;
- every H2 is numbered ('## 1.' or '## R1.'), the example callout is worded
  'Example names used on this page', and the page ends with a '*See also:*' line.
Section pages (has_children) need title == H1. Exits 1 on any problem.
"""
import glob
import json
import os
import re
import sys

MAX = 100
RETIRED = re.compile(r'\b(core-sw\d|edge-rtr\d|dist-sw\d|old-sw\d|pdu-a\d|authsrv|jsmith|mlee|contractor1|prod)\b')
DOCTYPES = ('tutorial', 'how-to', 'reference', 'explanation')
PDF_LINE = re.compile(r'^\[Printable PDF\]\((?:\.\./)?pdf/tacctl-[a-z0-9-]+\.pdf\)\{: \.pdf-link \}$')

site = sys.argv[1] if len(sys.argv) > 1 else 'site'
problems = 0


def bad(page, msg):
    global problems
    problems += 1
    print(f'{page}: {msg}')


def split(text):
    if not text.startswith('---\n'):
        return {}, text
    end = text.index('\n---\n', 4)
    fm = {}
    for line in text[4:end].split('\n'):
        key, _, val = line.partition(':')
        val = val.strip()
        fm[key.strip()] = json.loads(val) if val.startswith('"') else val
    return fm, text[end + 5:].lstrip('\n')


def sections(body):
    return {m.group(1) for m in re.finditer(r'^#{2,3} (R?\d+(?:\.\d+)?)[. ]', body, flags=re.M)}


pages = {}
for path in sorted(glob.glob(os.path.join(site, '*.md'))):
    pages[os.path.basename(path)] = split(open(path, encoding='utf-8').read())

for name, (fm, body) in pages.items():
    prose = re.sub(r'```.*?```', '', body, flags=re.S)
    for m in re.finditer(r'\]\(([a-z0-9-]+\.md)(#[^)\s]*)?\)', body):
        if m.group(1) not in pages:
            bad(name, f'link to a missing page: {m.group(0)}')
    for m in re.finditer(r'\]\(([a-z0-9-]+\.md)\)\s*(R\d+(?:,\s*R\d+)*|§\d+(?:\.\d+)?(?:[–-]\d+)?)', prose):
        if m.group(1) not in pages:
            continue
        have = sections(pages[m.group(1)][1])
        for ref in re.findall(r'R?\d+(?:\.\d+)?', m.group(2).replace('§', '')):
            if ref not in have:
                bad(name, f'{m.group(1)} has no section {ref}')
    for m in re.finditer(r'\]\(([A-Z][A-Za-z0-9-]*)(#[^)]*)?\)', body):
        bad(name, f'wiki-style link {m.group(0)}')
    if '{{' in body or '{%' in body:
        bad(name, 'Liquid tag in the page')
    infence = False
    for n, line in enumerate(body.split('\n'), 1):
        if line.startswith('```'):
            infence = not infence
        elif infence and len(line) > MAX:
            bad(name, f'code line {n} of the body has {len(line)} characters (the most is {MAX})')
        r = RETIRED.search(line)
        if r:
            bad(name, f'body line {n}: example name "{r.group(1)}" is not from the examples table')

    lines = body.split('\n')
    h1 = lines[0][2:].strip() if lines and lines[0].startswith('# ') else None
    if name == '404.md':
        continue
    if h1 is None:
        bad(name, 'the body does not start with an H1')
        continue
    if fm.get('title') != h1:
        bad(name, f'title "{fm.get("title")}" differs from the H1 "{h1}"')
    if fm.get('has_children') == 'true':
        continue
    if fm.get('doctype') not in DOCTYPES:
        bad(name, f'front matter doctype "{fm.get("doctype", "")}" is not one of {", ".join(DOCTYPES)}')
    if not any(PDF_LINE.match(l) for l in lines[:6]):
        bad(name, 'no "[Printable PDF](...){: .pdf-link }" line under the subtitle')
    sub = re.match(r'^\*(.+?) · Checked against .+\*$', lines[2]) if len(lines) > 2 else None
    if not sub:
        bad(name, 'line 3 of the body is not "*<subtitle> · Checked against ...*"')
    elif fm.get('description') != sub.group(1):
        bad(name, 'description differs from the subtitle')
    for h in re.findall(r'^## (.+)$', prose, flags=re.M):
        if not re.match(r'R?\d+\. ', h):
            bad(name, f'unnumbered H2 "{h}"')
    if 'Example names used in this guide' in body:
        bad(name, 'callout must read "Example names used on this page"')
    if '*See also:*' not in body:
        bad(name, 'no "*See also:*" line')

print(f'pages: {len(pages)}, problems: {problems}')
sys.exit(1 if problems else 0)
