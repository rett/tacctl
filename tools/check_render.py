#!/usr/bin/env python3
"""Checks the rendered site against its Markdown sources.

Usage: python3 tools/check_render.py <site dir> <built dir>
  (for example: python3 tools/check_render.py site _site)

A page whose Markdown is parsed wrongly renders without an error: one line
that starts with '<scope>' makes Kramdown take the rest of the page for raw
HTML. check_site.py reads the Markdown only, so this reads what Jekyll built:

  * every H2 and H3 of the source is a heading of the built page, in order;
  * no text outside <pre> and <code> holds a Markdown leftover: a backtick,
    '**', '](', a line that starts with '#' or '|', or '```';
  * every <pre> and <table> that the source has fenced code blocks and
    tables for is in the page, in the same number.

Exits 1 when a page has a problem.
"""
import glob
import html.parser
import os
import re
import sys

site = sys.argv[1] if len(sys.argv) > 1 else 'site'
built = sys.argv[2] if len(sys.argv) > 2 else '_site'
problems = 0


def bad(page, msg):
    global problems
    problems += 1
    print(f'{page}: {msg}')


class Page(html.parser.HTMLParser):
    """Collects the headings, the text outside code, and the counts of
    <pre> and <table> in the main content of a built page."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth_code = 0
        self.in_main = False
        self.headings = []
        self._h = None
        self.text = []
        self.pre = 0
        self.table = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'div' and 'main-content' in (a.get('class') or '').split():
            self.in_main = True
        if not self.in_main:
            return
        if tag in ('pre', 'code', 'script', 'style'):
            self.depth_code += 1
        if tag == 'pre':
            self.pre += 1
        if tag == 'table':
            self.table += 1
        if tag in ('h2', 'h3'):
            self._h = [tag, '']

    def handle_endtag(self, tag):
        if not self.in_main:
            return
        if tag in ('pre', 'code', 'script', 'style'):
            self.depth_code = max(0, self.depth_code - 1)
        if tag in ('h2', 'h3') and self._h:
            self.headings.append((self._h[0], re.sub(r'\s+', ' ', self._h[1]).strip()))
            self._h = None

    def handle_data(self, data):
        if not self.in_main:
            return
        if self._h is not None:
            self._h[1] += data
        if self.depth_code == 0:
            self.text.append(data)


def front_matter(text):
    if not text.startswith('---\n'):
        return {}, text
    end = text.index('\n---\n', 4)
    fm = {}
    for line in text[4:end].split('\n'):
        k, _, v = line.partition(':')
        fm[k.strip()] = v.strip().strip('"')
    return fm, text[end + 5:]


def plain(h):
    """A heading as the built page shows it: Markdown marks and the
    anchor-link text taken out."""
    h = re.sub(r'`([^`]*)`', r'\1', h)
    h = re.sub(r'\*\*?([^*]*)\*\*?', r'\1', h)
    h = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', h)
    h = h.translate({0x2018: "'", 0x2019: "'", 0x201c: '"', 0x201d: '"', 0x2013: '-', 0x2014: '--', 0x2026: '...'})  # Kramdown's typography
    return re.sub(r'\s+', ' ', h).strip()


for path in sorted(glob.glob(os.path.join(site, '*.md'))):
    name = os.path.basename(path)
    fm, body = front_matter(open(path, encoding='utf-8').read())
    permalink = fm.get('permalink') or '/' + name[:-3] + '/'
    out = os.path.join(built, permalink.strip('/'), 'index.html')
    if permalink.endswith('.html'):
        out = os.path.join(built, permalink.strip('/'))
    if permalink == '/':
        out = os.path.join(built, 'index.html')
    if not os.path.exists(out):
        bad(name, f'not built: {out} is missing')
        continue
    p = Page()
    p.feed(open(out, encoding='utf-8').read())

    # headings of the source: outside fenced code
    src, fence = [], False
    for line in body.split('\n'):
        if line.lstrip().startswith('```'):
            fence = not fence
            continue
        m = None if fence else re.match(r'^(#{2,3}) (.+)$', line)
        if m:
            src.append(('h' + str(len(m.group(1))), plain(m.group(2))))
    got = [(t, plain(h)) for t, h in p.headings if h != 'Table of contents']  # the theme's own
    if src != got:
        miss = [h for h in src if h not in got]
        extra = [h for h in got if h not in src]
        bad(name, f'headings differ from the source: missing {miss[:3]}, extra {extra[:3]} ({len(src)} in the source, {len(got)} built)')

    # code blocks and tables of the source
    fences = len(re.findall(r'^\s*```', body, flags=re.M)) // 2
    if fences != p.pre:
        bad(name, f'{fences} fenced code blocks in the source, {p.pre} <pre> in the built page')
    tables = len(re.findall(r'(?:^|\n)\|[^\n]*\|\n\|[ :|-]*---[ :|-]*\|', re.sub(r'```.*?```', '', body, flags=re.S)))
    if tables != p.table:
        bad(name, f'{tables} tables in the source, {p.table} <table> in the built page')

    # Markdown that was left in the text
    text = '\n'.join(p.text)
    for pat, what in ((r'`', 'a backtick'), (r'\*\*', '"**"'), (r'\]\(', '"]("'),
                      (r'(?m)^\s*#{1,4} \S', 'a line that starts with "#"'),
                      (r'(?m)^\s*\|.*\|\s*$', 'a table row as text'), (r'```', '"```"')):
        m = re.search(pat, text)
        if m:
            around = text[max(0, m.start() - 40):m.end() + 40].replace('\n', ' ')
            bad(name, f'{what} in the text outside code: "...{around}..."')

print(f'built pages checked: {len(glob.glob(os.path.join(site, "*.md")))}, problems: {problems}')
sys.exit(1 if problems else 0)
