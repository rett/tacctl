"""Check every tacctl command and flag on the site against the man page of a release.

Usage:
  python3 tools/check_commands.py [site-dir]                  check each page against its tag
  python3 tools/check_commands.py --latest <tag> [--strict] [site-dir]
  python3 tools/check_commands.py --tag <tag> [site-dir]      check every page against one tag
  python3 tools/check_commands.py --tags-needed [site-dir]    print the tags the pages declare
  python3 tools/check_commands.py --diff <old> <new>          commands, flags and tiers that changed

The oracle is man/tacctl.1 at the tag a page names in its line 3 ('Checked against
tacctl <tag>'), read with 'git show <tag>:man/tacctl.1' from the clone this runs in
(fetch the tags first: 'git fetch --tags origin', or one tag with
'git fetch --no-tags origin tag <tag>').

From 0.2.3 on, the man page carries one generated block per runnable command
('.\\" BEGIN GENERATED: command <path>'): its tier line and its exact flag list,
written from the code and compared byte for byte by the repository's own tests
(internal/cli/man_gen_test.go, man_gate_test.go) at every release. The command
tree is those paths and their prefixes. Older man pages (0.0.15 to 0.2.2) have no
such blocks; for them the tree comes from the '.TP' tags (bold words before the
first placeholder), which is a superset of the real tree, and the flags from each
entry; results for those tags are marked approximate.

What is checked on each page (front matter 'commands: historical' exempts a page):
- every line of a fenced block that starts with 'tacctl', 'sudo tacctl' or
  '$ tacctl' (in 'text' blocks: only the first line, '$ '-prompted lines and
  console-prompt lines '<host>> <command>', which are checked as 'tacctl <command>');
- every inline code span that starts with 'tacctl ' (tables included).
The words after 'tacctl' must walk the command tree: a word after a command that
only groups sub-commands must be one of them. Every '-x' or '--name' flag must be a
flag of the command it follows, or --help/-h. Placeholders (<name>, NAME, ...),
quoted strings and anything after ' -- ', '|', ';', '&&', '>' or '$(' end the check
of a line. 'a|b' in a command word checks each alternative.

Limits: names only, not meaning; output lines are not checked; a word after a
command that both runs and has sub-commands is taken as an argument; console-mode
commands in prose (without 'tacctl') are not checked; hidden commands are invisible.
Exits 1 on any problem (and on a lagging page with --strict).
"""
import argparse
import os
import re
import subprocess
import sys

WORD = re.compile(r'^[a-z][a-z0-9-]*$')
FLAG = re.compile(r'^(--?[A-Za-z][A-Za-z0-9-]*)(=.*)?$')
GLOBAL_FLAGS = {'--help', '-h'}
ALT = re.compile(r'\{ ([a-z :-]+(?: \| [a-z :-]+)+) \}')
CHECKED = re.compile(r'Checked against tacctl (\d+\.\d+\.\d+)')
COMMAND_SECTIONS = {'COMMANDS', 'SCOPE MANAGEMENT', 'DEVICE REGISTRY', 'RADIUS DEVICE CONFIGURATIONS'}
MACRO_FONTS = {'B': 'B', 'I': 'I', 'R': 'R', 'SM': 'R', 'SS': 'B', 'SH': 'B',
               'BI': 'BI', 'BR': 'BR', 'IR': 'IR', 'IB': 'IB', 'RB': 'RB', 'RI': 'RI'}


# ---------------------------------------------------------------- man page

def roff_args(s):
    """The arguments of a roff macro line: words, or "quoted words" ("" is a quote)."""
    out = []
    s = s.strip()
    while s:
        if s[0] == '"':
            i, b = 1, []
            while i < len(s):
                if s[i] == '"':
                    if s[i + 1:i + 2] == '"':
                        b.append('"')
                        i += 2
                        continue
                    break
                b.append(s[i])
                i += 1
            out.append(''.join(b))
            s = s[i + 1:].strip()
            continue
        m = re.match(r'\S+', s)
        out.append(m.group(0))
        s = s[m.end():].strip()
    return out


def styled(text, font):
    """Text with roff escapes as a list of (character, font); font is B, I or R."""
    out, cur, prev, i = [], font, font, 0
    while i < len(text):
        c = text[i]
        if c == '\\' and i + 1 < len(text):
            n = text[i + 1]
            if n == 'f' and i + 2 < len(text):
                f = text[i + 2]
                if f == 'P':
                    cur, prev = prev, cur
                else:
                    prev, cur = cur, {'1': 'R', '2': 'I', '3': 'B'}.get(f, f)
                i += 3
            elif n == '-':
                out.append(('-', cur))
                i += 2
            elif n == 'e':
                out.append(('\\', cur))
                i += 2
            elif n == '(':
                i += 4
            elif n in '~ ':
                out.append((' ', cur))
                i += 2
            else:
                i += 2
            continue
        out.append((c, cur))
        i += 1
    return out


def line_styled(line):
    """A source line as (character, font) pairs, or None when it prints nothing."""
    if line.startswith('.\\"') or line == '.TP':
        return None
    if line.startswith('.'):
        name, _, rest = line[1:].partition(' ')
        fonts = MACRO_FONTS.get(name)
        if fonts is None:
            return None
        out = []
        for k, arg in enumerate(roff_args(rest)):
            if len(fonts) == 2:
                out += styled(arg, fonts[k % 2])
            else:
                out += ([(' ', fonts)] if k else []) + styled(arg, fonts)
        return out
    return styled(line, 'R')


def plain(st):
    return ''.join(c for c, _ in st)


def expand_alternatives(st):
    """'config allow { list | add }' as one styled string per alternative."""
    text = plain(st)
    m = ALT.search(text)
    if not m:
        return [st]
    out, pos = [], m.start(1)
    for alt in m.group(1).split(' | '):
        k = text.index(alt, pos)
        pos = k + len(alt)
        out += expand_alternatives(st[:m.start()] + st[k:k + len(alt)] + st[m.end():])
    return out


def styled_tokens(st):
    toks, cur = [], []
    for c, f in st + [(' ', 'R')]:
        if c.isspace():
            if cur:
                toks.append((''.join(x for x, _ in cur), cur[0][1]))
                cur = []
        else:
            cur.append((c, f))
    return toks


def flags_in(text):
    return set(re.findall(r'(?<![A-Za-z0-9-])(--?[A-Za-z][A-Za-z0-9-]*)', text))


class Tree:
    """The command tree of one man page.

    commands: path (tuple of words) -> set of flags, for every command that runs
    families:  every path that has sub-commands
    tiers:     path -> tier from the 'Requires:' line (generated mode only)
    exact:     True when built from the generated blocks (0.2.3 and later)
    """

    def __init__(self):
        self.commands, self.families, self.tiers, self.exact = {}, set(), {}, False
        self.paths = set()

    def add_path(self, words):
        words = tuple(words)
        for k in range(1, len(words) + 1):
            self.paths.add(words[:k])
            if k < len(words):
                self.families.add(words[:k])

    def children(self, path):
        n = len(path)
        return {p[n] for p in self.paths if len(p) == n + 1 and p[:n] == path}

    def runs(self, path):
        return path in self.commands


def parse_man(text):
    lines = text.split('\n')
    tree = Tree()
    begin = re.compile(r'^\.\\" BEGIN GENERATED: command (.+?)\s*$')
    end = re.compile(r'^\.\\" END GENERATED: command ')
    cur, block = None, []
    for line in lines:
        m = begin.match(line)
        if m:
            cur, block = tuple(m.group(1).split()), []
            continue
        if cur is not None and end.match(line):
            flags, prev = set(), ''
            for b in block:
                if prev == '.TP':
                    flags |= flags_in(plain(line_styled(b) or []))
                prev = b
            tree.add_path(cur)
            tree.commands[cur] = tree.commands.get(cur, set()) | flags
            req = re.search(r'Requires: (.*?)\.(\s|$)', plain(styled(' '.join(block), 'R')))
            if req:
                tree.tiers[cur] = req.group(1).strip()
            cur = None
            continue
        if cur is not None:
            block.append(line)
    if tree.commands:
        tree.exact = True
        return tree
    return _parse_tags(lines, tree)


def _parse_tags(lines, tree):
    """Older pages: commands from the '.TP' tags of the command sections."""
    section, entries = None, []
    for i, line in enumerate(lines):
        if line.startswith('.SH '):
            section = plain(line_styled(line) or []).strip()
            entries.append((None, i))
        elif line.startswith('.SS '):
            entries.append((None, i))
        elif line == '.TP' and i + 1 < len(lines) and section in COMMAND_SECTIONS:
            st = line_styled(lines[i + 1])
            if not st:
                continue
            found = []
            for alt in expand_alternatives(st):
                words = []
                for tok, font in styled_tokens(alt):
                    if font == 'I' or not WORD.match(tok):
                        break
                    words.append(tok)
                if words:
                    found.append(tuple(words))
            if found:
                entries.append((found, i))
    for k, (paths, start) in enumerate(entries):
        if not paths:
            continue
        stop = entries[k + 1][1] if k + 1 < len(entries) else len(lines)
        flags = set()
        for line in lines[start:stop]:
            flags |= flags_in(plain(line_styled(line) or []))
        for p in paths:
            tree.add_path(p)
            tree.commands[p] = tree.commands.get(p, set()) | flags
    for p in list(tree.paths):            # a tag head that is only a prefix still runs here
        tree.commands.setdefault(p, set())
    return tree


_cache = {}


def git_dir():
    return os.environ.get('CHECK_COMMANDS_REPO') or os.getcwd()


def man_at(tag):
    if tag in _cache:
        return _cache[tag]
    r = subprocess.run(['git', '-C', git_dir(), 'show', f'refs/tags/{tag}:man/tacctl.1'],
                       capture_output=True, text=True)
    if r.returncode != 0:
        have = subprocess.run(['git', '-C', git_dir(), 'rev-parse', '-q', '--verify', f'refs/tags/{tag}'],
                              capture_output=True, text=True).returncode == 0
        if have:
            raise LookupError(f'tag {tag} has no man/tacctl.1 (the man page exists from 0.0.15)')
        raise LookupError(f'tag {tag} is not in this clone: git fetch --no-tags origin tag {tag}')
    _cache[tag] = parse_man(r.stdout)
    return _cache[tag]


# ---------------------------------------------------------------- pages

def front_matter(text):
    if not text.startswith('---\n'):
        return {}, text, 0
    end = text.index('\n---\n', 4)
    fm = {}
    for line in text[4:end].split('\n'):
        key, _, val = line.partition(':')
        fm[key.strip()] = val.strip().strip('"')
    return fm, text[end + 5:], text[:end + 5].count('\n')


def candidates(body, offset=0):
    """(line number, command text after 'tacctl') for every command on a page."""
    out = []
    lines = body.split('\n')
    fence, first = None, False
    i = 0
    while i < len(lines):
        line = lines[i]
        n = i + 1 + offset
        if line.startswith('```'):
            fence = line[3:].strip() if fence is None else None
            first = True
            i += 1
            continue
        if fence is not None:
            while line.endswith('\\') and i + 1 < len(lines):   # continuation lines
                i += 1
                line = line[:-1] + ' ' + lines[i].strip()
            s = line.strip()
            prompted = re.match(r'^\$ (.*)$', s)
            console = re.match(r'^[a-z][a-z0-9.-]*> (\S.*)$', s)
            if fence == 'text':
                if prompted:
                    s = prompted.group(1)
                elif console:
                    out.append((n, console.group(1)))
                    first = False
                    i += 1
                    continue
                elif not first:
                    i += 1
                    continue
            elif prompted:
                s = prompted.group(1)
            first = False
            m = re.match(r'^(?:sudo\s+(?:-n\s+)?)?tacctl\s+(.*)$', s)
            if m:
                out.append((n, m.group(1)))
            i += 1
            continue
        for m in re.finditer(r'(`+)tacctl ((?:(?!\1).)+?)\1', line):
            out.append((n, m.group(2).replace('\\|', '|')))
        i += 1
    return out


def words_of(cmd):
    """The tokens of a command up to the first shell operator; quoted strings drop out."""
    cmd = re.sub(r'\s#\s.*$', '', ' ' + cmd).strip()        # trailing comment
    cmd = re.split(r'\s(?:\||;|&&|>|<|2>)\s|\$\(', ' ' + cmd + ' ')[0].strip()
    cmd = re.sub(r'"[^"]*"|\'[^\']*\'', ' "" ', cmd)
    return cmd.split()


def check_command(tree, cmd):
    """Problems (strings) for one command line, empty when it holds."""
    toks = words_of(cmd)
    path, k = (), 0
    while k < len(toks):
        t = toks[k]
        alts = t.split('|') if '|' in t and all(WORD.match(a) for a in t.split('|')) else None
        if alts and all(path + (a,) in tree.paths for a in alts):
            return [p for a in alts for p in
                    check_command(tree, ' '.join(list(path) + [a] + toks[k + 1:]))]
        if WORD.match(t) and path + (t,) in tree.paths:
            path += (t,)
            k += 1
            continue
        break
    problems = []
    rest = toks[k:]
    nxt = rest[0] if rest else None
    if not path:
        if nxt and WORD.match(nxt):
            problems.append(f"'tacctl {nxt}' is not a command")
        return problems
    name = 'tacctl ' + ' '.join(path)
    if nxt and path in tree.families and not tree.runs(path):
        if WORD.match(nxt) or ('|' in nxt and all(WORD.match(a) for a in nxt.split('|'))):
            problems.append(f"'{name}' has no sub-command '{nxt}'")
            return problems
    allowed = tree.commands.get(path, set()) | GLOBAL_FLAGS
    for t in rest:
        if t == '--':
            break
        for part in re.split(r'[\[\]{}()|,]', t):
            m = FLAG.match(part)
            if m and m.group(1) not in allowed:
                problems.append(f"'{name}' has no flag {m.group(1)}")
    return problems


def page_tag(body):
    lines = body.lstrip('\n').split('\n')
    m = CHECKED.search(lines[2]) if len(lines) > 2 else None
    return m.group(1) if m else None


def load_pages(site):
    pages = []
    for name in sorted(os.listdir(site)):
        if name.endswith('.md'):
            with open(os.path.join(site, name), encoding='utf-8') as f:
                text = f.read()
            fm, body, offset = front_matter(text)
            pages.append((name, fm, body, offset))
    return pages


def check_page(name, fm, body, offset, tag=None, latest=None, strict=False, out=print):
    """(problems, warnings, commands checked) for one page."""
    if fm.get('commands') == 'historical':
        out(f'{name}: skipped (commands: historical)')
        return 0, 0, 0
    cands = candidates(body, offset)
    want = tag or page_tag(body)
    if not cands:
        return 0, 0, 0
    if want is None:
        out(f'{name}: has tacctl commands but no "Checked against tacctl <tag>" line 3')
        return 1, 0, 0
    problems = warnings = 0
    if latest and want != latest and not tag:
        msg = f'{name}: checked against tacctl {want}, the latest release is {latest}'
        if strict:
            out(msg)
            problems += 1
        else:
            out('warning: ' + msg)
            warnings += 1
    try:
        tree = man_at(want)
    except LookupError as e:
        out(f'{name}: {e}')
        return problems + 1, warnings, 0
    note = '' if tree.exact else ' (approximate: no generated blocks at this tag)'
    for n, cmd in cands:
        for p in check_command(tree, cmd):
            out(f'{name}:{n}: {p} at {want}{note}: tacctl {cmd}')
            problems += 1
    return problems, warnings, len(cands)


def check_site_page(site, page, tag, out=print):
    """Problems of one page of site against tag."""
    for name, fm, body, offset in load_pages(site):
        if name == page:
            return check_page(name, fm, body, offset, tag=tag, out=out)[0]
    raise LookupError(f'no page {page} in {site}')


def check_site(site, tag=None, latest=None, strict=False, out=print):
    problems = warnings = checked = 0
    for page in load_pages(site):
        p, w, n = check_page(*page, tag=tag, latest=latest, strict=strict, out=out)
        problems, warnings, checked = problems + p, warnings + w, checked + n
    out(f'commands checked: {checked}, problems: {problems}, warnings: {warnings}')
    return problems


def tags_needed(site):
    tags = set()
    for name, fm, body, _ in load_pages(site):
        t = page_tag(body)
        if t and fm.get('commands') != 'historical':
            tags.add(t)
    return sorted(tags, key=lambda t: tuple(int(x) for x in t.split('.')))


# ---------------------------------------------------------------- diff

def diff(old, new):
    """Lines describing what changed between two trees (old, new are Tree objects)."""
    out = []
    a, b = set(old.paths), set(new.paths)
    removed, added = sorted(a - b), sorted(b - a)
    renamed = []
    for r in list(removed):
        same = [x for x in added if x[:-1] == r[:-1] and len(x) == len(r)
                and old.commands.get(r) == new.commands.get(x)]
        if len(same) == 1 and r[:-1] in b:
            renamed.append((r, same[0]))
    for r, x in renamed:
        removed.remove(r)
        added.remove(x)
    for r, x in renamed:
        out.append(f"renamed?  tacctl {' '.join(r)}  ->  tacctl {' '.join(x)}")
    for r in removed:
        out.append(f"removed   tacctl {' '.join(r)}")
    for x in added:
        out.append(f"added     tacctl {' '.join(x)}")
    for p in sorted(a & b):
        fo, fn = old.commands.get(p, set()), new.commands.get(p, set())
        gone, came = sorted(fo - fn), sorted(fn - fo)
        if len(gone) == 1 and len(came) == 1:
            out.append(f"flag renamed?  tacctl {' '.join(p)} {gone[0]}  ->  {came[0]}")
            gone = came = []
        for f in gone:
            out.append(f"flag removed  tacctl {' '.join(p)} {f}")
        for f in came:
            out.append(f"flag added    tacctl {' '.join(p)} {f}")
        to, tn = old.tiers.get(p), new.tiers.get(p)
        if to and tn and to != tn:
            out.append(f"tier changed  tacctl {' '.join(p)}: {to} -> {tn}")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('site', nargs='?', default='site')
    ap.add_argument('--tag', help='check every page against this tag instead of its own')
    ap.add_argument('--latest', help='warn when a page is checked against an older tag')
    ap.add_argument('--strict', action='store_true', help='with --latest: a lagging page is a problem')
    ap.add_argument('--tags-needed', action='store_true', help='print the tags the pages declare')
    ap.add_argument('--diff', nargs=2, metavar=('OLD', 'NEW'))
    a = ap.parse_args(argv)
    if a.tags_needed:
        print(' '.join(tags_needed(a.site)))
        return 0
    if a.diff:
        try:
            old, new = man_at(a.diff[0]), man_at(a.diff[1])
        except LookupError as e:
            print(e)
            return 1
        for t, tree in zip(a.diff, (old, new)):
            if not tree.exact:
                print(f'note: {t} has no generated blocks; its tree is approximate')
        lines = diff(old, new)
        print('\n'.join(lines) if lines else 'no command, flag or tier changes')
        return 0
    return 1 if check_site(a.site, a.tag, a.latest, a.strict) else 0


if __name__ == '__main__':
    sys.exit(main())
