"""The per-release sync of the site, in two runs around the hand work.

Usage:
  python3 tools/release_sync.py --from <old> --to <new>            discover what changed
  python3 tools/release_sync.py --from <old> --to <new> --finish   bump, check, build, render
Options: --site DIR (default site), --out DIR (default /tmp/release-sync-<new>),
         --no-fetch, --external (also check external links, with a two-week cache),
         --no-build (finish without the Jekyll build, html-proofer and PDFs).

Discover (the routine's steps 1 to 4, and what step 5 must fix):
  1. git fetch --no-tags origin tag <old> tag <new>
  2. the command, flag and tier diff of the man pages (check_commands.py --diff),
     with the pages that name each removed or renamed command: the blocking list
  3. the reference diff (docs/ without docs/plans/, man/tacctl.1, CHANGELOG.md) and the release notes,
     written to --out; the CHANGELOG heading of <new> (for What's new)
  4. the tier diff (docs/security/tiers.md, internal/cli/audit.go) to --out, and the
     pages that name each command whose tier moved
  and the pages that fail check_commands.py against <new>.

Then, by hand: fix the pages, add the release to whats-new-for-operators.md.

Finish (steps 6, 8 and 9):
  6. bump 'Checked against tacctl <old>' to <new> on line 3 of every page that passes
     check_commands.py against <new> (a failing page is refused and listed), and the
     footer (site/_includes/footer_custom.html) once every page is bumped
  8. check_site.py, check_commands.py, the Jekyll build, html-proofer (internal links;
     with --external also external links, cached for two weeks)
  9. every PDF into site/pdf (git-ignored)
Exits 1 when a step fails or a page was refused. Commits nothing and pushes nothing.
"""
import argparse
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_commands as cc  # noqa: E402

TAG = re.compile(r'^\d+\.\d+\.\d+$')
STAMP = 'Checked against tacctl {}'
FOOTER = os.path.join('_includes', 'footer_custom.html')
REFERENCE = ('docs/', ':(exclude)docs/plans/', 'man/tacctl.1', 'CHANGELOG.md')   # plans are not user docs


def git(*args, check=True):
    r = subprocess.run(['git', '-C', cc.git_dir(), *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r


def head(title):
    print(f'\n== {title}')


def mentions(site, words):
    """Pages that name a command: 'tacctl <words>' or a code span starting with <words>."""
    phrase = ' '.join(words)
    pat = re.compile(r'(?:tacctl |`|^|> )' + re.escape(phrase) + r'(?![a-z0-9-])', re.M)
    return [name for name, _, body, _ in cc.load_pages(site) if pat.search(body)]


def discover(a):
    os.makedirs(a.out, exist_ok=True)
    if not a.no_fetch:
        head(f'1. fetch tags {a.old} and {a.new}')
        git('fetch', '--no-tags', 'origin', 'tag', a.old, 'tag', a.new)
        print('ok')
    head(f'2. commands, flags and tiers: {a.old} -> {a.new}')
    old, new = cc.man_at(a.old), cc.man_at(a.new)
    for t, tree in ((a.old, old), (a.new, new)):
        if not tree.exact:
            print(f'note: {t} has no generated blocks; its tree is approximate')
    lines = cc.diff(old, new)
    print('\n'.join(lines) if lines else 'no command, flag or tier changes')
    blocking = []
    for line in lines:
        m = re.match(r'(renamed\?|removed) +tacctl (.+?)(?:  ->|$)', line)
        if m:
            pages = mentions(a.site, m.group(2).split())
            if pages:
                blocking.append(f'tacctl {m.group(2)}: {", ".join(pages)}')
    print('\nBlocking (removed or renamed commands still on pages):')
    print('\n'.join('  ' + b for b in blocking) if blocking else '  none')

    head('3. reference diff')
    stat = git('diff', '--stat', a.old, a.new, '--', *REFERENCE).stdout
    print(stat.rstrip() or 'no change')
    full = git('diff', a.old, a.new, '--', *REFERENCE).stdout
    write(a.out, 'reference.diff', full)
    notes = git('show', f'{a.new}:docs/release-notes-{a.new}.md', check=False)
    if notes.returncode == 0:
        write(a.out, f'release-notes-{a.new}.md', notes.stdout)
    else:
        print(f'no docs/release-notes-{a.new}.md at {a.new}')
    changelog = git('show', f'{a.new}:CHANGELOG.md', check=False).stdout
    m = re.search(r'^## ' + re.escape(a.new) + r'\b.*$', changelog, re.M)
    print(f'CHANGELOG heading: {m.group(0)[3:] if m else "not found"}')

    head('4. tiers')
    tiers = git('diff', a.old, a.new, '--', 'docs/security/tiers.md', 'internal/cli/audit.go').stdout
    write(a.out, 'tiers.diff', tiers)
    moved = [line for line in lines if line.startswith('tier changed')]
    for line in moved:
        words = re.match(r'tier changed  tacctl (.+?):', line).group(1).split()
        pages = mentions(a.site, words)
        print(f'{line}\n    pages: {", ".join(pages) if pages else "none"}')
    if not moved:
        print('no tier changes in the man page')

    head(f'pages against {a.new} (check_commands.py --tag {a.new})')
    failing = cc.check_site(a.site, tag=a.new)
    print(f'\nNext: fix the pages, add {a.new} to whats-new-for-operators.md, then run with --finish.')
    return 1 if failing else 0


def write(out, name, text):
    path = os.path.join(out, name)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    print(f'wrote {path} ({len(text.splitlines())} lines)')


def bump(site, old, new, refuse=()):
    """Bump line 3 of every page at <old> (except those in refuse) and, when no page
    is left at <old>, the footer. Returns the files changed."""
    changed, left = [], []
    for name, fm, body, _ in cc.load_pages(site):
        if cc.page_tag(body) != old:
            continue
        if name in refuse:
            left.append(name)
            continue
        path = os.path.join(site, name)
        with open(path, encoding='utf-8') as f:
            text = f.read()
        lines = text.split('\n')
        start = len(text) - len(body.lstrip('\n'))
        n = text[:start].count('\n') + 2                     # line 3 of the body
        lines[n] = lines[n].replace(STAMP.format(old), STAMP.format(new))
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        changed.append(path)
    footer = os.path.join(site, FOOTER)
    if not left and os.path.exists(footer):
        with open(footer, encoding='utf-8') as f:
            text = f.read()
        new_text = text.replace(f'tacctl {old}</strong>', f'tacctl {new}</strong>')
        if new_text != text:
            with open(footer, 'w', encoding='utf-8') as f:
                f.write(new_text)
            changed.append(footer)
    return changed


def run(title, cmd, env=None):
    print(f'$ {" ".join(cmd)}')
    r = subprocess.run(cmd, env={**os.environ, **(env or {})})
    if r.returncode != 0:
        print(f'FAILED: {title}')
    return r.returncode == 0


def finish(a):
    head(f'6. bump {a.old} -> {a.new}')
    refused = []
    for name, fm, body, _ in cc.load_pages(a.site):
        if cc.page_tag(body) != a.old or fm.get('commands') == 'historical':
            continue
        out = []
        cc.check_site_page(a.site, name, a.new, out.append)
        if out:
            refused.append(name)
            print('\n'.join(out))
    changed = bump(a.site, a.old, a.new, refuse=set(refused))
    print('\n'.join(f'bumped {p}' for p in changed) or 'nothing to bump')
    if refused:
        print(f'refused (fail against {a.new}): {", ".join(refused)}; the footer stays at {a.old}')
    tools = os.path.dirname(os.path.abspath(__file__))
    ok = not refused
    head('8. checks')
    ok &= run('check_site', [sys.executable, os.path.join(tools, 'check_site.py'), a.site])
    ok &= run('check_commands', [sys.executable, os.path.join(tools, 'check_commands.py'),
                                 '--latest', a.new, '--strict', a.site])
    if a.no_build:
        return 0 if ok else 1
    head('9. PDFs')
    ok &= run('render_pdf', [sys.executable, os.path.join(tools, 'render_pdf.py'), '--all',
                             a.site, os.path.join(a.site, 'pdf')])
    head('8. build and links')
    ok &= run('jekyll', ['bundle', 'exec', 'jekyll', 'build', '-s', a.site, '-d', '_site'],
              {'JEKYLL_ENV': 'production'})
    proof = ['bundle', 'exec', 'htmlproofer', './_site', '--swap-urls', '^/tacctl/:/']
    ok &= run('htmlproofer (internal)', proof + ['--disable-external'], {'LANG': 'C.UTF-8'})
    if a.external:
        ok &= run('htmlproofer (external)', proof + ['--cache', '{"timeframe":{"external":"2w"}}'],
                  {'LANG': 'C.UTF-8'})
    print('\nall steps passed' if ok else '\nsome steps failed (see above)')
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--from', dest='old', required=True)
    ap.add_argument('--to', dest='new', required=True)
    ap.add_argument('--site', default='site')
    ap.add_argument('--out')
    ap.add_argument('--finish', action='store_true')
    ap.add_argument('--no-fetch', action='store_true')
    ap.add_argument('--no-build', action='store_true')
    ap.add_argument('--external', action='store_true')
    a = ap.parse_args(argv)
    for t in (a.old, a.new):
        if not TAG.match(t):
            ap.error(f'not a release tag: {t}')
    a.out = a.out or f'/tmp/release-sync-{a.new}'
    try:
        return finish(a) if a.finish else discover(a)
    except (LookupError, RuntimeError) as e:
        print(e)
        return 1


if __name__ == '__main__':
    sys.exit(main())
