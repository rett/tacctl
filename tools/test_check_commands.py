"""Tests for check_commands.py: python3 -m unittest discover -s tools -p 'test_*.py'"""
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_commands as cc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

# A small man page in the shape of 0.2.3 and later: generated blocks per command.
MAN_NEW = textwrap.dedent(r'''
    .TH TACCTL 1 "2026-10-25" "tacctl 9.9.2"
    .SH COMMANDS
    .TP
    .BI "user add " name " " group " [ \-\-scopes " list " ]"
    .\" BEGIN GENERATED: command user add
    .RS
    .PP
    Requires: \fBsuperuser\fR.
    .PP
    Options:
    .TP
    \fB\-\-scopes\fR \fI<list>\fR
    The scopes.
    .TP
    \fB\-\-hash\fR \fI<hash>\fR
    A hash.
    .RE
    .\" END GENERATED: command user add
    .TP
    .BI "user disable " name
    .\" BEGIN GENERATED: command user disable
    Requires: \fBsuperuser\fR.
    .\" END GENERATED: command user disable
    .TP
    .BI "user enable " name
    .\" BEGIN GENERATED: command user enable
    Requires: \fBsuperuser\fR.
    .\" END GENERATED: command user enable
    .TP
    .B "config devices " "[ show ]"
    .\" BEGIN GENERATED: command config devices
    Requires: \fBreadonly\fR.
    .\" END GENERATED: command config devices
    .TP
    .B "config devices show"
    .\" BEGIN GENERATED: command config devices show
    Requires: \fBreadonly\fR.
    .\" END GENERATED: command config devices show
    .TP
    .BI "device client\-config"
    .\" BEGIN GENERATED: command device client-config
    Requires: \fBreadonly\fR.
    .\" END GENERATED: command device client-config
    .TP
    .BI "device sync " name
    .\" BEGIN GENERATED: command device sync
    Requires: \fBengineer\fR.
    Options:
    .TP
    \fB\-y\fR, \fB\-\-yes\fR
    Do not ask.
    .\" END GENERATED: command device sync
    .TP
    .BI "ssh " name
    .\" BEGIN GENERATED: command ssh
    Requires: \fBreadonly\fR.
    .\" END GENERATED: command ssh
    ''').lstrip('\n')

# The same tree one release earlier: a renamed verb, a renamed flag, a tier move.
MAN_OLD = (MAN_NEW.replace('client-config', 'ssh-config').replace(r'client\-config', r'ssh\-config')
           .replace(r'\fB\-\-hash\fR', r'\fB\-\-password\-hash\fR')
           .replace('Requires: \\fBengineer\\fR.', 'Requires: \\fBsuperuser\\fR.'))

# A man page in the shape of 0.2.2 and earlier: tags only.
MAN_TAGS = textwrap.dedent(r'''
    .SH COMMANDS
    .TP
    .B "config allow " "{ list | add | remove } " [ cidr[,cidr...] ]
    Manage the allow list.
    .TP
    \fB\-\-force\fR
    Force.
    .TP
    .BI "user show " name
    Show a user.
    .SH EXIT STATUS
    .TP
    .B loglevel
    Not a command: outside the command sections.
    ''').lstrip('\n')


def page(body, tag='9.9.2', extra=''):
    return (f'---\ntitle: "T"\ndescription: "D"\n{extra}---\n\n# T\n\n'
            f'*D · Checked against tacctl {tag}*\n\n{body}\n')


class Parse(unittest.TestCase):
    def test_generated_blocks(self):
        t = cc.parse_man(MAN_NEW)
        self.assertTrue(t.exact)
        self.assertEqual(t.commands[('user', 'add')], {'--scopes', '--hash'})
        self.assertEqual(t.commands[('device', 'sync')], {'-y', '--yes'})
        self.assertIn(('user',), t.families)
        self.assertNotIn(('user',), t.commands)
        self.assertTrue(t.runs(('config', 'devices')))
        self.assertEqual(t.tiers[('device', 'sync')], 'engineer')
        self.assertEqual(t.children(('user',)), {'add', 'disable', 'enable'})

    def test_tags_fallback(self):
        t = cc.parse_man(MAN_TAGS)
        self.assertFalse(t.exact)
        for verb in ('list', 'add', 'remove'):
            self.assertIn(('config', 'allow', verb), t.paths)
            self.assertIn('--force', t.commands[('config', 'allow', verb)])
        self.assertIn(('user', 'show'), t.paths)
        self.assertNotIn(('user', 'show', 'name'), t.paths)      # italic placeholder ends the path
        self.assertNotIn(('loglevel',), t.paths)                  # outside the command sections


class Check(unittest.TestCase):
    def setUp(self):
        self.tree = cc.parse_man(MAN_NEW)

    def problems(self, cmd):
        return cc.check_command(self.tree, cmd)

    def test_good(self):
        for cmd in ('user add alice operator --scopes site-a,site-b',
                    'user add <name> <group> [--scopes <list>]',
                    'user add alice operator --hash -    # paste the hash',
                    'user disable|enable <n>',
                    'config devices', 'config devices show', 'config devices anything',
                    'device client-config > ~/.ssh/tacctl.conf',
                    'device sync sw1 -y', 'device sync sw1 --help',
                    'ssh sw1 -- show version | include uptime',
                    'user', 'device', '…', '<command>',
                    'user add alice operator --scopes "a --b"'):
            self.assertEqual(self.problems(cmd), [], cmd)

    def test_bad(self):
        cases = {
            'users list': "'tacctl users' is not a command",
            'device ssh-config': "'tacctl device' has no sub-command 'ssh-config'",
            'user add alice operator --scope site-a': "'tacctl user add' has no flag --scope",
            'device sync sw1 --yes=1 --all': "'tacctl device sync' has no flag --all",
            'user disable|remove <n>': "'tacctl user' has no sub-command 'disable|remove'",
        }
        for cmd, want in cases.items():
            got = self.problems(cmd)
            self.assertEqual(len(got), 1, (cmd, got))
            self.assertIn(want, got[0])


class Pages(unittest.TestCase):
    def test_candidates(self):
        body = textwrap.dedent('''
            Run `tacctl user add alice operator` or `tacctl-console` or `tacctl`.

            | Task | Command |
            |---|---|
            | Toggle | `tacctl user disable\\|enable <n>` |

            ```bash
            tacctl user disable carol      # comment
            sudo tacctl ssh sw1
            $ tacctl device sync sw1 \\
                --yes
            ssh alice@tacacs.example.net
            ```

            ```text
            tacctl shell --password-cache
            tacctl console on tacacs — type 'help'.
            tacacs> device sync sw1
            $ tacctl ssh rtr1
            ```
            ''')
        got = [c for _, c in cc.candidates(body)]
        self.assertEqual(got, [
            'user add alice operator',
            'user disable|enable <n>',
            'user disable carol      # comment',
            'ssh sw1',
            'device sync sw1  --yes',
            'shell --password-cache',
            'device sync sw1',
            'ssh rtr1',
        ])

    def run_site(self, files, **kw):
        cc._cache.clear()
        cc._cache['9.9.2'] = cc.parse_man(MAN_NEW)
        cc._cache['9.9.1'] = cc.parse_man(MAN_OLD)
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                with open(os.path.join(d, name), 'w', encoding='utf-8') as f:
                    f.write(text)
            out = []
            n = cc.check_site(d, out=out.append, **kw)
        return n, out

    def test_site_per_page_tag(self):
        n, out = self.run_site({
            'a.md': page('`tacctl device client-config`'),
            'b.md': page('`tacctl device client-config`', tag='9.9.1'),
            'c.md': page('`tacctl device ssh-config`', tag='9.9.1'),
        })
        self.assertEqual(n, 1, out)
        self.assertTrue(out[0].startswith("b.md:"), out)

    def test_historical_and_missing_tag(self):
        n, out = self.run_site({
            'h.md': page('`tacctl enroll`', extra='commands: historical\n'),
            'x.md': '# X\n\n`tacctl ssh sw1`\n',
        })
        self.assertEqual(n, 1, out)
        self.assertIn('no "Checked against', out[1])

    def test_latest_and_strict(self):
        files = {'b.md': page('`tacctl ssh sw1`', tag='9.9.1')}
        n, out = self.run_site(files, latest='9.9.2')
        self.assertEqual(n, 0)
        self.assertTrue(out[0].startswith('warning:'))
        n, _ = self.run_site(files, latest='9.9.2', strict=True)
        self.assertEqual(n, 1)

    def test_override_tag(self):
        n, _ = self.run_site({'b.md': page('`tacctl device client-config`', tag='9.9.1')}, tag='9.9.2')
        self.assertEqual(n, 0)

    def test_tags_needed(self):
        with tempfile.TemporaryDirectory() as d:
            for name, tag in (('a.md', '0.2.19'), ('b.md', '0.2.9'), ('c.md', '0.2.19')):
                with open(os.path.join(d, name), 'w') as f:
                    f.write(page('x', tag=tag))
            self.assertEqual(cc.tags_needed(d), ['0.2.9', '0.2.19'])


class Diff(unittest.TestCase):
    def test_diff(self):
        lines = cc.diff(cc.parse_man(MAN_OLD), cc.parse_man(MAN_NEW))
        self.assertIn('renamed?  tacctl device ssh-config  ->  tacctl device client-config', lines)
        self.assertIn('flag renamed?  tacctl user add --password-hash  ->  --hash', lines)
        self.assertIn('tier changed  tacctl device sync: superuser -> engineer', lines)
        self.assertEqual(len(lines), 3, lines)


def have_tag(tag):
    return subprocess.run(['git', '-C', HERE, 'rev-parse', '-q', '--verify', f'refs/tags/{tag}'],
                          capture_output=True).returncode == 0


@unittest.skipUnless(have_tag('0.2.19'), 'tag 0.2.19 not fetched (git fetch --no-tags origin tag 0.2.19)')
class RealManPage(unittest.TestCase):
    """The man page at 0.2.19 read as the code's own command tree (testdata/README.md)."""

    def test_tree_and_flags_equal_the_code(self):
        os.environ['CHECK_COMMANDS_REPO'] = HERE
        cc._cache.pop('0.2.19', None)
        t = cc.man_at('0.2.19')
        want = {}
        with open(os.path.join(HERE, 'testdata', 'tree-0.2.19.tsv'), encoding='utf-8') as f:
            for line in f:
                path, _, flags = line.rstrip('\n').partition('\t')
                want[tuple(path.split())] = {x for x in flags.split(',') if x}
        self.assertTrue(t.exact)
        self.assertEqual(t.paths, set(want))
        for path, flags in want.items():
            self.assertEqual(t.commands.get(path, set()), flags, path)


if __name__ == '__main__':
    unittest.main()
