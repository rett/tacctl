"""Tests for release_sync.py: python3 -m unittest discover -s tools -p 'test_*.py'"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_commands as cc  # noqa: E402
import release_sync as rs  # noqa: E402
from test_check_commands import MAN_NEW, MAN_OLD, page  # noqa: E402


class Bump(unittest.TestCase):
    def site(self, d, pages):
        os.makedirs(os.path.join(d, '_includes'))
        for name, text in pages.items():
            with open(os.path.join(d, name), 'w', encoding='utf-8') as f:
                f.write(text)
        with open(os.path.join(d, '_includes', 'footer_custom.html'), 'w', encoding='utf-8') as f:
            f.write('<p>Checked against <strong>tacctl 9.9.1</strong> · x</p>\n')

    def read(self, d, name):
        with open(os.path.join(d, name), encoding='utf-8') as f:
            return f.read()

    def test_bump_line_3_and_footer(self):
        with tempfile.TemporaryDirectory() as d:
            self.site(d, {
                'a.md': page('`tacctl ssh sw1`', tag='9.9.1'),
                'h.md': page('tacctl 9.9.1 added `tacctl x`. Checked against tacctl 9.9.1 here.',
                             tag='9.9.1', extra='commands: historical\n'),
                'o.md': page('x', tag='9.9.0'),
            })
            changed = rs.bump(d, '9.9.1', '9.9.2')
            self.assertEqual(sorted(os.path.basename(p) for p in changed),
                             ['a.md', 'footer_custom.html', 'h.md'])
            h = self.read(d, 'h.md')
            self.assertIn('*D · Checked against tacctl 9.9.2*', h)
            self.assertIn('Checked against tacctl 9.9.1 here.', h)   # only line 3 changes
            self.assertIn('tacctl 9.9.1 added', h)
            self.assertIn('tacctl 9.9.0', self.read(d, 'o.md'))      # another tag is left alone
            self.assertIn('tacctl 9.9.2</strong>', self.read(d, '_includes/footer_custom.html'))

    def test_refused_page_keeps_footer(self):
        with tempfile.TemporaryDirectory() as d:
            self.site(d, {'a.md': page('x', tag='9.9.1'), 'b.md': page('y', tag='9.9.1')})
            changed = rs.bump(d, '9.9.1', '9.9.2', refuse={'b.md'})
            self.assertEqual([os.path.basename(p) for p in changed], ['a.md'])
            self.assertIn('tacctl 9.9.1', self.read(d, 'b.md'))
            self.assertIn('tacctl 9.9.1</strong>', self.read(d, '_includes/footer_custom.html'))


class Finish(unittest.TestCase):
    def test_finish_refuses_a_failing_page(self):
        cc._cache.clear()
        cc._cache['9.9.1'] = cc.parse_man(MAN_OLD)
        cc._cache['9.9.2'] = cc.parse_man(MAN_NEW)
        with tempfile.TemporaryDirectory() as d:
            Bump.site(self, d, {
                'good.md': page('`tacctl ssh sw1`', tag='9.9.1'),
                'bad.md': page('`tacctl device ssh-config`', tag='9.9.1'),
            })
            args = ['--from', '9.9.1', '--to', '9.9.2', '--site', d, '--finish', '--no-build']
            calls = []
            run, rs.run = rs.run, lambda title, cmd, env=None: calls.append(title) or True
            with open(os.devnull, 'w') as null:
                stdout, sys.stdout = sys.stdout, null
                try:
                    rc = rs.main(args)
                finally:
                    sys.stdout, rs.run = stdout, run
            self.assertEqual(calls, ['check_site', 'check_commands'])
            self.assertEqual(rc, 1)
            self.assertIn('tacctl 9.9.2', Bump.read(self, d, 'good.md'))
            self.assertIn('tacctl 9.9.1', Bump.read(self, d, 'bad.md'))


class Mentions(unittest.TestCase):
    def test_mentions(self):
        with tempfile.TemporaryDirectory() as d:
            for name, body in (('a.md', 'Run `tacctl device ssh-config`.'),
                               ('b.md', 'Console: `device ssh-config`'),
                               ('c.md', '`tacctl device ssh-configs`')):
                with open(os.path.join(d, name), 'w', encoding='utf-8') as f:
                    f.write(page(body))
            self.assertEqual(rs.mentions(d, ['device', 'ssh-config']), ['a.md', 'b.md'])


if __name__ == '__main__':
    unittest.main()
