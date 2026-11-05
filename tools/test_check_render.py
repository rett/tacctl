"""Tests for check_render.py: python3 -m unittest discover -s tools -p 'test_*.py'"""
import os
import subprocess
import sys
import tempfile
import unittest

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'check_render.py')

PAGE = '''---
title: "Demo"
permalink: "/demo/"
---

# Demo

## 1. First

Some text.

## 2. Second

Text with `code`.
'''


def built(h2s, extra=''):
    heads = ''.join(f'<h2 id="x{i}">{h}</h2>' for i, h in enumerate(h2s))
    return f'<html><body><div class="main-content">{heads}<p>text</p>{extra}</div></body></html>'


class CheckRender(unittest.TestCase):
    def run_tool(self, md, html):
        with tempfile.TemporaryDirectory() as d:
            site, out = os.path.join(d, 'site'), os.path.join(d, 'out')
            os.makedirs(site)
            os.makedirs(os.path.join(out, 'demo'))
            with open(os.path.join(site, 'demo.md'), 'w', encoding='utf-8') as f:
                f.write(md)
            with open(os.path.join(out, 'demo', 'index.html'), 'w', encoding='utf-8') as f:
                f.write(html)
            r = subprocess.run([sys.executable, TOOL, site, out], capture_output=True, text=True)
            return r.returncode, r.stdout

    def test_a_page_that_renders_as_written_passes(self):
        code, out = self.run_tool(PAGE, built(['1. First', '2. Second']))
        self.assertEqual(code, 0, out)

    def test_a_missing_heading_is_reported(self):
        # a page whose rest was taken for raw HTML: the second heading is not built
        code, out = self.run_tool(PAGE, built(['1. First']))
        self.assertEqual(code, 1)
        self.assertIn('headings differ', out)
        self.assertIn('2. Second', out)

    def test_markdown_left_in_the_text_is_reported(self):
        code, out = self.run_tool(PAGE, built(['1. First', '2. Second'], '<p>a `scope snmp</p>'))
        self.assertEqual(code, 1)
        self.assertIn('a backtick', out)

    def test_a_code_block_that_is_not_built_is_reported(self):
        md = PAGE + '\n```bash\ntacctl status\n```\n'
        code, out = self.run_tool(md, built(['1. First', '2. Second']))
        self.assertEqual(code, 1)
        self.assertIn('fenced code blocks', out)

    def test_curly_quotes_and_the_theme_heading_are_not_problems(self):
        md = PAGE.replace('## 1. First', "## 1. The server's login")
        code, out = self.run_tool(md, built(['Table of contents', '1. The server’s login', '2. Second']))
        self.assertEqual(code, 0, out)


if __name__ == '__main__':
    unittest.main()
