"""Render site pages to PDF (WeasyPrint).

Usage:
    python3 tools/render_pdf.py <site/page.md> <out.pdf>
    python3 tools/render_pdf.py --all <site-dir> <out-dir>

A page is rendered when it carries the '[Printable PDF](...pdf)' line; --all
renders every such page to the file name that line links to. The header
title is the front-matter 'title'. The front matter and the PDF line are
dropped, links to other pages ('page.md') print as italic text, relative
links print as plain text, and the italic '*<subtitle> · Checked against
...*' line under the H1 becomes the cover subtitle.

Needs: pip install weasyprint markdown pygments; fonts Inter and DejaVu Sans Mono.
"""
import glob
import json
import os
import re
import sys

PDF_LINE = re.compile(r'^\[Printable PDF\]\((?:\.\./)?pdf/([a-z0-9-]+\.pdf)\)(\{:[^}]*\})?\s*$', re.M)

CSS = """
@page{size:Letter;margin:22mm 20mm 20mm 20mm;
 @top-right{content:"tacctl · __HDR__";font:8.5pt Inter;color:#7a8699}
 @bottom-center{content:counter(page) " / " counter(pages);font:8.5pt Inter;color:#7a8699}}
@page:first{@top-right{content:none}}
body{font-family:Inter;font-size:10pt;line-height:1.5;color:#1f2933}
h1{font-size:26pt;color:#0b3d61;margin:0 0 4mm;border-bottom:3px solid #1a73a8;padding-bottom:3mm}
h2{font-size:15pt;color:#0b3d61;margin-top:9mm;border-bottom:1px solid #d5dde6;padding-bottom:1.5mm;page-break-after:avoid}
h3{font-size:11.5pt;color:#1a5a85;margin-top:6mm;page-break-after:avoid}
h2+p,h3+p{page-break-before:avoid}
a{color:#1a73a8;text-decoration:none}
code{font-family:'DejaVu Sans Mono';font-size:8.6pt;background:#eef2f6;padding:0 2px;border-radius:2px}
.hl{background:#f6f8fa;border:1px solid #dde3ea;border-left:3px solid #1a73a8;border-radius:3px;padding:2.5mm 3mm;margin:3mm 0;page-break-inside:avoid}
.hl pre{margin:0;white-space:pre-wrap;font-size:8.3pt;line-height:1.4}
.hl code{background:none;padding:0}
pre{font-family:'DejaVu Sans Mono'}
table{border-collapse:collapse;width:100%;margin:3mm 0;font-size:8.8pt}
tr{page-break-inside:avoid} thead{display:table-header-group}
th{background:#0b3d61;color:#fff;text-align:left;padding:1.6mm 2mm;font-weight:600}
td{border-bottom:1px solid #dde3ea;padding:1.4mm 2mm;vertical-align:top}
tr:nth-child(even) td{background:#f7f9fb}
blockquote{margin:3mm 0;padding:2mm 4mm;background:#fff8e6;border-left:3px solid #e0a100;color:#3d3420}
blockquote p{margin:1mm 0}
.toc{page-break-after:always}
.toc ul{list-style:none;padding-left:0}.toc ul ul{padding-left:6mm;font-size:9.3pt}
.toc li{margin:1mm 0}.toc>ul>li>a{font-weight:600;color:#0b3d61}
.toc a::after{content:leader('.') target-counter(attr(href),page);color:#7a8699}
.subtitle{color:#52606d;font-size:11pt}
"""


def front_matter(text):
    """Return (dict, body) for a page that starts with '---' front matter."""
    if not text.startswith('---\n'):
        return {}, text
    end = text.index('\n---\n', 4)
    fm = {}
    for line in text[4:end].split('\n'):
        key, _, val = line.partition(':')
        val = val.strip()
        if val.startswith('"'):
            val = json.loads(val)
        fm[key.strip()] = val
    return fm, text[end + 5:].lstrip('\n')


def render(src_path, out_path):
    import markdown
    from pygments.formatters import HtmlFormatter
    from weasyprint import HTML
    fm, src = front_matter(open(src_path, encoding='utf-8').read())
    title = fm.get('title') or sys.exit(f'{src_path}: no title in the front matter')
    src = PDF_LINE.sub('', src)
    src = re.sub(r'\[([^\]]+)\]\(([a-z0-9-]+\.md)(#[^)\s]*)?\)', r'*\1*', src)      # other pages -> italic
    src = re.sub(r'\[([^\]]+)\]\((?![a-z]+:|#)[^)]+\)', r'\1', src)               # other relative links -> text
    md = markdown.Markdown(extensions=['tables', 'fenced_code', 'codehilite', 'toc', 'sane_lists'],
                           extension_configs={'codehilite': {'guess_lang': False, 'css_class': 'hl'},
                                              'toc': {'toc_depth': '2-3'}})
    body = md.convert(src).replace('\\|', '|')      # escaped pipes in table cells
    body = body.replace('<hr />', '', 1)
    title_end = body.index('</h1>') + 5
    m = re.match(r'\s*<p><em>(.*?Checked against.*?)</em></p>', body[title_end:], flags=re.S)
    if not m:
        sys.exit(f"{src_path}: the line under the H1 must be '*<subtitle> · Checked against ...*'")
    sub = m.group(1)
    body = body[:title_end] + body[title_end + m.end():]
    toc = '<nav class="toc"><h2>Contents</h2>' + md.toc + '</nav>'
    css = HtmlFormatter(style='friendly').get_style_defs('.hl') + CSS.replace('__HDR__', title)
    html = (f"<html><head><meta charset='utf-8'><style>{css}</style></head><body>"
            f"{body[:title_end]}<p class='subtitle'>{sub}</p>{toc}{body[title_end:]}</body></html>")
    HTML(string=html).write_pdf(out_path)


def main(argv):
    if len(argv) == 4 and argv[1] == '--all':
        site, out = argv[2], argv[3]
        os.makedirs(out, exist_ok=True)
        n = 0
        for page in sorted(glob.glob(os.path.join(site, '*.md'))):
            m = PDF_LINE.search(open(page, encoding='utf-8').read())
            if m:
                render(page, os.path.join(out, m.group(1)))
                n += 1
        print(f'rendered {n} PDFs into {out}')
        return 0 if n else 1
    if len(argv) == 3:
        render(argv[1], argv[2])
        return 0
    sys.exit(__doc__)


if __name__ == '__main__':
    sys.exit(main(sys.argv))
