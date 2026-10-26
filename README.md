# gh-pages: the tacctl documentation site

Source of <https://rett.github.io/tacctl/>: operations guides for tacctl, built with
Jekyll and the just-the-docs theme. The site and its printable PDFs are built and deployed
by a GitHub Actions workflow; nothing built is committed here.

This is an **orphan branch**: it shares no history with `master` or `develop` and holds
no code. **Never merge it into a code branch.** Changes reach it only through pull requests
from `docs/<slug>` branches; the `build` check must pass before a merge.

| Path | Contents |
|---|---|
| `site/` | The Markdown pages, `_config.yml`, the theme overrides and a build plugin |
| `tools/check_site.py` | Checks links, section references, front matter (incl. `doctype`), house style and code width |
| `tools/check_commands.py` | Checks every `tacctl` command and flag on a page against `man/tacctl.1` at the release the page names; `--diff <old> <new>` lists what changed between releases |
| `tools/release_sync.py` | The per-release routine: `--from <old> --to <new>` finds what changed, `--finish` bumps the pages, checks, builds and renders |
| `tools/render_pdf.py` | Renders a page, or every page with `--all`, to PDF |
| `tools/test_*.py`, `tools/testdata/` | Tests of the tools: `python3 -m unittest discover -s tools -p 'test_*.py'` |
| `Gemfile`, `Gemfile.lock` | Jekyll, the theme, plugins and html-proofer |

Build and check locally:

```bash
python3 tools/check_site.py site
git fetch --no-tags origin tag $(python3 tools/check_commands.py --tags-needed site)
python3 tools/check_commands.py site
python3 tools/render_pdf.py --all site site/pdf      # needs weasyprint, markdown, pygments
bundle install
JEKYLL_ENV=production bundle exec jekyll build -s site -d _site
bundle exec htmlproofer ./_site --disable-external --swap-urls '^/tacctl/:/'
```

The reference documentation for every command is in
[docs/](https://github.com/rett/tacctl/tree/master/docs) on `master` and in `man tacctl`.
