# Contributing to tacctl

tacctl accepts pull requests and issues from anyone. A security problem is not reported in a
public issue: open an issue that only asks for a private channel, without describing the problem,
and the maintainer will answer there.

`AGENTS.md` holds the commands, the rules and the development environment; this page does not
repeat them. `docs/development/README.md` has the working rules and the examples table.

## Branches

- `master` holds the tagged releases.
- `develop` is the integration branch.
- Work happens on `feature/<name>`, cut from `develop` and merged back with `--no-ff`.
- `release/<version>` and `hotfix/<version>` are cut by the maintainer.
- `gh-pages` is the documentation site and is never merged into the others.

A pull request from a contributor targets `develop`.

## What a change carries

- A numbered item in the next release's section of `CHANGELOG.md` (the heading is
  `## <next version> (unreleased)`). Use the next free number; the maintainer renumbers.
- For a user-visible change, also `man/tacctl.1` and the matching page under `docs/`.
- Examples only from the table in `docs/development/README.md` (§ Examples).
- No private names (hosts, addresses, users, home paths, domains) in files or commit messages.
- No attribution trailers in commit messages.

## Authorship

Commits that arrive in an outside pull request keep their author. The maintainer merges the pull
request with a merge commit and does not rebase or re-author it. Commits the maintainer makes with
their own tooling carry the maintainer as author.

## Before opening a pull request

Run `make lint` and `GATE_TMPFS=1 make gate-go`; the maintainer runs the longer `make gate-ci`
before a release. `AGENTS.md` ("Commands") lists the rest. CI runs the `test` workflow on every
pull request.

## Releases

The maintainer cuts them; the steps are in `docs/releasing.md`.
