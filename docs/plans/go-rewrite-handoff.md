# Go rewrite: handoff (2026-10-03, before a reboot)

Read this first when resuming, then `docs/plans/go-rewrite.md`: its status notes, §3.9 (the intentional changes, items 1-26) and §9.6 onwards. The decisions are recorded in the plan (§12, plus the dated notes) and in `docs/plans/backlog.md`. The project memory in `~/.claude/projects/-home-user-tacctl/memory/project_go_rewrite.md` has the full chronology.

## Where things stand

- **Branch `feature/go-rewrite`** (local only, never pushed) holds Phases 0–3, complete.
  - Every tacctl command runs natively in Go; nothing is delegated to bash any more.
  - The bootstrap shim is staged as `bin/tacctl.sh.new`.
  - `bin/tacctl.sh` (bash 0.1.17) and `lib/` are still in the tree. They are the parity baseline the tests run against.
- **Last full verification** (before the shim-checksum change):
  - Go black-box: 896/896, and 898/898 after it.
  - Bash suite: 1523/1523.
  - Bash-vs-Go corpora: only the §3.9 differences.
  - Lint: 0 issues.
  - `make test-go`: green with and without `-tags testknobs`.
- **Container cross-over rehearsal passed** (rootless podman on the dev server): 0.1.17 → Go on both upgrade paths, then a no-op second upgrade, then back to 0.1.17, plus a fresh Go install. Its scripts are now in `tests/containers/crossover/` (see the README there). The images `localhost/tacctl-rehearsal:{noble,installed-0.1.17}` persist in rootless podman storage.
- **Released bash versions:**
  - **0.1.17** (tag on `master` 6ce7a09, pushed): the tacquito `.bak` `cp -p` fix. The dev server runs it.

## Done since: 0.1.18 and the private-names scrub (2026-10-03 evening)

- **0.1.18 released:** the full suite passed (1441/1441), and the release is tagged, pushed and merged into `feature/go-rewrite`. The parity baseline is now the `0.1.18` tag (`tests/diff/run.sh`, `TACCTL_BASH_RELEASE` in `bin/tacctl.sh.new`). The dev server runs it with no restarts.
- **History rewritten again** to replace personal host names, home paths and user names with roles and `example.*` placeholders. `master`, `develop` and the release tags were force-pushed; the dev server's clone was reset to `origin/develop`. Commit references in the docs name the rewritten commits.
- **Guard:** `make lint` runs `tests/tools/no-private.sh`, which uses generic checks plus an untracked `~/.config/tacctl/private-patterns`. `make hooks` installs it as a pre-push hook.
- **A clone made before the history rewrites** holds the old SHAs. Before `sudo tacctl upgrade`, reset it: `sudo git -C /opt/tacctl status` (expect clean), `sudo git -C /opt/tacctl fetch --tags --force origin`, `sudo git -C /opt/tacctl reset --hard origin/master`.

## Next work packages (Phase 4, then 5): one at a time

1. **WP4.1.**
   - `mv bin/tacctl.sh.new bin/tacctl.sh`.
   - Delete `lib/`, `internal/cli/delegate.go`, the `delegatedKey` annotation and the delegation tests, `TACCTL_BASH_IMPL`/`paths.BashImpl`, and the bash-only branches of the bats files.
   - Reconcile the suite: white-box bats become Go tests or are dropped, as documented.
   - Make the Makefile `test` target run against Go.
   - Update `lint-sh`, `shim.bats` (`SHIM=` and its recipe-identity test) and `TestShimGoVersionIsTacctls`.
   - The bash parity side is then the **tag** (`tests/diff/run.sh --against 0.1.18`).
2. **WP4.2.**
   - Generated completion: `tacctl completion bash`. Install currently copies `config/tacctl.bash-completion` from the tree.
   - Man page, README and CHANGELOG, under the user's documentation policy: current behaviour only, no "formerly" notes; history goes in the CHANGELOG.
   - Document `-y`, `config render --dry-run --out`, `version --long`, and the README one-liner.
   - Replace `tests/containers/hosts/run.sh:105`'s sourcing of `cmd_config_linux_build`.
3. **WP4.3.** The parity proof: `tests/diff/run.sh --all --against 0.1.18`, every difference classified under §3.9, written up in `docs/plans/go-rewrite-parity.md`.
4. **WP5.1, WP5.2, WP5.3.** Live acceptance on the dev server, then the test client, then release prep (plan §6.4, §6.6).
   - The user does the logins with real passwords, runs the roughly 1.5-hour container matrix on the release candidate, and runs the GitHub metadata command (§7.4).
   - Always use `--scope lab` when re-enrolling the test client or the dev server.

## Working rules that held all campaign

- **Scope:** 0.2.0 is functional equivalence only (user). New ideas go in `docs/plans/backlog.md`; the operator console is 0.2.1/0.2.2 in `docs/plans/operator-console.md`.
- **Who commits:** subagents never commit. The coordinator commits at package boundaries when lint and tests are green, and never pushes `feature/go-rewrite` without being asked.
- **Worktrees:** create them manually from the current branch tip (`git worktree add <scratch>/wt-x -b wp/x <HEAD>`, then `submodule update --init --recursive`), and cherry-pick the results.
- **Briefs:** forbid polling loops, since a `pgrep -f` loop once ran for 7 hours. Every test env must sandbox all host paths (there are guard tests), with no host-default `TACQUITO_SRC`, logrotate, `/usr/local/bin` or `/opt/tacctl`.
- **Live tests:** only on the dev hosts. Snapshot the dev server before any live test.
- **Go on the dev server:** `~/go` and `~/.cache/go-build` are root-owned, so use `GOCACHE=$HOME/.cache/tacctl/go-build` and `GOPATH=$HOME/.cache/tacctl/gopath`. golangci-lint 2.14.0 is in `~/.local/bin`. GNU parallel is installed, so `BATS_JOBS=4` works.
- **The user decides:** shown as AskUserQuestion with a recommendation. For example: tentative features are questions, documentation describes current behaviour only, and hotfixes go to 0.1.x.

## After the reboot

- Run `git worktree prune` in `/home/user/tacctl`; the scratch worktrees under `/tmp` are gone.
- Branch to keep: `feature/go-rewrite`.
- `ps` should show no tacctl test processes.
- The dev server services: `systemctl is-active tacquito freeradius`.
