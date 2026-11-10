# tacctl

Go CLI that manages a TACACS+ (tacquito) and FreeRADIUS server, its users,
groups and scopes, network devices and enrolled Linux hosts.

## Read first

- `docs/development/README.md`: working rules, the examples table.
- `docs/plans/backlog.md` §0: the roadmap.
- The plan of the release in progress, under `docs/plans/`.
- `CONTRIBUTING.md`: branches, pull requests.
- `docs/releasing.md`: releases.

## Development environment

- The Go version is `GO_VERSION` in `bin/tacctl.sh`; the linter pin is `GOLANGCI_LINT_VERSION` in the `Makefile`.
- `make bootstrap` only initialises the bats submodules (`git submodule update --init --recursive`) and installs nothing else; preview it with `make -n bootstrap`.
- `make doctor` checks the checkout and prints one line per item: it prints only `ok`, `missing` and `expected` lines: `missing` is a problem, `expected` is a known accepted absence, and exit status 1 means at least one `missing`. Run it after pulling and before the gates.
- Agents never install system packages themselves; the doctor prints the install line.
- A new tool the project needs goes into `make doctor` and into this section in the same change.

## Commands

- Build: `make build` (binary in `dist/tacctl`)
- Go tests: `LANG=C.UTF-8 go test ./internal/...`
  Two tests need the 0.2.2 tag (the rollback build, the 0.2.2 schema); without it they skip and say so, so CI must fetch the tags.
- Gate run of the Go tests: `make gate-go` (`tests/tools/gate-go.sh`). Start it with Bash `run_in_background`, never with a trailing `&`, never wait for it with `pgrep -f`; only its final `GATE-GO PASS` line counts as a pass, and a `GATE-GO FAIL` line has up to ten `FAIL: <test>` lines above it (the packages instead, when no test failed). `GATE_TMPFS=1 make gate-go` runs the tests' sandboxes on `/dev/shm`, about three times faster.
- CI-equivalent run of the Go tests: `make gate-ci` (`tests/tools/gate-ci.sh`).
  `make gate-go` runs neither the race detector nor `-tags testknobs`; CI runs both (the packages but `internal/cli` with `-race`, the two `internal/cli` shards), so run this before a pull request or a release PR. Same rules as `gate-go` (`run_in_background`, no `&`, no `pgrep -f`, `GATE_TMPFS=1`); only its final `GATE-CI PASS` line counts, a `GATE-CI FAIL` line names the failing tests, and it takes several times as long as `gate-go`.
- Lint: `make lint GOLANGCI_LINT=<path to golangci-lint>` (includes `tests/tools/no-private.sh`)
- Bats: `make build`, then as an ordinary user, neither root nor one with sudo (`tests/README.md`): `tests/bats/bats-core/bin/bats tests/integration/<file>.bats`
- Diff corpus: `tests/diff/run.sh --all --against <previous release tag>`
- Containers (rootless podman): `tests/containers/run-all.sh` (the whole matrix, with a table) or one of `tests/containers/{hosts,radius,fresh}/run.sh`
- The whole-suite runs are gated per feature with `make lint`, the static checks (`test -z "$(gofmt -l cmd internal)"`, `go vet ./...` and `go vet -tags testknobs ./...`, `tests/tools/go-test-shard.sh --check 2`) and `GATE_TMPFS=1 make gate-go`; per release with `GATE_TMPFS=1 make gate-ci`.

## Rules

- No private names (hosts, addresses, users, home paths, domains) in repo files or commit messages.
- Examples are generic and standard: every domain, host, user, address, time zone (`UTC`), location, SNMP value, secret, serial number and pasted device output comes from the table in `docs/development/README.md` (§ Examples), in docs, man page, help, CHANGELOG, tests and commit messages.
- No Claude attribution in commit messages (no `Claude-Session`, `Co-authored-by` or `Generated with` lines). The owner is the author of every commit made with the project's own tooling: reset a member's author when taking a series in (`git rebase --exec 'git commit --amend --no-edit --reset-author'`); `.mailmap` names the owner for the identities of earlier commits. The one exception is an outside pull request: its commits keep the contributor as author and are merged with a merge commit, never rebased or re-authored. Push only to the current feature branch unless told otherwise.
- Never act against the production host.
- Every user-visible change gets a numbered CHANGELOG item.
- Every user-visible change also updates `man/tacctl.1` and the matching page under `docs/` (`README.md` only holds the quick start and the index) in the same change; the man page shows everything and is never tier-filtered (`make lint` runs the man tests, `make lint-man`, which check it against the code, and `groff -k -ww`; `make man` rewrites its generated blocks).
- Plans are pruned once implemented: delete a release's plan, handoff, lab sheet and spike in the release that ships it (`docs/development/README.md`, Working rules).
