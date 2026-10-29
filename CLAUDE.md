# tacctl

Go CLI that manages a TACACS+ (tacquito) and FreeRADIUS server, its users,
groups and scopes, network devices and enrolled Linux hosts.

Start with `docs/development/README.md` (working rules, examples), then
`docs/plans/backlog.md` §0 (roadmap) and the plan of the release in progress.

## Commands

- Build: `make build` (binary in `dist/tacctl`)
- Go tests: `LANG=C.UTF-8 go test ./internal/...`
  Two tests need the 0.2.2 tag (the rollback build, the 0.2.2 schema); without it they skip and say so, so CI must fetch the tags.
- Gate run of the Go tests: `make gate-go` (`tests/tools/gate-go.sh`). Start it with Bash `run_in_background`, never with a trailing `&`, never wait for it with `pgrep -f`; only its final `GATE-GO PASS` line counts as a pass. `GATE_TMPFS=1 make gate-go` runs the tests' sandboxes on `/dev/shm`, about three times faster.
- CI-equivalent run of the Go tests: `make gate-ci` (`tests/tools/gate-ci.sh`).
  `make gate-go` runs neither the race detector nor `-tags testknobs`; CI runs both (the packages but `internal/cli` with `-race`, the two `internal/cli` shards), so run this before a pull request or a release PR. Same rules as `gate-go` (`run_in_background`, no `&`, no `pgrep -f`, `GATE_TMPFS=1`); only its final `GATE-CI PASS` line counts, a `GATE-CI FAIL` line names the failing tests, and it takes several times as long as `gate-go`.
- Lint: `make lint GOLANGCI_LINT=<path to golangci-lint>` (includes `tests/tools/no-private.sh`)
- Bats: `make build`, then as user `tester`: `tests/bats/bats-core/bin/bats tests/integration/<file>.bats`
- Diff corpus: `tests/diff/run.sh --all --against <previous release tag>`
- Containers (rootless podman): `tests/containers/run-all.sh` (the whole matrix, with a table) or one of `tests/containers/{hosts,radius,fresh}/run.sh`

## Rules

- No private names (hosts, addresses, users, home paths, domains) in repo files or commit messages.
- Examples are generic and standard: every domain, host, user, address, time zone (`UTC`), location, SNMP value, secret, serial number and pasted device output comes from the table in `docs/development/README.md` (§ Examples), in docs, man page, help, CHANGELOG, tests and commit messages.
- No Claude attribution in commit messages. Push only to the current feature branch unless told otherwise.
- Never act against the production host.
- Every user-visible change gets a numbered CHANGELOG item.
- Every user-visible change also updates `man/tacctl.1` and the matching page under `docs/` (`README.md` only holds the quick start and the index) in the same change; the man page shows everything and is never tier-filtered (`make lint` runs the man tests, `LANG=C.UTF-8 go test ./internal/cli -run Man`, which check it against the code, and `groff -k -ww`; `make man` rewrites its generated blocks).
- Plans are pruned once implemented: delete a release's plan, handoff, lab sheet and spike in the release that ships it (`docs/development/README.md`, Working rules).
