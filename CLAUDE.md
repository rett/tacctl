# tacctl

Go CLI that manages a TACACS+ (tacquito) and FreeRADIUS server, its users,
groups and scopes, network devices and enrolled Linux hosts.

Start with `docs/plans/0.2.4-handoff.md` (state, scope, working rules), then
`docs/plans/backlog.md` §0 (roadmap) and the current release plan.

## Commands

- Build: `make build` (binary in `dist/tacctl`)
- Go tests: `LANG=C.UTF-8 go test ./internal/...`
  Two tests need the 0.2.2 tag (the rollback build, the 0.2.2 schema); without it they skip and say so, so CI must fetch the tags.
- Lint: `make lint GOLANGCI_LINT=<path to golangci-lint>` (includes `tests/tools/no-private.sh`)
- Bats: `make build`, then as user `tester`: `tests/bats/bats-core/bin/bats tests/integration/<file>.bats`
- Diff corpus: `tests/diff/run.sh --all --against <previous release tag>`
- Containers (rootless podman): `tests/containers/run-all.sh` (the whole matrix, with a table) or one of `tests/containers/{hosts,radius,fresh}/run.sh`

## Rules

- No private names (hosts, addresses, users, home paths, domains) in repo files or commit messages.
- No Claude attribution in commit messages. Push only to the current feature branch unless told otherwise.
- Never act against the production host.
- Every user-visible change gets a numbered CHANGELOG item.
- Every user-visible change also updates `man/tacctl.1` and `README.md` in the same change; the man page shows everything and is never tier-filtered (`make lint` runs the man tests, `LANG=C.UTF-8 go test ./internal/cli -run Man`, which check it against the code, and `groff -k -ww`; `make man` rewrites its generated blocks).
