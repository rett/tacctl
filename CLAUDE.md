# tacctl

Go CLI that manages a TACACS+ (tacquito) and FreeRADIUS server, its users,
groups and scopes, network devices and enrolled Linux hosts.

Start with `docs/plans/0.2.3-handoff.md` (state, scope, working rules), then
`docs/plans/backlog.md` §0 (roadmap) and the current release plan.

## Commands

- Build: `make build` (binary in `dist/tacctl`)
- Go tests: `LANG=C.UTF-8 go test ./internal/...`
- Lint: `make lint GOLANGCI_LINT=<path to golangci-lint>` (includes `tests/tools/no-private.sh`)
- Bats: `make build`, then as user `tester`: `tests/bats/bats-core/bin/bats tests/integration/<file>.bats`
- Diff corpus: `tests/diff/run.sh --all --against <previous release tag>`
- Containers (rootless podman): `tests/containers/{hosts,radius,fresh}/run.sh`

## Rules

- No private names (hosts, addresses, users, home paths, domains) in repo files or commit messages.
- No Claude attribution in commit messages. Push only to the current feature branch unless told otherwise.
- Never act against the production host.
- Every user-visible change gets a numbered CHANGELOG item.
