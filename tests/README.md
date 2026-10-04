# tacctl tests

tacctl is a Go program (`cmd/tacctl`, `internal/...`) with a bash bootstrap
shim (`bin/tacctl.sh`). Its tests come in layers:

| Layer | Tool | What it proves | Where |
|---|---|---|---|
| Go unit tests | `go test -race ./...` with the fake runner, temp dirs and the test knobs | every package on its own: the PyYAML-compatible reader and writer, the store, the model, the renderers, the backend contract (with a stand-in backend), the lifecycle phases, the CLI's argument handling, exit codes and usage blocks | `internal/*/..._test.go` |
| Goldens | Go tests and bats `golden_diff` over `tests/fixtures/golden/*`, `tests/fixtures/store.*.yaml`, `tests/fixtures/model/*.json` | rendered artifacts byte for byte | both layers |
| Black-box bats | bats-core against `dist/tacctl` | the command line: output, exit codes, prompts, files and modes, the system commands run (PATH stubs) | `tests/integration`, `tests/e2e` |
| Differential | `tests/diff/run.sh` | the binary against the last bash release (the `0.1.18` tag) on the same inputs, success and error paths | on demand |
| Containers | rootless podman | real FreeRADIUS, real PAM logins on enrolled hosts, the cross-over from the bash release | on demand, never by `make test` |

## Running

```sh
make bootstrap       # first time: pull the bats submodules
make test            # make test-go, then the bats suite against dist/tacctl
make test-go         # go test -race ./..., with and without -tags testknobs
make test-bats       # make build, then the bats suite (integration, then e2e)
make test-integration
make test-e2e
make build           # dist/tacctl: bin/tacctl.sh --build with the test knobs compiled in
make coverage        # go test -coverprofile; coverage/go.out, coverage/index.html and the total
make lint            # shellcheck (bin/tacctl.sh, config/linux, tests/helpers, tests/tools, tests/diff,
                     #   tests/containers/crossover), gofmt, go vet, golangci-lint (pinned; prints how
                     #   to install it when missing), and tests/tools/no-private.sh
make test-pyyaml     # the yamlpy and conf PyYAML corpora regenerated with PyYAML and compared
make test-diff CORPUS=users   # the differential runner on one corpus
```

The bats files run in parallel (`bats --jobs`, one file per job, the tests of
a file in order) when GNU `parallel` is installed: `BATS_JOBS` sets the number
of jobs (default: the CPU count), `BATS_JOBS=1` runs serially. `BATS_FLAGS`
is passed to bats (default `--print-output-on-failure`).

Run a single file or test (after `make build`):

```sh
tests/bats/bats-core/bin/bats tests/integration/user_crud.bats
tests/bats/bats-core/bin/bats --filter 'user add' tests/integration/user_crud.bats
go test -run TestStoreApply ./internal/backend
```

Test-time tools: bash, GNU coreutils, `parallel` (optional), and `python3`
for a few bats assertions that read JSON and for the generators below. The
binary itself runs no python3.

## Layout

```
tests/
├── bats/                # vendored bats-core + helpers (git submodules)
├── helpers/             # setup.bash, tmpenv.bash, mocks.bash, fixtures.bash
├── fixtures/
│   ├── tacquito.*.yaml  # tacquito.yaml fixtures (every one must import into the store without --force)
│   ├── legacy.*.yaml    # tacquito.yaml inputs for the importer and the upgrade gate (edge cases, unrepresentable content, the old installer's output)
│   ├── store.*.yaml     # store.yaml fixtures; store.X.yaml is exactly what importing tacquito.X.yaml writes
│   ├── model/           # golden model JSON (what 'store show --json' prints for a fixture)
│   ├── systemd/         # unit files of earlier releases
│   └── golden/          # expected rendered output: device configs, tacquito.X.rendered.yaml,
│                        #   radius.<family>.*, drop-ins, rendered.json, the templates manifest,
│                        #   the Linux installer headers, tacctl.overrides.yaml
├── integration/         # the command line against real files in the test's tmpdir
├── e2e/                 # whole command flows with stubbed system commands
├── diff/                # the differential runner, its corpora, stubs and state roots
├── tools/               # no-private.sh (lint), pyyaml-corpus.py, usage-goldens.sh, pre-push
├── containers/radius/   # real FreeRADIUS in podman
├── containers/hosts/    # 'host enroll|sync|unenroll' for real, server and client containers
└── containers/crossover/ # the upgrade from the bash release to the Go binary, and back
```

Go tests live beside their packages; their own inputs are in each package's
`testdata/`.

## The bats harness

`tests/helpers/setup.bash` points `TACCTL_BIN_SCRIPT` at `dist/tacctl` (it
stops with a message when the binary is missing: run `make build`) and sets
`TACCTL_TREE` to this checkout, the tree the binary treats as its own
(templates, patches, the deploy clone of `config branch`).
`tacctl_tmpenv_init` (`tests/helpers/tmpenv.bash`) points every `TACCTL_*`
path into `$BATS_TEST_TMPDIR` and sets `TACCTL_SKIP_SUDO=1`;
`tests/integration/fixtures.bats` checks that it does.

**Writing a test:**

```bash
#!/usr/bin/env bats
load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd systemctl
    load_fixture tacquito.minimal.yaml
}

@test "tacctl user list shows fixture users" {
    run "$TACCTL_BIN_SCRIPT" user list
    assert_success
    assert_output --partial 'alice'
}

@test "a mutation restarts tacquito" {
    run "$TACCTL_BIN_SCRIPT" user disable alice
    assert_success
    stub_called 'systemctl restart tacquito'
}
```

- `tacctl_mocks_init` prepends `$BATS_TEST_TMPDIR/stubs` to `PATH`;
  `stub_cmd <name> [body]` shadows a system command there and records each
  call in `$CALLS_LOG`; `stub_called`, `refute_called` and `stub_calls`
  check it. The binary finds programs through PATH, so the stubs work for it
  exactly as for a shell script. What it still runs: `systemctl`,
  `journalctl`, `ss`, `ps`, `visudo`, `install` (sudoers only), `ssh`,
  `podman`, `git`, `go`, `wget`, the package managers, `useradd`/`userdel`,
  `id`, `getent`, `logger`, `ip`, `tar`, `mandb`, `diff`, `tacquito` and the
  FreeRADIUS daemon's `-C`. File work, hashing, randomness, dates and YAML
  are native: there is nothing to stub for `chown`, `openssl`, `date`,
  `sleep`, `curl` or `python3`, so tests assert the effect (modes, contents,
  the knobs below fixing the clock and the random bytes).
- Ownership (`tacquito:tacquito`, `root:freerad`) is set natively and best
  effort; unprivileged it cannot be checked, so tests assert mode and content.
- Every scratch directory goes under `TMPDIR`; tests that care set `TMPDIR`
  to a directory of their own and assert it is empty afterwards.
- `config listen|loglevel|metrics` restart a unit and check that it stayed
  up after `TACCTL_SETTLE_SECONDS` (default 0.5): export
  `TACCTL_SETTLE_SECONDS=0` in a file that runs many of them.
- `TACCTL_SYSTEMD_DIR` (unit files and the instances' drop-in directories)
  defaults to the parent of `TACCTL_OVERRIDE_DIR`, which tmpenv puts in the
  test's tmpdir. A test that needs the real layout exports both.
- The hidden commands are part of the contract the tests use:
  `_completion-names <kind>` (the completion bridge: users, groups, scopes,
  backups, backends, enabled-backends, listeners) and `_phase <backend>
  <install|upgrade|uninstall> <phase>[,<phase>...] [<tree>|--keep-logs]`,
  which runs lifecycle phases of one backend on their own and prints
  `SUMMARY <note>` / `SAVED <line>` for what they leave to the closing
  summaries (`radius.bats` drives the RADIUS upgrade and uninstall phases
  that way; the container drivers drive them in real containers).
- The completion is the binary's own: `tacctl completion bash|zsh|fish` prints
  the script and `tacctl __complete <words>` answers it. `completion.bats`
  runs the generated bash script with the real bash-completion library and a
  `sudo` stub for the bridge; the Go tests (`internal/cli/completion_test.go`)
  check the words per verb, and `internal/cli/man_test.go` checks that
  `man/tacctl.1` names every command of the tree and none that is not in it.

## Goldens

Device configs (`config cisco|juniper|wti`, with `--protocol radius` as
`*-radius-lab.conf`) are compared through the CLI; regenerate them after an
intended change and review the diff:

```sh
UPDATE_GOLDEN=1 make test-integration
git diff tests/fixtures/golden/
```

The other goldens come from the last bash release, never from the Go code
they check. Their generators need git (the release tag), bash and PyYAML,
and write nothing outside a temp directory:

| Files | Generator |
|---|---|
| `golden/dropin.*.conf`, `golden/rendered.json`, `internal/render/tacacs/testdata/corpus.jsonl` | `python3 internal/render/tacacs/testdata/gen.py` |
| `internal/conf/testdata/*` (defaults, the schema's acceptance and messages, writes) | `python3 internal/conf/testdata/gen.py` |
| `internal/store/testdata/load/*`, `internal/store/testdata/import/*` | the `gen.py` beside them |
| `internal/cidr/testdata/*` | `python3 internal/cidr/testdata/gen.py` |
| `internal/yamlpy/testdata/*`, `internal/conf/testdata/pyyaml/*` | `tests/tools/pyyaml-corpus.py` (`make test-pyyaml` checks them) |
| `internal/cli/testdata/usage/*` (every usage block) | `tests/tools/usage-goldens.sh` |

The store fixtures (`tests/fixtures/store.*.yaml`) and model JSON
(`tests/fixtures/model/*.json`) are PyYAML and Python output of the bash
release; `internal/store` and `internal/model` compare the Go output with
them byte for byte.

## Fixtures and the store

tacctl-owned state (users, groups, scopes, filters) lives in
`$TACCTL_STATE_DIR/store.yaml`, not in the daemon's `tacquito.yaml`. Three
helpers in `tests/helpers/fixtures.bash` put a fixture in place:

| Helper | Does |
|---|---|
| `load_fixture tacquito.X.yaml` | Copies the file to `$TACCTL_CONFIG` and seeds `store.yaml` from it with a strict `tacctl store import` (never `--force`). A fixture the importer rejects fails the test with the importer's report; fix the fixture. |
| `load_store_fixture store.X.yaml` | Copies `tests/fixtures/store.X.yaml` to `$TACCTL_STATE_DIR/store.yaml` (0600). Does not touch `tacquito.yaml`. |
| `place_fixture <name>` | Copy only: no seeding. For tests of the importer and of the no-store (legacy) read path, which need an empty state dir. |

Two more plant state an earlier release left: `rendered_record <file>...`
records files in `rendered.json` as rendered by tacctl, `rendered_forget
<file>...` drops their records. `golden_diff <actual> <golden>` compares with
`tests/fixtures/golden/` (or rewrites it under `UPDATE_GOLDEN=1`).

Notes:

- `load_fixture` of a directory fixture, or of a `legacy.*.yaml` file, copies and
  does not seed. Only `tacquito.*.yaml` names are seeded.
- A second `load_fixture tacquito.*.yaml` in the same test replaces both the file
  and the store.
- Seeding is cheap: the importer runs once per distinct fixture per bats run (in a
  scratch directory, cached under `$BATS_RUN_TMPDIR/store-seed`, safe for parallel
  jobs) and later loads copy the cached store. The seed is the `store.yaml` file
  only: no lock file, snapshot or output. If a test planted password-date or
  disabled-hash sidecars before loading, the helper imports directly instead,
  because the importer reads them.
- Commands read and write the store. `tacquito.yaml` is what tacctl renders from
  it, so after `load_fixture` the hand-built fixture file is only the starting
  artifact: a test that edits `$TACCTL_CONFIG`, or writes its own, changes
  nothing a command reads. Put the change in the store instead
  (`load_store_fixture`, a `tacctl` command, or an edit of
  `$TACCTL_STATE_DIR/store.yaml` when the test needs a store no command would
  write).
- The first mutating command after `load_fixture` replaces the fixture file with
  the render of the store and prints a `Previous … saved to …/backups/legacy/…`
  line: the file was never rendered by tacctl, and it is adopted because it says
  what the store says. A fixture file edited after loading no longer does, and
  the command is refused (exit 3) like any hand edit.
- What to assert on: the store (or a read command) for what a command *did*;
  `$TACCTL_CONFIG` text for what tacquito is *given* (anchor names, the
  `scopes:`/`groups:` of a user entry, the disabled marker, `secrets[]` order).
  Note the renderer quotes a hash whose hex is all digits.
- Every mutating command snapshots first: `$TACCTL_STATE_DIR/backups/<ts>/{store.yaml,tacctl.yaml,manifest}`.
  `tests/integration/backup.bats` has helpers for listing snapshots and comparing
  the live state before and after.
- For legacy read-only mode (no store), use `place_fixture`. Every mutating
  command must refuse there; `tests/integration/store_mutations.bats` holds the
  list of verbs and is where a new mutating verb gets added.
- The daemon load-smoke is skipped in tests (`$TACCTL_BIN` holds no `tacquito`);
  tests that exercise it install a stand-in script there.

### Which fixtures pass `store import --check`

`--check` renders the imported model and asks whether tacquito would behave
identically on the two files. The hand-built `tacquito.*.yaml` fixtures do
**not** pass as they stand, and that is the correct verdict: they carry no
per-group command rules (the product wrote those from `tacctl.yaml` on every
install and upgrade), `tacquito.legacy-exec.yaml` still names the Cisco
service `exec`, and `tacquito.multiscope.yaml` lists `prod` before the
narrower `prod-inner`, an order no pre-store release left on disk. All but
multiscope pass once the migrations every upgrade runs on a legacy file have
run on them (the exec service-name migration and the regeneration of the
command rules). Multiscope does not: upgrade never sorted `secrets`, and the
gate does not rewrite a file to make it pass, so it is the fixture for a
clean import that is not equivalent. `internal/model`'s
`TestImportCheckGoldens` pins these verdicts. A test that needs a config
which passes the check as-is should load `legacy.fresh-install.yaml` (what
the template-editing installer wrote: old layout, four disabled seed users,
scope `lab`), `golden/tacquito.minimal.rendered.yaml` or
`golden/tacquito.multiscope.rendered.yaml`.

## Backends

Generic code reaches a daemon only through the backend contract
(`internal/backend`); TACACS+ (tacquito) is `internal/backend/tacacs`,
RADIUS (FreeRADIUS) `internal/backend/radius`, both registered by
`internal/backend/all`.

- `internal/backend/faketest` is a stand-in backend with a knob for every
  failure point (gate refusing or adopting, stage or commit failing, an
  install phase failing, a start leaving the service down, a stop failing).
  `internal/backend` tests the one mutation path (`StoreApply`: gate,
  snapshot, store write, render of every enabled backend, commit all or
  restore all, restart what changed) with two backends;
  `internal/cli` tests `backend enable|disable`, the per-backend sections of
  `status`, `config validate`, `config show`, `log` and `backup restore` with
  it. `faketest.CheckContract` is the contract test each module runs on
  itself.
- `TACCTL_FAULT=<point>[,...]` (test builds only, below) makes a named step
  fail through the CLI: `render-stage:<id>`, `render-commit:<id>`,
  `snapshot`.
- `tests/integration/backend_cli.bats` drives `backend list|status` and the
  multi-backend sections through the command line with the two shipped
  backends; `tests/integration/radius.bats` drives `backend enable|disable
  radius` with the real module.
- Tests that need an id tacctl does not have use `ldap`.

## The RADIUS backend

The tests never run FreeRADIUS; what the real daemon does with the rendered
files is checked in containers (next section).

- `tacctl_tmpenv_init` points the module at the test's tmpdir:
  `TACCTL_RADIUS_DIR` (the raddb), `TACCTL_RADIUS_LOG`, `TACCTL_RADIUS_BIN`
  (the daemon binary; absent unless a test installs a stand-in, and then the
  module's config check runs it), `TACCTL_RADIUS_DICT` and
  `TACCTL_LOGROTATE_DIR`. The unit drop-in goes to `TACCTL_SYSTEMD_DIR`.
  `TACCTL_RADIUS_FAMILY=debian|rhel` selects the distro layout (unit,
  account, paths) instead of detection.
- `tests/fixtures/store.radius.yaml` has what the renderer must handle: a
  TACACS+-only and a RADIUS-only scope, an IPv6 prefix, overlapping prefixes,
  secrets that need each quoting form, a disabled user, the sink, a custom
  group and both filters. `internal/render/radius` renders it against the
  goldens `golden/radius.{debian,rhel}.{conf,users}` and `radius.dictionary`.
- `integration/radius.bats`: the commands, with stubs written in the file
  itself: a `systemctl` that remembers which units are active and enabled
  (in `$SD`), `apt-get`/`dnf` that "install" a stand-in daemon, `ss`, `id`.
  `$SD/fail-start` makes a start or restart leave the unit inactive,
  `$SD/fail-check` makes the daemon's `-C` reject the config.

## RADIUS in containers

The one check that runs real FreeRADIUS: rootless podman, one container per
distro, nothing on the host touched outside podman and a temp directory.
Needs podman and `python3-bcrypt` (and, for `almalinux-8`, Go in
`/usr/local/go`: the files are rendered on this machine); the first run of a
distro builds an image (`localhost/tacctl-radius-check:<distro>`, kept) and
needs the package mirrors. Inside the systemd containers tacctl is built by
its own bootstrap (`bin/tacctl.sh` downloads Go, verified, and builds from
the vendored sources), so they need network access to `dl.google.com`.

```sh
tests/containers/radius/run.sh ubuntu-noble     # FreeRADIUS 3.2.x, Debian layout
tests/containers/radius/run.sh almalinux-9      # 3.0.27, RHEL layout
tests/containers/radius/run.sh almalinux-8      # 3.0.20, RHEL layout
```

Each prints `PASS`/`FAIL`/`SKIP` lines and exits non-zero on a `FAIL`. Add
`--keep` to leave the container (`tacctl-radius-check-<distro>`) for a look;
remove it with `podman rm -f`.

| File | Does |
|---|---|
| `make-store.py <dir>` | writes a store with real bcrypt hashes (six users, ten scopes, both filters; four scopes enable vendor attributes, five addresses are tagged) and one `sec.<scope>` file per secret |
| `run.sh <distro>` | builds the image if needed, starts the container, runs the check, removes the container; for `almalinux-8` it renders with `tacctl config render --dry-run --out <dir>` (`TACCTL_RADIUS_FAMILY=rhel`) and serves the files with `radiusd` started by hand |
| `flow.sh <data dir>` | inside a systemd container with this checkout mounted read-only at `/opt/tacctl`: `tacctl backend enable radius` for real (package install, render, the daemon's `-C`, the drop-in with `-D`, start), then the cases, mutations, listeners, drift, reload, disable, re-enable, the uninstall phases (`tacctl _phase radius uninstall ...`), and the way from the release before the vendor attributes (that old bash release runs from a `git archive` of its commit; its upgrade step is `tacctl _phase radius upgrade config,files,finish`) |
| `cases.sh <data dir>` | the radclient cases, every reply decoded with tacctl's dictionary and compared attribute by attribute: Service-Type alone for a scope that enables nothing, each vendor's attribute per scope and per tagged address and never another's, rejects with none, no internal attribute anywhere; wrong password, user outside the client's scope, disabled user, sink, overlapping prefixes, a TACACS+-only scope, quoted secrets, both filters, the package's default client, IPv6, CHAP, Status-Server, accounting |

Notes:

- tacquito is not in the containers. The TACACS+ backend renders its config
  there and warns that its service did not restart; that is expected.
- The systemd containers run with `--cap-add SYS_ADMIN`: the Debian unit's
  sandboxing cannot be set up in a rootless container without it.
- Clients are told apart by source address. All of 127.0.0.0/8 is local, so
  `radclient` sends from 127.0.0.2, .3, .4, .9 and .66 with
  `Packet-Src-IP-Address`; a request to the container's own address comes
  from it (scope `prod`).
- Record what a run showed, with package versions, in `docs/radius-notes.md`.

## Linux hosts in containers

`tacctl host enroll|sync|unenroll` for real, for both methods: a server
container runs tacctl with real FreeRADIUS (installed by `backend enable
radius`) and real tacquito, and enrolls a client container of the
distribution under test over SSH; the logins are then made with SSH and
`sudo` on the client. Rootless podman, a network of its own
(`tacctl-host-check`), nothing on the host touched.

```sh
tests/containers/hosts/run.sh ubuntu-noble radius    # one client, one cycle
tests/containers/hosts/run.sh rocky-9 switch
tests/containers/hosts/run.sh almalinux-9 radius --server almalinux-9
tests/containers/hosts/run.sh debian-trixie probe    # what pam_radius_auth returns
tests/containers/hosts/matrix.sh [<log dir>]         # everything docs/radius-notes.md records
```

Clients: `ubuntu-noble`, `debian-trixie`, `debian-bookworm`,
`almalinux-8|9|10`, `rocky-8|9|10`. Cycles:

| Cycle | Does |
|---|---|
| `radius`, `tacplus` | snapshot of the host; `host enroll --method <m>` (per-host scope); users added to the scope and pushed with `host sync` (one of them a pre-existing account that needs `--adopt`); where the secret is; SSH login right and wrong, `sudo` and `sudo -i` for the superuser, none for the readonly user; a user removed from the scope on the server and not yet synced; the local administrator; the server unreachable (packets dropped at the server with nft) with timings; a wrong shared secret on the host; console login, the stand-in for GDM and a PAM client that is not root; re-enroll; the server's logs; `host unenroll`; the snapshot again, byte for byte |
| `switch` | all of `tacplus`, then `host enroll --method radius` on the enrolled host (nothing of pam_tacplus left, logins answered by FreeRADIUS), then back (nothing of pam_radius_auth's configuration left), then unenroll and the snapshot |
| `probe` | no enroll: installs the package and prints what `pam_radius_auth` returns for accept, reject, a wrong secret, a silent server with `retry=0..2`, a missing server file, account, session and password change, and the accounting records the server got |

Each run prints `PASS`/`FAIL`/`NOTE` lines and exits non-zero on a `FAIL`;
`--keep` leaves `thc-server` and `thc-client-<client>` for a look.

| File | Does |
|---|---|
| `run.sh` | builds the two images if needed (`localhost/tacctl-host-check:{server,client}-<distro>`, kept; the server image gets tacctl built from this checkout by its bootstrap, and the pinned pam_tacplus source through `tacctl config linux build`), starts the containers, runs the cycle |
| `matrix.sh` | the runs recorded in `docs/radius-notes.md`, one after another, a log per run |
| `server-setup.sh` | in the server: a store with three users (real bcrypt hashes), tacquito under its unit through the backend's own install phases (`tacctl _phase tacacs install account|start`), `backend enable radius` |
| `client-prep.sh` | at client image build: sshd, sudo, a local administrator `ladm`, a pre-existing account `carl`, a stand-in `gdm-password` service file, and what a rootless container needs (below). No PAM module, no EPEL: enrollment brings those |
| `sshtry.sh` | one SSH password login to the container's own sshd (via `SSH_ASKPASS`; `sshpass` is not in every base repository) |
| `pamprobe.py` | a PAM client: runs the phases of a service for a user and prints each return code and how long it took |

Notes:

- **tacquito is not built here.** The server image takes
  `/usr/local/bin/tacquito` from the machine that builds it; without one,
  only `radius` and `probe` can run. With `--server almalinux-9`
  (FreeRADIUS 3.0.27) only `radius` and `probe` run.
- No podman in the server container, so pam_tacplus is compiled on the
  client (the `--build-on-host` path), with the build packages enrollment
  installs.
- What the client containers need and a real host does not: `--cap-add
  AUDIT_WRITE` for sshd, `pam_loginuid` commented out, `pam_unix`'s account
  step replaced by `pam_permit`, and on the RHEL family `/etc/shadow` mode
  0400 instead of 0000 (pam_unix's helper `unix_chkpwd` drops root's
  capabilities, and current EL pam always goes through it). All are in
  place before the snapshot.
- SELinux is not enforced in containers: the policy modules are not
  installed there, let alone exercised (see `docs/radius-notes.md`).
- Remove the images to rebuild them after changing `client-prep.sh` or the
  package lists in `run.sh`: `podman rmi $(podman images -q localhost/tacctl-host-check)`.
- Record what a run showed, with package versions, in `docs/radius-notes.md`.

## The cross-over in containers

`tests/containers/crossover/` (see its README) rehearses `tacctl upgrade
--branch <Go tree>` from an installed bash release in a systemd container,
both ways the release hands over, then a second upgrade that must change
nothing, the way back to the bash release, and a fresh install through the
shim.

## Install, upgrade, uninstall

These write fixed host paths (`/opt/tacctl`, `/usr/local/bin/tacctl`,
`/usr/local/go`, the bash completion, the man page, `/root`), so they run
only in test builds with `TACCTL_TEST_ROOT` (below), which moves all of them
under one directory:

- `internal/lifecycle`: state migration, seeding, the legacy migrations, the
  store gate and rollback, install, upgrade (self-update, the hand-over to a
  bash release, the offline and partial-failure matrix), uninstall, the
  template manifest; with the fake runner.
- `internal/backend/tacacs` and `internal/backend/radius`: each module's
  lifecycle phases (units and drop-ins, the conversion of a hand-managed
  drop-in, the restart and rollback of an upgrade, the tacquito patches).
- `tests/integration/shim.bats`: the bootstrap shim's own rows (a copy of
  `bin/tacctl.sh` in a scratch tree, Go and git stand-ins).
- `tests/integration/characterisation.bats` and `radius.bats` run
  `install|upgrade` argument handling and one whole `upgrade` under
  `TACCTL_TEST_ROOT`.

## Test knobs (`internal/app/knobs*.go`)

Four environment variables let a test fix what a command takes from the world.
They are read **only** by a binary built with `-tags testknobs` (`make build`,
which the bats harness and the differential runner use); the installed binary
and the bootstrap shim do not read them at all, whatever the variables hold,
and `tacctl version --long` prints `test knobs: on|off`. `TACCTL_SKIP_SUDO` is
not a knob: it stays an ordinary environment check.

| Variable | Effect (test builds only) |
|---|---|
| `TACCTL_TEST_NOW=<RFC 3339>` | `Knobs.Now()` returns that instant, in the local zone, instead of the clock |
| `TACCTL_TEST_RANDOM=<hex>` | `Knobs.Rand()` yields those bytes, repeated as often as needed, each call starting at the first byte |
| `TACCTL_FAULT=<point>[,<point>...]` | `Knobs.Fault(point)` returns an error for each named point |
| `TACCTL_TEST_ROOT=<dir>` | tacctl's fixed host locations, which no `TACCTL_*` variable moves (the deploy clone `/opt/tacctl`, `/usr/local/bin/tacctl`, `/usr/local/go`, the bash completion, the man page, `/root`), move under `<dir>` (`paths.Paths.Reroot`), so a test can run `install`, `upgrade` and `uninstall` |

A malformed value is an error naming the variable; an empty one is the same as
unset. The bootstrap shim honours `TACCTL_TEST_ROOT` for the installed command
and Go as well, and so does its build recipe (`bin/tacctl.sh --build`).
Run the Go tests of the knobs both ways: `go test ./internal/app` (the off
build: the variables are ignored) and `go test -tags testknobs ./internal/app`;
`make test-go` and `make lint` do both for every package.

## The fake runner (`internal/execx/fake`)

The Go counterpart of `mocks.bash`: `stub_cmd systemctl 'exit 3'` is
`r.On([]string{"systemctl"}, execx.Result{Code: 3})`, `stub_called 'systemctl restart tacquito'`
is `r.Called("systemctl", "restart", "tacquito")` (or `r.CalledRegexp` for the
bats pattern). Scripting: `On` (argv prefix, newest rule wins), `When`/`Func`/`OnFunc`
(by predicate or function), `Seq` (a different answer per call, the last repeats),
`Fail`, `Missing`/`Install` (what `LookPath` finds), `ExecErr`, `Strict` (an
unscripted call is an error). Asserting: `Calls`, `Records` (with the stdin each
call got), `Argvs`, `Called`, `Count`, `ArgvContains` (a secret must never reach an
argv), `Signals`, `Execs`, `Reset`.

## Coverage

```sh
make coverage        # coverage/go.out, coverage/index.html, the total on stdout
go tool cover -func=coverage/go.out | sort -k3 -n | head    # the least covered functions
```

The bats suite is not instrumented; what it covers shows as the black-box
contract, not as line coverage.

## Differential runner: `tests/diff/run.sh`

Runs every command of a corpus under two implementations of tacctl, each against
its own copy of the same fixture state, and reports any difference in stdout,
stderr, exit code, the calls made to the stubbed system commands (`systemctl`,
`logger`) and the resulting state tree (modes, sizes and contents of every file
under the sandbox root, an empty `TMPDIR` included).

```sh
make test-diff CORPUS=users                  # builds dist/tacctl first; A = the 0.1.18 tag, B = the binary
tests/diff/run.sh users groups store         # several corpora
tests/diff/run.sh --all                      # every corpus
tests/diff/run.sh --b bash users             # B = the tag again: a difference here is a runner bug
tests/diff/run.sh --filter 'user add' users  # only the lines matching a regex; --keep keeps the work dir
tests/diff/run.sh --self-test                # the runner against itself and against a deliberately wrong B
```

- **A is always a tag** (`--against`, default `0.1.18`, the last bash
  release): a shared clone of this repository checked out at the tag into a
  temp dir, run from there; nothing of the working tree is used for A. B is
  `go` (`dist/tacctl`, started with `TACCTL_TREE` pointing at this tree, as
  the bats harness does), `bash`, or any executable.
- **Corpora** are `tests/diff/corpus/<name>.txt`: `users`, `scopes`, `groups`,
  `config`, `backup`, `store`, `log`, `devices`, `hosts`. One command per line,
  program name left out; `<<< text` is stdin (`\n` a line break; no `<<<` means
  a closed stdin); ` ;; ` chains commands that share one state; `@fixture`,
  `@env`, `@unenv`, `@stub <cmd> <rc>`, `@known <why>`, `@path <dir>` (more
  stand-ins on PATH: the hosts corpus stubs ssh, podman, getent, ip and
  `git clone` from `tests/diff/stubs/hosts`, so nothing leaves the machine) and
  `@root <dir>` (files copied into the state root, such as the stand-in
  pam_tacplus tarball) are directives; `{HASH}`, `{FIXTURES}`, `{DATE}`, `{TS}`
  are placeholders. Commands run in the state root, so a file written to a
  relative path is compared with the rest of the state. The header of `run.sh`
  is the full syntax. Every corpus has at least as many failing lines as
  succeeding ones (the summary prints the count); add the error paths (unknown
  verb, missing argument, bad value, closed stdin, `n` to a prompt) with every
  success path.
- **Both sides run the same sandbox** (`env -i`; `TACCTL_*` paths under one root;
  `LANG=C.UTF-8`, `TZ=UTC`; `TACCTL_SKIP_SUDO=1`; PATH stubs). The two sides run one
  after the other in the same place, so a path a command writes into a file is the
  same on both. The fixture is built once, with A's implementation.
- **Determinism** comes from the stubs on the bash side and the test knobs on the Go
  side, fixed to the same values: the clock is today at 12:00:00 UTC (`date` stub;
  `TACCTL_TEST_NOW`), randomness is the bytes `a1b2c3d4e5f60718293a4b5c6d7e8f90`
  repeated (`openssl rand` stub; a `sitecustomize` that replaces python's
  `os.urandom`, which is where bcrypt takes its salt; `TACCTL_TEST_RANDOM`). So a
  generated password, secret or hash is the same on both sides; the Go code must
  draw its salts and secrets from `app.Knobs.Rand()` for that to hold. What is still
  normalised: ANSI colours (`--colour` keeps them), timestamps (`<TS>`, `<ISO>`), the
  version, the sandbox and tree paths, and generated bcrypt hashes (not the ones
  the command line itself carries).
- Exit status: 0 no unexplained difference, 1 a difference, 2 a usage or setup
  error. A line marked `@known` (an intended change listed in
  `docs/plans/go-rewrite.md` 3.9) is reported as `known`, not a failure; the
  runner says so when the marked line no longer differs.

## Characterisation tests: `tests/integration/characterisation.bats`

CLI behaviour no other test pins: `hash generate|commands`, `user verify`,
the generated-password path of `user add|passwd`, `config defaults|branch`,
the argument handling of `install|upgrade --branch`, the top-level usage
(`help`, `-h`, no command, an unknown word, `version`), and every usage
block of `internal/cli/testdata/usage/` compared with the real output.
Quirks they pin on purpose: `user verify` exits 0 on a wrong password, a
closed stdin is a blank password (one is generated), `upgrade --branch`
without a value exits 1 without a word.

## Isolation guarantees

- Every bats test runs with `$TACCTL_ETC`, `$TACCTL_STATE_DIR`, `$TACCTL_LOG`,
  `$TACCTL_BIN` and the RADIUS paths pointing at `$BATS_TEST_TMPDIR`. No test
  touches `/etc/tacctl`, `/etc/tacquito`, `/var/log/tacquito` or a FreeRADIUS
  directory on the host. A test that reaches `TACQUITO_SRC`, the Linux host
  data, the logrotate directory or the fixed host locations sets those to its
  tmpdir (`TACQUITO_SRC`, `TACCTL_LINUX_DIR`, `TACCTL_LOGROTATE_DIR`,
  `TACCTL_TEST_ROOT`).
- Go tests build their paths with `paths.Resolve` over a sandbox environment
  and `Paths.Reroot` for the fixed locations; the fake runner stands in for
  every program.
- `tacctl_mocks_init` prepends `$BATS_TEST_TMPDIR/stubs` to `PATH`, so stubs
  shadow real `systemctl`, `git`, `journalctl` and the rest. Stubs record
  calls to `$CALLS_LOG`.
- bats isolates each `@test` in its own process, so global state doesn't leak
  between tests.
