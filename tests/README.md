# tacctl tests

Test suite for `bin/tacctl.sh` (the entrypoint) and `lib/*.sh` plus `lib/backends/*.sh` (the code it loads), built on [bats-core](https://github.com/bats-core/bats-core).

## Running

```sh
make bootstrap       # first time: pull bats submodules
make test            # all tiers (unit → integration → e2e)
make test-unit       # pure-logic only, <5s
make test-integration
make test-e2e
make coverage        # produces coverage/index.html (requires: apt install kcov)
make lint            # shellcheck (bin/tacctl.sh, lib/*.sh, lib/backends/*.sh, tests/helpers, tests/tools, config/linux)
                     #   + gofmt, go vet, golangci-lint (pinned; prints how to install it when missing)
```

The bats files run in parallel (`bats --jobs`, one file per job) when GNU
`parallel` is installed: `BATS_JOBS` sets the number of jobs (default: the
CPU count), `BATS_JOBS=1` runs serially.

During the Go rewrite (`docs/plans/go-rewrite.md`) the suite drives either
implementation: `TACCTL_IMPL=bash` (the default) runs `bin/tacctl.sh`,
`TACCTL_IMPL=go` runs `dist/tacctl`, which hands every command it does not
implement yet to `bin/tacctl.sh`.

```sh
make build                         # dist/tacctl (bin/tacctl.sh --build, with the test knobs)
make test-go                       # go test -race ./...
TACCTL_IMPL=go make test-blackbox  # tests/blackbox.list against dist/tacctl
```

`tests/blackbox.list` lists the files that drive tacctl only through its
command line; a test there that cannot run against the binary is tagged
`# bats test_tags=bash-only`. An entry marked `# go-after: <package>` runs
only in bash mode until that package is done; one marked
`# go-tags: <tag>...` runs in full in bash mode and, in go mode, only its
tests carrying one of those tags (in a bats run of its own). `tests/tools/usage-goldens.sh` rewrites
`internal/cli/testdata/usage/` (the usage blocks the Go side must print) from
the `0.1.16` tag.

Run a single file:
```sh
tests/bats/bats-core/bin/bats tests/unit/validators.bats
```

## Layout

```
tests/
├── bats/                # vendored bats-core + helpers (git submodules)
├── helpers/             # setup.bash, tmpenv.bash, mocks.bash, fixtures.bash
├── fixtures/
│   ├── tacquito.*.yaml  # tacquito.yaml fixtures (every one must import into the store without --force)
│   ├── legacy.*.yaml    # tacquito.yaml inputs for the importer and the upgrade gate (edge cases, unrepresentable content, the old installer's output)
│   ├── store.*.yaml     # store.yaml fixtures; store.X.yaml is exactly what importing tacquito.X.yaml writes
│   ├── model/           # golden model JSON (what model_dump returns for a fixture)
│   ├── templates/       # device config templates
│   └── golden/          # expected rendered output: device configs (M3; `--protocol radius` ones are `*-radius-lab.conf`), tacquito.X.rendered.yaml
│                        #   (what the TACACS+ renderer produces from store.X.yaml) and radius.<family>.*
├── containers/radius/   # the check against real FreeRADIUS in podman (not run by make test)
├── containers/hosts/    # 'host enroll|sync|unenroll' for real, server and client containers (not run by make test)
├── unit/                # pure-logic, no I/O, no mocks
├── integration/         # real file I/O into $TACCTL_ETC tmpdir
└── e2e/                 # stubbed systemctl/git/etc.
```

The code under test is `bin/tacctl.sh` (entrypoint) plus `lib/*.sh` and the
backend modules in `lib/backends/*.sh`. Tests keep sourcing `bin/tacctl.sh`
through `tacctl_source_lib`; it loads the lib files. `tests/unit/sanity.bats`
enumerates both directories.

## Writing a test

**Unit test** (direct function call):
```bash
#!/usr/bin/env bats
load ../helpers/setup
load ../helpers/tmpenv

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
}

@test "validate_username rejects empty" {
    run validate_username ""
    assert_failure
}
```

**Integration test** (subprocess):
```bash
#!/usr/bin/env bats
load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    load_fixture tacquito.minimal.yaml
}

@test "tacctl user list shows fixture users" {
    run "$TACCTL_BIN_SCRIPT" user list
    assert_success
    assert_output --partial 'alice'
}
```

**E2E test** (with stubbed commands):
```bash
#!/usr/bin/env bats
load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd systemctl
    stub_cmd git 'echo "ok"'
}

@test "restarting the TACACS+ backend calls systemctl restart tacquito" {
    tacctl_source_lib
    backend_call tacacs service restart
    stub_called 'systemctl restart tacquito'
}
```

## Golden-file workflow

Template-rendering tests (M3) compare produced output against `tests/fixtures/golden/*.conf`.
Regenerate the golden files after intentional output changes:

```sh
UPDATE_GOLDEN=1 make test-integration
git diff tests/fixtures/golden/   # review the delta
```

The store tests use the same switch for `tests/fixtures/model/*.json` and
`tests/fixtures/store.*.yaml`:

```sh
UPDATE_GOLDEN=1 tests/bats/bats-core/bin/bats tests/unit/store_import.bats
git diff tests/fixtures/model/ tests/fixtures/store.*.yaml
```

`tacctl_tmpenv_init` points `TACCTL_STATE_DIR` at `$BATS_TEST_TMPDIR/state`, so
the store never resolves to `/etc/tacctl`; tests need no setup of their own for it.

## Fixtures and the store

tacctl-owned state (users, groups, scopes, filters) lives in
`$TACCTL_STATE_DIR/store.yaml`, not in the daemon's `tacquito.yaml`. Three
helpers in `tests/helpers/fixtures.bash` put a fixture in place:

| Helper | Does |
|---|---|
| `load_fixture tacquito.X.yaml` | Copies the file to `$TACCTL_CONFIG` and seeds `store.yaml` from it with a strict `tacctl store import` (never `--force`). A fixture the importer rejects fails the test with the importer's report; fix the fixture. |
| `load_store_fixture store.X.yaml` | Copies `tests/fixtures/store.X.yaml` to `$TACCTL_STATE_DIR/store.yaml` (0600). Does not touch `tacquito.yaml`. |
| `place_fixture <name>` | Copy only: no seeding. For tests of the importer and of the no-store (legacy) read path, which need an empty state dir. |

Notes:

- `load_fixture` of a directory fixture, or of a `legacy.*.yaml` file, copies and
  does not seed. Only `tacquito.*.yaml` names are seeded.
- A second `load_fixture tacquito.*.yaml` in the same test replaces both the file
  and the store.
- Seeding is cheap: the importer runs once per distinct fixture per bats run (in a
  scratch directory, cached under `$BATS_RUN_TMPDIR/store-seed`) and later loads
  copy the cached store. The seed is the `store.yaml` file only: no lock file,
  snapshot or output. If a test planted password-date or disabled-hash sidecars
  before loading, the helper imports directly instead, because the importer reads them.
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
- Every mutating command snapshots first: `$TACCTL_STATE_DIR/backups/<ts>/{store.yaml,tacctl.yaml,manifest}`
  (not `tacquito.yaml.<ts>`; those exist only as old-style backups a test plants, or
  the `backups/legacy/` copies the renderer makes). `tests/integration/backup.bats`
  has helpers for listing snapshots and comparing the live state before and after.
- For legacy read-only mode (no store), use `place_fixture`. Every mutating
  command must refuse there; `tests/integration/store_mutations.bats` holds the
  list of verbs and is where a new mutating verb gets added.
- The legacy `tacquito.yaml` migrations (`conf_migrate_command_rules`,
  `conf_migrate_exec_service_name`, and the legacy half of
  `regenerate_tacquito_commands`) are no-ops once a store exists, so
  their tests place fixtures with `place_fixture`.

The renderer goldens work the same way:

```sh
UPDATE_GOLDEN=1 tests/bats/bats-core/bin/bats tests/unit/render_tacacs.bats
git diff tests/fixtures/golden/tacquito.*.rendered.yaml
```

Drop-in and bookkeeping goldens: `golden/dropin.{default,default-override,mgmt,alt6}.conf` and
`golden/rendered.json` come from 0.1.16 via `internal/render/tacacs/testdata/gen.py` (which also
writes that package's `corpus.jsonl`); regenerate with
`python3 internal/render/tacacs/testdata/gen.py` from the repository root.

### Which fixtures pass `store import --check`

`--check` renders the imported model and asks whether tacquito would behave
identically on the two files. The hand-built `tacquito.*.yaml` fixtures do
**not** pass as they stand, and that is the correct verdict: they carry no
per-group command rules (the product wrote those from `tacctl.yaml` on every
install and upgrade), `tacquito.legacy-exec.yaml` still names the Cisco
service `exec`, and `tacquito.multiscope.yaml` lists `prod` before the
narrower `prod-inner`, an order no pre-store release left on disk. All but
multiscope pass once the migrations every upgrade runs on a legacy file have
run on them (`config_sync_existing`: `conf_migrate_exec_service_name`,
`regenerate_tacquito_commands`). Multiscope does not: upgrade never sorted
`secrets`, and the gate does not rewrite a file to make it pass, so it is the
fixture for a clean import that is not equivalent. `tests/unit/render_tacacs.bats`
pins these verdicts. A test that needs a config which passes the check as-is
should load `legacy.fresh-install.yaml` (what the template-editing installer
wrote: old layout, four disabled seed users, scope `lab`),
`golden/tacquito.minimal.rendered.yaml` or `golden/tacquito.multiscope.rendered.yaml`.

The daemon load-smoke is skipped in tests (`$TACCTL_BIN` holds no `tacquito`);
tests that exercise it install a stand-in script there.

## Backends

Generic code reaches a daemon only through the backend contract
(`lib/backend.sh`); TACACS+ (tacquito) is the module `lib/backends/tacacs.sh`,
RADIUS (FreeRADIUS) `lib/backends/radius.sh` (see "The RADIUS backend").

- `tests/unit/backend.bats` checks the contract itself: every registered
  backend defines every verb in `BACKEND_VERBS` (and no `backend_<id>_*`
  function that is not one), every file in `lib/backends/` is sourced and
  registers under its file name, `backends.enabled` and its schema, and the
  TACACS+ module's read-only verbs. A new module needs no new test to be held
  to the contract; a new verb goes into `BACKEND_VERBS`.
- `tests/integration/backend_mutation.bats` covers what a mutation does with
  two backends, using a stand-in backend defined in the test shell
  (`BACKEND_IDS+=(fake)`, a few `backend_fake_*` functions, and
  `backends: {enabled: [tacacs, fake]}` written to `tacctl.yaml` by hand; the
  schema accepts whatever `BACKEND_IDS` holds when it is read, so
  `conf_set_list backends.enabled` takes the id too). It can refuse at its
  gate, fail while staging, or fail in its commit after damaging its
  artifact. Copy that pattern to test generic code against a backend that
  misbehaves.
- `tests/integration/backend_cli.bats` covers `tacctl backend
  list|status|enable|disable` and the per-backend sections of `status`,
  `config validate`, `config show`, `log` and `backup restore`, with a fuller
  stand-in (`fake_backend_write`: every verb, and environment knobs to make
  one step fail: `FAKE_GATE`, `FAKE_FAIL`, `FAKE_PHASE_FAIL`, `FAKE_START`,
  `FAKE_STOP_FAIL`). The stand-in is a file sourced after `bin/tacctl.sh` in a
  bash of its own under `set -euo pipefail` (`tc <function> [args]`), because
  a module's install phases `exit` on failure and errexit is ignored inside
  bats' `run`. Every failure of `enable` asserts the same thing: `state()`
  (store, tacctl.yaml, both artifacts, rendered.json) is byte-identical to
  before and no `.apply.*`, `.enable.*` or staging directory is left.
- `tests/integration/completion.bats` runs the real completion function with
  the real bash-completion library and a stub `sudo` that plays the
  `_completion-names` bridge (the only source of user, group, scope, backup,
  backend and listener names: the completion reads no file);
  `tests/integration/tiers.bats` holds the check that `tier_permits` and
  `emit_tier_sudoers` agree on every verb (bash-only: it sources the
  library; for the Go binary, `internal/tier` derives both from one table and
  `TestGateAndSudoersAgree` runs the same check over the same verb list).
- To make a render fail in a test, override the contract function
  (`backend_tacacs_render_stage() { return 1; }`), not `tacacs_render_apply`:
  commands render through `backends_render_all`. `tacacs_render_apply` is
  still what the legacy-mode code calls (the upgrade gate, `config_sync_existing`).
- Results of `backends_render_all`, `backends_gate` and `_backends_load` are
  shell variables (`BACKENDS_CHANGED`, `BACKENDS_ADOPT`, `BACKENDS_ENABLED`):
  call them, and `store_apply`, in the test shell rather than under `run` when
  the test reads those.

## The RADIUS backend

`lib/backends/radius.sh` (FreeRADIUS from the distro package). The tests never
run FreeRADIUS; what the real daemon does with the rendered files is checked
in containers (next section).

- `tacctl_tmpenv_init` points the module at the test's tmpdir:
  `TACCTL_RADIUS_DIR` (the raddb), `TACCTL_RADIUS_LOG`, `TACCTL_RADIUS_BIN`
  (the daemon binary; absent unless a test installs a stand-in, and then the
  module's config check runs it) and `TACCTL_LOGROTATE_DIR`. The unit
  drop-in goes to `TACCTL_SYSTEMD_DIR`. `TACCTL_RADIUS_FAMILY=debian|rhel`
  selects the distro layout (unit, account, paths) instead of detection.
- `tests/fixtures/store.radius.yaml` has what the renderer must handle: a
  TACACS+-only and a RADIUS-only scope, an IPv6 prefix, overlapping prefixes,
  secrets that need each quoting form, a disabled user, the sink, a custom
  group and both filters.
- `unit/render_radius.bats`: hash conversion, secret quoting, clients, users,
  the filter policy, the render id, notes, listeners, the drop-in, and the
  goldens `golden/radius.{debian,rhel}.{conf,users}`, rendered with the
  production paths of each layout
  (`UPDATE_GOLDEN=1 tests/bats/bats-core/bin/bats tests/unit/render_radius.bats`).
- `integration/radius.bats`: the commands, with stubs written in the file
  itself: a `systemctl` that remembers which units are active and enabled
  (in `$SD`), `apt-get`/`dnf` that "install" a stand-in daemon, `ss`, `id`.
  `$SD/fail-start` makes a start or restart leave the unit inactive,
  `$SD/fail-check` makes the daemon's `-C` reject the config. No stub was
  added to `tests/helpers/`; `tmpenv.bash` gained the four variables above.
- 'radius' is a registered backend now. Tests that need an id tacctl does
  not have use `ldap`.

## RADIUS in containers

The one check that runs real FreeRADIUS: rootless podman, one container per
distro, nothing on the host touched outside podman and a temp directory.
Needs podman and `python3-bcrypt`; the first run of a distro builds an image
(`localhost/tacctl-radius-check:<distro>`, kept) and needs the package
mirrors.

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
| `run.sh <distro>` | builds the image if needed, starts the container, runs the check, removes the container |
| `flow.sh <data dir>` | inside a systemd container with this checkout mounted read-only at `/opt/tacctl`: `tacctl backend enable radius` for real (package install, render, the daemon's `-C`, the drop-in with `-D`, start), then the cases, mutations (vendor attributes among them), listeners, drift, reload, disable, re-enable, uninstall phases, and the way from the release before the vendor attributes (commit e9142d5, taken with `git archive`): its own enable, then this release's `upgrade config` step, then the next mutation |
| `cases.sh <data dir>` | the radclient cases, every reply decoded with tacctl's dictionary and compared attribute by attribute: Service-Type alone for a scope that enables nothing, each vendor's attribute per scope and per tagged address and never another's, rejects with none, no internal attribute anywhere; wrong password, user outside the client's scope, disabled user, sink, overlapping prefixes, a TACACS+-only scope, quoted secrets, both filters, the package's default client, IPv6, CHAP, Status-Server, accounting |

Notes:

- `ubuntu-noble` and `almalinux-9` run tacctl itself in the container.
  `almalinux-8` has python 3.6, which cannot: there the two files are
  rendered on the host for the RHEL layout (`TACCTL_RADIUS_FAMILY=rhel`,
  `render_radius_config`), copied in and served by a daemon started by hand,
  and only `cases.sh` runs.
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
| `run.sh` | builds the two images if needed (`localhost/tacctl-host-check:{server,client}-<distro>`, kept), starts the containers, runs the cycle |
| `matrix.sh` | the runs recorded in `docs/radius-notes.md`, one after another, a log per run |
| `server-setup.sh` | in the server: a store with three users (real bcrypt hashes), tacquito under its unit through the backend's own install phases, `backend enable radius` |
| `client-prep.sh` | at client image build: sshd, sudo, a local administrator `ladm`, a pre-existing account `carl`, a stand-in `gdm-password` service file, and what a rootless container needs (below). No PAM module, no EPEL: enrollment brings those |
| `sshtry.sh` | one SSH password login to the container's own sshd (via `SSH_ASKPASS`; `sshpass` is not in every base repository) |
| `pamprobe.py` | a PAM client: runs the phases of a service for a user and prints each return code and how long it took |

Notes:

- **tacquito is not built here.** The server image takes
  `/usr/local/bin/tacquito` from the machine that builds it; without one,
  only `radius` and `probe` can run. The pinned pam_tacplus source is
  prepared in the image by `config linux build`'s own function. With
  `--server almalinux-9` (FreeRADIUS 3.0.27) only `radius` and `probe` run.
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

## Listeners and units

A listener of a backend is `listeners.<backend>.<name>` in `tacctl.yaml`
(schema and reader: `lib/conf.sh` `_listener_py`, `backend_listeners`). The
TACACS+ backend runs each in a systemd unit of its own (`tacquito.service`
for `default`, `tacquito@<name>.service` for any other) and renders one
drop-in per unit, `<unit>.d/tacctl.conf`, an artifact recorded in
`rendered.json` like `tacquito.yaml`.

- Where the files land in a test: `tacctl_tmpenv_init` sets
  `TACCTL_OVERRIDE_DIR=$BATS_TEST_TMPDIR/systemd-dropin`, the default
  listener's drop-in directory. Unit files and the instances' drop-in
  directories go to `TACCTL_SYSTEMD_DIR`, which defaults to the parent of
  that directory (`$BATS_TEST_TMPDIR`), never to `/etc/systemd/system`. A test
  that needs the real layout (drop-in directory beside the unit file) exports
  both before sourcing, as `integration/units_convert.bats` does.
- Any mutating command now also writes `systemd-dropin/tacctl.conf` and
  records it, and `backend_call tacacs artifacts` lists it after
  `tacquito.yaml`; messages that name the artifacts name both. With no unit
  file in the test's unit directory a render makes no `systemctl` call for it.
- `config listen|loglevel|metrics` restart a unit and then check that it
  stayed up after `TACCTL_SETTLE_SECONDS` (default 0.5). Export
  `TACCTL_SETTLE_SECONDS=0` in a file that runs many of them. To make the
  unit "not come up", stub `systemctl` so that `is-active` fails.
- An install "not converted" is one whose hand-managed
  `tacctl-overrides.conf` still exists in the default drop-in directory:
  write that file to get one (`old_install` in `units_convert.bats`).
  `tests/fixtures/systemd/` holds the unit files of earlier releases.

| File | Covers |
|---|---|
| `unit/listeners.bats` | the schema and its rejections (reserved TLS, collisions), `backends.tacacs.*`, `backend_listeners`, the shipped unit files |
| `integration/listeners.bats` | `config listen` with and without `--listener`/`--backend`, the `listeners` and `service` verbs, drop-in rendering and its place in the render machinery, `status` and logs with several listeners |
| `integration/units_convert.bats` | `_tacacs_units_install` (fresh, conversion, already converted, interrupted, failures), the restart and rollback of `_tacacs_upgrade_finish`, commands on an install that is not converted, uninstall of both layouts |

## Install, upgrade, uninstall

`cmd_install`, `cmd_upgrade` and `cmd_uninstall` shell out to git, go, apt,
useradd and systemd and write fixed system paths, so they are not run by the
suite as they are (one test runs `cmd_upgrade` with those steps replaced, for
the order of its output). The daemon's own steps are the TACACS+ backend's lifecycle phases
(`backend_tacacs_install|upgrade|uninstall <phase>`, the `_tacacs_install_*`,
`_tacacs_upgrade_*` and `_tacacs_uninstall_*` functions); those write fixed
system paths too and are not run either. What the commands do to the
configuration is in functions the tests drive directly, in the order the
commands call them (the config ones live in `lib/backends/tacacs.sh`):

| Function | Called by | Tests |
|---|---|---|
| `state_migrate` | install, upgrade | `integration/state_migrate.bats` |
| `install_seed_config` (fresh store + first render; existing data is kept) | install | `e2e/install_seed.bats` |
| `config_sync_existing` (legacy migrations, or a re-render with a store; the backend's `upgrade config` phase) | upgrade, install over existing data | `integration/upgrade_store_flip.bats` |
| `upgrade_store_flip` (the import gate: 0 flipped, 10 store present, 20 stopped; part of the backend's `upgrade finish` phase) | upgrade, install over a legacy config | `integration/upgrade_store_flip.bats` |
| `cmd_store_rollback` (`tacctl store rollback`) | operator | `integration/upgrade_store_flip.bats` |
| `install_readme`, `uninstall_remove_access` | install, uninstall | `e2e/install_seed.bats` |
| `_tacacs_units_install` (unit, template unit, drop-ins; converts the hand-managed drop-in) | install (`start` phase), upgrade (`files` phase, through `_tacacs_upgrade_units`) | `integration/units_convert.bats` |
| `_tacacs_upgrade_finish` (the restart; unit files, settings and binary go back when the unit does not come up) | upgrade | `integration/units_convert.bats` |
| `_tacacs_uninstall_stop`, `_tacacs_uninstall_units` | uninstall | `integration/units_convert.bats` |
| `_radius_upgrade_config` (re-render, drop-in, restart; the RADIUS backend's `upgrade config` phase) | upgrade, install over an existing store | `integration/radius.bats` |
| `cmd_upgrade` itself, with the build, the system files and the package step replaced by stand-ins and no management repo: the order of its output (banner, build, then the `config` phase with the RADIUS re-render, then system files and summary) | upgrade | `integration/radius.bats` ("upgrade: the output reads in order") |

Notes:

- `cmd_upgrade` runs the backends' phases in the order of
  `BACKEND_UPGRADE_PHASES` (`preflight build config files finish`;
  `tests/unit/backend.bats` checks it): `config` comes after the build and
  the scripts pull, so after a self-update it runs once, with the new code.
- The gate refuses to run without the daemon binary (a skipped load-smoke is
  not a pass), so a test that expects a flip installs a stand-in `tacquito`
  in `$TACCTL_BIN` first.
- `e2e/install_seed.bats` sets `TACCTL_TIER_SUDOERS_FILE` and `TACCTL_LINUX_DIR`
  before sourcing, because `uninstall_remove_access` deletes those paths; a
  test that calls it must do the same.
- `_tacacs_upgrade_files` and `_tacacs_uninstall_program|data` themselves
  write fixed paths (`/etc/logrotate.d`, `/usr/local/bin`): do not call them
  from a test; call the functions in the table.
- The suite runs unprivileged with `chown` stubbed. Real ownership (the store
  0600 root, `tacquito.yaml` 0640 `tacquito:tacquito`, `config_service_access`)
  is only exercised by a run as root on a real host.

## Coverage baseline

Measured via `make coverage` (kcov v42, full suite of 335 tests). This table predates
the split of `bin/tacctl.sh` into `bin/` + `lib/*.sh`; the `bin/tacctl.sh` figure now
spreads over the entrypoint and eleven lib files and has not been re-measured:

| Target | Coverage |
|---|---|
| `bin/tacctl.sh` | 52.14% (2283 / 4379 lines) |
| `tests/helpers/*` (tmpenv, setup, mocks) | 92%+ |
| Overall | 52.41% (2319 / 4425 lines) |

Uncovered territory is dominated by the bodies of `cmd_install` / `cmd_upgrade` /
`cmd_uninstall` (heavy shell-outs to git, apt, go, systemctl, useradd — see
"Install, upgrade, uninstall" above for the parts that are covered)
plus a smattering of defensive error branches. Filling these in is a follow-up
milestone, not a blocker.

On a platform without apt-kcov (e.g. KDE Neon, some Debian variants), build from
source:
```sh
git clone --depth 1 --branch v42 https://github.com/SimonKagstrom/kcov.git /tmp/kcov
cd /tmp/kcov && mkdir build && cd build && cmake .. && make -j && sudo make install
```
Required build deps: `cmake binutils-dev libssl-dev libcurl4-openssl-dev libelf-dev zlib1g-dev libdw-dev libiberty-dev build-essential`.

Known quirk: kcov instruments bash via `BASH_ENV`, which breaks `bash -c 'source ...'`
subshells used in tests (results in "BASH_SOURCE: unbound variable"). Use heredocs
or `run <cmd> <<< "..."` in tests that need to feed stdin to a library function —
not `bash -c`.

## Isolation guarantees

- Every test runs with `$TACCTL_ETC`, `$TACCTL_STATE_DIR`, `$TACCTL_LOG`, `$TACCTL_BIN` and the
  RADIUS paths (`$TACCTL_RADIUS_DIR`, `$TACCTL_RADIUS_LOG`, `$TACCTL_RADIUS_BIN`,
  `$TACCTL_LOGROTATE_DIR`) pointing at `$BATS_TEST_TMPDIR`. No test touches `/etc/tacctl`,
  `/etc/tacquito`, `/var/log/tacquito` or a FreeRADIUS directory on the host.
- `tacctl_mocks_init` prepends `$BATS_TEST_TMPDIR/stubs` to `PATH`, so stubs shadow real
  `systemctl`, `git`, `journalctl`, `openssl`. Stubs record calls to `$CALLS_LOG`.
- bats isolates each `@test` in its own process, so global state doesn't leak between tests.

## The Go rewrite: differential runner, test knobs, characterisation tests

Added by work package WP0.2 of `docs/plans/go-rewrite.md` (sections 2.2, 2.5, 3.6).

### Differential runner: `tests/diff/run.sh`

Runs every command of a corpus under two implementations of tacctl, each against
its own copy of the same fixture state, and reports any difference in stdout,
stderr, exit code, the calls made to the stubbed system commands (`systemctl`,
`logger`) and the resulting state tree (modes, sizes and contents of every file
under the sandbox root, an empty `TMPDIR` included).

```sh
make test-diff CORPUS=users                  # builds dist/tacctl first; A = the 0.1.16 tag, B = Go
tests/diff/run.sh --b bash users             # B = the tag again: a difference here is a runner bug
tests/diff/run.sh --b tree users             # B = bin/tacctl.sh of the working tree
tests/diff/run.sh --all                      # every corpus
tests/diff/run.sh --filter 'user add' users  # only the lines matching a regex; --keep keeps the work dir
tests/diff/run.sh --self-test                # the runner against itself and against a deliberately wrong B
```

- **A is always a tag** (`--against`, default `0.1.16`): a shared clone of this
  repository checked out at the tag into a temp dir, so a result does not depend on
  which bash files the working tree touched. B is `go` (`dist/tacctl`, started with
  `TACCTL_BASH_IMPL` and `TACCTL_TREE` pointing at this tree, as the bats harness
  does), `bash`, `tree`, or any executable.
- **Corpora** are `tests/diff/corpus/<name>.txt`: `users`, `scopes`, `groups`,
  `config`, `backup`, `store`, `hosts` (more arrive with the packages that cut over
  devices). One command per line, program name left out; `<<< text` is stdin
  (`\n` a line break; no `<<<` means a closed stdin); ` ;; ` chains commands that
  share one state; `@fixture`, `@env`, `@unenv`, `@stub <cmd> <rc>`, `@known <why>`,
  `@path <dir>` (more stand-ins on PATH: the hosts corpus stubs ssh, podman, getent,
  ip and `git clone` from `tests/diff/stubs/hosts`, so nothing leaves the machine) and
  `@root <dir>` (files copied into the state root, such as the stand-in pam_tacplus
  tarball) are directives; `{HASH}`, `{FIXTURES}`, `{DATE}`, `{TS}` are
  placeholders. Commands run in the state root, so a file written to a relative
  path is compared with the rest of the state. The
  header of `run.sh` is the full syntax. Every corpus has at least as many failing
  lines as succeeding ones (the summary prints the count); add the error paths
  (unknown verb, missing argument, bad value, closed stdin, `n` to a prompt) with
  every success path.
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
  error. A line marked `@known` (an intended change listed in the plan's 3.9) is
  reported as `known`, not a failure; the runner says so when the marked line no
  longer differs.

### Test knobs (`internal/app/knobs*.go`)

Four environment variables let a test fix what a command takes from the world.
They are read **only** by a binary built with `-tags testknobs` (`make build`, which
the bats harness and the differential runner use); the installed binary and the
bootstrap shim do not read them at all, whatever the variables hold, and
`tacctl version --long` prints `test knobs: on|off`. `TACCTL_SKIP_SUDO` is not a
knob: it stays an ordinary environment check.

| Variable | Effect (test builds only) |
|---|---|
| `TACCTL_TEST_NOW=<RFC 3339>` | `Knobs.Now()` returns that instant, in the local zone, instead of the clock |
| `TACCTL_TEST_RANDOM=<hex>` | `Knobs.Rand()` yields those bytes, repeated as often as needed, each call starting at the first byte; the bash stubs do the same |
| `TACCTL_FAULT=<point>[,<point>...]` | `Knobs.Fault(point)` returns an error for each named point; it replaces the function-override fault injection of the bash tests |
| `TACCTL_TEST_ROOT=<dir>` | tacctl's fixed host locations, which no `TACCTL_*` variable moves (the deploy clone `/opt/tacctl`, `/usr/local/bin/tacctl`, `/usr/local/go`, the bash completion, the man page, `/root`), move under `<dir>` (`paths.Paths.Reroot`), so a test can run `install`, `upgrade` and `uninstall` |

A malformed value is an error naming the variable; an empty one is the same as
unset. The bootstrap shim (`bin/tacctl.sh.new`, bash) honours `TACCTL_TEST_ROOT`
for the installed command and Go as well, and so does the build recipe it shares
with `bin/tacctl.sh --build`; `tests/integration/shim.bats` runs the shim's own
rows of the upgrade matrix (Go installed or kept, Decision 20's way back) that
way. Run the Go tests of the knobs both ways: `go test ./internal/app` (the
off build: the variables are ignored) and `go test -tags testknobs ./internal/app`.

### The fake runner (`internal/execx/fake`)

The Go counterpart of `mocks.bash`: `stub_cmd systemctl 'exit 3'` is
`r.On([]string{"systemctl"}, execx.Result{Code: 3})`, `stub_called 'systemctl restart tacquito'`
is `r.Called("systemctl", "restart", "tacquito")` (or `r.CalledRegexp` for the
bats pattern). Scripting: `On` (argv prefix, newest rule wins), `When`/`Func`/`OnFunc`
(by predicate or function), `Seq` (a different answer per call, the last repeats),
`Fail`, `Missing`/`Install` (what `LookPath` finds), `ExecErr`, `Strict` (an
unscripted call is an error). Asserting: `Calls`, `Records` (with the stdin each
call got), `Argvs`, `Called`, `Count`, `ArgvContains` (a secret must never reach an
argv), `Signals`, `Execs`, `Reset`.

### Characterisation tests: `tests/integration/characterisation.bats`

CLI behaviour of the `0.1.16` bash implementation that no other test pins:
`hash generate|commands`, `user verify`, the generated-password path of
`user add|passwd`, `config defaults|branch`, the argument handling of
`install|upgrade --branch`, the top-level usage (`help`, `-h`, no command, an
unknown word, `version`), and every usage block of
`internal/cli/testdata/usage/` compared with the real output. They were written
and made green against bash first; the Go port must keep them green. Each test
carries a `# bats test_tags=cutover:<package>` tag (`cutover:wp2-4a`, ...) naming
the package that moves its verb to Go; a package checks its verbs with

```sh
TACCTL_IMPL=go tests/bats/bats-core/bin/bats --filter-tags cutover:wp2-4a \
    tests/integration/characterisation.bats
```

`tests/blackbox.list` ran it against Go with
`# go-tags: cutover:wp0-1 cutover:wp2-4a ...` while the families were cut over;
since `WP3.3d`, the last of them, the whole file runs. Tests tagged `bash-only` cannot move as they are: the
`config branch` tests call `cmd_config_branch` with `DEPLOY_DIR` pointed at a scratch
directory (bash has no environment variable for the deploy clone; the Go
port takes it from `TACCTL_TREE`), and the missing-`python3-bcrypt` test has no Go
counterpart (the Go binary has no python3). Quirks the tests pin on purpose:
`user verify` exits 0 on a wrong password, a closed stdin is a blank password
(one is generated), `upgrade --branch` without a value exits 1 without a word.
