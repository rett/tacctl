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
make lint            # shellcheck (bin/tacctl.sh, lib/*.sh, lib/backends/*.sh, tests/helpers, config/linux)
```

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
│   └── golden/          # expected rendered output: device configs (M3) and tacquito.X.rendered.yaml,
│                        #   what the TACACS+ renderer produces from store.X.yaml
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
(`lib/backend.sh`); TACACS+ (tacquito) is the module `lib/backends/tacacs.sh`.

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
  schema would refuse the id, the reader does not). It can refuse at its
  gate, fail while staging, or fail in its commit after damaging its
  artifact. Copy that pattern to test generic code against a backend that
  misbehaves.
- To make a render fail in a test, override the contract function
  (`backend_tacacs_render_stage() { return 1; }`), not `tacacs_render_apply`:
  commands render through `backends_render_all`. `tacacs_render_apply` is
  still what the legacy-mode code calls (the upgrade gate, `config_sync_existing`).
- Results of `backends_render_all`, `backends_gate` and `_backends_load` are
  shell variables (`BACKENDS_CHANGED`, `BACKENDS_ADOPT`, `BACKENDS_ENABLED`):
  call them, and `store_apply`, in the test shell rather than under `run` when
  the test reads those.

## Install, upgrade, uninstall

`cmd_install`, `cmd_upgrade` and `cmd_uninstall` shell out to git, go, apt,
useradd and systemd and write fixed system paths, so they are not run by the
suite. The daemon's own steps are the TACACS+ backend's lifecycle phases
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

Notes:

- The gate refuses to run without the daemon binary (a skipped load-smoke is
  not a pass), so a test that expects a flip installs a stand-in `tacquito`
  in `$TACCTL_BIN` first.
- `e2e/install_seed.bats` sets `TACCTL_TIER_SUDOERS_FILE` and `TACCTL_LINUX_DIR`
  before sourcing, because `uninstall_remove_access` deletes those paths; a
  test that calls it must do the same.
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

- Every test runs with `$TACCTL_ETC`, `$TACCTL_LOG`, `$TACCTL_BIN` pointing at `$BATS_TEST_TMPDIR`.
  No test touches `/etc/tacquito` or `/var/log/tacquito` on the host.
- `tacctl_mocks_init` prepends `$BATS_TEST_TMPDIR/stubs` to `PATH`, so stubs shadow real
  `systemctl`, `git`, `journalctl`, `openssl`. Stubs record calls to `$CALLS_LOG`.
- bats isolates each `@test` in its own process, so global state doesn't leak between tests.
