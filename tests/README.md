# tacctl tests

Test suite for `bin/tacctl.sh` (the entrypoint) and `lib/*.sh` (the code it loads), built on [bats-core](https://github.com/bats-core/bats-core).

## Running

```sh
make bootstrap       # first time: pull bats submodules
make test            # all tiers (unit → integration → e2e)
make test-unit       # pure-logic only, <5s
make test-integration
make test-e2e
make coverage        # produces coverage/index.html (requires: apt install kcov)
make lint            # shellcheck (bin/tacctl.sh, lib/*.sh, tests/helpers, config/linux)
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
│   ├── legacy.*.yaml    # tacquito.yaml inputs for the importer only (edge cases, unrepresentable content)
│   ├── store.*.yaml     # store.yaml fixtures; store.X.yaml is exactly what importing tacquito.X.yaml writes
│   ├── model/           # golden model JSON (what model_dump returns for a fixture)
│   ├── templates/       # device config templates
│   └── golden/          # expected rendered output: device configs (M3) and tacquito.X.rendered.yaml,
│                        #   what the TACACS+ renderer produces from store.X.yaml
├── unit/                # pure-logic, no I/O, no mocks
├── integration/         # real file I/O into $TACCTL_ETC tmpdir
└── e2e/                 # stubbed systemctl/git/etc.
```

The code under test is `bin/tacctl.sh` (entrypoint) plus `lib/*.sh`. Tests keep
sourcing `bin/tacctl.sh` through `tacctl_source_lib`; it loads the lib files.

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

@test "restart_service calls systemctl restart tacquito" {
    tacctl_source_lib
    restart_service
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
- For legacy read-only mode (no store), use `place_fixture`. Every mutating
  command must refuse there; `tests/integration/store_mutations.bats` holds the
  list of verbs and is where a new mutating verb gets added.
- The legacy `tacquito.yaml` migrations (`conf_migrate_command_rules`,
  `conf_migrate_exec_service_name`, `flatten_secrets_if_needed`, and the legacy
  half of `regenerate_tacquito_commands`) are no-ops once a store exists, so
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
per-group command rules (the product writes those from `tacctl.yaml` on every
install and upgrade), `tacquito.legacy-exec.yaml` still names the Cisco
service `exec`, and `tacquito.multiscope.yaml` lists `prod` before the
narrower `prod-inner`, an order the product never leaves on disk. Each one
passes once the sync steps a pre-store install had applied have run on it: the
migrations every upgrade runs on a legacy file (`conf_migrate_exec_service_name`,
`regenerate_tacquito_commands`) and, for multiscope, the flatten-and-sort of
`secrets` that install applied (`flatten_secrets_if_needed`; upgrade does not
run it); `tests/unit/render_tacacs.bats` pins both verdicts. A test that needs a config which passes the check as-is should load
`golden/tacquito.minimal.rendered.yaml` or `golden/tacquito.multiscope.rendered.yaml`.

The daemon load-smoke is skipped in tests (`$TACCTL_BIN` holds no `tacquito`);
tests that exercise it install a stand-in script there.

## Coverage baseline

Measured via `make coverage` (kcov v42, full suite of 335 tests). This table predates
the split of `bin/tacctl.sh` into `bin/` + `lib/*.sh`; the `bin/tacctl.sh` figure now
spreads over the entrypoint and eleven lib files and has not been re-measured:

| Target | Coverage |
|---|---|
| `bin/tacctl.sh` | 52.14% (2283 / 4379 lines) |
| `tests/helpers/*` (tmpenv, setup, mocks) | 92%+ |
| Overall | 52.41% (2319 / 4425 lines) |

Uncovered territory is dominated by `cmd_install` / `cmd_upgrade` / `cmd_uninstall`
(heavy shell-outs to git, apt, go, systemctl, useradd — deliberately deferred)
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
