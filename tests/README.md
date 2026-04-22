# tacctl tests

Test suite for `bin/tacctl.sh`, built on [bats-core](https://github.com/bats-core/bats-core).

## Running

```sh
make bootstrap       # first time: pull bats submodules
make test            # all tiers (unit → integration → e2e)
make test-unit       # pure-logic only, <5s
make test-integration
make test-e2e
make coverage        # produces coverage/index.html (requires: apt install kcov)
make lint            # shellcheck
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
│   ├── *.yaml           # tacquito.yaml fixtures
│   ├── templates/       # device config templates
│   └── golden/          # expected rendered output (M3)
├── unit/                # pure-logic, no I/O, no mocks
├── integration/         # real file I/O into $TACCTL_ETC tmpdir
└── e2e/                 # stubbed systemctl/git/etc.
```

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

## Coverage baseline

Measured via `make coverage` (kcov v42, full suite of 335 tests):

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
