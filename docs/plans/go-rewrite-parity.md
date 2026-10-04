# tacctl 0.2.0: the parity proof (WP4.3)

This is the record of WP4.3 of `docs/plans/go-rewrite.md` (§9.6): the Go
binary against the last bash release on every corpus of the differential
runner, every difference classified under the plan's §3.9 (the only accepted
differences), the bats suite reconciled with the Go tests, and the release
gate items §6.6 1-5 and 8b on the working tree after the package.

Baseline: the **`0.1.18` tag**. The plan text names 0.1.16 in places; 0.1.18
supersedes it (0.1.16, plus the upgrade's `cp -p` of `tacquito.bak` in 0.1.17,
plus the verified Go download in 0.1.18; §3.9 items 24 and 26).

Commit under test: `feature/go-rewrite` at `e3ed134` plus the WP4.3 working
tree changes listed under "Changes made by WP4.3".

## Method

`tests/diff/run.sh` (plan §2.5; usage in `tests/README.md`):

- **A** is `bin/tacctl.sh` of the `0.1.18` tag, checked out into a temp dir
  once per run; nothing of the working tree is used for A.
- **B** is `dist/tacctl` (`make build`, test knobs compiled in), started with
  `TACCTL_TREE` pointing at this tree, as the bats harness does.
- Each corpus line runs under both, each against its own copy of the same
  fixture state, in `env -i` with the same sandbox: every `TACCTL_*` path
  under a per-side root, `LANG=C.UTF-8`, `TZ=UTC`, `TACCTL_SKIP_SUDO=1`, PATH
  stubs for `systemctl` and `logger` (recording their argv) and for `chown`,
  `sleep`, `date` and `openssl`; the clock and the random bytes are fixed
  (`TACCTL_TEST_NOW`, `TACCTL_TEST_RANDOM` on the Go side, stubs and a
  `sitecustomize` on the bash side), so generated secrets and passwords are
  equal without masking. The hosts corpus adds stand-ins for `ssh`, `podman`,
  `getent`, `ip` and `git clone` (`tests/diff/stubs/hosts`): nothing leaves
  the machine and nothing on the host is touched.
- Compared per command: stdout, stderr, exit code, the stubbed commands'
  argv, and the resulting state tree (mode, size and content of every file
  under the sandbox root, an empty `TMPDIR` included). Normalised: ANSI
  colours, timestamps, `mktemp` names, the version, the sandbox and tree
  paths, and bcrypt hashes the commands generated (random salt).
- A line marked `@known <reason>` is a difference the plan accepts; the
  reason cites its §3.9 item. A marked line that shows no difference is
  reported too ("drop the marker"), so markers cannot go stale silently.

Runs (all from the working tree described above):

| run | command | result |
|---|---|---|
| the proof (final, every corpus incl. `lifecycle`) | `tests/diff/run.sh --all --against 0.1.18` | 1378 lines: 1318 same, **0 differ**, 60 known; no stale marker; exit 0; 35 min 07 s |
| the first run (clean tree at `e3ed134`, before `lifecycle`) | the same | 1328 lines: 1268 same, 0 differ, 60 known, 2 stale markers (dropped, below); exit 0; 34 min 48 s |
| the runner against itself | `tests/diff/run.sh --all --against 0.1.18 --b bash`, then `--b bash lifecycle` | 1328 + 50 lines: all same, 0 differ (every `@known` marker reports "no difference", as it must when A = B); exit 0 |
| the runner's self-test | `tests/diff/run.sh --self-test` | A=B: 17 lines, 17 same; the mutant B: 4 differ, 1 known, as expected ("self-test passed") |

## Results per corpus

Final run. Of the 1378 lines, 719 end in a command that fails under A (the
plan wants at least as many failing lines as succeeding ones); in the new
`lifecycle` corpus 28 of 50.

| corpus | lines | same | differ | known |
|---|---|---|---|---|
| backup | 56 | 56 | 0 | 0 |
| config | 250 | 237 | 0 | 13 |
| devices | 79 | 41 | 0 | 38 |
| groups | 185 | 182 | 0 | 3 |
| hosts | 112 | 111 | 0 | 1 |
| lifecycle (new) | 50 | 50 | 0 | 0 |
| log | 86 | 86 | 0 | 0 |
| scopes | 284 | 284 | 0 | 0 |
| store | 70 | 69 | 0 | 1 |
| users | 206 | 202 | 0 | 4 |
| **all** | **1378** | **1318** | **0** | **60** |

(`selftest` is the runner's own corpus, run by `--self-test`.)


## Known differences, by §3.9 item

Every marked line cites its item. The examples below come from a scratch
copy of the marked lines run without their markers (normalised runner output;
`-` is 0.1.18, `+` is the Go binary).

| §3.9 item | lines | corpora | example |
|---|---|---|---|
| 1 `version --long` adds commit, build date, Go version, test knobs | 1 | users | `version --long`: `+commit: …`, `+built: … (commit date)`, `+go: go1.26.2`, `+test knobs: on` after the same first line |
| 3 the `Using template:` note names the built-in template | 38 | devices | `config cisco --scope lab`: `-  - Using template: <SIDE>/tag-tree/config/templates/cisco.template`, `+  - Using template: built-in cisco.template` (every rendered device config of the corpus; the rest of each config is equal, checked at WP3.1 with a wrapper that maps the note back) |
| 5 the `user move` usage names `tacctl user move` | 2 | users | `user move`: `-[ERROR] Usage: tacctl move <username> <new-group>`, `+[ERROR] Usage: tacctl user move <username> <new-group>` |
| 8 `config render --dry-run --out <dir>` is new | 2 | config | `config render --dry-run`: `-[ERROR] Usage: tacctl config render [--force]`, `+[ERROR] Usage: tacctl config render --dry-run --out <dir>` |
| 10 a password over 72 bytes is refused | 1 | users | `user add bob operator --scopes lab <<< <73 bytes>`: 0.1.18 adds the user (bcrypt of the first 72 bytes), exit 0; Go `[ERROR] Password is longer than 72 bytes; bcrypt would ignore the rest. Choose a shorter one.`, exit 1, nothing written |
| 14 `--match` regexes are RE2 | 1 | groups | `group commands add operator show --match '(?=x)'`: 0.1.18 adds the rule, exit 0; Go `[ERROR] Invalid regex: '(?=x)'`, exit 1, nothing written |
| 18 a failed `config sudoers [tiers] install` leaves no temp file | 2 | config | `config sudoers tiers install` (the unprivileged `install -o root` fails): 0.1.18 leaves `tmp/tmp.<RAND>` (the sudoers text) in `TMPDIR`; Go leaves `TMPDIR` empty; output and exit code equal |
| 19 `--match` with no value, `remove` of an invalid regex name | 2 | groups | `group commands add operator show --match`: `-…/lib/groups.sh: line 421: 2: unbound variable` (both exit 1); `group commands remove operator 'sh['`: `-grep: Unmatched [, …`, `-BrokenPipeError: [Errno 32] Broken pipe` (same outcome otherwise) |
| 21 `config linux uid <u> 09999` | 1 | hosts | `-…/lib/linux_hosts.sh: line 583: ((: 09999: value too great for base (error token is "09999")`; outcome equal |
| 22 a legacy `tacquito.yaml` that is not YAML, in yaml.v3's words | 1 | store | `store rollback <<< y` with a broken pre-store file: `-…: expected ',' or ']', but got '<stream end>' (line 2, column 1)`, `+…: did not find expected ',' or ']' (line 1)`; the `[ERROR] … cannot be read as a tacquito.yaml. Nothing was changed.` line and exit 1 are equal |
| 28 the `config defaults` and `config dump` headers name tacctl | 5 | config | `config defaults`: `-# DO NOT edit this output — it is generated by conf_emit_defaults() in`, `-# lib/conf.sh. …`, `+# DO NOT edit this output — it is generated by \`tacctl config defaults\``, `+# (built into tacctl). …`; the data equal |
| 30 the `config` usage lists `render --dry-run --out` | 4 | config | `config bogus`: `+  render --dry-run --out <dir>         Render into a new, empty directory at the live paths; nothing live is written` |

No difference needed an item it does not have: there is **no proposed new
§3.9 item** from WP4.3. The other items have no marked line: 2 (external
commands no longer spawned; the runner records only the `systemctl` and
`logger` calls, which are equal), 4, 6, 7, 9, 11, 12, 13, 15, 16, 17, 20,
23-27 and 29 concern lifecycle paths a sandboxed run does not take, the
binary's build, inputs no corpus line feeds (raw non-UTF-8 bytes, hand-edited
YAML constructs, Python tracebacks), or output the corpora do not exercise.
They are pinned by the Go and bats tests the plan's item text names, by the
container cross-over rehearsal, and in WP5.1.


## Changes made by WP4.3

No Go parity bug was found: the first full run (from the clean tree at
`e3ed134`) showed 0 unexplained differences in 1328 lines. WP4.3 changed:

| file | change | found by |
|---|---|---|
| `tests/diff/corpus/lifecycle.txt` (new) | 50 lines for `backend enable`, `backend disable`, `install`, `uninstall` (see "Corpus coverage") | the coverage check of the cobra tree against the corpora |
| `tests/diff/corpus/{config,groups,hosts,store,users}.txt` | the `@known` reasons that still said "proposed 3.9 item" now cite the items the user accepted since (18, 19, 21, 22); "plan 3.9 item" spelled as the others | reading the markers against §3.9 |
| `tests/diff/corpus/config.txt` | two stale markers dropped (`config` and `config defaults` under `@fixture none`: preflight refuses both on both sides before any output that differs); the runner reported them as "marked @known, but no difference" | the first full run, `config:300` and `config:307` |
| `tests/diff/run.sh` | B's version is read from the binary (`dist/tacctl version`) and every version string is normalised longest first; before, only the tree's `git describe --dirty` and the tag's were, so a binary built from a clean tree compared from an edited one (or the reverse) left `-59-ge3ed134` behind in `rendered.json` and every snapshot manifest | a second run started after the first edits: every mutating line of `users` differed in `tacctl_version` |
| `internal/pyyaml/emitted_test.go`, `internal/pyyaml/roundtrip_test.go` (new) | `TestRoundTripFile`, the manual tool that re-emits a real store or `tacctl.yaml` (the shadow check of plan §2.5), moved behind `-tags roundtrip`; without `-roundtrip <file>` it now fails instead of skipping. The default and testknobs runs contain no skipped test (§6.6 item 2 forbids `t.Skip`); the tool works as before with the tag | the Go test count (`go test -json`: 1 skip) |
| `tests/README.md` | the corpus list names `lifecycle` | |
| `README.md` | "Project Structure" names the Go dependencies of `go.mod` (§6.6 item 8b: the list must match; there was none) | the gate check |


## Corpus coverage

Every user-facing command of the cobra tree (141 commands with the
families; hidden ones left out: `_completion-names`, `_phase`, `completion`,
`__complete`) was checked against the command lines of the corpora (each
` ;; `-separated command counted on its own, 1986 commands before WP4.3).
Before WP4.3 six commands had no line: `backend enable`, `backend disable`,
`install`, `uninstall`, `upgrade` and `config branch`.

The new corpus `tests/diff/corpus/lifecycle.txt` (50 lines, 28 of them
failing under A) covers the first four on every path that stops before
changing anything: argument errors (no id, unknown id, unknown option, two
ids, case), the already-enabled and not-enabled answers, the last enabled
backend refused, the legacy (no store) and no-state refusals, and the
confirmation prompts of `backend enable radius`, `install` and `uninstall`
answered with a closed stdin, `n`, `N`, `no` and `yes` (only `y`/`Y` is a
yes). No line answers `y` or passes `-y`: past the prompt these commands
install packages and write `/opt`, `/etc` and `/usr/local`.

Left out on purpose, and where they are covered instead:

| command | why not in a corpus | covered by |
|---|---|---|
| `upgrade` | its first steps (each backend's upgrade preflight, then `git config --system` for the deploy clone) touch the host before any prompt | `internal/lifecycle` and the backend modules' upgrade tests; the lifecycle bats tests (`TACCTL_TEST_ROOT`); the container cross-over rehearsal (`tests/containers/crossover`, 0.1.17 → Go → 0.1.17); WP5.1 live on the dev server |
| `config branch` | it reads and fetches the deploy clone `/opt/tacctl`, which no variable moves for the bash release | `characterisation.bats` (six tests on a scratch clone) |

Every other command has at least one line; the ones with fewest are the
`config sudoers` and `config sudoers tiers` verbs (install writes root-owned
files, so only the refusal and prompt paths run unprivileged; the bats
`config_metrics_sudoers.bats` and `tiers.bats` cover the rest with a stubbed
`install`), `config deny clear|remove`, `config metrics reset` and `config
linux build` (one or two lines each, success and error).

## The bats suite reconciled with the Go tests

WP4.1 deleted 715 bats tests that drove bash internals (26 whole files and 88
tests of files that stay), moved 11, added 1 and rewrote 23 for the Go
binary. Every deleted test maps to the Go test that replaces it, to a
remaining black-box bats test, or to a drop reason of plan §2.3; the full
table, test by test, is `docs/plans/go-rewrite-wp41-reconcile.md`, which this
document adopts as its reconciliation section. Its two "decisions for the
user" were decided and became §3.9 items 27 and 28.

After WP4.1 the bats suite had 816 tests; WP4.2's generated completion
brought it to 819 (all run in "Final runs"). WP4.3 deleted no bats test and
no Go test; it moved one Go test (`TestRoundTripFile`, a manual tool) behind
a build tag.

## Final runs

On the working tree after WP4.3 (the dev server, 8 cores):

| command | result | wall |
|---|---|---|
| `make lint` (shellcheck, gofmt, go vet ×2, golangci-lint v2.14.0 ×2, no-private) | exit 0, golangci-lint "0 issues" both builds | 11 s |
| `make test-go` (`-race`, without and with `-tags testknobs`) | exit 0 | 22 s cached; uncached `-count=1`: 88 s and 98 s |
| Go test count (`go test -race -count=1 -json`) | default: 1271 tests + 454 subtests passed; testknobs: 1276 + 454; **0 failed, 0 skipped** | |
| `make build && BATS_JOBS=8 make test-bats` | 1..819, 819 ok, 0 not ok, no `# skip` (integration 806, e2e 13) | 208 s |
| `make coverage` | 87.7 % of statements | 40 s uncached |
| `go mod verify` | "all modules verified" | |
| `GOFLAGS=-mod=vendor go build ./...` | exit 0 | |
| `go mod vendor`, then `git diff --exit-code vendor go.mod go.sum` | no diff | |
| `go vet ./...` | exit 0 (also inside `make lint`) | |
| `git diff --exit-code tests/fixtures` | no diff: no golden changed in WP4.3 | |
| `tests/diff/run.sh --all --against 0.1.18` | see "Results per corpus" | 35 min |
| `go vet` and `golangci-lint run --build-tags roundtrip ./internal/pyyaml/` | exit 0, 0 issues (the tagged tool test) | |


## Coverage (plan §6.2)

`make coverage` (`go test -tags testknobs -coverprofile`): **87.7 %** of
statements overall (target ≥ 75 %). Per package, against the §6.2 targets:

| target | packages (statements covered) | holds |
|---|---|---|
| ≥ 85 % | conf 94.6, store 95.0, model 95.9, yamlpy 94.1, cidr 98.9, hash 93.7, names 100.0, policy 94.9, rendered 88.7, render/tacacs 88.2, render/radius 95.2 | yes |
| ≥ 75 % | backend 91.6, devices 93.4, hosts 88.5, cli/args (`internal/cli/args.go`) 100.0 | yes |
| ≥ 60 % | lifecycle 79.7, backend/tacacs 90.6, backend/radius 90.0 | yes |
| overall ≥ 75 % | 87.7 | yes |

The rest: app 98.8, assets 89.5, execx 93.5, pyyaml 96.2, py 93.2, snapshot
90.4, tier 98.6, ui 96.9, paths 100.0, shellquote 100.0; `internal/cli` as a
whole 74.8 (its command bodies are what the bats suite and the differential
runner drive through the binary, which `go test` coverage does not count;
`group.go` 35.6 and `scope.go` 65.3 are the lowest, both exercised by 185 and
284 corpus lines and their bats files); `cmd/tacctl` 0 (two statements:
`main`).


## Release gate, §6.6 items 1-5 and 8b

| # | item | status | evidence |
|---|---|---|---|
| 1 | `make lint` exit 0 | **holds** | "Final runs" |
| 2 | `make test` green, no skipped tests | **holds** | Go 1271/1276 tests + 454 subtests, 0 skips (after moving `TestRoundTripFile` behind its tag); bats 819/819, no `# skip`. Environment-conditional skips exist only for root runs (`t.Skip("root can write anywhere")` and alike, 8 sites) and a missing `git` or `bash` (2 sites); none fires as the unprivileged test user |
| 3 | `make coverage` meets §6.2 | **holds** | 87.7 % overall; every package target met ("Coverage") |
| 4 | the differential runner, zero unexplained differences (baseline: the `0.1.18` tag, superseding 0.1.16) | **holds** | 1378 lines, 0 differ, 60 known, each citing its §3.9 item |
| 5 | goldens unchanged since WP4.3, except the reviewed item 3 diff | **holds** | `git diff --exit-code tests/fixtures` clean on the working tree. Since the `0.1.18` tag the goldens changed only by: the item 3 note line in the eight device-config goldens (one line each); goldens added from the bash release by the campaign (§2.4: drop-ins, installer heads, logrotate, `rendered.json`, `tacctl.overrides.yaml`, `templates.manifest`); and `store.radius.yaml`, whose one secret was hand-quoted (`'inner\secret "quoted" 0123456789'`) and is now what PyYAML 6 itself emits (plain), checked again here with `yaml.safe_dump` (commit `8ced7b3`) |
| 8b | `go mod verify`, `go vet ./...` clean; `vendor/modules.txt` consistent; the README's dependency list matches `go.mod` | **holds** | "Final runs"; the README had no dependency list, WP4.3 added one to "Project Structure" naming the five direct and two indirect modules of `go.mod` |


## Left for Phase 5

- **Shadow mode** (plan §2.5, §6.4 WP5.1 step 1): the read-only verbs on the
  dev server's live state under 0.1.18 and the Go binary, and the mutating
  verbs on a copy; `TestRoundTripFile` (`-tags roundtrip`) re-emits the live
  `store.yaml` and `tacctl.yaml`.
- **What no sandboxed corpus can run**: `upgrade` (and the cross-over from
  0.1.18, both directions), `install`/`uninstall` past their prompt, `backend
  enable radius` with an install, `config branch` on the deploy clone, the
  sudo re-exec, the masked password prompt on a terminal, and real daemons
  (tacquito, FreeRADIUS), logins and host enrolments: WP5.1 (the dev server,
  including the failure rehearsal of §6.4 step 2b) and WP5.2 (the test
  client, re-enrolled with `--scope lab`).
- **Release gate items not in WP4.3**: 6 (container drivers and the hosts
  matrix, started by the user), 7, 8 (fresh install in a clean container
  with the README one-liner), 9-12.

