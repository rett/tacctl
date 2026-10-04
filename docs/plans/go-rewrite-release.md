# tacctl 0.2.0: release checklist (WP5.3)

The record of WP5.3 of `docs/plans/go-rewrite.md` (§9.7): the release gate of
§6.6 run on the release candidate, and the commands that release it. No work
package performs the release; the user runs the commands in "Releasing" below.

Release candidate: `feature/go-rewrite` at `66a1882` (`origin/develop` =
`c654081` plus one local commit, the container check's radclient retry) and
the WP5.3 working tree changes listed under "Changes made by WP5.3". The
baseline everywhere is the `0.1.18` tag (the plan's "0.1.16" reads as 0.1.18).

## Release gate (§6.6)

Run on the dev server (8 cores) with `GOCACHE`/`GOPATH` under the user's
cache, `BATS_JOBS=8`. Go code under test is `66a1882` throughout: WP5.3
changed no Go file.

| # | item | status | evidence |
|---|---|---|---|
| 1 | `make lint` exit 0 | **holds** | shellcheck (now including `tests/containers/fresh`), gofmt, `go vet` ×2, golangci-lint v2.14.0 ×2 "0 issues", no-private; 11 s. Again after the item 32 fix: exit 0 |
| 2 | `make test` green, nothing skipped | **holds** | `go test -race -count=1 -v ./...`: 1273 tests + 454 subtests passed, 0 failed, 0 `--- SKIP`; with `-tags testknobs` 1278 + 454, 0 failed, 0 skipped (3 min 9 s for both). After the item 32 fix: 1276 + 454 and 1281 + 454 (the three new hand-over tests), 0 failed, 0 skipped. The `t.Skip` calls in the tree are conditional on running as root or without git/bash and did not fire. `make build && BATS_JOBS=8 make test-bats`: `1..819`, 819 ok, 0 not ok, no `# skip` (225 s; after the fix again 819/819, 207 s) |
| 3 | `make coverage` meets §6.2 | **holds** | 87.8 % overall (≥ 75). ≥ 85: conf 94.6, store 95.0, model 95.9, yamlpy 94.1, cidr 98.9, hash 93.7, names 100, policy 94.9, rendered 88.7, render/tacacs 88.2, render/radius 95.2. ≥ 75: backend 91.9, devices 93.4, hosts 88.5, cli/args (`internal/cli/args.go`) 100. ≥ 60: lifecycle 79.7, backend/tacacs 90.6 (its `lifecycle*.go` 83.8), backend/radius 90.1 (`lifecycle*.go` 95.5). `internal/cli` as a whole 74.8, as in WP4.3. `make coverage` needed the Makefile fix below on a machine without `go` on `PATH` |
| 4 | differential runner, 0 unexplained differences | **holds** | `tests/diff/run.sh --all --against 0.1.18`, B = `dist/tacctl` built in a clean detached worktree at `66a1882` (version `0.1.18-63-g66a1882`, so no `-dirty` stamp in the snapshot manifests): 1378 command lines, 1318 same, **0 differ, 60 known**, each citing its §3.9 item (3: 38, 28: 5, 30: 4, 5/8/18/19: 2 each, 1/10/14/21/22: 1 each); 719 lines end in a failing command under A; exit 0; 38 min. After the item 32 fix, the corpora that reach `upgrade`/`install` and `config branch` (`lifecycle`, `config`): 300 lines, 0 differ, 13 known, exit 0 (6 min). (A first run in the main tree was stopped and discarded: a `make build` there mid-run stamped `-dirty` into B's snapshot manifests.) |
| 5 | goldens unchanged since WP4.3 except reviewed items | **holds** | `git diff --stat fce3ac6 HEAD -- tests/fixtures ':(glob)internal/**/testdata/**'` and the same against the working tree: empty. The two commits since WP4.3 (`c654081`, `66a1882`) touch code, tests and docs only |
| 6 | RADIUS containers and the hosts matrix | **holds** | RADIUS: almalinux-8 42/0, ubuntu-noble 115/0 (1 driver SKIP, IPv6 listener not configured by the flow) on the working tree; almalinux-9 passed at `c654081`/`66a1882` in WP5.1. `hosts/matrix.sh`: 26 runs, exit 0, every run 0 FAIL, 55 min. No driver change was needed. Tables under "Container runs" |
| 7 | WP5.1 and WP5.2 | **holds** (recorded by the coordinator) | WP5.1 on the dev server: cross-over from 0.1.18 with `upgrade --branch develop` (19 s; cold build 12 s, 129 MB cache), functional round, a second upgrade rebuilt and restarted nothing, rollback to `master` (0.1.18) and forward again without manual repair, the failure rehearsal of §6.4 2b; it found the systemd start-limit problem fixed as §3.9 item 31 (`c654081`), with which the dev server was upgraded again (no restarts; 20 starts in 6 s fine). WP5.2 on the test client: RADIUS ↔ TACACS+ enrol cycles, `sudo`/read-only, unenroll and re-enroll on `lab` with tacplus, end state equal to the start. Summarised in the release notes' "Verification" |
| 8 | fresh install without Go | **holds** | `tests/containers/fresh/run.sh` on `66a1882` (new, re-runnable): 19 PASS, 0 FAIL; the bootstrap installed Go 1.26.2 from `dl.google.com` after verifying its checksum, built and installed the binary; `version --long`, `user passwd engineer` through a pty, `config cisco --scope lab`, `status`, `config validate`; `uninstall -y` left `/usr/local/go`, `/opt/tacquito-src`, `/root/go`, the build cache, and two by-products (Go's telemetry counters in `/root/.config/go`, an empty `/etc/gitconfig`). Details and the `--rollback` run (now with no manual step: the hand-over installs Python itself) under "Container runs" |
| 8b | `go mod verify`, `go vet`, vendor, README modules | **holds** | "all modules verified"; `go vet ./...` and `-tags testknobs` exit 0; `go mod vendor` then `git status vendor go.mod go.sum`: no change; README "Project Structure" names cobra (with pflag, mousetrap), x/crypto, x/sys, x/term, yaml.v3 = `go.mod`'s five direct and two indirect modules |
| 9 | docs | **holds** | README, `man/tacctl.1`, CHANGELOG updated in WP4.2/4.3 and item 31; `tests/README.md` gains the fresh-install section (WP5.3); `docs/release-notes-0.2.0.md` written. `MANWIDTH=80 man --warnings -l man/tacctl.1 > /dev/null`: no warning, exit 0. `TestManPageNamesEveryCommand` and `TestManPageNamesNoMissingCommand` pass |
| 10 | `tacctl version` prints the tag; `--long` shows go1.26.2 | **pending the tag** | `--long` shows `go: go1.26.2`, `test knobs: off` on the dev server (c654081) and in the fresh container (66a1882). The first line follows `git describe`: `0.2.0` on `master` once tagged (`0.2.0-1-g…` on `develop` after the back-merge) |
| 11 | the user's read-only check on production | **pending the user** | commands in "Releasing", step 5 |
| 12 | GitHub description and topics | **pending the user** | command in "Releasing", step 6 |

## Container runs

Rootless podman on the dev server, against the working tree (Go code =
`66a1882`). Wall times are per run; several runs shared the machine.

**RADIUS** (`tests/containers/radius/run.sh`):

| distro | FreeRADIUS | result | wall |
|---|---|---|---|
| almalinux-8 | 3.0.20 (rendered with `config render --dry-run --out`, served by `radiusd`) | 42 PASS, 0 FAIL | 70 s |
| ubuntu-noble | 3.2.5 | 115 PASS, 0 FAIL, 1 SKIP (the driver's own "IPv6 client (no udp6 listener)": the flow configures no udp6 listener; almalinux-8 covers IPv6) | 306 s |
| almalinux-9 | 3.0.27 | passed at `c654081`/`66a1882` in WP5.1 (not re-run) | |

**Linux hosts** (`tests/containers/hosts/matrix.sh`, 26 runs):

| cycle | client (server) | result | wall |
|---|---|---|---|
| radius | ubuntu-noble | 56 PASS, 0 FAIL | 96 s |
| radius | debian-trixie | 57 PASS, 0 FAIL | 109 s |
| radius | debian-bookworm | 57 PASS, 0 FAIL | 118 s |
| radius | almalinux-8 | 57 PASS, 0 FAIL | 140 s |
| radius | almalinux-9 | 57 PASS, 0 FAIL | 153 s |
| radius | almalinux-10 | 57 PASS, 0 FAIL | 116 s |
| radius | rocky-8 | 57 PASS, 0 FAIL | 141 s |
| radius | rocky-9 | 57 PASS, 0 FAIL | 181 s |
| radius | rocky-10 | 57 PASS, 0 FAIL | 144 s |
| probe | ubuntu-noble, debian-trixie, debian-bookworm, almalinux-8, almalinux-9, almalinux-10 | completed, no FAIL line (records, not checks) | 75, 80, 74, 100, 112, 91 s |
| radius | almalinux-9 (server almalinux-9, FreeRADIUS 3.0.27) | 57 PASS, 0 FAIL | 200 s (with the server image rebuild) |
| radius | ubuntu-noble (server almalinux-9) | 56 PASS, 0 FAIL | 89 s |
| tacplus | ubuntu-noble, debian-trixie, rocky-9, almalinux-10 | 50 PASS, 0 FAIL each | 98, 88, 121, 100 s |
| switch | ubuntu-noble, debian-bookworm, rocky-8, rocky-9, almalinux-10 | 82 PASS, 0 FAIL each | 148, 162, 180, 200, 166 s |

`matrix.sh` exit 0, 26 runs, 55 min wall (3286 s), while other checks shared
the machine; server image FreeRADIUS 3.2.5 and the dev server's tacquito.

The `server-almalinux-9` image dated from before the Go rewrite (no Go, no
tacctl binary) and was removed so the driver rebuilt it; the other images were
current. No driver needed a fix.

**Fresh install** (`tests/containers/fresh/run.sh`, ubuntu:noble with
systemd, git, wget, sudo, iproute2; no Go, no Python; the release candidate
as `master` of a scratch bare clone):

| run | result | wall |
|---|---|---|
| plain | 19 PASS, 0 FAIL | 177 s |
| `--rollback` | 37 PASS, 0 FAIL | 204 s |

What the plain run showed: the one-liner cloned, the bootstrap printed
`Installing Go 1.26.2...`, `Go tarball checksum verified.`, `Go 1.26.2
installed.`, built `/usr/local/bin/tacctl` (a regular file) and ran `install`
(87 s in all, including tacquito's build and the packages for Linux hosts),
which said `Go 1.26.2 already installed, skipping.`; tacquito active; python3
still absent; `version --long` showed commit `66a1882…`, `go1.26.2`, `test
knobs: off`; `user passwd engineer` through a pty (masked echo, snapshot,
restart, `Password changed`), `user list` shows engineer active, `user verify`
accepts the password; `config cisco --scope lab` names
`/etc/tacctl/templates/cisco.template` (the copy install writes, so the
§3.9 item 3 wording does not show on an installed server; as in 0.1.18) and the
server's address; `status`, `config validate` clean; `uninstall -y` (1 s).
Left on the filesystem afterwards, compared with the state before the install
and with a container that only installed the same 203 packages:
`/usr/local/go`, `/opt/tacquito-src`, `/root/go`, `/root/.cache/go-build`,
plus `/root/.config/go` (10 files: the Go toolchain's own telemetry counters,
written by every `go` run) and an empty `/etc/gitconfig` (the
`safe.directory` entries are unset, the file stays; 0.1.18 does the same).
No account left behind. The packages the install added stay, as documented.

The `--rollback` run, on the same kind of install with python3, python3-yaml
and python3-bcrypt added (what a server from 0.1.x has): `upgrade --branch
0.1.18` → `Switched to branch '0.1.18'.`, `Target branch is a bash release of
tacctl; handing over.`, 0.1.18's upgrade `Management scripts already up to
date.`; the command is the link again, `tacctl version` = `tacctl 0.1.18`,
tacquito active, `status` and `config validate` clean under bash, the store
byte-identical, `user verify` accepts the password; `upgrade` again stays on
the tag; `upgrade --branch master` → `tacctl updated — restarting upgrade with
new version...`, `Building /usr/local/bin/tacctl from /opt/tacctl...`, back on
the Go binary of `66a1882`, store unchanged; a further `upgrade` builds
nothing; `uninstall -y` as in the plain run.

**Found, then fixed in WP5.3 (§3.9 item 32).** The first rollback rehearsal
was on a server with Python added by hand. On a server *installed* with 0.2.0,
which has no Python, the hand-over left a broken command: 0.1.18's
`bin/tacctl.sh` stopped at its first line, `lib/conf.sh: line 189: python3:
command not found` (exit 127), and so did every later `tacctl` command until
`python3 python3-yaml python3-bcrypt` were installed by hand. The user chose to
fix it before the release: the Go upgrade now installs those packages before
it hands over, and refuses (exit 1, clone back on its branch, command
unchanged, the `apt-get` command printed) when it cannot.

Re-run after the fix, on the working tree (`--worktree`: a `git stash create`
commit of the tracked files, so the uncommitted Go change is what is
installed):

| run | result | wall |
|---|---|---|
| `--worktree --rollback` | 40 PASS, 0 FAIL | 179 s |
| `--worktree` (plain) | 19 PASS, 0 FAIL | 141 s |

With no Python on the server and no manual step, `upgrade --branch 0.1.18`
printed `Switched to branch '0.1.18'.`, `Installing packages the bash release
needs: python3 python3-yaml python3-bcrypt`, `Target branch is a bash release of
tacctl; handing over.`; then `python3 -c "import yaml, bcrypt"` works, `tacctl
version` is `tacctl 0.1.18`, status and validate are clean under bash, the store
is unchanged, and the way forward with `--branch master` and the no-op upgrade
pass as before. The plain run is unchanged (19/0; same leftovers).

## Changes made by WP5.3

- `Makefile`: `make coverage` puts the Go toolchain's directory on `PATH` (the
  coverage run of a package without tests calls `go tool covdata` through
  `PATH`, so on a machine whose `PATH` has no `go` the target failed with
  `exec: "go": executable file not found`); `lint-sh` also checks
  `tests/containers/fresh/*.sh`.
- `tests/containers/fresh/run.sh` (new) and its section in `tests/README.md`:
  the release gate's item 8, re-runnable, with `--rollback` for the way back to
  the bash release by tag and forward again, and `--worktree` to install the
  uncommitted tracked files.
- `internal/lifecycle/upgrade.go`, `internal/lifecycle/deps.go`: before the
  hand-over to a bash release, `ensureBashReleaseDeps` checks `python3`,
  `python3-yaml`, `python3-bcrypt` with `dpkg-query` and installs the missing
  ones with `apt-get` (the dependency step's own helpers); on failure no
  hand-over, the clone goes back to the branch (or commit) it was on before a
  `--branch` switch, and the command to run is printed (§3.9 item 32).
  `internal/lifecycle/matrix_test.go`: the matrix host's git plays
  `symbolic-ref`; three tests (all present: no `apt-get`; missing: `apt-get
  install` then the hand-over; `apt-get` fails: refusal, no exec, the Go
  binary and the clone as before).
- `docs/plans/go-rewrite.md` §3.9 item 32; `CHANGELOG.md` item 32, the
  "Rolling back" section, and item 3 reworded to what an installed server
  shows.
- `docs/release-notes-0.2.0.md` (new): the GitHub release text, built from the
  CHANGELOG's 0.2.0 section plus a verification summary.
- This file.

## Open points

1. ~~Rollback from a server installed with 0.2.0 needs Python first.~~ Fixed
   (§3.9 item 32, user 2026-10-04): see "Container runs".
2. ~~CHANGELOG item 3 wording.~~ Reworded in the CHANGELOG and the release
   notes: the built-in note shows only when `/etc/tacctl/templates/` has no
   copy, and an installed server has one (fresh-install container: `Using
   template: /etc/tacctl/templates/cisco.template`, as in 0.1.18).
3. ~~`make coverage` failed on a machine without `go` on `PATH`.~~ Fixed in
   the `Makefile`.
4. After a rollback by tag the clone is detached and plain `upgrade` stays on
   the tag: the intended effect of a rollback by tag; the CHANGELOG and step
   5 below say how to follow `master` again. No change.
5. `/root/.config/go` (Go's telemetry counters) and an empty
   `/etc/gitconfig` also survive `uninstall`, besides the documented four;
   both are by-products (the toolchain's, and `git config --unset`'s) and
   0.1.18 leaves them too. Documenting them is optional.

## Releasing (the user)

Every step below is the user's. Paths are the user's own checkout of the
repository; "the dev server" tracks `develop`, "the production host" tracks
`master`. The release date is written as `YYYY-MM-DD`; put the real date in.

### 1. Commit WP5.3 and bring `develop` up to the release candidate

```sh
git checkout feature/go-rewrite
git status                      # only the files of "Changes made by WP5.3"
git add Makefile tests/containers/fresh/run.sh tests/README.md CHANGELOG.md \
        internal/lifecycle/upgrade.go internal/lifecycle/deps.go internal/lifecycle/matrix_test.go \
        docs/plans/go-rewrite.md docs/release-notes-0.2.0.md docs/plans/go-rewrite-release.md
git commit -m "fix(go): install a bash release's packages before handing over to it (section 3.9 item 32); WP5.3 release gate, fresh-install check, 0.2.0 release notes"
git checkout develop
git merge --ff-only feature/go-rewrite      # develop was c654081; 66a1882 and the WP5.3 commit follow
git push origin develop
```

On the dev server:

```sh
sudo tacctl upgrade             # rebuilds the binary (the tree changed), restarts nothing
tacctl version                  # tacctl 0.1.18-64-g<sha of the WP5.3 commit>
```

### 2. The release branch and its date stamps

The version comes from `git describe` at build time; nothing else in the tree
carries it except two dates:

```sh
git flow release start 0.2.0
sed -i 's/^## 0\.2\.0 (unreleased)$/## 0.2.0 (YYYY-MM-DD)/' CHANGELOG.md
sed -i '3s/^\.TH TACCTL 1 "[0-9-]*" "tacctl 0\.2\.0"/.TH TACCTL 1 "YYYY-MM-DD" "tacctl 0.2.0"/' man/tacctl.1
git diff --stat                 # CHANGELOG.md and man/tacctl.1, one line each
MANWIDTH=80 man --warnings -l man/tacctl.1 > /dev/null
git commit -am "docs: 0.2.0 release date"
```

(The README's `tacctl version   # tacctl 0.2.0` example is already right; the
release notes carry no date.)

### 3. Finish, fix the tag message, push

```sh
git flow release finish -m "Release 0.2.0" 0.2.0
git tag -f -a 0.2.0 -m "Release 0.2.0" master    # git-flow writes "Release 0.2.0 0.2.0"
git tag -n1 0.2.0                                  # 0.2.0  Release 0.2.0
git describe master                                # 0.2.0
git push origin develop master 0.2.0
```

`feature/go-rewrite` is fully merged and can be deleted afterwards
(`git branch -d feature/go-rewrite`); it was never pushed.

### 4. The dev server

```sh
sudo tacctl upgrade             # develop is now "Merge tag '0.2.0' into develop"
tacctl version                  # tacctl 0.2.0-1-g<sha>
```

### 5. The production host (when the user chooses)

Read-only first:

```sh
tacctl version                              # tacctl 0.1.18
sudo git -C /opt/tacctl status -sb | head -1    # ## master...origin/master, nothing else
/usr/local/go/bin/go version                # go1.26.x: used as is; older than 1.26.0 → the bootstrap installs 1.26.2 (needs dl.google.com)
df -h /root /usr/local                      # ~150 MB for the build cache and the binary
```

A snapshot to fall back on, as on the dev server (add
`/etc/freeradius/3.0/tacctl-radius* /etc/systemd/system/freeradius.service.d`
if RADIUS is enabled):

```sh
sudo tar czf /root/tacctl-pre-0.2.0.tgz --ignore-failed-read /etc/tacctl /etc/tacquito \
    /etc/systemd/system/tacquito* /etc/bash_completion.d/tacctl /usr/local/bin/tacctl
sudo chmod 600 /root/tacctl-pre-0.2.0.tgz
sudo tacctl backup list | tail -3
```

The cross-over:

```sh
sudo tacctl upgrade
```

What to see, in order (0.1.18 runs first, then the bootstrap, then 0.2.0;
the dev server's cross-over took 19 s with a 12 s cold build):

1. the 0.1.18 banner and `Backends: …`, tacquito "up to date" (or rebuilt, if
   upstream moved);
2. `Pulling latest management scripts...`, `Management scripts updated: <sha>`,
   `tacctl updated — restarting upgrade with new version...`;
3. `Building /usr/local/bin/tacctl from /opt/tacctl...` (the bootstrap; it
   first prints `Installing Go 1.26.2...` / `Go tarball checksum verified.`
   only if the host's Go is older than 1.26.0);
4. the 0.2.0 upgrade: `Management scripts already up to date.`, the config
   phase, `Updated: bash completion` (once), the man page, templates you have
   not customised, logrotate; a service is restarted only if something it
   reads changed (on the dev server: none).

If the build fails, the old command is left in place and the bootstrap prints
the way back (`sudo git -C /opt/tacctl checkout 0.1.18 && sudo tacctl config
branch master`).

Afterwards (read-only, release gate items 10 and 11):

```sh
ls -l /usr/local/bin/tacctl         # a regular file, about 11 MB, not a link
tacctl version                      # tacctl 0.2.0
tacctl version --long               # commit = $(git -C /opt/tacctl rev-parse HEAD), go: go1.26.2, test knobs: off
systemctl is-active tacquito        # (and freeradius, if enabled)
tacctl status
tacctl config validate              # exit 0, no DRIFT line
sudo tacctl upgrade                 # again: changes nothing, builds nothing, restarts nothing
```

**Rollback**, if needed (nothing in `/etc/tacctl` has to change):

```sh
sudo tacctl upgrade --branch 0.1.18
```

A tag works as the target: the Go upgrade fetches tags, checks the tag out
(`Switched to branch '0.1.18'.`, a detached HEAD), sees a bash release,
installs `python3`, `python3-yaml` and `python3-bcrypt` if any is missing
(`Packages the bash release needs: all present.` on the production host,
which came from 0.1.x), prints `Target branch is a bash release of tacctl;
handing over.`, turns `/usr/local/bin/tacctl` back into the link to
`bin/tacctl.sh` and runs 0.1.18's `upgrade`, which finds no upstream on a
detached HEAD and stays put (`Management scripts already up to date.`).
Read from `internal/lifecycle/upgrade.go` (`updateDeploy`,
`ensureBashReleaseDeps`, `handOverToBash`) and 0.1.18's `cmd_upgrade`, and run
in a container (`tests/containers/fresh/run.sh --rollback`, "Container runs").
Afterwards the clone is on the tag, not on a branch: `sudo tacctl upgrade`
stays on 0.1.18, and `sudo tacctl upgrade --branch master` makes the host
follow `master` again (and, while `master` is 0.2.0, crosses over again).

Without a working `tacctl` (the CHANGELOG's manual recipe):

```sh
sudo git -C /opt/tacctl fetch --tags --force origin
sudo git -C /opt/tacctl checkout 0.1.18
sudo ln -sf /opt/tacctl/bin/tacctl.sh /usr/local/bin/tacctl
sudo tacctl upgrade
```

### 6. GitHub

Description and topics (§7.4):

```sh
gh repo edit rett/tacctl --description "One CLI to run TACACS+ (tacquito) and RADIUS (FreeRADIUS) authentication servers from a single user, group and scope store, with device configs for Cisco, Juniper and WTI and PAM login for Linux hosts." --add-topic tacacs-plus --add-topic tacacs --add-topic radius --add-topic freeradius --add-topic tacquito --add-topic aaa --add-topic pam --add-topic network-automation --add-topic cisco --add-topic juniper
```

The release (optional; the repository has no releases yet):

```sh
gh release create 0.2.0 --verify-tag --title "tacctl 0.2.0" --notes-file docs/release-notes-0.2.0.md
```

### 7. Housekeeping

- The dev server keeps `/root/tacctl-pre-go-*.tgz` (WP5.1) and
  `/root/tacctl-pre-wp52-*.tgz` (WP5.2) until the user removes them.
- Container images kept in rootless podman: `localhost/tacctl-host-check:*`,
  `localhost/tacctl-radius-check:*`, `localhost/tacctl-rehearsal:*`,
  `localhost/tacctl-fresh:noble`; `podman rmi` them when no longer wanted.
