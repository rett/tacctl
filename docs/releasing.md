# Releasing tacctl

A release is a tag on `master` plus four GitHub release assets, built and
signed on the release manager's own machine; a workflow then rebuilds them
independently and compares (step 8):

| Asset | What it is |
|---|---|
| `tacctl-<tag>-linux-amd64` | the binary for x86_64 hosts |
| `tacctl-<tag>-linux-arm64` | the binary for aarch64 hosts |
| `SHA256SUMS` | the SHA-256 of both binaries |
| `SHA256SUMS.sig` | an `ssh-keygen -Y sign` signature of `SHA256SUMS` by the release key (identity and namespace `tacctl-release`) |

## What a host does with them

`/opt/tacctl/bin/tacctl.sh` (the bootstrap shim, which `tacctl install` and
`tacctl upgrade` also use to replace `/usr/local/bin/tacctl`) downloads a
release binary only when the clone is checked out exactly at a release tag
(`git describe --tags --exact-match`). It then:

1. requires a key in the clone's `release/allowed_signers`, the `wget` and
   `ssh-keygen` commands (`openssh-client`) and an amd64 or arm64 machine;
2. downloads `SHA256SUMS`, `SHA256SUMS.sig` and the binary for the machine
   from `https://github.com/rett/tacctl/releases/download/<tag>/`;
3. verifies the signature with the clone's `release/allowed_signers`, the
   binary against its line of `SHA256SUMS`, and that the binary's
   `tacctl version --long` names the commit the clone is at;
4. installs it in one rename and says
   `Installing the <tag> release binary (linux/<arch>, verified)`.

If any step does not hold, it says why in one line,
`Release binary for <tag> not used (<reason>); building from source.`, and
builds the binary from the clone as on a branch. A branch checkout never
downloads anything. The Go toolchain is installed either way (tacquito is
built from source on the host), so the release binary saves the tacctl build
and brings arm64 hosts a tested binary; it removes no dependency.

The key is the one in the tree being installed: every tag carries its own
`release/allowed_signers`.

## The release key

The release key is already generated and its public half committed
(`release/allowed_signers`); this section is how it was made, and how to
replace it. The private key stays on the release manager's machine; only the public
half is committed.

```sh
ssh-keygen -t ed25519 -f ~/.ssh/tacctl-release -C tacctl-release   # set a passphrase
printf 'tacctl-release namespaces="tacctl-release" %s\n' \
    "$(cut -d' ' -f1,2 ~/.ssh/tacctl-release.pub)" >> release/allowed_signers
git add release/allowed_signers
git commit -m "release: the release signing key"
```

`release/allowed_signers` then ends with one line of the form

```
tacctl-release namespaces="tacctl-release" ssh-ed25519 AAAA...
```

Commit it on `develop` before the release branch starts, so the tag carries
it. Until a key line is there, every host builds from source and says
`(no release key configured)`.

To replace the key, add the new line (and, when the old key must no longer
be trusted, remove its line) in a release; older tags keep trusting the key
their own tree lists.

## Each release

The example is 0.2.1 (the release before it 0.2.0); replace it throughout.

A release runs with qargi, the git-flow release tooling the maintainer
uses. The commands that change something (`release start`, `push`, `finish`
and `publish`, and `branch prune`) are plans: each prints what it will do
before anything is applied. `release verify`, `release assets`, `release
step` and `release sign` print no plan (`sign` is run by the key holder on
their own terminal). The division of labour is fixed. The maintainer's
tooling drives the git-flow steps (verify, start, push, finish) and the
after-steps that build, publish and clean up; the key holder alone signs; and
every merge into `develop` or `master`, every push, every tag, every publish
and every prune is a plan that needs the maintainer's explicit go-ahead
(`start`, `push`, `finish`, `publish` and `prune` each print a plan and take
a plan token with `--plan` and the go-ahead with `--approved`; `push` opens
the pull request; `prune` deletes branches). The hand commands are kept at
the end, for a release made without the tooling.

Before the first step, bring the tacquito fork's `main` up to upstream
(`patches/README.md`, Following upstream) and run the gates on it: a host
builds the fork's head, and a host upgrading from a release before 0.2.24
pulls upstream once before the new binary points its clone at the fork, so a
fork behind upstream makes that host rebuild tacquito at every upgrade until
the fork catches up.

Also before the first step, on `develop`:

- **The rollback target.** Every release ships `tacctl rollback <previous
  release>` (0.2.17 to 0.2.28 each did). Check that the release before this
  one is a constant in `internal/lifecycle/rollback.go` (`RollbackTarget0228`
  for 0.2.29) and is the one the refusal names "(the release before this
  one)" (`internal/lifecycle/rollback_test.go`), that the `rollback` entry of
  `man/tacctl.1` lists it the same way, that the CHANGELOG has its item, and
  that `const rollbackFrom` in `internal/cli/rollback.go` is this release (the
  snapshot note and the two recovery hints of a rollback name it;
  `TestRollbackFromIsTheReleaseOfTheChangelog` compares it with the first
  `## X.Y.Z` heading of `CHANGELOG.md`).
- **The plans.** A plan, handoff, lab sheet or spike of this release is
  deleted in this release (`docs/development/README.md`, Working rules) and
  recorded under "Removed plans" in `docs/plans/README.md` with the commit
  or tag that still holds it (`git show <commit>:docs/plans/<file>`).
  `docs/plans/` keeps the backlog, what is deferred and the plan of the
  release in progress.
- **The notes.** `tests/tools/release-notes-check.sh <version>` (qargi runs
  it as `release.preflight` before `release start` and `release push`) checks
  that `docs/release-notes-<version>.md` exists and points at the CHANGELOG,
  that the CHANGELOG section of the version has items numbered 1, 2, 3 ...
  without a gap, and that `const rollbackFrom` is the version. The notes are
  committed on `develop` before the release starts. Model them on
  `docs/release-notes-0.2.23.md`: a `# tacctl <version>` title, a paragraph
  on what the release does that points to its numbered CHANGELOG section for
  everything that differs from the release before, then sections by theme
  (`## Devices`, `## Rollback`, `## Upgrading`, ...). The publish step
  (step 7) uses them as the release's text.

The steps, in order. The first four are the git-flow steps; the rest are the
after-steps. Six of them are recorded with `qargi release step 0.2.1 <name>`
once their proof holds, and they are exactly these: `assets`, `sign`,
`publish`, `reproducible`, `site` and `prune`. Step 9, the check on a host, is
not one of them: it is the maintainer's own check, and nothing records it.

| # | Step | Who | What proves it |
|---|---|---|---|
| 1 | verify | the maintainer's tooling | a passing release gate at the head of `develop` |
| 2 | start | the maintainer's tooling, on the maintainer's go-ahead | `release/0.2.1` exists, its first commit dates the release |
| 3 | push | the maintainer's tooling, on the maintainer's go-ahead | the checks of the pull request into `master` are green |
| 4 | finish | the maintainer's tooling, on the maintainer's go-ahead | `git describe master` prints `0.2.1`; `master`, `develop` and the tag are pushed |
| 5 | assets | the maintainer's tooling | the worktree that `release assets` prints holds the two binaries and `SHA256SUMS` |
| 6 | sign | the key holder only | `release sign` records that `make release-verify` passed |
| 7 | publish | the maintainer's tooling, on the maintainer's go-ahead | the GitHub release holds the four files |
| 8 | reproducible | the maintainer's tooling | the `release-reproducible` run of the tag is green |
| 9 | check on a host | the maintainer, not recorded | `tacctl upgrade` installs the verified binary |
| 10 | site | the maintainer's tooling | the `build` check of the `gh-pages` pull request is green, then it is merged |
| 11 | prune | the maintainer's tooling, on the maintainer's go-ahead | no merged `agent/*` or `feature/*` branch is left locally and, if pruned with `--remote`, on origin |

### 1. Verify

```sh
qargi release verify 0.2.1
```

Runs the release gate: the feature gates first (`make lint`, the static
checks and `make gate-go`), then `GATE_TMPFS=1 make gate-ci` (what the `test`
workflow runs: the race detector and the `-tags testknobs` shards;
`docs/development/README.md`, Working rules). Only a passing run at the head
of `develop` lets a release start; a commit after it needs a new run. The
verdict that counts is the final `GATE-CI PASS` line.

### 2. Start

```sh
qargi release start 0.2.1
```

A plan and a token, applied on the maintainer's go-ahead. It runs the stored
preflight (`tests/tools/release-notes-check.sh 0.2.1`, above), creates
`release/0.2.1` from `develop`, and makes the first commit of the branch: the
CHANGELOG heading `## 0.2.1 (unreleased)` becomes `## 0.2.1 (YYYY-MM-DD)` and
the `.TH` line of `man/tacctl.1` takes the same date and `tacctl 0.2.1`.
There is no `VERSION` file: the version is the CHANGELOG heading, the tag and
`const rollbackFrom` in `internal/cli/rollback.go`.

### 3. Push

```sh
qargi release push 0.2.1
```

A plan, on the maintainer's go-ahead. Pushes the release branch and opens the
pull request into `master`, so that
the `test` workflow runs on the release commit (the date changes and the
notes) before the tag exists; the workflow runs on a pull request and on a
push to `develop`, not on a push to `master`, whose files are the same as
`develop`'s after the finish. Wait for the checks of the pull request: all
green before the finish.

### 4. Finish

First, in a checkout of the release branch (`release/0.2.1`, at the commit the
pull request checks ran on), check the release metadata:

```sh
tests/tools/release-preflight.sh 0.2.1
```

Finish only when it passes. It lists every problem: the dated
`## 0.2.1 (YYYY-MM-DD)` CHANGELOG heading (a real date, and no
`(unreleased)` one), the `.TH` line of `man/tacctl.1` naming `tacctl 0.2.1`
and the same date, and `docs/release-notes-0.2.1.md`. Little else before
the finish checks this: `release start` only checks that the man page's
`.TH` line exists and runs `tests/tools/release-notes-check.sh`, which
accepts an `(unreleased)` heading, and `release finish` refuses an empty
`.TH` date or version. Only the preflight checks the dated heading, that the
date and the version match, and the notes, so run it before the finish.
`make release-assets` runs it only in step 5, after the finish has pushed the
tag, when a fault is no longer fixable in this release. A second argument names another tree to check instead of this
repository.

```sh
qargi release finish 0.2.1
```

A plan, a token and the maintainer's go-ahead. It merges `release/0.2.1`
into `master` without fast-forward, creates the annotated tag `0.2.1`,
merges the release into `develop`, deletes the release branch, and pushes
`master`, `develop` and the tag. The pull request closes by itself when
`master` is pushed. `git describe master` prints `0.2.1`.

The GitHub repository refuses force pushes and deletion of `master` and
`develop` and any move or deletion of a `0.*` tag: a pushed tag is final, so
a fault found after the finish is fixed in the next release (or a hotfix),
never by moving the tag. That is why the gate of step 1, the checks of
step 3 and the preflight above come before it; the gate and the checks of
the pull request do not look at the release metadata (the dated heading, the
`.TH` line, the notes), so the preflight above is the only check of it
before the tag. A host that upgrades between
the finish and the publish (step 7) finds no release binary and builds from
source (`could not download SHA256SUMS`).

### 5. Assets

```sh
qargi release assets 0.2.1
```

Builds `tacctl-0.2.1-linux-amd64`, `tacctl-0.2.1-linux-arm64` and
`SHA256SUMS` from the tag, with `make release-assets`, in a clean detached
worktree of the tag under qargi's state directory. It prints the path of that
worktree; the files are in its `dist/release`, not in `dist/release` of the
repository's own checkout, which it never touches. The signing (step 6) and
the publish (step 7) take their files from the same worktree. By hand:
`git checkout 0.2.1`, a clean checkout of exactly the tag, then `make
release-assets`, and the files are in that checkout's `dist/release`.

`make release-assets` refuses a tree that is not at a release tag or has
local changes, and one whose release metadata is not in place
(`tests/tools/release-preflight.sh`, which lists every problem): the tag has
its dated `## <tag> (YYYY-MM-DD)` CHANGELOG heading and no `(unreleased)`
one, the `.TH` line of `man/tacctl.1` names `tacctl <tag>` and the same date,
and `docs/release-notes-<tag>.md` exists. It then builds both architectures
with the same recipe as a host (`bin/tacctl.sh --build … --goarch <arch>`,
test knobs off, the version and commit stamped from git) and prints
`SHA256SUMS`. `RELEASE_TAG=<name>` builds trial assets from any tree and
skips the metadata check.

### 6. Sign and verify

Only the key holder signs, on the release manager's own machine, and types
the passphrase; nobody else handles the passphrase or the private key. The
release waits for the key holder here.

```sh
qargi release sign 0.2.1
```

The key holder runs it, in their own terminal; it refuses without a terminal.
In the worktree that `release assets` printed (step 5) it runs the two
commands below: `ssh-keygen -Y sign -f <key> -n tacctl-release <file>` for
each file to sign, so that the passphrase is typed on the terminal and never
passes through qargi, a log or an agent, and then `make release-verify`. It
records the result, and `release publish` (step 7) waits for that recorded
ok.

What it runs, and what to run by hand in a checkout of the tag after `make
release-assets`:

```sh
ssh-keygen -Y sign -f ~/.ssh/tacctl-release -n tacctl-release dist/release/SHA256SUMS
make release-verify
```

`ssh-keygen -Y sign` writes `dist/release/SHA256SUMS.sig`. `make
release-verify` checks what a host will check, with the committed
`release/allowed_signers`: the signature, every file against `SHA256SUMS`,
that the binary for this machine was built from `HEAD`, and, for both
binaries and without running either, that the test knobs are off and `HEAD`'s
commit is stamped in (`tests/tools/release-stamps.sh`). It must print
`Release assets in dist/release verified.` and then `Release binaries in
dist/release: test knobs off, built from <commit> (amd64 and arm64).`

`ALLOWED_SIGNERS=<file>` points `make release-verify` at another
allowed_signers file, for a trial with a throwaway key (no key, test or
otherwise, is kept in the repository):

```sh
ssh-keygen -q -t ed25519 -N '' -f /tmp/trial-key
printf 'tacctl-release namespaces="tacctl-release" %s\n' "$(cut -d' ' -f1,2 /tmp/trial-key.pub)" \
    > /tmp/trial-signers
RELEASE_TAG=trial make release-assets
ssh-keygen -Y sign -f /tmp/trial-key -n tacctl-release dist/release/SHA256SUMS
make release-verify ALLOWED_SIGNERS=/tmp/trial-signers
```

### 7. Publish

```sh
qargi release publish 0.2.1 --notes-file docs/release-notes-0.2.1.md
```

A plan, a token and the maintainer's go-ahead. Creates the GitHub release of
the tag with the four assets (the two binaries, `SHA256SUMS` and
`SHA256SUMS.sig`) in one step, and the release notes as its text. All four go together: the `release-reproducible` workflow
starts on the publish and needs the signed sums.

A release's title is always `tacctl <tag>` (`tacctl 0.2.1`), never the bare
tag; the title of a release made another way is fixed with
`gh release edit 0.2.1 --title "tacctl 0.2.1"`. To list the titles that do
not follow the rule:

```sh
gh release list --limit 100 --json tagName,name \
    --jq '.[] | select(.name != "tacctl " + .tagName) | .tagName'
```

For a release that already exists, `gh release upload 0.2.1` with the same
four files adds them (with `--clobber`, replaces them).

Once, for discoverability, set the repository topics:

```sh
gh repo edit --add-topic tacacs-plus --add-topic tacacs --add-topic radius --add-topic aaa \
    --add-topic freeradius --add-topic network-automation --add-topic cisco --add-topic junos \
    --add-topic golang
```

### 8. Reproducible

```sh
gh run list --workflow release-reproducible.yml --limit 1   # the job the publish started
gh run watch <run id>
```

Watch the run of the tag and record its URL with the step. The
`release-reproducible` workflow (`.github/workflows/release-reproducible.yml`)
starts when the release is published. On a clean runner it checks out the
tag, installs the Go version that tag's `bin/tacctl.sh` names, and runs
`tests/tools/release-reproduce.sh <tag>`:

1. downloads the published `SHA256SUMS` and `SHA256SUMS.sig`;
2. verifies the signature with the tag's own `release/allowed_signers` (the
   published sums are the signed ones; the job holds no key and no secret);
3. rebuilds both binaries with `make release-assets` and diffs the sums;
4. checks that the rebuilt binaries have the test knobs off and the tag's
   commit stamped in.

A red job means the uploaded binaries are not what a clean checkout of the
tag builds (a dirty tree, another Go, another commit): replace the assets
with a set built from the tag and signed again (`gh release upload --clobber`
with the four files). The job's artifact holds both sums files and the diff.

The same check by hand, from a clean checkout of the tag (after the upload;
exit 0 is reproducible):

```sh
git checkout 0.2.1 && make release-reproduce TAG=0.2.1
```

The workflow also runs by hand for any published tag, older releases
included (it takes the script from the branch it is run on and the build
recipe from the tag): `gh workflow run release-reproducible.yml -f tag=0.2.1`.
The workflow file must be on the default branch for that.

### 9. Check on a host

On a host that follows `master`:

```sh
sudo tacctl upgrade         # [INFO] Installing the 0.2.1 release binary (linux/amd64, verified)
tacctl version --long       # commit: the commit of the tag (git rev-parse 0.2.1^{commit}), test
                            # knobs: off
```

To verify the assets by hand anywhere:

```sh
ssh-keygen -Y verify -f /opt/tacctl/release/allowed_signers -I tacctl-release -n tacctl-release \
    -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

The fresh-install container check can then run against the published
release: `tests/containers/fresh/run.sh --release 0.2.1`.

### 10. The documentation site

The site at https://tacctl.rettware.com/ is built from the orphan
`gh-pages` branch, which has no history in common with the code and is never
merged into or from a code branch. After the release is published, sync it
on a `docs/<slug>` branch cut from `gh-pages`:

```sh
git fetch origin gh-pages
git checkout -b docs/release-0.2.1 origin/gh-pages
python3 tools/release_sync.py --from 0.2.0 --to 0.2.1   # what changed between the releases
# update the pages it names, and add the release to site/whats-new-for-operators.md
python3 tools/release_sync.py --from 0.2.0 --to 0.2.1 --finish
git add -A && git commit -am "site: tacctl 0.2.1"
git push -u origin docs/release-0.2.1
gh pr create --base gh-pages --head docs/release-0.2.1 --title "site: tacctl 0.2.1" \
    --body "Sync the site with 0.2.1"
gh pr checks --watch          # the build check; green before the merge
```

`--finish` bumps the pages' "Checked against tacctl <version>" line, runs
the checks, builds the site and renders the PDFs. The checks also run by
hand, from the top of the `gh-pages` checkout:

```sh
python3 tools/check_site.py site
python3 tools/check_commands.py site
```

Merge the pull request into `gh-pages` only once its `build` check has
passed.

### 11. Prune

```sh
qargi branch prune
qargi branch prune --remote
```

A plan, on the maintainer's go-ahead, since it deletes branches: the ones
that are merged (the release's `feature/*` and `agent/*` branches). Without
`--remote` it deletes only the local ones; run the second form, with its own
plan and go-ahead, when the branches on origin are meant to go too.

## A hotfix

A fix that cannot wait for the next release starts from `master`, not from
`develop`. `qargi release start 0.2.6 --hotfix` is the tooling's way to cut
`hotfix/0.2.6` from `master`, but it is refused for this project at present:
before it changes anything it needs content under the CHANGELOG's unreleased
heading and runs the stored preflight
(`tests/tools/release-notes-check.sh 0.2.6`, which wants
`docs/release-notes-0.2.6.md`, a numbered `## 0.2.6 (` section and `const
rollbackFrom` equal to `0.2.6`), and on `master` none of that exists before
the hotfix branch does (`release.preflight failed ... nothing was changed`).
So cut the branch by hand, and use the tooling from the push on:

```sh
git checkout master && git pull
git flow hotfix start 0.2.6          # the branch is hotfix/0.2.6
```

Commit on that branch:

- the fix;
- its CHANGELOG section, `## 0.2.6 (YYYY-MM-DD)`, dated now because `start`
  is not there to date it, numbered from 1, with the items that differ from
  the release it fixes;
- `docs/release-notes-0.2.6.md`;
- `const rollbackFrom` in `internal/cli/rollback.go` set to `0.2.6`;
- the `.TH` line of `man/tacctl.1` with the same date and `tacctl 0.2.6` (the
  `sed` of the by-hand section below).

Then check it, push it and finish it with the tooling:

```sh
tests/tools/release-preflight.sh 0.2.6
tests/tools/release-notes-check.sh 0.2.6
qargi release push 0.2.6 --hotfix
qargi release finish 0.2.6 --hotfix
```

`finish` tags `master` and merges the fix back into the release branch when
one is open, else into `develop`. Everything else is as for a release: the
same plans and go-aheads, and the after-steps 5 to 11 above (assets, sign,
publish, reproducible, check on a host, site, prune). This route has not
been exercised with the tooling yet, so read each plan before approving it.

## If the release tooling is unavailable (by hand)

A release can be made without qargi. First the gate (step 1) and the notes
check, on `develop`:

```sh
GATE_TMPFS=1 make gate-ci
tests/tools/release-notes-check.sh 0.2.1
```

Then the git-flow steps 2 to 4 by hand:

```sh
git checkout develop && git pull
git flow release start 0.2.1
sed -i 's/^## 0\.2\.1 (unreleased)$/## 0.2.1 (YYYY-MM-DD)/' CHANGELOG.md
sed -i 's/^\.TH TACCTL 1 "[^"]*" "tacctl [^"]*"/.TH TACCTL 1 "YYYY-MM-DD" "tacctl 0.2.1"/' \
    man/tacctl.1
git add docs/release-notes-0.2.1.md    # unless it is committed on develop already
git commit -am "docs: 0.2.1 release date"
git push -u origin release/0.2.1
gh pr create --base master --head release/0.2.1 --title "0.2.1" --body "Release 0.2.1"
gh pr checks --watch          # the Go tests on the release commit; all green before the tag
tests/tools/release-preflight.sh 0.2.1   # the release metadata (step 4); finish only when it passes
git flow release finish -m "Release 0.2.1" 0.2.1
git tag -f -a 0.2.1 -m "Release 0.2.1" master   # git-flow writes "Release 0.2.1 0.2.1"
git describe master                               # 0.2.1
```

The `sed` of `man/tacctl.1` sets the date and the version of its `.TH` line,
which must carry the same date and version as the CHANGELOG heading
(`tests/tools/release-preflight.sh` checks that they match).

The tag is made and checked locally (`git tag -f`) and pushed once, with the
signed assets already built from it, because a pushed tag is final. Build
the assets from the tag and sign them (steps 5 and 6), then push and
publish (step 4's pushes and step 7):

```sh
git checkout develop
git push origin develop master 0.2.1
gh release create 0.2.1 --verify-tag --title "tacctl 0.2.1" \
    --notes-file docs/release-notes-0.2.1.md \
    dist/release/tacctl-0.2.1-linux-amd64 dist/release/tacctl-0.2.1-linux-arm64 \
    dist/release/SHA256SUMS dist/release/SHA256SUMS.sig
```

The pull request closes by itself when `master` is pushed; delete the
remote branch then: `git push origin --delete release/0.2.1`. Then steps 8
to 11 as above. A host that upgrades between the push and the upload simply
builds from source (`could not download SHA256SUMS`).

A hotfix by hand: `git flow hotfix start 0.2.6` (the branch is
`hotfix/0.2.6`), the fix and its CHANGELOG section (`## 0.2.6
(unreleased)`, numbering from 1, the items that differ from the release it
fixes), then `git flow hotfix finish -m "Release 0.2.6" 0.2.6`, which tags
`master` and merges back into `develop`; the date and version in
`man/tacctl.1` and the CHANGELOG heading come before the finish, and the
rest is as above.
