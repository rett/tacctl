# Releasing tacctl

A release is a tag on `master` plus four GitHub release assets, built and
signed on the release manager's own machine; a workflow then rebuilds them
independently and compares (step 4):

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

The example is 0.2.1; replace it throughout.

### 1. The release branch, the dates, the tag

```sh
git checkout develop && git pull
git flow release start 0.2.1
sed -i 's/^## 0\.2\.1 (unreleased)$/## 0.2.1 (YYYY-MM-DD)/' CHANGELOG.md
# man/tacctl.1's .TH date and version, as in earlier releases
git commit -am "docs: 0.2.1 release date"
git flow release finish -m "Release 0.2.1" 0.2.1
git tag -f -a 0.2.1 -m "Release 0.2.1" master   # git-flow writes "Release 0.2.1 0.2.1"
git describe master                               # 0.2.1
```

### 2. Build the assets from the tag

```sh
git checkout 0.2.1          # a clean checkout of exactly the tag
make release-assets         # dist/release/tacctl-0.2.1-linux-{amd64,arm64} and SHA256SUMS
```

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

### 3. Sign and verify

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

### 4. Push and publish

```sh
git checkout develop
git push origin develop master 0.2.1
gh release create 0.2.1 --verify-tag --title "tacctl 0.2.1" \
    --notes-file docs/release-notes-0.2.1.md \
    dist/release/tacctl-0.2.1-linux-amd64 dist/release/tacctl-0.2.1-linux-arm64 \
    dist/release/SHA256SUMS dist/release/SHA256SUMS.sig
gh run list --workflow release-reproducible.yml --limit 1   # the job the publish started
gh run watch <run id>
```

The `release-reproducible` workflow
(`.github/workflows/release-reproducible.yml`) starts when the release is
published. On a clean runner it checks out the tag, installs the Go version
that tag's `bin/tacctl.sh` names, and runs
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

Once, for discoverability, set the repository topics:

```sh
gh repo edit --add-topic tacacs-plus --add-topic tacacs --add-topic radius --add-topic aaa \
    --add-topic freeradius --add-topic network-automation --add-topic cisco --add-topic junos \
    --add-topic golang
```

A release's title is always `tacctl <tag>` (`tacctl 0.2.1`), never the bare
tag; the title of a release made another way is fixed with
`gh release edit 0.2.1 --title "tacctl 0.2.1"`. To list the titles that do
not follow the rule:

```sh
gh release list --limit 100 --json tagName,name \
    --jq '.[] | select(.name != "tacctl " + .tagName) | .tagName'
```

(For a release that already exists: `gh release upload 0.2.1` with the same
four files.) A host that upgrades between the push and the upload simply
builds from source (`could not download SHA256SUMS`).

### 5. Check on a host

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

## A hotfix

A fix that cannot wait for the next release starts from `master`, not from
`develop`: `git flow hotfix start 0.2.6` (the branch is `hotfix/0.2.6`), the
fix and its CHANGELOG section (`## 0.2.6 (unreleased)`, numbering from 1, the
items that differ from the release it fixes), then `git flow hotfix finish -m
"Release 0.2.6" 0.2.6`, which tags `master` and merges back into `develop`.
Everything else is as for a release: the date and version in `man/tacctl.1`
and the CHANGELOG heading before the finish, and steps 2 to 5 above.
