#!/bin/bash
# make-branch.sh <tree> [<base-branch>]: the rehearsal branch 'go-rehearsal'
# in the scratch bare clone ./tacctl.git: <tree> (a checkout of the Go
# rewrite, committed or not) on top of <base-branch> of that clone
# (default feature/go-rewrite). Nothing in the real repository is touched.
# Make the bare clone first: git clone --bare /home/user/tacctl tacctl.git
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WT="$(cd "${1:?usage: make-branch.sh <tree> [<base-branch>]}" && pwd)"
BASE_BRANCH="${2:-feature/go-rewrite}"
rm -rf "${HERE}/work"
git clone -q "${HERE}/tacctl.git" "${HERE}/work"
cd "${HERE}/work"
git checkout -q -B go-rehearsal "origin/${BASE_BRANCH}"
rsync -a --delete --exclude /.git --exclude /dist --exclude /tests/bats --exclude /coverage "${WT}/" "${HERE}/work/"
git add -A
git -c user.name="tacctl rehearsal" -c user.email="rehearsal@localhost" commit -q -m "rehearsal: the Go tree"
git push -q -f origin go-rehearsal
git log --oneline -1
git -C "${HERE}/tacctl.git" rev-parse go-rehearsal
