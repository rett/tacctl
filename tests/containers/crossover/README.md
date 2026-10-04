# Cross-over rehearsal (bash 0.1.x -> Go 0.2.0)

Rootless podman with systemd, local containers only; nothing on the host is
touched outside podman and this directory. Used by WP3.3d (passed
2026-10-03) and as the dry run for WP5.1 (docs/plans/go-rewrite.md §6.4).

1. `./build-image.sh` — `localhost/tacctl-rehearsal:noble` (ubuntu:noble,
   systemd, the packages a server has before tacctl).
2. `git clone --bare /home/user/tacctl tacctl.git` — the scratch clone the
   containers fetch from (`url.insteadOf`, set inside each container only).
3. `./make-branch.sh <tree> [<base-branch>]` — pushes `go-rehearsal` (the Go
   tree) into the scratch clone.
4. `./rehearse.sh install` — the bash release from its tag via the README
   one-liner, committed as `localhost/tacctl-rehearsal:installed-0.1.17`.
   0.1.17 needs Go pre-placed (its go.dev checksum URL is broken; 0.1.18
   fixes it).
5. `./rehearse.sh cross local|new` — `tacctl upgrade --branch go-rehearsal`
   with the branch pre-created in the clone or not; then `version --long`, a
   second upgrade (must be a no-op), and `upgrade --branch master` back to
   bash.
6. `./rehearse.sh fresh` — 0.2.0 from scratch through the shim.

Logs go to `./logs/`; `tacctl.git`, `work/` and `logs/` are not committed.
