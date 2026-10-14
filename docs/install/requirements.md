# Requirements and how tacctl is built

[Documentation](../README.md) › [Installation and upgrades](README.md)

A server needs `git` and `wget`; everything else is installed by tacctl. tacctl is a single Go binary, `/usr/local/bin/tacctl`, **built on the server** from the clone in `/opt/tacctl`: the dependencies are vendored in the clone, so building needs no network and no module proxy. `/opt/tacctl/bin/tacctl.sh` is the bootstrap: it installs the Go toolchain (`/usr/local/go`) when it is missing, after verifying the download against its published SHA-256, builds the binary when it is missing or out of date, and runs it. The first build compiles the standard library and the dependencies (about 15 seconds on an eight-core machine, about 130 MB in root's Go build cache, `/root/.cache/go-build`); later builds reuse the cache. `tacctl version` prints the installed version; `--long` adds the commit, build date and Go version:

```bash
tacctl version          # tacctl <version>
tacctl version --long   # adds the commit, the build date, the Go version and "test knobs: off"
```

`install` and `upgrade` say `Building /usr/local/bin/tacctl from /opt/tacctl...` whenever they build, so the installed binary always matches the commit of the clone.

When the clone is at a release tag (as `master` is right after a release), the bootstrap downloads that release's binary for the host (linux/amd64 or linux/arm64) instead of building it, and installs it only if its `SHA256SUMS` carries a valid signature by the key in `/opt/tacctl/release/allowed_signers` (`ssh-keygen -Y verify`, from `openssh-client`), its checksum matches and it was built from the clone's commit: `Installing the <tag> release binary (linux/amd64, verified)`; otherwise it says `Release binary for <tag> not used (<reason>); building from source.` and builds as above. To check the release assets by hand: `ssh-keygen -Y verify -f /opt/tacctl/release/allowed_signers -I tacctl-release -n tacctl-release -s SHA256SUMS.sig < SHA256SUMS`, then `sha256sum -c --ignore-missing SHA256SUMS` (see the [release procedure](../releasing.md)). Passwords, YAML, rendering and checksums are handled inside the binary; no helper program (Python, OpenSSL) is needed on the server.
