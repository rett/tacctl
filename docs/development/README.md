# Development

[Documentation](../README.md)

## Project Structure

```
tacctl/
  bin/
    tacctl.sh               # bootstrap: installs Go if needed, builds the binary, runs it
  cmd/tacctl/               # main package
  internal/                 # the implementation: cli, store, model, conf, render, devices, hosts,
                            # lifecycle, backend (and backend/tacacs, backend/radius), ...
  vendor/                   # vendored Go dependencies (builds need no network)
  go.mod, go.sum            # dependencies: github.com/spf13/cobra (with spf13/pflag and
                            # inconshreveable/mousetrap), golang.org/x/crypto (bcrypt, ssh),
                            # golang.org/x/sys, golang.org/x/term, gopkg.in/yaml.v3
  config/
    backends/tacacs/
      tacquito.yaml         # Reference layout of the rendered TACACS+ config
      tacquito.service      # Systemd unit (the default listener)
      tacquito@.service     # Template unit (further listeners)
      tacquito.logrotate    # Log rotation (daily, 90-day retention)
    templates/              # Device config templates: cisco, cisco-legacy, juniper, wti,
                            # and cisco-radius, juniper-radius, wti-radius for --protocol radius
    linux/                  # client-install.sh, client-remove.sh (Linux host enrollment)
  .github/workflows/        # test.yml: the Go tests (internal/cli in two shards);
                            # release-reproducible.yml: rebuilds each published release and compares
  man/tacctl.1              # `man tacctl`
  patches/                  # tacquito source patch overlay (patches/README.md)
  release/allowed_signers   # the public key that signs release binaries
  docs/                     # user documentation by topic (install, server, security, hosts,
                            # devices, cli),
                            # development/ (this page), releasing.md (the release procedure and how
                            # hosts
                            # verify a release binary), radius-notes.md, release notes, plans/
  tests/                    # Go and bats suites, containers (tests/README.md)
  CHANGELOG.md
  README.md
  LICENSE
```

## Working rules

- Model routing: Opus reviews, Sonnet and Haiku implement, Fable decides
  important design questions. Subagents never commit; the coordinator
  reviews, merges, renumbers CHANGELOG items and commits.
- Commit when appropriate (a coherent unit of work that has passed its
  gates); ask before pushing, and push only the branch being worked on;
  merges into `develop` and `master`, tags and releases only when the
  user says so. No Claude attribution in commit messages.
- No private names (hosts, addresses, users, home paths, domains) and no
  description of any installation's state, deployment or log collector in
  repo files or commit messages; examples follow § Examples.
- Never act against the production host and never connect to a
  production device: prepare the files and let the user apply them.
- Every user-visible change gets a numbered CHANGELOG item and updates
  `man/tacctl.1` and the matching `docs/` page in the same change.
- No secret, hash, password or community string in any log line, test
  golden or doc example.
- Gates: build, gofmt, `go vet`, `make lint`, Go tests (`make gate-go`,
  which runs `internal/cli` under `setsid` with no stdin and ends with one
  `GATE-GO PASS|FAIL` line: start it with the Bash tool's
  `run_in_background`, never with a trailing `&` or a `pgrep -f` wait, and
  count only that line), bats as the invoking user, the diff corpus
  against the previous release, the container matrix, `groff -k -ww`; the
  `test` workflow on the pull request. Tests sandbox host paths, and a
  test must not read a path of the machine it runs on. A test that needs
  the process environment, the lock wait or a package-wide registry calls
  `serial(t)` first; the others run in parallel (`hooks_test.go`).
- A release: `docs/releasing.md`. The release branch is pushed and a pull
  request opened to `master` so the Go tests run before the tag;
  `release-reproducible` runs on the tag by `workflow_dispatch`.
- Plans are pruned once implemented: a plan, handoff, lab sheet or spike
  of a released version is deleted in the release that ships it (its
  decisions are in the CHANGELOG, the docs and git; the code cites them
  by number and file name, which `git show <tag>:docs/plans/<file>`
  reads). `docs/plans/` keeps the backlog, what is deferred and the plan
  of the release in progress.

## Examples

Every example in the repository (docs, man page, help text, CHANGELOG, test
fixtures, commit messages) uses the values below and nothing else, so that
no example can be mistaken for, or traced to, a real installation. A value
that is not in the table is invented in the same style, never copied.

| Kind | Use |
| --- | --- |
| Domain | `example.net`; `example.org` when a second one is needed |
| Hosts | role plus number: `sw1`, `rtr1`, `fw1`, `core1`, `web1`, as `sw1.example.net`; a Junos switch `jsw1` where a test needs both vendors |
| Servers | `tacacs.example.net`, `ntp.example.net`, `dns.example.net`, `nms.example.net` |
| Users | `alice`, `bob`, `carol`, `dave`; the roles `admin` and `operator`; mail `alice@example.net` |
| IPv4 | RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; private-use `10.0.0.0/8` |
| IPv6 | RFC 3849: `2001:db8::/32` |
| AS numbers | RFC 5398: `64496`-`64511` |
| MAC addresses | `00:00:5e:00:53:xx` |
| Time zones | `UTC` (`2026-10-12T13:11Z`, `12:18:03 UTC`); another zone only where the behavior under test depends on it, and then `CET` |
| Locations | `Rack 4, DC1`, `Lab rack 2`, `Example City, Example State` |
| Contacts | `NOC <noc@example.net>` |
| SNMP | v2c community `example-ro`; v3 user `monitor`; `sysName` the example host name; `sysLocation` and `sysContact` as above |
| Secrets | plainly fake: `example-secret`, `example-passphrase`; never a value that was ever real, and no hash or key copied from a device |
| Serial numbers | `SN000001`, `SN000002` |
| Device classes, groups, scopes | `ops-rw`, `ops-ro`, `site-a`, `lab` |
| Paths | `/home/user/`, never a real home directory |

Output pasted from a real device, as a test fixture or an example, is
scrubbed first: the host name, users and class names, time zone, serial
numbers, addresses, locations, contacts, comments, banners and every SNMP
value are replaced from the table; what the parser reads (model, release
line, layout, spacing) stays as the device printed it. Model names and
releases are facts about a product and stay.

`tacctl device support-bundle` writes these values for the text it collects
(docs/devices/support-bundle.md).

`make lint` runs `tests/tools/no-private.sh`, which catches home paths and
mail addresses under real domains, and the patterns in
`~/.config/tacctl/private-patterns`; it cannot tell a real host name from an
example, so the table is checked in review.

## Project documents

- [Release procedure](../releasing.md): branches, tags, signing and how hosts verify a release binary
- Release notes: `docs/release-notes-<version>.md`
- [Backlog and plans](../plans/): the roadmap, deferred work and the plan of the release in progress
- [RADIUS notes](../radius-notes.md)
- [Tests](../../tests/README.md): the Go and bats suites, fixtures and containers
