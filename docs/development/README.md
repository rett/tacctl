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
  man/tacctl.1              # `man tacctl`
  patches/                  # tacquito source patch overlay (patches/README.md)
  release/allowed_signers   # the public key that signs release binaries
  docs/                     # user documentation by topic (install, server, security, hosts, devices, cli),
                            # development/ (this page), releasing.md (the release procedure and how hosts
                            # verify a release binary), radius-notes.md, release notes, plans/
  tests/                    # Go and bats suites, containers (tests/README.md)
  CHANGELOG.md
  README.md
  LICENSE
```

## Project documents

- [Release procedure](../releasing.md): branches, tags, signing and how hosts verify a release binary
- Release notes: `docs/release-notes-<version>.md`
- [Design and plans](../plans/): decisions, work packages and the backlog
- [RADIUS notes](../radius-notes.md)
- [Tests](../../tests/README.md): the Go and bats suites, fixtures and containers
