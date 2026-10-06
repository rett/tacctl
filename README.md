# tacctl

Management toolkit for network-device AAA. Users, groups and scopes are kept once, in tacctl's own store, and served over **TACACS+** by [tacquito](https://github.com/facebookincubator/tacquito) (RFC 8907, by Facebook Incubator) and, when enabled, over **RADIUS** by a tacctl-owned FreeRADIUS instance. Provides a CLI for user, group, and configuration management with multi-vendor support for Cisco IOS/IOS-XE and Juniper Junos devices, plus WTI console servers and Linux hosts. A device registry names the devices that authenticate here, shows which of them have been seen, and opens ssh sessions to them by name.

## Quick Start

```bash
# Install on a new server (TACACS+; RADIUS is added later, if wanted)
sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl && /opt/tacctl/bin/tacctl.sh install'

# Or upgrade an existing server (pulls latest from GitHub, rebuilds tacctl if needed)
tacctl upgrade

# Fresh installs seed four built-ins: engineer/superuser, operator/operator,
# viewer/readonly (all disabled — set a password to activate), plus
# root/readonly as a permanent accounting-only sink (Junos internal daemons
# emit accounting packets as root; tacctl user passwd root is rejected).
tacctl user passwd engineer

# Or add your own (lands in the default 'lab' scope)
tacctl user add jsmith superuser

# Create a production scope and grant jsmith access to it
tacctl scope add prod --prefixes 10.10.0.0/16 --secret generate
tacctl user scope jsmith add prod

# Manage users
tacctl user list

# Show device configs with your server's IP and scope-specific secret pre-filled
tacctl config cisco                   # default scope
tacctl config cisco --scope prod      # specific scope
tacctl config cisco --scope prod --legacy   # legacy IOS 12.x syntax (pre-15.0 devices)
tacctl config juniper --scope prod
tacctl config wti --scope prod        # WTI console server: serial-menu walkthrough

# Serve the same users over RADIUS as well
tacctl backend enable radius
tacctl scope vendor-attrs prod enable cisco,juniper   # RADIUS sends a vendor's privilege attribute only where a scope opts in
tacctl config cisco --scope prod --protocol radius
tacctl config juniper --scope prod --protocol radius
tacctl config wti --scope prod --protocol radius      # not verified on a unit

# Name your devices, then connect to them by name (see "Connecting to Devices by Name")
tacctl device add core-sw1 10.10.0.1 --vendor cisco
tacctl ssh core-sw1

# Work from a prompt instead of retyping "tacctl"
tacctl shell
```

### Requirements and how tacctl is built

A server needs `git` and `wget`; everything else is installed by tacctl. tacctl is a single Go binary, `/usr/local/bin/tacctl`, **built on the server** from the clone in `/opt/tacctl`: the dependencies are vendored in the clone, so building needs no network and no module proxy. `/opt/tacctl/bin/tacctl.sh` is the bootstrap: it installs the Go toolchain (`/usr/local/go`) when it is missing, after verifying the download against its published SHA-256, builds the binary when it is missing or out of date, and runs it. The first build compiles the standard library and the dependencies (about 15 seconds on an eight-core machine, about 130 MB in root's Go build cache, `/root/.cache/go-build`); later builds reuse the cache. `tacctl version --long` shows the commit, build date and Go version of the installed binary:

```bash
tacctl version          # tacctl 0.2.0
tacctl version --long   # adds the commit, the build date, the Go version and "test knobs: off"
```

`install` and `upgrade` say `Building /usr/local/bin/tacctl from /opt/tacctl...` whenever they build, so the installed binary always matches the commit of the clone.

When the clone is at a release tag (as `master` is right after a release), the bootstrap downloads that release's binary for the host (linux/amd64 or linux/arm64) instead of building it, and installs it only if its `SHA256SUMS` carries a valid signature by the key in `/opt/tacctl/release/allowed_signers` (`ssh-keygen -Y verify`, from `openssh-client`), its checksum matches and it was built from the clone's commit: `Installing the <tag> release binary (linux/amd64, verified)`; otherwise it says `Release binary for <tag> not used (<reason>); building from source.` and builds as above. To check the release assets by hand: `ssh-keygen -Y verify -f /opt/tacctl/release/allowed_signers -I tacctl-release -n tacctl-release -s SHA256SUMS.sig < SHA256SUMS`, then `sha256sum -c --ignore-missing SHA256SUMS` ([docs/releasing.md](docs/releasing.md)). Passwords, YAML, rendering and checksums are handled inside the binary; no helper program (Python, OpenSSL) is needed on the server.

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
                            # inconshreveable/mousetrap), golang.org/x/crypto (bcrypt),
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
  docs/                     # releasing.md (the release procedure and how hosts verify a release binary),
                            # radius-notes.md (what was verified against real FreeRADIUS and pam_radius_auth),
                            # release notes
  tests/                    # Go and bats suites, containers (tests/README.md)
  CHANGELOG.md
  README.md
  LICENSE
```

## Backends

A backend is a daemon that serves the store over one protocol. tacctl has two:

| ID | Protocol | Implementation | Installed by |
|---|---|---|---|
| `tacacs` | TACACS+ | tacquito, built from source | `tacctl install` (always) |
| `radius` | RADIUS | FreeRADIUS, the distribution's package, run as tacctl's own instance | `tacctl backend enable radius` (opt-in) |

TACACS+ over TLS is reserved, not implemented: a listener's `tls` block is part of the `tacctl.yaml` schema, and `tls.enabled: true` is rejected as "reserved for a future release".

```
tacctl backend list             # protocol, implementation, installed, enabled, service state
tacctl backend status [<id>]    # state, uptime, PID, and each listener: unit state, whether something listens
tacctl backend enable <id> [-y] # install if needed, render, enable at boot, start
tacctl backend disable <id> [-y]
```

Which backends are enabled is `backends.enabled` in `tacctl.yaml` (default: `[tacacs]`). Every command that changes users, groups, scopes or filters renders the config of **every** enabled backend from the store, all of them or none, and restarts only the backends whose files changed.

- `backend enable <id>` installs the backend if it is not installed (asking first; `-y` skips), checks every backend's rendered files for hand edits, takes a snapshot, adds the id to `backends.enabled`, renders, then enables and starts the service, which must come up. Any failure puts `tacctl.yaml`, the store and every rendered file back and stops the service; software the install step put on the machine stays.
- `backend disable <id>` stops the service and disables it at boot (asking first; `-y` skips). Its package and rendered files stay, and are no longer rendered or reported as drift; `backend enable` brings it back. Disabling the last enabled backend is refused, and so is disabling `tacacs` in legacy read-only mode.
- Commands need the store (`/etc/tacctl/store.yaml`), or, on an install from before the store, its `tacquito.yaml`; with neither they stop with `Config not found … Is tacctl installed?`. `tacquito.yaml` is the `tacacs` backend's file, rendered from the store: a RADIUS-only install has none and runs every command without it. With `tacacs` enabled and `tacquito.yaml` missing, commands run and warn; `tacctl config render` (or any change) writes it again.
- With more than one backend enabled, `tacctl status`, `tacctl config validate`, `tacctl config show` and `tacctl log …` print one labelled section per backend (`== Backend: radius (radius, freeradius) ==`); `log` takes `--backend <id>` to show one. With only `tacacs` enabled the output is laid out as before.
- `backend list` and `backend status` are open to the read-only and operator tiers; `enable` and `disable` are superuser-only.

### Listeners

How each backend listens is `listeners.<backend>.<name>` in `tacctl.yaml` (`network`, `address`, and for RADIUS `role: auth|acct`), set with `tacctl config listen`:

| Backend | Built-in listeners | Networks |
|---|---|---|
| `tacacs` | `default`: `tcp :49` | `tcp`, `tcp6` |
| `radius` | `auth`: `udp :1812`, `acct`: `udp :1813` | `udp`, `udp6` |

```
tacctl config listen tcp 10.1.0.1:49                                     # TACACS+ default listener
tacctl config listen --listener mgmt tcp 10.1.0.1:4949                   # a second TACACS+ listener
tacctl config listen --listener mgmt reset                               # remove it
tacctl config listen --backend radius show
tacctl config listen --backend radius --listener auth udp 10.1.0.1:1812
```

The TACACS+ default listener stays in `tacquito.service`; every further one is an instance `tacquito@<name>.service` of the template `tacquito@.service`, `PartOf=` and `WantedBy=` `tacquito.service`, so `systemctl stop|start|restart tacquito` covers them all and `journalctl -u tacquito` shows the default one. Each unit gets a rendered drop-in `<unit>.d/tacctl.conf` (listen address, log level, metrics address, accounting log); a listener's accounting goes to `/var/log/tacquito/accounting-<name>.log`. RADIUS listeners become `listen {}` sections of tacctl's FreeRADIUS configuration. `listen`, `loglevel` and `metrics` restart the unit and put `tacctl.yaml` and the drop-ins back if it does not stay up. `config loglevel` and `config metrics` are TACACS+ settings (`backends.tacacs.level`, `backends.tacacs.metrics_address`).

## The store and generated configs

| File | Role |
|---|---|
| `/etc/tacctl/store.yaml` | **Canonical**: users (group, scopes, bcrypt hash, disabled, password date), groups (priv-lvl, Juniper class), scopes (prefixes, secret, `protocols`, `vendor_attrs`, `devices`), connection filters. 0600 root. `tacctl store show` prints it (superuser-only: it holds secrets and hashes). |
| `/etc/tacctl/tacctl.yaml` | **Canonical** tunables and settings: per-group command rules and priv-exec mappings, per-scope device-config settings, listeners, `backends.enabled`. Only keys you changed (see [Configuration tunables](#configuration-tunables--tacctlyaml)). |
| `/etc/tacquito/tacquito.yaml`, the unit drop-ins | **Generated** for TACACS+. |
| `<raddb>/tacctl-radius.conf`, `tacctl-radius.users`, `tacctl-radius-dictionary/dictionary` | **Generated** for RADIUS. |
| `/etc/tacctl/rendered.json` | The checksum of every generated file. |

Every change goes one way: check that no generated file was edited by hand → snapshot → write the store (and `tacctl.yaml`) → render every enabled backend into a staging area and prove it (read back, the daemon's own config check) → replace the files → restart the backends whose files changed. If any step fails, the store, `tacctl.yaml` and every generated file are put back.

- **Drift.** A generated file whose checksum no longer matches was edited by hand. `tacctl status` and `tacctl config validate` show a red `DRIFT` line, and every change is refused (exit 3) rather than overwrite it. To keep a hand edit of `tacquito.yaml`: `tacctl store import --replace`, then `tacctl config render --force`. To discard it: `tacctl config render --force` (the edited file is kept under `/etc/tacctl/backups/legacy/` first). RADIUS files cannot be adopted, only re-rendered.
- **`tacctl config render [--force]`** regenerates every enabled backend's files from the store and restarts the ones that changed; needed after restoring files by hand or when `config validate` says a file is missing or out of date. **`tacctl config render --dry-run --out <dir>`** renders the same artifacts into a new, empty directory at their live paths (`<dir>/etc/tacquito/tacquito.yaml`, ...) and touches nothing else: no render record, no restart. The directory is private to root, since the artifacts hold secrets.
- **`tacctl store import [--check|--force] [--replace] [<file>]`** reads an old-style `tacquito.yaml` (default: the live one) into the store. `--check` writes nothing: it imports, renders, compares what tacquito would load from both files (users, groups and their services and command rules, the prefix-to-secret routing in order, filters) and load-tests the rendered file with the tacquito binary on a loopback port; it prints `EQUIVALENT` or the differences. Content the store cannot represent (other services, other authenticators or accounters, unknown keys, …) fails the import and is listed; `--force` drops it. `--replace` overwrites an existing store.
- **Legacy read-only mode.** Without a store (an upgrade whose gate stopped, or after `store rollback`) tacctl reads `tacquito.yaml` directly: every read command works, every command that would change users, groups, scopes or filters is refused with `store not initialised — review 'tacctl store import --check' and run 'tacctl store import [--force]'`. Only TACACS+ exists in this mode; `backend enable` needs a store.
- **`tacctl store rollback`** undoes the move into the store: it restores the pre-store `tacquito.yaml` (`/etc/tacctl/backups/legacy/tacquito.yaml.pre-store.<timestamp>`), removes the store and `rendered.json`, and restarts tacquito: legacy read-only mode under the new code. Refused while another backend is enabled (disable it first).
- **Snapshots**: see [Backup Commands](#backup-commands--tacctl-backup).

## System Files

**tacctl**

| File | Purpose |
|------|---------|
| `/etc/tacctl/` | State directory (0700 root) |
| `/etc/tacctl/store.yaml` | Users, groups, scopes, filters (0600) |
| `/etc/tacctl/tacctl.yaml` | Operator overrides — only keys you've changed. Absent keys inherit from the canonical defaults built into tacctl. Inspect with `tacctl config dump`; list canonical defaults with `tacctl config defaults`. |
| `/etc/tacctl/rendered.json` | Checksums of the generated files (drift detection) |
| `/etc/tacctl/backups/` | Snapshots (`<timestamp>/`), `legacy/` (old-style backups, pre-store config, displaced files), `password-dates/` (read by the importer) |
| `/etc/tacctl/templates/` | Device config templates: a copy of each shipped one, which you may customize (a file here overrides the built-in one); `.shipped.sha256` is the manifest of what tacctl wrote there, `<name>.template.new` is a new release's version beside a template you customized (see [Custom Templates](#custom-templates)) |
| `/etc/tacctl/devices.yaml` | The device registry (`tacctl device`): names, addresses and settings of the network devices; 0600 root, absent means none. Snapshots include it |
| `/etc/tacctl/console.yaml` | The login console's settings (`tacctl console`): per-tier switches, per-user overrides, idle timeout, system shell; 0600 root, absent means the defaults (the console on for every tier). Snapshots include it |
| `/etc/tacctl/linux-hosts`, `/etc/tacctl/linux-uids` | Enrolled Linux hosts; the UID each user gets on every host |
| `/var/lib/tacctl/` | tacctl's variable data; 0711 (every user may pass through, only root may list it) |
| `/var/lib/tacctl/ssh/known_hosts` | Generated from the pinned host keys in `devices.yaml` on every registry write; 0644 root in a 0755 directory, so every user's ssh reads it (`/etc/tacctl` is root's alone). Do not edit |
| `/var/lib/tacctl/devices-seen.json` | The seen cache of `tacctl device scan`: what the logs showed of each device address, where each backend's next scan resumes, the last host-key re-scans; 0600 root, derived, not snapshotted |
| `/var/lib/tacctl/linux/` | pam_tacplus source tarball and container-built modules |
| `/etc/sudoers.d/tacctl`, `/etc/sudoers.d/tacctl-tiers` | Optional sudoers rules (`tacctl config sudoers install`, `… tiers install`) |
| `/usr/local/bin/tacctl` | The tacctl binary, built on the server from `/opt/tacctl` by `install` and `upgrade` |
| `/usr/local/bin/tacctl-console` | The login console: a symlink to the binary, made by `install` and refreshed by `upgrade` (see [Login console](#login-console)) |
| `/etc/ssh/sshd_config.d/tacctl-console.conf` | sshd's drop-in for the members of `tac-console` (the console users): the console forced, no forwarding (X11 and TCP ports for the tiers of `console forwarding tiers`, superusers by default), no key logins. Written by `host sync` of this server or `tacctl console install`, checked with `sshd -t`, refreshed by `upgrade`; do not edit |
| `/etc/shells` | Gets the line `/usr/local/bin/tacctl-console` while any account may have the console; `console remove` and `uninstall` take it out again |
| `/opt/tacctl/` | Git clone of this repo: what the binary is built from, and what `upgrade` pulls. Holds the shipped templates, units, patches and man page |
| `/opt/tacctl/bin/tacctl.sh` | Bootstrap: installs Go if needed, builds the binary when it is missing or out of date, runs it |
| `/etc/bash_completion.d/tacctl`, `/usr/share/man/man1/tacctl.1.gz` | Completion (bash, generated by `tacctl completion bash`), man page |
| `/usr/local/go/` | The Go toolchain tacctl builds with (installed once, never replaced by an older one) |

**TACACS+ (tacquito)**

| File | Purpose |
|------|---------|
| `/etc/tacquito/tacquito.yaml` | Server configuration, generated from the store (0640 `tacquito:tacquito`) |
| `/etc/systemd/system/tacquito.service` | Systemd unit file (the default listener) |
| `/etc/systemd/system/tacquito@.service` | Template unit: one instance `tacquito@<name>` per further listener |
| `/etc/systemd/system/tacquito.service.d/tacctl.conf` | Drop-in with the listen address, log level, metrics address and accounting log, rendered from `tacctl.yaml`; do not edit (own unit settings go in another `.conf` file there). Instances have `tacquito@<name>.service.d/tacctl.conf` |
| `/var/log/tacquito/accounting.log` | Accounting records (`accounting-<name>.log` per further listener) |
| `/etc/logrotate.d/tacquito` | Log rotation |
| `/usr/local/bin/tacquito`, `/usr/local/bin/tacquito-hashgen` | Server binary, password hash generator |
| `/opt/tacquito-src/` | Tacquito server source code |

`/etc/tacquito/` also holds a copy of this README, and the old locations of `tacctl.yaml`, `linux-hosts`, `linux-uids`, `backups/` and `templates/` lead into `/etc/tacctl/`.

**RADIUS (FreeRADIUS)**, where enabled. `<raddb>` is `/etc/freeradius/3.0` on Debian/Ubuntu and `/etc/raddb` on the RHEL family; the unit is `freeradius.service` or `radiusd.service`, the logs are in `/var/log/freeradius` or `/var/log/radius`.

| File | Purpose |
|------|---------|
| `<raddb>/tacctl-radius.conf` | tacctl's complete FreeRADIUS configuration: listeners, one client per scope prefix, policy (generated, 0640 `root:<daemon group>`) |
| `<raddb>/tacctl-radius.users` | One entry per (user, scope) with the bcrypt hash (generated, same mode) |
| `<raddb>/tacctl-radius-dictionary/dictionary` | The package's dictionary plus the WTI vendor and tacctl's internal attributes (generated) |
| `/etc/systemd/system/<unit>.d/tacctl.conf` | Drop-in that starts the daemon as `-n tacctl-radius -D <dictionary dir>`; present exactly while the backend is enabled |
| `/etc/logrotate.d/tacctl-radius` | Log rotation |
| `<logs>/tacctl-auth.log` | One line per Access-Accept and Access-Reject (read by `status`, `log`, `user show`) |
| `<logs>/tacctl-accounting.log`, `<logs>/tacctl-radius.log` | Accounting detail records; the daemon's log |

No file the FreeRADIUS package installed is edited, moved or unlinked.

## Important Notes

- **IPv4 by default:** TACACS+ listens on IPv4 only (`tcp`), RADIUS on `udp`. Switching a listener to `tcp6`/`udp6` enables dual-stack, so IPv4 clients connect with mapped addresses (e.g., `::ffff:10.1.0.1`) that do not match IPv4 prefix rules — effectively bypassing prefix-based access control. Use `tacctl config listen tcp6 [::]:49` only if you also add IPv6 prefix rules; the command prompts for confirmation first.
- **Shared secrets:** Use hex-only secrets (`openssl rand -hex 16`) to avoid quoting issues on devices. A scope's secret is shared by TACACS+ and RADIUS.
- **Juniper template users are required:** Every `local-user-name` value (`RO-CLASS`, `OP-CLASS`, `RW-CLASS`) must have a matching local user on each Juniper device. Without this, authentication succeeds but Junos rejects the login.
- **Config edits:** Generated files are overwritten by tacctl and a hand edit blocks every change until it is resolved (see [Drift](#the-store-and-generated-configs)). Use tacctl commands; `tacctl` handles service restarts.

## Security Best Practices

### Bind to a specific interface
The default listener is `-address :49` (all interfaces). Change it to your management IP:
```
tacctl config listen tcp 10.1.0.1:49
tacctl config listen --backend radius --listener auth udp 10.1.0.1:1812    # and the RADIUS ones, where enabled
tacctl config listen --backend radius --listener acct udp 10.1.0.1:1813
```
The settings live in `tacctl.yaml` (`listeners.<backend>.<name>`), from which tacctl renders the units' systemd drop-ins, so they survive `tacctl upgrade`. Use `tacctl config listen show` to inspect, or `tacctl config listen reset` to revert to the default. More listeners: [Listeners](#listeners).

### Scopes (environment isolation)
A **scope** is a named bundle of `(client CIDR prefixes, shared secret)`. Each user carries a list of scope names; authentication succeeds only when the scope the client IP falls inside is in the user's scope list. Scopes let you run multiple environments (prod, lab, edge) off a single server with distinct secrets and tight device-class boundaries. A scope is served by every enabled backend unless its `protocols` filter says otherwise (`tacctl scope protocols prod set tacacs`).

Fresh installs ship with a single scope named **`lab`** (least-privilege default). An operator who runs `tacctl user add alice operator` without thinking about scopes gets a user that can only authenticate on lab devices — production access must be granted explicitly.

**Overlapping prefixes across scopes are supported.** A narrow lab subnet can live inside a broader production scope's address space; the most specific prefix wins (tacctl emits one `secrets:` entry per (scope, prefix) pair, globally sorted by specificity, so tacquito's first-match provider walk picks the narrowest scope; FreeRADIUS matches clients by longest prefix). The one-CIDR-per-scope invariant is still enforced: no two scopes can claim the same exact prefix.

Example multi-environment setup (broader prod with narrower lab and sandbox carved out):
```
tacctl scope add prod_dc_east  --prefixes 10.10.0.0/16      --secret generate
tacctl scope add prod_dc_west  --prefixes 10.20.0.0/16      --secret generate
tacctl scope add corp_campus   --prefixes 172.20.0.0/16     --secret generate
tacctl scope add lab_east      --prefixes 10.10.99.0/24     --secret generate   # carved from prod_dc_east
tacctl scope add sandbox       --prefixes 10.10.200.0/23    --secret generate   # carved from prod_dc_east

tacctl scope default prod_dc_east                  # optional: new users land in prod by default
tacctl user add alice superuser --scopes prod_dc_east,prod_dc_west
tacctl user add dev1 superuser  --scopes sandbox,lab_east    # no prod access

tacctl scope lookup 10.10.99.7                     # -> lab_east (shadowed by prod_dc_east, lab)
tacctl scope lookup 10.10.1.5                      # -> prod_dc_east (shadowed by lab)
```

Emit per-scope device configs:
```
tacctl config cisco --scope prod_dc_east            # prod's secret + header mentions sibling scopes
tacctl config juniper --scope lab_east
```

Scope management commands:
```
tacctl scope list                              # name, prefix list, user count, default marker
tacctl scope show <name>                       # full detail + secret length/posture (not its value) + users + default-ness
tacctl scope add <name> --prefixes <cidrs>     # --secret <v> | --secret generate | --protocols | --vendor-attrs | --default
tacctl scope remove <name> [--force]           # refuses if users reference it; --force strips them
tacctl scope rename <old> <new>                # rewrites user refs, default marker and per-scope settings
tacctl scope default [<name>]                  # show / set the default
tacctl scope lookup <ip|cidr>                  # trace which scope owns an address (+ shadow overlaps)
tacctl scope prefixes <name> list|add <cidrs>|remove <cidrs>|remove --all [--force]
tacctl scope secret <name>   show|set <v>|generate
tacctl scope protocols <name> list|set <csv>|clear
tacctl user scope <user>     list|add <s>|remove <s>|replace <s>|remove --all
```

### Configure connection filters
Use allow/deny lists for additional IP-level filtering (enforced by every backend; a filtered client gets no answer):
```
tacctl config allow add 10.1.0.0/24
tacctl config deny add 10.99.0.0/24
```
Deny takes precedence over allow.

### Cisco priv-exec mappings
Cisco IOS gates command **availability** by privilege level (`privilege exec level X <cmd>`) independently of TACACS+ command authorization. Both gates must say yes for a command to run. Manage the mappings per group:
```
tacctl group privilege seed                  # built-in defaults (only verified move-DOWNs)
tacctl group privilege list operator         # show current mappings + source (explicit / default)
tacctl group privilege add operator 'show ip route'
tacctl group privilege remove operator 'show running-config'
```
Defaults move only verified priv-15 commands DOWN to lower groups (e.g. `show running-config` → priv 7 for `operator`); they never move commands UP from a lower default level (which would silently restrict them from `readonly` users). Mappings live under `privileges.<group>` in `/etc/tacctl/tacctl.yaml` and survive `tacctl upgrade`. They are emitted by `config cisco` for both protocols.

### Per-command authorization
Restrict which commands a group can run, enforced live by Cisco IOS via TACACS+ and mirrored into Junos class `allow-commands`/`deny-commands` by `tacctl config juniper`. **RADIUS has no per-command authorization**: over RADIUS a group's users are limited only by the privilege level, login class or access level the Access-Accept carries (`tacctl status`, `config render` and `backend enable` name the groups whose rules RADIUS does not enforce; the Junos class rules are local to the device and stay in force). Tacctl ships sensible defaults — no seed step needed for fresh installs:

- `superuser`: unrestricted `*` catch-all (permit).
- `operator`: permits `show`, `ping`, `traceroute`, `terminal`; default **deny** catch-all.
- `readonly`: permits `show`, `ping`, `traceroute`; default **deny** catch-all (`terminal` omitted — `terminal monitor` can leak debug across sessions).

View the shipped defaults with `tacctl config defaults`; inspect a single group with `tacctl group commands list <group>`. Rules live under `commands.<group>` in `/etc/tacctl/tacctl.yaml`; tacquito.yaml's per-group `commands:` block is rendered from that source on every change.

The `tacctl group commands seed` command is retained as a recovery tool — it re-applies the original seed rules (with `enable`, `clear`, `monitor`, etc.) and should only be needed if you've customized and want to start over. On a fresh install, the shipped defaults above are already in effect.

Or build rules manually:
```
tacctl group commands default operator deny
tacctl group commands add operator show --action permit
tacctl group commands add operator ping --action permit
tacctl group commands add operator clear --match 'counters.*' --action permit
```
A rule's `name` is compared literally to the TACACS+ `cmd=` word. `--match` regexes are tested by tacquito against the command's **arguments only** — the space-joined `cmd-arg` values after the word, so `show running-config` is tested as `running-config`, never as the full line. A regex that repeats the command word (`^show .*$`) can never match and is rejected by `tacctl group commands add`, and so is a regex with a comma (the stored rule line separates matches with commas; write `\x2c`); omit `--match` to cover any arguments. (tacctl ≤ 0.1.10 shipped defaults with that dead shape, which denied every `show` to operator/readonly users; `tacctl upgrade` heals any override still carrying it.)
The trailing `*` catchall encodes the default action. Once any group has rules, `tacctl config cisco` emits `aaa authorization commands 1/7/15 default group TACACS-GROUP local` so IOS asks tacquito per command. Juniper enforcement is local via class `allow-commands`/`deny-commands` regex — `tacctl config juniper` emits the equivalent `set system login class …` lines, but you must push them to each device.

When you add the first rule to a group, tacctl auto-seeds a `* permit` catchall onto sibling groups at the same Cisco priv-lvl so their users aren't accidentally locked out.

### Management ACL (Cisco VTY-ACL + Juniper lo0 filter)
Restrict which source subnets can reach the device management plane. Build the permit list once on the tacctl server:
```
tacctl config mgmt-acl add 10.1.0.0/16
tacctl config mgmt-acl add 192.168.5.0/24
tacctl config mgmt-acl list
```
`tacctl config cisco` then emits a populated `VTY-ACL` applied to `line vty 0 15` via `access-class VTY-ACL in`. `tacctl config juniper` emits a commented `set firewall family inet filter MGMT-ACL` block (including a trailing `default-accept` term to keep BGP/OSPF/IS-IS traffic to the RE working) — review and uncomment per device. The list lives under `mgmt_acl.permits` in `/etc/tacctl/tacctl.yaml` and survives `tacctl upgrade`.

Rename the emitted ACL / filter names to match your site conventions:
```
tacctl config mgmt-acl cisco-name MGMT-ACCESS
tacctl config mgmt-acl juniper-name MGMT-SSH-FILTER
```
Overrides live under `mgmt_acl.names.{cisco,juniper}` in `/etc/tacctl/tacctl.yaml` and also survive `tacctl upgrade`.

### Prometheus metrics exporter
Tacquito ships a Prometheus HTTP exporter for auth-rate and error counters (FreeRADIUS has none; `tacctl status` counts RADIUS accepts and rejects from its auth log). By default it binds to **loopback only** (`127.0.0.1:8080`) — local scrapers on the box work out of the box, external scrapers are opt-in. Manage via:
```
tacctl config metrics                         # show current state + scrape URL
tacctl config metrics address 10.1.0.1:8080   # expose to external scrapers on a specific mgmt IP
tacctl config metrics disable                 # sink to 127.0.0.1:0 (unreachable ephemeral port)
tacctl config metrics enable                  # revert to loopback:8080 default
```
`disable` does not use tacquito's own `-export-promhttp=false` flag — upstream's handler unconditionally cancels the server context when the exporter goroutine returns, which would tear down the whole daemon. Binding to a loopback ephemeral port gives the same operator-visible result (no scraper can reach it) without requiring a tacquito patch.

### Log retention
Accounting logs are rotated daily and retained for 90 days (see `/etc/logrotate.d/tacquito`, and `/etc/logrotate.d/tacctl-radius` for RADIUS). Adjust the `rotate` value if your compliance requirements differ.

### Password age
The default password age warning is 90 days. Adjust with:
```
tacctl config password-age <days>
```

### Passwordless sudo for operators (opt-in)
By default, `tacctl` requires `sudo` authentication. To let a group run it without a password prompt, install a sudoers drop-in:
```
tacctl config sudoers install adm     # or: wheel, ops, etc.
```
This writes `/etc/sudoers.d/tacctl` (validated with `visudo -cf`) granting `%adm ALL=(ALL) NOPASSWD: /usr/local/bin/tacctl`, with `Defaults!/usr/local/bin/tacctl env_keep += "SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY"` so `tacctl host` keeps your agent socket through sudo (the second name is the login console's session marker). Because `tacctl` can modify system config and restart services, this is effectively passwordless root for members of that group — the command prompts for confirmation before installing. Remove with `tacctl config sudoers remove`.

### Login for Linux hosts
Linux hosts log in against this server by one of two methods. Accounts, tiers, sudo and the fallback to local passwords are the same for both; the PAM module differs:

| Method | PAM module | Backend | Where the module comes from |
|---|---|---|---|
| `tacplus` (default) | `pam_tacplus` | TACACS+ | Built by tacctl: no current distribution packages a usable build and upstream is archived, so tacctl pins v1.7.0 (verified by commit hash) and builds it itself, in a container on the server when hosts are enrolled with `tacctl host enroll`, or on the host when the install script is run by hand |
| `radius` | `pam_radius_auth` | RADIUS (`tacctl backend enable radius` first) | The host's distribution package: `libpam-radius-auth` on Debian/Ubuntu; `pam_radius` from EPEL on the RHEL family, enabling EPEL (`epel-release`) when the host does not have it |

```
tacctl config linux build                                  # once, on the server: prepare the pam_tacplus source tarball
tacctl config linux script --scope prod -o enroll.sh       # install script for hosts in a scope
tacctl config linux script --scope prod --method radius -o enroll.sh
tacctl config linux remove-script -o unenroll.sh           # removal script (no secrets; removes either method)
```
Copy the install script to the host and run it as root from a session you keep open. It:
- installs the PAM module before creating any account (`tacplus`: builds and installs `pam_tacplus`, installing `gcc`, `make` and `libpam0g-dev` with apt if missing, and leaving a host that already has the module from the same source alone; `radius`: installs the package, and stops before any account or PAM change when it cannot);
- creates a local account for each user in the scope, with a locked password, a UID that is the same on every host (80000-89999), `tac-users` as primary group and a 0700 home; superusers are also in `tac-superuser` (see [tacctl's groups](#tacctls-groups));
- deletes the accounts it created for users who are no longer in the scope (see [Account lifecycle on a host](#account-lifecycle-on-a-host));
- sends `sshd`, `sudo` (including `sudo -i`), console `login` and the graphical logins `sddm` and `gdm-password` (where present) to the server for members of `tac-users` only (the shared `common-*` files, or `system-auth`/`password-auth` on the RHEL family, and every other local account are untouched);
- grants `%tac-superuser` full sudo, authenticated with the network password.

A reject from the server is final. If the server is unreachable, login falls through to the local password, which tacctl's accounts do not have; local administrators and every other local account (not in `tac-users`) are never sent to the server and see no delay. With the server silent, measured in containers: a tacctl user is refused after 5-6 s (`tacplus`) or 8-9 s (`radius`) (`docs/radius-notes.md`). A wrong shared secret on the host behaves like a silent server. The script refuses to run unless a local administrator with a usable password exists outside the user list, and restores the PAM files if any step fails. Re-run it with `--accounts-only` after adding, removing or moving users.

The install script contains the scope's shared secret, and so do the root-only files it writes (`/etc/pam.d/tacctl-*` for `tacplus`; `/etc/tacctl-pam_radius.conf`, 0600, for `radius`): use a dedicated scope per host or host group, and keep TACACS+ and RADIUS traffic on a management network or tunnel (no Linux PAM client supports TACACS+ over TLS). `passwd` does not work for these users; they change passwords with `tacctl passwd` on the server.

`radius` specifics: PAP only; the host reads no vendor attribute, so a scope of Linux hosts needs none enabled. The module is given `client_id=<the host's fully qualified name>` (`hostname -f`), so its NAS-Identifier names the host: without it pam_radius_auth sends the PAM service's name (`sshd`, `sudo`), and `device scan` saw the host change name with every service. A host enrolled before 0.2.1 keeps sending the service's name until it is enrolled again (its `name-mismatch` notice says so); a host enrolled with pam_tacplus sends no NAS-Identifier, and a name recorded from an earlier RADIUS enrolment raises no notice. Session accounting is sent only where the module gets it right: it always goes to the authentication port plus one, so the RADIUS `acct` listener must be on that port (1813 by default), and it is left out on Ubuntu 24.04, whose pam_radius_auth 2.0.1 sends malformed accounting records. Logins are in the server's auth log either way. **BlastRADIUS (CVE-2024-3596):** pam_radius_auth 2.0.x on **Ubuntu 24.04 and Debian 12** neither sends nor checks Message-Authenticator; Debian 13 and the RHEL family (EL8/9 backported, EL10) do, and tacctl adds `require_message_authenticator` where the installed module has the option. Treat RADIUS from Ubuntu 24.04 and Debian 12 hosts as forgeable on an untrusted path; FreeRADIUS logs a "BlastRADIUS check" block for such clients.

Graphical login: SDDM and GDM authenticate these users, and GNOME's lock screen unlocks through GDM. The user's keyring or wallet is not unlocked automatically. KDE Plasma's lock screen is the exception: it checks passwords as the logged-in user and so cannot read the root-only secret. On a Plasma host the install script therefore switches screen locking off for the accounts it created (automatic lock, lock on resume and the Lock action), from their next login; local accounts keep theirs. The settings live in `/etc/xdg/tacctl` and `/etc/xdg/plasma-workspace/env/tacctl-nolock.sh`, and unenrolling removes them. A session that gets locked anyway (`loginctl lock-session`) is unlocked from another login with `loginctl unlock-sessions`. Accounts are created with the full name `<login> (TACACS+)` or `<login> (RADIUS)`, which is what login screens list.

Debian, Ubuntu and their derivatives are supported, and so is the RHEL family (RHEL, AlmaLinux, Rocky, CentOS Stream, Oracle Linux). Tested, both methods, over real SSH in containers: Ubuntu 24.04, Debian 12 and 13, AlmaLinux and Rocky 8, 9 and 10. On RHEL-family hosts the script adds an `include` line in front of the service's `password-auth`/`system-auth` line instead of replacing a Debian `@include`, leaves the authselect-managed files alone, uses `dnf`, and, when SELinux is enabled, installs a small policy module (`tacctl_pam`, which labels the TACACS+ port and lets `sshd`, `login` and `sudo` connect to it; `tacctl_pam_radius` for RADIUS). SELinux in enforcing mode is not verified for either method.

The removal script undoes the PAM edits and deletes the secret, module, SELinux policy module and sudoers drop-in of either method (packages stay installed). Accounts, home directories and the `tac-*` groups stay; it lists any account left with neither a local password nor an SSH key.

#### Enrolling hosts over SSH
`tacctl host` does the copy-and-run for you and keeps a registry of enrolled hosts:
```
tacctl host enroll admin@web1.example.net     # into the scope that covers web1's address; installs, registers
tacctl host enroll admin@web2 --method radius # the same with pam_radius_auth against the RADIUS backend
tacctl host enroll --local                    # this machine
tacctl user scope jsmith add <scope>          # give a user a login on hosts of that scope...
tacctl host sync web1                         # ...and push the account (or: tacctl host sync --all)
tacctl host list                              # with each host's METHOD
tacctl host target web1                       # how web1 is reached (target, port, identity, addresses)
tacctl host target web1 root@web1-mgmt.example.net --port 2222   # change it, tested first
tacctl host unenroll web1                     # remove the login method; accounts and home directories stay
tacctl host default-method radius             # what hosts enrolled without --method get (host.default_method)
```
The method of a host is, in order: `--method`; the method the host is registered with; the scope's `auth-method` (`tacctl scope auth-method`); the one protocol the scope's `protocols` filter names; `host default-method` (default `tacplus`). Its backend must be enabled and the scope must allow its protocol.

The scope of a host is, in order: `--scope`; the scope the host is registered in (re-enrolling never moves a host); the scope that answers its address (the first prefix that holds it, see `tacctl scope routing`), which enroll names: `10.1.2.3 (web1.example.net) is answered by scope 'lab' (prefix 10.0.0.0/8); enrolling web1 there`. A host whose address no scope covers is refused before anything changes, since the server would refuse its every login; enroll prints how to add the address to a scope (`tacctl scope prefixes <scope> add <address>/32`) or give the host a scope of its own, whose secret is useless from any other host (`tacctl scope add linux-web1 --prefixes <address>/32 --secret generate`, then `--scope linux-web1`). Enroll never creates a scope: a `/32` scope made for a host takes its address from any broader prefix, and that scope's users lose their accounts there.

**When the scope no longer answers the host.** A prefix change, a new address or an enroll into the wrong scope can leave a host registered in one scope while another answers its address: the server then checks its logins against that scope's users and secret, and refuses them. tacctl never moves a host on its own (a move changes its secret and deletes the accounts of the users it loses); it says so, with the fix, on every `host sync` of the host, below `host list`, and in `config validate` (from the address recorded at the last enroll or sync): `dev: registered in scope 'linux-dev', but 10.125.0.222 is answered by scope 'lab' (prefix 10.0.0.0/8): its logins are checked against that scope's users and secret, so they are refused. To move it: tacctl host move dev`. Moving prefixes between scopes is one change: `tacctl scope prefixes ipnode move 172.29.0.0/16 lab` takes them out of one scope and into the other and names the enrolled hosts that then belong to the other scope. A scope enrolled hosts use cannot be removed until they are moved.

**One machine, one registration.** Enroll refuses a new name for a machine already enrolled under another one (the same address on the same ssh port, or one of this server's own addresses when it is enrolled with `--local`): `'h10-125-0-222' is the enrolled host 'dev' (enrolled as rett@dev.example.net): both reach 10.125.0.222.` Re-enroll it under its registered name (`--name dev`) or change how it is reached (`tacctl host target dev <[user@]host>`).

**Provisioning off-site.** A host or network device set up on a bench, at an address its scope does not cover, before it is shipped to the scope's network: give the scope it will be installed in and `--staging` (`tacctl host enroll admin@bench-host --scope lab --staging`; `tacctl config cisco|juniper|wti --scope lab --staging <bench-ip> [--name <device>]`). The bench address joins the scope as a `/32`, so the scope's own secret and users answer the device on the bench and nothing changes on it when it comes online in the scope's prefixes. tacctl records it (`tacctl scope staging` lists each, with where its host or device is seen now) and removes the `/32` once the host (its next enroll or sync) or the registered device (`tacctl device address <name> <ip>`, `device add`) is seen at another address the scope covers: `Staging address 203.0.113.9/32 removed from scope 'lab': sw1 is now seen at 192.168.5.9 (prefix 192.168.0.0/16).` A device staged without a name, and not registered at its bench address, is removed by hand: `tacctl scope staging remove <address>`. **Moving a host:** `tacctl host move <host> [<scope>]` (without a scope: the one that answers its address; `--all`: every host another scope answers), which is an enroll of the registered host naming the new scope; before anything changes it says `Moving dev from scope 'linux-dev' to scope 'lab': it gets that scope's secret and users.` and names the users whose accounts the move deletes, then asks on a terminal (`[y/N]`); without a terminal it stops unless given `--yes`. Removed users' homes follow the usual rules (asked, `--remove-home`, or kept). **Switching:** re-enrolling a registered host with the other `--method` removes the first method's module, secret file and SELinux module and installs the other; re-enrolling without `--method` keeps the host's method.

`ssh` runs as the user who invoked `sudo`, with their keys; the remote login must be root or able to `sudo` (a password prompt works when run from a terminal). That login (the provisioning account: the target's `user@`, else your own username) must be a local account on the host that does not authenticate through tacctl, so enrolment and sync keep working when this server cannot be reached: `host enroll` refuses a tacctl user, and `host sync` warns about an existing enrolment that uses one. `tacctl ssh` never uses it. Without a terminal, a host whose sudo needs a password is reported as such rather than attempted. The steps of one command share a single ssh connection per host, so a login without a key asks for its ssh password once, followed by one sudo prompt; with a key (or agent) and passwordless sudo or a root login there is no prompt at all. `--scope` enrolls into an existing scope instead of creating one (the scope must answer the host's requests: `--local` is refused, nothing changed, when the scope does not cover 127.0.0.1, the address this server's own logins come from; another host gets a warning when the scope does not cover the address its name resolves to, and `host sync` of this server warns when its scope stops covering 127.0.0.1), `--server` overrides the detected server address, `--name` the registry name, and `--port` / `--identity` are passed to ssh. `host target <name> [<[user@]host>] [--port <n>] [--identity <file>|--no-identity]` changes how a host is reached without re-enrolling it: it logs in to the new target the same way first, checks that the login is root or may use sudo, compares the host's ssh keys read over that session with the pinned ones (a host whose keys differ is refused: it is not the same machine), records the address reached, and only then rewrites the registry line (scope, server and method kept), after a snapshot. Account changes are not pushed automatically: run `host sync` after `user add`, `remove`, `move`, `disable` or `scope` changes. Until then a removed user is already refused at password login by the server, but an SSH key on the host keeps working.

#### Where the module is built (`tacplus`)
`host enroll` reads the host's `/etc/os-release` and architecture, builds `pam_tacplus` once for that OS release in a rootless `podman` container on the server (base image plus compiler pulled with network access; the compile itself runs with no network and no capabilities), caches it under `/var/lib/tacctl/linux/builds/`, and ships the binary. The host installs it without a compiler, headers or package repository, after checking its checksum and that it loads against the host's libraries.
```
tacctl config linux builds               # list cached builds with the base image digest each used
tacctl config linux builds clear         # drop them; the next enroll of each OS release rebuilds
tacctl host enroll web1 --build-on-host  # skip the container and compile on the host
```
The host compiles from the embedded source instead when there is no image for its OS, its architecture differs from the server's, `podman` is missing or the container build fails, or the shipped module does not load there. Base images come from Docker Hub (`ubuntu:<codename>`, `debian:<codename>`, and `almalinux:<major>` for every RHEL-family host, since they share an ABI per major release) and are trusted as pulled; the digest is recorded with each build. None of this applies to `radius` (`--build-on-host` warns that it is not applicable).

`tacctl install` and every `tacctl upgrade` install the packages this needs if they are missing (`podman`, `uidmap`, the autotools set for `config linux build`, `openssh-client`), along with tacctl's core requirements.

#### Consistent UIDs and GIDs
Each user gets one number, its UID on every host this server enrolls (its primary group is `tac-users`). It is assigned the first time the user is sent to a host, from the server's range only, **80000-89999** unless changed (after the highest one given so far, never into a gap), and stored in `/etc/tacctl/linux-uids`. The default range is clear of what else hands out numbers on a Linux host: above the distributions' `useradd` range (`UID_MAX 60000` on Debian, Ubuntu and the RHEL family) and systemd's reserved numbers (60001-60513, 61184-65519, 65534/65535), inside the range systemd leaves unused (65536-524287), and below the usual start of `/etc/subuid` (100000). A number is never reused: a removed user's entry stays in the file, so a later user never inherits its files on a host. When the range is used up, the next user is refused with `No UID left for '<user>'` until it is given a free number of the range by hand.
```
tacctl config linux uid                  # list assignments
tacctl config linux uid jsmith           # print one
tacctl config linux uid jsmith 80500     # change it (within the range only)
tacctl config linux uid-range            # show the range
tacctl config linux uid-range 100000-109999   # change it, for all hosts
```
An entry outside the range (from a release that allowed it) is listed as `outside 80000-89999: not used on hosts`, and its user gets no account on any host until it is given a number in the range.

**Another range.** `config linux uid-range <min>-<max>` sets `linux.uid_min` and `linux.uid_max` in `tacctl.yaml`; one range serves all hosts. A range must hold at least 1000 numbers, start at 1000 or above, and stay clear of systemd's reserved numbers (60001-60513, 61184-65519, 65534-65535, and 524288 and up); one that overlaps `useradd`'s default 1000-60000 is accepted with a warning, since every host's `/etc/login.defs` must then keep clear of it. A change moves every entry of `linux-uids` by the offset between the two starts (80005 becomes 100005), as the move from 20000-29999 below does, and the next enroll or sync moves each host's accounts the same way. It is refused, nothing changed, when the new range overlaps one the file was numbered for (hosts may still have accounts there), when an entry would land past its end, or when a number is already another name's. A range grown or shrunk at the same start moves nothing. The file records its range on its first line (`# range 80000-89999`) and the earlier ones (`# previous 20000-29999`), so a backup or a copy to another server carries its numbers and their range together; a range set by hand in `tacctl.yaml` is applied, the same way, by the next command that reads the file.

**Hosts that cannot hold the range.** An unprivileged container (rootless podman, an LXC/LXD container) sees only the IDs its user namespace maps, usually 0-65535: `useradd` there accepts a larger UID, but the account cannot log in. Before anything runs on a host, `host enroll` and `host sync` read its `/proc/self/uid_map` and `gid_map` (this server's own for `--local`) and refuse a host that cannot hold the whole range: `'<host>' cannot hold UIDs 80000-89999: its user namespace maps only 0-65535 (an unprivileged container).` Give the container an ID map that covers the range, run it privileged, or choose a range all hosts can hold. `host target` warns about such a host.

**Numbers in 20000-29999** (where releases up to 0.2.0 gave them out) move once to the same offset in the range (20005 becomes 80005). On the server, the first `config linux uid`, `config linux script`, `host enroll` or `host sync` that finds such entries in `linux-uids` rewrites them all (users and removed users), keeps the old file as `linux-uids.pre-renumber-<UTC time>` and logs `uid-map renumbered <n> entries`; it refuses, changing nothing, when a new number is already another name's (`config linux uid <other> <uid>` resolves it). On each host, the next enroll or sync renumbers the accounts tacctl created there with a UID in 20000-29999: the UID (`usermod -u`, which re-owns the home directory tree), reported as `'<user>': renumbered <old> -> <new> (home re-owned)` and counted in the summary (`web1: synced (3 users; 1 renumbered).`). Files outside the home that still carry the old number (under `/home`, `/tmp`, `/var/tmp`, `/var/spool/cron`, `/var/mail`; at most 20 listed) are reported and left as they are. An account whose user is logged in, or whose new UID is taken on the host, is left exactly as it is and named as refused until a later sync can renumber it. Accounts in 20000-29999 that tacctl did not create are not touched.

If the number is already taken on a host by another account, the install or sync **stops before changing anything** and lists the options (GIDs do not matter: tacctl's accounts have no group of their own):
1. free the number on the host by renumbering the account that holds it (`usermod -u`, then `chown` its files);
2. assign the tacctl user another free number of the range (`tacctl config linux uid <user> <uid>`) and re-run;
3. accept a different number on that host only: `tacctl host enroll|sync ... --allow-uid-mismatch`, which takes the highest number of the range that is free there.

An account tacctl created whose UID on a host differs from the assignment (but is in the range) is kept as it is; every sync reports the difference and how to fix it. Changing an assignment does not renumber accounts already created on hosts. Two tacctl servers assign independently, so copy `linux-uids` between them if their hosts must agree.

#### tacctl's groups
Each of tacctl's groups has a fixed GID, the same on every host: the first numbers of the UID range (80000-89999 by default; they follow `config linux uid-range`). A host has only the groups it uses:

| Group | GID | Where | Used for |
|---|---|---|---|
| `tac-users` | 80000 | every host | primary group of every account tacctl manages; PAM sends only its members to the server; the server's tier check |
| `tac-console` | 80001 | the tacctl server | sshd's login-console drop-in |
| `tac-superuser` | 80002 | every host | `%tac-superuser` sudo (and the tiers sudoers on the server) |
| `tac-operator` | 80003 | the tacctl server | its tiers sudoers |
| `tac-readonly` | 80004 | the tacctl server | its tiers sudoers |

Accounts have no group of their own; with a shared primary group, each home is made 0700 when the account is created or moved. The first enroll or sync with this release moves what an earlier one made, once: each managed account's primary group becomes `tac-users` (`usermod -g` re-groups the files in its home) and its own group is removed when it has no members; each group moves to its fixed GID (`groupmod -g`; files in the managed homes that carried `tac-users`' old number follow it); on a host other than the tacctl server, `tac-readonly`, `tac-operator` and `tac-console` are removed when only tacctl's accounts are in them (otherwise kept, and said). A fixed GID that another group already holds on the host is left to it: tacctl's group keeps or gets another number, with a warning (`Group 'tac-users' keeps GID 1001, not 80000: GID 80000 belongs to group '<other>' here.`).

#### Account lifecycle on a host
tacctl manages an account on a host only when it created it (the host's `/var/lib/tacctl-client/created`) **and** its UID there is in the server's range. Every other account, whatever its name, is never created, expired, deleted or otherwise changed, with one exception: it is taken out of tacctl's own groups (`tac-users`, `tac-readonly`, `tac-operator`, `tac-superuser`, `tac-console`), so it is a plain local account that is never sent to the server; nothing else on it changes (UID, home, password, shell, expiry, full name). The host reports each one: `'<user>': removed from tacctl's groups (tac-users, tac-<tier>); it is a plain local account again.`

- **New user in the scope:** the install or sync creates the account.
- **Local account with the same name:** if the host already has an account named like a tacctl user that tacctl did not create, that user gets no account on that host, with a warning; the local account stays exactly as it is (an emergency login that does not depend on this server), and the rest of the install or sync goes on. A matching name does not prove it is the same person: rename the tacctl user, keep it off that host, or remove or rename the local account. The sync summary names such users: `web1: synced (4 users; 1 refused: carl).`
- **Disabled user** (`tacctl user disable`): the account is expired (no login, SSH keys included) and its files are kept; `tacctl user enable` and the next sync restore it.
- **Removed user** (no longer in the scope, or no longer a tacctl user): the account is deleted (`userdel`), and an own group an earlier release made when that is now empty; its UID stays reserved on the server. Its home directory is deleted only when asked for: on a terminal, `host sync` and `host enroll` ask `Delete /home/<user> of removed user '<user>'? [y/N]` for each removed user (the list is read from the host's `getent passwd` over the same ssh connection before anything runs there); `--remove-home` deletes them without asking; with no terminal and no flag every home is kept. A kept home is moved out of reach of a later local account that gets the same UID: to `/home/.tacctl-removed/<user>-<YYYYmmdd-HHMMSS>` (`/home/.tacctl-removed` is root's, 0700; the moved tree is made `root:root` with `chown -hR`, never following a link, its top 0700), and the host prints `home kept: /home/.tacctl-removed/<user>-<time>`. A home is never deleted or moved when it is not a directory directly under `/home`, is or sits behind a symbolic link, is not owned by the account, or is also another account's home (`home kept in place: <home> (<reason>)`); one on another file system than `/home` stays in place too. A removed user who is still logged in cannot be deleted: the account is expired and deleted at the next sync.
- **Local accounts and tacctl's UID range:** local `useradd` on a host must not give out UIDs of the server's range, or a local account could take a number tacctl has given out. `host enroll` and `host sync` read the host's `/etc/login.defs` and warn when its `UID_MIN`-`UID_MAX` overlaps the range (the default `UID_MAX` 60000 does not overlap 80000-89999); keep it clear of the range there. tacctl never edits the file.
- **Accounts an earlier release adopted:** reported once (`Accounts an earlier tacctl adopted are no longer tracked`), taken out of tacctl's groups in that same run, and not tracked after that.

`host unenroll` does not touch any account.

### Tiered access for tacctl users (opt-in)
tacctl users who have a local account on the server can be given tacctl access that follows their group:
```
tacctl config sudoers tiers show      # print the rules
tacctl config sudoers tiers install   # write /etc/sudoers.d/tacctl-tiers
```
| Local group | Tier (priv-lvl) | tacctl access |
|---|---|---|
| `tac-readonly` | read-only (below 7) | `passwd`, `status`, `version`, `help` (also `-h`, `--help`), `user list`, `user show`, `group list`, `scope list`, `backend list`, `backend status`, `device list`, `device show`, `device notices`, `device ssh-config`, `ssh` and `device ssh` (their own scopes' devices only), `_console-policy` (the login console reads its settings with it) |
| `tac-operator` | operator (7-14) | read-only set plus `log tail/search/failures/accounting`, `config validate`, `backup list`, `device export`, `device scan`, `device discover`, `device check`, `console show`, `console check`, `device list --scan` and `--probe` (their own scopes' devices only; `discover` lists every unregistered address) |
| `tac-superuser` | superuser (15) | everything, plus full `sudo` |

Lower-tier rules are plain `NOPASSWD` lines. The only things the file lets through from the caller's environment are the agent socket, the console's marker and the X11 display (`Defaults!/usr/local/bin/tacctl env_keep += "SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY"`: the agent socket for `tacctl host`, the login console's session marker, and the display `tacctl ssh -X` hands on), so a caller cannot hand tacctl another `SUDO_USER`; tacctl also refuses a `SUDO_USER` that is not the account of `SUDO_UID`. Anything that prints a shared secret or a password hash (`config cisco|juniper|wti`, `scope secret`, `backup diff`, `config dump`, `store show`) stays superuser-only, as does `scope show`, and so does everything that changes anything. tacctl also checks the tier itself on every run, taking it from the user's group in the store rather than from local group membership, and logs denials to syslog. Callers who are not in the local group `tac-users` (root, local admins) are not restricted. `tacctl upgrade` rewrites an installed `/etc/sudoers.d/tacctl-tiers` that differs from the release's rules (after `visudo -cf` accepts them), so a new release's verbs reach the tiers (the upgrade says `Updated: tiers sudoers`, or `Unchanged:`); it never creates the file, and when `visudo` refuses the new rules the old file stays and a warning says so. Without that refresh a tier user could not run the verbs a release adds until an administrator re-ran `tacctl config sudoers tiers install`.

`tacctl passwd` (no arguments) lets any tier change their own password: it acts only on the user who invoked sudo and asks for the current password first.

### Login console

**On the tacctl server itself, every tacctl user's login shell becomes the login console once the server's accounts are synced** (`tacctl host enroll --local`, then `tacctl host sync <name>` after any change); nothing changes for anyone before that sync. A console user who logs in over ssh gets a `<host>> ` prompt that runs tacctl commands (as `sudo tacctl …`, so the tiers above apply line by line) and `tacctl ssh` to the registered devices of their scopes, and nothing else: no system shell, no file transfer, no port forwarding (superusers excepted by default: `console forwarding tiers`). `ssh <server> 'user list'` runs one tacctl line; `scp`, `sftp` and `rsync` are refused.

- **Who gets it.** Every tier by default. `tacctl console tiers <tier> disable` switches a tier off, `tacctl console user <name> disable|enable` overrides one user, and the next `host sync` of the server applies it (`usermod -s`); `tacctl console show` lists each user's effective shell and why.
- **Break-glass.** Local accounts that are not tacctl users (root, the administrators who installed the server) are never touched, so they keep their shells and their local passwords. To give one tacctl user bash back: `tacctl console user <name> disable`, then `tacctl host sync <server>`.
- **sshd's drop-in is the key line.** `Match Group tac-console` in `/etc/ssh/sshd_config.d/tacctl-console.conf` sets `ForceCommand /usr/local/bin/tacctl-console` (every login, remote command and subsystem, the sftp server included, reaches the console, which takes the client's command from `SSH_ORIGINAL_COMMAND` and lets only one tacctl line through), `DisableForwarding yes` with `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`, `X11Forwarding no`, `AllowAgentForwarding no` and `PermitTunnel no` (agent forwarding only with `console agent-forwarding enable`). For each tier of `console forwarding tiers` (default: superuser) a block before it, `Match Group tac-console Group tac-<tier>`, sets `DisableForwarding no`, `AllowTcpForwarding yes` and `X11Forwarding yes`: sshd takes the first value it finds, so those users can `ssh -X`, `-L`, `-R`, `-D` and `-J` through the server (still into the console, still by password) while everyone else stays closed. Then `PubkeyAuthentication no` (a key login would bypass TACACS+), and `ClientAliveInterval 300` / `ClientAliveCountMax 2`. Every change is checked with `sshd -t` and undone when sshd refuses it; sshd is reloaded otherwise. `/etc/ssh/sshd_config` must include `sshd_config.d/*.conf` (Debian, Ubuntu and RHEL 9 do). `tacctl console check` (operator and up) asks `sshd -T` what it applies to a console user and warns in red when anything is off; `console show` does the same.
- **`system-shell`.** The console word `system-shell` starts the user's own system shell, logged; superusers only by default (`tacctl console system-shell tiers`).
- **Logged.** Sessions, refused commands and system shells go to syslog (tag `tacctl-console`), every line to sudo's log, and every `tacctl ssh` session with `console=<session>`.
- **Undoing it.** `tacctl host unenroll <server>` gives tacctl's accounts `/bin/bash` back and removes the drop-in and the `/etc/shells` line; so does `tacctl uninstall`, which never leaves an account with a shell that is about to disappear.

The tiers sudoers rules (above) must be installed for readonly and operator console users: without them their lines are refused by sudo.

### Host keys of devices and hosts (pinning)
`tacctl ssh` signs users in to devices with their tacctl password, so a device that is not the one registered would be handed that password. The registry therefore pins each device's ssh host keys, and ssh is made to accept those keys and nothing else:

- **Pinning.** `tacctl device add` reads the keys the device offers (`ssh-keyscan`, as root) and prints each `SHA256:` fingerprint with the command that shows it on the device's console; compare them before the first connection, because the scan itself trusts what answers. `--host-key SHA256:<fp>` registers only when the device offers that key. A device that does not answer is refused unless `--no-host-key` registers it unpinned, which leaves a standing `hostkey-unpinned` notice (ssh then uses the user's own `known_hosts`).
- **Enrolled hosts** are not pinned from a scan alone: `host enroll` and `host sync` read the host's own `/etc/ssh/ssh_host_*_key.pub` over the enrolment's authenticated ssh connection and pin only the keys an `ssh-keyscan` of the target holds too. A key type on which the two reads disagree pins nothing and is logged (`host hostkey-mismatch`).
- **No silent change.** Only `tacctl device hostkey <name> accept|set` (administrators, after verifying on the console) changes a pin; it is logged to syslog. A scan that finds a different key raises a `hostkey-changed` notice that cannot be acknowledged away, and ssh refuses the connection to that device, after which `tacctl ssh` prints the pinned and offered fingerprints.
- **How it reaches ssh.** tacctl writes `/var/lib/tacctl/ssh/known_hosts` (0644, root-owned, in a 0755 directory: the registry itself is root's alone) from the pins on every registry write, and runs ssh with `UserKnownHostsFile` on it, `GlobalKnownHostsFile=none`, `StrictHostKeyChecking=yes`, `HostKeyAlias=<name>` and `UpdateHostKeys=no`. User-supplied ssh arguments come after those options and cannot replace them. `tacctl device ssh-config` gives plain `ssh` the same options.
- **Passwords only.** Sessions never use an agent, a key or another login: `PubkeyAuthentication=no`, the login is the caller's own name, and only an active tacctl user with a scope that includes the device's may connect, whatever the tier.

## RADIUS

```
tacctl backend enable radius
```
installs FreeRADIUS from the distribution (`freeradius freeradius-utils`; on the RHEL family from AppStream, no EPEL), renders tacctl's configuration, and starts the distribution's unit (`freeradius` or `radiusd`) with a drop-in that runs **tacctl's own instance** (`-n tacctl-radius`): the package's `radiusd.conf`, `clients.conf`, `sites-enabled/` and `mods-enabled/` are not read, edited or unlinked, so there is no EAP, inner tunnel, proxying, Status-Server or default `localhost/testing123` client. The module knows the Debian/Ubuntu and the RHEL-family layouts; `backend enable radius` was run for real on Ubuntu 24.04 (FreeRADIUS 3.2.5) and AlmaLinux 9 (3.0.27), and the rendered files were checked against 3.0.20 on AlmaLinux 8, where tacctl itself does not run (Python 3.6) (`docs/radius-notes.md`).

- **An existing FreeRADIUS is never taken over.** If the unit is running or enabled without tacctl's drop-in, `backend enable radius` refuses and says what to run if it is not in use (`systemctl disable --now freeradius`). On Debian/Ubuntu the package starts its own configuration on install; tacctl stops and disables that before starting its own.
- **Same users, groups, scopes and secrets.** One RADIUS client per prefix of every scope that RADIUS serves (no `protocols` filter, or one that names `radius`), with that scope's secret; overlapping prefixes resolve to the most specific, as with TACACS+. A user authenticates only from a client in a scope they belong to; disabled users and the `root` sink never authenticate. The connection filters (`config allow|deny`) apply.
- **PAP only**, against the stored bcrypt hashes. CHAP, MS-CHAP and EAP are rejected.
- **What RADIUS does not do:** no per-command authorization (`group commands` rules are not enforced by the server; see [Per-command authorization](#per-command-authorization)), no command accounting (login/exec accounting only, to a detail file), no Prometheus counters. Every change restarts FreeRADIUS (it reads clients only at start); requests in flight are retransmitted by the NAS.
- **Status and logs.** `tacctl status` has a RADIUS section (service, listeners, accepts and rejects of the last 24 hours from `tacctl-auth.log`, recent rejects with their reason, which vendor attributes are sent); `tacctl log tail|search|failures|accounting|clear --backend radius`; `tacctl user show` reads the last login from the auth log.
- **Secrets.** Any secret is rendered that FreeRADIUS can read back unchanged (refused: one with both a backslash and a `$`); beyond 63 characters, or with a space or non-ASCII character, `config render` warns, as some RADIUS clients take no more. Device configs refuse secrets a device CLI would misread (below).
- **Server-side BlastRADIUS:** FreeRADIUS 3.2.5 and 3.0.27 log a "BlastRADIUS check" block the first time a client sends Message-Authenticator, and from then on require it from that client (the package default, kept). See the Linux host caveat above for clients that send none.

### What an Access-Accept carries

A RADIUS server cannot tell what kind of device is asking, and one vendor's privilege attribute has no business on another vendor's device. So the RADIUS backend sends a vendor attribute only where the operator said so:

| Sent | When |
|---|---|
| `Service-Type` (`Administrative-User` at priv-lvl 15, else `NAS-Prompt-User`) | always (a standard attribute) |
| `Cisco-AVPair = "shell:priv-lvl=N"` | the scope enables `cisco`, or the device's address is tagged `cisco` |
| `Juniper-Local-User-Name = "<class>"` | the scope enables `juniper`, or the address is tagged `juniper` |
| `WTI-Super = 0..3` (ViewOnly, User, SuperUser, Administrator; the bands of the TACACS+ WTI mapping) | the scope enables `wti`, or the address is tagged `wti` |

- `tacctl scope vendor-attrs <scope> enable|disable <vendor>[,<vendor>...]` sets what a scope's devices get. It is an opt-in: **a new scope sends none** ("Vendor attributes: not sent"), and its verbs are `enable` and `disable`.
- `tacctl scope devices <scope> set <ip|cidr> <vendor>` tags an address: it gets its own vendor's attribute and no other, whatever the scope enables (`unset` removes the tag). The address must be one `scope lookup` answers with this scope; `scope prefixes remove` refuses to leave a tag outside the scope.
- An Access-Reject carries none of them. Linux hosts (`pam_radius_auth`) read none, so a scope of Linux hosts needs nothing enabled.
- `tacctl config validate` warns about a scope served over RADIUS that sends nothing and is not a Linux-host scope (one used by enrolled hosts whose prefixes are their single addresses); `tacctl status` counts the scopes that send something.
- How it is rendered (one FreeRADIUS client per prefix and per tagged address, the group's values in tacctl-internal attributes that never leave the server, a policy that adds a vendor attribute only on an exact match) is in the header of `lib/backends/radius.sh`; what was verified against FreeRADIUS 3.0.20, 3.0.27 and 3.2.5 is in `docs/radius-notes.md`.

### Which protocol a scope uses

- `tacctl scope protocols <scope> set tacacs|radius|tacacs,radius` limits which backends serve a scope (a filter: `clear` means every enabled backend). A backend leaves a scope it does not serve out of its config entirely: its devices get no answer.
- `tacctl scope auth-method <scope> tacacs|radius|clear` is the protocol a scope's devices and hosts use when a command names none: `config cisco|juniper|wti` without `--protocol`, and `host enroll` (a host not registered yet) / `config linux script` without `--method`. Without it, the one protocol the `protocols` filter names is used, else TACACS+ (device configs) or `host default-method` (hosts). It must be allowed by the scope's `protocols` filter, and `scope protocols set` refuses a list without it.
- `tacctl scope radius-group <scope> [label]` is the RADIUS twin of `tacacs-group`: the Cisco `aaa group server radius <LABEL>` name (default `RADIUS-GROUP`).

## Self-Service Password Generation

Users can generate their own bcrypt hash and provide it to an admin. The admin never sees the plaintext password.

Admins can print these same client-side commands on demand with:
```bash
tacctl hash commands
```

**On the server (if available):**
```bash
tacctl hash generate
```

**Linux / macOS:**
```bash
python3 -c "import bcrypt,getpass; print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt()).decode())"
```

**Windows (Python):**
```powershell
python -c "import bcrypt,getpass; print(bcrypt.hashpw(getpass.getpass().encode(), bcrypt.gensalt()).decode())"
```

**Windows (PowerShell, no Python):**
```powershell
Install-Module -Name BcryptNet -Scope CurrentUser
[BCrypt.Net.BCrypt]::HashPassword((Read-Host -AsSecureString "Password" | ConvertFrom-SecureString -AsPlainText))
```

**Admin adds with pre-generated hash:**
```bash
tacctl user add jsmith superuser --hash '$2b$12$...'
```

**Admin rotates an existing user's password with a pre-generated hash:**
```bash
tacctl user passwd jsmith --hash '$2b$12$...'
```

The same hash serves TACACS+ and RADIUS.

---

## Connecting to Devices by Name

The device registry (`/etc/tacctl/devices.yaml`) gives the network devices that authenticate against this server a name, and `tacctl ssh <name>` opens a session to one. Enrolled Linux hosts are in the same namespace.

```
tacctl device add core-sw1 10.99.0.1 --vendor cisco --legacy-ssh   # register; pins the ssh host keys and prints their fingerprints
tacctl device check core-sw1        # scope, vendor tag, last seen, reachable, host key against the pin
tacctl ssh core-sw1                 # a session, as you
tacctl ssh core-sw1 -- show version # one remote command
```

1. **Register.** A device whose address a scope's prefixes cover is `configured` in that scope (`tacctl device list`); one that no scope covers registers as `unconfigured`, and no one may connect to it. `--legacy-ssh` is for old IOS that offers only SHA-1 key exchange and `ssh-rsa`; `--vendor wti` selects the password-only method order. `device add` pins the host keys the device offers: **compare the printed fingerprints with the device's console** (Cisco `show ip ssh`, Junos `file show /etc/ssh/ssh_host_ed25519_key.pub` from the CLI, or `ssh-keygen -lf` on the same file from `start shell`, Linux `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). Names that are factory defaults (`switch`, `router`) are refused; name the device on the device too. Devices that already authenticate but are not registered are listed by `tacctl device discover`, each with a ready `device add` line. See [Host keys of devices and hosts (pinning)](#host-keys-of-devices-and-hosts-pinning).
2. **Who may connect.** An active tacctl user (in the store, not disabled) whose scopes include the device's scope, at every tier, superusers included. A local account that is not a tacctl user, a disabled user and a device in no configured scope are refused, and each refusal is logged to syslog (`ssh DENY`). A read-only or operator user (a member of `tac-users` with the [tiers file](#tiered-access-for-tacctl-users-opt-in) installed) may run `tacctl ssh` and sees only the devices of its own scopes.
3. **How it logs in.** ssh runs as you, never as root, and logs in with your own username and your tacctl password (which the device checks against this server): no agent, no key, no other login. Run it from your own account; as root it refuses. It needs a terminal.
4. **Plain `ssh`.** `tacctl device ssh-config > ~/.ssh/tacctl.conf` and `Include ~/.ssh/tacctl.conf` at the top of `~/.ssh/config` give a plain `ssh core-sw1` (and `scp`) the same options and the same pin. The fragment has one `Host` block per device you may see and no `User` line, so ssh logs in with your local username: a tacctl user whose local account has another name adds `User <tacctl name>` to its own `~/.ssh/config`. Re-run it after the registry changes.
5. **A key that changed.** When a device was replaced or reset, ssh is refused and tacctl prints the pinned and offered fingerprints and the console command that shows the key. After verifying on the console, an administrator re-pins with `tacctl device hostkey core-sw1 accept` (or `set SHA256:<fp>`).

From `tacctl shell`, `ssh core-sw1` is the same line. Every verb is in [Device Commands](#device-commands--tacctl-device).

## CLI Reference

> For a single-page reference, run `man tacctl` after install.

### Command Conventions

These patterns apply uniformly across every subcommand family:

- **No arguments** — dispatcher commands (`user`, `group`, `config`, `scope`, `host`, `device`, `console`, `backend`, `store`, `log`, `backup`, `hash`, and nested dispatchers like `scope prefixes` / `scope secret` / `scope aaa-order` / `scope exec-timeout` / `scope tacacs-group` / `scope radius-group` / `scope auth-method` / `scope vendor-attrs` / `scope devices` / `scope mgmt-acl` / `user scope` / `group privilege` / `config linux`) print their own usage and exit without side effects. Scalar getter/setters (`config loglevel`, `config listen`, `config metrics`, `config password-age`, `config bcrypt-cost`, `config password-min-length`, `config secret-min-length`, `config branch`, `scope default`, `host default-method`, `device address|hostname|vendor|port|description|legacy-ssh|stale-days`, `console idle-timeout|agent-forwarding|ssh-escape`) print the current value when called with no arguments.
- **Filters and opt-ins** — a setting that narrows something down is a *filter*: its verbs are `set` and `clear`, and empty (cleared) means everything (`scope protocols`, `config allow`, `config deny`). A setting that turns something on is an *opt-in*: its verbs are `enable` and `disable`, and nothing is on until it is enabled (`backend enable|disable`, `scope vendor-attrs`). An opt-in has no verb that could read as "empty means all".
- **Membership lists** — a list that names exactly what is in is a *membership list*, and empty means nothing, not everything (`user scope`, the scopes a user can authenticate from: none means nowhere; `scope prefixes`, the clients a scope serves: emptying it removes the scope). Its verbs are `add` and `remove`: `remove --all` empties it, and `user scope` replaces its whole list with `replace`.
- **Multi-item input** — every `add` / `remove` that takes a CIDR, a scope name, or a Cisco exec command accepts either a single value or a comma-separated list (`a,b,c`). Every input is validated first; a bad entry aborts the entire operation without writing anything.
- **CIDR semantics** — every CIDR-list subcommand (`scope prefixes`, `config allow`, `config deny`, `config mgmt-acl`) canonicalizes input before storage: `10.1.5.5/24` becomes `10.1.5.0/24`, `2001:DB8::/32` becomes `2001:db8::/32`. Exact duplicates (after canonicalization) are rejected as no-ops on `add`. Overlapping CIDRs of different prefix lengths coexist (`10.0.0.0/8` and `10.99.0.0/16` can both be present). Stored order is by broadcast-address ascending (IPv4 before IPv6): disjoint ranges sort by their end address, and an overlapping subnet falls immediately above its containing supernet (the subnet's range ends before the supernet's). This groups related CIDRs together and gives tacquito's provider selector the "most-specific first among overlaps" ordering it needs so a narrower scope wins a first-match lookup over a broader scope that contains it.
- **Scope prefix invariants** — every CIDR belongs to **exactly one** scope after canonicalization. Adding a prefix already claimed by a different scope is rejected with a message naming the owner; you must `tacctl scope prefixes <owner> remove <cidr>` before re-adding it elsewhere. Overlapping prefixes *across* scopes are allowed and routed correctly (e.g. `10.5.0.0/16` in `staging` coexists with `10.0.0.0/8` in `lab`). In the rendered `tacquito.yaml` a scope with N prefixes becomes N `secrets:` entries sharing the same `name:` and `secret.key`, sorted globally by prefix specificity (v4 before v6, smaller broadcast first), so tacquito's slice-ordered walk picks the narrowest scope. The CLI shows the logical one-bundle-per-scope view.
- **`clear` and `remove --all`** — `clear` and `remove --all` subcommands always prompt with `[y/N]` and print a warning describing the resulting posture (e.g. "no clients can connect" or "fails open"). Every prompt cancels, with a message, when standard input is closed.
- **Service restart** — changes to the store, and to the `tacctl.yaml` settings a backend renders (command rules, listeners, `backends.*`), re-render every enabled backend and restart the ones whose files changed. Settings only device configs read (mgmt-acl permits + names, priv-exec mappings, per-scope AAA order, exec timeout, group labels) and tacctl's own tunables (bcrypt cost, password age, …) restart nothing.
- **Flags** — long-form flags (`--hash`, `--scopes`, `--scope`, `--prefixes`, `--secret`, `--protocols`, `--vendor-attrs`, `--match`, `--action`, `--branch`, `--protocol`, `--method`, `--backend`, `--listener`, `--out`) take a single argument; `--default`, `--force`, `--legacy`, `--check`, `--replace`, `--json`, `--local`, `--all`, `--dry-run`, `--long` and `-y`/`--yes` take none. Required positional args come before flags.

### Top-Level Commands

```
tacctl install [--branch name] [-y|--yes]  # Install tacctl and the TACACS+ backend from scratch (-y: no confirmation)
tacctl upgrade [--branch name]  # Pull latest source, rebuild, update system files and every enabled backend
tacctl uninstall [-y|--yes]     # Remove tacctl, its backends' services and all associated files (-y: no confirmation, keeps no archive)
tacctl status                   # Service health, stats, errors, password age warnings (per backend)
tacctl passwd                   # Change your own password (asks for the current one; all tiers)
tacctl user <subcommand>        # User management (incl. per-user scope membership)
tacctl group <subcommand>       # Group management
tacctl scope <subcommand>       # Scope management (CIDR+secret bundles)
tacctl host <subcommand>        # Linux hosts: enroll, sync, unenroll, default-method
tacctl device <subcommand>      # Device registry: names, addresses and notices for the devices that authenticate here
tacctl ssh <name|address> [-p port] [-X|-Y] [-L|-R|-D spec]... [-- ssh args]  # ssh session to a registered device or enrolled host, as you, by password (never root)
tacctl console <subcommand>     # Login console: tiers, per-user overrides, settings
tacctl backend <subcommand>     # Backends: list, status, enable, disable
tacctl store <subcommand>       # The canonical store: show, import, rollback
tacctl config <subcommand>      # Configuration
tacctl log <subcommand>         # Log viewer
tacctl backup <subcommand>      # Backup management
tacctl hash                     # Show usage
tacctl hash generate            # Prompt + print a bcrypt hash
tacctl hash commands            # Print OS-specific client-side recipes
tacctl version [--long]         # Print tacctl version (--long: commit, build date, Go version)
tacctl completion bash|zsh|fish # Print the completion script of a shell (install and upgrade place the bash one)
tacctl shell [--no-history] [--idle min] [-c line]  # Interactive prompt: one tacctl command per line (runs as you; sudo per line)
```

Run any command without arguments for detailed help.

### Shell Completion

`install` and `upgrade` place the bash script in `/etc/bash_completion.d/tacctl`. zsh and fish are print-only: write the script where the shell looks for it, as the user who will use it.

```bash
# zsh: any directory on fpath, then compinit
mkdir -p ~/.zfunc
tacctl completion zsh > ~/.zfunc/_tacctl
# in ~/.zshrc, before compinit:  fpath=(~/.zfunc $fpath); autoload -Uz compinit && compinit

# fish
tacctl completion fish > ~/.config/fish/completions/tacctl.fish
```

The scripts ask `tacctl __complete` for the words, so they match the installed binary; regenerate them after an upgrade. Live names (users, groups, scopes, ...) need root or the NOPASSWD sudoers rule; without it only fixed words are completed.

### Interactive Shell — `tacctl shell`

```
tacctl shell                      # Prompt 'tacctl> ': type commands without 'tacctl' (user list, scope show lab)
tacctl shell --no-history         # Keep this session's history in memory only
tacctl shell --idle 30            # Leave after 30 minutes at the prompt without input (0, the default: never)
tacctl shell -c 'user list'       # Run one line and exit with its status
tacctl shell < commands.txt       # Run the lines in order; stop at the first non-zero status and exit with it
```

The shell runs as you and holds no privilege: each line runs as `sudo [-n] tacctl <words>` with the terminal attached, so sudo's rules and log, and the tier gate, apply to every line as they do from bash; prompts and password input work as usual. Tier users of the readonly and operator tiers (members of `tac-users`, who have no local password) get `sudo -n`, and a line their tier's sudoers rules do not cover is reported as not permitted; superusers (`tac-superuser`) get plain `sudo`, which asks for their network password on the terminal when a line needs it (once; sudo's cache applies), so their write verbs work from the shell. `hash` and `completion` lines run without sudo; `host` lines carry `SSH_AUTH_SOCK` as the re-exec does.

A line is split into words at blanks; single and double quotes and backslash quote as in `sh`, and nothing else is special — no variables, globbing, pipes, redirections, `;`, `$(...)`, backticks or `!`. Lines are at most 4096 bytes. The shell's own words are `help` (the top-level usage), `help <command>` (that family's usage), `history`, and `exit`/`quit` (or Ctrl-D). After a non-zero status the shell prints `[exit N]`.

Keys: Tab completes commands, flags and live names (asked of `sudo -n tacctl _completion-names`, kept 5 s); a second Tab lists the matching words alone, in columns that fit the terminal. `?` inserts nothing and shows help for the cursor's position: where words can come, `Possible completions:` with each one's argument column and description (devices and hosts with vendor, address and scope); after a command that takes arguments, its usage lines, its options and what comes next (`Next: <username> <group>`, `Next: <Enter> to run`). Inside quotes, or after a backslash (`\?`), `?` is typed as a character. A list of more than 40 entries asks first (`Show all 45 devices? [y/N]`): `y` shows it, any other key (or Ctrl-C) prints how to narrow it and gives the line back. Help from `?` taller than the terminal is shown a screenful at a time (`-- more (Space: page, Enter: line, q: quit) --`; `q` or Ctrl-C stops). Up/Down walk the history, Ctrl-R searches it (Ctrl-R again: older; Enter runs; Ctrl-G restores the line). Esc-b/Esc-f (Alt-Left/Right) move by word; Home/End, Ctrl-A/E/K/U/W/T/L as usual. A paste is one line (newlines become blanks, at most 4096 bytes) and runs only on Enter. Ctrl-C discards the line, or ends the running command; Ctrl-Z and Ctrl-\ do nothing (no job control, inherited by the commands).

History lives in `~/.local/state/tacctl/history` (0600, newest 1000 lines). Lines are stored redacted: everything after `--secret`, `--hash`, `--password`, after `set` in `secret … set`, after `import` with a value, and after the word of a `passwd` line becomes `…(redacted)` (`scope secret lab set x` → `scope secret lab set …(redacted)`); a recalled redacted line is refused. Lines ended with Ctrl-C are not stored; batch input is never stored. In a batch (`tacctl shell < file`) the commands get no stdin, so questions cannot be answered from the file — use `-y` where a command has it. Over ssh, ask for a terminal to get the interactive shell: `ssh -t <host> tacctl shell`; without `-t` ssh allocates none, the shell reads commands from standard input, and it says so on stderr.

### User Commands — `tacctl user`

```
user list                                         List all users (name, group, status, pw age, scopes)
user show <name>                                  Show user details incl. scope membership and last login (no password prompt)
user add <name> <group>                           Add a new user; lands in default scope. Reserved names `root` and `tacquito` are rejected (they collide with OS accounts tacquito resolves locally).
user add <name> <group> --scopes <name>[,name...] Grant specific scopes at creation
user add <name> <group> --hash <hash>             Add user with pre-generated bcrypt hash
user remove <name>                                Remove a user (with confirmation)
user passwd <name>                                Change password (with confirmation)
passwd                                            Change your own password (asks for the current one; all tiers)
user passwd <name> --hash <hash>                  Change password with pre-generated bcrypt hash
user disable <name>                               Disable (preserves hash for re-enable)
user enable <name>                                Re-enable a disabled user
user rename <old> <new>                           Rename a user
user move <name> <group>                          Move user to a different group (keeps password)
user verify <name>                                Show user details and verify password
user scope <name>                                 List the user's scopes (orphan refs flagged red)
user scope <name> add <s>[,s...]                  Grant one or more scopes
user scope <name> remove <s>[,s...]               Revoke one or more scopes
user scope <name> replace <s>[,s...]              Replace the full scope list
user scope <name> remove --all                    Revoke every scope (with confirmation)
```

### Group Commands — `tacctl group`

```
group list                                                List all groups with Cisco priv-lvl, Juniper class, user count
group add <name> <priv-lvl> <class>                       Add a custom group
group edit <name> priv-lvl <0-15>                         Change Cisco privilege level
group edit <name> juniper-class <CLASS>                   Change Juniper class name
group remove <name>                                       Remove a custom group (built-ins protected)
group commands list <group>                               Show per-command rules + default action
group commands default <group> <permit|deny>              Set default action (catchall)
group commands add <group> <name> [--match <regex>]...    Add a command rule
                                  [--action permit|deny]
group commands remove <group> <name>                      Drop a rule
group commands clear <group>                              Wipe rules for a group
group commands seed [<group>] [--force]                   Populate built-ins with sensible defaults
group privilege list <group>                              Show Cisco priv-exec mappings
group privilege add <group> '<cmd>'[,'<cmd>'...]          Move one or more commands to the group's priv-lvl
group privilege remove <group> '<cmd>'[,'<cmd>'...]       Remove one or more mappings
group privilege clear <group>                             Wipe explicit mappings (revert to defaults)
group privilege seed [<group>] [--force]                  Populate built-ins with safe priv-exec defaults
```

**Default Groups:**

| Group | Cisco priv-lvl | Juniper class | WTI access level | Use Case |
|-------|---------------|---------------|------------------|----------|
| `readonly` | 1 | RO-CLASS | ViewOnly | Monitoring, read-only |
| `operator` | 7 | OP-CLASS | User | Operational (show, ping, traceroute) |
| `superuser` | 15 | RW-CLASS | Administrator | Full administrative access |

The WTI column is derived from the Cisco priv-lvl (WTI bands: 0-4 ViewOnly, 5-9 User, 10-14 SuperUser, 15 Administrator); a group at priv-lvl 10-14 is the only way to land in the SuperUser band. Over RADIUS the same values travel as `Cisco-AVPair`, `Juniper-Local-User-Name` and `WTI-Super`, where the scope sends them.

### Config Commands — `tacctl config`

```
config show                                 Show current configuration summary incl. per-scope breakdown and each backend's listeners
config dump                                 Show tacctl defaults + overrides + merged view
config defaults                             Print canonical tacctl defaults (built into tacctl)
config get <path> [fallback]                Read a dotted-path value from the merged config
config get-list <path>                      Read a list value (one item per line)
config cisco [--scope <name>] [--legacy] [--protocol tacacs|radius]
                                            Generate working Cisco device config for a scope (default if omitted). --legacy emits IOS 12.x syntax (tacacs-server host / aaa group server ... / server <ip>) for devices predating the IOS 15.0 'tacacs server' block. --protocol radius (default: the scope's `auth-method`, else the one protocol its `protocols` filter names, else tacacs) renders the RADIUS configuration instead (see "RADIUS device configs" below)
config juniper [--scope <name>] [--protocol tacacs|radius]
                                            Generate working Juniper device config for a scope (default if omitted); --protocol radius as for cisco
config wti [--scope <name>] [--protocol tacacs|radius]
                                            Print the step-by-step serial-menu procedure for a WTI console server (firmware v8.x) with the scope's server IP, secret, and group→access-level mapping filled in; --protocol as for cisco (the RADIUS walkthrough is not verified on a unit)
config render [--force]                     Regenerate every enabled backend's config from the store and tacctl.yaml, all or none, and restart the ones that changed (needs the store; refuses to overwrite a hand-edited file unless --force, which first saves it under backups/legacy/)
config render --dry-run --out <dir>         Render every enabled backend into a new, empty directory at the live paths; nothing live is written, no restart
config validate                             Validate the store, tacctl.yaml (schema walk, incl. commands.<group> / privileges.<group> / mgmt_acl.* / listeners) and the server-config structure (orphan scope refs, scope.default pointing at a nonexistent scope, reserved usernames, missing accounter:), then each enabled backend: rendered config up to date, drift; RADIUS scopes that send no vendor attribute. Exits 1 on errors
config diff [timestamp]                     Alias of `backup diff`
config restore <timestamp> [--legacy]       Alias of `backup restore`
config loglevel [debug|info|error]          Show or change the TACACS+ log level
config listen [--backend <id>] [--listener <name>] [show|tcp|tcp6|udp|udp6|reset] [addr]
                                            Show, change, or reset a listen address (default: the TACACS+ listener 'default'; see "Listeners")
config metrics <show|enable|disable|address <host:port>|reset>   Prometheus exporter control (TACACS+). Default: loopback-only 127.0.0.1:8080. `disable` sinks to 127.0.0.1:0 (unreachable ephemeral port) since tacquito's own disable flag would crash the server.
config linux build|script|remove-script|uid|uid-range|builds   Login for Linux hosts (see "Host Commands")
config linux script [--scope <name>] [--server <address>] [--method tacplus|radius] [--output <file>]
                                            Write the install script for hosts in a scope (contains the secret)
config linux remove-script [--output <file>]  Write the removal script (no secrets; removes either method)
config linux uid [<user> [<uid>]]           Show or change the UID a user gets on every host
config linux uid-range [<min>-<max>]        Show or change the UID range of all hosts (default 80000-89999)
config linux builds [list|clear]            Show or drop the pam_tacplus modules 'host enroll' built in containers
config sudoers [show|install|remove] [grp]  Manage NOPASSWD sudoers drop-in for tacctl
config sudoers tiers [show|install|remove]  Manage per-tier (RO/OP/SU) sudoers rules for tacctl users with local accounts
config password-age [days]                  Show or set password age warning threshold (default 90)
config bcrypt-cost [10-14]                  Show or set bcrypt cost factor for new hashes (default 12)
config password-min-length [8-64]           Show or set minimum interactive password length (default 12)
config secret-min-length [16-128]           Show or set minimum shared-secret length (default 16)
config allow list|add|remove|clear          Manage connection allow list (IP ACL; add/remove accept comma-lists)
config deny list|add|remove|clear           Manage connection deny list (IP ACL; add/remove accept comma-lists)
config mgmt-acl list|add|remove|clear       Manage Cisco VTY-ACL + Juniper lo0-filter permits (add/remove accept comma-lists)
config mgmt-acl cisco-name [name]           Show or set the emitted Cisco ACL name (default VTY-ACL)
config mgmt-acl juniper-name [name]         Show or set the emitted Juniper filter name (default MGMT-ACL)
config branch [name]                        Show or change the tacctl repo branch
```

#### Configuration tunables — `tacctl.yaml`

tacctl ships canonical tunable defaults, built into the binary (printed by `tacctl config defaults`). Operator overrides live in a single file: `/etc/tacctl/tacctl.yaml`. Only list keys you want to change; missing keys inherit from the defaults. Setting a key back to the default value removes it (revert-to-default) and an empty overrides file is pruned.

Schema (what `tacctl config defaults` prints):

```yaml
password:
  max_age_days: 90           # warning threshold in `tacctl status`  (int, >= 1)
  min_length: 12             # floor for interactively-typed passwords  (int, 8..64)

secret:
  min_length: 16             # floor for operator-typed shared secrets  (int, 16..128)

bcrypt:
  cost: 12                   # applies only to new hashes  (int, 10..14)

scope:
  default: lab               # matches the fresh-install seed scope; override via `tacctl scope default`

host:
  default_method: tacplus    # how `tacctl host enroll` sets up a new Linux host: tacplus | radius

mgmt_acl:
  names:
    cisco: VTY-ACL           # ACL name emitted by `tacctl config cisco`  (letter-start, [A-Za-z0-9_-], 1..63)
    juniper: MGMT-ACL    # filter name emitted by `tacctl config juniper`  (same rules)
  permits: []                # list of CIDRs; each element validated

privileges:                  # per-group Cisco priv-exec lowering (move commands DOWN from priv 15)
  operator:
    - show running-config
    - show startup-config
    - show tech-support
    - show archive
    - show access-list
    - show ip route

commands:                    # per-group command-authz rules. Rendered for both Cisco
                             # (tacquito enforces) and Juniper (class allow/deny-commands)
                             # from this single tacctl-authored source. Ordered
                             # superuser → operator → readonly. Not enforced over RADIUS.
  superuser:
    - { name: "*", action: permit }
  operator:
    - { name: show,       action: permit }
    - { name: ping,       action: permit }
    - { name: traceroute, action: permit }
    - { name: terminal,   action: permit }
    - { name: "*",        action: deny }
  readonly:
    - { name: show,       action: permit }
    - { name: ping,       action: permit }
    - { name: traceroute, action: permit }
    - { name: "*",        action: deny }
```

Keys without a shipped default, written by their commands: `backends.enabled` (`backend enable|disable`), `backends.tacacs.level` / `backends.tacacs.metrics_address` (`config loglevel|metrics`), `listeners.<backend>.<name>` (`config listen`), and per scope `aaa.order`, `exec_timeout`, `tacacs_group`, `radius_group`, `scope_auth_method`, `scope_mgmt_acl.*`.

Merge semantics:
- Maps deep-merge (overriding `password.max_age_days` keeps the default `password.min_length`).
- Lists replace wholesale (an override list does not concatenate with the default list).
- Scalars replace.

**Write-time validation.** Every `tacctl config <setter>` invocation checks the value against a schema table defined next to the defaults. Out-of-range numbers, bad ACL names, malformed CIDRs, invalid Cisco command strings, colliding or malformed listeners, and typo'd keys are rejected with a clear error before anything is written. `tacctl config validate` runs the same schema over `tacctl.yaml` to catch hand-edits.

**A `tacctl.yaml` that does not parse** is never written into: every setter refuses with `tacctl.yaml: could not parse <path>: line L, column C: <problem>` and exits non-zero, leaving the file and every setting in it as they are. Commands that only read carry on with the defaults and say so once, on stderr. Fix or remove the file; `tacctl config validate` reports the same line. A change to users, groups or scopes is refused as well, since every backend's config is rendered from the file.

**Read path caching.** Every read merges defaults + overrides and walks the dotted path, but the merged view is cached for the duration of one command. Commands that touch many tunables (`config cisco`, `status`, `config show`) load the merged YAML once and then answer from memory. Writes invalidate the cache.

View effective posture with `tacctl config dump`; read individual values with `tacctl config get <path>` / `tacctl config get-list <path>`.

### Scope Commands — `tacctl scope`

```
scope list                                               One row per scope (deduplicated; prefixes joined)
scope routing                                            One row per (scope, prefix) — first-match order
scope show <name>                                        Full detail: prefixes, users, secret length + posture (the value: `scope secret <name> show`), default-ness, protocols, auth-method, vendor attributes, tagged addresses
scope add <name> --prefixes <cidrs>                      Create a new scope
          [--secret <value>|--secret generate] [--protocols <csv>] [--vendor-attrs <csv>] [--default]
scope remove <name> [--force]                            Delete. Refuses if users reference it unless --force
scope rename <old> <new>                                 Rewrites every user's scopes[], the default marker and every per-scope setting
scope default [<name>]                                   Show / set the default scope
scope lookup <ip|cidr>                                   Resolve an IP/CIDR to the owning scope (+ shadowed overlaps, + its vendor tag)
scope prefixes <name> list|add|remove <cidrs>            Per-scope CIDR list (add/remove accept comma-lists; the last prefix cannot be removed this way)
scope prefixes <name> remove --all [--force]             Remove every prefix, which removes the scope (confirms; refuses if users reference it unless --force, which strips it from them)
scope secret   <name> show|set <value>|generate          Per-scope shared secret (show prints the raw value + length/posture)
scope protocols <name> list|set <csv>|clear              Limit the scope to some protocols (tacacs, radius). A filter: empty (`clear`) means every enabled backend serves it
scope vendor-attrs <name> [enable|disable <csv>]         RADIUS: the vendors (cisco, juniper, wti) whose privilege attribute an Access-Accept carries for the scope's devices. Opt-in: a new scope sends none ("not sent"); its verbs are enable and disable. Stored in store.yaml, so a change re-renders and restarts the RADIUS backend. TACACS+ is not affected. See "What an Access-Accept carries"
scope devices <name> [list|set <ip|cidr> <vendor>|unset <ip|cidr>]  RADIUS: tag an address (a bare IP is a /32) of the scope with its vendor: it gets that vendor's attribute and no other, whatever the scope enables. The address must be one `scope lookup` answers with this scope. `scope prefixes remove` refuses to leave a tag outside the scope's prefixes; tags go with the scope on rename and remove. Shown by `scope show` and `scope lookup`
scope aaa-order <name> [tacacs-first|local-first]        Order of the server vs local in this scope's generated Cisco / Junos AAA lines (TACACS+ and RADIUS). Default `tacacs-first` keeps the server authoritative (local only kicks in on server outage). Set `local-first` when a break-glass local account must authenticate while the server is still reachable — any local name that collides with a server user wins locally, so scope local accounts to emergency credentials only.
scope exec-timeout <name> [minutes]                      Per-scope idle-session timeout for this scope's generated device configs. Cisco renders `exec-timeout <n> 0` on `line con 0` / `line vty 0 15`; Junos renders `set system login idle-timeout <n>`. Range 0..60 (Junos's max); `0` disables idle expiry on both vendors. Default 60.
scope tacacs-group <name> [label]                        Per-scope Cisco `aaa group server tacacs+ <LABEL>` name. Rendered into every AAA group + method-list line for that scope. Must conform to Cisco ACL naming rules (letter-start, letters/digits/_/-). Default `TACACS-GROUP`. Junos has no equivalent.
scope radius-group <name> [label]                        The RADIUS twin of `tacacs-group`: the Cisco `aaa group server radius <LABEL>` name rendered by `config cisco --protocol radius`. Same naming rules. Default `RADIUS-GROUP`.
scope auth-method <name> [tacacs|radius|clear]           The protocol this scope uses when a command names none: `config cisco|juniper|wti` without `--protocol`, and `host enroll` (a host not registered yet) / `config linux script` without `--method` (`tacacs` is host method `tacplus`, which is accepted here too). The order: `--protocol` / `--method`; a registered host's own method; this setting; the one protocol the scope's `protocols` filter names, when it names exactly one; the global default (device configs: TACACS+; hosts: `host default-method`). `clear` removes the setting (`default` is accepted for it). Refused when the scope's `protocols` filter leaves the protocol out, and `scope protocols <name> set` refuses a list without it. `config cisco --legacy` on a scope that resolves to RADIUS needs `--protocol tacacs`. Shown by `scope show`.
scope mgmt-acl <name> list|add|remove|clear [cidrs]      Per-scope permit list. Mirrors the global `tacctl config mgmt-acl list|add|remove|clear`. Falls back to the global `mgmt_acl.permits` when this scope's list is empty, so per-scope use is reserved for scopes that genuinely need different permits than the house default. `clear` unsets the per-scope override (renders fall back to global).
scope mgmt-acl <name> cisco-name|juniper-name [label]    Per-scope mgmt-acl / filter name. Mirrors the global `tacctl config mgmt-acl cisco-name|juniper-name`. Cisco renders `ip access-list standard <LABEL>` + `access-class <LABEL> in`; Junos renders `set firewall family inet filter <LABEL>` + lo0 filter apply. Fallback chain: per-scope override → global (`tacctl config mgmt-acl …`) → shipped default (`VTY-ACL` / `MGMT-ACL`).
```

**Connection filters:** `deny` takes precedence over `allow`. Both empty = all connections accepted.

**Settings stored under a scope's name** in `tacctl.yaml` (`aaa.order`, `exec_timeout`, `tacacs_group`, `radius_group`, `scope_auth_method`, `scope_mgmt_acl.names.cisco|juniper`, `scope_mgmt_acl.permits`) follow the scope on `scope rename` and are removed with it by `scope remove` (and `scope prefixes remove --all`), so a new scope of the same name starts from the defaults. Its `protocols`, `vendor-attrs` and `devices` are part of its entry in `store.yaml` and do the same.

### Host Commands — `tacctl host`

```
host list                                   Show enrolled Linux hosts (target, scope, server, METHOD, users)
host enroll <[user@]host>|--local [opts]    Install TACACS+ or RADIUS login on a host over SSH and register it
      --method tacplus|radius               pam_tacplus (TACACS+) or pam_radius_auth (RADIUS); re-enroll with the other to switch
      --scope <name>                        The host's scope (default: its registered one, else the scope covering its address)
      --server <address>                    Address the host should use for this server (default: detected)
      --name <name>                         Registry name (default: short hostname)
      --port <n>, --identity <file>         SSH port and key
      --build-on-host                       (tacplus) compile pam_tacplus on the host instead of in a container here
      --yes                                 (enroll and move) Move a registered host to another scope even when that deletes accounts
      --staging                             (with --scope) Provisioned off-site: the bench address joins the scope as a /32 until the host is seen in place
host sync <name>|--all                      Push account adds, deletions, expiries and tier changes; pins the host's ssh keys if none are (enroll pins them too)
      --allow-uid-mismatch                  (enroll and sync) accept a UID conflict on the host instead of stopping
      --remove-home                         (enroll and sync) delete removed users' home directories without asking (on a terminal each is asked; without one they are kept)
host move <name> [<scope>]|--all            Move an enrolled host to another scope (default: the one answering its address; --all: every host another scope answers); asks before deleting accounts
host unenroll <name> [--force]              Remove the login method from the host (accounts are kept) and its pinned host keys; --force drops it from the registry even if the removal fails
host default-method [tacplus|radius]        Show or set the method for hosts enrolled without --method (host.default_method)
```

### Device Commands — `tacctl device`

The device registry gives names to the network devices that authenticate here. It lives in `/etc/tacctl/devices.yaml` and never touches `store.yaml`: a device's scope and vendor tag are looked up from the store when shown, so registering a device renders nothing and restarts nothing. Every write takes a snapshot first.

```
device list [--stale] [--unconfigured] [--scan] [--probe] [--json]   Registered devices, then enrolled hosts: scope, STATE (configured: a scope's prefixes cover the address; unconfigured; stale), last seen / by / via from the seen cache, open notices; --scan scans first, --probe adds REACH (TCP connect to the ssh port, 3 s)
device show <name|address> [--all] [--json]       One entry in full (scope and routing prefix, shadowed scopes, vendor tag, pinned keys, sightings and NAS-Identifier, the open notices and how many are acknowledged; --all lists the acknowledged ones too, marked)
device add <name> <address>                       Register a device (writes: administrators only)
      --vendor cisco|juniper|wti|other            Default other; drives the ssh profile, never tags the address in the scope
      --hostname <dns>, --port <n>, --description <text>, --legacy-ssh
      --host-key SHA256:<fp>                      Register only if the device offers a key with this fingerprint; pin that key alone
      --no-host-key                               Register without scanning: unpinned, with a hostkey-unpinned notice
      --allow-generic                             Register a generic name (switch, router, cisco, ubuntu, ...) anyway
device remove <name>[,<name>...] | --all [-y]     Remove from the registry (confirms; hosts, scopes and vendor tags are not touched)
device rename <old> <new> [--allow-generic]
device address|hostname|vendor|port|description <name> [<value>|clear]   Show, set or clear one field
device legacy-ssh <name> [enable|disable]         Opt in to the legacy IOS ssh algorithms
device stale-days [<n>]                           Days without a sighting after which a device is stale (default 30)
device notice <name> ack|unack <kind>             Acknowledge or reopen a notice
device notices [<name>] [--all]                   The open notices, each with the command that fixes or acknowledges it (--all: the acknowledged ones too, marked)
device import [--check] [--replace] [--allow-generic] [-y] <file|->   CSV (name,address[,vendor[,port[,description]]]) or the registry's YAML; merges by default
device export [--csv|--json]                      The registry (YAML by default), only the devices of your own scopes below the administrator tier
device hostkey <name> [show]                      The pinned ssh host-key fingerprints of a device or enrolled host (administrators)
device hostkey <name> accept [-y]                 Re-scan and pin every key it offers, after confirmation (verify on the console first)
device hostkey <name> set SHA256:<fp>             Re-scan and pin only the key with this fingerprint
device ssh <name|address> [-p <port>] [-X|-Y] [-L|-R|-D <spec>]... [-- <ssh args>]   Same as tacctl ssh
device ssh-config                                 Print an ssh_config Include for your devices (Host blocks with the vendor options and the pin)
device scan [--full] [--since <dur>] [--backend <id>]   Read the backends' logs into the seen cache from where the last scan stopped; re-scan pinned host keys (never re-pins); print each log's window and the notices
device discover [--all] [--backend <id>]          Scan, then list the addresses that authenticated unregistered, each with a ready 'tacctl device add' line; --all adds those only refused
device check <name>|--all                         Checklist: scope, vendor tag, last seen, reachable (TCP connect, 3 s), host key against the pin, notices
```

A device is found by name (any case) or by its registered address; an unregistered address is not found, even when a scope covers it. An address is registered once. Enrolled Linux hosts share the namespace and appear in `list` and `show` as `linux` entries, read-only. `list`, `show`, `notices`, `ssh-config` and `tacctl ssh` are open to the read-only and operator tiers, limited to the entries of their own scopes (`tacctl ssh` is limited so for every tier); `export` is operator-level, filtered the same way.

A name that is a factory or image default is refused with the command that names the device on the device itself (`hostname`, `set system host-name`, ...); a host enrolled under such a name before the registry existed is not refused and carries a `generic-name` notice. `host enroll --name` follows the same rules. Add your own patterns with `generic_names:` (regular expressions, whole-name, case-insensitive) in `devices.yaml`.

**Seen data.** `device scan` reads what the daemons logged about each device into `/var/lib/tacctl/devices-seen.json` (0600, a cache: never snapshotted, `--full` rebuilds it): the tacquito journal (`journalctl -u tacquito … -o json`, resuming at its cursor; the `accepting user [u] from [address]` / `failed to validate the user [u] from [address]` lines, `bad secret detected for ip [address:port]`, `remote [address:port] has no secret providers` (no scope covers the address), and at log level 30 `prefix secret provider matches remote [address]`) and FreeRADIUS's `tacctl-auth.log` with its rotations (`client=`, `nas=`, `user=`, resuming by inode and offset). The first scan reads the last `stale-days` days; `--full` everything the logs hold, `--since 7d` that stretch. Per address it keeps the first and last sighting, the count, the last user, outcome and backend and the NAS-Identifier; records unseen for twice `stale-days` are dropped. `list` and `show` read the cache only (`seen data as of <time>`); LAST SEEN is `rejected <time> (bad secret)` when the last exchange was refused. `check` and `list --probe` connect to the ssh port: the server often has no route to management ports, so a timeout may be a false alarm. `scan`, `discover` and `check` are operator-level.

**Notices** are computed when shown (only acknowledgements are stored) and appear in `scan`/`discover` output, a `Device notices` section of `tacctl status` (count and the first five), `device list` (NOTICES), `device notices`, and `device show` (which counts the acknowledged ones; `--all` on either lists them, marked). Besides `generic-name`, `hostkey-unpinned` and, for an enrolled host whose address changed between two enrolments or syncs, `address-changed` (the only notice an enrolled host acknowledges), a scan raises `ambiguous-nas-id` (one NAS-Identifier from several addresses), `generic-nas-id`, `name-mismatch` (informational), `duplicate-address` (two entries at one address, or an address identifying as another entry), `identity-changed` (an address's NAS-Identifier changed: replaced or reset?), and from the host-key re-scan `hostkey-changed` (cannot be acknowledged; only `device hostkey <name> accept|set` clears it), `hostkey-added` and `hostkey-unreachable`. Each line ends with the command that fixes or acknowledges it.

**Host keys.** `device add` reads the keys the device offers (`ssh-keyscan -T 5 -p <port> -t ed25519,ecdsa,rsa <address>`, as root; `legacy-ssh` devices are asked for `ssh-rsa` by name too), pins them in `devices.yaml` and prints each `SHA256:` fingerprint with the command that shows it on the device console (Cisco `show ip ssh`, Junos `file show /etc/ssh/ssh_host_ed25519_key.pub` from the CLI, or `ssh-keygen -lf` on the same file from `start shell`, Linux `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`); compare them before connecting (`tacctl device hostkey <name> show` prints each pinned key as an `ssh-ed25519 AAAA…` line as well, so a `file show` output can be compared by eye). A device that does not answer is refused unless `--no-host-key` is given. `host enroll` and `host sync` pin an enrolled host's keys the first time from two independent reads: the host's own public key files (`cat /etc/ssh/ssh_host_*_key.pub`, read-only, over the enrolment's ssh connection, which your own ssh checked against your known_hosts) and an `ssh-keyscan` of the target. Only keys both reads hold are pinned; a key type they disagree on refuses the pin (both sets are shown and `host hostkey-mismatch` is logged), a type only one of them has is reported and not pinned, and key files that cannot be read pin nothing. The enrolment or sync succeeds either way. A sync of a pinned host compares the session's keys with the pin, reports a difference and keeps the pin. The same connection gives the host's address: enroll and sync record the address the connection reached (the host's side of `SSH_CONNECTION`; `--local` records 127.0.0.1) in `devices.yaml`'s `hosts:` section, and warn when it differs from what the target's name resolves to. `device add` and `device address` refuse that address, `device show <address>` finds the host, sightings from it are the host's, and `device discover` does not list it; a sync that finds another address records it and raises `address-changed`. Only `device hostkey <name> accept|set` changes a pin. Every registry write regenerates `/var/lib/tacctl/ssh/known_hosts` (0644), one `<name> <type> <key>` line per pinned key, for `ssh -o UserKnownHostsFile=/var/lib/tacctl/ssh/known_hosts -o GlobalKnownHostsFile=none -o HostKeyAlias=<name> -o StrictHostKeyChecking=yes`.

**`tacctl ssh <name|address>`** opens an ssh session to a registered device or an enrolled host, as you: the name is resolved as root (the registry is root's), and only an active tacctl user (in the store, not disabled) whose scopes include the entry's may connect, at every tier, superusers included (`'jdoe' has no access to scope 'prod' (device core-sw1)`; a local account that is not a tacctl user, and an entry in no configured scope, are refused to everyone; each refusal is logged as `ssh DENY … reason=`). The session is logged (`ssh user=<you> device=<name> addr=<address>`, syslog auth.info), and ssh runs as the invoking user (`sudo -u <you> -H ssh …`), logging in as you by password: your tacctl password, checked by the device against this server; no agent, no key, no other login. An enrolled host's enrolment account and identity are never used. Its exit status is passed back. `-X`/`-Y` forward X11 to this server's display (the `DISPLAY` of an `ssh -X` login here, which sudo keeps for tacctl), and `-L`, `-R` and `-D` (repeatable) are ssh's port forwardings; the log line then carries `forward=x11,local,…`. In the login console they are for the tiers of `console forwarding tiers` only (default superuser; others get `ssh DENY … reason=forward`). Run as root itself it refuses (`tacctl ssh runs ssh as the user who invoked it; run it from your own account, not as root`); it needs a terminal. An unregistered address is refused with the `device add` command that registers it. The options per device:

| Device | ssh options |
|---|---|
| every one | `-o ConnectTimeout=10 -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password`; your username as the login; the device's hostname, else its address; its port (`-p`) unless given |
| `wti` | `PreferredAuthentications=password` instead (see WTI Console Servers) |
| `legacy-ssh` | `-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa` (old IOS; OpenSSH 8.5 or later) |
| pinned keys | `-o UserKnownHostsFile=/var/lib/tacctl/ssh/known_hosts -o GlobalKnownHostsFile=none -o StrictHostKeyChecking=yes -o HostKeyAlias=<name> -o UpdateHostKeys=no` |
| enrolled host | its target's host and its port |

An unpinned device is checked against your own known_hosts, after its `hostkey-unpinned` notice. Arguments after `--` follow the target, so ssh takes them as the remote command (`tacctl ssh core-sw1 -- show version`); they cannot replace an option. Each session is logged when it starts (`ssh user= device= addr=`) and when it ends (`ssh end user= device= status= duration=`).

From a login console session (each of its lines carries `TACCTL_CONSOLE=<session>`), `tacctl ssh` reads no ssh configuration file and opens nothing but the session: it adds `-F /dev/null -o PermitLocalCommand=no -o ControlMaster=no -o ClearAllForwardings=yes -o ForwardAgent=no`, `-o EscapeChar=none` unless `tacctl console ssh-escape enable`, and puts the target after `--`, so the words after the name's `--` are only ever the remote command (a first word starting with `-` is refused). A device or host with no pinned host key is refused: `'<name>' has no pinned host key, so the console does not connect to it; an administrator pins it: tacctl device hostkey <name> accept`. Its log lines end with `console=<session>`. When ssh fails with 255 on a pinned device whose key changed, tacctl prints the pinned and offered fingerprints, the console command that shows the key, and `tacctl device hostkey <name> accept|set`.

`tacctl device ssh-config > ~/.ssh/tacctl.conf`, with `Include ~/.ssh/tacctl.conf` at the top of `~/.ssh/config`, gives a plain `ssh <name>` the same options and pin (one `Host` block per device you may see, with `PubkeyAuthentication no` and the password methods and no `User` line: ssh logs in with your local username, which for a tacctl user is the tacctl name; print-only, re-run after registry changes).

```yaml
# /etc/tacctl/devices.yaml
version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco, legacy_ssh: true, description: DC1 core}
  lab-rtr2: {address: 192.0.2.7, vendor: juniper, hostname: lab-rtr2.lab.example.net}
```

### Console Commands — `tacctl console`

The login console is the login shell of tacctl users on the tacctl server: tacctl commands and ssh to registered devices, nothing else. Its model is `/etc/tacctl/console.yaml` (0600, snapshotted, in `backup diff` and `restore`; absent means the defaults): the console is on for every tier, a user override wins over the tier's switch, and local accounts that are not tacctl users are never touched. The settings commands change that file only (after a snapshot); they never change an account or sshd. The accounts' login shells and sshd's drop-in follow it when this server's accounts are synced (`tacctl host sync <name of the host enrolled with --local>`), which every change to a tier switch, a user override or agent forwarding prints. The idle timeout, the ssh escape and the system shell are read by each console session when it starts.

```yaml
version: 1
tiers: {readonly: enable, operator: enable, superuser: enable}
users: {jdoe: disable}            # per-user override: enable or disable
settings:
  idle_timeout: 30                # minutes at the prompt; 0 = never
  agent_forwarding: false
  ssh_escape: false
  system_shell: /bin/bash
  system_shell_tiers: [superuser]
  list_max: 40                    # completions the shell lists without asking
```

```
console show                                      Tiers, settings, each user of this server's scope with its effective shell and why, and the server's pieces (operator tier and up)
console tiers [<tier> enable|disable]             Show or switch the console for readonly, operator or superuser
console user <name> [enable|disable|clear]        Show or set one user's override (clear: the tier decides)
console idle-timeout [<min>]                      Minutes idle before the session ends, 0-1440 (default 30, 0 = never)
console agent-forwarding [enable|disable]         Opt in to agent forwarding for console users (default disabled)
console ssh-escape [enable|disable]               Opt in to ssh's ~. and ~C in the console's ssh (default disabled)
console forwarding tiers [<csv>|none]             Tiers that may forward X11 and TCP ports: sshd, and ssh -X/-Y/-L/-R/-D to a device in the console (default superuser)
console system-shell tiers [<csv>|none]           Tiers that may start their system shell from the console (default superuser)
console system-shell path [<path>]                The system shell (default /bin/bash; absolute, executable, listed in /etc/shells)
console install                                   Put the /etc/shells line and sshd's drop-in in place (host sync of this server does too), then check
console remove                                    Take them away (refused while an account has the console as its shell)
console check                                     Whether sshd applies the console's settings to its users; exit 1 and a red warning when not (operator tier and up)
```

`console show` lists the users of the scope of the host enrolled with `--local` with `console (user override)`, `console (tier readonly)` or `bash (tier readonly disabled)`, then the server's pieces: the `/usr/local/bin/tacctl-console` symlink, the `/etc/shells` line, sshd's drop-in and what `sshd -T -C user=<user>` reports for a console user (`allowtcpforwarding`, `allowagentforwarding`, `forcecommand`, `pubkeyauthentication`). It warns in red when the drop-in is missing, sshd does not force the console, still allows forwarding, or allows key logins, because a console user could then forward ports past the device registry, run programs or sftp, or log in without TACACS+. A server that is not enrolled with `--local` says so.

#### The console session — `tacctl-console`

`/usr/local/bin/tacctl-console` is a symlink to the tacctl binary; started under that name (sshd starts a login shell as `-tacctl-console`, and with the drop-in's `ForceCommand` every login as `tacctl-console -c /usr/local/bin/tacctl-console`, the client's command in `SSH_ORIGINAL_COMMAND`) it is the console: `tacctl shell` with the prompt `<host>> ` and the banner `tacctl console on <host> — type 'help'. Devices: device list. This session is logged.`, running every line as `sudo [-n] TACCTL_CONSOLE=<session> /usr/local/bin/tacctl <words>` (`-n` by the shell's rule: readonly and operator; superusers are asked for their network password) and starting nothing else. The login environment is discarded except `TERM`, `LANG`, `LC_*`, `HOME`, `USER`, `LOGNAME`, `SSH_CONNECTION`, `SSH_CLIENT` and `SSH_TTY`; `PATH` is `/usr/local/bin:/usr/bin:/bin`. The session asks the server for its settings once (`sudo -n tacctl _console-policy`; without an answer: 30 minutes idle, no system shell) and ends after the idle timeout at the prompt (not while a line runs).

```
ssh carol@authsrv                 # The console: prompt 'authsrv> ', Tab, ?, history, help
ssh carol@authsrv 'user list'     # One tacctl line (sshd passes it as -c), logged; no terminal needed
ssh carol@authsrv < lines.txt     # The lines as a batch; stops at the first failure
```

`-c` accepts one line that starts with a tacctl command or `help`. Everything else — `scp`, `sftp`, `rsync`, any program, the shell's own words, an empty string — is refused with `the tacctl console does not run programs; file transfer is not available` (exit 126) and nothing runs; so is any other argument (`the tacctl console takes no options`).

`system-shell` (the console's own word, at the prompt only) starts the user's system shell (`console system-shell path`, default `/bin/bash`) as the user, without arguments, with the console's environment and `SHELL=<path>`; the idle timer does not run meanwhile and sshd's drop-in still applies; `exit` returns to the console (`back in the tacctl console`). It is open to the tiers of `console system-shell tiers` (default: superusers only); for anyone else it is refused with `system-shell is not available for the <tier> tier on this console. An administrator enables it with: tacctl console system-shell tiers …` (status 1), and through `-c` or in a batch with status 126.

Logged to syslog with the tag `tacctl-console`: `console start session= user= from= tty= mode=interactive|command|batch`, `console end session= user= reason=exit|eof|idle|hangup|signal|command|failed lines= status=`, `console DENY session= user= reason=command first=<word>` (auth.warning), `console system-shell start|end|DENY` (with `status=` and `duration=` at the end). Every line is in sudo's own log too, and `tacctl ssh` logs `console=<session>`.

### Backend Commands — `tacctl backend`

```
backend list                Every backend: protocol, implementation, installed, enabled, service
backend status [<id>]       Service and listener state of every backend (or one)
backend enable <id> [-y]    Install the backend if needed, enable it, render its config, start it
backend disable <id> [-y]   Stop and disable it, take it out of backends.enabled (confirms); its package and rendered files stay
```

### Store Commands — `tacctl store`

```
store show [--json]                          Print the model (users, groups, scopes, filters); superuser-only (secrets, hashes)
store import [--check|--force] [--replace] [<file>]
                                             Import an old-style tacquito.yaml (default: the live one). --check writes nothing and
                                             proves equivalence; --force drops what the store cannot represent; --replace overwrites a store
store rollback                               Restore the pre-store tacquito.yaml, remove the store, restart (legacy read-only mode)
```

### Log Commands — `tacctl log`

```
log tail [-f] [n] [--backend <id>]  Last N entries (default 20): TACACS+ journal; RADIUS auth log and daemon log; -f follows new ones until Ctrl-C
log search <term> [--backend <id>]  Search the logs for a username or keyword (TACACS+: last 7 days)
log failures [--backend <id>]       Auth failures from the last 24 hours
log accounting [n] [--backend <id>] Last N accounting records
log clear [--force|-y] [--backend <id>]  Purge the TACACS+ journal and truncate the accounting logs; truncate the RADIUS auth, accounting and daemon logs (prompts)
```

With more than one backend enabled each subcommand shows every backend's log in a section headed by its name; `--backend <id>` (anywhere on the line) shows one.

### Backup Commands — `tacctl backup`

```
backup list                    Show snapshots (newest first), then old-style backups
backup diff [timestamp]        Diff store.yaml and tacctl.yaml against a snapshot (default: most recent)
backup restore <ts> [--legacy] Restore a snapshot (with confirmation); --legacy for an old-style backup
```

A backup is a snapshot of the canonical files, `/etc/tacctl/backups/<timestamp>/{store.yaml,tacctl.yaml,manifest}`, taken automatically before every change that would alter them (nothing is added when they already equal the newest snapshot). The manifest records `rendered.json` and the tacctl version. The newest 30 snapshots are kept. Snapshots hold shared secrets and password hashes: the directory is `0700`, the files `0600`, and `backup diff` and `backup restore` are superuser-only.

`backup restore <ts>` puts back both files, re-renders every enabled backend's config (a hand-edited file is kept under `backups/legacy/` first), and restarts the backends. It snapshots the current state first, so a restore can be undone with another restore, and it changes nothing if the snapshot is invalid or the render fails. The snapshot's `backends.enabled` comes back with the rest of `tacctl.yaml`: a backend it enables must already be installed (otherwise nothing changes and the message says to run `backend enable`) and is started; one it leaves out is stopped and disabled.

Old-style `tacquito.yaml.<timestamp>` files (made before the store existed, or kept in `backups/legacy/`) are listed after the snapshots. `backup restore <timestamp> --legacy` runs `store import --check` on one, then imports it. Without a store (legacy read-only mode) `list`, `diff` and `restore` work on those files as before.

---

## Network Device Configuration

Use `tacctl config cisco` or `tacctl config juniper` to generate
copy-pasteable configs with your server's IP and shared secret pre-filled,
or `tacctl config wti` for a menu-by-menu walkthrough of a WTI console server.
Each takes `--protocol tacacs|radius`; without it the output follows the scope (see [Which protocol a scope uses](#which-protocol-a-scope-uses)), and is TACACS+ otherwise.

### Cisco IOS / IOS-XE

The generated config includes AAA setup, TACACS+ server definition, and operator
privilege level command mappings. All groups and their privilege levels are included
dynamically.

**Key points:**
- `local` fallback ensures access if TACACS+ is unreachable
- Custom privilege levels (2-14) require `privilege exec level` command mappings
- Use `config cisco` to regenerate after adding groups
- By default the output uses the modern IOS 15.0+ `tacacs server <name>` block. For older devices
  (e.g. IOS 12.4), add `--legacy` to emit the global `tacacs-server host` / `aaa group server ... / server <ip>`
  syntax instead. Only the server-definition block changes; the AAA, privilege, and line config are identical.

### Juniper Junos

The generated config includes template user creation, TACACS+ server setup, and
verification commands. All groups and their Juniper classes are included dynamically.

**Key points:**
- Template users MUST exist before TACACS+ logins will work
- If a login fails silently after successful TACACS+ auth, the template user is missing
- Use `config juniper` to regenerate after adding groups

### RADIUS device configs (`--protocol radius`)

`tacctl config cisco|juniper|wti --protocol radius` renders the configuration for logging in to a device against this server's RADIUS backend (`tacctl backend enable radius`). The server address, the authentication and accounting ports (the `auth` and `acct` RADIUS listeners; `tacctl config listen --backend radius show`) and the scope's shared secret are filled in; the management ACL, exec timeout, `aaa-order` (the server first, or local first) and the local fallback behave as in the TACACS+ output.

- **Cisco** gets a `radius server RADIUS` block, `aaa group server radius <radius-group>` (see `scope radius-group`), `aaa authentication login`, `aaa authorization exec` (the privilege level comes from `Cisco-AVPair = "shell:priv-lvl=N"`, which the scope must send: see [What an Access-Accept carries](#what-an-access-accept-carries)) and `aaa accounting exec`, plus the same `privilege exec level` mappings. `--legacy` (IOS 12.x) is TACACS+ only.
- **Juniper** gets `system radius-server` (explicit ports), `authentication-order radius` (or `[ password radius ]`), `system accounting destination radius`, the template users the server maps logins to with `Juniper-Local-User-Name`, and the same per-class `allow-commands`/`deny-commands` rules, which stay in force because the class is local to the device.
- **What the Access-Accept carries for the device, and what is lost compared with TACACS+** is printed under every RADIUS config: `Service-Type` and the vendor's attribute (and whether the scope enables it or only tagged addresses get it); no per-command authorization (the only authorization is the privilege level, login class or access level in the Access-Accept; `tacctl group commands` rules are not enforced by the server), no command accounting (exec/login events only), PAP only, and UDP instead of TCP/49.
- **Refused, with an error and no output:** the RADIUS backend not enabled; a scope whose `scope protocols` filter leaves out `radius` (the daemon would ignore its devices); a scope that sends the vendor's attribute to none of its devices (neither enabled with `scope vendor-attrs` nor any address tagged with it; the error prints the command that enables it); and a scope secret holding a character an IOS or Junos CLI reads as syntax (whitespace, quotes, a backtick, a non-ASCII character, or any of `? ! # $ \ ; { } [ ] | & < > , * ( )`). Letters, digits and `. _ + / = : @ % ^ ~ -` paste as they are, and `scope secret generate` (base64) makes such a secret. The scope secret is shared with TACACS+, so changing it means changing it on every device of the scope. A secret longer than 63 characters renders with a warning (some RADIUS clients take no more).
- **A listener bound to one IPv4 address** is used as the server address; IPv6 listeners and a loopback bind are warned about.
- **WTI** gets a walkthrough of the unit's RADIUS Parameters menu (`/N`, item 29 in WTI's user guide) and the group → `WTI-Super` table. **It has not been verified on a unit**: it is written from WTI's documents (`docs/radius-notes.md`), which disagree on the access level a login gets when the reply carries no `WTI-Super`. See the WTI section below.

Nothing here was tested against Cisco, Juniper or WTI hardware: the device syntax follows the vendors' documentation, and the server side was verified against real FreeRADIUS.

### WTI Console Servers (DSM/CPM/REM/TSM/RSM, firmware v8.x)

WTI units are configured through numbered text menus on the serial SetUp port, so
`tacctl config wti` prints a walkthrough instead of a pasteable config: `/N` → the
**TACACS** entry (item 28 on recent firmware) → one value per menu item, then `[Esc]`
until "Saving Configuration". No WTI-specific service is added to `tacquito.yaml` — the
unit requests exec authorization and reads the standard `priv-lvl` attribute from the same
`shell` service Cisco uses. WTI maps priv-lvl bands to its four access levels:

| priv-lvl | WTI access level | Shipped group |
|----------|------------------|---------------|
| 0-4 | ViewOnly (only the ports/services granted under Default TACACS User Access; factory: none) | `readonly` (1) |
| 5-9 | User (only the ports/services granted under Default TACACS User Access; factory: none) | `operator` (7) |
| 10-14 | SuperUser (all ports/plugs; no configuration menus) | *(add a group at 10-14)* |
| 15 | Administrator | `superuser` (15) |

**Key points:**
- WTI authenticates with **PAP**; tacquito's bcrypt authenticator handles PAP, nothing to change server-side
- **Account Management Module = Enabled** is the authorization request that carries `priv-lvl`; **Session Management Module = Enabled** is accounting (the unit's client uses PAM terminology). Accounting needs tacquito built with `patches/0002` (empty `server_msg` on accounting success): given upstream's `success, logging started` message, the unit drops the SSH session right after login. `tacctl install` / `tacctl upgrade` apply the patch overlay
- **Service Name** is set to `shell` so the unit's request matches tacquito's configured service directly. The factory default `wti` also works, but only through the default-service-permit patch in `patches/` (an unmatched service is answered with the group's `shell` priv-lvl)
- **Fallback Local** follows the scope's `aaa-order`: `tacacs-first` → `On (Transport Failure)`, `local-first` → `On (All Failures)`. Keep a local Administrator account on the unit as break-glass
- **Default User Access must be `On`** (Access Level `ViewOnly` as the least-privilege floor; the returned `priv-lvl` still sets the effective level). SSH logins go through the unit's OpenSSH, which has to resolve the account locally: with it `Off`, a TACACS-only user is invalid to sshd, which forwards a junk password (`\b\n\r\177INCORRECT…`), so tacquito logs `failed to validate the user` on every attempt no matter what was typed
- If the unit's **IP Tables** (`/N`) end in `DROP`, they must accept `-i lo` and `-m conntrack --ctstate ESTABLISHED,RELATED` before the final DROP. Otherwise the unit's TACACS+ SYN leaves but tacquito's SYN-ACK is dropped: every login waits out the Fallback Timer, and tacquito logs nothing (only SYNs in tcpdump, half-open sockets in `ss`). The unit's Ping Test passes regardless — it is ICMP only
- Test the first login with `ssh -o PreferredAuthentications=password <user>@<wti>` (`tacctl ssh <name>` uses the password method for every `wti` device). If a plain `ssh` is closed without a password prompt while the password method works, the unit's Invalid Access Lockout is armed from earlier failures — `/UL` clears it
- Port and service access for User/ViewOnly-level logins is defined only under Default TACACS User Access → Port Access / Service Access (factory: Administrator and SuperUser get all ports, User and ViewOnly get none), so an operator (User) sees no ports until they are turned On there; on a power unit Plug Access and Plug Group Access work the same way. The lists are per unit and shared by every such login. Step 3 of `tacctl config wti` sets them, and its "Port access" section names the groups they apply to. A same-named local account on the unit overrides the server-assigned level, so keep the two directories disjoint
- The output warns when the scope secret contains whitespace/punctuation or exceeds 32 characters, or when a scope member's username exceeds WTI's 32-character limit — regenerate a hex-only key with `tacctl scope secret <name> set $(openssl rand -hex 16)`
- Verify with `tacctl config loglevel debug` + `tacctl log tail`: `accepting user [x] using a bcrypt password` (PAP), then `client args [service=shell ...]`, then `authorized user [x] ... [priv-lvl=N]`; accounting (start at login, stop after `/X`) lands in `tacctl log accounting`. On the unit, TACACS Parameters → `12. Debug: On` echoes every exchange on the serial session — turn it back `Off` when done

**Over RADIUS** (`tacctl config wti --protocol radius`, or a scope that resolves to RADIUS) — **not verified on a unit.** The walkthrough follows WTI's documents for the RADIUS Parameters menu (`/N`, item 29 in the user guide; numbers vary by firmware): Enable, Primary Host and Secret Word, Fallback Timer and Retries (factory defaults), Fallback Local from the scope's `aaa-order` as above, the Authentication and Accounting Ports of this server's RADIUS listeners, Default RADIUS User Access `On` at `ViewOnly`, Debug. The server returns the access level in `WTI-Super` (vendor 24496, attribute 41), from the group's priv-lvl in the bands of the table above; the scope must send it (`tacctl scope vendor-attrs <scope> enable wti`, or tag the unit with `tacctl scope devices <scope> set <ip> wti`), or the walkthrough is refused. What carries over from the TACACS+ walkthrough: the unit's IP Tables must let the server's UDP replies in (ESTABLISHED,RELATED), keep a local Administrator, the lockout and `/UL`. Port and plug access is not sent (no `WTI-Port-Access`). WTI's user guide and knowledge base disagree on the level a login gets without `WTI-Super` (User or View), so the walkthrough sets it explicitly. `tacctl log tail --backend radius` shows each attempt, with `nas=` — what the unit sends as its NAS-Identifier.

### Custom Templates

The generated Cisco, Juniper, and WTI output is rendered from template files using `${VAR}` placeholders (processed by `envsubst`). You can customize the output by editing the templates.

**Template locations** (checked in order):
1. `/etc/tacctl/templates/` — per-host overrides (takes precedence)
2. `config/templates/` in the repo — version-controlled defaults

**Template files:**
- `cisco.template`, `cisco-legacy.template` — Cisco IOS/IOS-XE device config (`--legacy`: IOS 12.x)
- `juniper.template` — Juniper Junos device config
- `wti.template` — WTI console-server serial-menu walkthrough
- `cisco-radius.template`, `juniper-radius.template`, `wti-radius.template` — the same for `--protocol radius`

**Available variables:**

| Variable | Used in | Description |
|----------|---------|-------------|
| `${SERVER_IP}` | All | Auto-detected server IP address |
| `${SECRET}` | All | Shared secret of the scope |
| `${AUTH_PORT}`, `${ACCT_PORT}` | Cisco, WTI RADIUS | UDP ports of the RADIUS `auth` and `acct` listeners |
| `${RADIUS_GROUP}` | Cisco RADIUS | `aaa group server radius` label (`scope radius-group`, default `RADIUS-GROUP`) |
| `${AUTHN_METHODS}`, `${AUTHZ_EXEC_METHODS}`, `${EXEC_TIMEOUT}`, `${VTY_ACL_BLOCK}`, `${VTY_ACCESS_CLASS}` | Cisco | Method lists (from `aaa-order`), idle timeout and the management-ACL blocks |
| `${RADIUS_CONFIG}` | Juniper RADIUS | Pre-rendered RADIUS server, authentication-order and accounting commands |
| `${PRIVILEGE_COMMANDS}` | Cisco | Pre-rendered privilege level command mappings |
| `${TEMPLATE_USERS}` | Juniper | Pre-rendered `set system login user` lines |
| `${TACPLUS_CONFIG}` | Juniper | Pre-rendered TACACS+ server setup commands |
| `${VERIFY_COMMANDS}` | Juniper | Pre-rendered `show configuration` commands |
| `${GROUP_SUMMARY}` | All | Human-readable group mapping table |
| `${SCOPE}` | WTI | Name of the scope being rendered |
| `${FALLBACK_LOCAL}` | WTI | `On (Transport Failure)` or `On (All Failures)`, from the scope's `aaa-order` |
| `${SERVICE_NAME}` | WTI | Authorization service name the unit should send (`shell`) |

**To customize:** edit the copy in the override location (install puts one there; if it is missing, copy the default first):
```bash
sudo cp /opt/tacctl/config/templates/cisco.template /etc/tacctl/templates/cisco.template
sudo vi /etc/tacctl/templates/cisco.template
```

**On upgrade:** a template in `/etc/tacctl/templates/` that you have not changed is replaced by the new release's. tacctl records what it wrote there in `/etc/tacctl/templates/.shipped.sha256` (`sha256sum` format; `cd /etc/tacctl/templates && sha256sum -c .shipped.sha256` lists which are still as shipped). A template you changed is left as it is: the new release's version is written beside it as `<name>.template.new`, and the upgrade warns, naming both files. A `.new` file is never used for rendering. Compare and merge what you want, or take the new version as it is:
```bash
sudo diff /etc/tacctl/templates/cisco.template /etc/tacctl/templates/cisco.template.new
sudo mv /etc/tacctl/templates/cisco.template.new /etc/tacctl/templates/cisco.template
```
Until you do, each upgrade warns again and refreshes the `.new` file. A template with no record there counts as unchanged when it is byte for byte a version tacctl shipped (according to the git history in `/opt/tacctl`).

**To reset to defaults:** remove the override file (and its `.new`, if any). The repo's default is used, and the next upgrade puts a fresh copy of it back:
```bash
sudo rm /etc/tacctl/templates/cisco.template
```

---

## Upgrading

```bash
tacctl upgrade

# Switch to a specific branch during upgrade
tacctl upgrade --branch develop
```

The upgrade command:
1. Moves tacctl state into `/etc/tacctl` if it is not there yet (idempotent)
2. Pulls latest tacquito server source and rebuilds the binary (if upstream or the patch overlay changed) (the overlay's `0003` makes tacquito log the address a device connected from, which `tacctl log` and `device scan` read; `0004` stops it sending a server message with a failed login; `0005` records accounting from a device's local accounts and daemons, which tacquito refused (Junos: `AUDITD_TACPLUS_START_NO_RESPONSE`), in the accounting log; a server upgraded from 0.2.0 rebuilds tacquito once for them, see `patches/README.md`)
3. Pulls the latest tacctl repository into `/opt/tacctl` (after switching to the `--branch` given). If the installed binary was not built from the commit now checked out, it replaces it, with the verified release binary when the clone is at a release tag (`Installing the <tag> release binary (linux/<arch>, verified)`), otherwise built from the clone (`Building /usr/local/bin/tacctl from /opt/tacctl...`), and re-executes itself once, so the binary always matches the clone
4. Installs packages a newer tacctl needs
5. Brings the configuration in line with this release: re-renders each enabled backend from the store (RADIUS: and restarts it when its files or its unit drop-in changed); without a store, runs the in-place migrations of `tacquito.yaml`
6. Updates system files (unit files and drop-ins, logrotate, the tiers sudoers rules if that file is installed, the completion `tacctl completion bash` generates, the man page, templates you have not customized) if changed, and reports each one as `Updated:` or `Unchanged:`; a template you customized is kept, with the new release's version beside it as `<name>.template.new` (see [Custom Templates](#custom-templates))
7. For an install without a store: moves it into the store, behind the gate described below
8. Restarts tacquito only if what it reads changed (its binary, a unit or drop-in, or `tacquito.yaml`), and rolls the binary and unit files back if it does not come up. A new README, logrotate file, completion or template restarts nothing, and neither does an upgrade with nothing new

Running `tacctl upgrade` again right after an upgrade changes nothing. Use `--branch` to switch to a different branch (e.g., `develop` for pre-release features). You can also switch branches without upgrading: `tacctl config branch <name>`.

**The store gate.** An install that has no store yet runs the legacy migrations of `tacquito.yaml`, then `tacctl store import --check` with the running binary: import (nothing unrepresentable), render, equivalence of what tacquito would load from the two files, and a load test of the rendered file on a loopback port. Only when all of that passes is `/etc/tacctl/store.yaml` written, the old file kept as `/etc/tacctl/backups/legacy/tacquito.yaml.pre-store.<timestamp>`, `tacquito.yaml` rendered from the store and tacquito restarted.

**When the gate stops**, the upgrade still completes: the code is installed, `tacquito.yaml` and the running daemon are left exactly as they were, and tacctl runs in **legacy read-only mode** (read commands work, changes are refused). The report says why: content the store cannot hold (another service on a group, a non-bcrypt authenticator, an unknown top-level key, ...), a render that is not equivalent, or a failed load test. It never forces either through. Fix what `tacctl store import --check` reports and upgrade again, or accept the difference: `tacctl store import --force`, then `tacctl config render --force`.

**Undoing the move into the store.** `tacctl store rollback` restores the kept pre-store `tacquito.yaml` and legacy read-only mode (refused while RADIUS is enabled: `tacctl backend disable radius` first).

After an upgrade: `tacctl status`, `tacctl config validate` (store, rendered config, drift), and `tacctl backup list` (the pre-store file is under the old-style backups).

---

## Troubleshooting

### Common Issues

**`bad secret detected for ip [x.x.x.x]`**
- Shared secret mismatch between server and device
- Identify which scope the client falls into: `tacctl scope lookup <ip>` / `tacctl scope show <name>`
- Regenerate that scope's key: `tacctl scope secret <name> generate`
- On Juniper: delete and re-set the secret to avoid hidden characters

**`failed to validate the user [x] using a bcrypt password`**
- Shared secret is correct but password doesn't match
- Verify: `tacctl user verify <username>`
- Reset: `tacctl user passwd <username>`

**TACACS+ auth succeeds but Juniper login fails**
- Template user is missing on the device
- Fix: create all template users shown by `tacctl config juniper`

**A command is refused with exit 3 / `DRIFT` in `tacctl status`**
- A generated file was edited by hand; tacctl will not overwrite it. `tacctl config validate` names the file and both ways out: keep the edit (`tacctl store import --replace`, then `tacctl config render --force`; TACACS+ only) or discard it (`tacctl config render --force`, the edited copy is kept under `/etc/tacctl/backups/legacy/`)

**`store not initialised`**
- The install is in legacy read-only mode (the upgrade's store gate stopped, or after `store rollback`). See [Upgrading](#upgrading)

**RADIUS: no answer, or `Access-Reject`**
- `tacctl log failures --backend radius` gives the reason per reject (`not an enabled user of this scope`: the user lacks the scope the device's address falls in, or is disabled; `Crypt digest does not match`: wrong password)
- No line at all: the client is in no scope RADIUS serves (`tacctl scope lookup <ip>`, `tacctl scope protocols <scope>`), its secret is wrong, or a connection filter drops it
- Logged in at the wrong level, or without one: the scope does not send that vendor's attribute (`tacctl scope vendor-attrs <scope>`, `tacctl scope devices <scope>`)

**WTI login refused, or lands at the wrong access level**
- `tacctl config loglevel debug`, retry, then `tacctl log tail 50`: the `client args [...]` line shows the service name the unit sent. If it is not `shell`, set TACACS Parameters → Service Name to `shell` (or confirm the default-service-permit patch is applied: `tacctl status`)
- No authorization request at all → Account Management Module is Disabled on the unit
- `failed to validate the user [x] using a bcrypt password` on every attempt although `tacctl user verify` accepts the password → Default User Access is `Off` on the unit (its sshd sends a junk password for users it cannot resolve); set it `On` / Access Level `ViewOnly`
- Nothing in the tacquito log while the unit waits the Fallback Timer, SYNs visible in tcpdump → the unit's IP Tables drop tacquito's replies; add the `ESTABLISHED,RELATED` accept rule before the final DROP
- Login succeeds, then the session drops (`Broken pipe`) with an accounting start but no stop → tacquito lacks `patches/0002`; run `tacctl upgrade`, or disable the unit's Session Management Module until it is rebuilt
- Level is right but no ports are reachable → User/ViewOnly-level accounts only get the ports granted under Default TACACS User Access → Configure Port Access (factory: none)
- Level is wrong for one user only → a same-named local account on the unit overrides the server-assigned level
- `bad secret detected` in `tacctl log failures` → Secret Word was mistyped or truncated on the unit; `unknown authenticate start packet type` → the unit did not send PAP with TACACS+ minor version 1 (open an issue)
- Set TACACS Parameters → `12. Debug: On` on the unit to see the exchange from its side

**No connection attempts reaching the server**
- Verify port 49 reachable: `telnet <server_ip> 49` from the device (RADIUS: UDP 1812/1813, not testable with telnet)
- Check service is running: `tacctl status` / `tacctl backend status`
- Check listener network/address: `tacctl config listen show` (`--backend radius` for RADIUS)

**Config change not taking effect**
- Changes made through tacctl are rendered and restart what changed; a file edited by hand is drift (above)
- Check for errors: `tacctl config validate`

### Useful Commands

```bash
tacctl status          # Health check with auth stats, per backend
tacctl backend status  # Services and listeners
tacctl log failures    # Recent auth failures
tacctl config validate # Store, tacctl.yaml, rendered configs, drift
tacctl config diff     # What changed since the last snapshot
```

---

## License

MIT License. See [LICENSE](LICENSE).
