# Backends

[Documentation](../README.md) › [Server](README.md)

A backend is a daemon that serves the store over one protocol. tacctl has two:

| ID | Protocol | Implementation | Installed by |
|---|---|---|---|
| `tacacs` | TACACS+ | tacquito, built from source | `tacctl install` (always) |
| `radius` | RADIUS | FreeRADIUS, the distribution's package, run as tacctl's own instance | `tacctl backend enable radius` (opt-in) |

TACACS+ over TLS is reserved, not implemented: a listener's `tls` block is part of the `tacctl.yaml` schema, and `tls.enabled: true` is rejected as "reserved for a future release".

```
tacctl backend list             # protocol, implementation, installed, enabled, service state
tacctl backend status [<id>]    # state, uptime, PID, and each listener: unit state, whether
                                # something listens
tacctl backend enable <id> [-y] # install if needed, render, enable at boot, start
tacctl backend disable <id> [-y]
```

Which backends are enabled is `backends.enabled` in `tacctl.yaml` (default: `[tacacs]`). Every command that changes users, groups, scopes or filters renders the config of **every** enabled backend from the store, all of them or none, and restarts only the backends whose files changed.

- `backend enable <id>` installs the backend if it is not installed (asking first; `-y` skips), checks every backend's rendered files for hand edits, takes a snapshot, adds the id to `backends.enabled`, renders, then enables and starts the service, which must come up. Any failure puts `tacctl.yaml`, the store and every rendered file back and stops the service; software the install step put on the machine stays.
- `backend disable <id>` stops the service and disables it at boot (asking first; `-y` skips). Its package and rendered files stay, and are no longer rendered or reported as drift; `backend enable` brings it back. Disabling the last enabled backend is refused, and so is disabling `tacacs` in legacy read-only mode.
- Commands need the store (`/etc/tacctl/store.yaml`), or, on a legacy install with no store yet, its `tacquito.yaml`; with neither they stop with `Config not found … Is tacctl installed?`. `tacquito.yaml` is the `tacacs` backend's file, rendered from the store: a RADIUS-only install has none and runs every command without it. With `tacacs` enabled and `tacquito.yaml` missing, commands run and warn; `tacctl config render` (or any change) writes it again.
- With more than one backend enabled, `tacctl status`, `tacctl config validate`, `tacctl config show` and `tacctl log …` print one labelled section per backend (`== Backend: radius (radius, freeradius) ==`); `log` takes `--backend <id>` to show one. With only `tacacs` enabled the output has no backend sections.
- `backend list` and `backend status` are open to the read-only and operator tiers; `enable` and `disable` are superuser-only.

## Listeners

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
