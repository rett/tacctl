# Server Commands — `tacctl server`

[Documentation](../README.md) › [CLI reference](README.md)

```
server show [--json]

    This server at a glance, changing nothing: the address devices and hosts reach it at, the
    default method of `host enroll`, the metrics exporter, every backend (installed, enabled,
    service) and every listener with its network, address, port and unit state. `--json` prints
    the same as a document. Superuser only

server addresses [list]

    The address devices and hosts reach this server at: the setting `server.addresses` of
    `tacctl.yaml`. With no word, or `list`, it prints the recorded address (this server's registry
    entry's copy when the setting does not hold it yet). Superuser only

server addresses add <ip>[,<ip>...]
server addresses remove <ip>[,<ip>...]
server addresses replace <ip>[,<ip>...]

    Changes it. This release holds one address: `add` sets it when none is set and is refused
    while one is ("only one server address is supported yet; use replace"); `remove` of the only
    address is refused ("the server needs an address; use replace"), and of one that is not set it
    says so and changes nothing; `replace` changes it. The list grammar takes more than one
    address, and more than one is refused ("only one server address is supported yet") until a
    release lifts the limit. An address is an IP address, which may be behind NAT or a VPN and need
    not be on this machine; a host name, `0.0.0.0`, `::`, a loopback and a link-local address are
    refused. Superuser only

server listen [--backend <id>] [--listener <name>] [show|tcp|tcp6|udp|udp6|reset] [<addr>]

    Show, change, or reset a listen address (default: the TACACS+ listener 'default'; see
    server/backends.md, "Listeners"). Superuser only

server metrics show|enable|disable|reset|address <host:port>

    Prometheus exporter control (TACACS+). Default: loopback-only 127.0.0.1:8080. `disable` sinks to
    127.0.0.1:0 (unreachable ephemeral port) since tacquito's own disable flag would crash the
    server. Superuser only
```

```
tacctl server show
tacctl server listen tcp 10.1.0.1:49
tacctl server metrics address 10.1.0.1:8080
tacctl server addresses
tacctl server addresses replace 192.0.2.10
```

**`server show`.**

```
Server
--------------------------------------------
  Address:         192.0.2.10
  Default method:  tacplus  (for hosts enrolled without --method)
  Metrics:         enabled, loopback only  (127.0.0.1:8080)

Backends
------------------------------------------
  ID      PROTOCOL  ENABLED  SERVICE
  ----------------------------------------
  tacacs  tacacs    yes      active
  radius  radius    no       not installed

Listeners
---------------------------------------------------
  BACKEND  LISTENER  NETWORK  ADDRESS  PORT  UNIT
  -------------------------------------------------
  tacacs   default   tcp      :49      49    active
```

The address is the setting, else the copy in this server's registry entry (the
line says so). The metrics line is the exporter of the TACACS+ backend's
default listener: `disabled` when it is sunk to a port no scraper can reach,
`enabled, loopback only` or `enabled, externally reachable` by its address.
The listeners are those of the backends that are installed or enabled; a unit
that is not installed shows `-`. `--json` has `addresses`, `address_source`
(`setting`, `registry` or empty), `default_method`, `metrics` (`address`,
`state`, `reach`) and `backends` (`id`, `protocol`, `installed`, `enabled`,
`service` and `listeners` with `name`, `network`, `address`, `port`, `unit`).

**`server listen` and `server metrics`** write `listeners.<backend>.<name>` and
`backends.tacacs.metrics_address` of `tacctl.yaml`, and the log lines are `server listen backend=
listener= from= to=` and `server metrics from= to=`. [Listeners](../server/backends.md#listeners)
and [Metrics](../server/metrics-and-retention.md) have the details.

**What a change does.** `server addresses add` and `replace` run in one apply,
after a snapshot (`tacctl backup list`): the setting, this server's registry
entry (which keeps a copy for the older releases), the prefixes of the managed
scope (`tacctl`: the server's login addresses, `127.0.0.1` and the server
address) and the server's own PAM client and accounts change together, by the
same enrolment of this server that `tacctl host enroll --local --server <ip>`
runs, with every safeguard of it (sshd is checked with `sshd -t` before it is
reloaded and the change undone when it refuses it, root and the local
administrators are not touched, the PAM files are backed up). `host enroll
--local --server <ip>` with an address that is not the recorded one is this
change, so the two cannot differ. If the setup on this machine fails, nothing
is changed: the setting, the entry and the scope stay as they were. A server
with no login set up (no registry entry) has only its setting changed; `tacctl
host enroll --local`, `install` and `upgrade` set the login up at that address.

**Where the address is the default.** The recorded address is the default of
`--server` of the device walkthroughs (`config cisco|juniper|wti`, and so of
`device config show`, `pull`, `diff`, `plan` and `apply`, which render the same
text), of `config linux script` and of `host enroll`, and the managed scope's
prefixes are derived from it. An explicit `--server` wins for that run. With
nothing recorded each detects the address as before. Three details:

- A walkthrough names the recorded address where the device is told where the
  server is. The address tacctl itself reaches the devices from (`--source`:
  the first SNMP client, the ssh permits, the WTI list) is still the detected
  one, and when the two differ the walkthrough says which plays which role
  (`The device is told to authenticate against 203.0.113.9 (server.addresses)`).
  A RADIUS listener bound to an address keeps that address in a RADIUS
  walkthrough.
- `host enroll` of a host that is already enrolled keeps the server address the
  host has, so re-enrolling for a repair never repoints it; `--server`
  changes it. A new host gets the recorded address; before, the source address
  of the route to the host.
- `host sync` of this server repairs the managed scope's prefixes from the
  recorded address when they drifted (`Repaired the managed server login.`).

A change says what is left to do, once:

```
[INFO] Re-point the devices and hosts at the new address: tacctl host sync --all; the device
walkthroughs name the new address
```

The log has `server addresses op=<add|replace> address=<ip>` beside the pair of
lines every change of state writes. Only the superuser runs the family: the
tier table has no row for it, as for `scope prefixes`, so the sudoers rules of
the tiers are as before.

See also [Enrolling hosts](../hosts/enrolling.md) (**This machine**) and
[Installing](../install/installing.md).
