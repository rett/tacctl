# Break-glass

[Documentation](../README.md) › [Network devices](README.md)

## Break-glass local users

A device that authenticates against this server should still have a local account for the day the server cannot be reached. `tacctl scope breakglass <scope> add <user> [--role admin|operator|readonly]` records which accounts a scope's devices keep (`list` shows them, `remove <user>` drops one); the role defaults to `admin`. The record is per scope, kept in `tacctl.yaml` as `breakglass_scope.<scope>.users` (a list of `name:role`, written only when set, moved by `scope rename`, removed with the scope), and is the superuser's to change. A name must be a device-safe user name (a letter, then up to 31 letters, digits, `_` and `-`), must not be a tacctl user of the scope (a local account of that name would shadow the server's), and must not collide with a template-user or class name of the Juniper walkthrough or be the Junos account `remote` (the template account of every remote user without a local-user-name). `root` is the exception to the reserved names: it is the Junos system account, accepted as a break-glass entry for a scope's Junos devices (see [Junos root](#junos-root)), always `admin` (`--role operator|readonly` is refused) and written in lower case only. Names compare without regard to case. In the other direction, `user add`, `user scope add|replace` and `user rename` refuse a tacctl user name equal to a break-glass account of a scope the user is in (or would be in) and name `scope breakglass <scope> remove <name>` as the way out.

**tacctl never stores a password or hash for these accounts.** `config cisco|juniper|wti` render the account lines for the scope with a placeholder where the credential goes, commented out so that a paste cannot create an account with the placeholder for a password, and name each recorded account on an `Unfilled break-glass credentials` line (tacctl cannot see whether you put in a credential, so the line stays for as long as the account is recorded):

- **Cisco**: `username <name> privilege <15|7|1> secret 9 <TYPE9-HASH>` (the hash itself, as `show running-config` prints it; `algorithm-type scrypt secret` would take a plaintext password and hash it again, so it is not used; with `--legacy` the IOS 12.x form `secret 5 <HASH>`), in Step 0, before the AAA step they back (`aaa authentication login default group <G> local` follows the scope's `aaa-order`; the console's `CONSOLE` list is local only).
- **Junos**: `set system login user <name> class <class> authentication encrypted-password '<HASH>'`, the class being the local class of the built-in `superuser` (`admin`), `operator` or `readonly` group (`RW-CLASS`, `OP-CLASS`, `RO-CLASS`); never a template user.
- **Junos root**: see [below](#junos-root).
- **WTI**: a menu step that adds a local account of the matching access level (`admin` is Administrator, `operator` User, `readonly` ViewOnly, or the level the group's `wti-level` sets, as in the mapping table of the same output), with `<PASSWORD>` where the password you keep goes.

A scope without break-glass users renders the existing advice plus a notice, `scope show` says `none` on its `Break-glass:` line, and `config validate` warns, on one line naming the scopes, that they are a lockout risk (a warning, not an error). Creating, rotating and removing the account on the device stays with you.

### Junos root

Many Junos devices keep `root` as their local access. Junos holds it under `system root-authentication`, not under `system login user`, so `scope breakglass <scope> add root` records it as a break-glass entry of the scope's Junos devices (`list` and `scope show` print it with a note that it is the Junos system account). The Junos walkthrough renders, in the break-glass step and commented out like the other accounts, with the same placeholder rule (tacctl never stores or generates a password or hash):

```
# set system root-authentication encrypted-password '<HASH>'
# set system services ssh root-login allow
```

and nothing for a user named `root` under `system login user`. The second statement is there because Junos refuses root over ssh by default; allowing it is a security trade-off the person decides, since root can then log in over ssh with the password: keep the device behind the [management filter](../security/management-acl.md) (the permit list), or leave the line out and keep root on the console. The `Unfilled break-glass credentials` line names `root (admin)` like the other accounts.

`root` means nothing to Cisco and WTI. Their walkthroughs render nothing for the entry and say so in one line (`'root' is recorded for the scope: it is the Junos system account, so nothing is rendered for it here.`), they leave it off the `Unfilled` line, and the comparison of their break-glass section ignores it. A scope whose only entry is `root` has no local account on its Cisco and WTI devices: their walkthroughs carry the no-break-glass notice, and `config validate` warns, per scope and naming the vendors of its registered devices (`scope 'lab' records only 'root', a Junos account: its cisco and wti devices have no break-glass local user`). On a Junos device `root` counts like any named account, so a scope with `root` alone raises no warning for its Junos devices.

## Holding break-glass

The local accounts of [Break-glass local users](#break-glass-local-users) (`root` included, for a Junos device) reach a device's vty only while no server answers it: a server's refusal is final, so a local login there is refused while the server is up. On a Cisco console the `CONSOLE` list is local, so a local account logs in there with the server up, lands at privilege 1, and `enable` with the local enable secret takes it to 15. `tacctl breakglass hold <device> --reason "<text>"` makes the server stop answering a registered device (or an enrolled Linux host, see below) on purpose, so that its local accounts can be used on a vty (and on a Junos or WTI device) while the server is up. It is for exceptional cases: a paste that cut your session and left no login that works, a device whose only way back is its console.

- **What it does.** The record (`breakglass_hold.<device>` in `tacctl.yaml`: the address, when, by whom and the reason) makes both renderers take the device's address out of every scope's prefixes (and out of every tagged address, for RADIUS) when they render: a `/24` that held it answers as the eight prefixes `/25` to `/32` that do not, a prefix equal to the address is gone, an IPv6 `/64` becomes sixty-four prefixes. Every other address is answered by the scope that answered it before. `store.yaml` and every device are untouched; `tacquito.yaml` and `clients.conf` get a comment block that names the address, the device (or host) and the prefixes it was carved from, never the reason. One restart of each backend whose file changed.
- **What it carves, and what it does not.** Only the address the device is registered at (`device address`, its management address). A device that sends its AAA from another address (a Cisco `ip tacacs source-interface`, which `cisco.source_interface.<scope>` sets, a NAT, an IPv6 address) is still answered by the server, and the hold does not stop it. The report says so (`Carved:   only <address>, the address registered for <device>. A device that sends its AAA from another address (a source interface, a NAT) is still answered.`) and, when `device scan` data show no request from the registered address, adds a `Warning:` line naming `tacctl device config pull <device>` (its source interface) or `show tacacs` and the device's own log as the way to learn the address it sends from.
- **Several devices.** `hold <device>[=<reason>][,<device>[=<reason>]...]
  [--reason "<text>"]` and `release <device>[,<device>...]` take a comma
  list, one argument (quote it when a reason holds a space). A device's
  reason is its own, after `=`, or the `--reason` default; a device with
  neither is a usage error that names it, and a name is given once, by
  name or by address. A reason of its own ends at the
  next comma: one that holds a comma is given with `--reason`. The list is
  held best effort: each device is checked on its own, those that pass are
  held together (one write of `tacctl.yaml`, one render, one restart of each
  backend whose file changed) and each that is refused is named with why on
  a `Not held: <name>: <why>` line, in the confirmation and in the report. A
  device that another superuser held while the names were typed is skipped
  the same way. When none passes nothing is asked or changed. The exit code
  is 1 when any device was not held, or a restart failed, and 0 when all are
  held. A release names what is not held under `Not released:`, releases the
  rest in one restart and exits 1; with none held it changes nothing. One
  device is held and released, asked and reported as before.
- **What it asks.** The device name typed back, at a terminal (for a list, the names of the devices that passed, as printed, comma separated; a hold is a person's act: there is no `--yes`), after a paragraph that says the act is for devices in exceptional circumstances and which local accounts (`scope breakglass <scope> list`) will be the only way in. It is refused when the name is neither a registered device nor an enrolled host, has no address, is already held, is at a loopback address or an address a listener binds (the server's own logins come from `127.0.0.1`), is a device at the address of an enrolled host (a hold there would silence the host too), or when no scope covers its address (it is unanswered already).
- **A Linux host.** `breakglass hold|release|list` name an enrolled host as
  they name a device, with the same record, carve-out, confirmation (the
  host's name typed back), restart and release. A host is held at the address
  `host enroll` or `host sync` recorded for it, else at its ssh target's when
  that is an address (a name that resolves is not used: what is carved must
  not depend on a resolver). The server then answers no TACACS+ or RADIUS
  login and no sudo check for that address: tacctl users cannot log in by
  password or use sudo there, while the host's local administrator (a local
  account that does not authenticate through tacctl) and its console work,
  which is the point. A host is refused when it is this server's own host
  (`host enroll --local`: its logins come from `127.0.0.1`), has no recorded
  address and an ssh target that is not an address (`host sync` records it),
  is at a loopback address or a listener's address, or when no scope covers
  its address; a name that is both an enrolled host and a registered device is
  refused as ambiguous, naming both, and nothing is changed; so is a host at
  the address of a registered device (a hold there would silence the device
  too). A host is held by its name: an address that is only its ssh target's
  is refused, naming the host. While a host is
  held, `host sync`, `host show --check`, `host enroll` of the registered host
  (and `host move`), `host target <name> <target>`,
  `host provisioner <name> rotate`, `host unenroll` (also with `--force`) and
  `host forget` are refused, naming the hold (since, by whom, why) and
  `tacctl breakglass release <name>`, before anything is attempted over ssh
  (also when the device registry, which records the address, cannot be read);
  `host sync --all` and `host check` skip it and say so, and `tacctl ssh` warns
  and connects.
  `host list` marks the host (`BREAK-GLASS` in a STATE column and a footer),
  `host show` has a Break-glass section (`breakglass` in `--json`), and
  `status`, `scope show|list|routing|lookup` and `config validate` name the
  hold as they do for a device. `breakglass list` has a KIND column (`device`
  or `host`) and `--json` a `kind` field. A record whose host is no longer
  enrolled at the record's address is an orphan like a device's. The superuser
  holds and releases; an engineer sees the holds of the hosts of their own
  scopes (`breakglass list`, `host list|show`, `status`). The audit lines read
  `breakglass hold host=<name> addr=<ip> reason="<text>" by=<user>` and
  `breakglass release host=<name> addr=<ip> held=<duration> by=<user>`. The
  rendered files name a held host in their comment block as `(host <name>)`
  and a held device as `(device <name>)`.
- **The way in, by vendor.** *Cisco IOS:* ssh as a local account (the device waits for the server a few seconds, then takes the local password; the account lands at the level of its `username ... privilege` line); on the console, log in as the local account (the `CONSOLE` list is local), then `enable` with the local enable secret (that works with the server up, held or not). Logins by your TACACS+ name fail on that device until you release it. *Junos:* ssh or console as a local user (`system login user`), or as `root` when the scope records it ([Junos root](#junos-root): ssh needs `root-login allow`); the switch waits out its tacplus-server timeout, then checks the local password (`authentication-order [ tacplus password ]`); root on the console is local always. *WTI:* the unit takes its local accounts only if its TACACS+ Fallback Local is `On (Transport Failure)` or `On (All Failures)` (the walkthrough sets it from the scope's `aaa-order`); with `Off`, nobody logs in until you release it. Nothing a held device does is accounted here: its accounting goes to a server that does not answer it, and what the technician typed is in the device's own log only.
- **While it stands.** There is no timer and no automatic release: a hold ends only with `tacctl breakglass release <device>`, and is shown until then: `breakglass list`, `status` (a red line per hold), `device show` (`Break-glass: HELD since ... by ...: <reason>; the server does not answer <address>`), `device list` (`BREAK-GLASS` in the STATE column and a footer), `device check` (the Scope row and `breakglass` in `--json`), `device scan` (a refusal of the address reads `(break-glass held)`), `scope routing|show|list|lookup` and `config validate` (a warning per hold). `device remove` of a held device is refused (`break-glass is held on <name>: release it first`); `device address` moves the hold with the device (see below), and `device rename` (for a host, `host rename`) moves the record with it. `device config pull|diff|plan --pull` of a held device is refused up front, and a batch skips it with that line, because the device does not authenticate your login; `device config plan` of the last pull works and says `BREAK-GLASS HELD on this device` before its items, and the cover page marks the device. `tacctl ssh` of a held device or host warns and connects. `backup restore` is a render like any other: a hold comes back with a snapshot of a `tacctl.yaml` that has it and goes with one that lacks it, and the restore names the devices held now and after it when that set changes.
- **A record that holds no device.** A record holds a device only while the device is registered at the record's address (a host: while a host of the name is enrolled and its recorded address is the record's). When the device was removed from `devices.yaml` by hand, or another was registered under the name at another address, the record is an *orphan*: `breakglass list` shows `<device> (orphan)` and says why (`--json` has `"orphan": true`), `status` and `config validate` name it, the address it carved stays carved, the device is not shown as held and none of the held-device refusals applies to it, and `breakglass hold <device>` is refused until `tacctl breakglass release <device>` removes the record. A hand-written key with a dot in it (`breakglass_hold: {sw.lab: ...}`) is read and released like any other; `config validate` names it, and names an entry with no address, an address that is not one IPv4 or IPv6 address, or that is not a record: those carve nothing, and `release <name>` removes them.
- **When the device moves.** `tacctl device address <device> <address> [-y]` on a held device moves the hold to the new address (superuser; an engineer is refused; releasing first would answer the old address again). The new address passes the checks of a new hold: not a loopback address, not an address a listener of either backend binds, not the address of an enrolled host, not held by another record, covered by a scope. One line names both addresses and asks to confirm (`Confirm moving the hold from <old> to <new>? [y/N]`; `-y` skips it); the registry and the record are written together, rendered once and each backend whose file changed is restarted once. The report names the hold's original reason and time, the rendered carve and that the old address is answered again. A refused address changes nothing (`Nothing was changed.`). A restart that fails is reported as `NOT restarted` and the command exits 1, with the registry and the record on the new address. `--apply` is refused for a held device (it does not authenticate your login). `auth.info` line: `breakglass hold-move device=<name> from=<ip> to=<ip> by=<user>`.
- **When a restart fails.** The report says `tacacs NOT restarted: the running server still answers <address> until it is restarted (run: sudo systemctl restart tacquito)` (for a release, `still does not answer`), the command exits 1, and nothing is undone: the record and the rendered files stay, and are what the next restart serves. Two superusers who hold one device at the same moment cannot both succeed: the second is refused as already held and the first record is left as it was.
- **After the way in.** Fix or back out, then `tacctl breakglass release <device>`: the report names the check (`tacctl device config pull <device> --diff`, then a new ssh login as yourself). Every plan's after-steps end with three comment lines that say how to get here (`Locked out ... A superuser runs: tacctl breakglass hold <name> --reason "..."`), whether or not the device is held, and the Step 0 of the Cisco walkthrough has one commented line after the accounts that says the same.
- **Who, and the log.** The superuser holds and releases (a hold takes one device out of AAA for everyone, as a change of a scope's prefixes does); an engineer lists the holds of their own scopes. Both verbs write an `auth.info` line per device (`breakglass hold device=<name> addr=<ip> reason="<text>" by=<user>`, `breakglass release device=<name> addr=<ip> held=<duration> by=<user>`: the reason is logged; `host=` in place of `device=` for a host) and the snapshot every change takes first.
- **`tacctl rollback` is refused while a hold stands**, in the dry run and with `--apply`: the release being left has the record and the older one does not, so the device would stay unanswered until the older release's first render and then be answered without anyone releasing the hold. Release it first.
