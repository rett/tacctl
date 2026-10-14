# Group Commands — `tacctl group`

[Documentation](../README.md) › [CLI reference](README.md)

```
group list                                                List all groups with Cisco priv-lvl, Juniper class, user count
group show <name>                                         Every setting and where it comes from, with the Junos patterns (open to every tier)
group add <name> <priv-lvl> <class> [--tier <tier>]       Add a custom group (at priv-lvl 15 its tier is recorded: superuser unless --tier; a leftover tier, WTI level or Junos setting of that name in tacctl.yaml is cleared)
                                    [--wti-level <level>] --wti-level gives it a WTI access level instead of its priv-lvl band
group edit <name> tier auto|<tier>                        tacctl tier of the group (auto = the priv-lvl band; recorded as superuser at 15)
group edit <name> priv-lvl <0-15>                         Change Cisco privilege level
group edit <name> juniper-class <CLASS>                   Change Juniper class name
group edit <name> wti-level auto|<level>                  WTI access level: viewonly, user, superuser or administrator (auto = the priv-lvl band)
group remove <name>                                       Remove a custom group (built-ins protected)
group commands list <group>                               Show per-command rules + default action
group commands default <group> <permit|deny>              Set default action (catchall)
group commands add <group> <name> [--match <regex>]...    Add a command rule
                                  [--action permit|deny]
                                  [--before <name>|--first]
group commands remove <group> <name> [--all]              Drop a rule (--match/--action pick one of several)
                                  [--match <regex>]... [--action permit|deny]
group commands reset <group> [--dry-run] [--yes]          Put the group's rules back to the shipped defaults:
                                                          the difference first, then a confirmation
group commands seed [<group>] [--force]                   Populate built-ins with sensible defaults
group preset roles [--dry-run] [--force]                  Starting values for viewer, operator, engineer and superuser
group reset <name> [--preset] [--dry-run] [--yes]         Put readonly, operator, superuser or engineer back to its canonical state:
                   [--only settings,commands,privileges,junos]   the difference first, then a confirmation
group privilege list <group>                              Show Cisco privilege mappings and their modes
group privilege add <group> '<cmd>'[,'<cmd>'...]          Move one or more commands to the group's priv-lvl ('<mode>: <cmd>'
                                                          for exec all, configure or configure all; exec without one)
group privilege remove <group> '<cmd>'[,'<cmd>'...]       Remove one or more mappings
group privilege reset <group> [--dry-run] [--yes]         Put the group's mappings back to the shipped default:
                                                          the difference first, then a confirmation
group privilege seed [<group>] [--force]                  Populate built-ins with safe priv-exec defaults
group junos <group> list|clear                            Both Junos deny sets and their sizes, or drop both (confirms)
group junos <group> deny-commands|deny-configuration      The patterns the server sends with the group's login class
                    list|add '<regex>'|remove '<regex>'|clear
```

**Default Groups:**

| Group | Cisco priv-lvl | Juniper class | WTI access level | Use Case |
|-------|---------------|---------------|------------------|----------|
| `readonly` | 1 | RO-CLASS | ViewOnly | Monitoring and configuration backup (NCM): reads, changes nothing |
| `operator` | 7 | OP-CLASS | User | Troubleshooting (show, ping, traceroute): changes nothing and interrupts nothing, even intermittently (on Junos `ping ... rapid|interval` and `monitor traffic` are denied only where the role preset's deny sets are sent); the `engineer` is the escalation |
| `superuser` | 15 | RW-CLASS | Administrator | Full administrative access |

**Role preset** (opt-in): `tacctl group preset roles [--dry-run] [--force]` writes starting values for four roles: the built-in `readonly` as the viewer, `operator`, an `engineer` group it creates (priv-lvl 15, class `EN-CLASS`, tier `engineer`) and `superuser`. It changes nothing that already has a value unless `--force` replaces it, and moves no user. `--dry-run` shows each setting and whether it would be set, kept or replaced. What it adds to the shipped defaults:

- **Cisco, viewer and operator:** a `show` deny in front of the shipped permits for the secret-bearing, unfiltered sub-trees (`running-config view full`, `tech-support`, `startup-config`, `derived-config`, `key chain`, `snmp community|user`, `archive log`; the viewer also `crypto`, the operator `crypto isakmp key` and `crypto key`). The deny has a `--match`, so a `show` that misses it falls through to the permit.
- **Cisco, engineer:** 34 rules that permit everything except the exec-level lifecycle (`reload`, `delete`, `erase`, `format`, `fsck`, `rename`, `mkdir`, `rmdir`, `request`, `install`, `software`, `upgrade`, `issu`, `write erase`, `archive` other than `archive config`), `copy` that would load a configuration or write flash (saving to `startup-config`, flash or a remote URL and exporting a file are permitted), `configure network|memory` and `configure replace <url>`, the shell escapes (`tclsh`, `guestshell`, `app-hosting`, `iox`, `scripting`), `hw-module`, `redundancy`, `switch`, `test aaa`, `debug all|aaa|tacacs|radius`, `clear aaa|logging|archive`, and the `do` form of those. **Configuration mode is not restricted as a mode**: an engineer can change AAA, the TACACS+ and RADIUS servers and keys, lines, privilege levels, SNMP and the management ACL, so that tacctl's push can run with the engineer's own login. A mistake there can lock a device out. Because tacquito sees only a command's first word and arguments and cannot tell exec from configuration mode, the rules apply inside it as well: `archive` (other than `archive config`), `switch`, `redundancy`, `hw-module`, `iox`, `app-hosting`, `scripting`, `software` and a bare `configure` are refused there. A site that wants a boundary adds rules, for example `tacctl group commands add engineer aaa --action deny` (a rule goes before the catchall).
- **Junos:** `deny-commands` per role, no `deny-configuration` on any role. Nothing is hidden from reading: the viewer and operator see the whole configuration with secrets shown as `SECRET-DATA` (their classes have no `secret` bit), and the engineer must not hide what they can see. Viewer, 136 of 241 bytes: no `ssh`, `telnet`, `file`, `request`, `restart`, `start`, `load`, `op`, `test`, `monitor`, `configure`, `edit`, `clear`, `ping ... rapid|interval` (the flags that send at the reply rate or at a chosen one), `show system rollback`. Operator, 133 of 241: no `file`, `request`, `restart`, `start`, `load`, `op`, `test`, `configure`, `edit`, `clear` (every family), `monitor traffic` (a capture on the routing engine, unbounded without a count; `monitor start|stop|list` and `monitor interface` stay), `ping ... rapid|interval`, `show system rollback`. Engineer, 219 of 241: no `request system|chassis routing-engine|vmhost|security`, `start`, `op`, `file copy|delete|delete-directory|rename|archive|show|change-owner|change-permission`, `clear system login|log`, `restart chassis|management`; `load` is allowed (Junos tests a pattern against a command's keywords with each argument replaced by a placeholder, so a pattern cannot allow `load set terminal` and refuse `load set <file>`). With these settings a Junos engineer's `EN-CLASS` bits are the only limit on configuration: an engineer can edit `system login`, `tacplus-server` and the management filter on Junos, where on Cisco only the Cisco rules limit them. A site that wants a Junos boundary sets `group junos engineer deny-configuration` itself (which also hides those paths from the engineer, while the viewer and operator can read them).
- **WTI:** the levels of the Default Groups table, with the engineer at `superuser`. A WTI level is a fixed menu. The operator's `User` level can open a console on a port the unit's Default User Access list grants, end the session another user holds on that port (`/D`) and erase its buffer (`/E`), which is what taking a console over from someone who left it connected needs. `ViewOnly`, the level below it, cannot open a console at all.

The Junos classes are `RO-CLASS`, `OP-CLASS`, `RW-CLASS` and, for the engineer, `EN-CLASS`. Their permission bits are the ceiling on the device and are final: the viewer has `network view view-configuration`, the operator `network trace view view-configuration` (no `clear`: an operator may not interrupt service, even intermittently, so nothing under `clear` is theirs, with or without the deny sets), the engineer the bits listed in [Juniper Junos](../devices/junos.md) (`clear` among them), the superuser `all`. What a role may do beyond them is the server-sent deny sets, which change without touching a device. The bit removal is the protection every install has: without the preset (or sets of your own with `tacctl group junos`, or the RADIUS `Juniper-Deny-Commands` attribute) nothing denies `ping ... rapid`, `ping ... interval` or an unbounded `monitor traffic`, and which bit `test interface restart-auto-negotiation` needs is not known. A device pasted from an older version keeps `clear` in `OP-CLASS` until Step 1 of `tacctl config juniper` is pasted again (`tacctl device config plan <device>` prints `delete system login class OP-CLASS permissions clear`). `tacctl upgrade` and `tacctl config validate` name stored deny sets from an older preset; `tacctl group reset operator --preset` and `tacctl group reset readonly --preset` bring the current ones. An install that ran an early version of the preset gets a red notice from `tacctl upgrade`, because that preset's Cisco denies did not hold; `tacctl group reset engineer` is the fix.

**Resetting a group:** `tacctl group reset <group> [--preset] [--only settings,commands,privileges,junos] [--dry-run] [--yes]` puts a group back to its canonical state and shows what changes before it writes anything. Superuser only. Canonical means:

- for `readonly`, `operator` and `superuser`, what a fresh install gives them: the shipped command rules and Cisco privileges, the priv-lvl and Junos class of the table above, and no setting of their own for the tier, the WTI level or the Junos sets (the priv-lvl band decides the first two);
- with `--preset`, the role preset's values instead (priv-lvl, class, WTI level, tier, Junos deny sets and Cisco rules of viewer, operator and superuser), which sets a built-in group back to its role;
- for `engineer`, which is not a built-in group, the preset's engineer (priv-lvl 15, class `EN-CLASS`, tier `engineer`, WTI `superuser`, its Junos `deny-commands`, no `deny-configuration`, its Cisco rules): `group reset engineer` is `group preset roles --force` for that one group, and creates the group when it is absent;
- any other group has none: `Group 'x' is not a built-in or role group, so it has no canonical defaults; group commands reset x drops its command overrides.`

The difference is printed in four sections. `settings` lists the priv-lvl, Junos class, tier and WTI level that differ as `current -> canonical` (the tier and level say whether the current value is set or automatic, as `group show` does); `commands` lists the rules removed (`-`), added (`+`) and moved (`~`) and the default action; `privileges` the lines removed and added; `junos` each deny set with its size, its patterns removed and added. A section without a difference says `unchanged`, and a group that already is canonical says so and exits 0 without asking. A priv-lvl change warns that Cisco logins and the per-level authorization lines change (re-paste `tacctl config cisco`), a class change that the Junos template user changes (re-paste `tacctl config juniper` Step 1). When the group ends with command rules, the groups at its priv-lvl that have none get a permit catchall, as `group commands add` does, so that the level's `aaa authorization commands` line cannot lock them out.

It then asks `Apply these changes to group '<group>'? [y/N]`. `--yes` answers for you; without a terminal and without `--yes` it changes nothing and exits 1. `--dry-run` prints the difference and stops. `--only` limits the reset to the sections named (a comma list). The reset takes the usual pre-change snapshot, writes in one step, renders and restarts the backends, logs `group reset name=<group> sections=<list> by=<user>`, and, when it lowers a tier, syncs this server's accounts at once like `group edit ... tier` does. It never changes the group's name, users or built-in flag.

The WTI column is derived from the Cisco priv-lvl (WTI bands: 0-4 ViewOnly, 5-9 User, 10-14 SuperUser, 15 Administrator); a group at priv-lvl 10-14 is the only way to land in the SuperUser band. Over RADIUS the same values travel as `Cisco-AVPair`, `Juniper-Local-User-Name` and `WTI-Super`, where the scope sends them.
