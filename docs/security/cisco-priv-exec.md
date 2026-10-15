# Cisco priv-exec mappings

[Documentation](../README.md) › [Security](README.md)

Cisco IOS gates command **availability** by privilege level (`privilege exec level X <cmd>`) independently of TACACS+ command authorization. Both gates must say yes for a command to run. Manage the mappings per group:
```
tacctl group privilege seed                  # built-in defaults (only verified move-DOWNs)
tacctl group privilege list operator         # show current mappings + source (explicit / default)
tacctl group privilege add operator 'show ip route'
tacctl group privilege add operator 'configure: router bgp','exec all: show ip'
tacctl group privilege remove operator 'show running-config'
tacctl group privilege reset operator --dry-run    # back to the shipped default: the difference,
                                                   # nothing written
```
An entry may start with a mode: `exec:` (the default when there is none), `exec all:`, `configure:` or `configure all:`. `config cisco` renders it as `privilege <mode> [all] level <N> <command>` (`privilege configure level 7 router bgp`), and `group privilege list` shows the mode in its own column. An entry is stored as typed in its mode's form (`exec: show ip` and `show ip` are the same mapping).

Defaults move only verified priv-15 commands DOWN to lower groups; they never move commands UP from a lower default level (which would silently restrict them from `readonly` users: `show ip route` and `show access-list` are level 1 already). IOS levels are cumulative, so the level-7 `operator` inherits what `readonly` has at level 1. Shipped:

- `readonly` lowers `show running-config` to level 1, so a monitoring account reads the configuration its level may see (IOS filters it to the commands that level could enter; `show running-config view full` is unfiltered, shows every key and is not lowered).
- `operator` lowers `undebug all` and nothing else. An operator may not interrupt service, even intermittently, so no command that clears a table, an adjacency or a line, captures traffic or sends traffic at a rate is lowered to level 7; those stay at level 15, the `engineer`'s.

Every shipped entry is permitted by the group's [command rules](command-authorization.md#per-command-authorization), bare and with any arguments that the entry's own keywords leave to it (a keyword child that has a level of its own, such as `show running-config view full`, keeps that level). IOS lowers a verb with every argument it accepts, so with the server unreachable (the `local` fallback) and on a device that authenticates over RADIUS, which carries no command rules, a user gets what the server permits. A verb whose arguments the rules bound (`ping` and `traceroute`, whose one-line `repeat`, `timeout` and `size` values the server rule limits) is therefore never lowered: with no server answering, and over RADIUS, an operator has the basic `ping` and `traceroute` IOS gives a user at its own levels and nothing more. This is the strict side of the trade-off.

Mappings live under `privileges.<group>` in `/etc/tacctl/tacctl.yaml`, survive `tacctl upgrade` and are emitted by `config cisco` for both protocols.

`tacctl group privilege reset <group> [--dry-run] [--yes]` puts one group's mappings back to the shipped default (what `tacctl group reset <group> --only privileges` does, for any group). It prints the entries it removes (`-`) and adds (`+`), asks `Apply these changes to the privileges of group '<group>'? [y/N]`, takes the usual snapshot and logs `group privilege reset name=<group> by=<user>`. `--yes` answers for you; without a terminal and without `--yes` it changes nothing and exits 1; `--dry-run` prints the difference and stops; a group that already is canonical says so and exits 0. A group with no shipped list, a custom group, has none afterwards: its override is removed, never stored as an empty list. The reset takes no `--preset`; it resets to the shipped default, and the role preset's values come with `tacctl group reset <group> --preset`. Superuser only.

Devices keep the `privilege exec level N ...` lines they were pasted with, so the difference lists the `no privilege exec level N <command>` lines for the entries it removes; paste them, then the output of `tacctl config cisco`.

A device pasted with older `privilege exec level 7 ...` lines keeps them, and until they are removed its operators keep the old reach whenever the server does not answer. The lines that remove them are `no privilege exec all level 7 ping`, `no privilege exec all level 7 traceroute`, `no privilege exec all level 7 monitor capture`, `no privilege exec level 7 clear counters`, `clear line`, `clear ip arp`, `clear arp-cache` and `clear mac address-table dynamic`, and, from lists older than 0.2.3, `no privilege exec level 7 show running-config`, `show startup-config`, `show tech-support`, `show archive`, `show access-list` and `show ip route`. Paste them, then the output of `tacctl config cisco`. They come from three places:

- `tacctl device config plan <device>` prints the `no privilege exec ...` lines of a device pulled with them (it knows what each device holds).
- `tacctl upgrade` prints them once, on the first upgrade onto this release (and again while a stored setting still carries a removed entry).
- `tacctl group privilege reset operator` prints the lines for the entries a stored list holds that the shipped one does not. For an install on the shipped list it says the group is already canonical and prints none, so use the upgrade's notice or the lines named in this section.

A `privileges.operator` list stored in `/etc/tacctl/tacctl.yaml` that is exactly the list 0.2.3 shipped is dropped by `tacctl upgrade`; one that differs keeps its entries, and `tacctl upgrade` and `tacctl config validate` name the removed ones that it still lowers (`tacctl group privilege reset operator`, or `tacctl group privilege remove operator '<entry>'`, puts them right).
