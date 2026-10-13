# tacctl 0.2.7

0.2.7 adds configuration blocks (the parts of a device's configuration that
tacctl does not render from its own standard but a site wants kept the same
everywhere), reads, compares and plans WTI units, and lets a management ACL
entry name the services it permits. The numbered list in `CHANGELOG.md`
(0.2.7, items 1 to 25) is everything that differs from 0.2.6.

"Upgrading" covers 0.2.6 to 0.2.7. Nothing is written to a device by tacctl:
the walkthroughs and the plan print what a person pastes.

## Read this first: a plain management ACL entry now means every port

An entry of a management ACL list that has no `:service` (`10.0.0.0/8`) now
permits every protocol and port from that source. On a WTI unit that is wider
than 0.2.6, which rendered such an entry as ssh and ICMP only: the unit's
IP Tables list carries `iptables -A INPUT -s <cidr> -j ACCEPT` for it, so the
unit's telnet and web pages are reachable from those sources. To keep what
the list permitted, replace each plain entry with `<cidr>:tcp/22`:

    tacctl scope mgmt-acl <scope> remove 10.0.0.0/8
    tacctl scope mgmt-acl <scope> add 10.0.0.0/8:tcp/22

The first `tacctl upgrade` onto 0.2.7 prints, once, each scope that has a
registered WTI unit and a plain entry in the list that applies to it, with the
entries and the commands above. `tacctl device config plan` of a unit says the
same at the top of its report when the paste holds a plain entry. Cisco and
Junos devices render plain entries as before (the source only).

## What is new

- **Configuration blocks** (items 5 to 11, 21, 22). A scope has, and a device
  may override, vendor-native text files kept under `/etc/tacctl/blocks`:
  a Junos `snmp` block (communities, client lists, trap groups, trap source),
  a Junos `system` block (login message, domain name and search, time zone,
  name servers, NTP), the IOS `snmp` block and the IOS `system` block
  (banner, domain name and list, time zone, name servers, NTP and its keys).
  `tacctl scope block <scope> juniper|cisco` and `tacctl device block <name>`
  manage them with the verbs `list`, `show`, `check`, `set`, `remove`, `edit`
  and `adopt` (which drafts a block from what a device has). Junos and IOS
  are never translated into each other.
  A block is owned statement by statement: tacctl sets what the block states,
  keeps the device's other statements and lists them as unmanaged, and never
  deletes what it does not own. Secrets in a block are shown elided and read
  with `--reveal`, which is logged. Compare, plan and back-out cover the
  blocks; the walkthrough prints them after the standard steps.
- **WTI units are read, compared and planned** (items 12, 15 to 19, 24, 25).
  `device config pull|diff|list` log in over ssh and read the unit's menu
  pages; `device config plan` prints the menu steps to type and one block to
  paste (the IP Tables list, as a single paste with ICMP, ssh only and the
  48-slot guard). A pull reads the whole system name, contact and location.
  Multiple Logins must be On, and the standard says so.
- **A management ACL entry can list its services** (items 20, 25).
  `<cidr>[:<service>[,<service>...]]`, with `tcp/<ports>`, `udp/<ports>` or
  `icmp`; `<ports>` is `N`, `N-M` or `*`:
  `tacctl scope mgmt-acl lab add 172.16.100.0/23:tcp/22,udp/161,udp/162`.
  The Cisco VTY ACL and the Junos filter render the source only for a plain
  entry or one with `tcp/22` or `tcp/*`, and the report says when an entry
  permits less than the access list can express.
- **A restore point for a Cisco plan** (item 23).
  `device config plan <device> --restore-point[=<fs>]` puts a block before
  the plan that copies the running configuration to a local file system (or
  runs `archive config` where the device has one), and the back-out names the
  file and the `configure replace` form that returns to it. Off by default.
- **Smaller changes** (items 1 to 4, 13, 14). The break-glass section compares
  login names without regard to case and says so; SNMP community and trap
  group names are told apart in the compared form; the Junos plan no longer
  types a delete for another community's clients; a section that holds only
  the device's own statements reads ok with a count; `config snmp test`
  follows a registered device; `device list` is sorted by name and can be
  narrowed by name, address, vendor and scope.

## Upgrading from 0.2.6

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
The upgrade changes nothing on the server, the rendered files or a device.

- **WTI templates.** The WTI walkthrough text changed (no tcp 443 rule, the
  IP Tables list as one paste, the item names of an 8.10 unit). A WTI
  template you customized in `/etc/tacctl/templates/` is kept, with the new
  version beside it as `<name>.template.new`.
- **A WTI unit's CONFIG state** in `device list` reads `never` until the unit
  is pulled with `tacctl device config pull`.
- **A device's SNMP, ACL and name data** are unchanged. No block exists until
  you set one; a scope with no blocks renders byte for byte as before.
- **Blocks hold community strings.** The block files are root-only (0600) and
  are part of every snapshot and backup; treat a backup as a secret.

## Checked on a device, and not

Before release the following were pasted on a lab Cisco IOS 15.6(2)T router
and read back as matching: the IOS `snmp` block, the IOS `system` block (the
banner, domain name and list, time zone, name server and NTP lines), the
trap source, and the restore point's copy form (the single empty line answers
the `Destination filename` prompt). A WTI unit's read, compare and plan were
checked on a lab unit.

Not checked on a device: the Junos `system` block (its statement forms are
from the documentation); the restore point's `archive config` and
`configure replace` forms; a WTI plan applied and backed out on a unit; the
IOS forms the grammar refuses (VRF, IPv6 NTP servers). The report and the
docs say "not lab-tested" where it applies, and a plan prints the statements
before anything is pasted, so read them.

## Limits

- IOS has no commit-confirm: a pasted plan is live when the paste ends. The
  restore point is a file, not a timer.
- A block's `system` text on IOS refuses a banner line over 80 columns, a
  tab or a non-ASCII character, and a banner that holds all of the
  delimiters tacctl can choose.
- A WTI unit's SNMP section is one community, read-only, by design; a device
  that needs another sets it at the device level.
- Junos 11.4 does not accept `set system login idle-timeout` (the timeout is
  set per login class there); a plan that carries the statement is refused at
  the device's check, and nothing is committed.

## Rolling back

0.2.7 adds keys (`blocks.*` and `blocks_device.*`, in `tacctl.yaml`), files
(`/etc/tacctl/blocks`), management ACL entries that carry services, and one
record field (`archive_fs`, in the last-pull record). A 0.2.6 binary does not
know the keys or the entries and its validation refuses them, so remove them
first, or restore a snapshot from before they were set (`tacctl backup list`,
`tacctl backup restore`), then `tacctl upgrade --branch 0.2.6`:

- `tacctl scope block <scope> juniper|cisco remove <block>` and
  `tacctl device block <name> remove <block>` for each block;
- `tacctl scope mgmt-acl <scope> remove <entry>` (and `tacctl config mgmt-acl`
  for the global list) for each entry that carries services.

`tacctl rollback 0.2.3` removes the block lists and leaves the files, and
refuses (the dry run too) while an entry carries services; it lists each one
with the command that removes it. The record field is ignored by older
releases.
