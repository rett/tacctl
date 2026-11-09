# Chassis member fixtures

The `real-` files are captures from a device: a Junos vMX 14.1R1.10 that
refuses `show virtual-chassis status` (it has no virtual chassis), and a
device that is no stack and refuses `show switch` (the text is the reply as
the device printed it).

The `real-ex4400-vc-2-*`, `real-ex4600-ex4300-vc-4-*` and
`real-ex4300-vc-enabled-1-*` files are captures of Junos virtual chassis, each
as three files, the answers of `show virtual-chassis status` (`-status`),
`show chassis hardware` (`-hardware`) and `show version invoke-on all-routing-engines`
(`-version`): a two-member EX4400-48T virtual chassis (Junos 24.2R2.18); a
preprovisioned, mixed-mode chassis of two EX4600-40F members and two EX4300-48T
linecards (Junos 21.4R3-S2.4); and one EX4300-48T with virtual chassis enabled
and no other member (Junos 20.2R3.9), which is no chassis. They are trimmed to
the rows the readers use (the package lines, the transceivers, the fans and the
PIC details are removed from the hardware answers), the host name, serial
numbers and virtual chassis ID are replaced by the examples, and the columns are
aligned again after the replacement. Nothing else was changed.

The `synthetic-` files are written by hand from the vendors' documented
output formats (the member table of Junos `show virtual-chassis status`, the
`FPC n` rows of `show chassis hardware`, the per-member `fpcN:` blocks of
`show version`, and the IOS and IOS-XE `show switch`, `show inventory` and
`show version` tables of a Catalyst stack), not copied from a device; they
open with a `# SYNTHETIC FIXTURE` header that no device prints, and their
names and serial numbers come from the examples table. They exist for the states no
capture shows (a member that is not present, a three-member chassis whose
master prints its own label in `show version`) and for the Catalyst stacks, of
which no capture was at hand: a real capture of a Catalyst stack replaces
them when available, and the tests that read them then check the readers
against the devices' own text. The synthetic virtual chassis files stay for the
states above.

`synthetic-iosxe-show-switch-active-3.txt` is the `show switch` of an IOS-XE
16.x or later stack (Catalyst 3650, 3850, 9000), which prints the role `Active`
where IOS 12.x and 15.x print `Master`; it is synthetic like the others, from
the documented format.

`synthetic-ios-show-switch-provisioned.txt` is a two-member stack plus a
provisioned member 3 whose H/W version column is blank (the all-zero MAC
address and the state `Provisioned` stand alone); it checks that the reader
accepts a row with that column blank. It is synthetic like the others and says
nothing about which devices print such a row.
