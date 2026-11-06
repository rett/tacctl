# Chassis member fixtures

The `real-` files are captures from a device: a Junos vMX 14.1R1.10 that
refuses `show virtual-chassis status` (it has no virtual chassis), and a
device that is no stack and refuses `show switch` (the text is the reply as
the device printed it).

The `synthetic-` files are written by hand from the vendors' documented
output formats (the member table of Junos `show virtual-chassis status`, the
`FPC n` rows of `show chassis hardware`, the per-member `fpcN:` blocks of
`show version`, and the IOS and IOS-XE `show switch`, `show inventory` and
`show version` tables of a Catalyst stack), not copied from a device; they
open with a `# SYNTHETIC FIXTURE` header that no device prints, and their
names and serial numbers come from the examples table. They exist because no
capture of a multi-member chassis was at hand: real captures from a
two-member EX virtual chassis and a Catalyst stack replace them when
available, and the tests that read them then check the readers against the
devices' own text.
