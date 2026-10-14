# IOS fixtures, device facts

`facts-iosv/` (IOSv 15.6(2)T) and `facts-7200/` (a 7200 on IOS 12.4(15)SW)
hold what a pull reads of the device's facts, and `../ios-xe/facts-csr1000v/`
(CSR1000V on IOS-XE 16.7.1) the same for IOS-XE:

- `show-version-include-version.txt`: the lines of `show version` that the
  pull's `show version | include Version` keeps (the XE build prints its
  zero-padded number first, then the `Cisco IOS Software ... Version 16.7.1,`
  line the release is taken from; the 7200 prints the boot loader's and the
  midplane's `Version` lines too).
- `show-inventory.txt`: `show inventory`, whose first entry is the chassis.

Serial numbers are replaced by `FXYZ0000001`-style fakes; the captured host
names are not in these outputs.
