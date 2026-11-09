# Support bundles

`tacctl device support-bundle <name> [--vendor cisco|juniper|wti] [--login <local-user>] [--out <name>]`
collects what a developer needs to make tacctl read a kind of device, in one attended login, and
writes it so that it can be shared.

It is the engineer's, for the devices of their own scopes. The login is the one of
`device config pull`: your own TACACS+ account, with the password asked on the terminal (it is not
cached), or, for a Junos device with a pinned host key, `--login <local-user>` with the one-shot
password of a local account. The registered vendor decides what is run; `--vendor` reads the device
as another vendor for this run only, and saves nothing.

## What is collected

Read-only commands, fixed per vendor. None prints the configuration: the Junos
`compare rollback 0` shows only the difference of a candidate to the committed
configuration (empty when nobody has a change open), and the IOS lines are the
ones that name the device.

| Vendor | Commands |
| --- | --- |
| Junos | `show version` (every member and routing engine), `show chassis hardware`, `show virtual-chassis`, `show chassis cluster status`, `show chassis routing-engine`, `show system uptime`, `show cli authorization`, `show system commit`, `show configuration \| compare rollback 0` |
| IOS, IOS-XE | `show version`, `show inventory`, `show switch`, `show module`, `show clock`, `show privilege`, and the running-configuration lines that name the device (`hostname`, `ip domain`, `clock timezone`, `snmp-server location|contact`) |
| WTI | the screens the unit's pull reads, without the user directory |

The SNMP system group (`sysObjectID`, `sysDescr`, `sysName`, `sysLocation`) is added when SNMP is set
up. A command the device does not know is recorded as the device answered; the next one runs.

## What is written

A directory `support-bundles/<name>` in your home, one file per command, and a `README.txt` that
lists the commands. `--out` is the bundle's name, not a path: a letter or digit, then letters,
digits, `.`, `_` or `-`, at most 64 characters (default `<device>-<UTC YYYYMMDD-HHMMSS>`); anything
else, a `/`, `..`, a leading dot, `~` or `$` included, is refused. The `support-bundles` folder is
created with mode 0700 when it is missing, and the success lines print the full paths. The name
must not be in use, and neither must its `.map` file: nothing is ever replaced. The home is the
one of the person who ran `sudo` (else of the user running tacctl), taken from the account
database and never from `$HOME`; tacctl does not expand `~` or variables, and a `support-bundles`
folder that is a link leading out of the home is refused. The text is scrubbed
first (see [Examples](../development/README.md#examples) for the values):

- host names, domains, users, login classes, IPv4 and IPv6 and MAC addresses, serial numbers,
  locations and contacts become example values, the same real value always the same example;
- serial numbers are replaced by their field, whatever their length, case or digits: the `SN:`
  value of `show inventory`, `Hw Serial#:` in a description (also inside a quoted `DESCR:`),
  `Processor board ID`, `System serial number`, the generic `Serial number:` field, the Junos
  `Serial ID` of a routing engine. The value runs to the next blank, comma or quote and ends at
  its last letter or digit, so the punctuation after it stays: `(serial: abc12345)` becomes
  `(serial: SN000001)`. The serial cell of every row of `show chassis hardware` (transceiver, PIC
  and power supply rows included) and of Junos `show virtual-chassis` is replaced too, cut at the
  column its header gives. In that column any word with a letter or digit is a serial, whatever
  its length, case or digits, except the status words `Prsnt`, `NotPrsnt`, `Unprvsnd`, `Absent`,
  `Present`, `Inactive`, `Online`, `Offline`, `Master`, `Backup`, `Linecard`, `Spare` and `Empty`
  (in any case). A table ends at a blank line, at a line of one word and a colon, and at a prompt
  line that begins with `{`; a row with nothing in or after the serial column (`Midplane`, a
  member without a serial) is an empty row inside the table. A tab-separated row is cut at its
  tabs: with as many cells as the header it has its serial at the header's column; a row with
  fewer cells (no Description, no version) has it by shape, the one cell that is a single word
  with a digit or the one after the part number, and a cell with a hyphen (`650-114384`,
  `NON-JNPR`, `EX4300-48T`) is a part number or a model and never a serial. If several cells
  qualify and none follows a part number, the table takes none (the shape rule below still reads
  them), and a part number without a hyphen is not told from a serial in such a row. An empty or
  `BUILTIN` cell stays, and so does the Description column of the two tables, the one place of a
  table row where a model name stands;
- any other token with the shape of a serial number (eight to fourteen capitals and digits, with
  both) is replaced as well, except an example value (`SN0...`), an image name (`K9`), a model
  name the files state and the text of a quoted `DESCR:`;
- time zones are `UTC`;
- the free text of a commit comment is removed (tacctl's own comments stay);
- anything that looks like a secret, a hash or a key is removed;
- model names, release lines and the layout of every answer stay as the device printed them: the
  values after `PID:` (up to two blanks, a comma, `VID:` or `SN:`) and `VID:`, the quoted `DESCR:`
  string, the model of the `Model:` line of Junos, the model of the `cisco <model> (...) processor`
  line of IOS and of the `Cisco IOS Software, <model> Software` line, and every model name the files
  of the bundle state, in all the files; only the model is kept, never the rest of its line (the
  serial after `Model number : WS-C3750X-48P-S` is replaced, and so is a quoted `NAME:`); an object
  identifier, a dotted run of numbers that begins `1.3.6.1.` (`1.3.6.1.4.1.2636`), is not an
  address, and the digits around any other address (`10.20.30.40.179`) do not make it a version;
- the host names of vendors and standards bodies stay when they say nothing about the owner: the
  bare domain cisco.com, juniper.net, hpe.com, hp.com, gnu.org, fsf.org, openssl.org, ietf.org or
  kernel.org, and one of the labels `www`, `tools`, `ftp`, `cdn`, `software` or `support` in front
  of it, and the `example.*` names, so `Technical Support: http://www.cisco.com/techsupport` is as
  the device printed it. A mail address is a person's and is replaced (only an `example.*`
  address stays, so the support address of a vendor becomes an example address), and so is any
  other name under a vendor domain (`acme-corp.hpe.com`) and any name under a domain the files
  state as the owner's. The parent domain of every host name that is replaced (all after its
  first label) is the owner's too, so once `acme-corp.hpe.com` is replaced, `hpe.com` and
  `www.hpe.com` are replaced in every file of that bundle, whichever file names them first. A
  public label is never replaced as a word of its own: the host `www.hpe.com` becomes an example
  host as a whole, and `www` and `Technical Support:` stay where they stand;
- when a replacement is shorter or longer than the text it replaces and blanks follow, blanks are
  added or taken away so that the columns after it stay where the device printed them (nothing is
  done at the end of a line);
- a Cisco device that echoes a command longer than its terminal is wide, in several lines, leaves
  none of the echo in the file: it starts with the device's answer.

A text that still holds a value the scrubber learned to replace is not written, and nothing is.

What was replaced is kept in `support-bundles/<name>.map`, beside the directory, mode 0600: kind, real value and
example, one per line. It holds the real names, so it is private; keep it out of the bundle and out
of every repository. Read the files before you share them: the scrubber knows the shapes it
replaces, not everything a device can print.

Logged: `auth.info device support-bundle user= device= vendor= login=own|local:<account> files=
result=ok`, never a command's text.
