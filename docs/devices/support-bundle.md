# Support bundles

`tacctl device support-bundle <name> [--vendor cisco|juniper|wti] [--login <local-user>] [--out <dir>]`
collects what a developer needs to make tacctl read a kind of device, in one attended login, and
writes it so that it can be shared.

It is the engineer's, for the devices of their own scopes. The login is the one of
`device config pull`: your own TACACS+ account, with the password asked on the terminal (it is not
cached), or, for a Junos device with a pinned host key, `--login <local-user>` with the one-shot
password of a local account. The registered vendor decides what is run; `--vendor` reads the device
as another vendor for this run only, and saves nothing.

## What is collected

Read-only commands, fixed per vendor. None prints the configuration.

| Vendor | Commands |
| --- | --- |
| Junos | `show version` (every member and routing engine), `show chassis hardware`, `show virtual-chassis`, `show chassis cluster status`, `show chassis routing-engine`, `show system uptime`, `show cli authorization`, `show system commit`, `show configuration \| compare rollback 0` |
| IOS, IOS-XE | `show version`, `show inventory`, `show switch`, `show module`, `show clock`, `show privilege`, and the running-configuration lines that name the device (`hostname`, `ip domain`, `clock timezone`, `snmp-server location|contact`) |
| WTI | the screens the unit's pull reads, without the user directory |

The SNMP system group (`sysObjectID`, `sysDescr`, `sysName`, `sysLocation`) is added when SNMP is set
up. A command the device does not know is recorded as the device answered; the next one runs.

## What is written

A directory (default `support-bundle-<UTC time>` in the current directory; it must not exist or must
be empty), one file per command, and a `README.txt` that lists the commands. The text is scrubbed
first (see [Examples](../development/README.md#examples) for the values):

- host names, domains, users, login classes, IPv4 and IPv6 and MAC addresses, serial numbers,
  locations and contacts become example values, the same real value always the same example;
- time zones are `UTC`;
- the free text of a commit comment is removed (tacctl's own comments stay);
- anything that looks like a secret, a hash or a key is removed;
- model names, release lines and the layout of every answer stay as the device printed them.

A text that still holds a value the scrubber learned to replace is not written, and nothing is.

What was replaced is kept in `<dir>.map`, beside the directory, mode 0600: kind, real value and
example, one per line. It holds the real names, so it is private; keep it out of the bundle and out
of every repository. Read the files before you share them: the scrubber knows the shapes it
replaces, not everything a device can print.

Logged: `auth.info device support-bundle user= device= vendor= login=own|local:<account> files=
result=ok`, never a command's text.
