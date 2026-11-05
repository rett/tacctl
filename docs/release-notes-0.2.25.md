# tacctl 0.2.25

0.2.25 makes `device config shapes` readable with many devices, rewrites the
explanation of shapes, canary and confirmed in the planning page, and fixes
three failures of `device config pull` and `apply` on Junos devices: a NETCONF
hello that names its capabilities with the XML namespace's prefix, a slow
device whose late answer arrived in front of a command's echo, and a virtual
chassis whose master prints its own label. Text a device sends is shown with
more characters replaced. The numbered list in `CHANGELOG.md` (0.2.25) is
everything that differs from 0.2.24.

## Devices

- `tacctl device config shapes` keeps its table narrow. The `NOW` column holds
  a count (`49 devices`, `1 device`, `-`) instead of the names, and below the
  table a block headed `At a shape now (last check or apply):` lists the
  devices of each shape, wrapped at 80 columns, one entry per shape in the
  table's order (none when no shape has a device). `shapes list --show <hash>`
  wraps its `at this shape now` line the same way. `--json` is unchanged.
- "Applying a plan" in the planning page opens with a rollout in five steps
  and a table of what each step does to a device, then says what a shape is
  (with a worked example of `sw1`, `sw2` and `sw3`), what a canary is and what
  the states `new`, `confirmed` and `seeded` allow, and holds the options of
  `apply` in one table. The device reference, the help and the manual page say
  the same in plain words. No behaviour changed; the only output that did is
  the apply-pause line of `tacctl config devices`, which now ends `0-3600,
  from one device's end to the next one's start`.
- A Junos device that names its NETCONF capabilities with the XML namespace's
  prefix (`urn:ietf:params:xml:ns:netconf:base:1.0`, where RFC 6241 has
  `urn:ietf:params:netconf:base:1.0`) answered, but was recorded as `no hello`:
  a pull read it over the command line, `device check` showed `NETCONF: no
  hello`, and an apply that enabled the service was rolled back with `the
  device does not answer NETCONF after the change`. Both spellings are now the
  same capability, so such a device is also applied over NETCONF. The hello is
  read as the device prints it: with comments, an XML declaration, a byte order
  mark or text before `<hello>`, and with white space or line breaks inside a
  capability; a device that ends the channel right after its hello still
  gives it.
- A hello that is none says why. The pull line gives the reason and the first
  120 bytes the device sent (`ok via ssh (netconf: no hello: the device's first
  message is <rpc-error>, not a hello; the device sent "<rpc-error>...")`; the
  `fallback` field of `--json` the same), and so does the message of an apply
  that enabled NETCONF when the device answered with something that is not a
  usable hello. A device that closes the channel after accepting the
  subsystem, or sends no hello in time, is one the probe cannot tell about: the
  apply message says `the NETCONF probe could not tell: ...` and the proof
  fails. The record still stores `hello ok`, `port closed`, `no hello` or `not
  probed` only, so `device check` shows the word without the reason.
- A slow device (a satellite or WAN link, a loaded switch) no longer fails
  `device config apply` or a pull with `open: configure exclusive` or
  `pre-flight ...: not recognised`. The answer to the empty line the ssh client
  types a second time could still be on its way when the first command was
  typed, and arrived in front of the command's echo (`alice@sw1> configure
  exclusive`). The first command now drops that late answer (the line break,
  the `[edit]` line, the `{master:0}` line, the pending-commit line, the prompt)
  and keeps the echo. Anything else between commands, and a prompt more than
  the commands account for, is still refused.
- A Junos virtual chassis of two members whose master prints its own label
  (`fpc0:` as well as `fpc1:`) is applied to. Every apply on such a chassis was
  rolled back with `the confirmed commit's answer: ... outside the members'
  answers`, because a label opens several lines, not one. The answer of a
  commit is now read as one block per label, each member held to its rules (the
  check, then `commit complete` and, on a confirmed commit, the note), and every
  member of `show version` must be in it. A refused answer shows up to 40
  lines of up to 120 bytes instead of the first six, so a layout not seen yet
  can be read from the error.
- Text a device sends is shown with every control character (C0, DEL and C1),
  formatting character (the bidirectional overrides) and line separator
  replaced by `?`, in the terminal line and in `--json`; only C0 controls and
  DEL were before.

## Rollback

`tacctl rollback 0.2.24` is new. This release changed no stored file 0.2.24
reads strictly, so the target converts nothing, removes no key, takes no
snapshot and needs no `--yes`. The break-glass firewall, the users' email
addresses, the SNMPv3 users and the other things 0.2.24 has stay; the older
targets still drop or refuse them. It is refused only while a device's apply
is not settled, and it ends with `tacctl upgrade --branch 0.2.24`.

After that upgrade a Junos device that names its capabilities with the XML
namespace's prefix is recorded as `no hello` again by its next `device config
pull`, and an apply to a virtual chassis whose master prints its own label is
rolled back again, as in 0.2.24.

The note after a rollback that took a snapshot named 0.2.23 as the release the
snapshot holds the state of (`Restore it with 0.2.23 only`); it names 0.2.25.

## Upgrading

Nothing is converted: no stored file changed, and `tacctl upgrade` rewrites
none. Two things differ for what is already recorded:

- A Junos device recorded as `no hello` because of the namespace prefix shows
  `hello ok` after a new `tacctl device config pull`; run `tacctl device check`
  to see it.
- A virtual chassis whose master prints its own label, which `apply` could not
  finish, applies now. A device that failed with `open: configure exclusive`
  works with no change on your side.

## Known limits

- A virtual chassis of three or more members whose members all print a label
  is still read one line per label, as before: no capture of such a chassis
  exists. An answer refused in that layout says when a label appears twice.
  Every other layout (an unlabelled master, a single member, two routing
  engines, a cluster) is read as before.
- A reason for `no hello` is shown by the pull line and the apply message
  only; the record keeps the word.
