# tacctl 0.2.6

0.2.6 is a hotfix for 0.2.5. The standard Cisco block of 0.2.5 had an
`aaa authentication enable default group <G> enable` line, which lets any user
the server knows reach privilege 15 on a device by typing `enable` and their
own password. 0.2.6 takes the line out of the standard for every Cisco device,
for TACACS+ and RADIUS, and makes `device config plan` remove it from the
devices that have it. The numbered list in `CHANGELOG.md` (0.2.6, items 1 and
2) is everything that differs from 0.2.5.

"Upgrading" covers 0.2.5 to 0.2.6. Nothing is written to a device by tacctl:
the walkthroughs and the plan print what a person pastes.

## What is new

- **The standard Cisco block has no enable list** (item 1). tacquito answers a
  TACACS+ enable request as a login with the user's own password, so an
  operator at privilege 7 who typed `enable` and their own password reached
  privilege 15 and could `show running-config`, which holds the TACACS+ key,
  the enable secret's hash and the local users' hashes. This was tested on
  IOS 15.6 and IOS-XE 16.7; command authorization at level 15 still denied
  `configure`, `debug` and `clear`. `enable` now uses the local enable secret
  and nothing else, as it did in 0.2.3. `config cisco`, `device config show`
  and the managed `aaa` section print no `aaa authentication enable` line, and
  the RADIUS walkthrough has one comment in place of its commented-out line.
- **Compare and plan** (item 1). A device's `aaa authentication enable
  default ...` list (`group <G> enable`, `group tacacs+ ...`, `enable group
  <G>`, `line`, `none`, any other) is an extra, severity ACCESS, and `device
  config plan` removes it with one `no` line in the `aaa` region (the back-out
  types it again). `aaa authentication enable default enable`, which is what
  IOS does with no list, is tolerated and left; a list of another name is an
  extra of that name and is kept.
- **The break-glass texts** (item 2). On a Cisco console the local login and
  `enable` work while the server is up. The hold is for a vty local login (a
  server's FAIL for a local name is final) and for the local accounts of a
  Junos or WTI device.

## Upgrading from 0.2.5

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
The upgrade changes nothing on the server, the store, the rendered files or a
device.

- **A pulled Cisco device that has the list reads `differs`** in `tacctl device
  config list` after the upgrade, without a new pull: the rendering changed,
  and the pull need not be repeated. The next step is `tacctl device config plan <device>`
  (or `--all`), which prints one line per device that has the list, `no aaa
  authentication enable default group <G> enable`, in the `aaa` region, with
  the check and the back-out beside it as for any plan.
- **A Cisco template you customized** in `/etc/tacctl/templates/` is kept, with
  the new version beside it as `<name>.template.new`; it keeps the line until
  you take the new one, and the walkthrough and the plan use the copy.
- **Until the line is removed** from a device, `enable` on it asks the server
  and any user the server knows reaches privilege 15 with their own password.
  Plan and paste the devices you configured from the 0.2.5 walkthrough first.
- **The local enable secret** is again the one shared secret of the way up, on
  the vty and on the console alike, while the server is up. Who holds it is
  site policy (Step 0 of the walkthrough prints the line and keeps no value).
  Command authorization at level 15 still asks the server with the user's
  group rules, so an operator who knows the secret cannot configure, debug or
  clear, and can read the running configuration. A device with no enable
  secret has no `enable` once the list is gone: set one first; the plan warns
  when there is none.

## Rolling back

0.2.6 adds no key, file or record field, so going back to 0.2.5 needs no
conversion: `tacctl upgrade --branch 0.2.5`. The 0.2.5 walkthrough prints the
enable list again, and a device that had it removed is `differs` until it is
pasted. `tacctl rollback 0.2.3` works as it does in 0.2.5 (see
`docs/release-notes-0.2.5.md`).
