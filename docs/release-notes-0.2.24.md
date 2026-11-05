# tacctl 0.2.24

0.2.24 names the device that sent each TACACS+ accounting record, lets the
logs be filtered by time, user, device and kind and written as JSON, keeps a
user who must change the password from forwarding ports through the server,
stops setting `single-connection` on devices and removes it where it is, and
builds tacquito from the project's fork, with git pulls that wait for no
answer and drop a stalled transfer, and makes a held address stop completing
TCP handshakes with the server, so a device that falls back to its local
accounts only when the server is unreachable falls back. The numbered list in `CHANGELOG.md` (0.2.24) is
everything that differs from 0.2.23.

## Logs and accounting

- `tacctl log tail`, `search`, `failures` and `accounting` take `--since` and
  `--until` (`YYYY-MM-DD[ HH:MM[:SS]]`, `now`, `today`, `yesterday`, `-1h`,
  `2 hours ago`), `--user`, `--device` (a registered device or enrolled host,
  or an address), `--type login|change|command` (accounting only) and
  `--json` (one object per line). The filters combine, `tail -f` applies them
  to new entries, and a count limits the output after filtering. A log that
  names no device shows nothing for `--device` and says so.
- An accounting record carries `"Device"`, the address the record came from
  (tacquito patch `0006`), and `<`, `>` and `&` as they are instead of
  `\u003c`, `\u003e` and `\u0026`; the other fields keep their names and
  order. `log accounting` shows the registered name of a device or host the
  caller may see (`"Device":"sw1"`), else the address, and decodes older
  records too.

## Users and forwarding

- While anyone is held to a password change, the console's sshd drop-in
  (`/etc/ssh/sshd_config.d/tacctl-console.conf`) begins with a `Match User`
  block that closes every kind of forwarding for them, in every tier. The
  verbs that change who is held rewrite it, check it with `sshd -t` and undo
  it when sshd refuses it; with nobody held the file is as before. A
  connection the user has open already keeps its forwardings until it
  closes (`loginctl terminate-user <name>` ends it). `console check` reports
  a list that is not the users held now as drift and shows both lists.

## Devices

- `config juniper` and `config cisco` no longer print `single-connection`:
  tacquito closes a connection idle for 15 seconds, and a later login over
  the dead socket failed. `config cisco --legacy` prints the host line as
  `tacacs-server host <address> [port <n>] timeout 5 key ...`.
- On a device that has it, `device config plan` and `apply` delete it from
  tacctl's server, and `diff` and `plan` list it as an extra; the plan is a
  new shape, which `apply --confirmed` takes once one device of it has been
  applied and confirmed again. A Junos `single-connection` that only an
  apply-group gives is left alone (`inherited from a group: remove it from
  the group by hand`). Another server's line, a custom template and a copy
  of `cisco.template` or `cisco-legacy.template` made earlier keep theirs.
  The upgrade changes no device: run `device config plan` and `apply` on
  the devices that have the line.

## Break-glass

- A hold took the address out of the scopes' prefixes, which silences RADIUS
  (UDP), but tacquito (TCP) still completed the handshake and closed the
  connection afterwards. A WTI unit with `Fallback Local: On (Transport
  Failure)` and a Junos switch with `authentication-order [ tacplus password ]`
  saw a reachable server and never used their local accounts. tacctl now loads
  an nftables table of its own, `inet tacctl` (the rest of the ruleset is never
  touched): the held addresses in two sets, one input-hook chain at priority
  -10 that rejects with a TCP reset (`reject`, the default) or drops (`drop`) a
  held source address connecting to a tacquito port, an open session included.
  `tacctl config breakglass-firewall reject|drop|off` sets it (`off` is the
  0.2.23 behaviour) and loads the table at once.
- The table is loaded with `nft -f /etc/tacctl/breakglass-firewall.nft`, a file
  that replaces the whole table in one step, by every hold, release, move of a
  held device (`device address`), rename, every `backup restore`,
  `server listen` change and change of the setting, and at boot by the
  oneshot unit `tacctl-breakglass-firewall.service`. `install` and `upgrade`
  install the `nftables` package, and an upgrade with holds standing loads the
  table for them. `nftables.service` is never enabled or touched.
- The report of a hold has a `Firewall:` line, the report of a release the
  reverse, and the audit lines of hold, release and hold-move end
  `firewall=reject|drop|off|failed`. When `nft` is missing or fails the hold
  stands, the report says in red what the server still does and the fix (`sudo
  apt-get install nftables`, then `tacctl config breakglass-firewall
  <setting>`), and the command exits 1. Where the table would refuse nothing
  (the setting `off`, nothing held) a missing `nft` is no failure: nothing is
  loaded, nothing is red, the exit status is 0. `status`, `config validate`
  and `breakglass list` compare the live table with the holds and the setting.
- `tacctl rollback` (every target) removes `breakglass.firewall`, the table,
  the rules file and the boot unit and leaves the package; a hold that stands
  stays, without the firewall, as in 0.2.23. 0.2.23 refuses the key, so a
  rollback to it takes a snapshot when it is set. Until the older release is
  installed, run no verb that changes the holds, the listeners or the setting
  (each loads the table again). A downgrade with `upgrade --branch` and no
  rollback leaves a table the older release never updates;
  `docs/install/upgrading.md` shows how to remove it by hand.

## Installing and upgrading

- tacquito is built from the project's fork, `rett/tacquito`, whose `main`
  follows upstream only by reviewed merges. A checkout cloned from upstream
  by an earlier release is pointed at the fork at the next `install` or
  `upgrade` (`Tacquito source now pulls from ...`); an origin set by hand is
  left alone. The upgrade rebuilds tacquito once for patch `0006` and restarts it.
- The tacquito pull is a fetch and a fast-forward. A fetch that fails ends
  the install or upgrade and builds nothing; a checkout that cannot
  fast-forward, or is ahead of the fork's `main`, is reset to it with a
  warning that names the commit it was at and the one it is at now.
- git asks for no user name, password or key passphrase and drops a stalled
  transfer when it clones or fetches the tacquito source, clones, fetches or
  pulls `/opt/tacctl` (`upgrade`, `install`, `config branch`), or clones
  `pam_tacplus` (`config linux build`). A remote that needs a password fails
  instead: use a key, the agent or a credential helper. An ssh remote's host
  key must be in `known_hosts` already (connect once by hand, as the user git
  runs as), unless ssh's configuration sets `StrictHostKeyChecking
  accept-new`. Your own `GIT_SSH_COMMAND` or `GIT_SSH` is replaced: choose a
  key with `core.sshCommand` in the clone (`/opt/tacctl`; git's global
  configuration for a clone not made yet), which must take OpenSSH's `-o`
  options.
- No stored file is rewritten. An installed per-tier sudoers drop-in gains
  the operator's `log failures *`, so an operator can pass the log filters
  to `log failures` through sudo. `tacctl man` puts the pager on an entry
  again on groff 1.24.

## Rollback

`tacctl rollback 0.2.23` is new. This release changed no stored file, so the
target converts nothing, takes no snapshot and needs no `--yes`; it puts back
0.2.23's per-tier sudoers drop-in, without `log failures *`, when the file is
exactly this release's text, and every older target that rewrites that
drop-in takes this release's text as tacctl's own. The `upgrade --branch
0.2.23` that ends the rollback writes the console's sshd drop-in without the
block of held users, whose new connections forward again as their tier
allows. The tacquito this release built stays until 0.2.23 next rebuilds it
(a new commit on the fork's `main`), so records keep `"Device"` and the
literal `<`, `>` and `&`. On a device whose `single-connection` this release
removed, 0.2.23's `diff` and `plan` show the line as missing, and applying
that plan types it again. The tacquito checkout stays pointed at the fork,
which has the same history as the upstream clone 0.2.23 made.
