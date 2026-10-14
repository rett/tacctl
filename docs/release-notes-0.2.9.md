# tacctl 0.2.9

0.2.9 lets tacctl type a plan into Junos devices itself. `device config
apply` loads the plan in an exclusive session, checks it on the device,
commits it under `commit confirmed`, proves it through a fresh login and
confirms it; a review groups the devices by the change they need and asks one
question. A blank device is brought in with one of its local accounts by
`device onboard`, and an address nobody registered is read with one login by
`device collect`. The numbered list in `CHANGELOG.md` (0.2.9, items 1 to 15)
is everything that differs from 0.2.8.

"Upgrading" covers 0.2.8 to 0.2.9. Nothing is written to a device unless you
run `device config apply` or `device onboard` and answer its question.

## Read this first: the Junos paste plan types `configure exclusive`

The region of a Junos `device config plan` (and its cleanup and back-out
regions) now opens with `configure exclusive` instead of `configure private`.
Junos refuses `commit confirmed` in a private session (`error: commit
confirmed not supported for private configuration`), so a pasted 0.2.8 plan
never reached its confirmed commit and committed nothing.

An exclusive session takes the configuration lock until you leave it, and a
paste is refused when another session is editing:

- `error: configuration database modified` means another session has
  uncommitted changes. Have that person commit or discard them.
- `error: configuration database locked by: <name>` means another session
  holds the exclusive lock. Wait for it to exit.

Either way nothing happened (every later line of the paste is an unknown
command): paste again when the device is free. After `commit`, type `exit`,
which releases the lock; the report and the follow-up say so. The whole-paste
check refuses a region that starts with `configure private`.

Other changes in what a person types or sees:

- **Setter verbs print a line.** After `device location`, `description`,
  `address`, `config-syntax` or `vendor` stores a rendered value, and after a
  scope setting that devices are rendered from, a device with a stored pull
  that the plan would now change gets `The configuration of <name> would
  change: tacctl device config apply <name> --check`. It reads the stored
  pull only: no login, no network.
- **Listings gain apply state.** `device config list` has an `APPLIED`
  column once a listed device was checked or applied, and the Configuration
  row of `device show` ends with `apply: ...`, in red when a confirmed commit
  is pending: type nothing on that device before the time shown.
- **The review is answered by typing.** `device config apply`, `--apply` on
  the setter verbs and `device onboard` ask for the device's name (one
  device) or the number of devices back. There is no answer without a
  terminal except `--confirmed --yes`.
- **The password cache answers three more verbs.** With the cache on, `device
  config apply`, `device onboard` and `device collect` (for your own login)
  take the password from it; `--login` never does.

## What is new

- **`device config apply`** (items 4, 6, 7). `tacctl device config apply
  <name>[,<name>...] | --all | --scope <scope> | --vendor juniper` is the
  superuser's step after `plan` for Junos devices. It logs in as you, reads
  each device, loads the plan in an exclusive session, runs the device's
  `commit check` and discards the candidate; `--check` ends there. The
  devices that need a change are reviewed once, grouped by shape. Each is
  committed under `commit confirmed`, proven by a fresh login as you, by the
  change that landed matching the check and by a read of the planned
  sections, and then confirmed. A failed proof rolls the change back; a
  device whose state could not be read is reported `PENDING until <time>`
  and the next `apply` of it settles that first. `breakglass`, `netconf`,
  the root account and yours, `system services`, `interfaces` and groups are
  never written. Options: `--section`, `--hold`, `--server`, `--source`,
  `--concurrency`, `--timeout`, `--max-failures`, `--json`.
- **Shapes** (items 5, 6). Devices that need the same change have one shape.
  The first device of each shape is applied alone and the rest follow only
  when it applied (`--no-canary` starts them together; `--pause` waits
  between devices). `--confirmed` applies only shapes an earlier apply
  confirmed; `--max <n>` (default 5) caps the devices of a run. `device
  config shapes [list|seed]` lists the shapes, which are confirmed and on
  which devices; `seed` files the shape of a device you applied by hand. Each
  device's record keeps what the last check or apply did.
- **`device onboard <address> --login <local-user>`** (item 10). Brings a
  blank Junos device in with one of its local accounts: the host keys are
  shown and confirmed, the device is registered, its first-time plan is
  checked, reviewed and committed as the local account, and proven by your
  own TACACS+ login before it is confirmed. `--check` stops before the
  commit.
- **`--login <local-user>` on `device config pull`, `diff --pull` and `plan
  --pull`** (item 11). A superuser reads one registered device as a local
  account, for a device the server does not answer yet. The password is
  asked once and never stored or cached.
- **`device collect <address>... | --discovered`** (item 12). Reads what an
  address nobody registered is, with one login: the host keys are shown and
  confirmed once, then `show version` and the pull's read command are the
  only things typed. The result is one table; `--register` registers each
  device with its keys pinned and keeps the read as its first pull record.
- **`device sync`** (items 13, 14). Fills a Junos device's empty `hostname`,
  `location` and `description` in the registry from its last pull record,
  after a preview and one question. A host name is filled only when it
  resolves to the device's registered address.
- **`device add --pull`** (item 3). Registers the device and reads its
  configuration in the same command.
- **`--apply` on `device address`, `description`, `location` and
  `config-syntax`** and the line the setters print (items 8, 9). `--apply`
  stores the value and runs the reviewed apply for that device.
- **Settings** (item 1). `config devices apply-confirm-timeout` (minutes of
  the confirmed commit, 3 to 60, default 10) and `config devices apply-pause`
  (seconds between devices after the canary, 0 to 3600, default 60).

## Upgrading from 0.2.8

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
The upgrade writes nothing to a device.

- **Sudoers.** The per-tier drop-in and a group drop-in that is exactly
  0.2.8's text are rewritten: the password cache's alias gains the lines of
  `device config apply`, `device onboard` and `device collect`. An edited
  group drop-in is left, with the warning that names `tacctl config sudoers
  install <group>`. No row is added for a lower tier: the new verbs are the
  superuser's.
- **New settings are absent until set.** `device.apply.confirm_timeout` and
  `device.apply.pause` are written to `tacctl.yaml` only when you set them;
  the defaults apply until then.
- **Records gain fields.** `devices-config.json` keeps the `applied` part of
  a device that was checked or applied, and the `login`, `user_pulled` and
  `hostname` fields of a pull. A record made before this release has no
  `hostname` until the next pull, so `device sync` names `device config pull`
  for it. 0.2.8 ignores all of these.
- **`/var/lib/tacctl/device-apply/`** is created by the first apply: the
  shape store (0600) and a lock per device.
- A device's rendered configuration is unchanged.

## Known limits

- **Junos only.** `device config apply` and `device onboard` act on Junos
  devices. A Cisco IOS device or a WTI unit named is refused with the reason
  and a selector leaves them out; their plans are still pasted by a person.
- **No private mode.** An apply and a pasted plan both use `configure
  exclusive`, so a device another session is editing or holds the lock on is
  refused (the holder is named) and nothing is changed.
- **The device must echo what is typed ahead.** A device that does not echo
  the empty line tacctl types ahead (both prompts on one line) shows no
  banner of a pending commit, so apply cannot run on it.
- **Two routing engines.** Devices with two routing engines are not
  supported by apply in this release: a commit answer with a block per
  engine (`re0:`, `re1:`) is not recognised, so apply cancels the commit
  and reports it rolled back.
- **The first release of apply.** Start with `--check`, which commits
  nothing. Apply one device of each shape by hand, look at it
  (`device config pull <name> --diff`), and only then apply the rest: one
  canary per shape is the default, and `--confirmed` runs only shapes an
  earlier apply confirmed.
- **A pending commit is the device's.** Over the command line a device
  undoes a confirmed commit only when its window ends; any `commit` or
  `commit check` typed on it meanwhile confirms the change.
- `--hold` and the review need a terminal; `--hold` is refused with `--json`.

## Rolling back

`tacctl rollback 0.2.8` takes the release before this one as a target, as a
dry run until `--apply [--yes]`:

```
tacctl rollback 0.2.8                  # the dry run: steps, warnings, nothing written
tacctl rollback 0.2.8 --apply --yes    # convert (after a snapshot)
tacctl upgrade --branch 0.2.8          # install 0.2.8
```

It removes `device.apply.confirm_timeout` and `device.apply.pause` from
`tacctl.yaml` (0.2.8 refuses them; `--yes` is needed while one is set) and
rewrites the per-tier and group drop-ins that are exactly this release's
text with 0.2.8's, after `visudo -cf` (an edited one is left and named).

It lists, and does not delete, what 0.2.9 left that 0.2.8 ignores: the
`applied` parts and the `login`, `user_pulled` and `hostname` fields of
`devices-config.json`, and `device-apply/` (the shape store and the locks).

**An apply that is not settled stops the rollback**, the dry run too: a
device whose record says `pending` or `unknown` is named with its time and
the command that settles it, `tacctl device config apply <name> --check`
(or `tacctl device config forget <name>` once the device was looked at by
hand). Until 0.2.8 is installed, do not run the new verbs; they write the
state again.

`tacctl rollback 0.2.3` works as before, removes the same two keys with the
other keys 0.2.3 lacks, and also lists the apply state it leaves. The
targets `0.2.4` to `0.2.7` are refused: one release at a time.
