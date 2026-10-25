# tacctl 0.2.18

0.2.18 makes the command names complete with Tab and cleans up what Tab
and `?` show. A verb that was a complete word and also the start of a
sibling (`device config` and `device config-syntax`) could not be
completed with a space; the siblings are renamed. The numbered list in
`CHANGELOG.md` (0.2.18, items 1 to 7) is everything that differs from
0.2.17.

## Renamed verbs, flag and setting

The old names are gone, not aliased: each is an unknown subcommand or
option, so a script that uses one must change.

| 0.2.17 | 0.2.18 |
|---|---|
| `device config-syntax <name> [auto\|ios12\|modern]` | `device ios-syntax <name> [auto\|ios12\|modern]` |
| `device add --config-syntax <syntax>` | `device add --ios-syntax <syntax>` |
| `device notices [<name>] [--all]` | `device notice list [<name>] [--all]` |
| `device ssh-config` | `device client-config` |

- **The stored setting.** The key in `devices.yaml`, in `device export`
  and in the `--json` output of `device list` and `device show` is
  `ios_syntax` (it was `config_syntax`); the audit line of a change says
  `field=ios-syntax`. A registry, a snapshot or an imported file that
  holds the old key is read as before, and the next change of the
  registry writes the new one. A script that reads `config_syntax` from
  the JSON must change.
- **Sudoers.** `tacctl upgrade` rewrites the tiers drop-in: the engineer
  tier gets `device ios-syntax *`, every tier `device notice list` and
  `device client-config`.
- **Rollback.** `tacctl rollback 0.2.17` is new and takes the release
  before this one: its `--apply` takes a snapshot, writes the setting
  back under `config_syntax` and puts back the tiers drop-in 0.2.17
  writes. `0.2.16` and `0.2.9` write the setting back too, and `0.2.3`
  removes it under either key.

## Completion and `?`

- `device ios-syntax` completes the Cisco devices and `device netconf`
  the Junos devices; hosts and other vendors are not offered.
- An unknown command prints one error line, a `Did you mean` line for a
  verb of that name or a close spelling, and a pointer to `tacctl`, and
  exits 1 as before (`tacctl enroll` suggests `device enroll` and `host
  enroll`).
- `?` and Tab describe every command, flag and fixed word from the lines
  of its own verb. Flags that showed another verb's text, descriptions cut
  short and verbs with no usage in `?` are fixed. The usage text writes
  placeholders, ranges (`<10-14>`) and choices one way, and a verb whose
  forms take different arguments has a row for each. The manual page
  follows the usage.

No setting is new and no exit status changes.
