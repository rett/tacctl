# Fake device transcripts

Directories for `tacctl _fake-device <dir>` (a test build's hidden verb,
`internal/devssh/fakedev`): the files a fake device answers from, in the
layout `internal/devssh/fakedev/transcript.go` describes. The bats files
(`tests/integration/device_config_*.bats`) copy one, add the read command's
output (`<command>.out`: the configuration tacctl renders for the device,
taken from `tacctl config <vendor>`, so the pull agrees with it, or edited to
differ) and, with `TACCTL_TEST_DEVICE_DIAL`, point `device config pull` at it.

- `junos/`: the prompt of a Junos CLI. Its read command is
  `show configuration | display inheritance no-comments | display set`.
- `ios/`: the prompt of an IOS CLI. Its read command is `show running-config`
  (`terminal length 0` needs no file).

The login is the user who runs the verb (`SUDO_USER`) with the password of
`TACCTL_TEST_DEVICE_PASSWORD`: `_fake-device <dir> --user <name> --password
<text>` sets what it accepts.
