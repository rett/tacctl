# Live lab suite

`tests/lab/lab.sh run` registers real lab devices in a throwaway tacctl
sandbox (a temporary directory; no installed tacctl and no production host is
touched), pulls them with `tacctl device config pull`, and checks that each
device answered and that the pull recorded its release. It only reads from
the devices. The bats tests use a fake device (`tests/helpers/fakedev.bash`);
this suite is the one that meets a real image, with its slow prompts, old SSH
algorithms and odd output, so run it before a release and when a reader
changes.

## The devices

No address or login is stored in the repository. Put them in
`~/.config/tacctl/lab.env` (mode 0600) or point `TACCTL_LAB_ENV` at another
file:

```
LAB_PASSWORD='example-secret'
# name:address:vendor[:legacy]  -- legacy turns on 'device legacy-ssh' for a device
# that only offers SHA-1 key exchange, CBC ciphers or ssh-rsa
LAB_DEVICES='rtr1:192.0.2.11:cisco:legacy sw1:192.0.2.12:cisco jsw1:192.0.2.13:juniper'
```

Every device must accept the invoking user's name with `LAB_PASSWORD` (the
pull logs in as the user who runs it, with that password).

## Commands

| Command | What it does |
|---|---|
| `tests/lab/lab.sh run` | Build the sandbox, pull every device, check the result (exit 1 on a failure) |
| `tests/lab/lab.sh pull` | Pull again |
| `tests/lab/lab.sh list` | Show the sandbox's `device config list` |
| `tests/lab/lab.sh clean` | Remove the sandbox |

`make build` first: the suite uses `dist/tacctl` (`TACCTL_LAB_BIN` for
another binary). `pty-run.py` gives the pull its terminal password prompt.
