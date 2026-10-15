# Break-glass Commands — `tacctl breakglass`

[Documentation](../README.md) › [CLI reference](README.md)

```
breakglass hold <device> --reason "<text>"

    The server stops answering one registered device: its registered address (only that one) is
    taken out of every scope's prefixes at render time, so the device's local accounts are usable
    while the server is up. Asks for the device name typed back at a terminal (no --yes); restarts
    the backends whose file changed (once); prints the way in for the device's vendor. Superuser
    only

breakglass release <device>

    The server answers the device again (one restart, the original rendering byte for byte).
    Superuser only

breakglass list [--json]

    The holds that stand: device, address, scope, since, how long, by whom, why. An engineer: the
    devices of their own scopes
```

See [Holding break-glass](../devices/break-glass.md#holding-break-glass) for what a hold does and when to use it. `scope breakglass <scope>` records the *names* of a scope's local accounts, which a hold makes usable.
