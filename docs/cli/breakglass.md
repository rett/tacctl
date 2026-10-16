# Break-glass Commands — `tacctl breakglass`

[Documentation](../README.md) › [CLI reference](README.md)

```
breakglass hold <device>[=<reason>][,<device>[=<reason>]...] [--reason "<text>"]

    The server stops answering the registered devices named: each one's registered address (only
    that one) is taken out of every scope's prefixes at render time, so the device's local
    accounts are usable while the server is up. A device's reason is its own after "=" or the
    --reason default; one with neither is a usage error. Each device is checked on its own, the
    ones that pass are held together (one render, one restart of each backend whose file
    changed) and the others are named under "Not held" with why; exit 1 when any was not held.
    Asks for the names of the devices that pass typed back at a terminal (no --yes); prints the
    way in for the vendors present. Superuser only

breakglass release <device>[,<device>...]

    The server answers the devices again (one restart, the original rendering byte for byte).
    A name that is not held is named under "Not released" and the exit code is 1; the others
    are released. Superuser only

breakglass list [--json]

    The holds that stand: device, address, scope, since, how long, by whom, why. An engineer: the
    devices of their own scopes
```

```
tacctl breakglass hold "sw-lab-1=console recovery,sw-lab-2" --reason "failed paste"
tacctl breakglass release sw-lab-1,sw-lab-2
```

A per-device reason ends at the next comma: a reason that holds a comma is given
with `--reason`, which every device without its own reason takes.

See [Holding break-glass](../devices/break-glass.md#holding-break-glass) for what a hold does and when to use it. `scope breakglass <scope>` records the *names* of a scope's local accounts, which a hold makes usable.
