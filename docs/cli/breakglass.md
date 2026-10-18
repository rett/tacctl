# Break-glass Commands — `tacctl breakglass`

[Documentation](../README.md) › [CLI reference](README.md)

```
breakglass hold <name>[=<reason>][,<name>[=<reason>]...] [--reason "<text>"]

    The server stops answering the registered devices and enrolled Linux hosts named: each one's
    address (a device's registered one, a host's recorded one; only that one) is taken out of every
    scope's prefixes at render time, so the device's local accounts, or the host's local
    administrator and console, are usable while the server is up. A name's reason is its own after
    "=" or the --reason default; one with neither is a usage error. Each name is checked on its
    own, the ones that pass are held together (one render, one restart of each backend whose file
    changed) and the others are named under "Not held" with why; exit 1 when any was not held.
    Asks for the names that pass typed back at a terminal (no --yes); prints the way in for the
    vendors present. Superuser only

breakglass release <name>[,<name>...]

    The server answers the devices and hosts again (one restart, the original rendering byte for
    byte). A name that is not held is named under "Not released" and the exit code is 1; the others
    are released. Superuser only

breakglass list [--json]

    The holds that stand: name, kind (device or host), address, scope, since, how long, by whom,
    why. An engineer: the devices and hosts of their own scopes
```

```
tacctl breakglass hold "sw-lab-1=console recovery,sw-lab-2" --reason "failed paste"
tacctl breakglass hold web1 --reason "locked out of sudo"
tacctl breakglass release sw-lab-1,sw-lab-2
```

A per-name reason ends at the next comma: a reason that holds a comma is given
with `--reason`, which every name without its own reason takes.

A hold follows its device: `tacctl device address <device> <address> [-y]`
moves the hold to the new address after one question that names both
addresses. The new address passes the checks of a new hold, the registry and
the record are written together, and the backends are rendered and restarted
once; see [`device`](device.md). `device remove` of a held device is refused
until the hold is released.

A held enrolled host keeps its local administrator and its console and loses
every login and sudo check by the server. A host is held by its name: an
address that is only its ssh target's is refused, naming the host. A name that
is both an enrolled host and a registered device is refused as ambiguous, and
so are this server's own host (`host enroll --local`), a loopback address, a
listener's address, a host with no recorded address (its ssh target is not an
address either; `host sync` records it), a host at the address of a
registered device and a host no scope covers. `host sync`, `host show --check`, the
other `host` verbs that log in over ssh, `host unenroll` and `host forget` are refused for a
held host until it is released; see [`host`](host.md). A hold follows
`host rename`: the record moves to the host's new name and stays on the same
address, and the rendered files, which name the host in a comment, are
rendered again (no backend is restarted). A hold recorded under the new name
refuses the rename.

See [Holding break-glass](../devices/break-glass.md#holding-break-glass) for what a hold does and when to use it. `scope breakglass <scope>` records the *names* of a scope's local accounts, which a hold makes usable.
