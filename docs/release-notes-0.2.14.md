# tacctl 0.2.14

0.2.14 extends the break-glass hold in two ways: a hold follows its device
when `device address` changes the address, and an enrolled Linux host can be
held. There is no change of state format, no new setting and no new way of
writing to a device. The numbered list in `CHANGELOG.md` (0.2.14, items 1
and 2) is everything that differs from 0.2.13.

## A hold follows `device address`

A change of address on a held device used to be refused until the hold was
released, and releasing answered the old address again. It now moves the
hold. The new address must pass what a new hold passes (not a loopback
address, not one a listener binds, not an enrolled host's address, not held
by another record, covered by a scope), and one line names both addresses
and asks to confirm (`-y` skips it). The registry and the record are
written together, rendered once, and each backend whose file changed is
restarted once. A refused address changes nothing. A restart that fails is
reported as `NOT restarted` and the verb exits 1, with the registry and the
record both on the new address. The superuser moves a hold; an engineer is
refused.

## A hold on an enrolled Linux host

`tacctl breakglass hold|release|list` name hosts and devices alike, with
the same record and the same carve-out: the server answers no login and no
sudo check for the host's address, while the host's local administrator and
its console keep working. A host is held by its name. The verbs that log in
to the host over ssh (`host sync`, `host show --check`, `host target`,
`host provisioner rotate`, `host unenroll`, and enrolling a registered host)
refuse for a held host and attempt nothing; `host sync --all` skips it.
`host list` and `host show` mark a held host, and engineers see the holds
of the hosts in their own scopes. The refusals that stay: this server's own
host, loopback and listener addresses, a host with no address, an address no
scope covers, and a name that is both a host and a device.

## Upgrading from 0.2.13

Upgrade with `sudo tacctl upgrade` as always; a second run changes nothing.
Nothing is written to a device and no file is added or converted.

## Known limits

- The configuration the backends render still reads `(device <name>)` in a
  comment for a held host.
- There is no `host rename`: a host enrolled again under a new name is a
  separate host, and the hold under the old name is listed as an orphan.

## Rolling back

No state changed, so there is no conversion: `tacctl upgrade --branch
0.2.13` installs 0.2.13 over it. Release any hold on a host first
(`tacctl breakglass release <host>`); 0.2.13 treats such a record as an
orphan.
