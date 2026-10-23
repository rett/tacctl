# Vendor detection (filed 2026-10-23; 0.2.18 candidate)

Status: design only, nothing built. `device add` defaults the vendor to
`other`, and nothing reads it from the device. A device left at `other` has
no `device config pull|diff|plan|apply`, no `--pull` at registration and no
vendor walkthrough until someone runs `device vendor`.

## Signal

SNMP `sysObjectID.0` (1.3.6.1.2.1.1.2.0) with `sysDescr.0`
(1.3.6.1.2.1.1.1.0), read with the credentials the name lookup already uses
(the device's, else its scope's, else the default's). One more GET of the
system group; no new setting and no new credential. It fails exactly where
the name hint fails (no SNMP, a wrong community, a timeout), and then
nothing is offered.

- cisco: sysObjectID under 1.3.6.1.4.1.9. and a sysDescr that starts
  `Cisco IOS Software` or `Cisco IOS XE Software`.
- juniper: sysObjectID under 1.3.6.1.4.1.2636. and a sysDescr that names
  JUNOS.
- wti: sysObjectID under 1.3.6.1.4.1.2634., offered only after a lab capture
  is a fixture.

Enterprise 9 also covers ASA, NX-OS and IOS XR, which `cisco` does not
support: an enterprise-9 answer without the IOS sysDescr is reported
(`Cisco, not IOS or IOS-XE`) and never offered. Anything ambiguous (a known
enterprise without the OS string, an unknown enterprise, no sysDescr)
prints what was read and offers nothing. Not used: the ssh banner, host-key
algorithms, the NAS-Identifier and the TACACS+/RADIUS attributes (none
carries a vendor reliably). The TAG column of `device discover` is the
vendor tag a person set on a scope address, not a detection.

## Surfaces

1. **`device add`.** After the sysName answer, the registered device is
   followed by `The device says it is Junos (SNMP sysObjectID ...).`
   - `--vendor` given and agreeing: nothing more. Disagreeing: a warning
     with `tacctl device vendor <name> <detected>`, never a refusal.
   - No `--vendor`, at a terminal: one `y/N` (default no) to register with
     the detected vendor. `device add <address>` folds it into the existing
     question: `Register 192.0.2.10 as 'sw1' (juniper)? [y/N]`.
   - Without a terminal the detection is only printed.
   - **No name.** When the name cannot be discovered (no answer, a sysName
     that is no valid device name, a generic one such as a WTI unit's
     `WTI`), `device add <address>` at a terminal asks for the name instead
     of refusing; the same rules apply to what is typed (lower case, valid
     device name, generic names need `--allow-generic`). Without a terminal
     it still refuses with the usage line.
2. **`device check`.** A `Vendor` row from the same read: `match`,
   `differs: device says juniper, registered other`, or `unknown (<id>,
   <descr>)`; `--json` `vendor_detected`. `device check --all` is the
   read-only report of devices at `other` whose detected vendor is
   supported.
3. **`device vendor <name> --from-device [-y]`.** Reads now, shows the
   registered and the detected vendor, writes after a `y` at a terminal or
   with `-y`, refuses an ambiguous read with the reason. Like
   `device location --from-device`.
4. **`device discover --probe`.** Contacts each listed address by SNMP (as
   `device list --probe` does) and fills the suggested `device add` lines
   with `--vendor` and the name found. Without `--probe` discover reads logs
   only and contacts nothing.
5. **Notice.** A vendor tag that disagrees with the detected vendor is a
   `device notices` kind (`device show` already warns on tag against
   vendor).

## A vendor change

`device vendor` drops `config-syntax` unless the vendor is cisco, drops the
NETCONF setting unless it is juniper, and keeps `legacy-ssh`. A config
record pulled under the old vendor stays and is read in that vendor's
shape, so a change marks the record `needs pull` (`diff` and `plan` say to
pull again instead of comparing it).

## Work

`DetectVendor(objectID, descr) (vendor, reason)` with a table test; the SNMP
getter gains the two reads (stub, test agent, `_snmp-agent --sysobjectid
--sysdescr`); `device add`, `device check`, `device vendor`, `device
discover`, the notice kind; `docs/cli/device.md`,
`docs/devices/snmp-name-hint.md`, `man/tacctl.1`, CHANGELOG; unit tests and
one bats case. No fakedev or container work.

## Before it ships

One lab capture of `sysObjectID` and `sysDescr` from a WTI unit and from a
Junos and an IOS device, kept as fixtures, before `wti` and `juniper` are
offered.
