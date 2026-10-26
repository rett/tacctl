# Network Device Configuration

[Documentation](../README.md)

`tacctl config cisco` and `tacctl config juniper` generate copy-pasteable configs with your server's IP and shared secret filled in. `tacctl config wti` prints a menu-by-menu walkthrough of a WTI console server. Each takes `--protocol tacacs|radius`; without it the output follows the scope (see [Which protocol a scope uses](../server/radius.md#which-protocol-a-scope-uses)) and is TACACS+ otherwise.

## Pages

- [Connecting to devices by name](connecting.md): `tacctl ssh` and the registry.
- [Cisco IOS / IOS-XE](cisco.md): the Cisco configuration.
- [Juniper Junos](junos.md): the Juniper configuration.
- [WTI console servers (DSM/CPM/REM/TSM/RSM, firmware 8.x)](wti.md): serial-menu configuration of WTI units.
- [RADIUS device configuration](radius.md): device configuration for RADIUS scopes (`--protocol radius`).
- [Break-glass](break-glass.md): local accounts for when the server is unreachable, and holding a device or enrolled host back.
- [Custom templates](templates.md): editing the templates the output is rendered from.
- [Device configuration](configuration.md): reading, comparing and recording what devices run.
- [Support bundles](support-bundle.md): `device support-bundle`, a scrubbed collection of what a developer needs of one device.
- [Planning a device's change](planning.md): the paste-ready plan for a device, and `device config apply`, which types it under a confirmed commit and proves it; `device enroll`, which takes a new address from its host key to its plan in one attended run; `device onboard`, which brings a blank device in with one of its local accounts; `device collect`, which reads what an unregistered address is, and `device sync`, which fills the registry's empty fields from the records.
- [SNMP and NETCONF in the walkthroughs](walkthroughs.md): the SNMP and NETCONF steps, host keys and `tacctl ssh`.
- [The SNMP name hint](snmp-name-hint.md): the device's own name and location, and SNMP settings.
