# Security

[Documentation](../README.md)

Access control for the server, its users and the devices it serves.

## Pages

- [Network access](network-access.md): Listening address and connection filters.
- [Scopes](scopes.md): Prefixes, secrets and per-scope settings.
- [Management ACL](management-acl.md): Cisco VTY-ACL, Juniper lo0 filter and WTI IP Tables from the same permit lists.
- [Cisco priv-exec mappings](cisco-priv-exec.md): Mapping groups to Cisco privilege levels.
- [Per-command authorization](command-authorization.md): Command rules per group for Cisco, Junos and WTI.
- [Tiered access](tiers.md): Operator, engineer and superuser tiers for tacctl itself.
- [Login console](login-console.md): The restricted login console and its sshd configuration.
- [Passwordless sudo for operators](operator-sudo.md): Letting operator accounts run tacctl without a sudo password.
- [Host-key pinning](host-key-pinning.md): Pinning and verifying the host keys of devices and hosts.
- [Password generation](password-generation.md): Generated passwords and the self-service flow.
