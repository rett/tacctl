# CLI Reference

[Documentation](../README.md)

> For a single-page reference, run `man tacctl` after install.

## Pages

- [Conventions and top-level commands](conventions.md): Argument conventions and the top-level commands.
- [Shell and completion](shell.md): Shell completion, `tacctl shell` and the password cache.
- [User Commands — `tacctl user`](user.md): Users, passwords and per-user scope membership.
- [Group Commands — `tacctl group`](group.md): Groups, their privilege level, tier and Junos class.
- [Config Commands — `tacctl config`](config.md): Configuration settings and the device configuration walkthroughs.
- [Configuration tunables — `tacctl.yaml`](tunables.md): Every `tacctl.yaml` setting.
- [Scope Commands — `tacctl scope`](scope.md): Scopes: client prefixes, shared secrets and per-scope settings.
- [Host Commands — `tacctl host`](host.md): Linux hosts: enroll, sync, move, unenroll.
- [Device Commands — `tacctl device`](device.md): The device registry, notices, configuration pulls and plans.
- [Break-glass Commands — `tacctl breakglass`](breakglass.md): Holding and releasing a device's or host's break-glass.
- [Emergency Commands — `tacctl emergency`](emergency.md): Refusing the logins of groups on a scope (lockdown).
- [Console Commands — `tacctl console`](console.md): `tacctl console` and the console session.
- [Maintenance commands](maintenance.md): `tacctl backend`, `store`, `log` and `backup`.
- [Exit Status and Environment](exit-status.md): Exit codes and environment variables.
