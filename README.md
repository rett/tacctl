# tacctl

Management toolkit for network-device AAA. Users, groups and scopes are kept once, in tacctl's own store, and served over **TACACS+** by [tacquito](https://github.com/facebookincubator/tacquito) (RFC 8907, by Facebook Incubator) and, when enabled, over **RADIUS** by a tacctl-owned FreeRADIUS instance. Provides a CLI for user, group, and configuration management with multi-vendor support for Cisco IOS/IOS-XE and Juniper Junos devices, plus WTI console servers and Linux hosts. A device registry names the devices that authenticate here, shows which of them have been seen, and opens ssh sessions to them by name.

## Quick Start

```bash
# Install on a new server (TACACS+; RADIUS can be added later)
sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl &&
  /opt/tacctl/bin/tacctl.sh install'

# Or upgrade an existing server (pulls the latest from GitHub, rebuilds if needed)
tacctl upgrade

# Fresh installs seed engineer/superuser, operator/operator and viewer/readonly,
# all disabled until a password is set, and root/readonly, an accounting-only
# sink for Junos internal daemons (its password cannot be set; its records
# without a terminal are answered but not recorded).
tacctl user passwd engineer

# Or add your own (into the default 'lab' scope)
tacctl user add jsmith superuser

# Create a production scope and grant jsmith access to it
tacctl scope add prod --prefixes 10.10.0.0/16 --secret generate
tacctl user scope jsmith add prod

# Manage users
tacctl user list

# Show device configs with the server's address and the scope's secret filled in
tacctl config cisco                   # default scope
tacctl config cisco --scope prod      # specific scope
tacctl config cisco --scope prod --legacy   # IOS 12.x syntax (pre-15.0 devices)
tacctl config cisco source-interface prod Loopback0   # pin the devices' TACACS+/RADIUS source
                                                      # address
tacctl config juniper --scope prod
tacctl config wti --scope prod        # WTI console server: serial-menu walkthrough
tacctl device config show core-sw1    # a registered device's data, then its walkthrough with its
                                      # scope, location and name

# Serve the same users over RADIUS as well
tacctl backend enable radius
tacctl scope vendor-attrs prod enable cisco,juniper   # RADIUS sends a vendor's privilege attribute
                                                      # only where a scope enables it
tacctl config cisco --scope prod --protocol radius
tacctl config juniper --scope prod --protocol radius
tacctl config wti --scope prod --protocol radius

# Name your devices, then connect to them by name (docs/devices/connecting.md)
tacctl device add core-sw1 10.10.0.1 --vendor cisco
tacctl ssh core-sw1

# Work from a prompt instead of typing "tacctl" each time
tacctl shell
```

## Documentation

| Topic | Contents |
|---|---|
| [Installation and upgrades](docs/install/README.md) | Requirements, upgrading, rolling back, troubleshooting |
| [Server](docs/server/README.md) | Backends, the store and generated configs, system files, RADIUS, metrics |
| [Security](docs/security/README.md) | Scopes, command authorization, management ACLs, tiers, the login console, host-key pinning |
| [Linux hosts](docs/hosts/README.md) | Enrolling hosts, the PAM module, UIDs and groups, account lifecycle |
| [Network devices](docs/devices/README.md) | Connecting by name, Cisco, Junos, WTI, break-glass, pulling, planning and applying configuration, onboarding blank devices |
| [CLI reference](docs/cli/README.md) | Conventions and one page per command family, every `tacctl.yaml` setting |
| [Development](docs/development/README.md) | Repository layout, tests, releases |

The manual page (`man tacctl`) covers every command and setting in one place.

## License

MIT License. See [LICENSE](LICENSE).
