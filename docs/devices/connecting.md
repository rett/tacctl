# Connecting to devices by name

[Documentation](../README.md) › [Network devices](README.md)

The device registry (`/etc/tacctl/devices.yaml`) gives the network devices that authenticate against this server a name, and `tacctl ssh <name>` opens a session to one. Enrolled Linux hosts are in the same namespace.

```
tacctl device add core-sw1 10.99.0.1 --vendor cisco --legacy-ssh   # register; pins the ssh host
                                                                   # keys and prints their
                                                                   # fingerprints
tacctl device check core-sw1        # scope, vendor tag, last seen, reachable, host key against the
                                    # pin, SNMP name and location
tacctl device config show core-sw1  # the device's data, then the walkthrough for its vendor and
                                    # scope
tacctl ssh core-sw1                 # a session, as you
tacctl ssh core-sw1 -- show version # one remote command
```

1. **Register.** A device whose address a scope's prefixes cover is `configured` in that scope (`tacctl device list`); one that no scope covers registers as `unconfigured`, and no one may connect to it. `--legacy-ssh` is for a device that offers only SHA-1 key exchange, CBC ciphers and `ssh-rsa`, and is the ssh algorithms and nothing else (the configuration syntax is `--ios-syntax`); `--vendor wti` selects the password-only method order. `device add` pins the host keys the device offers: **compare the printed fingerprints with the device's console** (Cisco `show ip ssh`, Junos `file show /etc/ssh/ssh_host_ed25519_key.pub` from the CLI, or `ssh-keygen -lf` on the same file from `start shell`, Linux `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). Names that are factory defaults (`switch`, `router`) are refused; name the device on the device too. Devices that already authenticate but are not registered are listed by `tacctl device discover`, each with a ready `device add` line; `tacctl device collect --discovered` logs in to them once and shows what each is, and `--register` registers them (see [Collecting from addresses nobody registered](planning.md#collecting-from-addresses-nobody-registered)). See [Host keys of devices and hosts (pinning)](../security/host-key-pinning.md#host-key-pinning).
   **Pulling on registering.** `tacctl device add <name> <address> --vendor cisco|juniper|wti --pull` registers the device and then runs `device config pull` for it, as you, in the same command (the pull's password prompt and report follow the add's output). Nothing is pulled without `--pull`. The flag is refused, before anything is registered, when your tier may not run `device config pull`, when you are root, or when the vendor is not one the pull reads. A device that no scope's prefixes cover is registered and not pulled; one line gives `tacctl scope prefixes <scope> add <cidr>` and the pull command to run after it. A pull that fails leaves the device registered, and the command exits with the pull's status. See [Device configuration](configuration.md#device-configuration).
   **The configuration syntax.** A Cisco device is walked through and compared in one of two syntaxes: `modern` (`tacacs server NAME` / `address ipv4`, IOS 15.2 and later, 16.x, 17.x and IOS-XE) or `ios12` (`tacacs-server host`, the IOS 12.x template). It is independent of the ssh algorithms: a router of IOS 15.6 or IOS-XE 16.7 may need `--legacy-ssh` and still speak the modern syntax. `tacctl device ios-syntax <name> [auto|ios12|modern]` sets it (no word prints it; `device add --ios-syntax` sets it on registering; `auto`, the default, is not written to the file). With `auto` the syntax comes from the version line the last `device config pull` read (`show version | include Version`: `Version 12.` is `ios12`; `Version 15.2` to `15.9`, `16.`, `17.` and `IOS-XE` are `modern`; any other line, such as IOS 11.x, IOS 15.0 and 15.1, an ASA registered as cisco or IOS XR, is **unknown, never guessed**: the pull is refused with the command to set `ios12` or `modern`, so a setting is how those devices are compared); a device not pulled yet is walked through in the modern syntax with a line that says so, and `device config list` calls it `pull` (`needs pull (syntax unknown)`) until it is pulled once. A setting that contradicts the image the last pull read (`modern` on a device that says IOS 12.4: the lock-out direction) is **not refused, the setting wins, and it is shown**: `device config pull` (text and `--json`: `syntax_conflict`), `device show`, `device config list` and the walkthrough each say it. A pull refused because its version was not read or is not mapped is not recorded, so `device config list` is unchanged; the pull's output says why. See [Device configuration](configuration.md#device-configuration).
   **The device's own name.** With SNMP set up (`tacctl config snmp`), `device add` also reads the device's `sysName.0` (and its `sysLocation.0`, which it stores as the device's location) and says what the device calls itself; a name that is not the one given (or its `--hostname`, or the first label of either) is a warning with the fixes, and the add goes ahead. `tacctl device add <address>` with no name offers the sysName, lowercased, at a terminal. See [The SNMP name hint](snmp-name-hint.md#the-snmp-name-hint).
2. **Who may connect.** An active tacctl user (in the store, not disabled) whose scopes include the device's scope, at every tier, superusers included. A local account that is not a tacctl user, a disabled user and a device in no configured scope are refused, and each refusal is logged to syslog (`ssh DENY`). A read-only or operator user (a member of `tac-users` with the [tiers file](../security/tiers.md#tiered-access) installed) may run `tacctl ssh` and sees only the devices of its own scopes.
3. **How it logs in.** ssh runs as you, never as root, and logs in with your own username and your tacctl password (which the device checks against this server): no agent, no key, no other login. Run it from your own account; as root it refuses. It needs a terminal.
4. **Plain `ssh`.** `tacctl device client-config > ~/.ssh/tacctl.conf` and `Include ~/.ssh/tacctl.conf` at the top of `~/.ssh/config` give a plain `ssh core-sw1` (and `scp`) the same options and the same pin. The fragment has one `Host` block per device you may see and no `User` line, so ssh logs in with your local username: a tacctl user whose local account has another name adds `User <tacctl name>` to its own `~/.ssh/config`. Re-run it after the registry changes.
5. **A key that changed.** When a device was replaced or reset, ssh is refused and tacctl prints the pinned and offered fingerprints and the console command that shows the key. After verifying on the console, an administrator re-pins with `tacctl device hostkey core-sw1 accept` (or `set SHA256:<fp>`).

## Slow or distant devices

A device behind a satellite circuit (a round trip of 600 ms) or with a slow CPU (one measured needs about 4 s for each ssh connection) can miss the timings tacctl uses to reach a device. One whole number from 1 to 10, the timing scale, multiplies all of them; 1, the default, is every timing as it has always been.

```
tacctl device timeout-scale sat-rtr1 3     # this device
tacctl scope timeout-scale site-a 3        # every device of the scope
tacctl config devices timeout-scale 2      # every device of the server
```

The scale in force for a device is its own, else its scope's, else the server's, else 1 (the order of the NETCONF service setting); `clear` removes a device's or a scope's own, and a verb with no value prints the scale in force, where it comes from and what it makes of each timing. `device show` has a `Timeout scale` row (and `--json` a `timeout_scale` object) and `scope show` a row when the scale in force is not 1.

| What | At scale 1 | Multiplied |
| --- | --- | --- |
| The connect, handshake and first prompt of an ssh or NETCONF session (`device config pull`, `diff --pull`, `plan --pull`, `apply`, `enroll`, `onboard`, `collect`, `support-bundle`) | 10 s | yes |
| The ConnectTimeout of `tacctl ssh` and `device ssh` | 10 s | yes |
| The host-key scans (`device add`, `hostkey`, `scan`, `check`, `enroll`, `collect`, `onboard`, and the diagnosis after a failed `ssh`): ssh-keyscan's `-T`, the built-in client's connect, handshake and per-type attempt | 5 s and 3 s; 3 s, 10 s and 5 s | yes |
| The SNMP timeout (`snmp.timeout`, `scope snmp timeout`, `device snmp timeout`) | 2 s | yes, never above its maximum of 10 s |
| The per-device time of a pull or an apply (`device.config.timeout`) | 90 s | yes, kept between 10 s and 600 s |
| The confirmed-commit windows (`device.config.confirm_timeout`, `device.apply.confirm_timeout`) | minutes | no: they are timers on the device |

An option typed on the command line wins over the scale: `--timeout` of a pull or an apply is the time of every device of that run, as typed (the scale only replaces the default, `device.config.timeout`). Where one run covers devices with different scales, each device has the time its own scale gives. A scale cannot make a lost packet arrive: a device that is down is still found out, only later.

From `tacctl shell`, `ssh core-sw1` is the same line. Every verb is in [Device Commands](../cli/device.md#device-commands--tacctl-device).
