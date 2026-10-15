# Conventions and top-level commands

[Documentation](../README.md) › [CLI reference](README.md)

## Command Conventions

These patterns apply across every subcommand family:

- **No arguments** — dispatcher commands (`user`, `group`, `config`, `scope`, `host`, `device`, `console`, `backend`, `store`, `log`, `backup`, `hash`, and nested dispatchers like `scope prefixes` / `scope secret` / `scope aaa-order` / `scope exec-timeout` / `scope tacacs-group` / `scope radius-group` / `scope auth-method` / `scope vendor-attrs` / `scope devices` / `scope mgmt-acl` / `scope snmp` / `scope block` / `user scope` / `group privilege` / `config linux`) print their own usage and exit without side effects. Scalar getter/setters (`config loglevel`, `config listen`, `config metrics`, `config password-age`, `config bcrypt-cost`, `config password-min-length`, `config secret-min-length`, `config branch`, `scope default`, `host default-method`, `device address|hostname|vendor|port|description|location|legacy-ssh|stale-days`, `console idle-timeout|agent-forwarding|ssh-escape`) print the current value when called with no arguments.
- **Filters and opt-ins** — a setting that narrows something down is a *filter*: its verbs are `set` and `clear`, and empty (cleared) means everything (`scope protocols`, `config allow`, `config deny`). A setting that turns something on is an *opt-in*: its verbs are `enable` and `disable`, and nothing is on until it is enabled (`backend enable|disable`, `scope vendor-attrs`). An opt-in has no verb that could read as "empty means all".
- **Membership lists** — a list that names exactly what is in is a *membership list*, and empty means nothing, not everything (`user scope`, the scopes a user can authenticate from: none means nowhere; `scope prefixes`, the clients a scope serves: emptying it removes the scope). Its verbs are `add` and `remove`: `remove --all` empties it, and `user scope` replaces its whole list with `replace`.
- **Multi-item input** — every `add` / `remove` that takes a CIDR, a scope name, or a Cisco exec command accepts either a single value or a comma-separated list (`a,b,c`). Every input is validated first; a bad entry aborts the entire operation without writing anything.
- **CIDR semantics** — every CIDR-list subcommand (`scope prefixes`, `config allow`, `config deny`, `config mgmt-acl`, `scope mgmt-acl`) canonicalizes input before storage (a management ACL entry may carry services after the CIDR, `10.0.0.0/8:tcp/22,udp/161`, and is canonicalized as a whole; see [Management ACL](../security/management-acl.md)): `10.1.5.5/24` becomes `10.1.5.0/24`, `2001:DB8::/32` becomes `2001:db8::/32`. Exact duplicates (after canonicalization) are rejected as no-ops on `add`. Overlapping CIDRs of different prefix lengths coexist (`10.0.0.0/8` and `10.99.0.0/16` can both be present). Stored order is by broadcast-address ascending (IPv4 before IPv6): disjoint ranges sort by their end address, and an overlapping subnet falls immediately above its containing supernet (the subnet's range ends before the supernet's). This puts overlapping CIDRs most-specific first, so a narrower scope wins tacquito's first-match lookup over a broader scope that contains it.
- **Scope prefix invariants** — every CIDR belongs to **exactly one** scope after canonicalization. Adding a prefix already claimed by a different scope is rejected with a message naming the owner; you must `tacctl scope prefixes <owner> remove <cidr>` before re-adding it elsewhere. Overlapping prefixes *across* scopes are allowed and routed correctly (e.g. `10.5.0.0/16` in `staging` coexists with `10.0.0.0/8` in `lab`). In the rendered `tacquito.yaml` a scope with N prefixes becomes N `secrets:` entries sharing the same `name:` and `secret.key`, sorted globally by prefix specificity (v4 before v6, smaller broadcast first), so tacquito's slice-ordered walk picks the narrowest scope. The CLI shows the logical one-bundle-per-scope view.
- **`clear` and `remove --all`** — `clear` and `remove --all` subcommands always prompt with `[y/N]` and print a warning describing the resulting posture (e.g. "no clients can connect" or "fails open"). Every prompt cancels, with a message, when standard input is closed.
- **Service restart** — changes to the store, and to the `tacctl.yaml` settings a backend renders (command rules, listeners, `backends.*`), re-render every enabled backend and restart the ones whose files changed. Settings only device configs read (mgmt-acl permits + names, priv-exec mappings, per-scope AAA order, exec timeout, group labels) and tacctl's own tunables (bcrypt cost, password age, …) restart nothing.
- **Flags** — long-form flags (`--hash`, `--scopes`, `--scope`, `--prefixes`, `--secret`, `--protocols`, `--vendor-attrs`, `--match`, `--action`, `--branch`, `--protocol`, `--method`, `--backend`, `--listener`, `--out`) take a single argument; `--default`, `--force`, `--legacy`, `--check`, `--replace`, `--json`, `--local`, `--all`, `--dry-run`, `--long`, `--apply`, `--hosts` and `-y`/`--yes` take none. Required positional args come before flags.

## Top-Level Commands

```
tacctl install [--branch name] [-y|--yes]  # Install tacctl and the TACACS+ backend from scratch (-y: no confirmation)
tacctl upgrade [--branch name]  # Pull latest source, rebuild, update system files and every enabled backend
tacctl uninstall [-y|--yes]     # Remove tacctl, its backends' services and all associated files (-y: no confirmation, keeps no archive)
tacctl rollback <version> [--apply] [--yes] [--hosts]  # Prepare the state for the release before this one (0.2.9) or for 0.2.3: a dry run unless --apply; see install/upgrading.md, "Rolling back"
tacctl status                   # Service health, stats, errors, password age warnings (per backend)
tacctl passwd                   # Change your own password (asks for the current one; all tiers)
tacctl user <subcommand>        # User management (incl. per-user scope membership)
tacctl group <subcommand>       # Group management
tacctl scope <subcommand>       # Scope management (CIDR+secret bundles)
tacctl host <subcommand>        # Linux hosts: enroll, sync, unenroll, default-method
tacctl device <subcommand>      # Device registry: names, addresses and notices for the devices that authenticate here
tacctl breakglass <subcommand>  # Break-glass hold: make the server stop answering one device (hold, release, list); see devices/break-glass.md, "Holding break-glass"
tacctl ssh <name|address> [-p port] [-X|-Y] [-g] [-L|-R|-D spec]... [-- ssh args]  # ssh session to a registered device or enrolled host, as you, by password (never root)
tacctl console <subcommand>     # Login console: tiers, per-user overrides, settings
tacctl backend <subcommand>     # Backends: list, status, enable, disable
tacctl store <subcommand>       # The canonical store: show, import, rollback
tacctl config <subcommand>      # Configuration
tacctl log <subcommand>         # Log viewer
tacctl backup <subcommand>      # Backup management
tacctl hash                     # Show usage
tacctl hash generate            # Prompt + print a bcrypt hash
tacctl hash commands            # Print OS-specific client-side recipes
tacctl version [--long]         # Print tacctl version (--long: commit, build date, Go version); `tacctl --version` and `-v` print it too
tacctl completion bash|zsh|fish # Print the completion script of a shell (install and upgrade place the bash one)
tacctl shell [--no-history] [--idle min] [--space-completion on|off] [--password-cache] [-c line]  # Interactive prompt: one tacctl command per line (runs as you; sudo per line)
```

Run any command without arguments for detailed help.
