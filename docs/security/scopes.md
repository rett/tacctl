# Scopes

[Documentation](../README.md) › [Security](README.md)

A **scope** is a named bundle of `(client CIDR prefixes, shared secret)`. Each user carries a list of scope names; authentication succeeds only when the scope the client IP falls inside is in the user's scope list. Scopes let you run multiple environments (prod, lab, edge) off a single server with distinct secrets and tight device-class boundaries. A scope is served by every enabled backend unless its `protocols` filter says otherwise (`tacctl scope protocols prod set tacacs`).

A fresh install has a single scope, **`lab`** (the least-privilege default). A user added without scopes (`tacctl user add alice operator`) can authenticate only on lab devices; production access must be granted explicitly.

**Overlapping prefixes across scopes are supported.** A narrow lab subnet can live inside a broader production scope's address space; the most specific prefix wins (tacctl emits one `secrets:` entry per (scope, prefix) pair, globally sorted by specificity, so tacquito's first-match provider walk picks the narrowest scope; FreeRADIUS matches clients by longest prefix). No two scopes can claim the same exact prefix.

Example multi-environment setup (broader prod with narrower lab and sandbox carved out):
```
tacctl scope add prod_dc_east  --prefixes 10.10.0.0/16      --secret generate
tacctl scope add prod_dc_west  --prefixes 10.20.0.0/16      --secret generate
tacctl scope add corp_campus   --prefixes 172.20.0.0/16     --secret generate
tacctl scope add lab_east      --prefixes 10.10.99.0/24     --secret generate   # carved from
tacctl scope add sandbox       --prefixes 10.10.200.0/23    --secret generate   # prod_dc_east

tacctl scope default prod_dc_east                  # optional: new users land in prod by default
tacctl user add alice superuser --scopes prod_dc_east,prod_dc_west
tacctl user add dev1 superuser  --scopes sandbox,lab_east    # no prod access

tacctl scope lookup 10.10.99.7                     # -> lab_east (shadowed by prod_dc_east, lab)
tacctl scope lookup 10.10.1.5                      # -> prod_dc_east (shadowed by lab)
```

Emit per-scope device configs:
```
tacctl config cisco --scope prod_dc_east            # prod's secret + header mentions sibling scopes
tacctl config juniper --scope lab_east
```

Scope management commands:
```
tacctl scope list                              # name, prefix list, user count, default marker
tacctl scope show <name>                       # full detail + secret length/posture (not its value)
                                               # + users + default-ness
tacctl scope add <name> --prefixes <cidrs>     # --secret <v> | --secret generate | --protocols |
                                               # --vendor-attrs | --default
tacctl scope remove <name> [--force]           # refuses if users reference it; --force strips them
tacctl scope rename <old> <new>                # rewrites user refs, default marker and per-scope
                                               # settings
tacctl scope default [<name>]                  # show / set the default
tacctl scope lookup <ip|cidr>                  # trace which scope owns an address (+ shadow
                                               # overlaps)
tacctl scope prefixes <name> list|add <cidrs>|remove <cidrs>|remove --all [--force]
tacctl scope secret <name>   show|set <v>|generate
tacctl scope protocols <name> list|set <csv>|clear
tacctl user scope <user>     list|add <s>|remove <s>|replace <s>|remove --all
```
