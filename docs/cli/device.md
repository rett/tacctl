# Device Commands — `tacctl device`

[Documentation](../README.md) › [CLI reference](README.md)

The device registry gives names to the network devices that authenticate here. It lives in `/etc/tacctl/devices.yaml` and never touches `store.yaml`: a device's scope and vendor tag are looked up from the store when shown, so registering a device renders nothing and restarts nothing. Every write takes a snapshot first.

```
device list [<word>] [--name <text>] [--ip <addr|cidr|text>] [--vendor <v>] [--scope <s>] [--stale]
            [--unconfigured] [--scan] [--probe] [--json]

    Registered devices, then enrolled hosts, sorted by name; `--name` (names containing the text),
    `--ip` (an address, a CIDR or a text the address contains), `--vendor` and `--scope` narrow the
    list (one value or a comma list, any of them; the options must all match) and a bare word
    matches a name, an address, a vendor or a scope. Scope, STATE (configured: a scope's prefixes
    cover the address; unconfigured; stale), last seen / by / via from the seen cache, CONFIG (the
    state of the last configuration pull: `ok`, `differs`, `never`, `failed`, `pull` for a Cisco
    device whose syntax is unknown; `-` for a host, a vendor `other` and a device in no scope; the
    operator tier's: a read-only user's list has no such column), open notices; --scan scans first,
    --probe adds REACH (TCP connect to the ssh port, 3 s)

device show <name|address> [--all] [--json]

    One entry in full (scope and routing prefix, shadowed scopes, vendor tag, pinned keys, sightings
    and NAS-Identifier, the SNMP settings it is read with and where each comes from, the
    configuration of the last pull and the state of each section, then the `Release:`, `Model:` and
    `Serial:` rows that pull read from the device (left out when empty; all of this for the operator
    tier and up), the open notices and how many are acknowledged; --all lists the acknowledged ones
    too, marked)

device add [<name>] <address>

    Register a device (writes devices.yaml: superusers, and engineers for their own scopes); no
    name: the SNMP sysName is offered at a terminal, lowercased, and a terminal is asked for the
    name when the device gives none that can be offered (without a terminal: refused). The vendor
    the device names by SNMP (sysObjectID and sysDescr) is printed; a `--vendor` that disagrees
    is warned about, never refused; without `--vendor` a terminal is asked one y/N to register
    with it (see The SNMP name hint (devices/snmp-name-hint.md))

    --vendor cisco|juniper|wti|other
        Default other; drives the ssh profile, never tags the address in the scope
    --hostname <dns>, --port <n>, --description <text>
    --legacy-ssh
        SHA-1 key exchange, CBC ciphers and ssh-rsa for the ssh login (the ssh algorithms only)
    --ios-syntax auto|ios12|modern
        The Cisco configuration syntax (default auto: the pull's version line says); `--vendor
        cisco` only
    --snmp-location <text>
        Its place (120 characters), the SNMP location the walkthroughs render; without it the
        device's own sysLocation is read and stored (see The SNMP name hint
        (devices/snmp-name-hint.md))
    --host-key SHA256:<fp>
        Register only if the device offers a key with this fingerprint; pin that key alone
    --no-host-key
        Register without scanning: unpinned, with a hostkey-unpinned notice
    --no-lookup
        Do not read the device's own name, location and vendor by SNMP (sysName, sysLocation,
        sysObjectID, sysDescr)
    --pull
        After registering, read its configuration as `device config pull` does, for this device, as
        you; needs a vendor cisco, juniper or wti (`--vendor`, or the one the device names and
        the question takes) and a scope that covers the address (else it is registered and not
        pulled, with the commands that fix it); a failed pull leaves it registered
    --allow-generic
        Register a generic name (switch, router, cisco, ubuntu, ...) anyway

device onboard <address> --login <local-user> [--name <name>] [--host-key SHA256:<fp>]
               [--legacy-ssh] [--check] [--section <list>] [--json]

    Engineers, Junos devices: bring a blank device reached with one of its local accounts under
    tacctl in one run: the one host key that would be pinned (ed25519 first, then ECDSA, then RSA)
    shown with the Junos console command that shows it and accepted before any login by typing the
    device's name (`--name`, else its SNMP sysName, else the name to register it as, checked by the
    name rules; Enter or any other answer sends nothing; `--host-key` names the key instead;
    without a terminal only `--host-key --check` runs), the pre-flight as the local account (no
    pending commit, no TACACS+ or RADIUS server already, no local account of your own name), the
    registration through `device add` with that key pinned (the others offered are shown, not
    pinned; the device's own location and description fill the empty fields; never the hostname),
    the pull and the device's own check of the first-time plan as the local account (`--check`
    stops there), the review (the device's name typed back), then your own password and the commit
    as the local account, proven by your own fresh TACACS+ login (the template user of your group's
    class) and confirmed; see Onboarding a blank device (devices/planning.md, "Onboarding a blank
    device")

device collect <address>... | --discovered [--login <local-user>] [--host-key SHA256:<fp>]
               [--register [-y]] [--json]

    Engineers, Junos devices: log in once to each address nobody registered and read what it is:
    address by address and before any login, the one host key that would be pinned (ed25519 first,
    then ECDSA, then RSA) shown with the Junos console command that shows it and accepted by typing
    the address back (with `--register`, the device's SNMP sysName when it gives one that is not
    taken, not generic and valid; else the address, with a line that says why); Enter skips the
    address, any other answer refuses it, and nothing is sent to either (`--host-key` names the key
    of one address instead; without a terminal it is needed); then `show version` and the pull's
    read command in one session, nothing else, as one table (address, host name, model, release,
    authentication order, servers, EN-CLASS, NETCONF, lo0 filter, legacy ssh); your own password,
    or with `--login` a local account's, asked once and never kept or cached; the first refusal
    ends the run; `--register` registers each through `device add` under the name it reports, with
    the key accepted pinned (one question, `-y` without a terminal; `-y` answers only that
    question, never a key's) and keeps the read as its first pull record; `--json` lists under
    `host_keys` only the key accepted (none for a skipped or refused address); a registered address
    is refused; see Collecting from addresses nobody registered (devices/planning.md, "Collecting
    from addresses nobody registered")

device enroll <address>... | --discovered [--host-key SHA256:<fp>]
              [--vendor cisco|juniper|wti|other] [--name <name>] [--legacy-ssh] [--json]

    Engineers: the chain from an address to a plan, per address and in the order given
    (`--discovered`: the addresses `device discover` lists). Refused before any question: an
    address registered already, one no scope covers, one in a scope you are not a member of, a
    held one, one that offers no host key. The one key that would be pinned (ed25519 first, then
    ECDSA, then RSA) is shown with the console command that shows it; compare them and type the
    device's name (its SNMP sysName, or the name to register it as when SNMP gives none) to
    accept it; Enter skips the device, any other answer refuses it. The vendor the device names
    by SNMP is taken, else asked (`other` registers the device and ends its chain, exit 0); one
    y/N; the device is registered at once through `device add` with that key pinned (the others
    are shown as offered, not pinned); one snapshot for the run. Then your password, once, the
    pull of every device registered with a vendor tacctl reads, the registry rename to the name
    the device is configured with when a name was typed or given (Junos `host-name`, IOS
    `hostname`, a WTI unit's Site ID; kept, with the reason and the `device rename` line, when
    that name is taken, generic, not a valid name or the device is held; nothing is written to
    the device), the plan, printed as `device config plan --no-secrets` prints it (each secret a
    marked line; `device config plan <name>` prints the region to paste), and for Junos devices
    whose plan has a change one question that runs the apply review (each device's name typed
    back; a device whose plan has none says `nothing to apply`). Without a terminal:
    `--host-key` for one address, with `--vendor` and `--name` where SNMP reads none; `--json`
    and no terminal end at the plan. A device registered stays registered when a later stage
    fails; the table under the run (ADDRESS NAME VENDOR KEY PULL PLAN RESULT) gives each one's
    next step. Exit 0 every address went as far as its vendor allows, 1 one was refused, skipped
    or failed, 2 wrong arguments or no terminal, 130 interrupted; see Enrolling a device
    (devices/planning.md, "Enrolling a device")
    --discovered
        The unregistered addresses that authenticated (the seen cache); no address with it
    --host-key SHA256:<fp>
        Pin this key of ONE address, read on its console: no question (the only form without a
        terminal)
    --vendor cisco|juniper|wti|other
        The vendor of ONE address (default: the one it names by SNMP, else asked); a vendor the
        device names otherwise is a warning
    --name <name>
        The name of ONE address (default: its SNMP sysName, else typed at the key's question)
    --legacy-ssh
        Scan and register every device of the run with the legacy ssh algorithms (a device that
        answers only those is found so without it)
    --json
        The pull's lines and the plan's objects, then one object of the run, on standard output;
        the questions, the progress and the table on standard error

device sync <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> [--apply] [--overwrite]
            [--json] [-y]

    Engineers: fill the registry's empty hostname, location and description from what each Junos
    device's last pull record says of itself (no login; a reported host name is filled only when it
    resolves to the device's registered address and no other): the preview first, `--apply` writes
    in one registry write after one question (`-y`), `--overwrite` also replaces a field that is set
    and shows the old value; control characters and values the registry would not accept are
    refused; see Filling the registry from the records (devices/planning.md, "Filling the registry
    from the records")

device support-bundle <name> [--vendor cisco|juniper|wti] [--login <local-user>] [--out <dir>]

    Engineers: log in once to a registered device and collect what a developer needs to make tacctl
    read that kind of device (fixed, read-only commands; no configuration), scrubbed and written as
    a directory of text files: names, users, classes, addresses, serial numbers, locations,
    contacts and time zones become the standard example values, comments and secrets are removed.
    What was replaced is kept in `<dir>.map` (mode 0600), beside the directory, never in it.
    `--vendor` reads the device as another vendor for this run only; `--login` is a Junos local
    account's one-shot password, as for a pull; see Support bundles (devices/support-bundle.md)

device remove <name>[,<name>...] | --all [-y]

    Remove from the registry (confirms; hosts, scopes and vendor tags are not touched)

device rename <old> <new> [--allow-generic]

    Rename a device; the device's own host name is unchanged and not planned by tacctl, and the verb
    says so. The new name is lower case; changing only the spelling to lower case
    (`device rename Core-SW1 core-sw1`) is how a name from before is fixed

device address|hostname|vendor|port|description|location <name> [<value>|clear]

    Show, set or clear one field (`location`: the SNMP location of the walkthroughs; an empty text
    clears it too). A vendor change marks the last pull `needs pull (vendor changed)`: `config
    diff`, `plan` and `sync` say to pull again instead of reading it in the new vendor's shape

device vendor <name> --from-device [-y]

    Read the vendor the device names by SNMP now (as `device add` does), show it beside the
    registered one and set it after a `y` at a terminal, or with `-y`; a read that names no
    vendor, no answer and SNMP not set up are refused with the reason and change nothing

device address|description|location <name> <value> --apply

    After the value is stored, run `device config apply` for the device in the same command: the
    same review, answered by typing the device's name back, and the confirmed commit; superusers,
    Junos devices, at a terminal (anything else is refused before the registry changes); a value
    that is already set applies nothing; the exit status is the apply's

device address <name> <address> [-y]

    On a device with a break-glass hold the hold moves with the address (superuser; an engineer
    is refused). The new address must pass what a new hold passes: not a loopback address, not
    one a listener of either backend binds, not an enrolled host's, not held by another record,
    covered by a scope. One line names both addresses and asks to confirm (`-y` skips it); the
    registry and the record are written together, rendered once, and each backend whose file
    changed is restarted once (a restart that fails is reported as `NOT restarted`, exit 1; both
    stay on the new address). A refused address changes nothing. `--apply` is refused for a held
    device. `device remove` and `device import` of a held device are still refused

device location <name> --from-device [-y]

    Read the device's own location (SNMP sysLocation) now and store it; an empty answer is refused;
    a different registered one is shown beside it and replaced after a `y` at a terminal, or with
    `-y`

device legacy-ssh <name> [enable|disable]

    Opt in to the legacy ssh algorithms (SHA-1 key exchange, CBC ciphers, ssh-rsa); the
    configuration syntax is `ios-syntax`

device ios-syntax <name> [auto|ios12|modern [--apply]]

    Show or set the Cisco configuration syntax the walkthrough and the comparison use: `ios12`,
    `modern`, or `auto` (the last pull's version line says; no pull yet: modern in the walkthrough,
    `needs pull` in the comparison); an engineer's for the devices of their own scopes; Cisco
    devices only (a device that stops being Cisco through `device vendor` loses the setting, and the
    verb says so); one that the last pull's image contradicts is shown as such; `--apply` as for the
    fields above (the apply writes to Junos devices only in this release, so it is refused here
    before the setting changes); Tab offers the Cisco devices

device netconf <name> [show|enable|disable|leave|clear] [--connection-limit <n>|none]
               [--rate-limit <n>|none] [--apply]

    Superuser, Junos devices: show or set the device's own NETCONF service setting over its scope's
    (`scope netconf`): `enable` (with the limits, 1 to 250; one not given is the scope's),
    `disable`, `leave` (the device is left alone whatever its scope says) or `clear` (the scope's
    decides again). With no word, or `show`, it prints the setting and where each value comes from;
    `device show` has a `NETCONF` row, and `--json` a `netconf` object, when a Junos device's
    setting is not the default. A device that stops being Junos through `device vendor` loses the
    setting, and a registry file or an import that gives one to another vendor is refused; `--apply`
    as for the fields above; Tab offers the Junos devices

device stale-days [<n>]

    Days without a sighting after which a device is stale (default 30)

device notice list [<name>] [--all]

    The open notices, each with the command that fixes or acknowledges it (--all: the acknowledged
    ones too, marked); every tier, filtered to the caller's scopes

device notice <name> ack|unack <kind>

    Acknowledge or reopen a notice; the superuser's (three words are this form, so a device named
    `list` takes it too)

device import [--check] [--replace] [--allow-generic] [-y] <file|->

    CSV (name,address[,vendor[,port[,description]]]) or the registry's YAML; a file is existing
    data (so is the CSV of `device export --csv`) and loads its names as they are (a line says how
    many have upper case); merges by default,
    `--replace` removes the devices the file does not name together with their configuration records
    and SNMP credentials, as `remove` does; a CSV row, and a YAML file with no `ios_syntax`,
    leave a device's registered configuration syntax alone (an engineer imports from standard input
    only, `-` first)

device export [--csv|--json]

    The registry (YAML by default), only the devices of your own scopes below the administrator tier

device hostkey <name> [show]

    The pinned ssh host-key fingerprints of a device or enrolled host (administrators)

device hostkey <name> accept [-y]

    Re-scan and pin every key it offers, after confirmation (verify on the console first)

device hostkey <name> set SHA256:<fp>

    Re-scan and pin only the key with this fingerprint

    The scan behind `device add`, `device hostkey accept|set` and the rest is one `ssh-keyscan`
    for ed25519, ecdsa and rsa together. A device that accepts the connection but gives no key to
    that (one that limits the simultaneous connections ssh-keyscan opens, or drops its long
    offer) is asked again one key type at a time, ed25519, ecdsa, rsa (and ssh-rsa with
    `--legacy-ssh`), each with `-T 3`; the keys of every type that answers are returned, and a
    type that fails does not fail the scan. A device that refuses the connection or does not
    answer is not asked again.

device ssh <name|address> [-p <port>] [-X|-Y] [-g] [-L|-R|-D <spec>]... [-- <ssh args>]

    Same as tacctl ssh

device client-config

    Print an ssh_config Include for your devices (Host blocks with the vendor options and the pin)

device scan [--full] [--since <dur>] [--backend <id>]

    Read the backends' logs into the seen cache from where the last scan stopped; re-scan pinned
    host keys (never re-pins); print each log's window and the notices

device discover [--all] [--snmp] [--backend <id>]

    Scan, then list the addresses that authenticated unregistered, each with a ready 'tacctl device
    add' line; --all adds those only refused; --snmp reads each address's sysName and vendor by
    SNMP (its scope's credentials) and puts them in the line (`--vendor` when the device names
    one; what was not used as a `# SNMP:` comment). Without --snmp it contacts nothing

device check <name>|--all [--json]

    Checklist: scope, vendor tag, last seen, reachable (TCP connect, 3 s), host key against the pin,
    SNMP (the settings the device is read with and where each comes from; a credential only as set
    or not), SNMP name (sysName, match or differs), Location (sysLocation against the registry's:
    match, differs, registry only, device only; writes nothing), Vendor (the vendor the device
    names by SNMP against the registered one: match, differs, or unknown with what was read),
    NETCONF (a Junos device: what the last pull's probe found, `hello ok`, `port closed`, `no
    hello`, or `not probed`; a check logs in to nothing), notices; --all ends with the devices
    registered as other that name a vendor; --json: the rows, with sysname, syslocation,
    vendor_detected (vendor_reason, vendor_error) and netconf

device snmp <name> [show [--reveal]]

    The device's SNMP settings as it is read with: version, port, timeout, credentials (set or not;
    `--reveal` prints them, an engineer's own scopes' devices only, logged: one `secret-read` line
    for each level a printed secret comes from) and allowed clients, each with where it comes from:
    `(device)`, `(scope <scope>)`, `(default)` or `(built-in)`. A setting the device does not set
    comes from its scope, then the default, then the built-in

device snmp <name> version [v2c|v3]

    Show or set the device's own SNMP version (superusers); `community` and `v3-user` set it too

device snmp <name> port [<n>]

    Show or set the device's own agent port (1-65535)

device snmp <name> timeout [<seconds>]

    Show or set the device's own wait for an answer (1-10 seconds)

device snmp <name> clients list|add|remove [<cidr>[,<cidr>...]]

    The ranges allowed to query this device: its own list replaces its scope's (IPv4, at most 32,
    never `0.0.0.0/0`); removing the last gives the scope's back

device snmp <name> community [--stdin]

    Set the device's own v2c community (asked twice, not echoed; `--stdin`: one line); the device's
    version becomes v2c

device snmp <name> v3-user <user> [--stdin]

    Set the device's own v3 user and passphrases (authPriv; the protocols are the scope's or the
    default's); the device's version becomes v3

device snmp <name> clear

    Remove everything the device sets of its own (its map and its credentials file, which is removed
    without being read): its scope's settings apply again

device block <name> list

    The device's own configuration blocks, as `scope block ... list`, with the scope's blocks
    beneath named, and the device's orphans (a vendor directory that is not the device's, a device
    that is not registered)

device block <name> show <block> [--effective] [--reveal]

    The device's block elided (or as stored with `--reveal`); `--effective` is the block as it is
    rendered for the device (the scope's with the device's laid over it) with a comment per object
    that says which layer it comes from

device block <name> check <block> [--file <path>|-] [--against]

    As `scope block ... check`, for the device's own block; `--against` plans this device with the
    text in force

device block <name> set <block> (--file <path>|-) [-y]

    Superuser; as `scope block ... set`. Only a Junos or an IOS device in a scope has blocks

device block <name> remove <block> [-y]

    Superuser; as `scope block ... remove` (also for a device that has left every scope)

device block <name> edit <block> [-y]

    Superuser, at a terminal; as `scope block ... edit`. A new block opens with the scope's objects
    as `# set ...` lines to uncomment where the device differs

device block <name> adopt <block> [-y]

    Superuser, at a terminal; as `scope block ... adopt`, from this device, minus what the scope's
    block states with the same statements

device config show <name> [--protocol tacacs|radius] [--legacy] [--server <address|name>]
                   [--source <address>]

    The device's data (name, address, hostname, vendor, scope and prefix, description, location),
    then the walkthrough `tacctl config <vendor> --scope <its scope> --name <name>` prints, with the
    device's own values in the SNMP step (engineers: their own scopes' devices; a vendor `other`, an
    enrolled host or a device no scope covers is refused with the command that fixes it)

device config pull <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> | --stale
                   | --differs | --name <text> | --ip <addr|cidr|text>

    Log in to the devices as you and read each one's configuration: the managed sections (`aaa`,
    `roles`, `mgmt-acl`, `snmp`, `netconf`, `breakglass`; a WTI unit's are `aaa`, `mgmt-acl`,
    `snmp`, `breakglass`) are extracted, compared with what tacctl renders for that device and
    recorded; one line per device, a summary, exit 0 (differences are not failures), 1 (a device
    failed), 2 (wrong arguments), 130 (interrupted); names and `--all` stand alone, the filters
    combine (see Selecting devices, below)

    --stale --differs --name <text> --ip <addr|cidr|text>
        Filters of the selection, each below; they also select for `diff`, `plan` and `apply`
    --transport auto|netconf|ssh
        NETCONF where the device answers and the vendor reads over it (Junos; `auto`, the default),
        NETCONF only, or the ssh command line only
    --concurrency <n>, --timeout <seconds>, --max-failures <n>
        At most n devices at once (never above `device.config.max_concurrency`), the time one may
        take (10-600, default `device.config.timeout`), stop starting devices after n failures
    --diff --json
        Print the differences after the summary; one JSON line per device, then the summary
    --server <address|name>, --source <address>
        As for `config <vendor>`: the addresses the expected configuration is rendered with (not
        stored)
    --login <local-user>
        Engineers (`pull`, `diff --pull`, `plan --pull`): log in to one named, registered Junos
        device with a pinned key as that local account instead of you (any local account, a
        break-glass one included; only `root` is handled apart: only on a device never read as you);
        the password is asked once on the terminal and never kept or cached, the record says
        `login=local:<account>`; a device on which break-glass is held is refused (release it first)
        (see Onboarding a blank device (devices/planning.md, "Onboarding a blank device"))

device config diff <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> | --stale
                   | --differs | --name <text> | --ip <addr|cidr|text>

    The last pull against what tacctl renders now, per section: `-` a statement the device lacks,
    `+` one it has in a managed hierarchy that tacctl does not render, `!` a reordering, `?` a
    secret the login could not see, `=` a secret present (its value is never compared or shown); a
    section in which nothing rendered is missing or different and the extras are only statements of
    the device's own, kept by rule, reads `ok (+N unmanaged)`

    --pull
        Read the devices first (with the options of `pull`)
    --section <list>, --json, --exit-code
        Only those sections; JSON; exit 2 when a device differs (none failed)

device config plan <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> | --stale
                   | --differs | --name <text> | --ip <addr|cidr|text>

    What to paste to make each device match what tacctl renders, from the last pull: the report in
    plain words (each irregularity, its severity, what the paste does about it), one region between
    `PASTE FROM HERE` and `PASTE TO HERE` that is safe to paste whole (Junos ends it at `commit
    confirmed`, IOS at `end`), the check, the one line to type yourself afterwards and the back-out;
    a WTI unit has no region: its plan is a numbered checklist of menu steps to type and one
    `<iptables>` block for its IP tables list. A cover page for several devices. Reads no device
    unless `--pull`; writes to none. A device never pulled, pulled more than `stale-days` ago, whose
    last pull failed or whose Cisco syntax is unknown cannot be planned (exit 1). Engineers: their
    own scopes' devices

    --pull
        Read the devices first (with the options of `pull`)
    --section <list>
        Only aaa, roles, mgmt-acl, snmp, system, netconf (the report still names the others)
    --converge
        Add the cleanup of a device with nothing else to paste: the region that removes the old
        servers and the like (a device with a first region gets that and a line to plan again after
        the paste)
    --secrets --no-secrets
        Type the secrets of the planned sections also where the device has them; leave each secret
        as a marked line to fill in
    --plain --json, --backout
        The statements of one device alone (for `load set`); one object per device; the back-out
        region alone (the one kept from the plan once a later pull replaced the picture; not with
        `--pull`)
    --out <file>, --out-dir <dir>, --force
        Write one device's output, or one file per device with `COVER.txt` and each back-out (0600,
        0700 directory); replace what exists
    --from <address>, --exit-code
        The address you are logged in from (the cleanup keeps it; a Junos management filter that the
        device applies to `lo0` must permit it, or its section is refused, in either filter mode);
        exit 2 when a device needs a change
    --restore-point[=<fs>]
        (IOS and IOS-XE only) A restore point before the region, in a banner pair of its own: `copy
        running-config <fs>tacctl-<device>-<time>.cfg` on the file system named (`flash:`,
        `bootflash:`, `disk0:`) or, bare, `archive config` where the last pull read an `archive`
        with a `path`; the back-out names `configure replace` with it (a file, not a timer; the plan
        marks these lines as not checked on a device; not with `--plain` or `--backout`)

device config apply <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> | --stale
                    | --differs | --name <text> | --ip <addr|cidr|text> [--pull]

    Engineers, Junos devices: check each device's plan on the device (exclusive configure session,
    the device's own `commit check`, the candidate discarded), show the devices that need a change
    grouped by shape with every secret elided, ask for each device in turn (its line, then its name
    typed back, spaces and tabs around it ignored: anything else, another case, a carriage return,
    Enter or the end of input declines it, with no second try and no answer for several devices;
    all are asked before the first commit), then commit each approved
    device under `commit confirmed`, prove it with a fresh login as you, the landed change and a
    read of the planned sections, and confirm it; a failed proof rolls it back, a device whose state
    could not be read is `PENDING until <time>`; `--transport auto|cli|netconf` (default `config
    devices apply-transport`, `cli`) chooses the command line or NETCONF per device, and a change to
    the NETCONF service is always made over the command line.
    Exit 0 every device applied, was checked or had no change, 1 a device failed, was rolled back or
    is pending, a device was declined at the review (the others approved are still applied; JSON
    `"stop":"not-approved"`) or none was applied (every one skipped), 2 wrong arguments, 130
    interrupted (a Ctrl-C at a question of the review, or before the first commit, applies
    nothing). The audit lines of the
    review, the approval and each device's apply carry `mode=attended`, or `mode=scripted` for
    `--confirmed -y`

    --check
        Stop after the device's own commit check: nothing is committed, the shape is recorded
        (`--exit-code`: exit 2 when a device needs a change)
    --confirmed
        Apply only shapes an earlier apply confirmed and skip the others; the one form `-y` answers
        the review of (every device's question, no terminal needed; the lines say `mode=scripted`)
    --max <n>, --pause <seconds>, --no-canary
        At most n devices of a run (default 5); wait between devices after each shape's first
        (0-3600, default `device.apply.pause`); start a shape's devices together instead of its
        first alone
    --hold
        After the fresh login keep the change only when you log in with one account of each class
        and type `OK` (needs a terminal; not with `--json`). A line typed after the device before
        was answered or timed out, and before the question for this one, is dropped; one typed
        ahead of the first question is its answer
    --section <list>
        Only aaa, roles, mgmt-acl, snmp, system, netconf
    --pull
        Read the selected Junos devices first, as `pull` does (its lines,
        records and audit lines, over `device.config.transport`: `--transport`
        is how the apply writes), with the run's one password. A device whose
        pull fails is a failed row and is not checked; a pull that stops
        (interrupted, a refused password, `--max-failures`) ends the run with
        nothing checked. `--stale` and `--differs` then select from the fresh
        records (the others are `skipped ...: pulled, and the fresh pull
        matches what tacctl renders`, JSON `left_out.match_after_pull`, or,
        when a device cannot be compared, `could not be compared ...`, JSON
        `left_out.not_compared_after_pull`; neither is checked), so `--pull
        --differs` applies to the devices that differ now; without them every
        device pulled is checked. `--pull --differs` with no other selector
        pulls every Junos device you can see; the apply is still capped by
        `--max` and reviewed as any apply. With `--json` each pull object
        carries `"phase":"pull"`; a named Cisco device or WTI unit's refused
        row comes before them, and a device whose pull failed has only its
        pull object (the summary counts it failed)
    --concurrency <n>, --timeout <seconds>, --max-failures <n>, --server <address|name>,
                  --source <address>
        As for `pull` (an apply runs one device at a time unless `--concurrency`; `--max-failures`
        defaults to 1)
    --json -y
        One object per device and phase, then the summary (the review goes to standard error; each
        device's answer is an object with `"phase":"review"`, `"status":"approved"|"declined"` and
        `"mode":"attended"|"scripted"`; a declined device has only that object, no `"phase":"apply"`
        one; a review cut short by Ctrl-C ends with `"phase":"review","status":"interrupted"`);
        answer the review (with `--confirmed`)

device config shapes [list [--show <hash>] [--json] | seed <name>[,<name>...] [-y]]

    Superusers: the shapes of the changes `apply` has seen (the same change on two devices is one
    shape), which a verified apply confirmed, the devices at each now and, for a new one, the
    nearest confirmed shape; `--show` prints one shape's statements. `seed` files the shape of a
    device's last check or apply as confirmed on your word, for a device applied and verified by
    hand (one question; `-y` answers it). Contacts no device

device config list [--stale] [--never] [--failed] [--differs] [--name <text>]
                   [--ip <addr|cidr|text>] [--transport netconf|ssh|none]
                   [--scope <scope>] [--vendor <vendor>] [--json]

    Each device's state (`ok`, `differs`, `never`, `failed`, and `pull`: a Cisco device whose syntax
    is unknown, `needs pull (syntax unknown)`, or a device whose vendor changed since its last
    pull, `needs pull (vendor changed)`; a failed pull's DETAIL is its result: `denied` and
    `unsupported` for a WTI unit among the others), computed against today's rendering, with the
    release the last good pull read (`RELEASE`, `release` in `--json`; `-` when none), when it was
    read, by whom, over what, the NETCONF probe and the sections that differ (an `ok` device that
    holds statements of its own, which the plan keeps by rule, shows `snmp +N unmanaged`, and
    `--json` has the `unmanaged` map of section to count; a WTI unit's DETAIL and `--json` `unit`
    add its command menu version, Site ID and how many other sessions it had at the last pull);
    `--stale` is never, failed, differs and pull together; `--name` and `--ip` narrow the list as
    they do for the other verbs. The state words (`--stale`, `--never`, `--failed`, `--differs`)
    are alternatives here, but `pull`, `diff`, `plan` and `apply` require both when given both,
    so `list --stale --differs` shows more devices than they would select; the DETAIL of a device
    whose `ios-syntax` contradicts its pulled image says so (`syntax_conflict` in `--json`)

device config forget <name>[,<name>...] | --all

    Delete the pull records and stored sections (derived data: a pull makes them again);
    administrators
```

New device names are lower case: `device add`, `rename` and the
registrations of `device onboard` and `device collect --register` refuse a
name with upper case (`Names are lower case: use 'core-sw1'. Nothing was
changed.`); a name a device reports, or `device discover` suggests, is
lowercased. `device import` loads the names of a file (a CSV from
`device export --csv` too) as they are, so a server can be rebuilt from its
export. A name that exists with upper case keeps working, is found in any
case, and is listed by `tacctl config validate` with the `device rename` that
fixes it.

A device is found by name (any case) or by its registered address; an unregistered address is not found, even when a scope covers it. An address is registered once. A device name is letters, digits, `.`, `_` and `-`, starting with a letter or digit, at most 253 characters with each dotted part at most 63, so a fully qualified host name (`sw1.site-a.example`) is one. An enrolled host's name is the same, starting with a letter; `host enroll` borrows the short name from the target (`alice@sw1.example.net` is `sw1`), and a fully qualified name is given with `--name` or `host rename`. Enrolled Linux hosts share the namespace and appear in `list` and `show` as `linux` entries, read-only. `list`, `show`, `notice list`, `client-config` and `tacctl ssh` are open to the read-only and operator tiers, limited to the entries of their own scopes (`tacctl ssh` is limited so for every tier); `export` is operator-level, filtered the same way.

A name that is a factory or image default is refused with the command that names the device on the device itself (`hostname`, `set system host-name`, ...); a host already enrolled under such a name is not refused and carries a `generic-name` notice. `host enroll --name` follows the same rules. Add your own patterns with `generic_names:` (regular expressions, whole-name, case-insensitive) in `devices.yaml`.

**Seen data.** `device scan` reads what the daemons logged about each device into `/var/lib/tacctl/devices-seen.json` (0600, a cache: never snapshotted, `--full` rebuilds it): the tacquito journal (`journalctl -u tacquito … -o json`, resuming at its cursor; the `accepting user [u] from [address]` / `failed to validate the user [u] from [address]` lines, `bad secret detected for ip [address:port]`, `remote [address:port] has no secret providers` (no scope covers the address), and at log level 30 `prefix secret provider matches remote [address]`) and FreeRADIUS's `tacctl-auth.log` with its rotations (`client=`, `nas=`, `user=`, resuming by inode and offset). The first scan reads the last `stale-days` days; `--full` everything the logs hold, `--since 7d` that stretch. Per address it keeps the first and last sighting, the count, the last user, outcome and backend and the NAS-Identifier; records unseen for twice `stale-days` are dropped. `list` and `show` read the cache only (`seen data as of <time>`). An interactive session of the console or of `tacctl shell` (operator tier and up) starts `device scan --if-stale --quiet` in the background as it opens, so the logins are in by the time the list is looked at and nothing waits for it: it does nothing when the cache is younger than five minutes or another scan holds it (sessions that start together run one), reads a device's host keys again only when that device's last scan is a day old, goes on after the session ends, and prints nothing. Seen data an hour old or more is said so, with the command to run, in the footer of `list` and in the `Last seen` line of `show` (a read-only caller is told that an operator can run it); LAST SEEN is `rejected <time> (bad secret)` when the last exchange was refused. `check` and `list --probe` connect to the ssh port: the server often has no route to management ports, so a timeout may be a false alarm. `scan`, `discover` and `check` are operator-level.

**Selecting devices.** `device config pull`, `diff`, `plan` and `apply`
take device names, or `--all`, or filters that combine (a device must pass
every one given): `--scope`, `--vendor`, `--stale` (never read, last read in
failure, differing, or needs a pull), `--differs`, `--name <text>` and
`--ip <addr|cidr|text>`. Names and `--all` stand alone: naming a device and
a filter, or `--all` and a filter, is a usage error (exit 2), and so is a
filter given with no value (`--scope=`, `--name ""`). `--differs` keeps the
devices whose last good pull differs from what tacctl renders today, as
`device config list --differs` shows them; it is decided from the records and
the rendering, so no device is contacted and no password is asked. A device
that needs a pull, never was read, failed its last pull or whose stored
sections cannot be read is `--stale` but not `--differs`. With both, a device
must be both. `--name` keeps the devices whose name contains the text, in any
case; `--ip` keeps those whose address equals the address, lies inside the
prefix, or contains the text (`10.20.`); each takes a comma list, and any
item may match, as in `device list`. Because both match text, select the
devices of an `apply` by exact names, a full address or a CIDR: `--ip 10.1.1`
also matches 172.10.1.x and 10.1.10-19.x, and `--name sw1` also matches
`sw10`. A filter simply drops the devices that do not pass it. A device the
selection picks but cannot read (vendor `other`, no scope, a scope that is not
yours, a break-glass hold) is counted and named in the note that follows the
run; that note is made before `--stale` and `--differs` are applied, so it can
name a device those two would have left out anyway. An `apply` checks every
selected device on the device itself first, so a stale record can select a
device that then has no change, never a change nobody reviewed. `apply
--pull` pulls the devices the other selectors pick first and applies
`--stale` and `--differs` to the records that pull wrote.

Each change also writes a line of its own to the audit log, beside the `cmd start` and `cmd end` pair: `device add`, `device remove`, `device rename`, `device import`, `device set name= field= from= to=` for the setters and `device sync` with the devices written; a shown SNMP secret is `secret-read kind= name=` for every caller, and `device config show|plan` and the walkthroughs log the secret they read the same way ([Audit log](../security/audit.md#detail-lines)).
