# Enrolling hosts over SSH

[Documentation](../README.md) › [Linux hosts](README.md)

`tacctl host` does the copy-and-run for you and keeps a registry of enrolled hosts:
```
tacctl host enroll admin@web1.example.net     # into the scope that covers web1's address; installs,
                                              # registers
tacctl host enroll admin@web2 --method radius # the same with pam_radius_auth against the RADIUS
                                              # backend
tacctl host enroll --local                    # this machine's own login, for every user
tacctl user scope jsmith add <scope>          # give a user a login on hosts of that scope...
tacctl host sync web1                         # ...and push the account (or: tacctl host sync --all)
tacctl host list                              # with each host's address and METHOD
tacctl host list --json                       # the same for scripts
tacctl host show web1                         # web1 in full: scope, keys, sightings, accounts, last
                                              # sync, OS facts
tacctl host show web1 --check                 # ...and compare the host itself with what tacctl
                                              # would make it
tacctl host check web1 web2                   # the same read-only check of several hosts
tacctl host check --all                       # ...of every enrolled host (exit 1 on a difference)
tacctl host target web1                       # how web1 is reached (target, port, identity,
                                              # addresses)
tacctl host target web1 root@web1-mgmt.example.net --port 2222   # change it, tested first
# switch the account tacctl logs in with:
tacctl host provisioner web1 rotate deploy --key ~/.ssh/web1-deploy --remove-old
tacctl host unenroll web1                     # remove the login method; accounts and home
                                              # directories stay
tacctl host default-method radius             # what hosts enrolled without --method get
                                              # (host.default_method)
```
The method of a host is, in order: `--method`; the method the host is registered with; the scope's `auth-method` (`tacctl scope auth-method`); the one protocol the scope's `protocols` filter names; `host default-method` (default `tacplus`). Its backend must be enabled and the scope must allow its protocol.

The scope of a host is, in order: `--scope`; the scope the host is registered in (re-enrolling never moves a host); the scope that answers its address (the first prefix that holds it, see `tacctl scope routing`), which enroll names: `10.1.2.3 (web1.example.net) is answered by scope 'lab' (prefix 10.0.0.0/8); enrolling web1 there`. A host whose address no scope covers is refused before anything changes, since the server would refuse its every login; enroll prints how to add the address to a scope (`tacctl scope prefixes <scope> add <address>/32`) or give the host a scope of its own, whose secret is useless from any other host (`tacctl scope add linux-web1 --prefixes <address>/32 --secret generate`, then `--scope linux-web1`). Enroll never creates a scope: a `/32` scope made for a host takes its address from any broader prefix, and that scope's users lose their accounts there.

**When the scope no longer answers the host.** A prefix change, a new address or an enroll into the wrong scope can leave a host registered in one scope while another answers its address: the server then checks its logins against that scope's users and secret, and refuses them. tacctl never moves a host on its own (a move changes its secret and deletes the accounts of the users it loses); it says so, with the fix, on every `host sync` of the host, after the `host list` table, and in `config validate` (from the address recorded at the last enroll or sync): `dev: registered in scope 'linux-dev', but 192.0.2.22 is answered by scope 'lab' (prefix 192.0.2.0/24): its logins are checked against that scope's users and secret, so they are refused. To move it: tacctl host move dev`. Moving prefixes between scopes is one change: `tacctl scope prefixes site-a move 198.51.100.0/24 lab` takes them out of one scope and into the other and names the enrolled hosts that then belong to the other scope. A scope enrolled hosts use cannot be removed until they are moved.

**This machine.** `host enroll --local` sets up this machine's own login:
every user can log in to it and to its console unless disabled or of tier none,
whatever their scopes; it takes no `--scope`. `--server <address>` is the
address devices and hosts reach this server at (an address behind NAT or a
VPN that is not on this machine is taken; a host name, `0.0.0.0`, `::`, a
loopback or link-local address is not). Without it the recorded address is
used, else `--server` defaults to the address of the interface with the
default route, said in one line (`Using 192.0.2.10 as the server address (the
address of eth0); pass --server to use another.`). The address is the setting
`server.addresses` in `tacctl.yaml` (a list that holds one address for now);
`host enroll --local --server <address>` changes it. An install from before
whose server is registered in a scope that serves the server alone is taken
over at the next `host sync` of the server or `host enroll --local`, its
secret kept, in one line; one that also serves hosts or devices is left to
them, and `host enroll --local` sets up the server's own login apart from it.
A `host sync` of the server repairs its login when it was changed by hand
(`Repaired the managed server login.`).

**One machine, one registration.** Enroll refuses this server's own address unless it is `--local` (`'<target>' is this server; enroll it with --local`), and a new name for a machine already enrolled under another one (the same address on the same ssh port, or one of this server's own addresses when it is enrolled with `--local`): `'h192-0-2-22' is the enrolled host 'dev' (enrolled as admin@host.example.net): both reach 192.0.2.22.` Re-enroll it under its registered name (`--name dev`) or change how it is reached (`tacctl host target dev <[user@]host>`).

**A machine registered twice.** Registrations made before the name rules
(`Web1` and `web1` both enrolled, or a host and a device with one name), or
left half-removed by a failed command, are reported by `config validate` and
`host list` (see [`host` findings](../cli/host.md)), each with its fix. They
are repaired from the registry alone: `tacctl host forget <name>` drops one
registration (registry line, pin, record, staging addresses) and sends nothing
to the host, so the surviving registration keeps its accounts and `host
unenroll --force` (which would run the removal script on the shared machine)
is not needed. It is also the way to remove the leftovers of a name that has
no registry line. (`host unenroll` drops a host's pin, record and staging
addresses itself.)

**Renaming a registration.** A host enrolled under the wrong name is not
enrolled again (that would be a second registration of the machine, refused
as above): `tacctl host rename <old> <new>` gives the registration another
name. It is local and sends nothing to the host. The pinned ssh keys and
recorded address, the host's record, its staging addresses and its
break-glass hold follow the name, after a snapshot. If the host is the only
one in its own scope `linux-<old>`, the command asks whether to rename that
scope to `linux-<new>` too (`-y` says yes); without that, enrolling the
renamed host again without `--scope` would put it in `linux-<new>`. See
[`host rename`](../cli/host.md).

**Host names.** The registry name is `--name`, else the host's short name,
lowercased (host names are not case-sensitive; a host already enrolled under
exactly that spelling keeps it). A name no enrolled host has with exactly that
spelling is a new one and must pass the rules a device name passes: lower-case
letters, digits, `.`, `_` or `-`, starting with a letter (253 at most, each
dotted part 63 at most, so a fully qualified name is one); not a tacctl
word (`all`, `scope`, `local` and the other words a device cannot be called);
and not the name of an enrolled host or a registered device in any case. A
`--name` with upper case is refused (`Names are lower case: use 'web1'.
Nothing was changed.`). Names are not case-sensitive, so `Web1` is refused
while `web1` is enrolled (`'web1' is enrolled; names are not case-sensitive.`)
and a device `core-sw1` keeps `Core-SW1` from being a host. A break-glass
hold recorded under the new name is refused (`A break-glass hold is recorded
under the name 'web9' ...`): only `tacctl breakglass release web9` removes a
hold. A host enrolled
before with upper case keeps working and is enrolled again under its
registered spelling; `tacctl host rename Web1 web1` fixes it, and `tacctl
config validate` lists it. Nothing is changed and nothing is attempted over
ssh. The device registry is read again once the client script has run, when
the registry line is written: a device registered meanwhile (`device add`
from another session) is found there, the line is taken back, and the command
exits 1 with `A device named 'web1' (192.0.2.60) was registered while the
client script ran; a host and a device cannot share a name.` and the command
to enroll again under another `--name`. The script has already run on the
host, which authenticates through this server as long as its scope covers
its address; no record, pin or audit line is written until it is enrolled
under a name of its own. What the command did before the script stays and is
warned of: a scope opened to both protocols for the host (`Scope 'linux-web1'
is still open to tacacs, radius; see 'tacctl scope protocols linux-web1'.`)
and a `--staging` bench address (`Staging address 192.0.2.50/32 stays in
scope 'lab' ...; remove it: tacctl scope staging remove 192.0.2.50/32`).
The same holds when another enrolment of the name finishes first. Enrolling a
registered host again under its registered spelling is allowed: that is how it
is enrolled again or moved. An option that takes a value (`--method`,
`--scope`, `--server`, `--name`, `--port`, `--identity`) given without one is
a usage error that names the option.

**One host in full.** `tacctl host show <name>` prints, in sections: Connection (target, port, identity, server, method), Scope (the registered one, the scope and prefix that answer the host's address today, the drift warning of `host list` with its `host move` fix, a pending staging /32), Address (recorded, previous and when it changed), Host keys (the pinned fingerprints and the command that shows them on the host), Sightings, Notices (`--all`: the acknowledged ones too), Accounts (the tacctl users the next sync makes there, with tier, UID and groups; disabled users counted), Last sync (when, by whom, the result or why it failed, the client script protocol, the accounts created, updated and removed) and Host facts (OS, sshd version, the PAM module and its version, `useradd`'s UID range from `login.defs`, as that run read them). The last two are kept in `/etc/tacctl/hosts/<name>.json`, written by each `host enroll` and `host sync` (a failed sync too) and removed by `host unenroll`; they are only shown, never used to decide anything, and a host with no such record shows `no record under this name`. `--json` prints every field. `--check` logs in read-only (as `host sync` does: your ssh, sudo with a terminal for its password) and compares the host with what tacctl would make it: tacctl's groups and their GIDs, each account's UID, primary group and home mode, the PAM files tacctl writes (present, and the text the client script recorded writing), the client script protocol and the host's ssh keys against the pins; each difference is one line with the command that fixes it, and the exit status is 1 when there is one:
```
  - group tac-superuser has GID 1002, not 80002. Fix: tacctl host sync web1
  - /etc/pam.d/tacctl-auth is not the text tacctl wrote there. Fix:
    tacctl host enroll admin@web1.example.net --name web1
```

**Checking several hosts.** `tacctl host check <name>... | --all [--json]` is
`host show <name> --check` for each host named, or for every enrolled host
with `--all`: the same read-only login as you, the same comparison, and
nothing changed on a host or here. The names are checked first (an unknown
name refuses the run, a name given twice counts once; names and `--all` are
not given together). Each host gets a result on standard output, and what the
host prints besides the check goes to standard error:

```
web1: as tacctl would make it.
web2: 2 differences:
  - alice has no account. Fix: tacctl host sync web2
  - /etc/pam.d/tacctl-auth is not the text tacctl wrote there. Fix:
    tacctl host enroll admin@web2.example.net --name web2
web3: skipped: break-glass is held on it since ...: <reason> (tacctl breakglass release web3)
web4: could not be checked: the read-only run as root on web4 failed (see above); ...
4 hosts: 1 as tacctl would make it, 1 with differences, 1 not checked, 1 skipped (held).
```

The last line comes with more than one host. The exit status is 1 when a host
has a difference or could not be checked, else 0; a held host is skipped, and
that is not a failure (it is read-only, so there is nothing to refuse). An
interrupt ends the run after the host in progress. `--json` prints an array
(`[]` for no host) and nothing else on standard output: for each host `name`,
`target`, `state` (`ok`, `differences`, `failed` or `held`), `differences`
(each `text` and `fix`), `notes`, `error` (why a host could not be checked,
else empty) and `breakglass` (the hold, only for `held`). Like `host show
--check` it is the superuser's: it logs in over ssh.

**A held host.** `tacctl breakglass hold <host> --reason "<text>"` makes the
server stop answering a host (its recorded address, else its ssh target's when
that is an address), so that tacctl users cannot log in or use sudo on it
while its local administrator and its console work; the host is named, not its
address. While the hold stands the `host` verbs that log in over ssh refuse
it, naming the hold and `tacctl breakglass release <name>`: `host sync`, `host
show --check`, `host enroll` of the registered host (so `host move`), `host
target <name> <target>`, `host provisioner <name> rotate` and `host unenroll`
(also with `--force`) and `host forget`. `host sync --all` skips the host and
says so, and `host check` skips it. `host list` marks it `BREAK-GLASS`, and `host show` has a Break-glass
section. This server's own host (`--local`) cannot be held. See [Holding
break-glass](../devices/break-glass.md#holding-break-glass).

**Provisioning off-site.** A host or network device set up on a bench, at an address its scope does not cover, before it is shipped to the scope's network: give the scope it will be installed in and `--staging` (`tacctl host enroll admin@bench-host --scope lab --staging`; `tacctl config cisco|juniper|wti --scope lab --staging <bench-ip> [--name <device>]`). The bench address joins the scope as a `/32`, so the scope's own secret and users answer the device on the bench and nothing changes on it when it comes online in the scope's prefixes. tacctl records it (`tacctl scope staging` lists each, with where its host or device is seen now) and removes the `/32` once the host (its next enroll or sync) or the registered device (`tacctl device address <name> <ip>`, `device add`) is seen at another address the scope covers: `Staging address 203.0.113.9/32 removed from scope 'lab': sw1 is now seen at 192.168.5.9 (prefix 192.168.0.0/16).` A device staged without a name, and not registered at its bench address, is removed by hand: `tacctl scope staging remove <address>`. **Moving a host:** `tacctl host move <host> [<scope>]` (without a scope: the one that answers its address; `--all`: every host another scope answers, with one snapshot taken before the first move and none per host), which is an enroll of the registered host naming the new scope; before anything changes it says `Moving dev from scope 'linux-dev' to scope 'lab': it gets that scope's secret and users.` and names the users whose accounts the move deletes, then asks on a terminal (`[y/N]`); without a terminal it stops unless given `-y`. Removed users' homes follow the usual rules (asked, `--remove-home`, or kept). **Switching:** re-enrolling a registered host with the other `--method` removes the first method's module, secret file and SELinux module and installs the other; re-enrolling without `--method` keeps the host's method.

`ssh` runs as the user who invoked `sudo`, with their keys; the remote login must be root or able to `sudo` (a password prompt works when run from a terminal). That login (the provisioning account: the target's `user@`, else your own username) must be a local account on the host that does not authenticate through tacctl, so enrolment and sync keep working when this server cannot be reached: `host enroll` refuses a tacctl user, and `host sync` warns about an existing enrolment that uses one. `tacctl ssh` never uses it. Without a terminal, a host whose sudo needs a password is reported as such rather than attempted. The steps of one command share a single ssh connection per host, so a login without a key asks for its ssh password once, followed by one sudo prompt; with a key (or agent) and passwordless sudo or a root login there is no prompt at all. `--scope` enrolls into an existing scope instead of creating one (the scope must answer the host's requests: `--local` is refused, nothing changed, when the scope does not cover 127.0.0.1, the address this server's own logins come from; another host gets a warning when the scope does not cover the address its name resolves to, and `host sync` of this server warns when its scope stops covering 127.0.0.1), `--server` overrides the detected server address, `--name` the registry name, and `--port` / `--identity` are passed to ssh. `host target <name> [<[user@]host>] [--port <n>] [--identity <file>|--no-identity]` changes how a host is reached without re-enrolling it: it logs in to the new target the same way first, checks that the login is root or may use sudo, compares the host's ssh keys read over that session with the pinned ones (a host whose keys differ is refused: it is not the same machine), records the address reached, and only then rewrites the registry line (scope, server and method kept), after a snapshot. Account changes are not pushed automatically: run `host sync` after `user add`, `remove`, `move`, `disable` or `scope` changes. Until then a removed user is already refused at password login by the server, but an SSH key on the host keeps working.

**Snapshots.** `host enroll` (so `host move`), `host unenroll`, `host rename`
and `host forget` take a snapshot just before they change the registry (for
`host enroll`, after the script on the host has succeeded); `host sync` takes
none. A snapshot holds `linux-hosts` (the registry), `hosts/` (the records),
`staging` and `linux-uids` (the UID ledger). `tacctl backup restore
<timestamp>` puts them back when the snapshot has `linux-hosts` (one from
0.2.13 or older does not, and leaves them alone). It touches no host: it
names, before it asks, the hosts that come back or go and the users whose UID
the ledger drops or changes, and a host that no longer matches is fixed with
`host sync`, `host show <name> --check`, `host unenroll` or `host enroll`.

**This server's registration and a required password change.** The method of
this server's own entry (`--local`) decides where the backends keep a user who
must change the password. While any user is flagged, `host forget`,
`host unenroll` and `host enroll --local` with another method are refused with
the command that lifts the requirement first ([A required password
change](../cli/user.md)). `host move` of this server says that its login is
set up by `host enroll --local`.
With `--keep-uids` the ledger is left as it is, for a snapshot wanted for its
users or scopes when the hosts have synced since. See
[Backup commands](../cli/maintenance.md#backup-commands--tacctl-backup).

**Rotating the provisioning account.** `tacctl host provisioner <name> rotate <user> (--key <file>|--password) [--remove-old [--remove-home]] [--dry-run] [--yes]` changes the account tacctl logs in to a host with, and cannot lock tacctl out of it. One rotation of a host runs at a time on the tacctl server (a command that finds the host's lock held, a second rotation or a `host rename`, `host forget` or `backup restore`, fails at once: "<name> is locked by another tacctl command"), and nothing is changed until the local checks pass (an enrolled host that is not this server's own `--local` entry; the new account is not `root`, the login in use or a tacctl user; exactly one of `--key` and `--password`, the latter on a terminal and for a host whose ssh host keys are pinned; `--remove-old` only when the registry target names its user as `user@host`). Then, in this order: (1) the new account is created over the login in use by a small script of its own, below tacctl's UID range (its group too) and out of the ranges the server used before (`useradd -m -U -s /bin/bash -c 'tacctl provisioning account'`; that comment is for display, since the account can change it itself and a directory service may supply it). Root's proof that tacctl made the account is a record the script writes at once under `/var/lib/tacctl-provisioner` (root's alone, 0700): a re-run adopts an account only when it is in `/etc/passwd` itself and that record agrees, and any other account of that name is refused. The key (or password) is set first and the account's sudoers line comes last, in `/etc/sudoers.d/tacctl-provisioner` (checked with `visudo -cf`, written under a lock on the host; never `tacctl-host`, which each sync rewrites). A failure takes back what the run did, the line included. (2) A fresh ssh login in a new connection, with only the new account's credentials, must run `sudo id -u` and get `0`; its ssh trusts the host's pinned ssh keys and no others (a temporary known_hosts of the pins, strict host key checking, your own known_hosts is not used), so another machine is refused by ssh itself. A host with no pinned keys has nothing to trust: the proof goes by your own known_hosts, lists the keys the host answered with and asks you to confirm them (`--yes` confirms), and `--password` is refused (it would be typed to a peer nothing has authenticated). (3) Only then does the registry change, as `host target` does it (after a snapshot, the entry read again so a `host move` that ran meanwhile is kept, the old login kept in the host's record, the audit line `host provisioner rotate name= old= new= auth=key|password by=`); (4) with `--remove-old`, the old account is removed last, over the new one: its sudoers line first, then its processes end, `userdel` runs, and its home is moved out of reach and made root-owned, or deleted with `--remove-home` (a terminal is asked when neither is given). It refuses to remove an account that is `root`, a tacctl user, the new account, or one with a number in tacctl's UID range, and while the registry does not point at the new account. With `--key <file>` the account has a locked password, `NOPASSWD: ALL` and only that public key in its `authorized_keys`, written by the account itself and only into a `~/.ssh` that is not a link, is the account's own and is not writable by others; a missing file is made by `ssh-keygen -t ed25519` (it asks for the passphrase, empty is your choice), and every access to the file runs as you, never as root. An adopted account's `~/.ssh` is emptied first and adopted only if tacctl made it; the rest of its home is not scanned, so an account that has been in use is better removed and made again. With `--password` the account has `ALL` with a password that you type into the host's own `passwd` over the ssh terminal: it never passes through tacctl, an argument, the environment, a file, a log or the audit line (a host whose sshd has `PasswordAuthentication no` always fails that proof). If the create script fails it takes back its own steps (an account it made, the sudoers line it wrote) and names anything it could not; an interrupted run without a terminal is hung up on the host too. What can remain: a host that loses power during the run, a shell killed outright, a removal that itself fails (named), and an adopted account's emptied `~/.ssh`. If the proof fails, an account this run created is removed with its home and its line, an adopted one is never deleted (only the sudoers line this run added is taken out, and the output says what was left), the registry is left alone (`auth.warning host provisioner rotate ... step=prove`), and if a removal fails too what is left is named; a run interrupted before the registry changed is repeated with the same command, which adopts the account, and one interrupted after it is finished by the same command with `--remove-old`. `--dry-run` prints the plan (the `useradd` line, the sudoers line, the key's fingerprint, the registry line before and after) and runs only a test login to the current target, a look at whether the account exists and whether root's record names it, and the host's `sshd -T` value of `passwordauthentication`.
