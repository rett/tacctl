# Installing

[Documentation](../README.md) › [Installation and upgrades](README.md)

```bash
sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl &&
  /opt/tacctl/bin/tacctl.sh install'

tacctl install                          # an installed tacctl: the plan, then [y/N]
tacctl install --yes                    # answer yes to every confirmation
tacctl install --server 192.0.2.10      # the address devices and hosts reach this
                                        # server at
tacctl install --branch develop         # install from a branch
```

`install` shows its plan and asks `Continue with installation? [y/N]`. It
builds the TACACS+ backend, installs the clone in `/opt/tacctl`, the command,
the completion and the manual, seeds the store (see [Upgrading](upgrading.md)
for what a re-run keeps), starts the service, and ends with the summary and
the shared secret of the new `lab` scope, shown once. (Lines of output are
wrapped in the examples below.)

**This machine's own login.** Every user can log in to the tacctl server and
its console, so `install` sets up the server's own login too, with the
machinery of `tacctl host enroll --local`: the scope tacctl manages for it
(`tacctl`, which no listing shows), this server's entry in the host registry,
the PAM client and sshd's drop-in, and the accounts of the users. It asks
once, after the services are started, with the server address in the question
(`--yes` answers it):

```
[INFO] Using 192.0.2.10 as the server address (the address of eth0); pass --server to
use another.
Set up this machine's own login now, with 192.0.2.10 as the server address? [y/N]:
```

The server address is `--server`, else the address recorded in
`server.addresses` (a rerun of `install`), else the address of the interface
with the default route; the last is said in one line every time it is used.
The address is recorded in `tacctl.yaml` (`server.addresses`; `tacctl server
addresses` shows and changes it, see [Server commands](../cli/server.md)).

What `host enroll --local` does to stay safe is done here too: sshd's
configuration is checked with `sshd -t` before sshd is reloaded and the change
is undone if sshd refuses it, root and the local administrators are not
touched, the PAM files it replaces are backed up, and a snapshot is taken
before the change (`tacctl backup list`). A step that cannot be done safely
does not stop the install, which completes with its usual status and prints
one line that says what was skipped and the command to run:

```
[WARN] This machine's own login was not set up (the enrolment stopped, see above;
nothing is half applied); to set it up: tacctl host enroll --local
```

Nothing is left half applied: a failed setup leaves the store, the registry
and `tacctl.yaml` as they were. A run that is answered `n`, or has no standard
input to answer on, says the same in one line. Running `install` again when
the login is set up does nothing and prints nothing about it.

`tacctl host enroll --local` stays the command to rebuild a server (the entry
is there but the PAM files are not), to move it to another address (`--server`, or `tacctl server addresses
replace`, which is the same change) and to repair it.
