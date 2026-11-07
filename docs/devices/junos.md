# Juniper Junos

[Documentation](../README.md) › [Network devices](README.md)

The generated config includes template user creation, TACACS+ server setup, and verification commands. All groups and their Juniper classes are included.

**Key points:**
- Template users must exist before TACACS+ logins work. If a login fails silently after a successful TACACS+ authentication, the template user is missing
- The classes carry permission bits only. A group whose class is `EN-CLASS` gets the engineer bits (`view view-configuration network clear trace reset configure rollback interface interface-control routing routing-control firewall firewall-control system system-control snmp`) and its template user
- Step 3 lists, per class, what the server sends at login: the group's `deny-commands` and `deny-configuration` values with their sizes against the 241 and 236 byte limits, or `none`. Nothing in it is pasted; the sets are changed on the tacctl server with `tacctl group junos` (superuser) and apply at the next login; `tacctl group show <group>` prints the patterns themselves to every tier. `show cli authorization` after a login shows the values the device received
- The `tacctl group commands` rules are Cisco's and are not translated into class `allow-commands`/`deny-commands`; Step 3 lists the `delete system login class <class> allow-commands` lines that remove what an earlier walkthrough put there
- The server's port is the configured listener's (`tacctl server listen`; 49 by default): a listener that moved adds `set system tacplus-server <address> port <n>`, a default one adds nothing, and in management filter mode `strict` the replies term accepts that source port (see [The server's port](walkthroughs.md#the-servers-port)).
- The server is set without `single-connection`: tacquito closes a connection that has been idle for 15 seconds, and a device that keeps one connection for many sessions is left with a dead socket (a later login over it fails with `Network read timed out`). An earlier walkthrough set it; `tacctl device config plan` removes it (`delete system tacplus-server <address> single-connection`) and `diff` lists it as an extra
- Use `config juniper` to regenerate after adding groups

**A virtual chassis.** A good `tacctl device config pull` of a device that is a virtual chassis also records its members: `show virtual-chassis status` lists them (member id, status, priority and role `master`, `backup` or `linecard`), and the `FPC` rows of `show chassis hardware` and the `fpcN:` blocks of `show version`, which the pull reads already, give each member's model, serial number and release. `device show` and `device config show` print them under the data block, and the [members report](reports.md) has a row for each:

```
Chassis members:
-----------------------------------------------------------------
  ID  ROLE    MODEL       SERIAL    RELEASE      STATUS  PRIORITY
  ---------------------------------------------------------------
  0   master  EX4300-48T  SN000001  21.4R3-S5.4  Prsnt   129
  1   backup  EX4300-48T  SN000002  21.4R3-S5.4  Prsnt   129
```

A device that is no virtual chassis (the command is refused, or lists one member) has no members and is one row of the members report. The two routing engines of a chassis are not members, and a cluster is not read. Nothing here is a setting: the commands are read-only and a refusal changes nothing in the pull (see **Chassis members** in [Device configuration](configuration.md)).
