# Juniper Junos

[Documentation](../README.md) › [Network devices](README.md)

The generated config includes template user creation, TACACS+ server setup, and verification commands. All groups and their Juniper classes are included.

**Key points:**
- Template users must exist before TACACS+ logins work. If a login fails silently after a successful TACACS+ authentication, the template user is missing
- The classes carry permission bits only. A group whose class is `EN-CLASS` gets the engineer bits (`view view-configuration network clear trace reset configure rollback interface interface-control routing routing-control firewall firewall-control system system-control snmp`) and its template user
- Step 3 lists, per class, what the server sends at login: the group's `deny-commands` and `deny-configuration` values with their sizes against the 241 and 236 byte limits, or `none`. Nothing in it is pasted; the sets are changed on the tacctl server with `tacctl group junos` (superuser) and apply at the next login; `tacctl group show <group>` prints the patterns themselves to every tier. `show cli authorization` after a login shows the values the device received
- The `tacctl group commands` rules are Cisco's and are not translated into class `allow-commands`/`deny-commands`; Step 3 lists the `delete system login class <class> allow-commands` lines that remove what an earlier walkthrough put there
- The server's port is the configured listener's (`tacctl config listen`; 49 by default): a listener that moved adds `set system tacplus-server <address> port <n>`, a default one adds nothing, and in management filter mode `strict` the replies term accepts that source port (see [The server's port](walkthroughs.md#the-servers-port)).
- Use `config juniper` to regenerate after adding groups
