# Junos fixtures

Two `show configuration | display set` captures from Junos 25.x on an
EX-series switch, taken over an ssh exec channel (the same text comes back
over NETCONF `<command>` and `<get-configuration format="set"/>`).

- `lab-superuser/display-set.txt`: the superuser view, 564 lines.
- `lab-engineer/display-set.txt`: the same device as an engineer-class login,
  563 lines. Three secret values (the root and a login user's password hash,
  and that user's ssh public key) arrive masked as `/* SECRET-DATA */`, and
  the TACACS+ server `secret` statement is not shown at all.

Values are sanitised (host name, domain, addresses mapped into
`198.18.0.0/15` and the documentation ranges, VLAN names (`VLAN<id>`, with
the captured ids), users, hashes, keys, communities, serial number,
free-text descriptions); the statement shapes and
order are as captured.
