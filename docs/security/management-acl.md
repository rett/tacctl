# Management ACL

[Documentation](../README.md) › [Security](README.md)

Restrict which source subnets can reach the device management plane. Build the permit list once on the tacctl server:
```
tacctl config mgmt-acl add 10.1.0.0/16
tacctl config mgmt-acl add 192.168.5.0/24
tacctl config mgmt-acl list
```
`tacctl config cisco` then emits a populated `VTY-ACL` applied to `line vty 0 15` via `access-class VTY-ACL in`. The server's own address (`--source`, else the detected one) is the first permit of the Cisco ACL and of the Junos filter, once, so the access class cannot cut off tacctl's own ssh. `tacctl config juniper` emits a commented `set firewall family inet filter MGMT-ACL` block (in the default `ssh-only` mode, with a trailing `default-accept` term to keep BGP/OSPF/IS-IS traffic to the RE working; see [Strict mode for Junos](#strict-mode-for-junos)) — review and uncomment per device. `tacctl config wti` renders the unit's **IP Tables** list from the same permits. The list lives under `mgmt_acl.permits` in `/etc/tacctl/tacctl.yaml` and survives `tacctl upgrade`; a scope's own list (`tacctl scope mgmt-acl <scope> add <cidr>`) replaces it for that scope.

**Entries with services.** An entry is a CIDR, or a CIDR with the services it permits: `<cidr>[:<service>[,<service>...]]`, where a service is `tcp/<ports>`, `udp/<ports>` or `icmp` and `<ports>` is `N`, `N-M` or `*` (every port of the protocol). `tacctl config mgmt-acl add 172.16.100.0/23:tcp/22,udp/161,udp/162,10.0.0.0/8` adds two entries: a token that starts with `tcp/`, `udp/` or `icmp` belongs to the entry before it (a service before any CIDR is refused), and the CIDR is split from its services at the first `:` that is followed by `tcp/`, `udp/`, `icmp` or `*` (an IPv6 CIDR holds colons of its own). **A plain `<cidr>` permits every protocol and port from that source**: on a WTI unit that is a rule `iptables -A INPUT -s <cidr> -j ACCEPT`; write `<cidr>:tcp/22` for ssh alone. `<cidr>:*` and `<cidr>:tcp/*,udp/*,icmp` are spellings of the plain entry. Services are lower-cased, de-duplicated and stored in the order tcp, udp, icmp with ports ascending, `tcp/*` takes the other tcp services of the entry, an entry holds at most 8 services, ports are 1 to 65535, a range has its low port first, and `icmp` takes no port. The same CIDR may be listed twice with different services (two entries); an exact duplicate is a no-op. `list` prints the services after the CIDR (`172.16.100.0/23   tcp/22, udp/161, udp/162`). `remove <entry>` removes that exact entry, and `remove <cidr>` with no services removes **every** entry of that CIDR and says how many. What each consumer does with an entry:

| Consumer | A plain entry | An entry with services |
|---|---|---|
| WTI IP Tables list | `-s <cidr>` for every protocol and port; no separate ICMP line | one rule for each service (`-p tcp -s <cidr> --dport 22`, `--dport 161:162` for a range, no `--dport` for `*`, `-i eth0 -s <cidr> -p icmp` for `icmp`); ICMP from the network is still added unless the entry lists `icmp` |
| Cisco VTY-ACL | listed by its source | listed by its source when the services include `tcp/22` (alone, in a range or as `tcp/*`); any other entry is not listed, with a comment above the list that names it |
| Junos filter (`permit-mgmt` term) | listed by its source | the same rule; any other entry is not listed, with a comment that names it |

A standard access list and the filter's `permit-mgmt` term match a source only, so a source whose entry permits only `udp/161` is not a permit for the management plane there; the managed `mgmt-acl` section, `device config diff` and `plan` read the same filtered list, so they agree with the walkthrough. `tacctl rollback 0.2.3` is refused while any entry carries services (see [Rolling back](../install/upgrading.md#rolling-back)).

**Plain entries on WTI units.** A plain entry is every protocol and port on a WTI unit; earlier releases rendered ssh and ICMP for it. Two notices say where that applies before anything is pasted. The first `tacctl upgrade` onto this release prints, once, `Management ACL: plain entries now permit every protocol and port on WTI units.` and, for each scope that has a registered WTI unit and a plain IPv4 entry in the list that applies to it (its own, else the global one), the entries and up to five unit names, with the command that keeps ssh only (`tacctl scope mgmt-acl <scope> remove <cidr>`, then `add <cidr>:tcp/22`); a marker in the state directory (`wti-plain-acl-noted`) records it, a later upgrade and `config validate` say nothing of it, and a plain entry added afterwards is not announced. `tacctl device config plan` of a unit whose paste holds plain entries puts a `# WARNING:` line naming them at the top of the report, under the box and the basis of the pull, and `--backout` prints one when the list it puts back holds them.

**WTI (IP Tables, Step 5 of `tacctl config wti`, both protocols).** The walkthrough keeps its caution (the list must accept loopback and replies before a final DROP) and follows it with the unit's whole list for the device's scope, numbered in the unit's order. It reads what tacctl already holds and stores nothing: the scope's management permits (else the global list), the address the unit must permit for tacctl's own queries (the route to the devices, or `--source`; never `--server`) and the scope's SNMP clients (`tacctl scope snmp <scope> clients`). The rules, in order:

1. `iptables -A INPUT -i lo -j ACCEPT`, then `iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` (older builds take `-m state --state ESTABLISHED,RELATED`); the second covers the replies of the unit's own TACACS+/RADIUS, DNS and NTP queries.
2. For the tacctl server's /32: `-p tcp -s <cidr> --dport 22 -j ACCEPT`, the unit's ssh. Then each permitted range with what its entry lists: `-p <tcp|udp> -s <cidr> --dport <ports> -j ACCEPT` for each service (`--dport 161:162` for a range, no `--dport` for `tcp/*` or `udp/*`), `-i eth0 -s <cidr> -p icmp -j ACCEPT` for `icmp`, and `-s <cidr> -j ACCEPT` (every protocol and port, the unit's telnet and web pages included) for a plain entry. A rule is not repeated, and an entry that is the server's own /32 adds its services after the server's lines. Telnet (23), http (80) and https (443) are opened only by an entry that lists them or is plain; the step's notes name the plain entries and say to use `<cidr>:tcp/22` to restrict one.
3. For the SNMP clients (the server's /32 first, then the scope's ranges in order): `-p udp -s <cidr> --dport 161 -j ACCEPT`. These lines are the SNMP client restriction of the SNMP step, unless the unit has an SNMP access menu of its own.
4. ICMP, so that monitoring can ping the unit once the DROP is in force: one `-i eth0 -s <cidr> -p icmp -j ACCEPT` per network of the server, the permits and the SNMP clients (de-duplicated, IPv4 only); a network whose entry is plain, or lists `icmp`, has no line of its own here. The unit's own Ping Access item (`/N` 30) is separate.

The unit takes its whole list in **one paste**: the same rules are given again as one `<iptables>` ... `</iptables>` block (one command per line, no comments, no DROP) to paste at the IP Tables prompt (`/N`, 5). The paste replaces every entry the unit holds (read its list first), is applied at once (the network menu then shows `5. IP Tables: On`), and is written to flash when any session leaves a top-level menu. The unit holds 48 entries, 12 to a page: a list over 48 (or whose last-step list is over 48) carries a warning in Step 5, in Step 11 and at the end of the output, and is not cut.

The final `iptables -A INPUT -j DROP` is **never part of that list and never applied by the walkthrough**: it is the last step (Step 11), which tells you to keep the serial session open, to paste the line yourself as the last one (or the whole list again as one block: the rules, the DROP, `iptables -A OUTPUT -j ACCEPT` and the three `-P INPUT|OUTPUT|FORWARD DROP` policies last, the order that keeps the pasting session open), and to test a login from a permitted address before saving. The unit has no commit-confirm and no rollback: the way back is clearing the slots (`<SPACE><CR>` at a slot's prompt) or pasting Step 5's block again. Whether clearing a policy slot restores ACCEPT at once, and what the unit does with a malformed line in a block, is not known. **Lock-out guards:** a scope with no management permit list (and no global one, or only IPv6 entries, or no entry that permits ssh: plain or with `tcp/22`) gets the loopback, established and server rules and a *commented* DROP with the reason, because the DROP would lock out every administrator but tacctl; an unknown server address (pass `--source <address>`) also leaves the DROP commented and ends the output with `Unfilled SNMP values: tacctl server address (...)`. The list is IPv4 only (`iptables`, not `ip6tables`); an IPv6 entry of the lists is skipped with a note in the output.

Rename the emitted ACL / filter names to match your site conventions:
```
tacctl config mgmt-acl cisco-name MGMT-ACCESS
tacctl config mgmt-acl juniper-name MGMT-SSH-FILTER
```
Overrides live under `mgmt_acl.names.{cisco,juniper}` in `/etc/tacctl/tacctl.yaml` and also survive `tacctl upgrade`.

## Strict mode for Junos

The Junos filter restricts ssh, NETCONF and SNMP only: its last term,
`default-accept`, accepts everything else, so a device that should drop
traffic from sources outside the permit list needs the other mode. A scope
chooses it:

```
tacctl scope mgmt-acl <scope> mode              # show: ssh-only (default) or strict
tacctl scope mgmt-acl <scope> mode strict
tacctl scope mgmt-acl <scope> mode ssh-only
```

The setting is per scope, the superuser's to set (an engineer may read it for
a scope of their own), and only Junos devices read it: the Cisco VTY-ACL and
the WTI IP Tables list are the same in both modes. Only `strict` is stored
(`scope_mgmt_acl.mode.<scope>` in `tacctl.yaml`); setting `ssh-only` removes
the key.

**What `strict` renders.** The filter accepts every protocol from the permit
list and has no `default-accept` term, so the implicit discard at the end of
a Junos filter drops the rest. The terms, in order:

- `permit-mgmt`: the source of every plain entry, the tacctl server's own
  address (`--source`, else the detected one) first and once; then accept.
- One term for each distinct service of the entries that have services,
  named after the service (`permit-tcp-22`, `permit-udp-161-162`,
  `permit-tcp-any`, `permit-icmp`): the sources of the entries that name it,
  the protocol and the destination port; then accept. A service with no port
  (`tcp/*`, `udp/*`) matches the protocol alone, and `icmp` is `from protocol
  icmp` for every ICMP type. A port Junos prints by name is written with it
  (`ssh`, `snmp`, `ntp`, `bgp`), any other as a number, a range as `low-high`.
- `permit-auth-replies`, only when the walkthrough has a second server
  address: the device authenticates against another address than the one
  tacctl reaches it from (`--server`; `--source` alone, the device still being
  told the address detected for the server; a RADIUS listener bound to another
  address) and that address is not a source of `permit-mgmt` already. With
  none of them, or with both given the same, there is one address, one source
  /32 in `permit-mgmt` and no such term. The term holds that address, protocol
  `tcp` and source port `tacacs` for TACACS+, or protocol `udp` and the source
  ports `radius` and `radacct` (the listener's, 1812 and 1813 by default) for
  RADIUS; then accept. The device starts those sessions, so only the replies
  of the server are accepted from the address, never ssh or another protocol,
  and it is not counted as a source for `--from` (below). Add the address to
  the permit list to accept more from it.
- `permit-snmp` and `deny-snmp`, when the scope's SNMP clients are set, as in
  `ssh-only`.

An entry with services keeps only those services; a plain entry accepts
everything from its source. An entry for a network that already heads
`permit-mgmt` (the server's own /32, or a plain entry of the same network)
adds nothing, because that source accepts everything. A source that has
services needs `tcp/22` among them for ssh and `tcp/830` for NETCONF. IPv6
entries are skipped (the filter is family inet), and a list with no IPv4 entry
that permits ssh (a plain entry, or one with `tcp/22`) renders no filter in
either mode: the server's address alone would let only the server in. The
walkthrough then says what each entry permits and why there is no filter.

The walkthrough keeps the `set interfaces lo0 ... filter input` line
commented and never emits it. Once the filter is applied to lo0, these stop
reaching the routing engine:

- routing protocols carried over IP from neighbours that are not in the list
  (BGP, OSPF, LDP, VRRP, BFD);
- the replies of servers that are not in the list: TACACS+ and RADIUS (the
  server the walkthrough names is always in it), NTP, DNS;
- NTP, syslog and DHCP from hosts that are not in the list;
- SNMP from sources outside the list (the SNMP clients still poll);
- every other protocol (ping, traceroute) from sources outside the list.

IS-IS is not carried over IP, so a `family inet` filter on `lo0` does not see
it: this filter neither stops nor permits it.

Add every neighbour and server the device needs to the permit list the scope
renders from first (`tacctl scope mgmt-acl <scope> list` says which: the first
entry of the scope's own list replaces the global list for that scope, so add
the global entries to it too), keep a console session open when you apply the
filter, and commit with `commit confirmed`.

**Planning and applying a change of mode.** `tacctl device config plan` and
`device config apply` treat the filter as owned whole, so a move between the
modes is planned and applied like any other change of the filter, in both
directions, and a pulled filter is compared with the rendering of the scope's
mode. The report of a move to `strict` lists the traffic that stops (above),
and the report of a move back to `ssh-only` says that the `default-accept`
term returns. When the device applies the filter to `lo0`, the filter that
would replace it must still permit the address you are logged in from
(`--from <address>` for a plan; an apply knows its own): in `strict` that is a
source of `permit-mgmt`, or of a service term that holds `tcp/22` (the address
of `permit-auth-replies` is not one); otherwise the section is refused. See
[Planning](../devices/planning.md).
