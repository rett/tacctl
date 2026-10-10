# WTI fixtures

Screens of a WTI console server (command menu version 8.10) captured over
ssh on 2026-10-10 with read-only navigation only (display commands, numbered
pages opened and left with ESC; nothing was entered or changed). Names,
addresses, communities, the legal banner and the port names are replaced; the
layout, the field order and the wording are as the unit printed them.

- `01-login-banner.txt`, `02-port-list.txt`: what a login prints and the
  prompt it ends at (`DSM>`).
- `03-help-*.txt`: the command menu per access level (ViewOnly, User,
  SuperUser, Administrator), from test accounts of the readonly, operator,
  engineer and superuser groups. The levels the server returns are the
  `wti` service's `priv-lvl` 0, 5, 10 and 15.
- `04-network-status.txt` to `16-site-id.txt`: the network status, the system
  and network parameter menus and the pages of TACACS, RADIUS, SNMP access,
  SNMP trap, IP tables, syslog and ssh access, and the log and user-directory
  menus, `17-web-access.txt` (the web access page: HTTP and HTTPS enable and
port, certificates, hardening, TLS mode, listen addresses) and
`18-port-parameters.txt` (a serial port's parameters, with Direct Connect and
its SSH port).
- `19-prompt-text-field.txt` to `28-error-enum.txt`: the value prompts and
  their failures: a text field, a numeric field with its range, a two-choice
  and a three-choice pick, the secret word prompt (the unit prints the
  current secret in clear; the fixture replaces it with a note), the
  `ERROR: Invalid entry.` screen for a forbidden character, a non-number and
  an out-of-range pick, the accepted-value screen (no semantic check) and a
  page after a change.

- `pages/`: the navigation tree, one sanitised screen per file, captured
  read-only at Administrator level: `system-*` (`/F` and its items),
  `network-*` (`/N`, items such as `network-28-8` for `/N` > 28 > 8),
  `port-*` (`/P` for port 1), `alarm-top` (`/AC`). They are the screens
  `docs/plans/wti-interface.md` describes.

The headers follow the run sheet's (`# vendor`, `# os`, `# transport`,
`# command`, `# source`, `# captured`); `# level` names the access level of the
account. These are inputs for the WTI work after 0.2.4, which does not read
the unit (D71).
