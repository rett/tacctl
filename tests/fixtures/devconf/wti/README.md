# WTI fixtures

Screens of a WTI console server (command menu version 8.10) captured over
ssh on 2026-10-10 with read-only navigation only (display commands, numbered
pages opened and left with ESC; nothing was entered or changed), and, for
`29-` to `31-`, on 2026-10-12 around one approved write. Names,
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

- `29-iptables-upload.txt` to `31-network-iptables-on.txt`: the bulk upload at
  the IP tables prompt, captured 2026-10-12 on the same unit with the
  maintainer's approval (the list was uploaded and read back): the
  `<iptables>` block pasted (22 `-A` rules and the three `-P` policies, last)
  and the "Configuring iptables - Please wait..." screen, the page after it
  (`30-iptables-uploaded-page.txt`: entries 1-12; `-2`: 13-24; `-3`: 25 and
  the empty slots 26-36), and the network menu showing `5. IP Tables: On` once
  the list is not empty. Addresses are replaced (documentation ranges and
  10.0.0.0/8); the commands are otherwise as stored, one per entry, the `-P`
  lines as entries.

- `32-user-directory-view.txt`, `33-user-directory-details.txt`: the local
  user directory (`/F` 1 > 1): the names, and one user's details page (the
  password is only `(defined)`, the access level, port and service access, the
  API token).

- `pages/`: the navigation tree, one sanitised screen per file, captured
  read-only at Administrator level: `system-*` (`/F` and its items),
  `network-*` (`/N`, items such as `network-28-8` for `/N` > 28 > 8),
  `port-*` (`/P` for port 1), `alarm-top` (`/AC`). They are the screens
  `docs/plans/wti-interface.md` describes.

The headers follow the run sheet's (`# vendor`, `# os`, `# transport`, `#
command`, `# source`, `# captured`); `# level` names the access level of the
account. These are inputs for the WTI work after 0.2.4, which does not read
the unit (D71).
