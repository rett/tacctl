# WTI console server: interface reference (for the WTI release)

Status: discovery, 2026-10-10. Written from read-only navigation of a lab unit
(DSM-series console server, command menu version 8.10), from tests that
changed and restored a few settings of services that were off or unused, and
from WTI's published 8.10 artifacts (the RESTful v2 OpenAPI file, the
firmware's MIB, the release notes and the DSM/CPM user guide). The sanitised
screens are in `tests/fixtures/devconf/wti/` (one screen per file; `pages/`
holds the navigation tree). `0.2.4-spike.md` has the dated test log.

The goal of this document is to let the WTI work (after 0.2.4; the unit is
not read or written by 0.2.4, D71) implement a driver without further
exploration. What is not known is listed in section 10.

## 1. Session

| Item | Observed |
|---|---|
| Transport | ssh, TCP 22 (configurable). Host keys: ED25519 and RSA (2048). A pinned key from the registry is checked as for any device. |
| Authentication | password (also keyboard-interactive) against the unit's local users or TACACS+ / RADIUS (`Service Name` `wti`). Login failures do not lock out while "Invalid Access Lockout" is Off. |
| Terminal | a pty is needed. The unit paints full screens and has a pager. |
| After login | a legal banner (site text) and `Do you wish to continue? (<CR> to continue, /X to exit)`; then the port list and the prompt `DSM>` (the prompt text is configurable: "Command Prompt" under `/F` > 10). |
| Command entry | commands start with `/` (`/H` help, `/N` network, `/F` system, `/P` ports, `/X` exit); a bare number at `DSM>` is not a command. |
| Pager | long screens end with `Enter: SPACE for page, ENTER for line` (help) or `<CR> for more ports, <ESC> to quit` (status lists). |
| Concurrency | "Multiple Logins" is a setting (On on the lab unit). `/SN` lists the network sessions (`N1`..`N32`) with user names: a driver must check it for another administrator before it changes anything. |
| End of session | `/X`. Closing the connection ends the session; nothing is rolled back (section 4). |

## 2. Access levels

The level is the TACACS+ `wti` service `priv-lvl` (0, 5, 10, 15) or the
RADIUS `WTI-Super` value; tacctl's groups map as in `group show`:

| Level | priv-lvl | tacctl group | Command menu |
|---|---|---|---|
| ViewOnly | 0 | readonly | display commands (`/S /SD /SN /SA /AS /W /H /L /J`), `/X`, `/TELNET` |
| User | 5 | operator | + `/C /D /R /E` (connect, disconnect, read and erase buffer) |
| SuperUser | 10 | engineer | + `/V /TEST` and the configuration commands `/F /P /N /PNA /AC /I` (reboot is listed) |
| Administrator | 15 | superuser | + `/DF /UL /UFW /CP /VPN /TEL /WOF` (parameter file, unlock, firmware upgrade, port copy, VPN, telemetry, wakeup-on-failure) |

The documentation says SuperUser may view but not change the configuration.
The user reports (2026-10-10) that on the lab unit both the superuser group
(Administrator) and the engineer group (SuperUser) can change settings: the
documented "view only" for SuperUser does not hold on this firmware, so the
engineer tier's WTI level is a full configuration login, with the same
lock-out reach as Administrator for the pages in section 6. Every page
described here was opened at Administrator level.

"Default User Access" (TACACS item 8, RADIUS item 11) is a page of its own:
what a server-authenticated user who has no local account gets (access
level, port access, service access: serial, telnet/ssh, web, RESTful API).
The lab unit gives View Only for TACACS and User for RADIUS by default.

## 3. Page grammar

All pages are a title line (upper case, with the scope `[Shared]` or
`[eth0] IPv4`), the body and a footer. Five kinds:

| Kind | Body | Footer | Input |
|---|---|---|---|
| Menu | numbered items with their current values (`4.  Secret Word:  (defined)`) | `Enter: #<CR> to change,` + `<ESC> to return to previous menu ...` (top-level menus: `<ESC> to exit and save configuration ...`) | the item number and CR opens the item's page |
| Pick | `1. Off  2. On` (1-based numbered choices; some entries are `---`, unavailable) | `Enter: #<CR> to change,` | the choice number and CR |
| Number | a sentence with the range (`Enter 1 - 99 ...`, `Enter number of seconds (1-60).`), the current value on the last line | `Enter: <ESC> to exit.` | the number and CR |
| Text / address | the accepted characters and the length limit, the current value under a rule line | `Enter: <SPACE><CR> to clear, <text><CR> to change, <ESC> to return to previous menu` | the text and CR; a single space and CR clears |
| List | numbered slots (`1.` ... `8.`; IP tables 12 slots; static routes 8; hosts file 8) | `Enter: #<CR> to select menu / to change` | a slot number opens its prompt |

Failures print `ERROR: Invalid entry.` (or a specific line such as `ERROR:
SNMP V3 is not configured.`) above the current value; the page stays and
nothing changes. Not-allowed characters are listed on the page
(`Non-printables, ", /, \, <SPACE> *, +, :, <, >, &, | are NOT allowed.`; the
secret prompt allows `* + :` and forbids `# < > |`).

The unit does **no semantic validation**: `999.999.999.999` was accepted as a
host name. Ranges of number prompts are enforced.

An address item first asks the protocol (`1. IPv4  2. IPv6`), then the value.

## 4. Apply and save semantics (tested)

- A value is **live when its CR is accepted**. The page shows it at once and a
  new login sees it; a session killed (SIGKILL of the client) on the page,
  before any ESC, left the value in effect.
- The configuration is written to flash when a top-level menu (`/N`, `/F`,
  `/P`) is left with ESC: the unit prints `Saving configuration to flash -
  Please wait...`. An interrupted session is assumed not to have saved
  (not testable without a reboot); a driver always re-reads after a
  disconnect.
- There is no commit-confirm, no candidate, no rollback. A revert is another
  edit.
- Several items changed on one page apply as they are entered and are all
  visible to a new login after the page is left.

## 5. Menu tree

`pages/` holds one sanitised screen for every row below.

### `/N` network parameters

| Item | Page | Notes |
|---|---|---|
| 1 | IP address options | 1 IP address (address prompt), 2 public IP address (display text only) |
| 2 | subnet mask | address prompt |
| 3 | gateway options | 1 gateway address, 2 default gateway On/Off (shown on the menu with `*`) |
| 4 | DHCP | 1 client (enable, host name, lease, DNS, default gateway), 2 server (enable, gateway, DNS, domain, leases, pool) |
| 5 | IP tables | 12 slots; a bulk `<iptables> ... </iptables>` upload "replaces and overwrites all current entries" |
| 6 | static route | 8 slots |
| 7 | DNS services | 1 DNS servers (4 + ping test), 2 DDNS, 3 hosts file (8) |
| 8 | negotiation | auto, 10/100/1000 half/full |
| 11-16 | general: admin mode, logoff character, sequence disconnect, inactivity timeout, command echo, accept break | network-port defaults for sessions |
| 21 | telnet access | enable, port (23), max per source (1-25) |
| 22 | SSH access | 1 enable, 2 port, 3 security level (Normal/High), 4 view port, 5 view port bidirection, 6 pseudo-terminal, 7 disable password authentication |
| 23 | web access | HTTP enable/port; HTTPS enable/port; SSL certificates; harden level; TLS mode; HSTS; TRACE; OCSP; web terminal; inactivity timeout; oAuth; listen addresses. HTTPS is Off and the certificates are undefined on the lab unit. |
| 24 | syslog | 1 client (8 addresses + ping test), 2 server (enable, port, transport, TLS, block IPs) |
| 25 | SNMP access | 1 enable, 2 version (V1/V2 only, V3, all), 3 read-only, 4 system name, 5 contact, 6 location, 7 read-only community, 8 read/write community, 9 V3 users (4 slots; "SNMP V3 is not configured" until a user exists) |
| 26 | SNMP trap | managers 1-4 (address), 5 community, 6 trap version, 7 V3 engine id, 8 ping test |
| 27 | LDAP | 12+ items (hosts, port, TLS, bind type, DNs, filters, attributes) |
| 28 | TACACS+ | see section 6 |
| 29 | RADIUS | see section 6 |
| 30 | ping access | Limited / On / Off, 4 allowed networks |
| 31 | multiple logins | Off / On |
| 32 | email messaging | SMTP server, port, TLS, domain, authentication, user, password, from/to addresses |
| 33 | outbound access | access Off/On, secure level |
| 34 | raw socket access | Off / On |

### `/F` system parameters

1 user directory (view, add, modify, delete); 2 unit identification (site ID,
location name, hostname, domain, asset tag); 3 real time clock (date, time,
time zone, NTP enable, two NTP servers, timeout, test); 4 invalid access
lockout (serial, SSH, telnet, web protection); 5 temperature (format,
calibration); 6 log configuration (audit, alarm, change, temperature logs,
syslog format and protocol); 7 callback security; 8 front panel buttons;
9 modem phone number; 10 scripting options (hold write, reverse DNS, port 1
mode override, USB client, hunt, timestamps, user defined prompt, command
prompt, keep alive, status after login, NetReach); 11 SSL providers.

### `/P` port parameters (one port at a time, `<` and `>` move)

1 baud (300 to 921.6K), 2 bits/parity, 3 stop bits, 4 handshake, 11 admin
mode, 12 logoff character, 13 sequence disconnect, 14 inactivity timeout,
15 command echo, 16 accept break, **21 port name** (24 characters, first
character alphabetic), 22 port mode (any-to-any, passive, buffer, modem,
modemPPP; unavailable ones show `---`), 23 DTR output, 24 modem parameters
(unavailable outside modem mode), 25 buffer parameters (unavailable outside
buffer mode), 26 heartbeat, **31 direct connect** (Off, On - No Password,
On - Password), 32 IP alias (address), 33 break on raw disconnect.

With Direct Connect `On - Password` the menu shows the three TCP ports for the
port: telnet 2101, SSH 2201, raw 3101 for port 1 (and `+ n - 1` for port n on
a unit with 8 ports; the documentation lists 2201 to 2208 for DSM-8 and
CPM-800, 2201 to 2216 for CPM-1600, to 2224 and 2240 for the DSM-24 and
DSM-40). An SSH direct connection needs "On - Password" on that port.

### Others

`/AC` alarm configuration (12 alarms: temperature, lost communication, ping
no answer, lockout, power cycle, buffer threshold, no dialtone, wakeup on
failure, buffer filtering, user login/logout, VPN status change); `/L` logs
(audit, alarm, syslog server, temperature, change; each has display and
download); `/SN` network status; `/S` plug status; `/J` site ID; `/H` help.
Not entered (actions or out of scope): ping and NTP tests, `/I` reboot,
`/UFW`, `/DF`, `/VPN`, `/TEL`, `/WOF`, `/TEST`, `/C`, `/V`.

## 6. Settings tacctl would manage

Risk classes: **safe** (no effect on the way in), **guarded** (can lock out
the AAA path; needs the verification below), **forbidden** remotely (can
lock out the management path).

| Setting | Menu | REST v2 | Type and range | Risk |
|---|---|---|---|---|
| TACACS+ enable | `/N` 28.1 | `aaaserver` `service tacacs` `enable` | pick Off/On | guarded |
| TACACS+ primary / secondary host | 28.2 / 28.3 (protocol, then address or name up to 64) | `ietf-ipv4.primary[].ip` | address or name | guarded |
| TACACS+ secret | 28.4 (text up to 64; the prompt prints the current value in clear) | `...[].secret` | text, `# < > \|`, space not allowed | guarded; cannot be read back except by that prompt |
| TACACS+ fallback timer | 28.5 | `fallbacktime` | 1-600 s | safe |
| TACACS+ fallback local | 28.6 | `fallbacklocal` | Off / On (all failures) / On (transport failure) | guarded: the way back in when the server is wrong |
| TACACS+ port | 28.7 | `authport` | number | guarded |
| TACACS+ default user access | 28.8 (a page) | | level, ports, services | guarded |
| TACACS+ account / session modules | 28.9, 28.10 | | Disabled / Enabled | safe |
| TACACS+ service name | 28.11 | | text up to 64 (`wti`) | guarded: a wrong name returns users to default access |
| RADIUS (same shape) | `/N` 29 | `aaaserver` `service radius` | secrets per server, timer 1-60, retries 1-99, ports, one-time auth, message authenticator | guarded |
| SNMP enable, version, read-only | 25.1-25.3 | `snmpaccess` | picks | safe |
| SNMP system name, contact, location | 25.4-25.6 | `snmpaccess` | text | safe |
| SNMP communities | 25.7, 25.8 | `rocommunity`, `rwcommunity` | text; shown in clear | safe, secret |
| SNMP V3 users | 25.9 | `users[]` | name, auth/priv, passwords, protocols (MD5/SHA1, DES/AES128), 4 slots | safe, secret |
| SNMP trap managers, community, version | 26 | `snmptrap` | 4 addresses, text, V1/V2/V3 | safe |
| Syslog client / server | 24 | `syslogclient`, `syslogserver` | addresses, port, transport | safe |
| Serial port name, parameters | `/P` 21, 1-4, 11-16, 22, 23 | `serialports` | text 24, picks | safe |
| Per-port direct connect (SSH 22nn) | `/P` 31 | **not in the API** | Off / No Password / Password | safe in itself; widens access |
| Local users | `/F` 1 | `users` | name, password, level, port/plug/group access, serial/ssh/web/api/outbound access, token | guarded (never remove the last local administrator) |
| IP tables | `/N` 5 | `iptables` (48 entries) | iptables command text per slot | **forbidden** remotely |
| SSH enable, port, security, password auth | `/N` 22 | `ssh` | picks, number | **forbidden** remotely |
| Network interface, gateway, DHCP, DNS | `/N` 1-4, 7 | `interface`, `dnsservices` | addresses | **forbidden** remotely |
| Web, certificates | `/N` 23 | `web` | enable, ports, TLS, keys | outside the first release |
| Invalid access lockout | `/F` 4 | `lockout` | per service: enable, hit count, duration | guarded: wrong password attempts can lock the source |

## 7. Other interfaces

- **SNMP** (WTI-CONSOLE-MIB, enterprise 2634): ports (name, user, status),
  plugs and plug groups (state, action), a local user table (name, password,
  level, access flags, submit), environment, alarms, traps. No AAA, SNMP, SSH,
  IP-table or network settings. Useful for inventory and status only.
- **RESTful API v2** (8.10, "v2 (Jan26)"): HTTPS or HTTP, basic auth (local
  user with API access) or a token; every PUT applies at once; replies carry
  `status.code` and `status.text`; `GET /api/v2/config/settings` returns the
  configuration as XML. Needs web access enabled (Off on the lab unit, with no
  certificate): not used by the first release. The API has no direct connect
  or IP alias, so the menus stay necessary for per-port SSH.
- **Parameter file** (`/DF`, Administrator): download and restore of the whole
  configuration; not exercised.

## 8. Driver rules

1. Tables, not conversation: each page is declared (title, items, kind,
   range, accepted characters, risk). An unknown title or an unexpected
   screen aborts: ESC out, `/X`, no further input.
2. Validate every value (type, range, characters, and meaning: the unit does
   not) before it is typed; type it only at its own prompt.
3. Before a change: login, `/SN` (refuse if another administrator is
   connected), read the page, compare; send nothing when it already holds the
   wanted value; keep the old values (secrets: from tacctl's store) as the
   revert record.
4. Change one page per session; every `ERROR:` line is a failed field.
5. Leave through the whole ESC chain and wait for `Saving configuration to
   flash`; then log in again as a separate session and re-read the page; for
   AAA also log in as a real TACACS+ user. On a mismatch revert from the
   first session.
6. After an unexpected disconnect: reconnect, re-read, then continue or
   revert from what is found.
7. Never log screens (the secret prompt and the SNMP page print secrets in
   clear); redact before any capture is kept.
8. Version gate: tables are verified per command menu version (8.10); another
   version is read-only until its page titles match.
9. Forbidden settings are not changed by tacctl remotely (section 6).

## 9. Quirks seen

- The gateway line on the network menu ends with `*` when the default gateway
  is on.
- `/W` (who) printed the network menu on the lab unit; `/SN` lists the users.
- Pick lists show unavailable entries as `---` and keep their numbers.
- The clock line of the network page uses the unit's time zone and has no
  year offset issues in the captures (a driver must not parse it).
- Top-level footers say `exit and save configuration`; sub-page footers say
  `return to previous menu`; the `/P` footer also lists `<` and `>`.
- Entering a number at `DSM>` (not a command) printed nothing.
- Text prompts truncate display of long values on the menu (system name,
  contact and location show `...`); the full value is visible at the item's
  prompt only, so a revert record must be taken from the prompt.

## 10. Not known

- Whether the engineer tier's SuperUser login is limited in any page (it can change settings: section 2; which pages it cannot reach, if any, was not mapped).
- Whether an interrupted session reaches flash (needs a reboot).
- The add-user, modify-user and delete-user prompts of the user directory,
  and the IP table and static route slot prompts (entered only as lists).
- The V3 user prompts (needs V3 enabled).
- Behaviour of `/DF` and the parameter file, and whether a restore is a
  usable rollback.
- The REST API behaviour: whether a TACACS+ user can authenticate to it
  (the default-access page lists "RESTful API" as a service), what a partial
  PUT does, and the certificate procedure the web service needs.
- Other firmware versions (7.x, earlier 8.x) and the CPM models: the page
  titles and numbering above are 8.10 on an 8-port unit.
