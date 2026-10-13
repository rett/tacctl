# Fake WTI units

Directories for `fakedev.New(dir)` (`internal/devssh/fakedev`, menu mode,
`menu.go` has the manifest format) and for `tacctl _fake-device <dir>` in a
test build: a menu-driven WTI unit that serves the captured screens of the
parent directory (and `../pages/`) as a stateful menu. Read-only: nothing
typed at a prompt page is taken (the three SNMP text prompt pages, `# kind:
prompt` in their captures, log an `entry` for a CR alone as well, and ESC at
one repaints the SNMP access menu); `fakedev.Server.Commands()` lists the keys
and lines typed and `Events()` what happened (`save /N` when a top-level menu
was left with ESC, `close /N > 28` when the client went away on a page).

| Directory | Version | Login level | IP tables | Other sessions |
|---|---|---|---|---|
| `lab-superuser` | 8.10 | administrator | filled (25 entries) | 1 |
| `lab-engineer` | 8.10 | superuser | empty | 0 |
| `lab-user` | 8.10 | user | empty | 0 |
| `lab-viewonly` | 8.10 | viewonly | empty | 0 |
| `lab-old` | 7.4 | administrator | empty | 0 |

The login is the fake's default (`gotest` and its password) unless the
directory has a `login` file or the starter gives one. `lab-old` has its own
prompt (`LAB-WTI> `).

What a login above its level meets: the captured help screens are the only
evidence of the level, and no capture shows the unit's refusal text, so the
fake prints `Invalid command` for a command the level's `/H` does not list
(and for a line that is no command); its `refused <command>` event records
it. The first capture of the real wording replaces that line in
`internal/devssh/fakedev/menusession.go` (`refusedMsg`).
