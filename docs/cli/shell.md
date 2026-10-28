# Shell and completion

[Documentation](../README.md) › [CLI reference](README.md)

## Shell Completion

`install` and `upgrade` place the bash script in `/etc/bash_completion.d/tacctl`. zsh and fish are print-only: write the script where the shell looks for it, as the user who will use it.

```bash
# zsh: any directory on fpath, then compinit
mkdir -p ~/.zfunc
tacctl completion zsh > ~/.zfunc/_tacctl
# in ~/.zshrc, before compinit:  fpath=(~/.zfunc $fpath); autoload -Uz compinit && compinit

# fish
tacctl completion fish > ~/.config/fish/completions/tacctl.fish
```

The scripts ask `tacctl __complete` for the words, so they match the installed binary; a second Tab lists each sub-command, each verb word after a name (`scope mgmt-acl lab <Tab><Tab>`) and each flag. In bash the list is the words alone, in columns, as in the shell and the console; zsh and fish show a description beside each word in their menus (at most 72 characters; a longer one ends in `...`) and, for a flag, the value it takes. Regenerate the scripts after an upgrade. `completion` is a word of the top level in the scripts and in the shell, and completes the three shells. Live names (users, groups, scopes, ...; a device or host with its vendor and scope) need root or the NOPASSWD sudoers rule; without it only fixed words are completed.

## Interactive Shell — `tacctl shell`

```
tacctl shell

    Prompt 'tacctl> ': type commands without 'tacctl' (user list, scope show lab)

tacctl shell --no-history

    Keep this session's history in memory only

tacctl shell --idle 30

    Leave after 30 minutes at the prompt without input (0, the default: never)

tacctl shell --space-completion off

    A typed space is only a space (default on)

tacctl shell --password-cache

    Keep your network password in this shell's memory (see Password cache)

tacctl shell -c 'user list'

    Run one line and exit with its status

tacctl shell < commands.txt

    Run the lines in order; stop at the first non-zero status and exit with it
```

The shell runs as you and holds no privilege: each line runs as `sudo [-n] tacctl <words>` with the terminal attached, so sudo's rules and log, and the tier gate, apply to every line as they do from bash; prompts and password input work as usual. Tier users of the readonly and operator tiers (members of `tac-users`, who have no local password) get `sudo -n`, and a line their tier's sudoers rules do not cover is reported as not permitted; superusers (`tac-superuser`) get plain `sudo`, which asks for their network password on the terminal when a line needs it (once; sudo's cache applies), so their write verbs work from the shell. `hash` and `completion` lines run without sudo; `host` lines carry `SSH_AUTH_SOCK` as the re-exec does.

A line is split into words at blanks; single and double quotes and backslash quote as in `sh`, and nothing else is special — no variables, globbing, pipes, redirections, `;`, `$(...)`, backticks or `!`. Lines are at most 4096 bytes. A line pasted from the help or these pages may start with `tacctl`, `sudo tacctl` or `/usr/local/bin/tacctl`: that first word (and the `sudo` before it) is dropped, once, and the rest runs, completes and is explained as it would without it (`tacctl dev<Tab>` completes `device`, `tacctl ?` lists the top level); a `tacctl` anywhere else in the line is an argument. A line that is only `tacctl` prints what `tacctl` with no arguments prints, the top-level usage, and ends with status 1. The history keeps the line as typed. The shell's own words are `help` (the top-level usage), `help <command>` (that family's usage), `history`, `console forget` (see [Password cache](#password-cache)) and `exit`/`quit` (or Ctrl-D). After a non-zero status the shell prints `[exit N]`.

**Spaces at the prompt** are handled as on a Junos device (`--space-completion on`, the default): a space is refused where it would be a second one (at the start of the line, right after a space, right before one), and where a word ends it completes the word when the word is a command, a sub-command, a fixed choice or a flag name and only one such word starts with what is typed (`de` and a space give `device `). Several matches are listed once, as `?` lists them, without a question and without paging, and nothing is inserted; more than the console's `list_max` print nothing. A word that is complete already (`user` while `user-x` exists), a name of your own (a user, a host, a file), free text and a typo get the space as typed, and so does a space inside a word and a word of dashes only (`-`, the standard input of `device import - --check`, and `--`, the end of the options). Inside quotes, after a backslash, in a Ctrl-R search, and with Tab and `?`, nothing changes. A paste is not affected: it is inserted as it is, as without the setting (a paste is one line; see Keys). That assumes the terminal sends a paste bracketed; one that does not sends its spaces as typed ones, and a paste then completes words: turn the setting off there. `-c` and batch input are not affected. `--space-completion off` turns off the refusal of repeated spaces and the completion, so every typed space is a space.

**What the lists show.** In the shell and the login console, Tab, `?`, a typed space and the top-level `help` list only the commands and sub-commands your tier can run (the rows of the [tier table](../security/tiers.md), read from the same place as the sudoers drop-in, so the two cannot differ): a readonly user does not see `store` or `install`, an operator sees `log` and `config validate` but not `host`, a superuser and a caller outside `tac-users` see everything. The verbs of `device config` are listed by the tier of each (an operator sees `list`, an engineer all but `forget` and `shapes`). A line ends with `Shown: the commands the <tier> tier can run`. The usage stays complete: `help group` describes every verb and ends with the tier each one needs (`readonly   list, show` and so on, with a note for the verbs whose sub-verbs the code splits: `scope secret`, `scope staging`, `scope snmp`, `scope block`, `device block`, `host show`, `device import`; the man page prints the same table and notes under TIERS), and `?` after a verb typed by hand names the tier it needs (`Needs the <tier> tier.`; after a command family you cannot run at all, `Needs the <tier> tier. help <family> describes it.`). The descriptions of the rows that are listed are the usage's text and can still name a verb of the family that is not listed. This is display only: the tier gate and sudo remain the check, and a command typed by hand is refused as before. The shell learns your tier from the root side (`sudo -n tacctl _console-policy`, as the console does) when it starts, in the background and within 3 seconds, so typing never waits for it; until the answer is in, or when it cannot be learned, only the read-only commands are listed, and the next Tab, `?` or space asks again once 30 seconds have passed. A disabled tacctl user (the root side answers that the account has no tier) is listed no command, as the gate refuses them all; `help`, `exit` and `quit` remain. The plain `tacctl` usage, the man page and this documentation are not filtered. On a colour terminal the listing's labels are bold; the rule that decides colour is in [environment](exit-status.md).

Keys: Tab completes commands, flags and live names (asked of `sudo -n tacctl _completion-names`, kept 5 s); a second Tab lists the matching words alone, in columns that fit the terminal. `?` inserts nothing and shows help for the cursor's position: where words can come, `Possible completions:` with each one's argument column (at most 40 characters, a longer one is cut and ends in `...`; the whole form is in the usage of the command; a name with no column, such as a long device name, is cut the same way) and description (a long one goes on under its column, with the blanks that align a device's vendor, address and scope kept; a command or sub-command has the same description as in the completion scripts above; devices and hosts with vendor, address and scope; a fixed word such as `priv-lvl` after `group edit <name>` with the description of the usage line that has it); after a command that takes arguments, the usage lines of the forms the words typed so far fit, its options and what comes next (`Next: <username> <group>`; where the forms part, the choice: `Next: <name> priv-lvl|juniper-class|wti-level|tier ...`; `Next: <Enter> to run`). `-h` or `--help` after the words of a command, in the shell and from bash, prints that same help, from the same code (a command with sub-commands lists them; another one prints its usage, options and `Next:`; see [conventions](conventions.md)). Inside quotes, or after a backslash (`\?`), `?` is typed as a character. A list of more than 40 entries asks first (`Show all 45 devices? [y/N]`): `y` shows it, any other key (or Ctrl-C) prints how to narrow it and gives the line back. Help from `?` taller than the terminal is shown a screenful at a time (`-- more (Space: page, Enter: line, q: quit) --`; `q` or Ctrl-C stops). Up/Down walk the history, Ctrl-R searches it (Ctrl-R again: older; Enter runs; Ctrl-G restores the line). Esc-b/Esc-f (Alt-Left/Right) move by word; Home/End, Ctrl-A/E/K/U/W/T/L as usual. A paste is one line (newlines become blanks, at most 4096 bytes) and runs only on Enter. Ctrl-C discards the line, or ends the running command; Ctrl-Z and Ctrl-\ do nothing (no job control, inherited by the commands).

History lives in `~/.local/state/tacctl/history` (0600, newest 1000 lines). Lines are stored redacted: everything after `--secret`, `--hash`, `--password`, after `set` in `secret … set`, after `import` with a value, and after the word of a `passwd` line becomes `…(redacted)` (`scope secret lab set x` → `scope secret lab set …(redacted)`); a recalled redacted line is refused. Lines ended with Ctrl-C are not stored; batch input is never stored. In a batch (`tacctl shell < file`) the commands get no stdin, so questions cannot be answered from the file — use `-y` where a command has it. Over ssh, ask for a terminal to get the interactive shell: `ssh -t <host> tacctl shell`; without `-t` ssh allocates none, the shell reads commands from standard input, and it says so on stderr.

### Password cache

`device config pull` (and `diff --pull`, `plan --pull`) and `tacctl ssh` log in to devices with your own network password. In a shell or console session that password can be asked once and kept **in memory, for that session only**, so a pull of sixty devices, a diff and a few `ssh` lines ask once:

```
tacctl console password-cache tiers [<csv>|none]

    operator, engineer, superuser; default none (off for every tier)

tacctl console password-cache idle [<min>]

    forgotten after this long without a use (1-120, default 15)

tacctl console password-cache max [<hours>]

    forgotten this long after it was cached (1-24, default 8)

console forget

    a word of the shell and the console: forget it now
```

It is on in the login console for the tiers listed, and in a plain `tacctl shell` when you give `--password-cache` and the same policy opens the cache to your tier (a caller outside `tac-users` asks for it themselves). It is for the interactive session only: `-c` and batch lines keep no process to hold it, and the plain CLI from bash asks per run.

How it works: the shell process itself holds the password, in a page it locked in memory (`mlock`; when memory cannot be locked, a debugger is attached, or no private directory is available for the socket, there is no cache and one line says `password cache unavailable: <why>`: `cannot lock memory`, `this process is being traced` or `no private directory for its socket`), in a process marked not dumpable, zeroed when it is forgotten. It is never written to a file, a log, an argument or the environment. The shell listens on a socket in a private directory (`$XDG_RUNTIME_DIR/tacctl`, else `/run/user/<uid>/tacctl`, else `~/.local/state/tacctl/run`, mode 0700) and is shut between lines. For a line that runs `device config pull`, `device config diff --pull`, `device config plan --pull`, `ssh`, `device ssh`, `block ... adopt`, `device config apply`, `device onboard` (for your own password after its review), `device collect` or `device enroll`, and for no other line (a `diff` without `--pull` logs in to nothing, and a line with `--login <local-user>` logs in as a device's local account, whose password never comes from or goes into the cache, so their lines leave it shut), it mints a token and puts `TACCTL_ASKPASS=<socket>:<token>` in the environment of that line's `sudo` process, never on sudo's command line; the tiers drop-ins keep that one variable for those command lines only. The token exists only for that line: the agent answers only while the line runs, only to your own user or root (`SO_PEERCRED`), only with that token, and gives the password once; after that single `get` the token is good for nothing but `forget`, and when the line ends it is dead (a value read from an earlier line is refused). A second ask on the same line is a refusal and forgets the password. What remains is the usual one for a secret handed through an environment: a process of your own user that reads the pull's or ssh's environment during the line, and gets to the socket before the single `get` of that line, is answered as the line would be. The pull asks the cache, and when nothing is cached it prompts on the terminal itself; after the first device **accepts** a password it prompted for it is stored (a password that came from the cache is never stored again, so the maximum lifetime cannot be extended by use). A device that refuses the password makes the cache forget it at once and the run stops starting new devices. `tacctl ssh` uses a cached password only for a device with pinned host keys: ssh is then started as you directly, without sudo (your uid, gid and groups; an explicit environment of `HOME`, `USER`, `LOGNAME`, `PATH`, the terminal and locale, and the display), so the token is never a `sudo` variable or argument and reaches no log. It asks the shell's agent for the password through `SSH_ASKPASS` (this binary, which answers a password prompt and nothing else), `SSH_ASKPASS_REQUIRE=force`, one prompt (`NumberOfPasswordPrompts=1`), no configuration file and `StrictHostKeyChecking=yes` against the pinned keys; an ssh that ends with status 255 forgets the password. An account that is not in the local account database keeps the prompt.

It is forgotten when the session ends, after the idle time, after the maximum lifetime, when you change your password (`passwd`, `user passwd`), when a device refuses it, when the clock goes backwards, and by `console forget`; the shell says `password cached for this session (console password-cache)` when it keeps one and `password forgotten (<why>)` when it lets go. The cache protects the password against other users and against its landing in files, logs, arguments or the environment; root can read any process, and hibernation can write the locked page to disk.
