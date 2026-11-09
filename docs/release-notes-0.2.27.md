# tacctl 0.2.27

0.2.27 adds PDF device reports, makes the support-bundle scrubber keep what a device
printed about itself and replace what is the owner's, and puts the files tacctl writes at a
path you name inside your home. `tacctl device reports generate --format pdf` writes a
letter-landscape table with `weasyprint`, and `tacctl upgrade` offers the two packages it
needs, once. `device support-bundle --out` is now a name, not a path, and every other option
that names a file to write follows one rule: a path inside your home, with no `~` or
variable expanded. The scrubber, which took model names for serial numbers and moved the
columns of a table, was corrected against captures of real devices. A read-only user's
reports no longer hold what `device show` hides from them, and `tacctl rollback 0.2.26` is a
target. The numbered list in `CHANGELOG.md` (0.2.27) is everything that differs from 0.2.26.

## Where tacctl writes the files you name

- `tacctl device support-bundle <device> --out <name>` takes a name: a letter or digit, then
  letters, digits, `.`, `_` or `-`, at most 64 characters. A `/`, `..`, a leading dot, `~`
  or `$` is refused with exit status 2 and a sentence that says the rule, before anything is
  asked or written. Before, `--out ~/x` made a directory literally named `~` in the current
  directory when the `~` reached tacctl unexpanded (a quoted argument, a script).
- The bundle is `support-bundles/<name>` and its private map is `support-bundles/<name>.map`,
  in the home of the person who ran `sudo` (else of the user running tacctl), taken from the
  account database and never from `$HOME`. The `support-bundles` folder is made with mode 0700
  when it is missing, and one that is a link leading out of the home is refused. Without
  `--out` the name is `<device>-<UTC YYYYMMDD-HHMMSS>` (it was `support-bundle-<UTC time>` in
  the current directory). A name that exists, or whose `.map` exists, is refused as before,
  and the success lines print the full paths.
- The other options that name a file or directory to write follow one rule: `device config
  plan --out` and `--out-dir`, `device reports export --out`, `config render --dry-run
  --out`, and `config linux script` and `remove-script --output` (`-o`). tacctl never expands
  `~` or variables, and the path must be strictly inside the home of the person who ran
  `sudo` (else of the user running tacctl), after `..` and the symbolic links of its existing
  part. An empty path, a NUL, a first component that starts with `~`, a `$` or a backtick,
  and the home itself are refused with one sentence (`tacctl does not expand ~ or variables;
  name a path inside your home, relative to the current directory`), before a device is
  read, a report is opened or a script is made. `plan` and `reports export` end with exit
  status 2, the others with 1. Relative paths are taken from the current directory, and an
  account whose home is `/` is refused.
- This is a change for scripts: `--output /dev/stdout` and a directory outside the home such
  as `/var/tmp` are refused now. `config linux script --output` naming an existing directory
  is refused too (it used to write `tmp.XXXXXXXXXX` inside it and hand the directory to the
  caller). Without `--output` the two scripts are `tacctl-linux-<scope>.sh` and
  `tacctl-linux-remove.sh` in the current directory, as before.
- The files keep the protections they had. `plan`, `reports export` and `support-bundle`
  write as the caller, new files only, never through a link. `config render --dry-run`
  writes as root, now through a handle on the directory, so a link planted after the
  emptiness check cannot send a root write elsewhere. The two scripts are made as root and
  handed to the person who ran `sudo`, and no longer follow a link swapped in at the name.
  The `out=` field of the `device config plan` audit line and the `file=` field of the
  `secret-export` record of a script hold the resolved absolute path now.

## PDF reports

- `tacctl device reports generate --format pdf` writes a report as a PDF beside `text`, `csv`
  and `json`, with the extension `.pdf`. The page is letter landscape: a title block (the
  type, when the report was made, the filters, the date of the oldest datum), then the table
  in 8 pt DejaVu Sans with the header row repeated on each page, light stripes, no row split
  across two pages and a page counter. A word of more than 24 characters gets a zero-width
  space after every 24 characters so that it can wrap, so copying such a value out of the PDF
  can carry invisible characters.
- It needs `weasyprint` and the DejaVu fonts, which are optional:
  `sudo apt-get install -y weasyprint fonts-dejavu-core`. Without them the command refuses
  first, before it reads a device or writes a file, with that line and exit status 1.
- The document is made from the report itself, as one HTML document with every cell escaped
  and no link, image, script, style sheet or font reference. The tool is found in `/usr/bin`,
  `/usr/local/bin` or `/opt/weasyprint/bin` and nowhere else (not in the caller's `PATH`), and
  only when it, what a link of it leads to and every directory above are owned by root and not
  writable by the group or by others. Under `sudo` it runs as the person who ran `sudo`, with
  an environment of `PATH`, `LANG`, `HOME`, `XDG_CACHE_HOME` and `PYTHONNOUSERSITE=1` only, for
  120 seconds and 64 MiB of output at the most; a tool that runs over is stopped with every
  process it started. A tool that fails or makes no PDF gives an error with the first five
  lines of its own, and nothing is written.
- A PDF is binary. `--stdout` and `export` to standard output refuse at a terminal (`PDF is
  binary: use --out FILE or redirect`) and write the bytes when redirected; `show --content`
  prints `binary PDF, <n> bytes: use export`. A file counts as a PDF only by its name ending
  in `.pdf` and, for a superuser's `export <user>/<report>`, only if it also starts with
  `%PDF-`; the metadata file saying `pdf` is not enough, since the owner writes that too.
  A PDF that cannot be written to standard output (a full disk, a closed pipe) fails with
  exit status 1. With `--stdout`, in every format, the notices `No device matches: the report
  has no rows.` and `No device to read: ...` go to standard error, so that standard output
  holds the report only.
- `tacctl upgrade` offers the tools, last, once the upgrade is done. On a Debian or Ubuntu
  system where `weasyprint` or `fonts-dejavu-core` is missing, it asks at a terminal `tacctl
  can write device reports as PDF. Install weasyprint and fonts-dejavu-core now? [y/N]`; `y`
  or `yes` installs the missing ones (a failure is a warning, never a failed upgrade). A no
  is remembered in `/var/lib/tacctl/pdf-tools-offered`; delete the file to be asked again.
  Without a terminal nothing is asked and the upgrade prints the `apt-get` line. `install`
  does not offer them, `uninstall` removes the marker and a rollback leaves it.

The pages are `docs/devices/reports.md` and `docs/install/upgrading.md` (PDF reports).

## The support-bundle scrubber

Captures of real devices showed what the scrubber got wrong: it took model names for serial
numbers (`PID: CSR1000V` lost its model), missed serial numbers that have no serial shape,
rewrote `sysObjectID.0: 1.3.6.1.4.1.2636.1.1.1.2.165` as pieces of example addresses,
replaced the vendors' own host names, moved the columns of a table, garbled a sysDescr, and
left the echo of a long IOS command at the top of its file. It now does this:

- **Models stay.** The values after `PID:` and `VID:`, the quoted `DESCR:` strings of `show
  inventory`, the `Model:` line of Junos, the model of the `cisco <model> (...) processor`
  and `Cisco IOS Software, <model> Software` lines of IOS, and every model name the files of
  the bundle state are kept, in all the files. Only the model is kept, never the rest of its
  line: the serial after a model is replaced.
- **Serial numbers go by their field.** The `SN:` value, `Hw Serial#:`, `Processor board ID`,
  `System serial number`, the generic `Serial number:` field and the Junos `Serial ID` are
  replaced whatever their length, case or digits, and the same real serial is the same example
  in every file. The value runs to the next blank, comma or quote and ends at its last letter
  or digit, so `(serial: abc12345)` keeps its parenthesis. The serial cell of every row of
  `show chassis hardware` (transceiver, PIC and power supply rows too) and of Junos `show
  virtual-chassis` is replaced, cut at the column its header gives; any word with a letter or
  digit in that column is a serial except the status words (`Prsnt`, `Absent`, `Online`,
  `Master`, `Spare`, `Empty` and the like). A table ends at a blank line, a line of one word
  and a colon, or a prompt line that begins with `{`, not at a row with nothing in the serial
  column (`Midplane`, a member without a serial).
- **Tab-separated rows.** A row with as many cells as the header has its serial at the
  header's column; a row with fewer cells has it by shape (the one cell that is a word with a
  digit, or the one after the part number). A cell with a hyphen (`650-114384`, `NON-JNPR`,
  `EX4300-48T`) is a part number or a model, never a serial. An empty or `BUILTIN` cell and
  the Description column stay.
- **Object identifiers are not addresses.** A dotted run that begins `1.3.6.1.` is kept, and
  the digits around any other address (`10.20.30.40.179`) do not make it one. Release
  strings such as `12.4(15)SW4` and `16.07.01` were never read as addresses and still are not.
- **Column width.** When a replacement is shorter or longer than the text it replaces and
  blanks follow, blanks are added or taken away so the columns after it stay where the device
  printed them. The garbled sysDescr was the learn step: an empty `sysLocation.0:`,
  `sysContact.0:` or `snmp-server contact` line took the next line as its value. The patterns
  for the hostname, domain, location and contact lines stay on their line now.
- **Vendor names stay, vendor mail does not.** The bare domain of cisco.com, juniper.net,
  hpe.com, hp.com, gnu.org, fsf.org, openssl.org, ietf.org or kernel.org, with one of the
  labels `www`, `tools`, `ftp`, `cdn`, `software` or `support` in front of it, and the
  `example.*` names are kept, so `Technical Support: http://www.cisco.com/techsupport` is as
  the device printed it. A mail address (a vendor's too), a customer's name under those
  domains and any name under a learned domain are replaced. The parent domain of every host
  name that is replaced is learned as the owner's, so once `acme-corp.hpe.com` is replaced,
  `hpe.com` and `www.hpe.com` are replaced in every file of the bundle, and the files are
  looked at until nothing new is learned.
- **The echo is dropped.** A Cisco session drops the echo of a command longer than the
  terminal is wide (the device scrolls it over lines that start with `$`), so the file of
  `show running-config | include ^(hostname|...)` starts with the device's answer.
- **Real captures are test cases.** The shapes the captures showed (a CSR1000V inventory, an
  EX4300 hardware table with its tab-separated rows, an object identifier in a sysDescr) are
  tests of the scrubber now, so each of the faults above can fail a test.

The pages are `docs/devices/support-bundle.md` and the manual page.

## Other fixes

- A read-only user's `device reports` no longer hold what `device show` hides from that tier:
  below the operator tier the `model`, `serial` and `release` of the `inventory` and
  `software` reports are empty, the `members` count of `inventory` is `-` and the `members`
  report has no rows. The operator tier and up see what they saw, and a report a read-only
  user made with 0.2.26 keeps what it holds.
- A superuser's `device reports prune --user <name>` or `--all-users` writes its audit line
  (`device reports access verb=prune ...`) for each other user whose directory the run reads,
  before it reads that directory and also when nothing is old enough. With `--all-users`
  every line comes before the first directory is read, so under `audit.strict` a line that
  cannot be written refuses the whole run. The line no longer carries a count.
- The reader of `show switch` accepts a row whose H/W version column is blank (state
  `Provisioned`, no version); it used to drop the member silently.
- Two notes say what they do: the warning of `tacctl upgrade` when `linux-uids` already has
  a line for the new name of a renamed user no longer claims an account is removed, and the
  note that ends `tacctl rollback 0.2.25` and `0.2.24` names what the older restore refuses
  (the settings, a user's own limit, or both).
- The reports page no longer says every user has an account on the server. A user whose
  name has upper case letters or is longer than 32 characters has none, and `generate` then
  refuses and stores nothing; `--stdout` still prints, and `tacctl user rename` gives a
  name that can be an account.

## File transfer through the console

The tacctl console is the login shell of a tacctl user on this server, and it accepts one
tacctl line or `help`. `scp` and `sftp` are refused by it, as are `rsync` and every other
program. So the `scp` line that `device reports show` prints to fetch a report cannot be
used by a user whose login shell is the console, and this release does not change that.
`device reports export <report>` prints a report on standard output or writes it with
`--out` inside the home, but moving the file off the server is not something the console
does. File transfer through the console is planned for a later release.

## Rollback

`tacctl rollback 0.2.26` is new. This release changed no stored file 0.2.26 reads strictly,
so the rollback converts nothing: it removes no key and no field, takes no snapshot and
needs no `--yes`. The limits of the stored reports, the chassis members of the pull records,
every report in the users' homes, the per-tier sudoers drop-in, the break-glass firewall and
the other settings 0.2.26 knows all stay. It still refuses while a device's apply is not
settled, and it ends with `tacctl upgrade --branch 0.2.26`. `rollback 0.2.25` and older
behave as before. What this release changed outside the stored files is 0.2.26's to undo or
keep: after the rollback, a row of `show switch` with a blank version column is not read
again, and the reports of a user below the operator tier hold the model, serial number and
release again.

## Upgrading

`tacctl upgrade` converts nothing in this release. The new PDF offer comes last, once, and
installs only if you answer yes at a terminal. Existing reports, bundles and settings are
read as they were. A scripted use of `device support-bundle --out`, `device config plan
--out`, `reports export --out`, `config render --dry-run --out` or `config linux script
--output` that named a path outside the home, or a `~` for tacctl to expand, fails until it
names a path inside the home (a bundle name for `support-bundle`).

A PDF report is a file of the user's home like the others and the packages stay installed
after a rollback, but 0.2.26 has no PDF format: it lists such a report, its `show --content`
cleans the bytes as text, and `device reports rename` of a PDF gives the file the new name
without its `.pdf`. Fetch the PDF with the `scp` line of `show` first, and remove it or
rename it before the rollback.

## Known limits

- The scrubber is conservative about vendor names. Only the domains and labels listed above
  stay, and a vendor's name that the list does not hold is replaced, not kept.
- A part number without a hyphen in a tab-separated row that leaves cells out is not told
  from a serial, and is replaced as one.
- The scrubber knows the shapes it replaces, not everything a device can print: read the
  files before you share them.
- The `.map` file of a support bundle holds the real values next to their examples. It is
  private (mode 0600) and must never be shared; keep it out of the bundle and out of every
  repository.
- A PDF needs `weasyprint` and `fonts-dejavu-core` from apt; on a system without `apt-get`
  install the equivalents by hand, and the tool must be root's and in one of the three
  directories above.
- The `scp` line of `device reports show` does not work through the tacctl console, and
  there is no file transfer through the console yet.
