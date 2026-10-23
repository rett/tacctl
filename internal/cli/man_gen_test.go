package cli

// The generated blocks of man/tacctl.1 (docs/plans/0.2.3-plan.md D57). Each
// is a region between
//
//	.\" BEGIN GENERATED: <name>
//	.\" END GENERATED: <name>
//
// whose lines are written from the code and compared byte for byte by
// TestManGeneratedBlocksAreCurrent:
//
//	tiers              the TIERS table (tier.Rules) and the notes of the verbs the code splits (tierNotes)
//	audit-classes      the action and mixed commands of AUDIT LOG with their weight (auditTable)
//	config-keys        the tacctl.yaml keys (conf.Schema), with type and default
//	console-keys       the console.yaml settings (console.Defaults), with type and default
//	command <words>    for each command: its tier ('Requires:') and its flags, described as the usage describes them
//
// 'make man' rewrites them (go test ./internal/cli -run TestManGenerated
// -update-man): the 'command' blocks it inserts itself at the end of the
// command's first entry; the others sit where the page has their markers.
// The prose around the blocks is hand-written.

import (
	"flag"
	"fmt"
	"github.com/rett/tacctl/internal/blocks"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
	"github.com/spf13/cobra"
)

var updateMan = flag.Bool("update-man", false, "rewrite the generated blocks of man/tacctl.1 (make man)")

// roff is text safe in a roff line: backslashes and hyphens escaped, and a
// leading '.' or apostrophe kept from being read as a macro.
func roff(s string) string {
	s = strings.ReplaceAll(s, `\`, `\e`)
	s = strings.ReplaceAll(s, "-", `\-`)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}

// roffWrap is words joined by sep, broken into lines of about 70 columns
// (a line ends after the separator's last visible character).
func roffWrap(items []string, sep string) []string {
	var lines []string
	cur := ""
	for i, it := range items {
		piece := roff(it)
		if i < len(items)-1 {
			piece += strings.TrimRight(sep, " ")
		}
		if cur != "" && len(cur)+1+len(piece) > 70 {
			lines = append(lines, cur)
			cur = ""
		}
		if cur != "" {
			cur += " "
		}
		cur += piece
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// manBlock is a generated region: its name and the lines between the markers.
type manBlock struct {
	name  string
	lines []string
}

// manRowName is how TIERS names a row of tier.Rules.
func manRowName(r tier.Rule) string {
	switch {
	case r.Cmd == "":
		return "(no arguments)"
	case r.Sub != "":
		return r.Cmd + " " + r.Sub
	}
	return r.Cmd
}

// manTiersBlock is the TIERS table: for each tier, the lowest tier that may
// run each row, then the notes of the verbs the code splits further.
func manTiersBlock() manBlock {
	var l []string
	for _, tr := range tier.Managed {
		var rows []string
		for _, r := range tier.Rules {
			if r.Tier == tr {
				rows = append(rows, manRowName(r))
			}
		}
		l = append(l, ".TP", `.B `+string(tr))
		if len(rows) == 0 {
			l = append(l, "Every verb not listed above, and every verb of the tiers below.")
			continue
		}
		l = append(l, roffWrap(rows, ", ")...)
	}
	l = append(l, ".PP", "The gate sees two words, so a verb that the code splits further is listed at its",
		"two\\-word level and then limited by the code:")
	for _, k := range slices.Sorted(maps.Keys(tierNotes)) {
		note := strings.TrimPrefix(tierNotes[k], k+": ")
		l = append(l, ".TP", ".B "+roff(k), roff(upperFirst(note)))
	}
	return manBlock{name: "tiers", lines: l}
}

// manAuditBlock is the AUDIT LOG list of the commands that write the central
// lines: the action commands, then the mixed ones, each at its weight.
func manAuditBlock() manBlock {
	var l []string
	for _, class := range []auditClass{classAction, classMixed} {
		for _, notice := range []bool{false, true} {
			var rows []string
			for _, k := range slices.Sorted(maps.Keys(auditTable)) {
				e := auditTable[k]
				if e.Class != class {
					continue
				}
				switch {
				case !notice && e.Notice && e.NoticeWhen == nil:
					// always at auth.notice: in the other list
				case !notice:
					rows = append(rows, k)
				case e.Notice && e.NoticeNote != "":
					rows = append(rows, k+" ("+e.NoticeNote+")")
				case e.Notice:
					rows = append(rows, k)
				}
			}
			title := string(class)
			if notice {
				title += ", auth.notice"
			}
			l = append(l, ".TP", `.B "`+roff(title)+`"`)
			l = append(l, roffWrap(rows, ", ")...)
		}
	}
	return manBlock{name: "audit-classes", lines: l}
}

// manCommandBlocks are the 'command <words>' blocks: the tier line and the
// flags of each visible leaf command.
func manCommandBlocks(t *testing.T) []manBlock {
	t.Helper()
	inv, root, _ := shellTestInv(t)
	var out []manBlock
	pathsList, cmds := visibleLeaves(root)
	for i, p := range pathsList {
		words := strings.Join(p, " ")
		sub := ""
		if len(p) > 1 {
			sub = p[1]
		}
		l := []string{".RS", ".PP"}
		req := `Requires: \fB` + string(lowestTier(p[0], sub)) + `\fR.`
		if note, ok := tierNotes[p[0]+" "+sub]; ok {
			req += " " + roff(upperFirst(strings.TrimPrefix(note, p[0]+" "+sub+": ")))
		}
		// The gate sees 'device config'; each of its verbs holds its own tier.
		if need, ok := deviceConfigNeeds[strings.TrimPrefix(words, "device config ")]; ok && len(p) == 3 && p[0] == "device" && p[1] == "config" {
			req = `Requires: \fB` + string(need) + `\fR.`
			if need == tier.Engineer {
				req += " An engineer gets the devices of their own scopes only."
			}
		}
		l = append(l, req)
		if spec, ok := specFor(p); ok && len(spec.Flags) > 0 {
			var cands []string
			for _, f := range spec.Flags {
				cands = append(cands, f.Names...)
			}
			helps := inv.flagHelps(cmds[i], p, spec, cands)
			l = append(l, ".PP", "Options:")
			for _, f := range spec.Flags {
				value, desc := helps[f.Names[0]][0], helps[f.Names[0]][1]
				// The usage describes a flag on one line and may continue it
				// on the lines below; the page keeps the whole sentence.
				desc = inv.manFlagDesc(cmds[i], p, f, desc)
				if o, ok := manFlagOverrides[words+" "+f.Names[0]]; ok {
					desc = o
				}
				if desc == "" {
					t.Errorf("tacctl %s: flag %s has no description in the usage (the generated option list of man/tacctl.1 needs one)", words, f.Names[0])
				}
				var names []string
				for _, n := range f.Names {
					names = append(names, `\fB`+roff(n)+`\fR`)
				}
				tag := strings.Join(names, ", ")
				switch {
				case f.Value && value != "" && f.Optional:
					// '--name[=<value>]': the value may be left out
					tag += `[=\fI` + roff(value) + `\fR]`
				case f.Value && value != "":
					tag += ` \fI` + roff(value) + `\fR`
				}
				desc = capitalizeDesc(desc)
				if desc != "" && !strings.HasSuffix(desc, ".") {
					desc += "."
				}
				if f.Repeat && !strings.Contains(desc, "repeatable") {
					desc += " May be given more than once."
				}
				l = append(l, ".TP", tag, roff(desc))
			}
		}
		l = append(l, ".RE")
		out = append(out, manBlock{name: "command " + words, lines: l})
	}
	return out
}

// manFlagOverrides are the descriptions of flags that a command shares with
// others in one usage block, where the block's line is about another verb
// ("<command words> <flag>": the text for that command alone).
var manFlagOverrides = map[string]string{
	"host sync --all":                    "(sync) Every enrolled host.",
	"host check --all":                   "(check) Every enrolled host.",
	"host check --json":                  "(check) Print a JSON array (one object per host) and nothing else on standard output.",
	"host move --all":                    "(move) Every host that another scope answers; asks before deleting accounts.",
	"host enroll --local":                "Enroll this machine itself instead of a remote host (its tacctl users get the login console).",
	"host enroll --port":                 "The ssh port of the host.",
	"host enroll --identity":             "The ssh key file to log in with.",
	"host target --port":                 "The ssh port; tested first, and the host's ssh keys must match the pin.",
	"host target --identity":             "The ssh key file; tested first, and the host's ssh keys must match the pin.",
	"config render --dry-run":            "Render into the directory named by --out; nothing live is written.",
	"config render --out":                "The new, empty directory a --dry-run render writes to, at the live paths.",
	"config cisco --legacy":              "(cisco) IOS 12.x syntax.",
	"config listen --listener":           "Act on another listener than 'default' (its own tacquito@<name> unit; reset removes it).",
	"config listen --backend":            "Act on another backend (see 'tacctl backend list'); radius: --listener auth|acct <udp|udp6> <addr>.",
	"config snmp v3-user --priv":         "The privacy protocol: AES-128 (the only one).",
	"scope snmp --priv":                  "The privacy protocol: AES-128 (the only one).",
	"config snmp v3-user --auth":         "The authentication protocol: sha (HMAC-SHA-96) or sha256 (HMAC-SHA-256-192) (default sha).",
	"scope snmp --auth":                  "The authentication protocol: sha (HMAC-SHA-96) or sha256 (HMAC-SHA-256-192) (default: the default's, else sha).",
	"store show --json":                  "Print JSON instead of YAML.",
	"scope prefixes --all":               "(remove) Remove every prefix of the scope, which removes the scope.",
	"device onboard --login":             "The device's local account to log in as (any, a break-glass one included; root through its CLI wrapper): its password is asked once on the terminal and never kept or cached.",
	"device onboard --name":              "The registry name (default: the name the device reports; a generic or taken one is asked for).",
	"device onboard --host-key":          "Trust only this key, read on the device's console (no question; needed without a terminal); pin it alone.",
	"device onboard --legacy-ssh":        "SHA-1 key exchange, CBC ciphers and ssh-rsa (also chosen by itself when the handshake needs them); registered so.",
	"device onboard --section":           "Only these sections of the first-time plan: aaa, roles, mgmt-acl, snmp, system; aaa among them (the proof is a TACACS+ login).",
	"device onboard --json":              "One object at the end (the progress goes to standard error).",
	"device collect --discovered":        "The addresses 'device discover' lists (the seen cache: unregistered, authenticated); no address is named with it.",
	"device collect --login":             "The device's local account to log in as (any, a break-glass one included; root through its CLI wrapper) instead of you: its password is asked once on the terminal, never kept or cached, and goes to each address once; one account for the run.",
	"device collect --host-key":          "Trust only this key, read on the device's console (no question; needed without a terminal; one address); pin it alone.",
	"device collect --register":          "After the table, register each collected device through 'device add' with the keys shown pinned (one question) and keep the read as its first pull record.",
	"device collect --yes":               "Answer yes to the registration question of --register (needed without a terminal).",
	"device collect --json":              "One object at the end (the progress goes to standard error).",
	"device sync --all":                  "Every device of the registry.",
	"device sync --scope":                "Only the devices of that scope.",
	"device sync --vendor":               "Only that vendor's devices (only Junos records are read).",
	"device sync --apply":                "Write the fields, in one registry write, after one question.",
	"device sync --overwrite":            "Also replace a field that is set, showing the old value.",
	"device sync --yes":                  "Answer yes to the question of --apply (needed without a terminal).",
	"device sync --json":                 "One object: each device's fields, actions and facts.",
	"device show --all":                  "The acknowledged notices too.",
	"device notices --all":               "The acknowledged notices too.",
	"device remove --all":                "Remove every device (an engineer: those of their own scopes).",
	"device check --all":                 "Check every device.",
	"device discover --all":              "Also list the addresses that were only refused.",
	"device config forget --all":         "Every record, and the stored sections of every device (one of a device that is no longer registered too).",
	"device config pull --server":        "The address the devices are told to authenticate against, for devices behind a translating firewall (not stored).",
	"device config pull --source":        "The address this server reaches the devices from (not stored).",
	"device config diff --server":        "The address the devices are told to authenticate against (with --pull; not stored).",
	"device config diff --source":        "The address this server reaches the devices from (with --pull; not stored).",
	"device config plan --server":        "The address the devices are told to authenticate against, for devices behind a translating firewall (not stored).",
	"device config plan --source":        "The address this server reaches the devices from (not stored).",
	"device config plan --exit-code":     "Exit 2 when a device needs a change (and none could not be planned).",
	"device config plan --pull":          "Read the devices first (takes the pull options); the plan is made from that pull.",
	"device config plan --section":       "Only these sections: aaa, roles, mgmt-acl, snmp, system (the report still names the others).",
	"device config plan --json":          "One object per device: the findings, the region, the cleanup and the back-out; values elided.",
	"device config apply --all":          "Every device of yours that a scope covers (Junos devices; the others are left out and counted).",
	"device config apply --scope":        "Only the devices of that scope.",
	"device config apply --vendor":       "Only that vendor's devices (apply writes to Junos devices only).",
	"device config apply --stale":        "Only the devices never read, last read in failure, or differing.",
	"device config apply --concurrency":  "Check or apply at most n devices at once (never above device.config.max_concurrency; an apply runs one at a time unless given).",
	"device config apply --transport":    "How the check and the apply reach a device: auto (NETCONF where the last read found it answering and the login may commit, else the command line, with the reason), cli, or netconf (never falls back); default device.apply.transport. A change to the NETCONF service is made over the command line.",
	"device config apply --timeout":      "Per device check, connect included (10-600; default device.config.timeout); an apply may take its window and two minutes more.",
	"device config apply --max-failures": "Stop starting devices after n failures (an apply: default 1).",
	"device config apply --server":       "The address the devices are told to authenticate against, for devices behind a translating firewall (not stored).",
	"device config apply --source":       "The address this server reaches the devices from (not stored).",
	"device config apply --section":      "Only these sections: aaa, roles, mgmt-acl, snmp, system.",
	"device config apply --json":         "One object per device and phase, then the summary; the review goes to standard error.",
	"device config apply --exit-code":    "With --check: exit 2 when a device needs a change (and none failed).",
	"device config apply -y":             "Answer the review (only with --confirmed: every shape is one an earlier apply confirmed; no terminal needed).",
	"device config shapes -y":            "(seed) Answer the question: file the shapes as confirmed on your word.",
	"device config shapes --json":        "(list) One object per shape: its state, devices, confirmations and the nearest confirmed shape.",
	"device list --name":                 "Only names that contain the text (a comma list: any of them).",
	"device list --ip":                   "Only addresses equal to, inside, or containing it (an address, a CIDR or a text; a comma list).",
	"device list --vendor":               "Only that vendor: cisco, juniper, wti, other or linux (a comma list).",
	"device list --scope":                "Only the devices that scope answers (a comma list).",
	"device add --hostname":              "The device's DNS name.",
	"device add --description":           "A description of the device.",
	"device ssh -X":                      "Forward X11 to this server's display (untrusted, as ssh -X).",
	"device ssh -Y":                      "Forward X11 to this server's display (trusted, as ssh -Y).",
	"ssh -X":                             "Forward X11 to this server's display (untrusted, as ssh -X).",
	"ssh -Y":                             "Forward X11 to this server's display (trusted, as ssh -Y).",
	"host provisioner --remove-home":     "(provisioner) With --remove-old: also delete the old account's home directory, without asking (otherwise it is moved out of reach, made root's)",
	"host provisioner --yes":             "(provisioner) Rotate without asking, and continue with the host keys shown when none is pinned",
	"host forget -y":                     "(forget) Forget the host without asking.",
	"host rename -y":                     "(rename) Answer both questions yes: replace what an earlier host of the new name left, and rename the host's own linux-<name> scope.",
}

// capitalizeDesc starts the sentence of a description with a capital: the
// first word, or the first after a "(command list) " prefix, unless it is a
// name (it has a character that is not a letter, such as pam_tacplus).
func capitalizeDesc(s string) string {
	rest, prefix := s, ""
	if strings.HasPrefix(s, "(") {
		if i := strings.Index(s, ") "); i > 0 {
			prefix, rest = s[:i+2], s[i+2:]
		}
	}
	word, _, _ := strings.Cut(rest, " ")
	if word == "" || word[0] < 'a' || word[0] > 'z' {
		return s
	}
	for _, r := range word {
		if r < 'a' || r > 'z' {
			return s
		}
	}
	return prefix + strings.ToUpper(rest[:1]) + rest[1:]
}

// manFlagDesc is the description of flag f in the usage block of the
// command at path with the lines that continue it joined to it: the block
// continues a description on the lines below, indented to its column.
// first is the one-line description flagHelps found; it is returned when
// no line of the block gives it.
func (inv *invocation) manFlagDesc(cmd *cobra.Command, path []string, f Flag, first string) string {
	if first == "" {
		return first
	}
	_, block := inv.shellUsage(cmd, path)
	blocks := []string{block}
	if len(path) == 1 {
		blocks = append(blocks, Usage("top", UsageVars{"version": inv.build.Version}))
	}
	for _, b := range blocks {
		lines := blockBody(b)
		for i, line := range lines {
			line = strings.TrimRight(line, " ")
			if !strings.HasPrefix(line, "  ") {
				continue
			}
			left, d, ok := splitRow(line)
			if !ok || d != first {
				continue
			}
			named := false
			for _, w := range strings.Fields(strings.ReplaceAll(left, ",", " ")) {
				if slices.Contains(f.Names, w) {
					named = true
				}
			}
			if !named {
				continue
			}
			col := len(line) - len(d)
			pad := strings.Repeat(" ", col)
			full := d
			for _, next := range lines[i+1:] {
				next = strings.TrimRight(next, " ")
				if !strings.HasPrefix(next, pad) || len(next) <= col || next[col] == ' ' {
					break
				}
				full += " " + strings.TrimSpace(next)
			}
			return full
		}
	}
	return first
}

// Configuration keys.

// manKeyRow is one key of a settings file as the page lists it.
type manKeyRow struct {
	key, typ, def, verb, desc string
}

func (r manKeyRow) lines() []string {
	l := []string{".TP", ".B " + roff(r.key), roff(r.typ) + ". Default: " + roff(r.def) + "."}
	text := r.desc
	if r.verb != "" {
		text += " Set with " + r.verb + "."
	}
	if text != "" {
		l = append(l, text)
	}
	return l
}

// tacctl command in a key's "Set with": the words bold.
func setWith(cmds ...string) string {
	var parts []string
	for _, c := range cmds {
		parts = append(parts, `\fBtacctl `+roff(c)+`\fR`)
	}
	return strings.Join(parts, " or ")
}

// manKeyDocs say what each key is for and the verb that sets it; the types
// and defaults are the code's. A key without an entry here (or an entry
// without a key) fails TestManKeyDocsAreComplete.
var manKeyDocs = map[string]struct{ verb, desc string }{
	"password.max_age_days":                  {setWith("config password-age"), "Days after which a password counts as old: tacctl status warns."},
	"password.min_length":                    {setWith("config password-min-length"), "Shortest password typed at a prompt."},
	"secret.min_length":                      {setWith("config secret-min-length"), "Shortest shared secret an operator may type."},
	"bcrypt.cost":                            {setWith("config bcrypt-cost"), "Cost of the bcrypt hashes tacctl makes from now on."},
	"scope.default":                          {setWith("scope default"), "The scope new users and devices land in without a choice; null: none."},
	"host.default_method":                    {setWith("host default-method"), "The method a Linux host is enrolled with when its scope decides none."},
	"linux.uid_min":                          {setWith("config linux uid-range"), "First UID and GID of the Linux accounts tacctl makes, one range for every host."},
	"linux.uid_max":                          {setWith("config linux uid-range"), "Last UID and GID of that range."},
	"linux.engineer_sudo":                    {setWith("config linux engineer-sudo"), "The commands tac-engineer may run through sudo on enrolled hosts other than this server; unset: every command."},
	"mgmt_acl.names.cisco":                   {setWith("config mgmt-acl cisco-name"), "Name of the ACL config cisco emits."},
	"mgmt_acl.names.juniper":                 {setWith("config mgmt-acl juniper-name"), "Name of the filter config juniper emits."},
	"mgmt_acl.permits":                       {setWith("config mgmt-acl add", "config mgmt-acl remove"), "The entries the management ACL and filter permit: a CIDR, or a CIDR with its services (10.0.0.0/8:tcp/22,udp/161,icmp)."},
	"backends.enabled":                       {setWith("backend enable", "backend disable"), "The backends that serve the model, in render and restart order."},
	"backends.tacacs.level":                  {setWith("config loglevel"), "Log level of tacquito."},
	"backends.tacacs.metrics_address":        {setWith("config metrics address"), "Where tacquito's Prometheus exporter listens."},
	"snmp.version":                           {setWith("config snmp community", "config snmp v3-user"), "SNMP version of the name lookup of device add and device check; unset: no lookup."},
	"snmp.port":                              {setWith("config snmp port"), "UDP port of the agents."},
	"snmp.timeout":                           {setWith("config snmp timeout"), "Seconds to wait for an answer (one retry)."},
	"snmp.v3.auth":                           {setWith("config snmp v3-user"), "Authentication protocol of the v3 user."},
	"snmp.v3.priv":                           {setWith("config snmp v3-user"), "Privacy protocol of the v3 user."},
	"device.config.max_concurrency":          {setWith("config devices max-concurrency"), "The most devices device config pull reads at once; --concurrency can lower it for a run, never raise it."},
	"device.config.transport":                {setWith("config devices transport"), "How device config pull reads a device: NETCONF where it answers and the ssh command line otherwise (auto), NETCONF only, or ssh only."},
	"device.config.timeout":                  {setWith("config devices timeout"), "Seconds one device may take in a pull, connect included."},
	"device.config.confirm_timeout":          {setWith("config devices confirm-timeout"), "Minutes of the commit confirmed that ends the region of a Junos device config plan: the switch undoes the paste by itself after that long unless the one word commit is typed."},
	"device.apply.confirm_timeout":           {setWith("config devices apply-confirm-timeout"), "Minutes of the commit confirmed of every device config apply: the device undoes the change by itself after that long unless the confirming commit is typed."},
	"device.apply.pause":                     {setWith("config devices apply-pause"), "Seconds device config apply waits between the devices of a batch after the canary; 0: none."},
	"device.apply.transport":                 {setWith("config devices apply-transport"), "How device config apply reaches a Junos device: NETCONF where the last read found it answering and the login may commit, else the command line (auto), the command line only (cli), or NETCONF only (netconf)."},
	"privileges.<group>":                     {setWith("group privilege"), "The Cisco priv-exec commands the group's level may run; unset: the shipped list."},
	"commands.<group>":                       {setWith("group commands"), "The group's command rules, in order, ending in the catch-all; unset: the shipped rules."},
	"aaa.order.<scope>":                      {setWith("scope aaa-order"), "Order of the methods in the Cisco aaa lines and the Junos authentication-order the scope's configurations emit."},
	"exec_timeout.<scope>":                   {setWith("scope exec-timeout"), "Idle-session timeout in minutes the scope's device configurations set; 0: never."},
	"tacacs_group.<scope>":                   {setWith("scope tacacs-group"), "The label of the Cisco aaa group server tacacs+ the scope's configuration names."},
	"radius_group.<scope>":                   {setWith("scope radius-group"), "The label of the Cisco aaa group server radius the scope's configuration names."},
	"cisco.source_interface.<scope>":         {setWith("config cisco source-interface"), "The interface the scope's Cisco devices source their TACACS+ and RADIUS requests from (ip tacacs source-interface, ip radius source-interface); unset: the standard renders and compares no such line, and the walkthrough prints it commented."},
	"scope_auth_method.<scope>":              {setWith("scope auth-method"), "The protocol the scope's device configurations, new hosts and Linux scripts use when a command names none; unset: not decided (the scope's protocols filter, then the global default)."},
	"scope_mgmt_acl.names.cisco.<scope>":     {setWith("scope mgmt-acl"), "The scope's own ACL name, in place of mgmt_acl.names.cisco."},
	"scope_mgmt_acl.names.juniper.<scope>":   {setWith("scope mgmt-acl"), "The scope's own filter name, in place of mgmt_acl.names.juniper."},
	"scope_mgmt_acl.permits.<scope>":         {setWith("scope mgmt-acl"), "The scope's own permitted entries (a CIDR, or a CIDR with its services), in place of mgmt_acl.permits."},
	"listeners.<backend>.<name>":             {setWith("config listen"), "Where a backend's daemon listens; the built-in listeners can be changed and reset, not removed."},
	"junos.<group>.deny_commands":            {setWith("group junos"), "POSIX extended regular expressions of the commands the Junos class of the group may not run."},
	"junos.<group>.deny_configuration":       {setWith("group junos"), "POSIX extended regular expressions of the configuration statements the Junos class may not touch."},
	"wti_level.<group>":                      {setWith("group edit", "group add"), "The WTI access level of the group, in place of the one its priv-lvl band gives."},
	"tier.<group>":                           {setWith("group edit", "group add"), "The tacctl tier of the group, in place of the one its priv-lvl band gives."},
	"breakglass_scope.<scope>.users":         {setWith("scope breakglass"), "The break-glass local users the scope's device configurations create. Only the names and roles are kept; no credential is stored."},
	"breakglass_hold.<device>.address":       {setWith("breakglass hold"), "The address the server does not answer while the hold stands (a device's registered address, a host's recorded one); a name's dots are written ~ in the key. The renderers take it out of every prefix and tagged address."},
	"breakglass_hold.<device>.since":         {setWith("breakglass hold"), "When the hold was made (RFC 3339)."},
	"breakglass_hold.<device>.by":            {setWith("breakglass hold"), "The user who held it."},
	"breakglass_hold.<device>.reason":        {setWith("breakglass hold"), "Why, 1 to 256 characters; logged and shown, never rendered into a backend file. Removed with the hold by tacctl breakglass release."},
	"blocks.<scope>.<vendor>":                {setWith("scope block"), "The configuration blocks in force for the scope and vendor (juniper or cisco), a list of snmp and system; a file under the blocks directory that this list does not name is ignored."},
	"blocks_device.<device>.<vendor>":        {setWith("device block"), "The configuration blocks in force for one device and vendor (juniper or cisco), a list of snmp and system; the device's lower case name is written with every '.' as '~' (js1~lab~example~net), and a file under the blocks directory that this list does not name is ignored."},
	"snmp_scope.<scope>.version":             {setWith("scope snmp"), "The scope's SNMP version; unset: snmp.version."},
	"snmp_scope.<scope>.port":                {setWith("scope snmp"), "The scope's agent port; unset: snmp.port."},
	"snmp_scope.<scope>.timeout":             {setWith("scope snmp"), "The scope's timeout in seconds; unset: snmp.timeout."},
	"snmp_scope.<scope>.v3.auth":             {setWith("scope snmp"), "The scope's v3 authentication protocol; unset: snmp.v3.auth."},
	"snmp_scope.<scope>.v3.priv":             {setWith("scope snmp"), "The scope's v3 privacy protocol; unset: snmp.v3.priv."},
	"snmp_scope.<scope>.contact":             {setWith("scope snmp"), "The sysContact the scope's walkthroughs set."},
	"netconf_scope.<scope>.state":            {setWith("scope netconf"), "The NETCONF service of the scope's Junos devices: enable or disable (unset: leave, nothing is planned or compared)."},
	"netconf_scope.<scope>.connection_limit": {setWith("scope netconf"), "The connection limit of an enabled NETCONF service (1 to 250); unset: none stated."},
	"netconf_scope.<scope>.rate_limit":       {setWith("scope netconf"), "The rate limit of an enabled NETCONF service (1 to 250); unset: none stated."},
	"snmp_scope.<scope>.clients":             {setWith("scope snmp"), "The SNMP clients the scope's walkthroughs allow (the server's own address first and a final deny are added when rendered, not stored)."},
}

// manKeyDefaults are the defaults the code applies beside the schema, for a
// key the schema gives none.
var manKeyDefaults = map[string]string{
	"snmp.v3.auth": "none (unset); sha is used",
	"snmp.v3.priv": "none (unset); aes128 is used",
}

// manPlaceholders name the instance of a one-name wildcard family.
var manPlaceholders = map[string]string{
	"privileges.": "<group>", "commands.": "<group>", "wti_level.": "<group>", "tier.": "<group>",
	"aaa.order.": "<scope>", "exec_timeout.": "<scope>", "tacacs_group.": "<scope>", "radius_group.": "<scope>",
	"cisco.source_interface.": "<scope>",
	"scope_auth_method.":      "<scope>", "scope_mgmt_acl.names.cisco.": "<scope>",
	"scope_mgmt_acl.names.juniper.": "<scope>", "scope_mgmt_acl.permits.": "<scope>",
}

// manTypeText is how the page names a rule's type.
func manTypeText(r conf.Rule) string {
	switch r.Type {
	case conf.TypeInt:
		switch {
		case r.Min != nil && r.Max != nil:
			return fmt.Sprintf("integer, %d to %d", *r.Min, *r.Max)
		case r.Min != nil:
			return fmt.Sprintf("integer, %d or more", *r.Min)
		}
		return "integer"
	case conf.TypeNullableString:
		return "scope name (a letter, then up to 31 letters, digits, _ or -) or null"
	case conf.TypeEnum:
		return "one of " + strings.Join(r.Values, ", ")
	case conf.TypeACLName:
		return "name of 1 to 63 characters (a letter, then letters, digits, _ or -)"
	case conf.TypeInterfaceName:
		return "interface name in the long form IOS prints (" + strings.Join(conf.InterfaceTypes, ", ") + ", then the number, with / . : separators), such as Loopback0 or GigabitEthernet0/0; not an abbreviation such as lo0"
	case conf.TypeCIDRList:
		return "list of CIDRs, each with optional services after a colon (tcp/22, tcp/161-162, udp/*, icmp, comma separated)"
	case conf.TypeHostPort:
		return "host:port"
	case conf.TypeListener:
		return "mapping with " + strings.Join(conf.ListenerKeys, ", ") + " (tls is reserved)"
	case conf.TypeBackendList:
		return "non-empty list of backends (" + strings.Join(r.Values, ", ") + ")"
	case conf.TypeCiscoCmdList:
		return "list of Cisco priv-exec commands (an entry may start with exec:, exec all:, configure: or configure all:)"
	case conf.TypeCommandRules:
		return "ordered list of {name, action, match} rules ending in the name: \"*\" catch-all"
	case conf.TypeJunosRegexList:
		return "list of regular expressions"
	case conf.TypeSudoCommandList:
		return "non-empty list of absolute command paths"
	case conf.TypeBreakGlassList:
		return "list of name:role entries, role one of " + strings.Join(conf.BreakGlassRoles, ", ") + ", at most " + strconv.Itoa(conf.MaxBreakGlassUsers)
	case conf.TypeHoldAddress:
		return "one IPv4 or IPv6 address, in its canonical form, without a prefix length"
	case conf.TypeHoldSince:
		return "RFC 3339 time"
	case conf.TypeHoldText:
		return "text of 1 to " + strconv.Itoa(conf.MaxHoldReason) + " characters (a user name for by)"
	case conf.TypeSNMPClients:
		return "list of IPv4 CIDRs"
	case conf.TypeSNMPText:
		return "text of 1 to " + strconv.Itoa(conf.MaxSNMPText) + " characters"
	case conf.TypeBlockList:
		return "non-empty list of block names (" + strings.Join(blocks.KnownBlocks, ", ") + ")"
	}
	return "unknown type " + r.Type
}

// manValueText is a default as the page prints it.
func manValueText(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case bool:
		return strconv.FormatBool(x)
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = manValueText(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		return "[" + strings.Join(x, ", ") + "]"
	}
	return fmt.Sprint(v)
}

// defaultsAt is the shipped default (defaults.yaml) at a dotted path.
func defaultsAt(path string) (any, bool) {
	var cur any = conf.Defaults()
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(*yamlpy.Map)
		if !ok {
			return nil, false
		}
		if cur, ok = m.Get(k); !ok {
			return nil, false
		}
	}
	return cur, true
}

// manConfigKeyRows are the keys of tacctl.yaml: the exact keys of the schema
// in order, then its wildcard families.
func manConfigKeyRows(t *testing.T) []manKeyRow {
	t.Helper()
	var ids []string
	for _, b := range conf.ListenerBackends {
		ids = append(ids, b.ID)
	}
	s := conf.NewSchema(ids)
	var rows []manKeyRow
	add := func(key string, r conf.Rule, def string) {
		doc, ok := manKeyDocs[key]
		if !ok {
			t.Errorf("tacctl.yaml key %s has no entry in manKeyDocs (man_gen_test.go): add what it is for and the verb that sets it", key)
		}
		if d, ok := manKeyDefaults[key]; ok && def == "none (unset)" {
			def = d
		}
		rows = append(rows, manKeyRow{key: key, typ: manTypeText(r), def: def, verb: doc.verb, desc: doc.desc})
	}
	for _, k := range s.Keys() {
		r, _ := s.RuleFor(k)
		def := "none (unset)"
		if r.HasDefault {
			def = manValueText(r.Default)
		} else if v, ok := defaultsAt(k); ok {
			def = manValueText(v)
		}
		add(k, r, def)
	}
	for _, f := range s.Families() {
		def := "none (unset)"
		if f.Rule.HasDefault {
			def = manValueText(f.Rule.Default)
		}
		ph := manPlaceholders[f.Prefix]
		switch {
		case f.Rule.Tail != "" && f.Prefix == "breakglass_hold.":
			add(f.Prefix+"<device>."+f.Rule.Tail, f.Rule, def)
		case f.Rule.Tail != "":
			add(f.Prefix+"<scope>."+f.Rule.Tail, f.Rule, def)
		case f.Prefix == "junos.":
			for _, a := range conf.JunosAttrs {
				add(f.Prefix+"<group>."+a, f.Rule, def)
			}
		case f.Prefix == "breakglass_scope.":
			add(f.Prefix+"<scope>."+conf.BreakGlassUsersKey, f.Rule, def)
		case f.Prefix == conf.BlocksPrefix:
			add(f.Prefix+"<scope>.<vendor>", f.Rule, def)
		case f.Prefix == conf.BlocksDevicePrefix:
			add(f.Prefix+"<device>.<vendor>", f.Rule, def)
		case f.Prefix == "listeners.":
			var parts []string
			for _, b := range conf.ListenerBackends {
				for _, d := range b.Defaults {
					net, _ := d.Value.Get("network")
					addr, _ := d.Value.Get("address")
					parts = append(parts, fmt.Sprintf("%s.%s is %v %v", b.ID, d.Name, net, addr))
				}
			}
			add("listeners.<backend>.<name>", f.Rule, strings.Join(parts, "; "))
		case ph != "":
			if _, ok := defaultsAt(strings.TrimSuffix(f.Prefix, ".")); ok && !f.Rule.HasDefault {
				def = "the shipped value of each built-in group (tacctl config defaults)"
			}
			add(f.Prefix+ph, f.Rule, def)
		default:
			t.Errorf("the schema has the wildcard family %q, which man_gen_test.go does not know how to name: add a placeholder to manPlaceholders", f.Prefix)
		}
	}
	return rows
}

// Every key has a doc entry and every doc entry a key.
func TestManKeyDocsAreComplete(t *testing.T) {
	keys := map[string]bool{}
	for _, r := range manConfigKeyRows(t) {
		keys[r.key] = true
	}
	for k := range manKeyDocs {
		if !keys[k] {
			t.Errorf("manKeyDocs has %s, which is no key of the tacctl.yaml schema: drop it", k)
		}
	}
	for k := range manConsoleDocs {
		if !slices.ContainsFunc(manConsoleKeyRows(t), func(r manKeyRow) bool { return r.key == k }) {
			t.Errorf("manConsoleDocs has %s, which is no console.yaml setting: drop it", k)
		}
	}
}

// The console.yaml settings.

var manConsoleDocs = map[string]struct{ typ, verb, desc string }{
	"version":                     {"integer", "", "The format of the file; this release reads and writes 1."},
	"tiers.<tier>":                {"enable or disable", setWith("console tiers"), "Whether the tier gets the console as its login shell on this server (readonly, operator, engineer, superuser)."},
	"users.<name>":                {"enable or disable", setWith("console user"), "A user's override of the tier's switch; no entry: the tier decides."},
	"settings.idle_timeout":       {"integer, 0 to " + strconv.Itoa(console.MaxIdle) + " minutes (0: none)", setWith("console idle-timeout"), "Idle time after which a console session ends."},
	"settings.agent_forwarding":   {"true or false", setWith("console agent-forwarding"), "Whether the console's ssh and sshd's drop-in forward the ssh agent."},
	"settings.ssh_escape":         {"true or false", setWith("console ssh-escape"), "Whether the escape character of the console's ssh stays on."},
	"settings.system_shell":       {"absolute path", setWith("console system-shell path"), "The program the console's system-shell word starts."},
	"settings.system_shell_tiers": {"list of tiers (not engineer)", setWith("console system-shell tiers"), "The tiers that may start the system shell."},
	"settings.forwarding_tiers":   {"list of tiers (not engineer)", setWith("console forwarding tiers"), "The tiers whose console logins may forward X11 and TCP ports."},
	"settings.gateway_ports":      {"true or false", setWith("console forwarding gateway-ports"), "Whether those tiers may bind forwarded ports to an address other than loopback."},
	"settings.list_max":           {"integer, 1 to " + strconv.Itoa(console.MaxListMax), "", "The number of completions the console's shell lists without asking. Edit the file to change it."},
	"settings.space_completion":   {"true or false", setWith("console space-completion"), "Whether a typed space at the console's prompt completes a fixed word, as on Junos. Written to the file only when false."},
}

// manConsoleKeyRows are the settings of console.yaml, read from the file the
// code writes: the keys of a file with every setting present, and the
// defaults of the file that is not there.
func manConsoleKeyRows(t *testing.T) []manKeyRow {
	t.Helper()
	load := func(f *console.File) *yamlpy.Map {
		text, err := f.Text()
		if err != nil {
			t.Fatal(err)
		}
		v, err := pyyaml.LoadBytes(text)
		m, ok := v.(*yamlpy.Map)
		if err != nil || !ok {
			t.Fatalf("console.yaml text does not parse: %v", err)
		}
		return m
	}
	full := console.Defaults()
	full.SpaceCompletion = false
	all, def := load(full), load(console.Defaults())
	var rows []manKeyRow
	add := func(key, defText string) {
		doc, ok := manConsoleDocs[key]
		if !ok {
			t.Errorf("console.yaml key %s has no entry in manConsoleDocs (man_gen_test.go)", key)
		}
		rows = append(rows, manKeyRow{key: key, typ: doc.typ, def: defText, verb: doc.verb, desc: doc.desc})
	}
	for _, k := range all.Keys() {
		v, _ := all.Get(k)
		dv, _ := def.Get(k)
		m, isMap := v.(*yamlpy.Map)
		switch {
		case k == "tiers":
			dm := dv.(*yamlpy.Map)
			var vals []string
			for _, tk := range dm.Keys() {
				tv, _ := dm.Get(tk)
				if s := manValueText(tv); !slices.Contains(vals, s) {
					vals = append(vals, s)
				}
			}
			add("tiers.<tier>", strings.Join(vals, " or "))
		case k == "users":
			add("users.<name>", "none (no override)")
		case isMap && k == "settings":
			dm := dv.(*yamlpy.Map)
			for _, sk := range m.Keys() {
				var d any
				if x, ok := dm.Get(sk); ok {
					d = x
				} else {
					// Written only when it is not the default: the default is
					// the opposite of the value of the full file.
					sv, _ := m.Get(sk)
					b, isBool := sv.(bool)
					if !isBool {
						t.Fatalf("settings.%s is absent from the default file and is no boolean", sk)
					}
					d = !b
				}
				add("settings."+sk, manValueText(d))
			}
		default:
			add(k, manValueText(dv))
		}
	}
	return rows
}

func manKeysBlock(name string, rows []manKeyRow) manBlock {
	var l []string
	for _, r := range rows {
		l = append(l, r.lines()...)
	}
	return manBlock{name: name, lines: l}
}

// Every key of tacctl.yaml and every setting of console.yaml is under
// CONFIGURATION KEYS with its type and default.
func TestManPageDocumentsEveryConfigKey(t *testing.T) {
	d := readManDoc(t)
	from, to := d.section(t, "CONFIGURATION KEYS", "the generated key lists: 'make man'")
	tags, body := d.tagged(from, to)
	for _, set := range []struct {
		file string
		rows []manKeyRow
	}{{"tacctl.yaml", manConfigKeyRows(t)}, {"console.yaml", manConsoleKeyRows(t)}} {
		if len(set.rows) < 10 {
			t.Fatalf("%s: only %d keys", set.file, len(set.rows))
		}
		for _, r := range set.rows {
			text, ok := body[manClean(r.key)]
			switch {
			case !slices.Contains(tags, manClean(r.key)):
				t.Errorf("%s key %s is not under .SH CONFIGURATION KEYS in man/tacctl.1: run 'make man' (the %s list)", set.file, r.key, set.file)
			case !ok || !strings.Contains(text, manClean(r.typ)):
				t.Errorf("%s key %s: the page does not give its type %q: run 'make man'", set.file, r.key, r.typ)
			case !strings.Contains(text, "Default: "+manClean(r.def)):
				t.Errorf("%s key %s: the page does not give its default %q: run 'make man'", set.file, r.key, r.def)
			}
		}
	}
}

// The regions.

var manMarker = regexp.MustCompile(`^\.\\" (BEGIN|END) GENERATED: (.+)$`)

type manRegion struct {
	name       string
	begin, end int // the marker lines
}

// manRegions are the generated regions of the page, in order; problems
// are unbalanced or repeated markers.
func manRegions(lines []string) (regions []manRegion, problems []string) {
	open := -1
	seen := map[string]bool{}
	for i, l := range lines {
		m := manMarker.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		switch {
		case m[1] == "BEGIN" && open >= 0:
			problems = append(problems, fmt.Sprintf("man/tacctl.1:%d: BEGIN GENERATED %s inside %s", i+1, m[2], regions[len(regions)-1].name))
		case m[1] == "BEGIN":
			if seen[m[2]] {
				problems = append(problems, fmt.Sprintf("man/tacctl.1:%d: the generated block %s occurs twice", i+1, m[2]))
			}
			seen[m[2]] = true
			regions = append(regions, manRegion{name: m[2], begin: i})
			open = len(regions) - 1
		case open < 0 || regions[open].name != m[2]:
			problems = append(problems, fmt.Sprintf("man/tacctl.1:%d: END GENERATED %s without its BEGIN", i+1, m[2]))
		default:
			regions[open].end = i
			open = -1
		}
	}
	if open >= 0 {
		problems = append(problems, fmt.Sprintf("man/tacctl.1:%d: BEGIN GENERATED %s has no END", regions[open].begin+1, regions[open].name))
	}
	return regions, problems
}

// manInsertAt is the line before which the 'command' block of an entry goes:
// the end of the entry, without the paragraph and tag macros that lead into
// the next heading.
func manInsertAt(d *manDoc, e manEntry) int {
	at := e.end
	for at-1 > e.start && (d.lines[at-1] == ".TP" || d.lines[at-1] == ".PP" || strings.TrimSpace(d.lines[at-1]) == "") {
		at--
	}
	return at
}

// manApply is the page with the blocks written into it: the regions it has
// get the new lines, the 'command' blocks it lacks are inserted at the end
// of the command's first entry, a region nothing generates is dropped. changed
// names the blocks that differ; problems are what a person must fix (a
// block that is not a command's and has no markers, a command without
// entry).
func manApply(d *manDoc, blocks []manBlock) (out, changed, problems []string) {
	regions, problems := manRegions(d.lines)
	want := map[string]manBlock{}
	for _, b := range blocks {
		want[b.name] = b
	}
	have := map[string]manRegion{}
	for _, r := range regions {
		have[r.name] = r
	}
	inserts := map[int][]string{}
	for _, b := range blocks {
		if _, ok := have[b.name]; ok {
			continue
		}
		words, isCommand := strings.CutPrefix(b.name, "command ")
		if !isCommand {
			problems = append(problems, fmt.Sprintf("man/tacctl.1 has no generated block %q: put '.\\\" BEGIN GENERATED: %s' and '.\\\" END GENERATED: %s' lines where it belongs", b.name, b.name, b.name))
			continue
		}
		entries := d.entriesOf(strings.Fields(words))
		if len(entries) == 0 {
			problems = append(problems, fmt.Sprintf("man/tacctl.1 has no .TP entry for 'tacctl %s': add one (its tag starts '%s') in the section of its family", words, words))
			continue
		}
		at := manInsertAt(d, entries[0])
		inserts[at] = append(inserts[at], manMarkerLine("BEGIN", b.name))
		inserts[at] = append(inserts[at], b.lines...)
		inserts[at] = append(inserts[at], manMarkerLine("END", b.name))
		changed = append(changed, b.name)
	}
	byBegin := map[int]manRegion{}
	for _, r := range regions {
		byBegin[r.begin] = r
	}
	for i := 0; i < len(d.lines); i++ {
		out = append(out, inserts[i]...)
		r, ok := byBegin[i]
		if !ok || r.end == 0 {
			out = append(out, d.lines[i])
			continue
		}
		b, wanted := want[r.name]
		if !wanted {
			changed = append(changed, r.name+" (stale)")
			i = r.end
			continue
		}
		if !slices.Equal(d.lines[r.begin+1:r.end], b.lines) {
			changed = append(changed, r.name)
		}
		out = append(out, d.lines[i])
		out = append(out, b.lines...)
		out = append(out, d.lines[r.end])
		i = r.end
	}
	out = append(out, inserts[len(d.lines)]...)
	return out, changed, problems
}

func manMarkerLine(kind, name string) string { return `.\" ` + kind + " GENERATED: " + name }

// manBlocks are all the generated blocks, in page order where it matters.
func manBlocks(t *testing.T) []manBlock {
	t.Helper()
	blocks := []manBlock{manTiersBlock(), manAuditBlock(), manKeysBlock("config-keys", manConfigKeyRows(t)), manKeysBlock("console-keys", manConsoleKeyRows(t))}
	return append(blocks, manCommandBlocks(t)...)
}

// The generated blocks of the page are what the code generates. With
// -update-man (make man) the page is rewritten instead.
func TestManGeneratedBlocksAreCurrent(t *testing.T) {
	d := readManDoc(t)
	out, changed, problems := manApply(d, manBlocks(t))
	for _, p := range problems {
		t.Error(p)
	}
	if len(changed) == 0 && slices.Equal(out, d.lines) {
		return
	}
	if *updateMan {
		if len(problems) > 0 {
			t.Fatal("not rewriting man/tacctl.1 until the problems above are fixed")
		}
		if err := os.WriteFile(filepath.Join("..", "..", "man", "tacctl.1"), []byte(strings.Join(out, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("man/tacctl.1 rewritten: %d generated blocks changed", len(changed))
		return
	}
	shown := changed
	if len(shown) > 12 {
		shown = append(slices.Clone(shown[:12]), fmt.Sprintf("... and %d more", len(changed)-12))
	}
	t.Errorf("the generated blocks of man/tacctl.1 are stale (%d: %s): run 'make man' and commit the page", len(changed), strings.Join(shown, ", "))
}
