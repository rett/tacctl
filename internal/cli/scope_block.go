package cli

// 'scope block' (0.2.7, docs/plans/0.2.7-blocks-plan.md B4): a scope's
// configuration blocks, the vendor syntax it owns beside its structured
// settings. The engine is blocks_verbs.go; this file is the dispatcher, the
// argument specs and the usage. The verbs that set or remove are the
// superuser's, and so is every one that would change what a device is told;
// an engineer reads the blocks of their own scopes (the tier gate sees
// 'scope block' only, so the engineer's part is decided here, as 'scope
// snmp' does), and every reveal is logged.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	shellHelpBlocks["scope block"] = func(*invocation) string { return scopeBlockUsage("<scope>") }
	shellHelpBlocks["device block"] = func(*invocation) string { return deviceBlockUsage("<name>") }
}

const scopeBlockUse = "block <scope> {juniper|cisco} {list|show|check|set|remove|edit|adopt} [<block>] [options]"

const scopeBlockShort = "A scope's configuration blocks (Junos snmp and system, IOS snmp): list, show, check, set, remove, edit, adopt"

var (
	flagFile    = Flag{Names: []string{"--file"}, Value: true, Kind: KindFile}
	blockSubs   = "list|show|check|set|remove|edit|adopt"
	blockSubSet = map[string]bool{"list": true, "show": true, "check": true, "set": true, "remove": true, "edit": true, "adopt": true}
)

// scopeBlockSpecs are the arguments of each verb after the vendor.
var scopeBlockSpecs = map[string]Spec{
	"list":   {MaxArgs: 0},
	"show":   {MinArgs: 1, MaxArgs: 1, Args: []string{blockWords}, Flags: []Flag{{Names: []string{"--reveal"}}}},
	"check":  {MinArgs: 1, MaxArgs: 2, Args: []string{blockWords, ""}, Flags: []Flag{flagFile, {Names: []string{"--against"}, Value: true, Kind: KindDevices}}},
	"set":    {MinArgs: 1, MaxArgs: 2, Args: []string{blockWords, ""}, Flags: []Flag{flagFile, flagYes}},
	"remove": {MinArgs: 1, MaxArgs: 1, Args: []string{blockWords}, Flags: []Flag{flagYes}},
	"edit":   {MinArgs: 1, MaxArgs: 1, Args: []string{blockWords}, Flags: []Flag{flagYes}},
	"adopt":  {MinArgs: 2, MaxArgs: 2, Args: []string{KindDevices, blockWords}, Flags: []Flag{flagYes}},
}

// scopeBlockCompletion is the Spec of the whole verb for completion (the
// words after 'tacctl scope block').
var scopeBlockCompletion = Spec{MinArgs: 1, MaxArgs: -1,
	Args: []string{KindScopes, "juniper|cisco", blockSubs, Cond("adopt", KindDevices, blockWords), Cond("adopt", blockWords, "")},
	Flags: []Flag{{Names: []string{"--reveal"}, Only: "show"}, {Names: []string{"--file"}, Value: true, Only: "check|set", Kind: KindFile},
		{Names: []string{"--against"}, Value: true, Only: "check", Kind: KindDevices},
		{Names: []string{"-y", "--yes"}, Only: "set|remove|edit|adopt"}}}

// scopeBlockVerbs are the verbs ({Use, Short}), in usage order.
var scopeBlockVerbs = [][2]string{
	{"list", "The blocks of the scope: whether each is in force, its size and what it states, and the findings (a file tacctl.yaml does not name, a name with no file)"},
	{"show <block> [--reveal]", "The block as it is in force, elided (marks for community strings, trap group names, NTP keys and the login message); --reveal prints it as stored"},
	{"check <block> [--file <path>|-] [--against <device>]", "Lint the file in force, a file or standard input: every finding with its line, the objects that become owned, the statements that carry a secret and the diff against the file in force"},
	{"set <block> (--file <path>|-) [-y]", "Check a file or standard input, show the diff, ask, take a snapshot and put the block in force"},
	{"remove <block> [-y]", "Take the block out of force and delete its file (asks)"},
	{"edit <block> [-y]", "Open the block in your editor (VISUAL, EDITOR, else editor, else vi, run as you on a private copy), check what comes back and, after the diff and the question, put it in force"},
	{"adopt <device> <block> [-y]", "Read the device's own statements of the hierarchy with your login (nothing is stored), open them in your editor as the draft to prune, then check, diff, ask and put the block in force"},
}

// scopeBlockOptions are the option lines under a verb's row.
var scopeBlockOptions = map[string][][2]string{
	"show": {
		{"--reveal", "Print the strings (an engineer: their own scopes; logged)"},
	},
	"check": {
		{"--file <path>", "(check, set) The text to look at: a regular file of at most 256 KiB, read as you"},
		{"--against <device>", "Plan the device of this scope with this text in force and print the statements of its section (from its last pull; nothing is written and no device is reached)"},
	},
	"set": {
		{"-y, --yes", "(set, remove, edit, adopt) Answer yes to the question (a block read from standard input needs it)"},
	},
}

// scopeBlockUsage is the usage of 'scope block'.
func scopeBlockUsage(scope string) string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "tacctl scope block " + scope + " {juniper|cisco}" + ui.NC + " — configuration blocks of scope '" + scope + "'\n\nUsage: tacctl scope block " + scope + " {juniper|cisco} <subcommand>\n\n")
	for _, v := range scopeBlockVerbs {
		use, short := v[0], v[1]
		if len(use) > 40 {
			b.WriteString("  " + use + "\n  " + strings.Repeat(" ", 40) + "  " + short + "\n")
		} else {
			fmt.Fprintf(&b, "  %-40s  %s\n", use, short)
		}
		for _, o := range scopeBlockOptions[strings.Fields(use)[0]] {
			fmt.Fprintf(&b, "      %-36s  %s\n", o[0], o[1])
		}
	}
	b.WriteString(`
A block is the vendor's own syntax and nothing else, kept as a text file of
its own: Junos 'set' statements (a 'delete' line says "not managed on this
device") for juniper, IOS configuration lines (a 'no' line says it) for
cisco; <block> is snmp or system, and the IOS system block is not built. The
Junos snmp block's communities, client lists and trap groups, and the IOS snmp
block's communities and the standard access lists it defines, are objects
tacctl owns once the block is in force: 'device config plan' sets what a
device lacks and removes the statements of those objects that the block does
not state, and the device's other communities are kept. An IOS block's trap
hosts and 'enable traps' lines are added when missing and never removed. The
Junos system block is additive: its statements are set when missing and
nothing the device holds is removed. The login message is a heredoc (set
system login message <<'EOF' ... EOF). A block holds community strings, so
'show' elides them and only 'show --reveal' prints them. A block is in force
only while tacctl.yaml names it (blocks.<scope>.<vendor>); the files are
/etc/tacctl/blocks/<scope>/<vendor>/ (0600) and are in every snapshot.
Setting and removing are the superuser's; an engineer reads the blocks of
their own scopes.

edit and adopt need a terminal and are the superuser's. The editor is yours:
VISUAL, else EDITOR, else 'editor', else 'vi', started as you (never as root)
on a private copy in a directory of its own under /var/tmp, which is removed
afterwards; the text is installed only after the check passes, the diff is
shown and you say yes, and a text that fails the check is offered back to the
editor with the findings at the top. An editor may leave swap or backup files
beside its copy (they are in that directory, and removed with it), and a
block holds community strings, which are a poller's credential on this host
and in the snapshots. adopt reads the device's statements of the hierarchy
with your login (the password as 'device config pull' asks it; an IOS device's
'snmp-server' lines and the access lists its communities name), drops what
tacctl renders itself and the device's identity (snmp name, engine-id,
contact, location), and a community whose string the device shows masked or as
ciphertext is left out with a line that says so.

Examples:
  tacctl scope block ` + scope + ` juniper list
  tacctl scope block ` + scope + ` juniper check snmp --file snmp.txt --against js1.lab.example.net
  tacctl scope block ` + scope + ` juniper set snmp --file snmp.txt
  tacctl scope block ` + scope + ` juniper show system
  tacctl scope block ` + scope + ` juniper edit snmp
  tacctl scope block ` + scope + ` juniper adopt js1.lab.example.net snmp
  tacctl scope block ` + scope + ` cisco check snmp --file snmp.txt --against rt1.lab.example.net

`)
	return b.String()
}

// scopeBlock dispatches 'scope block <scope> juniper <subcommand>'.
func (inv *invocation) scopeBlock(args []string) error {
	const usage = "Usage: tacctl scope " + scopeBlockUse
	scope := arg(args, 0)
	switch scope {
	case "":
		return inv.usageErr(usage)
	case "-h", "--help", "help":
		inv.write(scopeBlockUsage("<scope>"))
		return nil
	}
	f := inv.callerScopes()
	if f.restricted {
		if err := inv.scopeNotFound(f, scope); err != nil {
			return err
		}
	}
	if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	vendor, sub := arg(args, 1), arg(args, 2)
	switch vendor {
	case "", "-h", "--help", "help":
		inv.write(scopeBlockUsage(scope))
		return nil
	case blocks.VendorJuniper, blocks.VendorCisco:
	case "wti":
		return inv.usageErr("A WTI unit has no configuration blocks: the vendors with blocks are juniper and cisco.", usage)
	default:
		if blockSubSet[vendor] {
			return inv.usageErr("The vendor comes before the verb: tacctl scope block "+scope+" juniper|cisco "+vendor+" ...", usage)
		}
		return inv.usageErr("Unknown vendor '"+vendor+"' for a block: juniper or cisco.", usage)
	}
	switch sub {
	case "":
		sub = "list"
	case "-h", "--help", "help":
		inv.write(scopeBlockUsage(scope))
		return nil
	}
	spec, ok := scopeBlockSpecs[sub]
	if !ok {
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(scopeBlockUsage(scope))
		return exit(1)
	}
	var rest []string
	if len(args) > 3 {
		rest = args[3:]
	}
	p, err := Parse(spec, rest)
	if err != nil {
		return inv.scopeBlockUsageErr(scope, vendor, sub, err)
	}
	c := &blockCtx{inv: inv, level: blocks.ScopeLevel(scope), vendor: vendor, scope: scope, restricted: f.restricted}
	return inv.blockRun(c, sub, p, "tacctl scope block "+scope+" "+vendor+" "+sub)
}

func (inv *invocation) scopeBlockUsageErr(scope, vendor, verbName string, err error) error {
	var use string
	for _, v := range scopeBlockVerbs {
		if strings.Fields(v[0])[0] == verbName {
			use = v[0]
		}
	}
	msg := err.Error()
	var uf *UnknownFlagError
	if errors.As(err, &uf) {
		msg = "Unknown option: '" + uf.Flag + "'"
	}
	return inv.usageErr(msg, "Usage: tacctl scope block "+scope+" "+vendor+" "+use)
}

// blockRun runs a verb that is the same at both levels once the level is
// settled.
func (inv *invocation) blockRun(c *blockCtx, sub string, p Parsed, usage string) error {
	if sub == "list" {
		return c.list()
	}
	block, device := p.Args[0], ""
	if sub == "adopt" && !c.isDevice() {
		device, block = p.Args[0], p.Args[1]
	}
	if err := inv.blockName(block); err != nil {
		return err
	}
	if c.vendor == blocks.VendorCisco && block == blocks.BlockSystem && sub != "remove" {
		return inv.usageErr("The IOS system block is not built: only the snmp block exists for vendor cisco.")
	}
	switch sub {
	case "show":
		return c.show(block, p.Has("--reveal"), p.Has("--effective"))
	case "check":
		against := p.Value("--against")
		if p.Has("--against") && c.isDevice() {
			against = c.dev.Name
		}
		if p.Has("--against") && against == "" {
			return inv.usageErr("--against takes the name of a device of the scope.", "Usage: "+usage+" "+block)
		}
		return c.check(block, p, against, usage+" "+block)
	case "set":
		return c.set(block, p, usage+" "+block)
	case "remove":
		return c.remove(block, p)
	case "edit":
		return c.edit(block, p)
	case "adopt":
		return c.adopt(block, device, p)
	}
	return inv.usageErr("Unknown subcommand: '" + sub + "'")
}
