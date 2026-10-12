package cli

// 'device block' (0.2.7, docs/plans/0.2.7-blocks-plan.md B8): one device's
// own configuration blocks, laid over its scope's. The verbs are those of
// 'scope block' (blocks_verbs.go); the device is found in the registry as
// 'device snmp' finds it, an engineer reaches the devices of their own scopes
// only, and a device that is not a Junos device of a scope has no blocks.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/ui"
)

const deviceBlockUse = "block <name> {list|show|check|set|remove} [<block>] [options]"

// deviceBlockSpecs are the arguments of each verb after the device's name.
var deviceBlockSpecs = map[string]Spec{
	"list": {MaxArgs: 0},
	"show": {MinArgs: 1, MaxArgs: 1, Args: []string{blockWords}, Flags: []Flag{{Names: []string{"--reveal"}}, {Names: []string{"--effective"}}}},
	"check": {MinArgs: 1, MaxArgs: 2, Args: []string{blockWords, ""}, Flags: []Flag{flagFile,
		{Names: []string{"--against"}}}},
	"set":    {MinArgs: 1, MaxArgs: 2, Args: []string{blockWords, ""}, Flags: []Flag{flagFile, flagYes}},
	"remove": {MinArgs: 1, MaxArgs: 1, Args: []string{blockWords}, Flags: []Flag{flagYes}},
}

// deviceBlockCompletion is the Spec of the whole verb for completion (the
// words after 'tacctl device block').
var deviceBlockCompletion = Spec{MinArgs: 1, MaxArgs: -1,
	Args: []string{KindDevices, blockSubs, blockWords, ""},
	Flags: []Flag{{Names: []string{"--reveal"}, Only: "show"}, {Names: []string{"--effective"}, Only: "show"},
		{Names: []string{"--file"}, Value: true, Only: "check|set", Kind: KindFile},
		{Names: []string{"--against"}, Only: "check"}, {Names: []string{"-y", "--yes"}, Only: "set|remove"}}}

// deviceBlockVerbs are the verbs ({Use, Short}), in usage order.
var deviceBlockVerbs = [][2]string{
	{"list", "The device's own blocks: whether each is in force, its size and what it states, and the findings"},
	{"show <block> [--effective] [--reveal]", "The device's block elided; --effective: the block as rendered (the scope's with the device's over it, a comment per object saying which layer it is from); --reveal prints the strings"},
	{"check <block> [--file <path>|-] [--against]", "Lint the file in force, a file or standard input; --against plans this device with the text in force and prints the statements of the block's section"},
	{"set <block> (--file <path>|-) [-y]", "Check a file or standard input, show the diff, ask, take a snapshot and put the block in force"},
	{"remove <block> [-y]", "Take the block out of force and delete its file (asks)"},
}

// deviceBlockOptions are the option lines under a verb's row.
var deviceBlockOptions = map[string][][2]string{
	"show": {
		{"--effective", "The block as rendered for the device, with the layer of each object"},
		{"--reveal", "Print the strings (an engineer: their own scopes' devices; logged)"},
	},
	"check": {
		{"--file <path>", "(check, set) The text to look at: a regular file of at most 256 KiB, read as you"},
		{"--against", "Plan the device with this text in force and print the statements of its section (from its last pull; nothing is written and no device is reached)"},
	},
	"set": {
		{"-y, --yes", "(set, remove) Answer yes to the question (a block read from standard input needs it)"},
	},
}

// deviceBlockUsage is the usage of 'device block'.
func deviceBlockUsage(name string) string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "tacctl device block " + name + ui.NC + " — configuration blocks of device '" + name + "'\n\nUsage: tacctl device block " + name + " <subcommand>\n\n")
	for _, v := range deviceBlockVerbs {
		use, short := v[0], v[1]
		if len(use) > 40 {
			b.WriteString("  " + use + "\n  " + strings.Repeat(" ", 40) + "  " + short + "\n")
		} else {
			fmt.Fprintf(&b, "  %-40s  %s\n", use, short)
		}
		for _, o := range deviceBlockOptions[strings.Fields(use)[0]] {
			fmt.Fprintf(&b, "      %-36s  %s\n", o[0], o[1])
		}
	}
	b.WriteString(`
A device's block is Junos 'set' statements, as a scope's is ('tacctl scope
block'), laid over its scope's block per object: a community the device's block
states replaces the scope's community of the same string whole, one it adds is
added, and the scope's others stay; the same for a trap group (by name), a
trap-options leaf and, in the system block, a single value or a list entry. A
'delete' line of the device's block takes the scope's object out for this
device. A device in no scope, and a device that is not a Junos device, has no
blocks. The files are /etc/tacctl/blocks/_devices/<name>/juniper/ (0600), named
in tacctl.yaml by blocks_device.<name>.juniper (the name's dots written '~');
'rename' moves them and 'remove' deletes them.

Examples:
  tacctl device block js1.lab.example.net list
  tacctl device block js1.lab.example.net show snmp --effective
  tacctl device block js1.lab.example.net set snmp --file snmp.txt

`)
	return b.String()
}

// deviceBlock dispatches 'device block <name> <subcommand>'.
func (inv *invocation) deviceBlock(args []string) error {
	const usage = "Usage: tacctl device " + deviceBlockUse
	key := arg(args, 0)
	switch key {
	case "":
		return inv.usageErr(usage)
	case "-h", "--help", "help":
		inv.write(deviceBlockUsage("<name>"))
		return nil
	}
	sub := arg(args, 1)
	switch sub {
	case "":
		sub = "list"
	case "-h", "--help", "help":
		inv.write(deviceBlockUsage(key))
		return nil
	}
	spec, ok := deviceBlockSpecs[sub]
	if !ok {
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(deviceBlockUsage(key))
		return exit(1)
	}
	var rest []string
	if len(args) > 2 {
		rest = args[2:]
	}
	p, err := Parse(spec, rest)
	if err != nil {
		return inv.deviceBlockUsageErr(key, sub, err)
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, err := inv.deviceFind(res, key)
	if err != nil {
		return err
	}
	entry := e
	c := &blockCtx{inv: inv, level: blocks.DeviceLevel(e.Name), vendor: blocks.VendorJuniper, scope: e.Scope, dev: &entry,
		restricted: inv.callerScopes().restricted}
	// what an engineer may not do is refused before the device's own
	// properties are discussed
	if (sub == "set" || sub == "remove") && e.Source == devreg.SourceDevice {
		if err := c.requireSuperuser(sub); err != nil {
			return err
		}
	}
	switch {
	case e.Source != devreg.SourceDevice:
		return inv.usageErr("'" + e.Name + "' is an enrolled Linux host; configuration blocks are for registered devices (tacctl device list).")
	case e.Vendor == blocks.VendorCisco:
		return inv.usageErr("IOS blocks come in the release after: only Junos devices have blocks in this release.")
	case e.Vendor != "juniper":
		return inv.usageErr("Device '" + e.Name + "' is vendor '" + dash(e.Vendor) + "': configuration blocks are for Junos devices.")
	case !e.Configured && sub != "remove":
		return inv.usageErr("Device '" + e.Name + "' is in no scope: no scope's prefixes cover " + e.Address + ", so nothing is rendered for it and a block of its own would never be used. Put it in a scope first (tacctl scope prefixes <scope> add <cidr>).")
	}
	return inv.blockRun(c, sub, p, "tacctl device block "+shellWord(e.Name)+" "+sub)
}

func (inv *invocation) deviceBlockUsageErr(name, verbName string, err error) error {
	var use string
	for _, v := range deviceBlockVerbs {
		if strings.Fields(v[0])[0] == verbName {
			use = v[0]
		}
	}
	msg := err.Error()
	var uf *UnknownFlagError
	if errors.As(err, &uf) {
		msg = "Unknown option: '" + uf.Flag + "'"
	}
	return inv.usageErr(msg, "Usage: tacctl device block "+name+" "+use)
}
