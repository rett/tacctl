package cli

// The 'device' family (docs/plans/operator-console.md 3 and 7): the registry
// of the network devices that authenticate against this server, in
// /etc/tacctl/devices.yaml (internal/devreg). It registers itself with
// registerFamily, registerSpecs and registerDeviceNames; root.go and
// completion.go know nothing of it. The registry never writes store.yaml:
// scope and vendor tag are looked up per display, and every write takes a
// snapshot first. Host-key pinning is device_hostkey.go ('add' scans and
// pins, 'hostkey' re-pins); the seen cache, the seen columns and 'device
// scan|discover|check' are device_scan.go.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerFamily(deviceCmd)
	// 'device <verb>' is deviceSpecs; 'device config <verb>' is
	// deviceConfigSpecs (device_config.go).
	registerSpecFunc("device", func(path []string) (Spec, bool) {
		switch {
		case len(path) == 3 && path[1] == "config":
			s, ok := deviceConfigSpecs[path[2]]
			return s, ok
		case len(path) == 2 && path[1] == "config":
			// A node of its own verbs: none of its flags is the node's.
			return Spec{}, false
		case len(path) == 2:
			s, ok := deviceSpecs[path[1]]
			return s, ok
		}
		return Spec{}, false
	})
	registerDeviceNames(deviceRegistryNames)
	shellHelpBlocks["device config"] = func(*invocation) string { return deviceConfigUsage() }
}

var (
	flagYes          = Flag{Names: []string{"-y", "--yes"}}
	flagJSON         = Flag{Names: []string{"--json"}}
	flagApply        = Flag{Names: []string{"--apply"}}
	flagAllowGeneric = Flag{Names: []string{"--allow-generic"}}
	flagAllNotices   = Flag{Names: []string{"--all"}}
	noticeWords      = strings.Join(devreg.AckableKinds, "|")
)

// deviceSpecs are the arguments of each verb, for the parser and for
// completion (args.go).
var deviceSpecs = map[string]Spec{
	"list": {MaxArgs: 1, Args: []string{""}, Flags: []Flag{{Names: []string{"--stale"}}, {Names: []string{"--unconfigured"}},
		{Names: []string{"--name"}, Value: true}, {Names: []string{"--ip"}, Value: true},
		{Names: []string{"--vendor"}, Value: true, Kind: KindVendors}, {Names: []string{"--scope"}, Value: true, Kind: KindScopes},
		{Names: []string{"--scan"}}, {Names: []string{"--probe"}}, flagJSON}},
	"show": {MinArgs: 1, MaxArgs: 1, Args: []string{KindDevices}, Flags: []Flag{flagJSON, flagAllNotices}},
	"add": {MinArgs: 1, MaxArgs: 2, Args: []string{"", ""}, Flags: []Flag{
		{Names: []string{"--vendor"}, Value: true, Kind: KindVendors},
		{Names: []string{"--hostname"}, Value: true},
		{Names: []string{"--port"}, Value: true},
		{Names: []string{"--description"}, Value: true},
		{Names: []string{"--snmp-location"}, Value: true},
		{Names: []string{"--legacy-ssh"}},
		{Names: []string{"--config-syntax"}, Value: true, Kind: "auto|ios12|modern"},
		{Names: []string{"--host-key"}, Value: true},
		{Names: []string{"--no-host-key"}},
		{Names: []string{"--no-lookup"}},
		{Names: []string{"--pull"}},
		flagAllowGeneric}},
	// 'onboard' (0.2.9, D136): a blank Junos device, as its local account.
	"onboard": {MinArgs: 1, MaxArgs: 1, Args: []string{""}, Flags: []Flag{
		{Names: []string{"--login"}, Value: true},
		{Names: []string{"--name"}, Value: true},
		{Names: []string{"--host-key"}, Value: true},
		{Names: []string{"--legacy-ssh"}},
		{Names: []string{"--check"}},
		{Names: []string{"--section"}, Value: true, Kind: strings.Join(planSections, "|") + KindList},
		flagJSON}},
	"remove":      {MaxArgs: -1, Args: []string{KindDevices + KindList}, Flags: []Flag{{Names: []string{"--all"}, Alone: true}, flagYes}},
	"rename":      {MinArgs: 2, MaxArgs: 2, Args: []string{KindDevices, ""}, Flags: []Flag{flagAllowGeneric}},
	"address":     {MinArgs: 1, MaxArgs: 2, Args: []string{KindDevices, ""}, Flags: []Flag{flagApply}},
	"hostname":    {MinArgs: 1, MaxArgs: 2, Args: []string{KindDevices, "clear"}},
	"vendor":      {MinArgs: 1, MaxArgs: 2, Args: []string{KindDevices, KindVendors + "|clear"}},
	"port":        {MinArgs: 1, MaxArgs: 2, Args: []string{KindDevices, "clear"}},
	"description": {MinArgs: 1, MaxArgs: -1, Args: []string{KindDevices, "clear"}, Flags: []Flag{flagApply}},
	"location":    {MinArgs: 1, MaxArgs: -1, Args: []string{KindDevices, "clear"}, Flags: []Flag{{Names: []string{"--from-device"}}, flagYes, flagApply}},
	"legacy-ssh":  {MinArgs: 1, MaxArgs: 2, Args: []string{KindDevices, "enable|disable"}},
	// The Cisco configuration syntax (D113).
	"config-syntax": {MinArgs: 1, MaxArgs: 2, Args: []string{KindDevices, "auto|ios12|modern"}, Flags: []Flag{flagApply}},
	"stale-days":    {MaxArgs: 1, Args: []string{""}},
	"notice":        {MinArgs: 3, MaxArgs: 3, Args: []string{KindDevices, "ack|unack", noticeWords}},
	"notices":       {MaxArgs: 1, Args: []string{KindDevices}, Flags: []Flag{flagAllNotices}},
	"import": {MinArgs: 1, MaxArgs: 1, Args: []string{KindFile}, Flags: []Flag{
		{Names: []string{"--check"}}, {Names: []string{"--replace"}}, flagAllowGeneric, flagYes}},
	"export":  {MaxArgs: 0, Flags: []Flag{{Names: []string{"--csv"}}, flagJSON}},
	"hostkey": {MinArgs: 1, MaxArgs: 3, Args: []string{KindDevices, "show|accept|set", ""}, Flags: []Flag{flagYes}},
	// 'device snmp' (D72) parses each verb with deviceSNMPSpecs; this is
	// the whole of it for completion.
	"snmp": deviceSNMPCompletion,
	// 'device block' parses each verb with deviceBlockSpecs.
	"block": deviceBlockCompletion,
	// 'device ssh' is 'tacctl ssh' (ssh.go); ssh-config is device_sshconfig.go.
	"ssh":        sshSpec,
	"ssh-config": {MaxArgs: 0},
	"scan": {MaxArgs: 0, Flags: []Flag{{Names: []string{"--full"}}, {Names: []string{"--since"}, Value: true},
		{Names: []string{"--backend"}, Value: true, Kind: KindBackends}}},
	"discover": {MaxArgs: 0, Flags: []Flag{{Names: []string{"--all"}}, {Names: []string{"--backend"}, Value: true, Kind: KindBackends}}},
	"check":    {MaxArgs: 1, Args: []string{KindDevices}, Flags: []Flag{{Names: []string{"--all"}, Alone: true}, flagJSON}},
	// 'device config show <name>' is device_config.go.
	"config": {MinArgs: 1, MaxArgs: 2, Args: []string{"show", KindDevices}, Flags: []Flag{
		{Names: []string{"--protocol"}, Value: true, Kind: "tacacs|radius"},
		{Names: []string{"--legacy"}},
		{Names: []string{"--server"}, Value: true},
		{Names: []string{"--source"}, Value: true}}},
}

// deviceVerbs are the verbs ({Use, Short}), in usage order.
var deviceVerbs = [][2]string{
	{"list [word] [--name <text>] [--ip <addr|cidr|text>] [--vendor <vendor>] [--scope <scope>] [--stale] [--unconfigured] [--scan] [--probe] [--json]", "Registered devices and enrolled hosts, by name: scope, state, last seen, notices; the options narrow the list"},
	{"show <name|address> [--all] [--json]", "One device or host in full (--all: the acknowledged notices too)"},
	{"add [<name>] <address> [options]", "Register a device (no name: offer the one it gives itself by SNMP)"},
	{"onboard <address> --login <local-user> [--name <name>] [--host-key SHA256:<fp>] [--legacy-ssh] [--check] [--section <list>] [--json]", "Superusers, Junos devices: register a blank device reached with one of its local accounts and commit its first configuration as that account, kept only after your own TACACS+ login proves it"},
	{"remove <name>[,<name>...] | --all [-y]", "Remove devices from the registry (confirms)"},
	{"rename <old> <new> [--allow-generic]", "Rename a device"},
	{"address <name> [<address>]", "Show or set the address (--apply: then run 'device config apply' for the device)"},
	{"hostname <name> [<dns>|clear]", "Show, set or clear the DNS name"},
	{"vendor <name> [cisco|juniper|wti|other]", "Show or set the vendor"},
	{"port <name> [<n>|clear]", "Show, set or clear the ssh port"},
	{"description <name> [<text>|clear]", "Show, set or clear the description (--apply: then run 'device config apply' for the device)"},
	{"location <name> [<text>|clear|--from-device [-y]]", "Show, set or clear the place, for the SNMP location in the walkthroughs (--from-device: read it from the device; --apply: then run 'device config apply' for the device)"},
	{"legacy-ssh <name> [enable|disable]", "Opt in to the legacy ssh algorithms (SHA-1 key exchange, CBC ciphers, ssh-rsa)"},
	{"config-syntax <name> [auto|ios12|modern]", "Show or set the Cisco configuration syntax (IOS 12.x or modern) of the walkthrough and the comparison (--apply: then run 'device config apply' for the device)"},
	{"stale-days [<n>]", "Show or set the days after which a device counts as stale"},
	{"notice <name> ack|unack <kind>", "Acknowledge or reopen a notice"},
	{"notices [<name>] [--all]", "The open notices, with what to do about each (--all: the acknowledged ones too)"},
	{"import [--check] [--replace] [--allow-generic] [-y] <file|->", "Import devices from CSV or the registry's YAML (an engineer: from standard input only, `-` first)"},
	{"export [--csv|--json]", "Print the registry (YAML by default)"},
	{"hostkey <name> [show|accept [-y]|set SHA256:<fp>]", "Show the pinned ssh host keys, or re-pin them after a verified change"},
	{deviceSNMPUse, "A device's own SNMP settings over its scope's: version, port, timeout, allowed clients and credentials, and where each comes from"},
	{deviceBlockUse, "A device's own configuration blocks (Junos snmp and system, IOS snmp) over its scope's: list, show, check, set, remove, edit, adopt"},
	{"ssh <name|address> [-p <port>] [-X|-Y] [-g] [-L|-R|-D <spec>]... [-- <ssh args>]", "Alias of 'tacctl ssh': a session to the device, as you"},
	{"ssh-config", "Print an ssh_config Include for your devices (Host blocks, pinned keys)"},
	{"scan [--full] [--since <dur>] [--backend <id>]", "Read the logs for the devices seen; re-scan pinned host keys"},
	{"discover [--all] [--backend <id>]", "Scan, then list the addresses that authenticated unregistered"},
	{"check <name>|--all [--json]", "Checklist: scope, tag, seen, reachable, host key, SNMP name and location"},
	{"config show <name> [--protocol tacacs|radius] [--legacy] [--server <address|name>] [--source <address>]", "The device's data, then its vendor walkthrough for its scope"},
	{"config pull <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> | --stale [options]", "Read the devices' configuration as you and compare the managed sections with what tacctl renders"},
	{"config diff <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> | --stale [--pull] [--section <list>] [--exit-code] [--json]", "The last pull against what tacctl renders now, section by section"},
	{"config plan <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> | --stale [--pull] [--section <list>] [--converge] [--secrets|--no-secrets] [--plain|--json|--backout] [--out <file>|--out-dir <dir>] [--force] [--from <address>] [--restore-point[=<fs>]] [--exit-code]", "What to paste (a WTI unit: what to type) to make each device match what tacctl renders: the report, the region or the steps, the check and the back-out"},
	{"config apply <name>[,<name>...] | --all | --scope <scope> | --vendor <vendor> | --stale [--check] [--confirmed] [--max <n>] [--pause <seconds>] [--hold] [--no-canary] [--section <list>] [--json] [-y]", "Superusers, Junos devices: check each device's plan on the device (--check stops there), then, after one review answered by typing the device's name or the number of devices back, commit it under a confirmed commit, prove it with a fresh login and the landed change, and confirm it"},
	{"config shapes [list [--show <hash>] [--json] | seed <name>[,<name>...] [-y]]", "Superusers: the shapes of the changes 'apply' has seen and which a verified apply confirmed; 'seed' files a device's shape as confirmed on your word"},
	{"config list [--stale] [--never] [--failed] [--differs] [--transport netconf|ssh|none] [--scope <scope>] [--vendor <vendor>] [--json]", "Each device's configuration state, when it was read, by whom and over what"},
	{"config forget <name>[,<name>...] | --all", "Delete the pull records (a pull makes them again)"},
}

// deviceOptions are the option lines under a verb's row in the usage, one
// per flag ({flag, description}), so the shell's '?' describes each.
var deviceOptions = map[string][][2]string{
	"list": {
		{"--stale", "Only the devices not seen for stale-days"},
		{"--unconfigured", "Only the devices no scope's prefixes cover"},
		{"--name <text>", "Only names containing the text (a comma list: any of them)"},
		{"--ip <addr|cidr|text>", "Only an address equal to, inside, or containing it (a comma list)"},
		// --vendor and --scope are described in the usage row: the shell's
		// help finds a flag's text by its name across the family, and 'add'
		// has its own --vendor line.
		{"--scan", "Scan the logs first (as 'device scan')"},
		{"--probe", "Add REACH: a TCP connect to each ssh port (3 s)"},
		{"--json", "(list, show, export, check) Print JSON"},
	},
	"add": {
		{"--vendor cisco|juniper|wti|other", "The vendor (default other)"},
		{"--hostname <dns>", "Its DNS name"},
		{"--port <n>", "Its ssh port (default 22)"},
		{"--description <text>", "A description"},
		{"--snmp-location <text>", "Its place (the SNMP location the walkthroughs render)"},
		{"--legacy-ssh", "SHA-1 key exchange, CBC ciphers and ssh-rsa; the configuration syntax is --config-syntax"},
		{"--config-syntax <syntax>", "(cisco) auto, ios12 or modern: the configuration syntax (default auto: the pull's version line says)"},
		{"--host-key SHA256:<fp>", "Register only if the device offers this key; pin it alone"},
		{"--no-host-key", "Register without a pinned key (a hostkey-unpinned notice)"},
		{"--no-lookup", "Do not read the device's own name and location by SNMP"},
		{"--pull", "After registering, read its configuration as 'device config pull' does (as you; needs a vendor and a scope)"},
		{"--allow-generic", "(add, rename, import) Allow a generic name such as 'switch'"},
	},
	"onboard": {
		{"--login <local-user>", "(onboard; config pull, diff --pull, plan --pull) The device's local account to log in as (any, a break-glass one included; root through its csh wrapper): its password is asked once on the terminal and never kept"},
		{"--name <name>", "The registry name (default: the name the device reports; a generic one is asked for)"},
		{"--check", "(onboard) Register, read and check the first-time plan on the device; commit nothing"},
	},
	"remove": {
		{"--all", "(remove, check) Every device; (show, notices) the acknowledged notices too"},
		{"-y, --yes", "(remove, import, hostkey, location) Answer yes to the confirmation"},
	},
	"location": {
		{"--from-device", "Read the location from the device (SNMP sysLocation) and store it"},
		{"--apply", "(address, description, location, config-syntax) After the change, run 'device config apply' for the device: the same review and confirmed commit; superusers, Junos devices"},
	},
	"import": {
		{"--check", "Write nothing; say what the import would do"},
		{"--replace", "Replace the registry instead of merging into it"},
	},
	"export": {
		{"--csv", "Print CSV instead of YAML"},
	},
	"snmp": deviceSNMPOptions,
	"block": {
		{"--effective", "(block show) The block as rendered for the device, with the layer each object is from"},
		{"--reveal", "(block show) Print the strings (an engineer: their own scopes' devices; logged)"},
		{"--file <path>", "(block check, set) The text to look at, read as you"},
		{"-y, --yes", "(block set, remove, edit, adopt) Answer yes to the question"},
		{"--against", "(block check) Plan the device with the text in force and print its section's statements"},
	},
	"ssh": {
		{"-p <port>", "Connect to this port instead of the registered one"},
		{"-X, -Y", "Forward X11 (untrusted, trusted) to this server's display"},
		{"-L <spec>", "Forward a local port, as ssh -L (repeatable)"},
		{"-R <spec>", "Forward a remote port, as ssh -R (repeatable)"},
		{"-D <spec>", "Open a SOCKS proxy, as ssh -D (repeatable)"},
		{"-g", "Let -L and -D ports listen on every address, as ssh -g"},
	},
	"scan": {
		{"--full", "Re-read everything the logs still hold"},
		{"--since <dur>", "Read this stretch of the logs (7d, 12h, 2w)"},
		{"--backend <id>", "(scan, discover) Only that backend's log"},
	},
	"discover": {
		{"--all", "Also list the addresses that were only refused"},
	},
	"config show": {
		{"--protocol tacacs|radius", "The protocol (default: the scope's auth-method, else its only protocol, else tacacs)"},
		{"--legacy", "(Cisco) The IOS 12.x syntax, whatever the device's config-syntax is; TACACS+ only"},
		{"--server <address|name>", "The address the device is told to authenticate against"},
		{"--source <address>", "The address this server reaches the device from"},
	},
	"config pull": {
		{"--all", "(pull, diff, plan, forget) Every device of yours that a scope covers"},
		{"--scope <scope>", "(pull, diff, plan, list) Only the devices of that scope"},
		{"--vendor cisco|juniper|wti", "(pull, diff, plan, list) Only that vendor's devices"},
		{"--stale", "(pull, diff, plan, list) Only the devices never read, last read in failure, or differing"},
		{"--transport auto|netconf|ssh", "(pull, diff, plan) NETCONF where the device answers (auto, default), NETCONF only, or the ssh command line only; (list) netconf, ssh or none: only the devices last read over that transport (none: never read)"},
		{"--concurrency <n>", "Read at most n devices at once (never above device.config.max_concurrency)"},
		{"--timeout <seconds>", "Per device, connect included (10-600; default device.config.timeout)"},
		{"--max-failures <n>", "Stop starting devices after n failures"},
		{"--diff", "Print the differences after the summary"},
		{"--server <address|name>", "The address the devices are told to authenticate against (not stored)"},
		{"--source <address>", "The address this server reaches the devices from (not stored)"},
		{"--login <local-user>", "(pull, diff --pull, plan --pull) Superusers, one registered Junos device with a pinned key: log in as that local account of the device instead of you (any local account, a break-glass one included; only root is handled apart: a device never read as you, through its csh wrapper); its password is asked once on the terminal and never kept or cached"},
		{"--json", "(pull, diff, plan, list) Print JSON (a pull: one line per device, then the summary)"},
	},
	"config diff": {
		{"--pull", "Read the devices first (takes the pull options)"},
		{"--section <list>", "Only these sections: aaa, roles, mgmt-acl, snmp, system, netconf, breakglass (a WTI unit has aaa, mgmt-acl, snmp and breakglass)"},
		{"--exit-code", "Exit 2 when a device differs (and none failed)"},
	},
	"config plan": {
		{"--pull", "Read the devices first (takes the pull options); the plan is made from that pull"},
		{"--section <list>", "Only these sections: aaa, roles, mgmt-acl, snmp, system (the report still names the others; a WTI unit has aaa, snmp and mgmt-acl)"},
		{"--converge", "Add the cleanup of a device with nothing else to paste: the region that removes the old servers and the like (a device with a first region gets that and a line to plan again after the paste; a WTI unit: the read/write community and the other protocol's switch)"},
		{"--secrets", "Type every secret of the planned sections, also the ones the device has (a WTI step names the command that shows the value unless given)"},
		{"--no-secrets", "Leave each secret as a marked line to fill in (no plain form; a WTI step already does)"},
		{"--plain", "The statements of one device alone, for 'load set' (--converge: two files, with --out or --out-dir); a WTI unit has none"},
		{"--json", "One object per device: the findings, the region, the cleanup and the back-out; values elided"},
		{"--backout", "Only the back-out region (what puts the pulled lines back; the one kept from the plan once a later pull replaced them; not with --pull)"},
		{"--out <file>", "Write one device's output to a file (0600)"},
		{"--out-dir <dir>", "One file per device (<name>.txt, .set with --plain, .json with --json; each plan's .backout.txt) and COVER.txt, 0600 in a 0700 directory"},
		{"--force", "Replace files --out or --out-dir would write"},
		{"--from <address>", "The address you are logged in from: the cleanup keeps it; the management filter check and a WTI unit's IP tables check use it"},
		{"--restore-point[=<fs>]", "(IOS and IOS-XE only) A restore point block before the plan: a copy of the running configuration on <fs> (flash:, bootflash:, disk0:), or, bare, 'archive config' where the pull read an archive path; the back-out names 'configure replace' with it; a file, not a timer (the bare form has not been checked on a device)"},
		{"--exit-code", "Exit 2 when a device needs a change (and none could not be planned)"},
	},
	"config apply": {
		{"--all", "(pull, diff, plan, apply, forget) Every device of yours that a scope covers"},
		{"--check", "Stop after the device's own commit check: nothing is committed, the device's shape is recorded"},
		{"--confirmed", "Apply only the shapes an earlier apply confirmed (the others are skipped), the one form --yes answers the review of"},
		{"--max <n>", "Apply at most n devices in one run (default 5; the rest are skipped, run it again)"},
		{"--pause <seconds>", "Wait between the devices after each shape's first, 0-3600 (default device.apply.pause)"},
		{"--hold", "After the fresh login keep the change only when you log in with one account of each class and type OK (needs a terminal)"},
		{"--no-canary", "Start every device of a shape at once, not the first alone"},
		{"--section <list>", "Only these sections: aaa, roles, mgmt-acl, snmp, system"},
		{"--json", "(apply) One object per device and phase, then the summary; the review goes to standard error"},
		{"--exit-code", "(apply) With --check: exit 2 when a device needs a change (and none failed)"},
		{"-y, --yes", "(apply) With --confirmed: answer the review (no terminal needed)"},
	},
	"config shapes": {
		{"--show <hash>", "(list) The statements of one shape, who confirmed it and the devices at it now"},
		{"-y, --yes", "(seed) Answer the question: mark the shape confirmed on your word"},
	},
	"config list": {
		{"--never", "Only the devices not pulled yet"},
		{"--failed", "Only the devices whose last pull failed"},
		{"--differs", "Only the devices that differ from what tacctl renders now"},
		{"--transport netconf|ssh|none", "Only the devices last read over that transport (none: never read)"},
	},
}

func deviceCmd(inv *invocation) *cobra.Command {
	c := verb("device <subcommand>", "Device registry: names, addresses and notices for the devices that authenticate here")
	c.RunE = inv.native(withPreflight, inv.device)
	// 'device config' has verbs of its own (show, pull, diff, list, forget):
	// its rows are the sub-commands of one node.
	var cfg *cobra.Command
	for _, v := range deviceVerbs {
		f := strings.Fields(v[0])
		word := f[0]
		if word == "config" && len(f) > 1 {
			if cfg == nil {
				cfg = verb("config <subcommand>", "A device's walkthrough, reading its configuration (pull, diff, list, forget), what to paste (plan) and writing it (apply, shapes)")
				cfg.RunE = inv.native(withPreflight, func(args []string) error {
					return inv.device(append([]string{"config"}, args...))
				})
				c.AddCommand(cfg)
			}
			sub := f[1]
			cfg.AddCommand(withRun(verb(strings.TrimPrefix(v[0], "config "), v[1]), inv.native(withPreflight, func(args []string) error {
				return inv.device(append([]string{"config", sub}, args...))
			})))
			continue
		}
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return inv.device(append([]string{word}, args...))
		})))
	}
	return c
}

// deviceOptKey is the key of a verb row's option lines in deviceOptions: its
// first word, and for a 'config' row the second as well.
func deviceOptKey(use string) string {
	f := strings.Fields(use)
	if f[0] == "config" && len(f) > 1 {
		return "config " + f[1]
	}
	return f[0]
}

// deviceRegUsage is the usage of the family.
func deviceRegUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Device Registry" + ui.NC + "\n\nUsage: tacctl device <subcommand> [arguments]\n\nSubcommands:\n")
	for _, v := range deviceVerbs {
		use, short := v[0], v[1]
		if len(use) > 56 {
			b.WriteString("  " + use + "\n  " + strings.Repeat(" ", 56) + "  " + short + "\n")
		} else {
			fmt.Fprintf(&b, "  %-56s  %s\n", use, short)
		}
		for _, o := range deviceOptions[deviceOptKey(use)] {
			fmt.Fprintf(&b, "      %-52s  %s\n", o[0], o[1])
		}
	}
	b.WriteString(`
Host keys: 'add' reads the device's ssh host keys (ssh-keyscan of the address
and port; for a legacy-ssh device that ssh-keyscan cannot read, tacctl's own
ssh client, which stops at the key and sends no password) and pins them; compare the fingerprints it prints with the device
console. --host-key SHA256:<fp> registers only when the device offers a key
with that fingerprint, and pins that key alone. --no-host-key registers without
a pinned key (a hostkey-unpinned notice). A device that does not answer is
refused unless --no-host-key is given. Only 'hostkey <name> accept' (re-scan,
confirm, pin) or 'hostkey <name> set SHA256:<fp>' changes a pin; 'tacctl ssh'
refuses a device whose key no longer matches.

Name hint: 'add' also reads the device's own name (SNMP sysName.0) and
compares it with the name given or its --hostname; a different one is a
warning, and the add goes ahead. A device that does not answer is added as
before; the NAS-Identifier a scan recorded for the address is shown instead
when there is one. 'add <address>' with no name offers the sysName,
lowercased, at a terminal ('y' to take it). --no-lookup skips the hint.
SNMP is set up with 'tacctl config snmp'; 'check' shows the sysName too.

Location: when no --snmp-location is given, 'add' also reads the device's own
location (SNMP sysLocation.0) and stores it, saying so. A device that reports
none gets one line with the command that sets it; at a terminal 'add' offers
to enter one (blank skips). A location the registry does not accept is shown
and not stored. 'check' compares the device's location with the registry's in
a Location row and writes nothing. 'location <name> --from-device' reads it
now and stores it: an empty answer is refused, and a different registered
location is shown beside the new one and asked about (-y answers yes).

Pulling: 'add --pull' registers the device and then runs 'config pull' for it,
as you (the pull's own output follows the add's). It needs --vendor cisco,
juniper or wti and the tier of 'config pull', and is refused before anything
is registered when they are missing. A device no scope covers is registered
and not pulled (the line says which commands to run); a failed pull leaves it
registered and the command returns the pull's status.

Configuration: 'config show <name>' prints the device's data (name, address,
hostname, vendor, the scope that covers it, description, location), then the
walkthrough 'tacctl config <vendor> --scope <its scope> --name <name>' prints,
with the device's own values in the SNMP step. Only cisco, juniper and wti
devices have one.

SNMP of its own: 'snmp <name>' gives one device a version, port, timeout,
allowed clients and credentials of its own, over its scope's ('tacctl scope
snmp') and the default's ('tacctl config snmp'): the device's value wins, then
the scope's, then the default's, then the built-in; 'snmp <name> show', 'show'
and 'check' say which one each value is, and a secret only as set or not
('snmp <name> show --reveal' prints it). A device's own list of allowed clients
replaces its scope's. The credentials are /etc/tacctl/snmp/devices/<name>.yaml
(0600); 'remove' deletes them and 'rename' moves them. Setting and clearing
are the superuser's; an engineer reads the devices of their own scopes.

Seen data: 'scan' reads each enabled backend's log (the tacquito journal,
FreeRADIUS's tacctl-auth.log) from where the last scan stopped into
/var/lib/tacctl/devices-seen.json, and re-scans the pinned host keys (a scan
never changes a pin). 'list' and 'show' read that cache only; 'list --scan'
scans first. --full re-reads everything the logs still hold, --since <dur>
(7d, 12h, 2w) that stretch. 'discover' lists the addresses that authenticated
without being registered, each with its 'device add' line (--all: those only
refused too). 'check' and 'list --probe' connect to each ssh port (3 s): this
server often has no path to management ports, so a timeout may be a false
alarm. Scans, discover and check are for the operator tier and up.

A device is found by name or by its registered address. A name is letters,
digits, '.', '_' and '-', at most 253 characters, each dotted part at most 63:
a fully qualified host name (sw1.site-a.example) is one. Enrolled Linux hosts
('tacctl host') are listed and found too, read-only. The registry is
/etc/tacctl/devices.yaml; scope and vendor tag are looked up, never stored.

Examples:
  tacctl device add core-sw1 10.99.0.1 --vendor cisco --no-host-key
  tacctl device list
  tacctl device scan
  tacctl device discover
  tacctl device rename core-sw1 dc1-core1
  tacctl device snmp core-sw1 community
  tacctl device snmp core-sw1 clients add 192.0.2.0/24
  tacctl device export --csv > devices.csv
  tacctl device ssh-config > ~/.ssh/tacctl.conf

`)
	return b.String()
}

// device dispatches: no sub-command, help, -h and --help are the usage
// (exit 0); anything else unknown is an error, then the usage (exit 1).
func (inv *invocation) device(args []string) error {
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	run := map[string]func([]string) error{
		"list": inv.deviceList, "show": inv.deviceShow, "add": inv.deviceAdd, "remove": inv.deviceRemove,
		"rename": inv.deviceRename, "legacy-ssh": inv.deviceLegacySSH, "config-syntax": inv.deviceConfigSyntax, "stale-days": inv.deviceStaleDays,
		"notice": inv.deviceNotice, "notices": inv.deviceNotices, "import": inv.deviceImport, "export": inv.deviceExport,
		"hostkey": inv.deviceHostkey, "onboard": inv.deviceOnboard, "snmp": inv.deviceSNMP, "block": inv.deviceBlock, "ssh": inv.ssh, "ssh-config": inv.deviceSSHConfig, "config": inv.deviceConfig,
		"scan": inv.deviceScan, "discover": inv.deviceDiscover, "check": inv.deviceCheck,
		"address": inv.deviceSetter("address"), "hostname": inv.deviceSetter("hostname"), "vendor": inv.deviceSetter("vendor"),
		"port": inv.deviceSetter("port"), "description": inv.deviceSetter("description"), "location": inv.deviceSetter("location"),
	}
	switch sub := arg(args, 0); sub {
	case "", "-h", "--help", "help":
		inv.write(deviceRegUsage())
		return nil
	default:
		if f, ok := run[sub]; ok {
			return f(rest)
		}
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(deviceRegUsage())
		return exit(1)
	}
}

// --- shared ----------------------------------------------------------------------

// deviceParse parses a verb's arguments with its Spec; a bad one is the
// error line and the verb's usage, exit 1.
func (inv *invocation) deviceParse(verbName string, args []string) (Parsed, error) {
	p, err := Parse(deviceSpecs[verbName], args)
	if err == nil {
		return p, nil
	}
	var use string
	for _, v := range deviceVerbs {
		// 'config' is five rows; this parse is the one of 'config show'.
		if f := strings.Fields(v[0]); f[0] == verbName && (verbName != "config" || (len(f) > 1 && f[1] == "show")) {
			use = v[0]
		}
	}
	msg := err.Error()
	var uf *UnknownFlagError
	if errors.As(err, &uf) {
		msg = "Unknown option: '" + uf.Flag + "'"
	}
	return p, inv.usageErr(msg, "Usage: tacctl device "+use)
}

func (inv *invocation) deviceFilter() devreg.ScopeFilter {
	f := inv.callerScopes()
	return devreg.ScopeFilter{Restricted: f.restricted, Scopes: f.scopes}
}

// deviceLoad reads the registry, the enrolled hosts and the store, and
// joins them.
func (inv *invocation) deviceLoad() (*devreg.File, *devreg.Resolver, error) {
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return nil, nil, err
	}
	reg, err := inv.registry()
	if err != nil {
		return nil, nil, err
	}
	m, err := inv.model()
	if err != nil {
		return nil, nil, err
	}
	res := devreg.NewResolver(f, reg, m)
	res.Seen = inv.seenLoad()
	return f, res, nil
}

// deviceWrite changes the registry: fn runs first on a copy, so every
// refusal comes before the snapshot; then, under the lock and after a
// snapshot of the current state, on the file itself. The resolver it
// returns is the state after the change. A caller the scope filter
// restricts (an engineer) may change only what is in their own scopes
// (deviceChangeScopes), checked on the copy and again on the file.
func (inv *invocation) deviceWrite(fn func(*devreg.File, *devreg.Resolver) error) (*devreg.Resolver, error) {
	f, res, err := inv.deviceLoad()
	if err != nil {
		return nil, err
	}
	scopes := inv.callerScopes()
	resolver := func(f *devreg.File) *devreg.Resolver {
		r := devreg.NewResolver(f, nil, res.Model)
		r.Hosts = res.Hosts
		return r
	}
	trial := f.Clone()
	after := resolver(trial)
	if err := fn(trial, after); err != nil {
		return nil, err
	}
	if err := inv.deviceChangeScopes(scopes, resolver(f), after); err != nil {
		return nil, err
	}
	if err := inv.snmpNewNamesFree(f, trial); err != nil {
		return nil, err
	}
	if err := inv.blocksNewNamesFree(f, trial); err != nil {
		return nil, err
	}
	if _, err := trial.Text(); err != nil {
		return nil, err
	}
	_, err = devreg.Mutate(inv.app.Paths.DevicesFile, inv.app.Paths.KnownHosts, inv.snapshotFirst, func(live *devreg.File) error {
		before := resolver(live.Clone())
		r := resolver(live)
		if err := fn(live, r); err != nil {
			return err
		}
		return inv.deviceChangeScopes(scopes, before, r)
	})
	if err == nil {
		// A device registered at, or moved to, its scope's prefixes ends
		// its staging address.
		inv.stagingSweep()
	}
	return after, err
}

// deviceChangeScopes is nil when a caller f restricts (an engineer) may
// make the change from before to after: every device or host record it
// adds, alters or removes is in one of their own scopes, where it was and
// where it is now (a device's scope is the one that answers its address,
// so a device moved to another scope's address is refused too), and the
// registry's own settings stay as they are. An unrestricted caller may
// make any change. The refusal is printed, exit 1.
func (inv *invocation) deviceChangeScopes(f scopeFilter, before, after *devreg.Resolver) error {
	if !f.restricted {
		return nil
	}
	bf, af := before.File, after.File
	if bf.StaleDays != af.StaleDays || !slices.Equal(bf.GenericNames, af.GenericNames) {
		return inv.usageErr("The registry's settings are not the engineer tier's to change. Nothing was changed.")
	}
	in := func(r *devreg.Resolver, name string) error {
		e, _ := r.Lookup(name, devreg.ScopeFilter{})
		if e.Scope == "" {
			return inv.usageErr("'" + name + "' is at an address no scope answers: the engineer tier registers devices at the addresses of its own scopes only. Nothing was changed.")
		}
		return inv.ownScope(f, e.Scope)
	}
	changed := func(name string, was, is any, wasThere, isThere bool) error {
		if wasThere && isThere && reflect.DeepEqual(was, is) {
			return nil
		}
		if wasThere {
			if err := in(before, name); err != nil {
				return err
			}
		}
		if isThere {
			return in(after, name)
		}
		return nil
	}
	seen := map[string]bool{}
	for _, d := range append(slices.Clone(bf.Devices), af.Devices...) {
		if key := strings.ToLower(d.Name); !seen[key] {
			seen[key] = true
			was, is := bf.Find(d.Name), af.Find(d.Name)
			// A device's SNMP settings are the superuser's to set (D72, D48):
			// an engineer's import or registration cannot carry them in or
			// change them. Removing a device, or renaming it (the same
			// address with the same settings under a new name), is not a
			// change of them.
			if is != nil && !is.SNMP.Empty() {
				switch {
				case was != nil && reflect.DeepEqual(was.SNMP, is.SNMP):
				case was == nil && slices.ContainsFunc(bf.Devices, func(o *devreg.Device) bool {
					return o.Address == is.Address && reflect.DeepEqual(o.SNMP, is.SNMP)
				}):
				default:
					return inv.usageErr("A device's SNMP settings are not the engineer tier's to change (tacctl device snmp is the superuser's); '" + d.Name + "' was not changed. Nothing was changed.")
				}
			} else if is != nil && was != nil && !was.SNMP.Empty() {
				return inv.usageErr("A device's SNMP settings are not the engineer tier's to change (tacctl device snmp is the superuser's); '" + d.Name + "' was not changed. Nothing was changed.")
			}
			if err := changed(d.Name, was, is, was != nil, is != nil); err != nil {
				return err
			}
		}
	}
	for _, h := range append(slices.Clone(bf.Hosts), af.Hosts...) {
		if key := "host " + h.Name; !seen[key] {
			seen[key] = true
			was, is := bf.Host(h.Name), af.Host(h.Name)
			if err := changed(h.Name, was, is, was != nil, is != nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// deviceFind finds the device a verb names (by name or address; hosts
// too) among what the caller may see.
func (inv *invocation) deviceFind(res *devreg.Resolver, key string) (devreg.Entry, error) {
	e, ok := res.Lookup(key, inv.deviceFilter())
	if !ok {
		return e, inv.usageErr("Device '" + key + "' not found. List them with: tacctl device list")
	}
	return e, nil
}

// deviceEditable is the registry device a write names: an enrolled host
// is refused, with where to change it. A device the caller may not see
// (another scope's, for an engineer) is not found.
func (inv *invocation) deviceEditable(res *devreg.Resolver, f *devreg.File, key string) (*devreg.Device, error) {
	d := f.Find(key)
	if d == nil {
		d = f.FindAddress(key)
	}
	if d != nil {
		if _, ok := res.Lookup(d.Name, inv.deviceFilter()); ok {
			return d, nil
		}
		return nil, inv.usageErr("Device '" + key + "' not found. List them with: tacctl device list")
	}
	// A host is not a device: an engineer, who reads hosts and deploys none
	// (host deployment is the superuser's), is told it is not found.
	if e, ok := res.NameTaken(key); ok && e.Source == devreg.SourceHost && !inv.callerScopes().restricted {
		return nil, inv.usageErr("'" + e.Name + "' is an enrolled host; 'tacctl host' manages it.")
	}
	return nil, inv.usageErr("Device '" + key + "' not found. List them with: tacctl device list")
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func kinds(ns []devreg.Notice) string {
	var k []string
	for _, n := range devreg.Open(ns) {
		k = append(k, n.Kind)
	}
	return strings.Join(k, ",")
}

// --- list and show ---------------------------------------------------------------

type deviceNoticeJSON struct {
	Kind  string `json:"kind"`
	Text  string `json:"text"`
	Acked bool   `json:"acked"`
}

type deviceJSON struct {
	Name      string `json:"name"`
	Source    string `json:"source"`
	Address   string `json:"address"`
	Hostname  string `json:"hostname,omitempty"`
	Vendor    string `json:"vendor"`
	Port      int    `json:"port"`
	LegacySSH bool   `json:"legacy_ssh"`
	// ConfigSyntax is the Cisco configuration syntax setting (auto, ios12
	// or modern; Cisco devices and devices that have one set only), Syntax
	// what it resolves to (ios12 or modern, from the setting or the last
	// pull; absent while unknown) and SyntaxSource where that comes from
	// (setting or pull). The resolution is part of the configuration state:
	// the caller who is not shown that state does not get it.
	// SyntaxConflict is set when the explicit setting is not the syntax the
	// last pull's version line (OS) derives to: the setting wins, and
	// ImageSyntax is what the line says.
	ConfigSyntax string `json:"config_syntax,omitempty"`
	// Applied is what 'device config apply' last did to the device (a
	// check or an apply), for the tiers that see the configuration state.
	Applied        *appliedJSON       `json:"applied,omitempty"`
	Syntax         string             `json:"syntax,omitempty"`
	SyntaxSource   string             `json:"syntax_source,omitempty"`
	SyntaxConflict bool               `json:"syntax_conflict,omitempty"`
	ImageSyntax    string             `json:"image_syntax,omitempty"`
	OS             string             `json:"os,omitempty"`
	Description    string             `json:"description,omitempty"`
	Location       string             `json:"location,omitempty"`
	Scope          string             `json:"scope"`
	Tag            string             `json:"tag"`
	Shadowed       []string           `json:"shadowed_by"`
	State          string             `json:"state"`
	HostKeys       []string           `json:"host_keys"`
	Notices        []deviceNoticeJSON `json:"notices"`
	Seen           *deviceSeenJSON    `json:"seen,omitempty"`
	// Config is the state of the configuration pull: ok, differs, never or
	// failed (none for a host and for a vendor that is not read).
	Config string `json:"config,omitempty"`
	// Release, Model and Serial are what the last good pull read from the
	// device about itself (read-only facts of the pull, shown to whoever is
	// shown Config; each is absent when the pull did not read it).
	Release string `json:"release,omitempty"`
	Model   string `json:"model,omitempty"`
	Serial  string `json:"serial,omitempty"`
	// SNMP is what the device is read with and where each value comes from
	// (D72); 'show' only, never a secret.
	SNMP *deviceSNMPJSON `json:"snmp,omitempty"`
	// Breakglass is the hold on the device ('tacctl breakglass'): present
	// while the server is told not to answer its address.
	Breakglass *deviceHoldJSON `json:"breakglass,omitempty"`
}

// deviceHoldJSON is the break-glass hold of a device as the displays give it.
type deviceHoldJSON struct {
	Held    bool   `json:"held"`
	Address string `json:"address"`
	Since   string `json:"since"`
	By      string `json:"by"`
	Reason  string `json:"reason"`
}

// deviceHoldOf is the hold of a registered device as JSON (nil when none).
func (inv *invocation) deviceHoldOf(e devreg.Entry) *deviceHoldJSON {
	if e.Source != devreg.SourceDevice {
		return nil
	}
	h, ok := inv.holdOf(e.Name, e.Address)
	if !ok {
		return nil
	}
	return &deviceHoldJSON{Held: true, Address: h.Address, Since: h.Since, By: h.By, Reason: h.Reason}
}

// holdRowText is the Break-glass row of 'device show' and the Scope row's
// note of 'device check'.
func (inv *invocation) holdRowText(h conf.Hold) string {
	return "HELD since " + holdTime(h) + " (" + holdAge(h, inv.app.Knobs.Now()) + ") by " + h.By + ": " + h.Reason +
		"; the server does not answer " + h.Address
}

// deviceSeenJSON is what the seen cache knows of an entry's address.
type deviceSeenJSON struct {
	First       string `json:"first"`
	Last        string `json:"last"`
	Count       int    `json:"count"`
	LastUser    string `json:"last_user"`
	LastOutcome string `json:"last_outcome"`
	Via         string `json:"via"`
	NASID       string `json:"nas_id"`
	Stale       bool   `json:"stale"`
}

// deviceJSONOf is one entry as JSON; recs are the configuration records of
// the pulls, nil when the caller is not shown them (a read-only user).
func deviceJSONOf(inv *invocation, res *devreg.Resolver, e devreg.Entry, recs *devconf.Records) deviceJSON {
	j := deviceJSON{Name: e.Name, Source: string(e.Source), Address: e.Address, Hostname: e.Hostname, Vendor: e.Vendor,
		Port: e.SSHPort(), LegacySSH: e.LegacySSH, Description: e.Description, Location: e.Location, Scope: e.Scope, Tag: e.Tag,
		Shadowed: append([]string{}, e.Shadowed...), State: e.State(), HostKeys: append([]string{}, e.HostKeys...),
		Notices: []deviceNoticeJSON{}}
	for _, n := range res.NoticesFor(e) {
		j.Notices = append(j.Notices, deviceNoticeJSON{Kind: n.Kind, Text: n.Text, Acked: n.Acked})
	}
	j.Seen = deviceSeenJSONOf(inv, res, e)
	j.Breakglass = inv.deviceHoldOf(e)
	if e.Source == devreg.SourceDevice && (e.Vendor == "cisco" || e.ConfigSyntax != "") {
		j.ConfigSyntax = devreg.SyntaxAuto
		if e.ConfigSyntax != "" {
			j.ConfigSyntax = e.ConfigSyntax
		}
	}
	if recs != nil {
		rec, _ := recs.Of(e.Name)
		if j.ConfigSyntax != "" {
			r := syntaxOf(e, rec)
			j.Syntax, j.SyntaxSource = r.Syntax, r.Source
			if rec != nil && e.Vendor == "cisco" {
				j.OS = cleanLine(rec.OS)
				if r.Conflict {
					j.SyntaxConflict, j.ImageSyntax = true, r.ImageSyntax
				}
			}
		}
		if st := inv.configStateOf(e, rec); st != "-" {
			j.Config = st
		}
		if rec != nil && e.Source == devreg.SourceDevice {
			j.Release, j.Model, j.Serial = cleanLine(rec.Release), cleanLine(rec.Model), cleanLine(rec.Serial)
			j.Applied = appliedJSONOf(rec.Applied)
		}
	}
	return j
}

// deviceSeenJSONOf is what the seen cache knows of e's address (nil when
// nothing).
func deviceSeenJSONOf(inv *invocation, res *devreg.Resolver, e devreg.Entry) *deviceSeenJSON {
	x, ok := res.Seen.Of(e.Address)
	if !ok || e.Address == "" {
		return nil
	}
	_, _, _, stale := deviceSeenCols(inv, res, e)
	const layout = "2006-01-02T15:04:05Z07:00"
	return &deviceSeenJSON{First: x.First.Format(layout), Last: x.Last.Format(layout), Count: x.Count,
		LastUser: x.LastUser, LastOutcome: x.LastOutcome, Via: x.Via, NASID: x.LastNASID, Stale: stale}
}

func (inv *invocation) printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	inv.write(string(b) + "\n")
	return nil
}

func (inv *invocation) deviceList(args []string) error {
	p, err := inv.deviceParse("list", args)
	if err != nil {
		return err
	}
	if (p.Has("--scan") || p.Has("--probe")) && !inv.scanAllowed() {
		return inv.usageErr("--scan and --probe are for the operator tier and up.")
	}
	var res *devreg.Resolver
	if p.Has("--scan") {
		sr, err := inv.runScan(scanRequest{})
		if err != nil {
			return err
		}
		if !p.Has("--json") {
			inv.printScan(sr)
		}
		res = sr.res
	} else if _, res, err = inv.deviceLoad(); err != nil {
		return err
	}
	var shown []devreg.Entry
	narrow := newDeviceListFilter(p)
	total := 0
	for _, e := range res.Visible(inv.deviceFilter()) {
		_, _, _, stale := deviceSeenCols(inv, res, e)
		if (p.Has("--unconfigured") && e.Configured) || (p.Has("--stale") && !stale) {
			continue
		}
		total++
		if !narrow.match(e) {
			continue
		}
		shown = append(shown, e)
	}
	sortEntriesByName(shown)
	// The configuration state is the operator tier's (D69): a read-only user
	// is not shown it, in the table or in the JSON.
	var configs *devconf.Records
	if inv.configVisible() {
		configs = inv.configRecords()
	}
	if p.Has("--json") {
		out := []deviceJSON{}
		for _, e := range shown {
			out = append(out, deviceJSONOf(inv, res, e, configs))
		}
		return inv.printJSON(out)
	}
	nd, nh := 0, 0
	for _, e := range shown {
		if e.Source == devreg.SourceHost {
			nh++
		} else {
			nd++
		}
	}
	head := fmt.Sprintf("Registered devices (%d) and enrolled hosts (%d)", nd, nh)
	if !narrow.empty() {
		head += fmt.Sprintf(", of %d", total)
	}
	inv.echo("")
	if len(shown) == 0 {
		inv.echoE(ui.Bold + head + ui.NC)
		inv.echo(ui.Rule(head))
		if narrow.empty() {
			inv.echo("  None. Register one with: tacctl device add <name> <address>")
		} else {
			inv.echo("  None match.")
		}
		inv.echo("")
		return nil
	}
	cols := []ui.Col{ui.Left("NAME"), ui.Left("ADDRESS"), ui.Left("VENDOR"), ui.Left("SCOPE"), ui.Left("STATE"), ui.Left("LAST SEEN"), ui.Left("BY"), ui.Left("VIA"), ui.Left("NOTICES")}
	if configs != nil {
		cols = slices.Insert(cols, 8, ui.Left("CONFIG"))
	}
	var reach []string
	if p.Has("--probe") {
		cols = slices.Insert(cols, len(cols)-1, ui.Left("REACH"))
		reach = inv.probeEntries(shown)
	}
	tb := ui.NewTable(head, cols...)
	open, held := 0, 0
	for i, e := range shown {
		last, by, via, stale := deviceSeenCols(inv, res, e)
		var state any = e.State()
		if stale {
			state = e.State() + " stale"
		}
		// A device the server has been told not to answer is marked, in
		// place of what the scopes would say of it.
		if e.Source == devreg.SourceDevice {
			if _, isHeld := inv.holdOf(e.Name, e.Address); isHeld {
				held++
				text := "BREAK-GLASS"
				if stale {
					text += " stale"
				}
				state = ui.Styled(ui.Red, text)
			}
		}
		ns := res.NoticesFor(e)
		open += len(devreg.Open(ns))
		row := []any{e.Name, dash(e.Address), e.Vendor, dash(e.Scope), state, last, by, via, dash(kinds(ns))}
		if configs != nil {
			rec, _ := configs.Of(e.Name)
			row = slices.Insert(row, 8, any(inv.configStateOf(e, rec)))
		}
		if reach != nil {
			row = slices.Insert(row, len(row)-1, any(reach[i]))
		}
		tb.Add(row...)
	}
	inv.write(tb.String())
	inv.echo("")
	inv.echo("  " + deviceSeenFooter(res))
	if reach != nil {
		inv.echo("  REACH: a TCP connect to the ssh port; this server often has no path to management ports, so a timeout may be a false alarm")
	}
	if open > 0 {
		inv.echo(fmt.Sprintf("  %d open notice(s): tacctl device notices", open))
	}
	if held > 0 {
		inv.echoE(fmt.Sprintf("  %s%d device(s) held for break-glass%s: tacctl breakglass list", ui.Red, held, ui.NC))
	}
	inv.echo("")
	return nil
}

func (inv *invocation) deviceShow(args []string) error {
	p, err := inv.deviceParse("show", args)
	if err != nil {
		return err
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, err := inv.deviceFind(res, p.Args[0])
	if err != nil {
		return err
	}
	if p.Has("--json") {
		var configs *devconf.Records
		if inv.configVisible() {
			configs = inv.configRecords()
		}
		j := deviceJSONOf(inv, res, e, configs)
		if e.Source == devreg.SourceDevice {
			if info, err := inv.deviceSNMPInfoOf(e); err == nil {
				j.SNMP = info.json()
			}
		}
		return inv.printJSON(j)
	}
	kind := "Device"
	if e.Source == devreg.SourceHost {
		kind = "Enrolled host"
	}
	inv.echo("")
	inv.echoE(ui.Bold + kind + " " + e.Name + ui.NC)
	inv.echo(ui.Rule(kind + " " + e.Name))
	row := func(k, v string) {
		if k != "" {
			k += ":"
		}
		inv.write(fmt.Sprintf("  %-13s %s\n", k, v))
	}
	row("Name", e.Name)
	row("Address", dash(e.Address))
	row("Hostname", dash(e.Hostname))
	row("Vendor", e.Vendor)
	row("Port", strconv.Itoa(e.SSHPort()))
	if e.Source == devreg.SourceHost {
		row("Target", e.Target)
		row("Identity", dash(e.Identity))
	} else {
		row("Legacy ssh", map[bool]string{true: "enabled", false: "disabled"}[e.LegacySSH])
		if e.Vendor == "cisco" || e.ConfigSyntax != "" {
			row("Config syntax", inv.configSyntaxText(e))
		}
		row("Description", dash(e.Description))
		row("Location", dash(e.Location))
	}
	switch {
	case e.Source == devreg.SourceHost && e.Configured:
		row("Scope", e.Scope)
	case e.Source == devreg.SourceHost:
		row("Scope", dash(e.Scope)+"  (no such scope)")
	case e.Configured:
		row("Scope", e.Scope+"  (via prefix "+e.Prefix+")")
	default:
		row("Scope", "-  (no scope's prefixes cover "+e.Address+")")
	}
	if len(e.Shadowed) > 0 {
		row("Shadowed", "also covered by "+strings.Join(e.Shadowed, ", ")+" (the more specific prefix wins)")
	}
	row("State", e.State())
	if h := inv.deviceHoldOf(e); h != nil {
		hold, _ := inv.holdOf(e.Name, e.Address)
		row("Break-glass", ui.Red+inv.holdRowText(hold)+ui.NC)
	}
	if e.Source == devreg.SourceDevice {
		switch {
		case e.Tag != "":
			row("Vendor tag", e.Tag)
		case slices.Contains(sortedVendors(), e.Vendor) && e.Configured:
			row("Vendor tag", "none  (over RADIUS: tacctl scope devices "+e.Scope+" set "+e.Address+" "+e.Vendor+")")
		default:
			row("Vendor tag", "none")
		}
		if e.Tag != "" && e.Vendor != devreg.VendorOther && e.Tag != e.Vendor {
			inv.app.Out.Warn("The vendor tag (" + e.Tag + ") and the registered vendor (" + e.Vendor + ") disagree.")
		}
	}
	if keys := devreg.ParseHostKeys(e.HostKeys); len(keys) == 0 {
		row("Host keys", "none pinned")
	} else {
		for i, k := range keys {
			row(map[bool]string{true: "Host keys", false: ""}[i == 0], k.Display())
		}
	}
	last, by, via, stale := deviceSeenCols(inv, res, e)
	if stale {
		last += "  (stale: older than " + strconv.Itoa(res.File.StaleDays) + " days)"
	}
	row("Last seen", last)
	if by != "-" || via != "-" {
		row("Seen by", by+" via "+via)
	}
	if x, ok := res.Seen.Of(e.Address); ok && e.Address != "" {
		row("First seen", seenTime(x.First)+"  ("+howMany(x.Count, "sighting")+")")
		if x.LastNASID != "" {
			row("Identifies", "as '"+x.LastNASID+"' (NAS-Identifier)")
		}
	}
	if e.Source == devreg.SourceDevice {
		inv.deviceSNMPRows(e, row)
	}
	if e.Source == devreg.SourceDevice && slices.Contains(sortedVendors(), e.Vendor) && inv.configVisible() {
		rec, _ := inv.configRecords().Of(e.Name)
		row("Configuration", configBlock(e, rec))
		// What the device reported of itself at that pull (facts.go); a row
		// the pull did not read is not shown.
		if rec != nil {
			for _, f := range [][2]string{{"Release", rec.Release}, {"Model", rec.Model}, {"Serial", rec.Serial}} {
				if v := cleanLine(f[1]); v != "" {
					row(f[0], v)
				}
			}
		}
	}
	ns := res.NoticesFor(e)
	acked := len(ns) - len(devreg.Open(ns))
	if !p.Has("--all") {
		ns = devreg.Open(ns)
	}
	hidden := ""
	if acked > 0 && !p.Has("--all") {
		hidden = howMany(acked, "acknowledged notice") + " not shown: tacctl device show " + e.Name + " --all"
	}
	if len(ns) == 0 && hidden != "" {
		row("Notices", "none open; "+hidden)
		hidden = ""
	} else if len(ns) == 0 {
		row("Notices", "none")
	}
	for i, n := range ns {
		k := "Notices"
		if i > 0 {
			k = ""
		}
		mark := ""
		if n.Acked {
			mark = " (acknowledged)"
		}
		row(k, n.Kind+mark+": "+n.Text)
	}
	if hidden != "" {
		row("", hidden)
	}
	inv.echo("")
	return nil
}

// retyped is the command line prefix args, as the user typed it (each
// word quoted for the shell where it needs it), without the value flag
// drop and with the switch add once at the end: the command a refusal
// suggests keeps every other flag.
func retyped(prefix string, args []string, drop, add string) string {
	words := []string{prefix}
	for i := 0; i < len(args); i++ {
		w := args[i]
		switch {
		case w == drop:
			i++
			continue
		case strings.HasPrefix(w, drop+"="), w == add:
			continue
		}
		words = append(words, shellquote.Q(w))
	}
	return strings.Join(append(words, add), " ")
}

func sortedVendors() []string { return []string{"cisco", "juniper", "wti"} }

// --- add -------------------------------------------------------------------------

func (inv *invocation) deviceAdd(args []string) error { return inv.deviceAddWith(args, nil) }

// deviceAddWith is 'device add'. trusted, when not nil, are host keys the
// caller already scanned and the person trusted ('device onboard', D136):
// they are pinned instead of a new scan, so that what is pinned is exactly
// what was shown. Every registration goes through here.
func (inv *invocation) deviceAddWith(args []string, trusted []devreg.HostKey) error {
	p, err := inv.deviceParse("add", args)
	if err != nil {
		return err
	}
	// The device's own name, read next to the host-key scan; with no name
	// given it is read first, and offered.
	if err := inv.deviceAddPullCheck(p); err != nil {
		return err
	}
	hint := make(chan nameHint, 1)
	if len(p.Args) == 1 {
		name, h, err := inv.deviceAddOffered(p, "Usage: tacctl device add [<name>] <address> [options]")
		if err != nil || name == "" {
			return err
		}
		p.Args = []string{name, p.Args[0]}
		args = append([]string{name}, args...)
		hint <- h
	}
	d := devreg.Device{Name: p.Args[0], Vendor: devreg.VendorOther, LegacySSH: p.Has("--legacy-ssh")}
	checks := []error{devreg.ValidateName(d.Name)}
	if p.Has("--config-syntax") {
		var serr error
		d.ConfigSyntax, serr = devreg.ValidateConfigSyntax(p.Value("--config-syntax"))
		checks = append(checks, serr)
	}
	if d.Address, err = devreg.NormalizeAddress(p.Args[1]); err != nil {
		checks = append(checks, err)
	}
	if p.Has("--vendor") {
		d.Vendor = strings.ToLower(p.Value("--vendor"))
		checks = append(checks, devreg.ValidateVendor(d.Vendor))
	}
	if p.Has("--port") {
		var perr error
		d.Port, perr = devreg.ValidatePort(p.Value("--port"))
		checks = append(checks, perr)
	}
	if p.Has("--hostname") {
		d.Hostname = p.Value("--hostname")
		checks = append(checks, devreg.ValidateHostname(d.Hostname))
	}
	d.Description = p.Value("--description")
	checks = append(checks, devreg.ValidateNewDescription(d.Description))
	if p.Has("--snmp-location") {
		d.Location = p.Value("--snmp-location")
		checks = append(checks, devreg.ValidateLocation(d.Location))
	}
	for _, e := range checks {
		if e != nil {
			return e
		}
	}
	if d.ConfigSyntax != "" && d.Vendor != "cisco" {
		return inv.usageErr("--config-syntax is the Cisco configuration syntax; give --vendor cisco.")
	}
	if p.Has("--host-key") && p.Has("--no-host-key") {
		return inv.usageErr("Give --host-key or --no-host-key, not both.")
	}
	if fp := p.Value("--host-key"); p.Has("--host-key") && !devreg.ValidFingerprint(fp) {
		return inv.usageErr("Invalid --host-key '" + fp + "': expected SHA256:<fingerprint> as ssh prints it.")
	}
	keep := retyped("tacctl device add", args, "--host-key", "--allow-generic")
	check := func(r *devreg.Resolver) error {
		if err := r.CheckName(d.Name, d.Vendor, p.Has("--allow-generic"), keep); err != nil {
			return err
		}
		return r.CheckAddress(d.Address, "")
	}
	// The refusals that need no device come before the scan.
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	if err := check(res); err != nil {
		return err
	}
	lookup := !p.Has("--no-lookup")
	if lookup && len(hint) == 0 {
		go func() { hint <- inv.lookupNameHint(d.Address) }()
	}
	// The device's own location, read alongside, unless one was given.
	var locCh chan locRead
	if lookup && !p.Has("--snmp-location") {
		locCh = make(chan locRead, 1)
		go func() { locCh <- inv.readLocation(d.Address) }()
	}
	retry := retyped("tacctl device add", args, "--host-key", "--no-host-key")
	pin, offered, err := inv.deviceAddKeys(d, p, retry, trusted)
	if err != nil {
		return err
	}
	d.HostKeys = devreg.KeyStrings(pin)
	var loc locRead
	stored := false
	if locCh != nil {
		loc = <-locCh
		if ok, _ := loc.storable(); ok {
			d.Location, stored = loc.text, true
		}
	}
	after, err := inv.deviceWrite(func(f *devreg.File, r *devreg.Resolver) error {
		if err := check(r); err != nil {
			return err
		}
		nd := d.Clone()
		f.Devices = append(f.Devices, &nd)
		return nil
	})
	if err != nil {
		return err
	}
	a := inv.app
	a.Out.Info("Device '" + d.Name + "' registered: " + d.Address + ", " + d.Vendor + ".")
	if lookup {
		inv.printNameHint(d, <-hint)
	}
	inv.deviceAddReport(d, p, pin, offered)
	e, _ := after.Lookup(d.Name, devreg.ScopeFilter{})
	if e.Configured {
		inv.echo("  Scope: " + e.Scope + " (via prefix " + e.Prefix + ")")
	} else {
		inv.echo("  Scope: none yet; no scope's prefixes cover " + d.Address + " ('tacctl scope prefixes <scope> add <cidr>').")
	}
	if locCh != nil {
		inv.printLocation(d, loc, stored)
	}
	for _, n := range devreg.Open(after.NoticesFor(e)) {
		a.Out.Warn(n.Kind + ": " + n.Text)
	}
	inv.echo("")
	if !p.Has("--pull") {
		return nil
	}
	// --pull: the pull verb for this one device, as the caller; a device no
	// scope covers is not read (the pull would refuse it).
	if !e.Configured {
		inv.echo("Not pulled: no scope's prefixes cover " + d.Address + ". Add them with 'tacctl scope prefixes <scope> add <cidr>', then run 'tacctl device config pull " + d.Name + "'.")
		inv.echo("")
		return nil
	}
	return inv.deviceConfigPull([]string{d.Name})
}

// deviceAddPullCheck is the refusal of --pull that needs no device, made
// before anything is registered: the caller's tier, the account the pull
// logs in as, and a vendor the pull reads.
func (inv *invocation) deviceAddPullCheck(p Parsed) error {
	if !p.Has("--pull") {
		return nil
	}
	if t, ok := inv.deviceConfigPermits("pull"); !ok {
		return inv.usageErr("--pull runs 'tacctl device config pull', which is not permitted for the " + string(t) + " tier.")
	}
	if _, err := inv.configLogin("device add --pull"); err != nil {
		return err
	}
	if !slices.Contains(sortedVendors(), strings.ToLower(p.Value("--vendor"))) {
		return inv.usageErr("--pull reads the configuration, which needs --vendor cisco, juniper or wti.")
	}
	return nil
}

// --- remove and rename -----------------------------------------------------------

func (inv *invocation) deviceRemove(args []string) error {
	p, err := inv.deviceParse("remove", args)
	if err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	var targets []string
	switch {
	case p.Has("--all") && len(p.Args) > 0:
		return inv.usageErr("--all takes no names.", "Usage: tacctl device remove <name>[,<name>...] | --all [-y]")
	case p.Has("--all"):
		// The caller's devices: every one, or an engineer's own scopes'.
		for _, e := range res.Visible(inv.deviceFilter()) {
			if e.Source == devreg.SourceDevice {
				targets = append(targets, e.Name)
			}
		}
		if len(targets) == 0 {
			inv.app.Out.Info("The registry is empty.")
			return nil
		}
	case len(p.Args) == 0:
		return inv.usageErr("Usage: tacctl device remove <name>[,<name>...] | --all [-y]")
	default:
		for _, a := range p.Args {
			for _, n := range strings.Split(a, ",") {
				if n == "" {
					continue
				}
				d, err := inv.deviceEditable(res, f, n)
				if err != nil {
					return err
				}
				if !slices.Contains(targets, d.Name) {
					targets = append(targets, d.Name)
				}
			}
		}
	}
	// A record without its device would silence an address nobody can find.
	var heldTargets, rel []string
	for _, n := range targets {
		if d := f.Find(n); d != nil && inv.isHeld(n, d.Address) {
			heldTargets = append(heldTargets, n)
			rel = append(rel, "tacctl breakglass release "+n)
		}
	}
	if len(heldTargets) > 0 {
		return inv.usageErr("break-glass is held on " + strings.Join(heldTargets, ", ") + ": release it first (" + strings.Join(rel, "; ") + "). Nothing was changed.")
	}
	a := inv.app
	a.Out.Warn(fmt.Sprintf("About to remove %d device(s) from the registry: %s.", len(targets), strings.Join(targets, ", ")))
	a.Out.Warn("Enrolled hosts, scopes and vendor tags are not touched.")
	if note := inv.deviceBlocksRemovalNote(targets); note != "" {
		a.Out.Warn(note)
	}
	if !p.Has("-y") && !a.Prompter().ConfirmPrefix("  Confirm removal? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		for _, n := range targets {
			f.Remove(n)
		}
		return nil
	}); err != nil {
		return err
	}
	for _, n := range targets {
		inv.configCarry(n, "")
		inv.snmpDeviceCarry(n, "")
		inv.blocksDeviceCarry(n, "")
	}
	a.Out.Info(fmt.Sprintf("Removed %d device(s).", len(targets)))
	inv.echo("")
	return nil
}

func (inv *invocation) deviceRename(args []string) error {
	p, err := inv.deviceParse("rename", args)
	if err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	old, err := inv.deviceEditable(res, f, p.Args[0])
	if err != nil {
		return err
	}
	oldName, newName := old.Name, p.Args[1]
	if err := devreg.ValidateName(newName); err != nil {
		return err
	}
	keep := "tacctl device rename " + oldName + " " + newName + " --allow-generic"
	if _, err := inv.deviceWrite(func(f *devreg.File, r *devreg.Resolver) error {
		d := f.Find(oldName)
		if d == nil {
			return inv.usageErr("Device '" + oldName + "' not found.")
		}
		// Changing only the spelling of a name is a rename too.
		if !strings.EqualFold(oldName, newName) {
			if err := r.CheckName(newName, d.Vendor, p.Has("--allow-generic"), keep); err != nil {
				return err
			}
		} else if oldName == newName {
			return inv.usageErr("'" + oldName + "' already has that name.")
		}
		d.Name = newName
		return nil
	}); err != nil {
		return err
	}
	inv.configCarry(oldName, newName)
	inv.snmpDeviceCarry(oldName, newName)
	inv.blocksDeviceCarry(oldName, newName)
	inv.holdCarry(oldName, newName, old.Address)
	inv.app.Out.Info("Device '" + oldName + "' renamed to '" + newName + "'.")
	inv.app.Out.Info("The device's own host name is unchanged: tacctl does not plan it.")
	inv.echo("")
	return nil
}

// --- scalar setters ---------------------------------------------------------------

// deviceSetter is the getter/setter of one field: no value shows it, 'clear'
// unsets an optional one, anything else sets it.
func (inv *invocation) deviceSetter(field string) func([]string) error {
	return func(args []string) error {
		p, err := inv.deviceParse(field, args)
		if err != nil {
			return err
		}
		f, res, err := inv.deviceLoad()
		if err != nil {
			return err
		}
		applyReq := p.Has("--apply")
		switch {
		case applyReq && field == "location" && p.Has("--from-device"):
			return inv.usageErr("--apply goes with a value to set: --from-device stores what the device reports, so there is nothing to apply.")
		case applyReq && len(p.Args) == 1:
			return inv.usageErr("--apply goes with a value to set: tacctl device " + field + " <name> <value> --apply")
		}
		if field == "location" && (p.Has("--from-device") || p.Has("-y")) {
			return inv.deviceLocationFromDevice(p, f, res)
		}
		if len(p.Args) == 1 {
			e, err := inv.deviceFind(res, p.Args[0])
			if err != nil {
				return err
			}
			inv.echo(map[string]string{
				"address": dash(e.Address), "hostname": dash(e.Hostname), "vendor": e.Vendor,
				"port": strconv.Itoa(e.SSHPort()), "description": dash(e.Description), "location": dash(e.Location),
			}[field])
			return nil
		}
		d, err := inv.deviceEditable(res, f, p.Args[0])
		if err != nil {
			return err
		}
		name := d.Name
		// The hold is on the address the server sees: moving the device
		// would leave the old address silenced and the new one answered.
		if field == "address" {
			if inv.isHeld(name, d.Address) {
				return inv.usageErr("break-glass is held on " + name + ": release it first (tacctl breakglass release " + name + "). Nothing was changed.")
			}
		}
		value := strings.Join(p.Args[1:], " ")
		if field != "description" && field != "location" && len(p.Args) > 2 {
			return inv.usageErr("Usage: tacctl device " + field + " <name> [<value>|clear]")
		}
		clearing := value == "clear" || (field == "location" && value == "")
		set := func(d *devreg.Device) error { return setField(d, field, value, clearing) }
		// Validate before the snapshot, on a copy.
		probe := d.Clone()
		if err := set(&probe); err != nil {
			return err
		}
		// A configuration syntax setting is a Cisco setting: it goes with
		// the vendor, and the message says which one went.
		droppedSyntax := d.ConfigSyntax != "" && probe.ConfigSyntax == ""
		changed := fieldValue(d, field) != fieldValue(&probe, field)
		if applyReq && changed {
			e, err := inv.deviceFind(res, name)
			if err != nil {
				return err
			}
			if err := inv.applyPreflight(e); err != nil {
				return err
			}
		}
		warnKeys := false
		if _, err := inv.deviceWrite(func(f *devreg.File, r *devreg.Resolver) error {
			live := f.Find(name)
			if live == nil {
				return inv.usageErr("Device '" + name + "' not found.")
			}
			if field == "address" && !clearing {
				a, _ := devreg.NormalizeAddress(value)
				if err := r.CheckAddress(a, name); err != nil {
					return err
				}
			}
			if err := set(live); err != nil {
				return err
			}
			if field == "address" {
				warnKeys = len(d.HostKeys) > 0 && live.Address != d.Address
				if live.Address != d.Address {
					live.HostKeys = nil
				}
			}
			return nil
		}); err != nil {
			return err
		}
		verbText := "set to " + value
		if clearing {
			verbText = "cleared"
		}
		inv.app.Out.Info("Device '" + name + "' " + field + " " + verbText + ".")
		if warnKeys {
			inv.app.Out.Warn("The pinned host keys belonged to the old address and were dropped.")
		}
		if droppedSyntax {
			inv.app.Out.Warn("The configuration syntax setting (" + d.ConfigSyntax + ") was removed: it is a Cisco setting.")
		}
		return inv.afterSetter(name, field, changed, applyReq)
	}
}

// fieldValue is the value a setter's field holds, to tell whether a set
// changed it.
func fieldValue(d *devreg.Device, field string) string {
	switch field {
	case "address":
		return d.Address
	case "hostname":
		return d.Hostname
	case "vendor":
		return d.Vendor
	case "port":
		return strconv.Itoa(d.Port)
	case "description":
		return d.Description
	case "location":
		return d.Location
	case "config-syntax":
		return d.ConfigSyntax
	}
	return ""
}

// afterSetter is what follows a setter that stored its value: --apply runs
// 'device config apply' for the device (the exit status is the apply's),
// otherwise a field that is rendered says, when the stored pull would now
// change, how to look at it. A set that changed nothing does neither.
func (inv *invocation) afterSetter(name, field string, changed, applyReq bool) error {
	switch {
	case !changed && applyReq:
		inv.app.Out.Info("Nothing changed, so nothing was applied.")
	case changed && applyReq:
		inv.app.Out.Info("Applying it to the device: tacctl device config apply " + name)
		return inv.deviceConfigApply([]string{name})
	case changed && rendersField(field):
		inv.configNudge(name)
	}
	return nil
}

func setField(d *devreg.Device, field, value string, clearing bool) error {
	switch field {
	case "address":
		if clearing {
			return fail1("The address is required; to drop the device: tacctl device remove " + d.Name)
		}
		a, err := devreg.NormalizeAddress(value)
		if err != nil {
			return err
		}
		d.Address = a
	case "hostname":
		d.Hostname = ""
		if !clearing {
			d.Hostname = value
			return devreg.ValidateHostname(value)
		}
	case "vendor":
		d.Vendor = devreg.VendorOther
		if !clearing {
			d.Vendor = strings.ToLower(value)
			if err := devreg.ValidateVendor(d.Vendor); err != nil {
				return err
			}
		}
		// The configuration syntax is a Cisco setting: a device that stops
		// being one does not keep it (the registry refuses the pair).
		if d.Vendor != "cisco" {
			d.ConfigSyntax = ""
		}
	case "port":
		d.Port = 0
		if !clearing {
			n, err := devreg.ValidatePort(value)
			d.Port = n
			return err
		}
	case "description":
		d.Description = ""
		if !clearing {
			d.Description = value
			return devreg.ValidateNewDescription(value)
		}
	case "location":
		d.Location = ""
		if !clearing {
			d.Location = value
			return devreg.ValidateLocation(value)
		}
	}
	return nil
}

func fail1(msg string) error { return &ExitError{Code: 1, Err: errors.New(msg)} }

func (inv *invocation) deviceLegacySSH(args []string) error {
	p, err := inv.deviceParse("legacy-ssh", args)
	if err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	if len(p.Args) == 1 {
		e, err := inv.deviceFind(res, p.Args[0])
		if err != nil {
			return err
		}
		inv.echo(map[bool]string{true: "enabled", false: "disabled"}[e.LegacySSH])
		return nil
	}
	on := p.Args[1] == "enable"
	if !on && p.Args[1] != "disable" {
		return inv.usageErr("Usage: tacctl device legacy-ssh <name> [enable|disable]")
	}
	d, err := inv.deviceEditable(res, f, p.Args[0])
	if err != nil {
		return err
	}
	name := d.Name
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		f.Find(name).LegacySSH = on
		return nil
	}); err != nil {
		return err
	}
	inv.app.Out.Info("Device '" + name + "' legacy-ssh " + p.Args[1] + "d.")
	return nil
}

func (inv *invocation) deviceStaleDays(args []string) error {
	p, err := inv.deviceParse("stale-days", args)
	if err != nil {
		return err
	}
	f, _, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	if len(p.Args) == 0 {
		inv.echo(strconv.Itoa(f.StaleDays))
		return nil
	}
	n, err := strconv.Atoi(p.Args[0])
	if err != nil || n < 1 || n > devreg.MaxStaleDays || strconv.Itoa(n) != p.Args[0] {
		return inv.usageErr("Invalid number of days '" + p.Args[0] + "': expected 1-" + strconv.Itoa(devreg.MaxStaleDays) + ".")
	}
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error { f.StaleDays = n; return nil }); err != nil {
		return err
	}
	inv.app.Out.Info("Devices count as stale after " + p.Args[0] + " day(s) without a sighting.")
	return nil
}

// --- notices ---------------------------------------------------------------------

func (inv *invocation) deviceNotice(args []string) error {
	p, err := inv.deviceParse("notice", args)
	if err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	action, kind := p.Args[1], p.Args[2]
	if action != "ack" && action != "unack" {
		return inv.usageErr("Usage: tacctl device notice <name> ack|unack <kind>")
	}
	if kind == devreg.NoticeHostKeyChanged {
		return inv.usageErr("'" + kind + "' cannot be acknowledged: it stays until the host key is verified and pinned again.")
	}
	if !slices.Contains(devreg.AckableKinds, kind) {
		return inv.usageErr("Unknown notice kind '"+kind+"'.", "Kinds: "+strings.Join(devreg.AckableKinds, ", ")+".")
	}
	if e, ok := res.Lookup(p.Args[0], inv.deviceFilter()); ok && e.Source == devreg.SourceHost {
		return inv.hostNotice(e, action, kind)
	}
	d, err := inv.deviceEditable(res, f, p.Args[0])
	if err != nil {
		return err
	}
	name := d.Name
	had := slices.Contains(d.Ack, kind)
	if (action == "ack") == had {
		inv.app.Out.Info("Notice '" + kind + "' of '" + name + "' is " + map[bool]string{true: "already", false: "not"}[had] + " acknowledged.")
		return nil
	}
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		live := f.Find(name)
		if action == "ack" {
			live.Ack = append(live.Ack, kind)
		} else {
			live.Ack = slices.DeleteFunc(live.Ack, func(k string) bool { return k == kind })
		}
		return nil
	}); err != nil {
		return err
	}
	inv.app.Out.Info("Notice '" + kind + "' of '" + name + "' " + map[string]string{"ack": "acknowledged", "unack": "reopened"}[action] + ".")
	return nil
}

// hostNotice acknowledges or reopens a notice of the enrolled host e: only
// the kinds an enrolled host may acknowledge (its other notices are
// cleared on the host).
func (inv *invocation) hostNotice(e devreg.Entry, action, kind string) error {
	if !slices.Contains(devreg.HostAckableKinds, kind) {
		return inv.usageErr("'"+e.Name+"' is an enrolled host; its '"+kind+"' notice is cleared on the host, not acknowledged.",
			"An enrolled host can acknowledge: "+strings.Join(devreg.HostAckableKinds, ", ")+".")
	}
	name := e.Name
	had := slices.Contains(e.Ack, kind)
	if (action == "ack") == had {
		inv.app.Out.Info("Notice '" + kind + "' of '" + name + "' is " + map[bool]string{true: "already", false: "not"}[had] + " acknowledged.")
		return nil
	}
	if action == "ack" && kind == devreg.NoticeAddressChanged && e.PrevAddress == "" {
		return inv.usageErr("'" + name + "' has no " + kind + " notice.")
	}
	if _, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		h := f.Host(name)
		if h == nil {
			return inv.usageErr("'" + name + "' has no " + kind + " notice.")
		}
		if action == "ack" {
			h.Ack = append(h.Ack, kind)
		} else {
			h.Ack = slices.DeleteFunc(h.Ack, func(k string) bool { return k == kind })
		}
		return nil
	}); err != nil {
		return err
	}
	inv.app.Out.Info("Notice '" + kind + "' of '" + name + "' " + map[string]string{"ack": "acknowledged", "unack": "reopened"}[action] + ".")
	return nil
}

func (inv *invocation) deviceNotices(args []string) error {
	p, err := inv.deviceParse("notices", args)
	if err != nil {
		return err
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	entries := res.Visible(inv.deviceFilter())
	if len(p.Args) == 1 {
		e, err := inv.deviceFind(res, p.Args[0])
		if err != nil {
			return err
		}
		entries = []devreg.Entry{e}
	}
	n := 0
	inv.echo("")
	for _, e := range entries {
		ns := res.NoticesFor(e)
		if !p.Has("--all") {
			ns = devreg.Open(ns)
		}
		for _, no := range ns {
			mark := ""
			if no.Acked {
				mark = " (acknowledged)"
			}
			inv.echo("  " + e.Name + "  " + no.Kind + mark + ": " + no.Text)
			n++
		}
	}
	if n == 0 && p.Has("--all") {
		inv.echo("  No notices.")
	} else if n == 0 {
		inv.echo("  No open notices.")
	}
	inv.echo("")
	return nil
}

// --- import and export -----------------------------------------------------------

func (inv *invocation) deviceImport(args []string) error {
	p, err := inv.deviceParse("import", args)
	if err != nil {
		return err
	}
	// sudoers lets an engineer's tacctl start with 'device import -' only;
	// this is the same rule where sudoers does not run (root's tacctl, the
	// tests).
	if inv.callerScopes().restricted && arg(args, 0) != "-" {
		return inv.usageErr("The engineer tier imports from standard input only: tacctl device import - [--check|--replace] < file")
	}
	var data []byte
	if p.Args[0] == "-" {
		data, err = io.ReadAll(inv.app.Stdin)
	} else {
		data, err = os.ReadFile(p.Args[0])
	}
	if err != nil {
		return inv.usageErr("Cannot read '" + p.Args[0] + "'.")
	}
	rows, err := devreg.ParseImport(data)
	if err != nil {
		return err
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	var hostEntries []devreg.Entry
	for _, e := range res.All() {
		if e.Source == devreg.SourceHost {
			hostEntries = append(hostEntries, e)
		}
	}
	trial := f.Clone()
	plan, err := trial.Import(rows, p.Has("--replace"), p.Has("--allow-generic"), hostEntries)
	if err != nil {
		return err
	}
	// An import that removes a held device or moves it to another address
	// is refused, as 'remove' and 'address' are.
	for _, h := range inv.holds() {
		// A record holds the device only while the device is registered at
		// the record's address; an orphan is not the import's to refuse.
		if cur := f.Find(h.Device); cur == nil || !sameAddress(cur.Address, h.Address) {
			continue
		}
		if d := trial.Find(h.Device); d == nil || !sameAddress(d.Address, h.Address) {
			return inv.usageErr("break-glass is held on " + h.Device + ": release it first (tacctl breakglass release " + h.Device + "). Nothing was changed.")
		}
	}
	a := inv.app
	summary := fmt.Sprintf("%d added, %d updated, %d unchanged, %d removed.", len(plan.Added), len(plan.Updated), len(plan.Unchanged), len(plan.Removed))
	if p.Has("--check") {
		a.Out.Info("Check passed; nothing written. Would import: " + summary)
		return nil
	}
	if len(plan.Removed) > 0 {
		a.Out.Warn(fmt.Sprintf("--replace removes %d device(s) the file does not name: %s.", len(plan.Removed), strings.Join(plan.Removed, ", ")))
		if note := inv.deviceBlocksRemovalNote(plan.Removed); note != "" {
			a.Out.Warn(note)
		}
		if !p.Has("-y") && !a.Prompter().ConfirmPrefix("  Confirm import? [y/N]: ") {
			a.Out.Info("Aborted.")
			return nil
		}
	}
	if _, err := inv.deviceWrite(func(f *devreg.File, r *devreg.Resolver) error {
		var hs []devreg.Entry
		for _, e := range r.All() {
			if e.Source == devreg.SourceHost {
				hs = append(hs, e)
			}
		}
		_, err := f.Import(rows, p.Has("--replace"), p.Has("--allow-generic"), hs)
		return err
	}); err != nil {
		return err
	}
	// A device the import removed takes its configuration record and its
	// SNMP credentials with it, as 'device remove' does.
	for _, n := range plan.Removed {
		inv.configCarry(n, "")
		inv.snmpDeviceCarry(n, "")
		inv.blocksDeviceCarry(n, "")
	}
	a.Out.Info("Imported: " + summary)
	for _, n := range plan.Added {
		if devreg.IsGeneric(n, f.GenericNames) {
			a.Out.Warn("'" + n + "' is a generic name: 'tacctl device notices'.")
		}
	}
	return nil
}

func (inv *invocation) deviceExport(args []string) error {
	p, err := inv.deviceParse("export", args)
	if err != nil {
		return err
	}
	if p.Has("--csv") && p.Has("--json") {
		return inv.usageErr("Give --csv or --json, not both.")
	}
	f, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	vis := f.Clone()
	vis.Devices, vis.Hosts = nil, nil
	filter := inv.deviceFilter()
	var devs []devreg.Device
	for _, e := range res.Visible(filter) {
		if e.Source == devreg.SourceDevice {
			devs = append(devs, e.Device)
			d := e.Clone()
			vis.Devices = append(vis.Devices, &d)
		}
	}
	switch {
	case p.Has("--csv"):
		inv.write(string(devreg.CSV(devs)))
	case p.Has("--json"):
		b, err := devreg.JSON(devs)
		if err != nil {
			return err
		}
		inv.write(string(b))
	default:
		b, err := vis.Text()
		if err != nil {
			return err
		}
		inv.write(string(b))
	}
	return nil
}

// --- names for completion and for 'host enroll' ------------------------------------

// deviceRegistryNames are the registry's device names the caller may see
// (the 'devices' completion kind adds the enrolled hosts').
func deviceRegistryNames(inv *invocation, f scopeFilter) []string {
	file, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return nil
	}
	var out []string
	if !f.restricted {
		for _, d := range file.Devices {
			out = append(out, d.Name)
		}
		return out
	}
	m, err := inv.model()
	if err != nil {
		return nil
	}
	res := devreg.NewResolver(file, nil, m)
	for _, e := range res.Visible(devreg.ScopeFilter{Restricted: true, Scopes: f.scopes}) {
		out = append(out, e.Name)
	}
	return out
}

// hostNameCheck is what 'host enroll' asks before it takes a name: the
// registry's namespace and its generic-name rule (devreg.CheckHostName).
func (inv *invocation) hostNameCheck(name string, enrolled bool) error {
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return err
	}
	return devreg.CheckHostName(f, name, enrolled)
}
