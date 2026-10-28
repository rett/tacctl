package cli

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/spf13/cobra"
)

// completeWords runs 'tacctl __completeNoDesc <words>' with the bridge answering
// as live says ('sudo -n tacctl _completion-names <kind> [arg]' to its
// output) and returns the words offered and the directive line.
func completeWords(t *testing.T, live map[string]string, words ...string) ([]string, string) {
	t.Helper()
	h := newHarness(t, append([]string{"__completeNoDesc"}, words...))
	h.runner.OnFunc([]string{"sudo"}, func(c execx.Cmd) (execx.Result, error) {
		key := strings.Join(c.Args[3:], " ")
		// The scripts ask a kind with descriptions for its names with
		// --desc-short ('name<TAB>vendor scope'); live holds the names.
		if kind, ok := strings.CutSuffix(key, " --desc-short"); ok {
			var lines []string
			for _, n := range strings.Fields(live[kind]) {
				lines = append(lines, n+"\tcisco lab")
			}
			return execx.Result{Stdout: []byte(strings.Join(lines, "\n") + "\n")}, nil
		}
		return execx.Result{Stdout: []byte(live[key])}, nil
	})
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(h.out.String(), "\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], ":") {
		t.Fatalf("%q: no directive line in %q", words, h.out.String())
	}
	got := lines[:len(lines)-1]
	// cobra prints this note on stderr, but be sure no stdout noise remains.
	got = slices.DeleteFunc(got, func(s string) bool { return strings.HasPrefix(s, "Completion ended") })
	return got, lines[len(lines)-1]
}

var liveNames = map[string]string{
	"backends":         "tacacs\nradius\n",
	"enabled-backends": "tacacs\n",
	"listeners radius": "auth\nacct\n",
	"listeners":        "default\n",
	"scopes":           "lab\nprod\n",
	"users":            "alice\nbob\n",
	"groups":           "ops\nadmins\n",
	"backups":          "20260101-000000\n",
	// The break-glass users recorded for the scope 'lab'.
	"breakglass-users lab": "lab-admin\nlab-ops\n",
	// the device registry's and the hosts' names (kind devices)
	"devices": "jsw1\nsw1\n",
	"hosts":   "web1\nweb2\n",
}

// The scenarios of the hand-written completion's tests, now answered by the
// binary: sub-commands from the tree, flags and positionals from the Specs,
// live names from the bridge.
func TestCompleteScenarios(t *testing.T) {
	cases := []struct {
		words []string
		want  []string
	}{
		{[]string{"ba"}, []string{"backend", "backup"}},
		{[]string{"backend", ""}, []string{"disable", "enable", "list", "status"}},
		{[]string{"backend", "enable", ""}, []string{"tacacs", "radius"}},
		{[]string{"backend", "status", "r"}, []string{"radius"}},
		{[]string{"backend", "disable", ""}, []string{"tacacs"}},
		{[]string{"backend", "enable", "radius", ""}, []string{"-y", "--yes"}},
		{[]string{"backend", "list", ""}, nil},
		{[]string{"store", ""}, []string{"import", "rollback", "show"}},
		{[]string{"store", "show", "-"}, []string{"--json"}},
		{[]string{"device", "config", "apply", "--pu"}, []string{"--pull"}},
		{[]string{"store", "import", "--"}, []string{"--check", "--force", "--replace"}},
		{[]string{"config", "ren"}, []string{"render"}},
		{[]string{"config", "render", ""}, []string{"--force", "--dry-run", "--out"}},
		{[]string{"config", "render", "--dry-run", ""}, []string{"--force", "--out"}},
		{[]string{"config", "listen", "--backend", ""}, []string{"tacacs", "radius"}},
		{[]string{"config", "listen", "--backend", "radius", "--listener", ""}, []string{"auth", "acct"}},
		{[]string{"config", "listen", "--listener", ""}, []string{"default"}},
		{[]string{"config", "listen", "--backend", "radius", ""}, []string{"show", "reset", "tcp", "tcp6", "udp", "udp6", "--listener"}},
		{[]string{"config", "cisco", ""}, []string{"--scope", "--protocol", "--staging", "--name", "--server", "--source", "--snmp-location", "--legacy"}},
		{[]string{"config", "juniper", ""}, []string{"--scope", "--protocol", "--staging", "--name", "--server", "--source", "--snmp-location"}},
		{[]string{"config", "cisco", "--protocol", ""}, []string{"tacacs", "radius"}},
		{[]string{"config", "juniper", "--scope", "lab", "--protocol", ""}, []string{"tacacs", "radius"}},
		{[]string{"config", "juniper", "--scope", "lab", ""}, []string{"--protocol", "--staging", "--name", "--server", "--source", "--snmp-location"}},
		{[]string{"config", "cisco", "--protocol", "radius", "--scope", "lab", ""}, []string{"--staging", "--name", "--server", "--source", "--snmp-location", "--legacy"}},
		{[]string{"config", "wti", "--scope", ""}, []string{"lab", "prod"}},
		{[]string{"scope", "radius"}, []string{"radius-group"}},
		{[]string{"scope", "auth"}, []string{"auth-method"}},
		{[]string{"scope", "auth-method", "lab", ""}, []string{"tacacs", "radius", "clear"}},
		{[]string{"scope", "vendor-attrs", "lab", ""}, []string{"show", "enable", "disable"}},
		{[]string{"scope", "vendor-attrs", "lab", "enable", ""}, []string{"cisco", "juniper", "wti"}},
		{[]string{"scope", "vendor-attrs", "lab", "disable", "w"}, []string{"wti"}},
		{[]string{"scope", "devices", "lab", ""}, []string{"list", "set", "unset"}},
		{[]string{"scope", "devices", "lab", "set", "10.1.2.3", ""}, []string{"cisco", "juniper", "wti"}},
		{[]string{"scope", "devices", "lab", "unset", "10.1.2.3", ""}, nil},
		{[]string{"scope", "add", "edge", ""}, []string{"--prefixes", "--secret", "--protocols", "--vendor-attrs", "--default"}},
		{[]string{"scope", "add", "edge", "--prefixes", "10.0.0.0/8", "--vendor-attrs", "cisco,"}, []string{"cisco,juniper", "cisco,wti"}},
		{[]string{"scope", "add", "edge", "--prefixes", "10.0.0.0/8", "--vendor-attrs", "cisco", ""}, []string{"--secret", "--protocols", "--default"}},
		{[]string{"log", "tail", "--"}, []string{"--backend", "--follow"}},
		{[]string{"log", "tail", "--backend", ""}, []string{"tacacs", "radius"}},
		{[]string{"log", "clear", ""}, []string{"--backend", "--force", "-y", "--yes"}},
		{[]string{"log", "clear", "--backend", "tacacs", ""}, []string{"--force", "-y", "--yes"}},
		{[]string{"scope", "protocols", "lab", ""}, []string{"list", "set", "clear"}},
		{[]string{"scope", "protocols", "lab", "set", ""}, []string{"tacacs", "radius"}},
		{[]string{"scope", "breakglass", "lab", ""}, []string{"list", "add", "remove"}},
		{[]string{"scope", "breakglass", "lab", "add", "lab-admin", ""}, []string{"--role"}},
		{[]string{"scope", "breakglass", "lab", "add", "lab-admin", "--role", ""}, []string{"admin", "operator", "readonly"}},
		{[]string{"scope", "breakglass", "lab", "remove", "lab-admin", ""}, nil},
		{[]string{"scope", "breakglass", "lab", "remove", ""}, []string{"lab-admin", "lab-ops"}},
		{[]string{"scope", "breakglass", "lab", "remove", "lab-a"}, []string{"lab-admin"}},
		{[]string{"scope", "block", ""}, []string{"lab", "prod"}},
		{[]string{"scope", "block", "lab", ""}, []string{"cisco", "juniper"}},
		{[]string{"scope", "block", "lab", "juniper", ""}, []string{"list", "show", "check", "set", "remove", "edit", "adopt"}},
		{[]string{"scope", "block", "lab", "juniper", "s"}, []string{"show", "set"}},
		{[]string{"scope", "block", "lab", "juniper", "e"}, []string{"edit"}},
		// edit takes a block; adopt takes a device, then a block
		{[]string{"scope", "block", "lab", "juniper", "edit", ""}, []string{"snmp", "system", "-y", "--yes"}},
		{[]string{"scope", "block", "lab", "juniper", "adopt", ""}, []string{"jsw1", "sw1", "-y", "--yes"}},
		{[]string{"scope", "block", "lab", "juniper", "adopt", "jsw1", ""}, []string{"snmp", "system", "-y", "--yes"}},
		{[]string{"scope", "block", "lab", "juniper", "adopt", "jsw1", "snmp", ""}, []string{"-y", "--yes"}},
		{[]string{"scope", "block", "lab", "juniper", "show", ""}, []string{"snmp", "system", "--reveal"}},
		{[]string{"scope", "block", "lab", "juniper", "set", "snmp", ""}, []string{"--file", "-y", "--yes"}},
		{[]string{"scope", "block", "lab", "juniper", "check", "snmp", "--against", ""}, []string{"jsw1", "sw1"}},
		{[]string{"scope", "block", "lab", "juniper", "check", "snmp", ""}, []string{"--file", "--against"}},
		// --restore-point takes its value after '=' only: the bare flag is a
		// word of its own, the value (alone: the scripts strip the flag) is
		// the file systems, and a device name after the bare flag is still a
		// device
		{[]string{"device", "config", "plan", "--restore"}, []string{"--restore-point"}},
		{[]string{"device", "config", "plan", "--restore-point=b"}, []string{"bootflash:"}},
		{[]string{"device", "config", "plan", "--restore-point=d"}, []string{"disk0:"}},
		{[]string{"device", "config", "plan", "--restore-point", "js"}, []string{"jsw1"}},
		{[]string{"device", "config", "plan", "--restore-point=disk0:", "--restore"}, nil},
		{[]string{"device", "block", ""}, []string{"jsw1", "sw1"}},
		{[]string{"device", "block", "jsw1", ""}, []string{"list", "show", "check", "set", "remove", "edit", "adopt"}},
		{[]string{"device", "block", "jsw1", "adopt", ""}, []string{"snmp", "system", "-y", "--yes"}},
		{[]string{"device", "block", "jsw1", "edit", "snmp", ""}, []string{"-y", "--yes"}},
		{[]string{"device", "block", "jsw1", "show", ""}, []string{"snmp", "system", "--reveal", "--effective"}},
		{[]string{"device", "block", "jsw1", "check", "system", ""}, []string{"--file", "--against"}},
		{[]string{"scope", "prefixes", "lab", ""}, []string{"list", "add", "remove", "move"}},
		{[]string{"scope", "prefixes", "lab", "remove", ""}, []string{"--all", "--force"}},
		{[]string{"scope", "prefixes", "lab", "remove", "--all", ""}, []string{"--force"}},
		{[]string{"user", "scope", "alice", ""}, []string{"list", "add", "remove", "replace"}},
		{[]string{"user", "scope", "alice", "remove", ""}, []string{"lab", "prod", "--all"}},
		{[]string{"user", "scope", "alice", "remove", "--all", ""}, nil},
		{[]string{"user", "scope", "alice", "replace", ""}, []string{"lab", "prod"}},
		{[]string{"user", "scope", "alice", "add", "lab,"}, []string{"lab,prod"}},
		{[]string{"user", "show", ""}, []string{"alice", "bob"}},
		{[]string{"user", "add", "carol", ""}, []string{"ops", "admins"}},
		{[]string{"user", "add", "carol", "ops", ""}, []string{"--hash", "--scopes"}},
		{[]string{"user", "move", "alice", ""}, []string{"ops", "admins"}},
		{[]string{"group", "commands", "default", "ops", ""}, []string{"permit", "deny"}},
		{[]string{"group", "commands", "add", "ops", "x", "--action", ""}, []string{"permit", "deny"}},
		{[]string{"group", "commands", "add", "ops", "x", ""}, []string{"--match", "--action", "--before", "--first"}},
		{[]string{"group", "commands", "remove", "ops", "x", ""}, []string{"--match", "--action", "--all"}},
		{[]string{"group", "commands", "remove", "ops", "x", "--action", ""}, []string{"permit", "deny"}},
		{[]string{"group", "privilege", "add", "ops", ""}, []string{"exec:", "exec all:", "configure:", "configure all:"}},
		{[]string{"group", "privilege", "add", "ops", "conf"}, []string{"configure:", "configure all:"}},
		{[]string{"group", "add", "eng", "15", "EN-CLASS", "--tier", ""}, []string{"readonly", "operator", "engineer", "superuser"}},
		{[]string{"group", "add", "eng", "15", "EN-CLASS", "--wti-level", ""}, []string{"viewonly", "user", "superuser", "administrator"}},
		{[]string{"group", "edit", "ops", "tier", ""}, []string{"auto", "readonly", "operator", "engineer", "superuser"}},
		{[]string{"group", "edit", "ops", "tier", "e"}, []string{"engineer"}},
		{[]string{"group", "edit", "ops", "priv-lvl", ""}, nil},
		{[]string{"config", "snmp", "v3-user", "monitor", "--priv", ""}, []string{"aes128"}},
		{[]string{"scope", "snmp", "lab", "v3-user", "monitor", "--priv", ""}, []string{"aes128"}},
		{[]string{"scope", "snmp", "lab", "v3-user", "monitor", "--auth", ""}, []string{"sha", "sha256"}},
		{[]string{"config", "linux", ""}, []string{"build", "builds", "engineer-sudo", "remove-script", "script", "uid", "uid-range"}},
		{[]string{"config", "linux", "script", ""}, []string{"--scope", "--server", "--method", "--output", "-o"}},
		{[]string{"config", "linux", "script", "--method", ""}, []string{"tacplus", "radius"}},
		{[]string{"config", "linux", "builds", ""}, []string{"list", "clear"}},
		{[]string{"config", "linux", "uid", ""}, []string{"alice", "bob"}},
		{[]string{"backup", "restore", ""}, []string{"20260101-000000"}},
		{[]string{"backup", "restore", "20260101-000000", ""}, []string{"--legacy", "--keep-uids"}},
		{[]string{"config", "restore", "20260101-000000", ""}, []string{"--legacy", "--keep-uids"}},
		{[]string{"host", "default-method", ""}, []string{"tacplus", "radius"}},
		{[]string{"host", "enroll", "--method", ""}, []string{"tacplus", "radius"}},
		{[]string{"host", "show", "web1", ""}, []string{"--all", "--json", "--check"}},
		// host rename: the first word is an enrolled host, the second a new
		// name (nothing to complete), then the one flag.
		{[]string{"host", "rename", ""}, []string{"web1", "web2"}},
		{[]string{"host", "rename", "web1", ""}, nil},
		{[]string{"host", "rename", "web1", "web9", ""}, []string{"-y", "--yes"}},
		{[]string{"host", "rename", "web1", "web9", "--yes", ""}, nil},
		// host forget: an enrolled host, then the one flag.
		{[]string{"host", "forget", ""}, []string{"web1", "web2"}},
		{[]string{"host", "forget", "web1", ""}, []string{"-y", "--yes"}},
		// host sync: hosts at every position, then the flags.
		{[]string{"host", "sync", ""}, []string{"web1", "web2", "--all", "--allow-uid-mismatch", "--remove-home"}},
		{[]string{"host", "sync", "web1", ""}, []string{"web1", "web2", "--all", "--allow-uid-mismatch", "--remove-home"}},
		{[]string{"host", "sync", "web1", "web2", "w"}, []string{"web1", "web2"}},
		// host check: hosts at every position, then the flags.
		{[]string{"host", "check", ""}, []string{"web1", "web2", "--all", "--json"}},
		{[]string{"host", "check", "web1", ""}, []string{"web1", "web2", "--all", "--json"}},
		{[]string{"host", ""}, []string{"check", "default-method", "enroll", "forget", "list", "move", "provisioner", "rename", "show", "sync", "target", "unenroll"}},
		{[]string{"install", ""}, []string{"--branch", "-y", "--yes"}},
		{[]string{"upgrade", ""}, []string{"--branch"}},
		{[]string{"uninstall", ""}, []string{"-y", "--yes"}},
		{[]string{"version", ""}, []string{"--long"}},
		{[]string{"shell", "-c", "sta"}, []string{"status"}},
		{[]string{"shell", "-c", "status", ""}, []string{"--no-history", "--idle", "--space-completion", "--password-cache"}},
	}
	for _, c := range cases {
		got, _ := completeWords(t, liveNames, c.words...)
		if !reflect.DeepEqual(got, c.want) && (len(got) != 0 || len(c.want) != 0) {
			t.Errorf("%q: offered %q, want %q", c.words, got, c.want)
		}
	}
}

// With descriptions (what bash, zsh and fish ask for), each flag carries
// the '?' text of the shell, after the value it takes; other words none.
func TestCompleteDescribesFlags(t *testing.T) {
	cases := map[string][]string{
		"shell -": {
			"--no-history\tKeep no history file for this session",
			"--idle\t<min>: End the session after this many idle minutes at the prompt",
			"--space-completion\ton|off: A typed space completes a fixed word and never doubles (default on)",
			"--password-cache\tKeep your network password in this shell's memory (when your tier's policy allows)",
			"-c\t<line>: Run one line and exit",
		},
		"backend enable ":              {"tacacs", "radius"},
		"device config plan --restore": {"--restore-point\t<fs>: (IOS and IOS-XE only) A restore point block before the plan: a copy of the running configuration on <fs> (flash:, bootflash:, disk0:), or, bare, 'archive config' where the pull read an archive path; the back-out names 'configure replace' with it; a file, not a timer (the bare form has not been checked on a device)"},
		"group commands remove operator show -": {
			"--match\t<regex>: (add, remove) A regex the command's arguments must match (repeatable; remove: the rule's, in order)",
			"--action\tpermit|deny: (add, remove) What the rule does (add: default permit)",
			"--all\t(remove) Drop every rule named <name>",
		},
	}
	for line, want := range cases {
		words := strings.Split(line, " ")
		h := newHarness(t, append([]string{"__complete"}, words...))
		h.runner.OnFunc([]string{"sudo"}, func(c execx.Cmd) (execx.Result, error) {
			return execx.Result{Stdout: []byte(liveNames[strings.Join(c.Args[3:], " ")])}, nil
		})
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		got := strings.Split(strings.TrimSuffix(h.out.String(), "\n"), "\n")
		got = slices.DeleteFunc(got[:len(got)-1], func(s string) bool { return strings.HasPrefix(s, "Completion ended") })
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %q, want %q", line, got, want)
		}
	}
	// Every flag of every verb is described.
	inv, root, _ := shellTestInv(t)
	var all [][]string
	commandPaths(root, nil, &all)
	for _, p := range all {
		c, _ := resolve(root, p)
		spec, ok := specFor(p)
		if len(c.Commands()) > 0 || !ok {
			continue
		}
		var flags []cobra.Completion
		for _, f := range spec.Flags {
			flags = append(flags, f.Names...)
		}
		for _, d := range inv.describeFlags(c, p, spec, flags) {
			if !strings.Contains(d, "\t") {
				t.Errorf("tacctl %s %s: no description", strings.Join(p, " "), d)
			}
		}
	}
}

// Without the sudo rule the bridge answers nothing: no names, no error.
func TestCompleteWithoutTheBridge(t *testing.T) {
	got, dir := completeWords(t, nil, "scope", "show", "")
	if len(got) != 0 || !strings.HasPrefix(dir, ":4") {
		t.Errorf("offered %q, %q", got, dir)
	}
}

// The listeners of the backend named on the line, else every backend's.
func TestCompleteAsksForTheListenersOfTheBackendOnTheLine(t *testing.T) {
	h := newHarness(t, []string{"__completeNoDesc", "config", "listen", "--backend", "radius", "--listener", ""})
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	argvs := h.runner.Argvs()
	if len(argvs) != 1 || argvs[0] != "sudo -n tacctl _completion-names listeners radius" {
		t.Errorf("calls %q", argvs)
	}
}

// Files are the shell's: --output and the file of 'store import' answer
// with the default directive and no words.
func TestCompleteFilesAreTheShells(t *testing.T) {
	for _, words := range [][]string{
		{"config", "linux", "script", "--output", ""}, {"store", "import", ""}, {"config", "render", "--out", ""},
	} {
		got, dir := completeWords(t, liveNames, words...)
		if len(got) != 0 || dir != ":0" {
			t.Errorf("%q: %q %q", words, got, dir)
		}
	}
}

// No completion, in any shell, offers the hidden words or a removed verb.
func TestCompleteOffersNoHiddenOrRemovedWords(t *testing.T) {
	for _, words := range [][]string{{""}, {"user", ""}, {"user", "scope", "alice", ""}, {"scope", "prefixes", "lab", ""},
		{"scope", "vendor-attrs", "lab", ""}, {"config", ""}} {
		got, _ := completeWords(t, liveNames, words...)
		for _, w := range got {
			switch w {
			case "set", "_phase", "_completion-names", "completion", "help", "none":
				t.Errorf("%q offers %q", words, w)
			}
			if w == "clear" && words[0] != "config" {
				t.Errorf("%q offers clear", words)
			}
		}
	}
}

// 'tacctl completion <shell>' prints cobra's script for the binary; a
// missing or unknown shell is a usage error.
func TestCompletionCommand(t *testing.T) {
	for shell, marker := range map[string]string{"bash": "# bash completion V2 for tacctl", "zsh": "#compdef tacctl", "fish": "# fish completion for tacctl"} {
		h := newHarness(t, []string{"completion", shell})
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(h.out.String(), marker) || !strings.Contains(h.out.String(), "__complete") {
			t.Errorf("%s: no script:\n%.200s", shell, h.out.String())
		}
		if len(h.runner.Execs()) != 0 || len(h.runner.Calls()) != 0 {
			t.Errorf("%s: ran something", shell)
		}
		for _, bad := range []string{"/etc/tacquito", "/etc/tacctl", "/home/", "/opt/"} {
			if strings.Contains(h.out.String(), bad) {
				t.Errorf("%s: script names a host path %q", shell, bad)
			}
		}
	}
	for _, args := range [][]string{{"completion"}, {"completion", "powershell"}} {
		h := newHarness(t, args)
		if code := exitCode(h.run(), h.app.Out); code != 1 || h.out.Len() != 0 || !strings.Contains(h.err.String(), "Usage: tacctl completion bash|zsh|fish") {
			t.Errorf("%q: %d %q %q", args, code, h.out.String(), h.err.String())
		}
	}
}

// TestConfigPathsCoverSchema: 'config get' completes every exact key of the
// schema and the prefix of every key family, so a key added to the schema
// is completed without a second list.
func TestConfigPathsCoverSchema(t *testing.T) {
	words := strings.Split(configPaths, "|")
	s := conf.NewSchema([]string{"tacacs", "radius"})
	for _, k := range slices.Concat(s.Keys(), s.Wildcards()) {
		if !slices.Contains(words, k) {
			t.Errorf("config get does not complete %q", k)
		}
	}
	if !slices.IsSorted(words) || len(slices.Compact(slices.Clone(words))) != len(words) {
		t.Errorf("configPaths is not sorted and unique")
	}
	for _, w := range words {
		if w == "" || strings.ContainsAny(w, " \t") {
			t.Errorf("bad word %q", w)
		}
	}
}

// A family prefix is offered without a trailing space; once it is typed the
// names come from the store, and a family whose key follows the name ends in
// a dot again.
func TestConfigGetCompletesFamiliesFromTheStore(t *testing.T) {
	got, dir := completeWords(t, liveNames, "config", "get", "ti")
	if !slices.Contains(got, "tier.") || dir != ":6" { // NoFileComp (4) | NoSpace (2)
		t.Errorf("ti: %q %s", got, dir)
	}
	got, _ = completeWords(t, liveNames, "config", "get", "tier.")
	if !slices.Contains(got, "tier.ops") || !slices.Contains(got, "tier.admins") {
		t.Errorf("tier.: %q", got)
	}
	got, dir = completeWords(t, liveNames, "config", "get", "exec_timeout.l")
	if !reflect.DeepEqual(got, []string{"exec_timeout.lab"}) || dir != ":4" {
		t.Errorf("exec_timeout.l: %q %s", got, dir)
	}
	got, dir = completeWords(t, liveNames, "config", "get", "junos.o")
	if !reflect.DeepEqual(got, []string{"junos.ops."}) || dir != ":6" {
		t.Errorf("junos.o: %q %s", got, dir)
	}
	got, _ = completeWords(t, liveNames, "config", "get", "snmp_scope.")
	if !slices.Contains(got, "snmp_scope.lab.") {
		t.Errorf("snmp_scope.: %q", got)
	}
	// A free-text family names nothing from the store.
	if got, _ = completeWords(t, liveNames, "config", "get", "listeners."); len(got) > 1 {
		t.Errorf("listeners.: %q", got)
	}
}

// Every wildcard family of the schema is in configFamilies, with the kind
// of name it takes or "" for one typed by hand: a new family has to be
// decided.
func TestConfigFamiliesCoverSchema(t *testing.T) {
	for _, p := range conf.NewSchema(nil).Wildcards() {
		if _, ok := configFamilies[p]; !ok {
			t.Errorf("configFamilies lacks the family %q", p)
		}
	}
	for p := range configFamilies {
		if !slices.Contains(conf.NewSchema(nil).Wildcards(), p) {
			t.Errorf("configFamilies names %q, which is not a family of the schema", p)
		}
	}
}

// The words this release (0.2.17) added, as completion offers them: the
// new verb and its flags, the selectors of the config verbs, apply --pull,
// vendor --from-device, discover --snmp, config audit-strict, audit.strict,
// the secret read from standard input, --hash and the rollback targets. A
// flag list is checked for what it contains, so later flags do not break it.
func TestCompleteThisReleasesWords(t *testing.T) {
	cases := []struct {
		words []string
		want  []string
		exact bool
	}{
		{[]string{"device", "enroll", ""}, []string{"--discovered", "--host-key", "--vendor", "--name", "--legacy-ssh", "--json"}, false},
		{[]string{"device", "enroll", "--"}, []string{"--discovered", "--host-key", "--vendor", "--name", "--legacy-ssh", "--json"}, false},
		{[]string{"device", "enroll", "--vendor", ""}, []string{"cisco", "juniper", "wti", "other"}, true},
		{[]string{"device", "config", "pull", "--"}, []string{"--differs", "--name", "--ip"}, false},
		{[]string{"device", "config", "diff", "--"}, []string{"--differs", "--name", "--ip"}, false},
		{[]string{"device", "config", "plan", "--"}, []string{"--differs", "--name", "--ip"}, false},
		{[]string{"device", "config", "apply", "--"}, []string{"--differs", "--name", "--ip", "--pull"}, false},
		{[]string{"device", "config", "list", "--"}, []string{"--differs", "--name", "--ip"}, false},
		{[]string{"device", "vendor", "x", "--"}, []string{"--from-device", "--yes"}, false},
		{[]string{"device", "discover", "--"}, []string{"--snmp"}, false},
		{[]string{"config", "audit-strict", ""}, []string{"on", "off"}, true},
		{[]string{"config", "get", "audit."}, []string{"audit.strict"}, false},
		{[]string{"scope", "secret", "lab", "set", "--"}, []string{"--stdin"}, false},
		{[]string{"user", "add", "x", "--"}, []string{"--hash"}, false},
		{[]string{"user", "passwd", "x", "--"}, []string{"--hash"}, false},
		{[]string{"rollback", ""}, []string{"0.2.18", "0.2.17", "0.2.16", "0.2.9", "0.2.3"}, true},
	}
	for _, c := range cases {
		got, _ := completeWords(t, liveNames, c.words...)
		if c.exact {
			if !slices.Equal(got, c.want) {
				t.Errorf("%q: %q, want %q", c.words, got, c.want)
			}
			continue
		}
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("%q: %q lacks %q", c.words, got, w)
			}
		}
	}
}
