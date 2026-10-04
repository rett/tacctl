package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

// The scope and group families and 'config allow|deny|mgmt-acl' end to
// end, in-process, on the sandbox of native_test.go (store.multiscope.yaml:
// alice, bob, carol; scopes prod, prod-inner, lab, dmz). The bats files
// (scope_*, group_*, config_mgmt_acl, store_mutations) and the corpora
// scopes.txt and groups.txt pin the bytes against 0.1.16; these pin the
// wiring: gate, preflight, StoreApply, tacctl.yaml, prompts, exit codes.

func (sb *sandbox) overrides() string {
	sb.t.Helper()
	data, err := os.ReadFile(filepath.Join(sb.dir, "state", "tacctl.yaml"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		sb.t.Fatal(err)
	}
	return string(data)
}

// runFamily runs args (the whole command line, 'config allow add x') on the
// family mk builds, as config.go's tree will once it registers it: the
// family word is args[1], the rest is resolved below it. In this tree the
// three config families are not wired into the root yet
// (config_policy_register.go).
func (sb *sandbox) runFamily(stdin string, mk func(*invocation) *cobra.Command, args ...string) string {
	sb.t.Helper()
	sb.out.Reset()
	sb.err.Reset()
	sb.runner = &fake.Runner{}
	sb.runner.On([]string{"systemctl"}, execx.Result{})
	sb.runner.On([]string{"logger"}, execx.Result{})
	a := app.New(args, paths.NewEnv(sb.env), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(stdin), Stdout: &sb.out, Stderr: &sb.err}, sb.runner)
	inv := &invocation{ctx: context.Background(), app: a}
	cmd, rest := resolve(mk(inv), args[2:])
	sb.code = exitCode(cmd.RunE(cmd, rest), a.Out)
	if len(sb.runner.Execs()) != 0 {
		sb.t.Errorf("%q: exec'd", args)
	}
	return sb.out.String()
}

func TestScopeUsageAndUnknown(t *testing.T) {
	sb := newSandbox(t, true)
	usage := Usage("scope", UsageVars{"current": "Current scopes: 4\nDefault scope:  lab"})
	for _, w := range []string{"", "help", "-h", "--help"} {
		args := []string{"scope"}
		if w != "" {
			args = append(args, w)
		}
		if got := sb.run("", args); got != usage || sb.code != 0 {
			t.Errorf("%q: %d %q", args, sb.code, got)
		}
	}
	if got := sb.run("", []string{"scope", "bogus"}); got != usage {
		t.Errorf("bogus: %q", got)
	}
	sb.expect(1, "", "[ERROR] Unknown subcommand: 'bogus'")
}

func TestScopeShowMasksTheSecret(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.run("", []string{"scope", "show", "lab"})
	sb.expect(0, "Secret:        (set, 27 chars) — show with 'tacctl scope secret lab show'", "")
	if strings.Contains(out, "lab-secret-0123456789abcdef") {
		t.Errorf("scope show printed the secret:\n%s", out)
	}
	for _, want := range []string{"Users:\x1b[0m\n    - alice\n    - bob\n    - carol\n", "    - 192.168.0.0/16\n    - 172.16.0.0/12\n",
		"Auth method:\x1b[0m   not set (devices: tacacs; hosts: tacacs)"} {
		if !strings.Contains(out, want) {
			t.Errorf("scope show lacks %q:\n%s", want, out)
		}
	}
	sb.run("", []string{"scope", "secret", "lab", "show"})
	sb.expect(0, "Value:  lab-secret-0123456789abcdef", "")
	sb.run("", []string{"scope", "show", "nosuch"})
	sb.expect(1, "", "[ERROR] Scope 'nosuch' does not exist.")
}

// Lengths are characters, as bash's ${#s} counts them in a UTF-8 locale.
func TestScopeSecretLengthInRunes(t *testing.T) {
	sb := newSandbox(t, true)
	fifteen := strings.Repeat("äöü", 5) // 15 characters, 30 bytes
	sb.run("", []string{"scope", "secret", "lab", "set", fifteen})
	sb.expect(1, "", "Secret is 15 characters; minimum is 16.")
	sb.run("", []string{"scope", "secret", "lab", "set", fifteen + "ß"})
	sb.expect(0, "Scope 'lab' secret updated.", "")
	sb.run("", []string{"scope", "show", "lab"})
	sb.expect(0, "(set, 16 chars)", "")
	sb.run("", []string{"scope", "secret", "lab", "set", strings.Repeat("a", 20)})
	sb.expect(1, "", "Secret is single-character-class (low entropy).")
}

func TestScopeLookupExitCodes(t *testing.T) {
	sb := newSandbox(t, true)
	for _, c := range []struct {
		query string
		code  int
		out   string
	}{
		{"10.10.99.5", 0, "10.10.99.5 -> scope 'prod-inner' (via prefix 10.10.99.0/24)"},
		{"8.8.8.8", 1, "No scope owns 8.8.8.8"},
		{"notanip", 2, "ERROR: invalid address or CIDR"},
	} {
		sb.run("", []string{"scope", "lookup", c.query})
		sb.expect(c.code, c.out, "")
	}
	sb.run("", []string{"scope", "lookup"})
	sb.expect(1, "", "Usage: tacctl scope lookup <ip|cidr>")
}

// SCOPE_CONF_KEYS: the per-scope keys of tacctl.yaml follow a rename and
// go with a remove; a scope created later under the old name starts clean.
func TestScopeConfKeysFollowRenameAndRemove(t *testing.T) {
	sb := newSandbox(t, true)
	for _, args := range [][]string{
		{"scope", "aaa-order", "dmz", "local-first"},
		{"scope", "exec-timeout", "dmz", "15"},
		{"scope", "auth-method", "dmz", "radius"},
		{"scope", "mgmt-acl", "dmz", "add", "10.9.0.0/16"},
		{"scope", "mgmt-acl", "dmz", "cisco-name", "DMZ-VTY"},
	} {
		sb.run("", args)
		sb.expect(0, "", "")
	}
	sb.run("", []string{"scope", "rename", "dmz", "edge"})
	sb.expect(0, "Scope renamed: dmz -> edge (1 user(s) updated).", "")
	o := sb.overrides()
	if strings.Contains(o, "dmz") || !strings.Contains(o, "aaa:\n  order:\n    edge: local-first") ||
		!strings.Contains(o, "scope_auth_method:\n  edge: radius") || !strings.Contains(o, "edge:\n    - 10.9.0.0/16") {
		t.Errorf("tacctl.yaml after rename:\n%s", o)
	}
	if !strings.Contains(sb.store(), "scopes: [lab, edge]") {
		t.Errorf("carol's scopes not renamed:\n%s", sb.store())
	}
	sb.run("y\n", []string{"scope", "remove", "edge", "--force"})
	sb.expect(0, "Scope 'edge' removed.", "")
	if o := sb.overrides(); o != "" {
		t.Errorf("tacctl.yaml after remove:\n%s", o)
	}
	// The default scope moves with a rename.
	sb.run("", []string{"scope", "rename", "lab", "lab2"})
	sb.expect(0, "Default-scope marker updated: lab -> lab2", "")
	sb.run("", []string{"scope", "default"})
	sb.expect(0, "Default scope: lab2", "")
}

func TestScopeRemoveGuards(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("y\n", []string{"scope", "remove", "prod"})
	sb.expect(1, "    tacctl user scope alice remove prod", "[ERROR] Cannot remove 'prod': 1 user(s) still reference it.")
	sb.run("y\n", []string{"scope", "remove", "lab", "--force"})
	sb.expect(1, "", "Cannot remove 'lab': it is the default scope.")
	sb.run("n\n", []string{"scope", "remove", "prod-inner"})
	sb.expect(0, "[INFO] Aborted.", "")
	sb.run("", []string{"scope", "remove", "prod-inner"})
	sb.expect(0, "[INFO] Aborted.", "")
	if !strings.Contains(sb.store(), "prod-inner:") {
		t.Error("removed without a yes")
	}
	sb.run("yes\n", []string{"scope", "remove", "prod-inner"})
	sb.expect(0, "Scope 'prod-inner' removed.", "")
}

func TestScopePrefixesMembershipVerbs(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "prefixes", "dmz", "clear"})
	sb.expect(1, "", "[ERROR] 'clear' was renamed: use 'tacctl scope prefixes dmz remove --all [--force]'")
	sb.run("", []string{"scope", "prefixes", "dmz", "remove", "--force"})
	sb.expect(1, "", "('--force' is only valid with --all)")
	sb.run("", []string{"scope", "prefixes", "dmz", "remove", "--all", "10.0.0.0/8"})
	sb.expect(1, "", "('--all' takes no CIDRs)")
	sb.run("", []string{"scope", "prefixes", "dmz", "add", "10.0.0.9/8"})
	sb.expect(1, "", "[ERROR]     - 10.0.0.0/8  (already in scope 'prod')")
	sb.run("y\n", []string{"scope", "prefixes", "dmz", "remove", "--all"})
	sb.expect(1, "    tacctl user scope carol remove dmz", "Cannot remove every prefix of 'dmz': 1 user(s) still reference it.")
	sb.run("y\n", []string{"scope", "prefixes", "dmz", "remove", "--all", "--force"})
	sb.expect(0, "Removed all prefixes from scope 'dmz' (the scope is removed).", "")
	if strings.Contains(sb.store(), "dmz") {
		t.Errorf("dmz left in the store:\n%s", sb.store())
	}
}

func TestScopeAddFlags(t *testing.T) {
	sb := newSandbox(t, true)
	// A value flag that ends the line ends the command, silently.
	sb.run("", []string{"scope", "add", "edge", "--prefixes", "198.51.100.0/24", "--secret"})
	if sb.code != 1 || sb.out.Len() != 0 || strings.Contains(sb.err.String(), "[ERROR]") {
		t.Errorf("--secret at the end: %d %q %q", sb.code, sb.out.String(), sb.err.String())
	}
	sb.run("", []string{"scope", "add", "edge", "--prefixes", "198.51.100.0/24", "--vendor-attrs"})
	sb.expect(1, "", "--vendor-attrs needs a list of vendors (cisco, juniper, wti).")
	sb.run("", []string{"scope", "add", "edge", "--prefixes", "198.51.100.0/24", "--secret", "edge-secret-0123456789abcdef",
		"--protocols", "radius,tacacs", "--vendor-attrs", "wti,cisco", "--default"})
	sb.expect(0, "Scope 'edge' added and set as default.", "")
	if !strings.Contains(sb.store(), "  edge:\n    prefixes: [198.51.100.0/24]\n    secret: edge-secret-0123456789abcdef\n    protocols: [tacacs, radius]\n    vendor_attrs: [cisco, wti]\n") {
		t.Errorf("store:\n%s", sb.store())
	}
	if !strings.Contains(sb.overrides(), "scope:\n  default: edge") {
		t.Errorf("tacctl.yaml:\n%s", sb.overrides())
	}
}

func TestScopeKnobsAndAuthMethod(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "exec-timeout", "lab", "90"})
	sb.expect(1, "", "tacctl config: exec_timeout.lab:")
	sb.run("", []string{"scope", "aaa-order", "nosuch"})
	sb.expect(1, "", "[ERROR] Scope 'nosuch' does not exist. Available: prod-inner prod lab dmz")
	sb.run("", []string{"scope", "protocols", "dmz", "set", "radius"})
	sb.expect(0, "is no longer served over TACACS+", "")
	sb.run("", []string{"scope", "auth-method", "dmz"})
	sb.expect(0, "In effect: radius: the scope's only protocol", "")
	sb.run("", []string{"scope", "auth-method", "dmz", "tacacs"})
	sb.expect(1, "", "Scope 'dmz' is limited to radius (tacctl scope protocols), so it is not served over tacacs.")
	sb.run("", []string{"scope", "auth-method", "dmz", "radius"})
	sb.expect(0, "[WARN] The radius backend is not enabled on this server", "")
	sb.run("", []string{"scope", "protocols", "dmz", "set", "tacacs"})
	sb.expect(1, "", "Scope 'dmz' has auth-method radius, which protocols 'tacacs' would leave unserved.")
}

func TestScopeVendorAttrsAndDevices(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "vendor-attrs", "lab", "enable", "wti,cisco"})
	sb.expect(0, "Scope 'lab': vendor attributes enabled: cisco, wti. Now sent: cisco, wti.", "")
	sb.run("", []string{"scope", "devices", "lab", "set", "192.168.7.7", "cisco"})
	sb.expect(0, "192.168.7.7/32 tagged cisco", "")
	sb.run("", []string{"scope", "vendor-attrs", "lab", "disable", "cisco"})
	sb.expect(0, "Tagged addresses keep their vendor's attribute: 192.168.7.7/32", "")
	sb.run("", []string{"scope", "prefixes", "lab", "remove", "192.168.0.0/16"})
	sb.expect(1, "", "a tagged address would be left outside the scope's prefixes")
	sb.run("", []string{"scope", "devices", "lab", "set", "8.8.8.8", "cisco"})
	sb.expect(1, "", "Cannot tag 8.8.8.8/32 in scope 'lab'")
	sb.run("", []string{"scope", "list"})
	sb.expect(0, "VENDOR ATTRIBUTES (RADIUS)", "")
}

func TestConfigFiltersAndMgmtACL(t *testing.T) {
	sb := newSandbox(t, true)
	sb.runFamily("", configAllowCmd, "config", "allow", "add", "10.0.0.9/8,192.168.0.0/16")
	sb.expect(0, "Added 2 to allow list: 10.0.0.0/8 192.168.0.0/16", "")
	if !strings.Contains(sb.store(), "allow: [10.0.0.0/8, 192.168.0.0/16]") {
		t.Errorf("store:\n%s", sb.store())
	}
	sb.runFamily("", configAllowCmd, "config", "allow", "list")
	sb.expect(0, "  - 10.0.0.0/8\n  - 192.168.0.0/16\n", "")
	sb.runFamily("n\n", configAllowCmd, "config", "allow", "clear")
	sb.expect(0, "[INFO] Aborted.", "")
	sb.runFamily("y\n", configAllowCmd, "config", "allow", "clear")
	sb.expect(0, "Cleared allow list (2 entries removed).", "")
	sb.runFamily("", configDenyCmd, "config", "deny", "frob")
	sb.expect(1, "Usage: tacctl config deny <list|add|remove|clear> [cidr[,cidr...]]", "")
	sb.runFamily("", configDenyCmd, "config", "deny", "help")
	sb.expect(0, "tacctl config deny — connection IP ACL (deny list)", "")

	sb.runFamily("", configMgmtACLCmd, "config", "mgmt-acl", "add", "192.168.5.5/24,10.0.0.0/8")
	sb.expect(0, "Added 2 to mgmt-acl: 192.168.5.0/24 10.0.0.0/8", "")
	if !strings.Contains(sb.overrides(), "mgmt_acl:\n  permits:\n  - 10.0.0.0/8\n  - 192.168.5.0/24\n") {
		t.Errorf("tacctl.yaml:\n%s", sb.overrides())
	}
	sb.runFamily("", configMgmtACLCmd, "config", "mgmt-acl", "cisco-name", "1bad")
	sb.expect(1, "", "[ERROR] Invalid ACL name '1bad'.")
	sb.runFamily("", configMgmtACLCmd, "config", "mgmt-acl", "cisco-name", "MY-VTY")
	sb.expect(0, "Set cisco-name = 'MY-VTY'.", "")
	sb.run("", []string{"scope", "mgmt-acl", "lab", "cisco-name"})
	sb.expect(0, "Source: global (tacctl config mgmt-acl cisco-name)", "")
	sb.runFamily("y\n", configMgmtACLCmd, "config", "mgmt-acl", "clear")
	sb.expect(0, "mgmt-acl cleared.", "")
}

func TestGroupFamily(t *testing.T) {
	sb := newSandbox(t, true)
	for _, w := range []string{"", "help", "bogus"} {
		args := []string{"group"}
		if w != "" {
			args = append(args, w)
		}
		if got := sb.run("", args); got != Usage("group", nil) || sb.code != 1 {
			t.Errorf("%q: %d", args, sb.code)
		}
	}
	sb.run("", []string{"group", "add", "helpdesk", "7", "HD-CLASS"})
	sb.expect(0, "Group 'helpdesk' added (Cisco priv-lvl 7, Juniper HD-CLASS).", "")
	sb.run("", []string{"group", "add", "netops", "16", "NO"})
	sb.expect(1, "", "Cisco privilege level must be 0-15.")
	// The first rule of helpdesk seeds operator, at the same level, first.
	sb.run("", []string{"group", "commands", "add", "helpdesk", "show", "--match", "version"})
	sb.expect(0, "[INFO] Added rule 'show' (action=permit, match=[version]) to group 'helpdesk'.", "")
	sb.run("", []string{"group", "commands", "default", "helpdesk", "deny"})
	sb.expect(0, "default action set to deny", "")
	o := sb.overrides()
	if !strings.Contains(o, "  helpdesk:\n  - name: show\n    action: permit\n    match:\n    - version\n  - name: '*'\n    action: deny\n") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	sb.run("", []string{"group", "commands", "add", "helpdesk", "show", "--match", "^show .*$"})
	sb.expect(1, "", "can never match for rule 'show'")
	sb.run("", []string{"group", "commands", "add", "helpdesk", "show", "--match", "(?=x)"})
	sb.expect(1, "", "[ERROR] Invalid regex: '(?=x)'")
	sb.run("y\n", []string{"group", "commands", "clear", "helpdesk"})
	sb.expect(0, "Cleared command rules for group 'helpdesk'", "")
	sb.run("", []string{"group", "privilege", "add", "operator", "show version"})
	sb.expect(0, "Added 1 priv-exec mapping(s) for group 'operator' (level 7):\n    - show version\n", "")
	sb.run("", []string{"group", "privilege", "list", "operator"})
	sb.expect(0, "  - show version\n", "")
	sb.run("y\n", []string{"group", "remove", "helpdesk"})
	sb.expect(0, "Group 'helpdesk' removed.", "")
	sb.run("y\n", []string{"group", "remove", "operator"})
	sb.expect(1, "", "Cannot remove built-in group 'operator'.")
}

// Every verb has a Spec (its arguments for completion), and every kind a
// Spec names is one completion can answer or a fixed word list.
func TestScopeGroupConfigSpecs(t *testing.T) {
	inv := &invocation{app: newHarness(t, nil).app}
	check := func(family string, specs map[string]Spec, cmds []*cobra.Command) {
		t.Helper()
		var count int
		var walk func(prefix string, cs []*cobra.Command)
		walk = func(prefix string, cs []*cobra.Command) {
			for _, c := range cs {
				if len(c.Commands()) > 0 && family == "group" {
					walk(prefix+c.Name()+" ", c.Commands())
					continue
				}
				count++
				spec, ok := specs[prefix+c.Name()]
				if !ok {
					t.Errorf("%s %s%s has no spec", family, prefix, c.Name())
					continue
				}
				kinds := append([]string(nil), spec.Args...)
				for _, f := range spec.Flags {
					kinds = append(kinds, f.Kind)
				}
				for _, k := range kinds {
					k = strings.TrimSuffix(k, KindList)
					if _, native := completionKinds[k]; k != "" && !native && !strings.Contains(k, "|") {
						t.Errorf("%s %s: kind %q is no completion kind", family, c.Name(), k)
					}
				}
			}
		}
		walk("", cmds)
		if count != len(specs) && family != "config" {
			t.Errorf("%s: %d specs for %d verbs", family, len(specs), count)
		}
	}
	check("scope", scopeSpecs, scopeCmd(inv).Commands())
	check("group", groupSpecs, groupCmd(inv).Commands())
	for _, mk := range []func(*invocation) *cobra.Command{configAllowCmd, configDenyCmd, configMgmtACLCmd} {
		c := mk(inv)
		if _, ok := configPolicyFamilySpecs[c.Name()]; !ok || c.RunE == nil {
			t.Errorf("config %s: no family spec or no RunE", c.Name())
		}
		for _, v := range c.Commands() {
			if v.RunE == nil {
				t.Errorf("config %s %s: no RunE", c.Name(), v.Name())
			}
		}
		check("config", configPolicySpecs, c.Commands())
	}
}

// config_policy_register.go hands the three config families to config.go,
// so they are native.
func TestConfigPolicyRegistered(t *testing.T) {
	for _, name := range []string{"allow", "deny", "mgmt-acl"} {
		if configVerbs[name] == nil {
			t.Errorf("config %s is not registered", name)
		}
		if _, ok := configSpecs[name]; !ok {
			t.Errorf("config %s has no spec", name)
		}
	}
}

// Secrets and hashes never reach the argv of a program a command runs
// (store_mutations.bats checked python3's argv in 0.1.16; the Go binary
// runs no python3, so every recorded call is checked instead).
func TestSecretsNeverOnArgv(t *testing.T) {
	sb := newSandbox(t, true)
	const hashB = "24326224313024626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"
	var argvs []string
	for _, args := range [][]string{
		{"user", "add", "dave", "operator", "--hash", testHash, "--scopes", "lab"},
		{"user", "passwd", "dave", "--hash", hashB},
		{"scope", "add", "edge", "--prefixes", "192.168.40.0/24", "--secret", "edge-secret-0123456789abcdef"},
		{"scope", "secret", "edge", "set", "rotated-secret-0123456789abc"},
		{"scope", "secret", "edge", "generate"},
		{"user", "disable", "dave"},
		{"user", "show", "dave"},
		{"scope", "show", "edge"},
	} {
		sb.run("", args)
		if sb.code != 0 {
			t.Fatalf("%q: exit %d %q", args, sb.code, sb.err.String())
		}
		argvs = append(argvs, sb.runner.Argvs()...)
	}
	if len(argvs) == 0 {
		t.Fatal("no program ran (systemctl, logger)")
	}
	for _, needle := range []string{testHash, hashB, "edge-secret-0123456789abcdef", "rotated-secret-0123456789abc", "lab-secret-0123456789abcdef"} {
		for _, a := range argvs {
			if strings.Contains(a, needle) {
				t.Errorf("argv carries a secret or hash: %q", a)
			}
		}
	}
}

// The usage functions of the families fill their blocks as 0.1.16 did
// (testdata/usage: generated from the 0.1.16 tag, minimal fixture).
func TestScopeGroupConfigUsageFunctions(t *testing.T) {
	for file, got := range map[string]string{
		"scope":           scopeUsageText(1, "lab"),
		"scope-prefixes":  scopePrefixesUsage("lab", 1),
		"scope-secret":    scopeSecretUsage("lab", 30, 16),
		"scope-mgmt-acl":  scopeMgmtACLUsage("lab", 0, 0),
		"config-allow":    configFilterUsage("allow", 0),
		"config-deny":     configFilterUsage("deny", 0),
		"config-mgmt-acl": configMgmtACLUsage("VTY-ACL", "MGMT-ACL", 0),
		"group":           groupUsage(),
		"group-commands":  groupCommandsUsage("/etc/tacctl/tacctl.yaml"),
		"group-privilege": groupPrivilegeUsage(),
	} {
		want, err := os.ReadFile(filepath.Join("testdata", "usage", file+".out"))
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("%s:\n%s\nwant\n%s", file, got, want)
		}
	}
}
