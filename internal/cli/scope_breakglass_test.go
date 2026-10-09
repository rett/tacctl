package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'scope breakglass' (D55) on the sandbox of native_test.go: alice (prod,
// lab), bob (lab) and carol (lab, dmz) are the tacctl users; the scopes are
// prod, prod-inner, lab and dmz.

func TestScopeBreakGlassAddListRemove(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "breakglass", "lab"})
	sb.expect(0, "Scope 'lab' has no break-glass local user.", "")
	// The default role is admin.
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.expect(0, "Break-glass user 'lab-admin' (admin) recorded for scope 'lab'.", "")
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-ops", "--role", "operator"})
	sb.expect(0, "Break-glass user 'lab-ops' (operator) recorded", "")
	sb.run("", []string{"scope", "breakglass", "lab", "add", "--role=readonly", "lab-ro"})
	sb.expect(0, "Break-glass user 'lab-ro' (readonly) recorded", "")
	if o := sb.overrides(); !strings.Contains(o, "breakglass_scope:\n  lab:\n    users:\n    - lab-admin:admin\n    - lab-ops:operator\n    - lab-ro:readonly\n") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	out := plain(sb.run("", []string{"scope", "breakglass", "lab", "list"}))
	for _, want := range []string{"Scope 'lab' break-glass local users:", "    lab-admin  (admin)", "    lab-ops  (operator)", "    lab-ro  (readonly)", "stores no password or hash"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	// Another scope is unaffected, and says so in scope show.
	if out := plain(sb.run("", []string{"scope", "breakglass", "prod"})); !strings.Contains(out, "Scope 'prod' has no break-glass local user.") {
		t.Errorf("prod:\n%s", out)
	}
	if out := plain(sb.run("", []string{"scope", "show", "lab"})); !strings.Contains(out, "Break-glass:    lab-admin (admin), lab-ops (operator), lab-ro (readonly)\n") {
		t.Errorf("scope show lab:\n%s", out)
	}
	if out := plain(sb.run("", []string{"scope", "show", "prod"})); !strings.Contains(out, "Break-glass:    none — a lockout risk with the server unreachable (tacctl scope breakglass prod add <name>)\n") {
		t.Errorf("scope show prod:\n%s", out)
	}
	// Remove: one, then the last (the key leaves tacctl.yaml with it).
	sb.run("", []string{"scope", "breakglass", "lab", "remove", "lab-ops"})
	sb.expect(0, "Break-glass user 'lab-ops' removed from scope 'lab'.", "")
	sb.run("", []string{"scope", "breakglass", "lab", "remove", "lab-ops"})
	sb.expect(1, "", "Scope 'lab' has no break-glass user 'lab-ops'.")
	sb.run("", []string{"scope", "breakglass", "lab", "remove", "lab-admin"})
	sb.run("", []string{"scope", "breakglass", "lab", "remove", "lab-ro"})
	sb.expect(0, "", "")
	if !strings.Contains(plain(sb.out.String()), "nobody can log in") && !strings.Contains(sb.stderr(), "now has no break-glass user") {
		t.Errorf("no lockout warning:\n%s\n%s", sb.out.String(), sb.err.String())
	}
	if o := sb.overrides(); o != "" {
		t.Errorf("tacctl.yaml after the last removal:\n%s", o)
	}
}

func TestScopeBreakGlassRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"scope", "breakglass"}, "Usage: tacctl scope breakglass <scope>"},
		{[]string{"scope", "breakglass", "nosuch", "list"}, "Scope 'nosuch' does not exist. Available:"},
		{[]string{"scope", "breakglass", "lab", "add"}, "Usage: tacctl scope breakglass lab add <name>"},
		{[]string{"scope", "breakglass", "lab", "add", "x", "--role", "boss"}, "Unknown role 'boss'. Roles: admin, operator, readonly"},
		{[]string{"scope", "breakglass", "lab", "add", "x", "--role"}, "--role requires a value"},
		{[]string{"scope", "breakglass", "lab", "list", "--role", "admin"}, "--role belongs to 'add'."},
		{[]string{"scope", "breakglass", "lab", "add", "x", "--bogus"}, "Unknown flag: '--bogus'"},
		{[]string{"scope", "breakglass", "lab", "frob"}, "Unknown subcommand: 'frob'"},
		{[]string{"scope", "breakglass", "lab", "remove"}, "Usage: tacctl scope breakglass lab remove <name>"},
		// Names: not device-safe, reserved, a tacctl user of the scope, a
		// template-user or class name, already recorded.
		{[]string{"scope", "breakglass", "lab", "add", "9lives"}, "'9lives' is not a device-safe user name"},
		{[]string{"scope", "breakglass", "lab", "add", "has space"}, "is not a device-safe user name"},
		{[]string{"scope", "breakglass", "lab", "add", "a;b"}, "is not a device-safe user name"},
		{[]string{"scope", "breakglass", "lab", "add", strings.Repeat("n", 33)}, "is not a device-safe user name"},
		{[]string{"scope", "breakglass", "lab", "add", "root"}, "'root' is reserved"},
		{[]string{"scope", "breakglass", "lab", "add", "tacquito"}, "'tacquito' is reserved"},
		// The Junos template account of every remote user without a
		// local-user-name; case does not matter.
		{[]string{"scope", "breakglass", "lab", "add", "remote"}, "'remote' is a Junos system account"},
		{[]string{"scope", "breakglass", "lab", "add", "Remote"}, "'Remote' is a Junos system account"},
		{[]string{"scope", "breakglass", "lab", "add", "ROOT"}, "'ROOT' is reserved"},
		{[]string{"scope", "breakglass", "lab", "add", "BOB"}, "'BOB' is a tacctl user of scope 'lab'"},
		{[]string{"scope", "breakglass", "lab", "add", "Lab-Admin"}, "already has break-glass user 'lab-admin' (admin)"},
		{[]string{"scope", "breakglass", "lab", "add", "bob"}, "'bob' is a tacctl user of scope 'lab'"},
		{[]string{"scope", "breakglass", "lab", "add", "alice"}, "'alice' is a tacctl user of scope 'lab'"},
		{[]string{"scope", "breakglass", "lab", "add", "RW-CLASS"}, "template-user or class name of the device walkthroughs (RW-CLASS)"},
		{[]string{"scope", "breakglass", "lab", "add", "op-class"}, "template-user or class name of the device walkthroughs (OP-CLASS)"},
		{[]string{"scope", "breakglass", "lab", "add", "super-user"}, "template-user or class name"},
		{[]string{"scope", "breakglass", "lab", "add", "lab-admin"}, "already has break-glass user 'lab-admin' (admin)"},
	} {
		sb.run("", c.args)
		sb.expect(1, "", c.err)
	}
	// A tacctl user of another scope only is no collision in this one: carol
	// is in lab and dmz, alice in prod and lab; nobody is in dmz alone, so a
	// name the dmz scope does not have is free there.
	sb.run("", []string{"scope", "breakglass", "dmz", "add", "bob"})
	sb.expect(0, "Break-glass user 'bob' (admin) recorded for scope 'dmz'.", "")
	// The most a scope may record.
	for i := 0; i < 16; i++ {
		sb.run("", []string{"scope", "breakglass", "prod-inner", "add", "bg" + strings.Repeat("x", i)})
	}
	sb.expect(0, "recorded", "")
	sb.run("", []string{"scope", "breakglass", "prod-inner", "add", "one-more"})
	sb.expect(1, "", "already has the most break-glass users it may record (16)")
	// Nothing was written for the refusals.
	if o := sb.overrides(); strings.Contains(o, "9lives") || strings.Contains(o, "root") || strings.Contains(o, "boss") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
}

// The record follows 'scope rename' and goes with 'scope remove'; a scope
// made later under the old name starts without it.
func TestScopeBreakGlassFollowsRenameAndRemove(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "breakglass", "dmz", "add", "edge-admin"})
	sb.run("", []string{"scope", "breakglass", "dmz", "add", "edge-ro", "--role", "readonly"})
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"scope", "rename", "dmz", "edge"})
	sb.expect(0, "Scope renamed: dmz -> edge", "")
	o := sb.overrides()
	if strings.Contains(o, "dmz") || !strings.Contains(o, "  edge:\n    users:\n    - edge-admin:admin\n    - edge-ro:readonly\n") ||
		!strings.Contains(o, "  lab:\n    users:\n    - lab-admin:admin\n") {
		t.Errorf("tacctl.yaml after rename:\n%s", o)
	}
	sb.run("y\n", []string{"scope", "remove", "edge", "--force"})
	sb.expect(0, "Scope 'edge' removed.", "")
	o = sb.overrides()
	if strings.Contains(o, "edge") || !strings.Contains(o, "lab-admin:admin") {
		t.Errorf("tacctl.yaml after remove:\n%s", o)
	}
}

// The walkthroughs render the record of the scope asked for, and tacctl.yaml
// holds no credential: only the names and roles are in it.
func TestScopeBreakGlassInWalkthroughs(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-ops", "--role", "operator"})
	sb.run("", []string{"scope", "breakglass", "prod", "add", "prod-ro", "--role", "readonly"})
	for _, c := range []struct {
		args       []string
		want, not  []string
		unfilledIn string
	}{
		{[]string{"config", "cisco", "--scope", "lab"},
			[]string{"! username lab-admin privilege 15 secret 9 <TYPE9-HASH>\n", "! username lab-ops privilege 7 secret 9 <TYPE9-HASH>\n"},
			[]string{"prod-ro", "algorithm-type", "scrypt"}, "lab-admin (admin), lab-ops (operator)"},
		{[]string{"config", "cisco", "--scope", "lab", "--legacy"},
			[]string{"! username lab-admin privilege 15 secret 5 <HASH>\n"}, []string{"scrypt"}, "lab-admin (admin)"},
		{[]string{"config", "juniper", "--scope", "lab"},
			[]string{"# set system login user lab-admin class RW-CLASS authentication encrypted-password '<HASH>'\n",
				"# set system login user lab-ops class OP-CLASS authentication encrypted-password '<HASH>'\n"}, []string{"prod-ro"}, "lab-admin (admin)"},
		{[]string{"config", "wti", "--scope", "prod"},
			[]string{"prod-ro  Access Level: ViewOnly  Password: <PASSWORD>\n"}, []string{"lab-admin", "lab-ops"}, "prod-ro (readonly)"},
		{[]string{"config", "wti", "--scope", "lab"},
			[]string{"lab-admin  Access Level: Administrator  Password: <PASSWORD>\n"}, []string{"prod-ro"}, "lab-admin (admin), lab-ops (operator)"},
		{[]string{"config", "cisco", "--scope", "dmz"},
			[]string{"No break-glass local user is recorded for scope 'dmz'"}, []string{"lab-admin", "Unfilled break-glass"}, ""},
	} {
		out := sb.cfgRun("", c.args, route)
		sb.expect(0, "", "")
		out = plain(out)
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v lacks %q:\n%s", c.args, w, out)
			}
		}
		for _, n := range c.not {
			if strings.Contains(out, n) {
				t.Errorf("%v holds %q:\n%s", c.args, n, out)
			}
		}
		if c.unfilledIn != "" && !strings.Contains(out, "Unfilled break-glass credentials (tacctl stores none; put in your own): "+c.unfilledIn) {
			t.Errorf("%v: no Unfilled line with %q:\n%s", c.args, c.unfilledIn, out)
		}
	}
	// No credential anywhere in the file.
	if o := sb.overrides(); strings.Contains(o, "HASH") || strings.Contains(o, "secret") || strings.Contains(o, "password") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
}

// 'config validate' warns, without failing, for a scope without a break-glass
// user, and for a recorded name that a tacctl user of the scope has since taken.
func TestScopeBreakGlassValidateWarns(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"config", "render"})
	sb.run("", []string{"config", "validate"})
	out := plain(sb.out.String())
	// One line, naming the scopes.
	if !strings.Contains(out, "Break-glass:          scopes 'dmz', 'lab', 'prod', 'prod-inner' without a break-glass local user — a lockout risk") ||
		strings.Count(out, "Break-glass:") != 1 {
		t.Errorf("the warning is not one line naming the scopes:\n%s", out)
	}
	sb.expect(0, "Configuration is valid.", "")
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"config", "validate"})
	out = plain(sb.out.String())
	if strings.Contains(out, "'lab'") || !strings.Contains(out, "scopes 'dmz', 'prod', 'prod-inner' without a break-glass") {
		t.Errorf("after adding to lab:\n%s", out)
	}
	sb.expect(0, "Configuration is valid.", "")
	// A hand edit that names a tacctl user of the scope.
	sb.write("state/tacctl.yaml", "breakglass_scope:\n  lab:\n    users: [bob:admin]\n", 0o600)
	sb.run("", []string{"config", "validate"})
	sb.expect(0, "'bob' in scope 'lab' is also a tacctl user of the scope", "")
	// A hand edit the schema refuses is an error with its path.
	sb.write("state/tacctl.yaml", "breakglass_scope:\n  lab:\n    users: [lab-admin:boss]\n", 0o600)
	sb.run("", []string{"config", "validate"})
	sb.expect(1, "breakglass_scope.lab.users: element 0: the role of 'lab-admin' must be one of", "")
}

// Superuser-only: an engineer reads the walkthrough of their scope, with the
// accounts in it, and cannot run the verb in any form.
func TestScopeBreakGlassEngineerTier(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.expect(0, "recorded", "")
	for _, args := range [][]string{{"scope", "breakglass", "lab"}, {"scope", "breakglass", "lab", "list"},
		{"scope", "breakglass", "lab", "add", "x"}, {"scope", "breakglass", "lab", "remove", "lab-admin"},
		{"scope", "breakglass", "prod", "add", "x"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if !strings.Contains(sb.overrides(), "lab-admin:admin") || strings.Contains(sb.overrides(), "x:admin") {
		t.Errorf("tacctl.yaml:\n%s", sb.overrides())
	}
	for _, v := range []string{"cisco", "juniper", "wti"} {
		out := sb.cfgRun("", []string{"config", v, "--scope", "lab"}, func(r *fake.Runner) {
			route(r)
			r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
		}, "SUDO_USER=bob")
		sb.expect(0, "", "")
		if !strings.Contains(plain(out), "lab-admin") || !strings.Contains(plain(out), "Unfilled break-glass credentials") {
			t.Errorf("config %s as an engineer:\n%s", v, plain(out))
		}
	}
	// scope show for their scope says what is recorded.
	if out := sb.asEngineer("", "scope", "show", "lab"); !strings.Contains(out, "Break-glass:    lab-admin (admin)") {
		t.Errorf("scope show:\n%s", out)
	}
}
