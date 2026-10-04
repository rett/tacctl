package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func hasLineRE(t *testing.T, out, pattern string) {
	t.Helper()
	if !regexp.MustCompile("(?m)" + pattern).MatchString(plain(out)) {
		t.Errorf("no line matching %q in\n%s", pattern, plain(out))
	}
}

func TestStatusOneBackendNoHeadings(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	out := sb.run("", []string{"status", "extra"})
	sb.expect(0, "Service Status", "")
	hasLineRE(t, out, `^  Users: +3$`)
	hasLineRE(t, out, `^  Config: +.*/etc/tacquito.yaml$`)
	hasLineRE(t, out, `^  Config backups: +0$`)
	hasLineRE(t, out, `^    Prefix scope: +[0-9]+ CIDR\(s\) across all scopes$`)
	hasLineRE(t, out, `^    Management ACL: +EMPTY`)
	hasLineRE(t, out, `^    Scopes: +configured \(4 scope\(s\), [0-9]+ user grant\(s\)\)$`)
	hasLineRE(t, out, `^    Default scope: +lab$`)
	hasLineRE(t, out, `^  Password Age Warnings:$`)
	if strings.Contains(out, "== Backend:") {
		t.Error("one backend prints no headings")
	}
}

func TestStatusTwoBackendsASectionEachAndTheV6Parity(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\nlisteners:\n  radius:\n    auth:\n      network: udp6\n      address: '[::]:1812'\n", 0o600)
	out := sb.run("", []string{"status"})
	sb.expect(0, "== Backend: tacacs (tacacs, tacquito) ==", "")
	sb.expect(0, "== Backend: radius (radius, freeradius) ==", "")
	if strings.Index(out, "Config backups:") > strings.Index(out, "== Backend: tacacs") {
		t.Error("the backup count belongs above the backend sections")
	}
	hasLineRE(t, out, `^    IPv6 ACL parity: +MISSING \(radius listener auth is udp6 but no IPv6 CIDRs`)
}

func TestStatusAStoreThatCannotBeReadIsReportedOnce(t *testing.T) {
	sb := newSandbox(t, false)
	sandboxRADIUS(sb)
	sb.write("state/store.yaml", "users: [this is not a store\n", 0o600)
	out := sb.run("", []string{"status"})
	if sb.code != 0 || strings.Count(sb.err.String(), "tacctl store:") != 1 {
		t.Errorf("exit %d, stderr %q", sb.code, sb.err.String())
	}
	hasLineRE(t, out, `^  Users: +0$`)
	hasLineRE(t, out, `^    Default scope: +UNSET`)
}

func TestStatusPasswordAge(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	store := sb.store()
	store = strings.Replace(store, "    group: superuser\n", "    group: superuser\n    password_changed: '2000-01-01'\n", 1)
	sb.write("state/store.yaml", store, 0o600)
	out := sb.run("", []string{"status"}, "TACCTL_TEST_NOW=2000-04-10T12:00:00Z")
	if !strings.Contains(plain(out), "password is ") && !strings.Contains(plain(out), "No passwords older than") {
		t.Fatalf("no password age section:\n%s", out)
	}
	sb.run("", []string{"config", "password-age", "1"})
	out = sb.run("", []string{"status"})
	hasLineRE(t, out, `^    alice: password is [0-9]+ days old \(changed 2000-01-01\)$`)
}

func TestLogArgumentsAndHeadings(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	for _, c := range []struct {
		args        []string
		code        int
		stdout, err string
	}{
		{[]string{"log"}, 1, "Usage: tacctl log <subcommand> [--backend <id>] [arguments]", ""},
		{[]string{"log", "--backend", "tacacs", "tail"}, 1, "clear [--force|-y]", ""},
		{[]string{"log", "tail", "--backend"}, 1, "", "--backend needs a backend id. Usage: tacctl log tail [--backend <id>] ..."},
		{[]string{"log", "tail", "--backend", "nope"}, 1, "", "Unknown backend 'nope' (known: tacacs radius)."},
		{[]string{"log", "accounting", "--backend=radius"}, 0, "Recent RADIUS Accounting Records", ""},
		{[]string{"log", "tail", "7", "--backend=nope", "--backend="}, 0, "Recent TACACS+ Log Entries", ""},
	} {
		sb.run("", c.args)
		sb.expect(c.code, c.stdout, c.err)
	}
	if !sb.runner.Called("journalctl", "-u", "tacquito", "--no-pager", "-n", "7") {
		t.Errorf("journalctl: %q", sb.runner.Argvs())
	}
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\n", 0o600)
	out := sb.run("", []string{"log", "accounting", "3"})
	sb.expect(0, "== Backend: radius (radius, freeradius) ==", "")
	if strings.Index(out, "Backend: tacacs") > strings.Index(out, "Backend: radius") {
		t.Error("sections out of order")
	}
	sb.run("", []string{"log", "search"})
	sb.expect(1, "", "Usage: tacctl log search <username>")
	if strings.Contains(sb.out.String(), "Backend: radius") {
		t.Error("a failing backend must end the command")
	}
}

func TestBackendListStatusAndUsage(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	out := sb.run("", []string{"backend", "list"})
	sb.expect(0, "IMPLEMENTATION", "")
	hasLineRE(t, out, `^  tacacs +tacacs +tacquito +no +yes +- +$`)
	hasLineRE(t, out, `^  radius +radius +freeradius +no +no +- +$`)
	out = sb.run("", []string{"backend", "status"})
	sb.expect(0, "== Backend: tacacs (tacacs, tacquito) ==", "")
	hasLineRE(t, out, `^  State: +not installed, enabled$`)
	hasLineRE(t, out, `^  State: +not installed, not enabled$`)
	sb.run("", []string{"backend", "status", ""})
	sb.expect(1, "", "Missing backend id (known: tacacs radius).")
	sb.run("", []string{"backend", "status", "nope"})
	sb.expect(1, "", "Unknown backend 'nope' (known: tacacs radius).")
	sb.run("", []string{"backend"})
	sb.expect(1, "Backends: tacacs radius\n", "")
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, ldap]\n", 0o600)
	for _, args := range [][]string{{"backend", "list"}, {"backend", "status"}, {"status"}, {"log", "tail"}} {
		sb.run("", args)
		sb.expect(1, "", "backends.enabled names 'ldap', and this tacctl has no such backend (it has: tacacs radius).")
	}
	if names := sb.run("", []string{"_completion-names", "enabled-backends"}); names != "" || sb.code != 0 {
		t.Errorf("enabled-backends with a broken list: %d %q", sb.code, names)
	}
	if names := sb.run("", []string{"_completion-names", "backends"}); names != "tacacs\nradius\n" {
		t.Errorf("backends: %q", names)
	}
}

// Every native verb of the families of this file has a Spec, and every
// kind a Spec names is one completion can answer.
func TestWP24dSpecs(t *testing.T) {
	inv := &invocation{app: newHarness(t, nil).app}
	families := []struct {
		cmd   *cobra.Command
		specs map[string]Spec
	}{{backupCmd(inv), backupSpecs}, {backendCmd(inv), backendSpecs}, {storeCmd(inv), storeSpecs}, {logCmd(inv), logSpecs}}
	for _, f := range families {
		fam := f.cmd.Name()
		if len(f.cmd.Commands()) != len(f.specs) {
			t.Errorf("%s: %d specs for %d verbs", fam, len(f.specs), len(f.cmd.Commands()))
		}
		for _, c := range f.cmd.Commands() {
			spec, ok := f.specs[c.Name()]
			if !ok {
				t.Errorf("%s %s has no spec", fam, c.Name())
				continue
			}
			kinds := append([]string(nil), spec.Args...)
			for _, fl := range spec.Flags {
				kinds = append(kinds, fl.Kind)
			}
			for _, k := range kinds {
				k = strings.TrimSuffix(k, KindList)
				_, model := completionKinds[k]
				_, other := completionArgKinds[k]
				if k != "" && !model && !other && !strings.Contains(k, "|") && k != KindFile {
					t.Errorf("%s %s: kind %q is no completion kind", fam, c.Name(), k)
				}
			}
		}
	}
}

// 'store rollback' and 'backend enable|disable' come from files of their
// own, in place of the family's declared word.
func TestRegisterFamilyVerbReplacesTheStub(t *testing.T) {
	for _, c := range []struct{ family, name string }{{"store", "rollback"}, {"backend", "enable"}} {
		// The real registrations (store rollback: WP3.3a) come back after.
		prevStore, hadStore := storeVerbs[c.name]
		prevBackend, hadBackend := backendVerbs[c.name]
		registerFamilyVerb(c.family, c.name, func(inv *invocation) *cobra.Command {
			return withRun(verb(c.name, "a test verb"), inv.native(noPreflight, func(args []string) error {
				inv.write(c.name + " " + strings.Join(args, " ") + "\n")
				return nil
			}))
		})
		sb := newSandbox(t, true)
		if out := sb.run("", []string{c.family, c.name, "x"}); out != c.name+" x\n" || sb.code != 0 {
			t.Errorf("%s %s: %d %q", c.family, c.name, sb.code, out)
		}
		delete(storeVerbs, c.name)
		delete(backendVerbs, c.name)
		if hadStore {
			storeVerbs[c.name] = prevStore
		}
		if hadBackend {
			backendVerbs[c.name] = prevBackend
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("an unknown family must panic")
		}
	}()
	registerFamilyVerb("user", "x", nil)
}
