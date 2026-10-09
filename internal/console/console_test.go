package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

func write(t *testing.T, dir, name, text string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAbsentFileIsTheDefaults(t *testing.T) {
	f, err := Load(filepath.Join(t.TempDir(), "console.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tr := range Tiers {
		if !f.TierOn[tr] {
			t.Errorf("tier %s is off by default", tr)
		}
	}
	if len(f.Users) != 0 || f.Idle != 30 || f.AgentForwarding || f.SSHEscape || f.SystemShell != "/bin/bash" ||
		!reflect.DeepEqual(f.SystemShellTiers, []tier.Tier{tier.Superuser}) ||
		!reflect.DeepEqual(f.ForwardingTiers, []tier.Tier{tier.Superuser}) || f.ListMax != 40 || !f.SpaceCompletion {
		t.Errorf("defaults: %+v", f)
	}
}

func TestMutateRoundTripAndMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state", "console.yaml")
	var before int
	changed, err := Mutate(p, func() error { before++; return nil }, func(f *File) error {
		f.TierOn[tier.Readonly] = false
		f.Users["jdoe"] = true
		f.Users["asmith"] = false
		f.Idle = 0
		f.AgentForwarding = true
		f.SSHEscape = true
		f.SystemShell = "/bin/sh"
		f.SystemShellTiers = []tier.Tier{tier.Operator, tier.Superuser}
		f.ForwardingTiers = nil
		f.ListMax = 100
		return nil
	})
	if err != nil || !changed || before != 1 {
		t.Fatalf("Mutate: %v %v %d", changed, err, before)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v %v", st, err)
	}
	want := Header + `version: 1
tiers: {readonly: disable, operator: enable, engineer: enable, superuser: enable}
users: {asmith: disable, jdoe: enable}
settings:
  idle_timeout: 0
  agent_forwarding: true
  ssh_escape: true
  system_shell: /bin/sh
  system_shell_tiers: [operator, superuser]
  forwarding_tiers: []
  gateway_ports: false
  list_max: 100
`
	if got, _ := os.ReadFile(p); string(got) != want {
		t.Errorf("file:\n%s\nwant:\n%s", got, want)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.TierOn[tier.Readonly] || !f.Users["jdoe"] || f.Users["asmith"] || f.Idle != 0 || !f.AgentForwarding || !f.SSHEscape ||
		f.SystemShell != "/bin/sh" || !reflect.DeepEqual(f.SystemShellTiers, []tier.Tier{tier.Operator, tier.Superuser}) ||
		len(f.ForwardingTiers) != 0 || f.ListMax != 100 {
		t.Errorf("round trip: %+v", f)
	}
	// The same change again writes nothing; a refusal writes nothing and
	// the snapshot hook runs first either way.
	changed, err = Mutate(p, nil, func(f *File) error { f.Idle = 0; return nil })
	if err != nil || changed {
		t.Errorf("no-op: %v %v", changed, err)
	}
	if _, err := Mutate(p, nil, func(f *File) error { f.Idle = 5000; return nil }); err == nil {
		t.Error("idle 5000 accepted")
	}
	if got, _ := os.ReadFile(p); string(got) != want {
		t.Error("a refused change was written")
	}
	// An empty system_shell_tiers and no users read back.
	if _, err := Mutate(p, nil, func(f *File) error { f.SystemShellTiers = nil; f.Users = map[string]bool{}; return nil }); err != nil {
		t.Fatal(err)
	}
	if f, err = Load(p); err != nil || len(f.SystemShellTiers) != 0 || len(f.Users) != 0 {
		t.Errorf("empty lists: %+v %v", f, err)
	}
	// A snapshot that fails stops the write.
	if _, err := Mutate(p, func() error { return os.ErrPermission }, func(*File) error { t.Error("fn ran"); return nil }); err == nil {
		t.Error("before's error ignored")
	}
}

// settings.space_completion is written only when it is off; a file without
// the key reads as on (see TestRollbackToTheOldParser for 0.2.2).
func TestSpaceCompletionSetting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.yaml")
	if _, err := Mutate(p, nil, func(f *File) error { f.Idle = 5; return nil }); err != nil {
		t.Fatal(err)
	}
	on, _ := os.ReadFile(p)
	if strings.Contains(string(on), "space_completion") {
		t.Errorf("the key is written while on:\n%s", on)
	}
	if f, err := Load(p); err != nil || !f.SpaceCompletion {
		t.Errorf("a file without the key: %+v %v", f, err)
	}

	changed, err := Mutate(p, nil, func(f *File) error { f.SpaceCompletion = false; return nil })
	if err != nil || !changed {
		t.Fatalf("off: %v %v", changed, err)
	}
	off, _ := os.ReadFile(p)
	if want := string(on) + "  space_completion: false\n"; string(off) != want {
		t.Errorf("file off:\n%s\nwant:\n%s", off, want)
	}
	f, err := Load(p)
	if err != nil || f.SpaceCompletion || f.Idle != 5 {
		t.Errorf("round trip off: %+v %v", f, err)
	}
	if pol := NewPolicy(f, paths.Paths{}); pol.SpaceCompletion() {
		t.Error("the policy says on")
	}

	// Back on: the key disappears and the bytes are those of the file that
	// never had it.
	if _, err := Mutate(p, nil, func(f *File) error { f.SpaceCompletion = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(p); string(again) != string(on) {
		t.Errorf("file on again:\n%s\nwant:\n%s", again, on)
	}

	// The values: a boolean, true or false.
	q := write(t, dir, "explicit.yaml", "version: 1\nsettings: {space_completion: true}\n", 0o600)
	if f, err := Load(q); err != nil || !f.SpaceCompletion {
		t.Errorf("explicit true: %+v %v", f, err)
	}
	q = write(t, dir, "bad.yaml", "version: 1\nsettings: {space_completion: maybe}\n", 0o600)
	if _, err := Load(q); err == nil || !strings.Contains(err.Error(), "invalid value for 'space_completion'") {
		t.Errorf("a non-boolean: %v", err)
	}
}

func TestInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ name, text, err string }{
		{"not yaml", "a: [", "not valid YAML"},
		{"list", "- a\n", "expected a mapping"},
		{"version", "version: 2\n", "unsupported version"},
		{"unknown key", "version: 1\nfoo: 1\n", "unknown key 'foo'"},
		{"unknown tier", "version: 1\ntiers: {root: enable}\n", "unknown tier or value for 'root'"},
		{"bad tier value", "version: 1\ntiers: {readonly: true}\n", "unknown tier or value for 'readonly'"},
		{"tiers not map", "version: 1\ntiers: [readonly]\n", "tiers must be a mapping"},
		{"bad user name", "version: 1\nusers: {'a b': enable}\n", "invalid user name 'a b'"},
		{"bad user value", "version: 1\nusers: {jdoe: yes}\n", "users: 'jdoe' must be enable or disable"},
		{"idle high", "version: 1\nsettings: {idle_timeout: 1441}\n", "idle_timeout must be 0-1440"},
		{"idle negative", "version: 1\nsettings: {idle_timeout: -1}\n", "idle_timeout must be 0-1440"},
		{"idle text", "version: 1\nsettings: {idle_timeout: soon}\n", "invalid value for 'idle_timeout'"},
		{"list_max zero", "version: 1\nsettings: {list_max: 0}\n", "list_max must be 1-1000"},
		{"agent not bool", "version: 1\nsettings: {agent_forwarding: enable}\n", "invalid value for 'agent_forwarding'"},
		{"relative shell", "version: 1\nsettings: {system_shell: bash}\n", "must be an absolute path"},
		{"unclean shell", "version: 1\nsettings: {system_shell: /bin/../bin/bash}\n", "must be an absolute path"},
		{"shell with space", "version: 1\nsettings: {system_shell: '/bin/my sh'}\n", "must be an absolute path"},
		{"tier repeat", "version: 1\nsettings: {system_shell_tiers: [operator, operator]}\n", "invalid or repeated tier 'operator'"},
		{"tier unknown", "version: 1\nsettings: {system_shell_tiers: [root]}\n", "invalid or repeated tier 'root'"},
		{"tiers scalar", "version: 1\nsettings: {system_shell_tiers: superuser}\n", "invalid value for 'system_shell_tiers'"},
		{"unknown setting", "version: 1\nsettings: {accounting: journal}\n", "unknown key 'accounting'"},
	} {
		p := write(t, dir, "bad.yaml", c.text, 0o600)
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.err)
		}
	}
	// An unreadable path is an error, not the defaults.
	if _, err := Load(dir); err == nil {
		t.Error("a directory read as the defaults")
	}
	// A partial file keeps the other defaults.
	f, err := Load(write(t, dir, "partial.yaml", "version: 1\nsettings: {idle_timeout: 5}\n", 0o600))
	if err != nil || f.Idle != 5 || !f.TierOn[tier.Operator] || f.SystemShell != "/bin/bash" {
		t.Errorf("partial: %+v %v", f, err)
	}
}

func TestParseTiers(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []tier.Tier
		bad  bool
	}{
		{"superuser", []tier.Tier{tier.Superuser}, false},
		{"readonly,operator,superuser", []tier.Tier{tier.Readonly, tier.Operator, tier.Superuser}, false},
		{"none", nil, false},
		{"", nil, false},
		{"operator,operator", nil, true},
		{"operator,", nil, true},
		{"admin", nil, true},
		{"none,operator", nil, true},
		{"Operator", nil, true},
		{"engineer", nil, true},
		{"superuser,engineer", nil, true},
	} {
		got, err := ParseTiers(c.in, "system-shell")
		if (err != nil) != c.bad || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: %v %v", c.in, got, err)
		}
	}
	for what, want := range map[string]string{
		"system-shell": "The engineer tier cannot be given the system shell on this server: a shell here would reach the server's secrets. Nothing was changed.",
		"forwarding":   "The engineer tier cannot be given forwarding on this server: engineers reach devices with the console's ssh. Nothing was changed.",
	} {
		if _, err := ParseTiers("operator,engineer", what); err == nil || err.Error() != want {
			t.Errorf("%s: %v", what, err)
		}
	}
}

// The engineer tier has a console switch (on by default, and in a file
// written before it existed), but never the system shell or forwarding,
// whatever a hand-edited file says.
func TestEngineerTier(t *testing.T) {
	dir := t.TempDir()
	f, err := Load(write(t, dir, "old.yaml", "version: 1\ntiers: {readonly: enable, operator: disable, superuser: enable}\n", 0o600))
	if err != nil || !f.TierOn[tier.Engineer] || f.TierOn[tier.Operator] {
		t.Fatalf("old file: %+v %v", f, err)
	}
	if text, err := f.Text(); err != nil || !strings.Contains(string(text), "engineer: enable") {
		t.Errorf("text: %s %v", text, err)
	}
	for _, body := range []string{
		"version: 1\nsettings: {system_shell_tiers: [superuser, engineer]}\n",
		"version: 1\nsettings: {forwarding_tiers: [engineer]}\n",
	} {
		if _, err := Load(write(t, dir, "bad.yaml", body, 0o600)); err == nil || !strings.Contains(err.Error(), "invalid or repeated tier 'engineer'") {
			t.Errorf("%q: %v", body, err)
		}
	}
	f = Defaults()
	f.SystemShellTiers = append(f.SystemShellTiers, tier.Engineer)
	f.ForwardingTiers = append(f.ForwardingTiers, tier.Engineer)
	p := &Policy{File: f, Command: "/usr/local/bin/tacctl-console"}
	if p.SystemShell(tier.Engineer) || p.Forwarding(tier.Engineer) || !p.SystemShell(tier.Superuser) {
		t.Error("engineer gets the system shell or forwarding")
	}
	if d := p.Decide("bob", tier.Engineer); !d.Console || d.Why != "tier engineer (always)" {
		t.Errorf("decide: %+v", d)
	}
	if TierGroup(tier.Engineer) != "tac-engineer" {
		t.Errorf("group %q", TierGroup(tier.Engineer))
	}
}

// The policy table: tier x tier switch x user override.
func TestPolicyDecisions(t *testing.T) {
	cmd := "/usr/local/bin/tacctl-console"
	for _, c := range []struct {
		name  string
		edit  func(*File)
		user  string
		t     tier.Tier
		want  string
		shell string
	}{
		{"default readonly", func(*File) {}, "u", tier.Readonly, "tier readonly", cmd},
		{"default operator", func(*File) {}, "u", tier.Operator, "tier operator", cmd},
		{"default superuser", func(*File) {}, "u", tier.Superuser, "tier superuser", cmd},
		{"tier off", func(f *File) { f.TierOn[tier.Readonly] = false }, "u", tier.Readonly, "tier readonly disabled", "/bin/bash"},
		{"other tier unaffected", func(f *File) { f.TierOn[tier.Readonly] = false }, "u", tier.Operator, "tier operator", cmd},
		{"override on beats tier off", func(f *File) { f.TierOn[tier.Readonly] = false; f.Users["u"] = true }, "u", tier.Readonly, "user override", cmd},
		{"override off beats tier on", func(f *File) { f.Users["u"] = false }, "u", tier.Superuser, "user override", "/bin/bash"},
		{"override of another user", func(f *File) { f.Users["v"] = false }, "u", tier.Superuser, "tier superuser", cmd},
		{"none", func(*File) {}, "u", tier.None, "no tier", "/usr/sbin/nologin"},
		{"none with override", func(f *File) { f.Users["u"] = true }, "u", tier.None, "no tier", "/usr/sbin/nologin"},
		{"unknown tier", func(*File) {}, "u", tier.Tier("bogus"), "no tier", "/usr/sbin/nologin"},
		// The engineer tier has the console or no login: neither the tier's
		// switch nor a user override turns it off.
		{"engineer", func(*File) {}, "u", tier.Engineer, "tier engineer (always)", cmd},
		{"engineer tier off", func(f *File) { f.TierOn[tier.Engineer] = false }, "u", tier.Engineer, "tier engineer (always)", cmd},
		{"engineer override off", func(f *File) { f.Users["u"] = false }, "u", tier.Engineer, "tier engineer (always)", cmd},
		{"unrestricted", func(*File) {}, "u", tier.Unrestricted, "no tier", "/bin/bash"},
	} {
		f := Defaults()
		c.edit(f)
		p := &Policy{File: f, Command: cmd}
		d := p.Decide(c.user, c.t)
		if d.Why != c.want || d.Console != (c.shell == cmd) || p.Shell(c.user, c.t) != c.shell {
			t.Errorf("%s: %+v shell %q", c.name, d, p.Shell(c.user, c.t))
		}
	}
}

func TestPolicySystemShellAndSettings(t *testing.T) {
	f := Defaults()
	p := &Policy{File: f}
	for _, c := range []struct {
		t    tier.Tier
		want bool
	}{
		{tier.Superuser, true}, {tier.Operator, false}, {tier.Readonly, false}, {tier.Unrestricted, true}, {tier.None, false},
	} {
		if got := p.SystemShell(c.t); got != c.want {
			t.Errorf("default %s: %v", c.t, got)
		}
	}
	f.SystemShellTiers = []tier.Tier{tier.Readonly, tier.Operator}
	if !p.SystemShell(tier.Readonly) || p.SystemShell(tier.Superuser) || !p.SystemShell(tier.Unrestricted) || p.SystemShell(tier.None) {
		t.Error("custom tiers")
	}
	f.SystemShellTiers = nil
	if p.SystemShell(tier.Superuser) || p.SystemShell(tier.Readonly) || !p.SystemShell(tier.Unrestricted) {
		t.Error("no tiers")
	}
	f.Idle = 7
	f.ListMax = 12
	f.SSHEscape, f.AgentForwarding = true, true
	if p.Idle().Minutes() != 7 || p.ListMax() != 12 || !p.SSHEscape() || !p.AgentForwarding() {
		t.Error("settings")
	}
	f.Idle = 0
	if p.Idle() != 0 {
		t.Error("idle 0")
	}
}

func TestCheckShell(t *testing.T) {
	dir := t.TempDir()
	exe := write(t, dir, "sh", "#!/bin/sh\n", 0o755)
	plainFile := write(t, dir, "data", "x", 0o644)
	shells := write(t, dir, "shells", "# comment\n\n"+exe+"\n  "+plainFile+"  \n/other/sh\n", 0o644)
	for _, c := range []struct{ path, err string }{
		{exe, ""},
		{"sh", "absolute path"},
		{"", "absolute path"},
		{dir + "/../" + filepath.Base(dir) + "/sh", "absolute path"},
		{filepath.Join(dir, "missing"), "is not an existing file"},
		{dir, "is not an existing file"},
		{plainFile, "is not executable"},
		{write(t, dir, "unlisted", "#!/bin/sh\n", 0o755), "is not listed in"},
	} {
		err := CheckShell(c.path, shells)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%q: %v", c.path, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%q: %v (want %q)", c.path, err, c.err)
		}
	}
	if err := CheckShell(exe, filepath.Join(dir, "no-shells")); err == nil || !strings.Contains(err.Error(), "Cannot read") {
		t.Errorf("no shells file: %v", err)
	}
	// A comment is not a listing.
	cm := write(t, dir, "shells2", "# "+exe+"\n", 0o644)
	if ok, _ := ShellListed(cm, exe); ok {
		t.Error("a comment listed the shell")
	}
	p := &Policy{File: &File{SystemShell: exe}, ShellsFile: shells}
	if got, err := p.SystemShellPath(); got != exe || err != nil {
		t.Errorf("SystemShellPath: %q %v", got, err)
	}
	p.ShellsFile = cm
	if got, err := p.SystemShellPath(); got != exe || err == nil {
		t.Errorf("SystemShellPath unlisted: %q %v", got, err)
	}
}

func TestInspect(t *testing.T) {
	dir := t.TempDir()
	p := paths.Resolve(paths.NewEnv([]string{"TACCTL_SSHD_DROPIN=" + filepath.Join(dir, "d.conf"), "TACCTL_SHELLS_FILE=" + filepath.Join(dir, "shells")}), "", func(string) bool { return false })
	p.ConsoleCommand = filepath.Join(dir, "tacctl-console")
	if pc := Inspect(p); pc.Exists || pc.Link != "" || pc.Shells || pc.DropIn {
		t.Errorf("empty: %+v", pc)
	}
	if err := os.Symlink("/usr/local/bin/tacctl", p.ConsoleCommand); err != nil {
		t.Fatal(err)
	}
	write(t, dir, "shells", "/bin/sh\n"+p.ConsoleCommand+"\n", 0o644)
	write(t, dir, "d.conf", "Match Group tac-console\n", 0o644)
	if pc := Inspect(p); !pc.Exists || pc.Link != "/usr/local/bin/tacctl" || !pc.Shells || !pc.DropIn {
		t.Errorf("in place: %+v", pc)
	}
	// A regular file where the symlink should be is present but not a link.
	_ = os.Remove(p.ConsoleCommand)
	write(t, dir, "tacctl-console", "x", 0o755)
	if pc := Inspect(p); !pc.Exists || pc.Link != "" {
		t.Errorf("regular file: %+v", pc)
	}
}

func TestSSHDCheck(t *testing.T) {
	ctx := context.Background()
	run := func(res execx.Result) (SSHD, *fake.Runner, error) {
		r := &fake.Runner{}
		r.On([]string{"sshd"}, res)
		s, err := SSHDCheck(ctx, r, "jdoe")
		return s, r, err
	}
	const fc = "forcecommand /usr/local/bin/tacctl-console\npubkeyauthentication no\n"
	s, r, err := run(execx.Result{Stdout: []byte("port 22\nallowtcpforwarding no\nallowagentforwarding no\nx11forwarding no\n" + fc)})
	if err != nil || s != (SSHD{"no", "no", "/usr/local/bin/tacctl-console", "no", "no", "", ""}) || !r.Called("sshd", "-T", "-C", "user=jdoe,host=localhost,addr=127.0.0.1") {
		t.Errorf("closed: %+v %v %q", s, err, r.Argvs())
	}
	if p := s.Problems(false, false, false, testConsole); len(p) != 0 {
		t.Errorf("problems: %v", p)
	}
	s, _, _ = run(execx.Result{Stdout: []byte("allowtcpforwarding yes\nallowagentforwarding yes\n" + fc)})
	if p := s.Problems(false, false, false, testConsole); !reflect.DeepEqual(p, []string{"allowtcpforwarding is 'yes'", "allowagentforwarding is 'yes'"}) {
		t.Errorf("open: %v", p)
	}
	// A user of a forwarding tier (console forwarding tiers): TCP forwarding is as designed.
	if p := s.Problems(false, true, false, testConsole); !reflect.DeepEqual(p, []string{"allowagentforwarding is 'yes'"}) {
		t.Errorf("forwarding tier: %v", p)
	}
	// X11 open for a tier that may not forward (a value read before the
	// drop-in): a problem; DisableForwarding yes closes it all anyway.
	s, _, _ = run(execx.Result{Stdout: []byte("allowtcpforwarding no\nallowagentforwarding no\nx11forwarding yes\ndisableforwarding no\n" + fc)})
	if p := s.Problems(false, false, false, testConsole); !reflect.DeepEqual(p, []string{"x11forwarding is 'yes'"}) {
		t.Errorf("x11 open: %v", p)
	}
	s, _, _ = run(execx.Result{Stdout: []byte("allowtcpforwarding yes\nallowagentforwarding no\nx11forwarding yes\ndisableforwarding yes\n" + fc)})
	if p := s.Problems(false, false, false, testConsole); len(p) != 0 {
		t.Errorf("disableforwarding yes: %v", p)
	}
	// Without the drop-in: nothing forced, key logins on.
	s, _, _ = run(execx.Result{Stdout: []byte("allowtcpforwarding no\nallowagentforwarding no\nforcecommand none\npubkeyauthentication yes\n")})
	if p := s.Problems(false, false, false, testConsole); !reflect.DeepEqual(p, []string{"forcecommand is 'none'", "pubkeyauthentication is 'yes'"}) {
		t.Errorf("no drop-in: %v", p)
	}
	s, _, _ = run(execx.Result{Stdout: []byte("allowtcpforwarding yes\nallowagentforwarding yes\n" + fc)})
	if p := s.Problems(true, false, false, testConsole); !reflect.DeepEqual(p, []string{"allowtcpforwarding is 'yes'"}) {
		t.Errorf("agent allowed: %v", p)
	}
	// Gateway ports: only for a user who may forward, with gateway-ports on;
	// moot when forwarding is closed.
	gw := SSHD{TCPForwarding: "yes", AgentForwarding: "no", ForceCommand: testConsole, PubkeyAuth: "no", GatewayPorts: "clientspecified"}
	if p := gw.Problems(false, true, false, testConsole); !reflect.DeepEqual(p, []string{"gatewayports is 'clientspecified'"}) {
		t.Errorf("gatewayports, gateway-ports off: %v", p)
	}
	if p := gw.Problems(false, true, true, testConsole); len(p) != 0 {
		t.Errorf("gatewayports, gateway-ports on: %v", p)
	}
	gw.TCPForwarding = "no"
	if p := gw.Problems(false, false, true, testConsole); len(p) != 0 {
		t.Errorf("gatewayports with forwarding closed: %v", p)
	}
	for _, v := range []string{"local", "remote", "all"} {
		if p := (SSHD{TCPForwarding: v, AgentForwarding: "no", ForceCommand: testConsole, PubkeyAuth: "no"}).Problems(false, false, false, testConsole); len(p) != 1 {
			t.Errorf("allowtcpforwarding %s: %v", v, p)
		}
	}
	if _, _, err = run(execx.Result{Code: 255, Stderr: []byte("Missing Match criteria for address\nmore\n")}); err == nil || !strings.Contains(err.Error(), "sshd -T failed: Missing Match criteria for address") {
		t.Errorf("failure: %v", err)
	}
	if _, _, err = run(execx.Result{Code: 1}); err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("silent failure: %v", err)
	}
	if _, _, err = run(execx.Result{Stdout: []byte("port 22\n")}); err == nil || !strings.Contains(err.Error(), "no forwarding settings") {
		t.Errorf("no settings: %v", err)
	}
	m := &fake.Runner{}
	m.Missing("sshd")
	if _, err := SSHDCheck(ctx, m, "jdoe"); err == nil || !strings.Contains(err.Error(), "sshd could not be run") {
		t.Errorf("missing sshd: %v", err)
	}
}

// accepts022 is the part of 0.2.2's console.yaml parser that matters for a
// rollback, as a fixture (parse and parseSettings of internal/console/config.go
// at the 0.2.2 tag): under 'tiers' only readonly, operator and superuser are
// known, and under 'settings' only the keys listed here; any other makes it
// fail, and the console falls back to the defaults.
func accepts022(text []byte) error {
	v, err := pyyaml.LoadBytes(text)
	if err != nil {
		return err
	}
	root := v.(*yamlpy.Map)
	// In this order, so the error a file gets is always the same.
	known := []struct {
		section string
		keys    []string
	}{
		{"tiers", []string{"readonly", "operator", "superuser"}},
		{"settings", []string{"idle_timeout", "list_max", "agent_forwarding", "ssh_escape", "gateway_ports",
			"system_shell", "system_shell_tiers", "forwarding_tiers"}},
	}
	for _, kn := range known {
		section, keys := kn.section, kn.keys
		sub, ok := root.Get(section)
		if !ok {
			continue
		}
		for k := range sub.(*yamlpy.Map).All() {
			if !slices.Contains(keys, k) {
				return errors.New(section + ": unknown key '" + k + "'")
			}
		}
	}
	return nil
}

// A console.yaml that 0.2.3 writes is not one 0.2.2 reads, whether or not
// space completion was ever turned off: the engineer tier's switch
// (tiers.engineer) is written on every write, and 0.2.2 rejects it. So
// going back to 0.2.2 needs the rollback step (tacctl rollback 0.2.2),
// which takes tiers.engineer and settings.space_completion out of the file.
// This test pins the two keys that step has to remove (doc writes them) and
// that the file without them is one the 0.2.2 fixture accepts.
func TestRollbackToTheOldParser(t *testing.T) {
	for _, off := range []bool{false, true} {
		f := Defaults()
		f.SpaceCompletion = !off
		text, err := f.Text()
		if err != nil {
			t.Fatal(err)
		}
		if err := accepts022(text); err == nil || !strings.Contains(err.Error(), "engineer") {
			t.Errorf("space completion off %v: want a rejection naming engineer, got %v\n%s", off, err, text)
		}
		v, err := pyyaml.LoadBytes(text)
		if err != nil {
			t.Fatal(err)
		}
		root := v.(*yamlpy.Map)
		tiers, _ := root.Get("tiers")
		settings, _ := root.Get("settings")
		if !tiers.(*yamlpy.Map).Has("engineer") {
			t.Errorf("no tiers.engineer is written:\n%s", text)
		}
		if settings.(*yamlpy.Map).Has("space_completion") != off {
			t.Errorf("space_completion written: %v, off: %v:\n%s", !off, off, text)
		}
		// tiers.engineer alone out: still rejected when space_completion is
		// written (off), accepted when it is not (on).
		tiers.(*yamlpy.Map).Delete("engineer")
		half, err := yamlpy.EmitChecked(root, yamlpy.StoreOptions, Header, pyyaml.LoadBytes)
		if err != nil {
			t.Fatal(err)
		}
		err = accepts022(half)
		if off && (err == nil || !strings.Contains(err.Error(), "space_completion")) {
			t.Errorf("space completion off: without tiers.engineer: %v\n%s", err, half)
		}
		if !off && err != nil {
			t.Errorf("space completion on: without tiers.engineer still rejected: %v\n%s", err, half)
		}
		// The rollback step: both keys out.
		settings.(*yamlpy.Map).Delete("space_completion")
		stripped, err := yamlpy.EmitChecked(root, yamlpy.StoreOptions, Header, pyyaml.LoadBytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := accepts022(stripped); err != nil {
			t.Errorf("space completion off %v: still rejected after the step: %v\n%s", off, err, stripped)
		}
	}
}
