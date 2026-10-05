package console

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
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
		!reflect.DeepEqual(f.SystemShellTiers, []tier.Tier{tier.Superuser}) || f.ListMax != 40 {
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
tiers: {readonly: disable, operator: enable, superuser: enable}
users: {asmith: disable, jdoe: enable}
settings:
  idle_timeout: 0
  agent_forwarding: true
  ssh_escape: true
  system_shell: /bin/sh
  system_shell_tiers: [operator, superuser]
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
		f.SystemShell != "/bin/sh" || !reflect.DeepEqual(f.SystemShellTiers, []tier.Tier{tier.Operator, tier.Superuser}) || f.ListMax != 100 {
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
	} {
		got, err := ParseTiers(c.in)
		if (err != nil) != c.bad || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: %v %v", c.in, got, err)
		}
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
		{"none", func(*File) {}, "u", tier.None, "no tier", "/bin/bash"},
		{"none with override", func(f *File) { f.Users["u"] = true }, "u", tier.None, "no tier", "/bin/bash"},
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
	s, r, err := run(execx.Result{Stdout: []byte("port 22\nallowtcpforwarding no\nallowagentforwarding no\nx11forwarding no\n")})
	if err != nil || s != (SSHD{"no", "no"}) || !r.Called("sshd", "-T", "-C", "user=jdoe,host=localhost,addr=127.0.0.1") {
		t.Errorf("closed: %+v %v %q", s, err, r.Argvs())
	}
	if p := s.Problems(false); len(p) != 0 {
		t.Errorf("problems: %v", p)
	}
	s, _, _ = run(execx.Result{Stdout: []byte("allowtcpforwarding yes\nallowagentforwarding yes\n")})
	if p := s.Problems(false); !reflect.DeepEqual(p, []string{"allowtcpforwarding is 'yes'", "allowagentforwarding is 'yes'"}) {
		t.Errorf("open: %v", p)
	}
	if p := s.Problems(true); !reflect.DeepEqual(p, []string{"allowtcpforwarding is 'yes'"}) {
		t.Errorf("agent allowed: %v", p)
	}
	for _, v := range []string{"local", "remote", "all"} {
		if p := (SSHD{v, "no"}).Problems(false); len(p) != 1 {
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
