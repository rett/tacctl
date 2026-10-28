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
	"time"

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
	if len(f.IgnoredTiers) != 0 || len(f.IgnoredUsers) != 0 || f.Idle != 30 || f.AgentForwarding || f.SSHEscape || f.SystemShell != "/bin/bash" ||
		!reflect.DeepEqual(f.SystemShellTiers, []tier.Tier{tier.Superuser}) ||
		!reflect.DeepEqual(f.ForwardingTiers, []tier.Tier{tier.Superuser}) || f.ListMax != 40 || !f.SpaceCompletion {
		t.Errorf("defaults: %+v", f)
	}
	// The file is written with no console switch: neither a tiers nor a
	// users mapping.
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), "tiers:") && !strings.Contains(string(text), "system_shell_tiers:") ||
		strings.Contains(string(text), "\nusers:") || strings.Contains(string(text), "\ntiers:") {
		t.Errorf("a switch is written:\n%s", text)
	}
}

func TestMutateRoundTripAndMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state", "console.yaml")
	var before int
	changed, err := Mutate(p, func() error { before++; return nil }, func(f *File) error {
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
	if f.Idle != 0 || !f.AgentForwarding || !f.SSHEscape ||
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
	// An empty system_shell_tiers reads back.
	if _, err := Mutate(p, nil, func(f *File) error { f.SystemShellTiers = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if f, err = Load(p); err != nil || len(f.SystemShellTiers) != 0 {
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
	if err != nil || f.Idle != 5 || f.SystemShell != "/bin/bash" {
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

// The engineer tier never has the system shell or forwarding, whatever a
// hand-edited file says, and has the console.
func TestEngineerTier(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{
		"version: 1\nsettings: {system_shell_tiers: [superuser, engineer]}\n",
		"version: 1\nsettings: {forwarding_tiers: [engineer]}\n",
	} {
		if _, err := Load(write(t, dir, "bad.yaml", body, 0o600)); err == nil || !strings.Contains(err.Error(), "invalid or repeated tier 'engineer'") {
			t.Errorf("%q: %v", body, err)
		}
	}
	f := Defaults()
	f.SystemShellTiers = append(f.SystemShellTiers, tier.Engineer)
	f.ForwardingTiers = append(f.ForwardingTiers, tier.Engineer)
	p := &Policy{File: f, Command: "/usr/local/bin/tacctl-console"}
	if p.SystemShell(tier.Engineer) || p.Forwarding(tier.Engineer) || !p.SystemShell(tier.Superuser) {
		t.Error("engineer gets the system shell or forwarding")
	}
	if d := p.Decide(tier.Engineer); !d.Console || d.Why != "managed user" {
		t.Errorf("decide: %+v", d)
	}
	if TierGroup(tier.Engineer) != "tac-engineer" {
		t.Errorf("group %q", TierGroup(tier.Engineer))
	}
}

// A console.yaml written before 0.2.20 has a console switch per tier and per
// user. Nothing reads them: every tier has the console whatever they say,
// and the file keeps them as they were (an older release, after a rollback,
// reads them as it always did) when it is rewritten for another setting,
// without adding a tier the file did not name.
func TestIgnoredSwitchesAreKept(t *testing.T) {
	dir := t.TempDir()
	const old = "version: 1\ntiers: {readonly: disable, operator: disable, superuser: enable}\nusers: {asmith: disable, jdoe: enable}\n" +
		"settings: {idle_timeout: 7}\n"
	p := write(t, dir, "console.yaml", old, 0o600)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	pol := &Policy{File: f, Command: "/usr/local/bin/tacctl-console"}
	for _, tr := range Tiers {
		if d := pol.Decide(tr); !d.Console || pol.Shell(tr) != "/usr/local/bin/tacctl-console" {
			t.Errorf("tier %s: %+v shell %q", tr, d, pol.Shell(tr))
		}
	}
	if !reflect.DeepEqual(f.IgnoredTiers, map[tier.Tier]bool{tier.Readonly: false, tier.Operator: false, tier.Superuser: true}) ||
		!reflect.DeepEqual(f.IgnoredUsers, map[string]bool{"asmith": false, "jdoe": true}) {
		t.Errorf("read: %+v %+v", f.IgnoredTiers, f.IgnoredUsers)
	}
	if _, err := Mutate(p, nil, func(f *File) error { f.Idle = 9; return nil }); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	for _, want := range []string{"tiers: {readonly: disable, operator: disable, superuser: enable}", "users: {asmith: disable, jdoe: enable}", "idle_timeout: 9"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("%q is gone:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "engineer") {
		t.Errorf("a tier the file did not name was added:\n%s", got)
	}
	// The values are still checked: a bad one is as unreadable as ever, so
	// the older release's reader is not handed a file it rejects.
	if _, err := Load(write(t, dir, "bad.yaml", "version: 1\ntiers: {operator: off}\n", 0o600)); err == nil {
		t.Error("a bad stored value was accepted")
	}
}

// The policy table: every tier has the console, whatever the file says; a
// caller with no tier has none.
func TestPolicyDecisions(t *testing.T) {
	cmd := "/usr/local/bin/tacctl-console"
	for _, c := range []struct {
		name  string
		edit  func(*File)
		t     tier.Tier
		want  string
		shell string
	}{
		{"default readonly", func(*File) {}, tier.Readonly, "managed user", cmd},
		{"default operator", func(*File) {}, tier.Operator, "managed user", cmd},
		{"default engineer", func(*File) {}, tier.Engineer, "managed user", cmd},
		{"default superuser", func(*File) {}, tier.Superuser, "managed user", cmd},
		{"stored tier switch", func(f *File) { f.IgnoredTiers[tier.Readonly] = false; f.IgnoredTiers[tier.Engineer] = false }, tier.Readonly, "managed user", cmd},
		{"stored tier switch, engineer", func(f *File) { f.IgnoredTiers[tier.Engineer] = false }, tier.Engineer, "managed user", cmd},
		{"stored user override", func(f *File) { f.IgnoredUsers["u"] = false }, tier.Superuser, "managed user", cmd},
		{"none", func(*File) {}, tier.None, "no tier", "/usr/sbin/nologin"},
		{"unknown tier", func(*File) {}, tier.Tier("bogus"), "no tier", "/usr/sbin/nologin"},
		{"unrestricted", func(*File) {}, tier.Unrestricted, "no tier", "/bin/bash"},
	} {
		f := Defaults()
		c.edit(f)
		p := &Policy{File: f, Command: cmd}
		d := p.Decide(c.t)
		if d.Why != c.want || d.Console != (c.shell == cmd) || p.Shell(c.t) != c.shell {
			t.Errorf("%s: %+v shell %q", c.name, d, p.Shell(c.t))
		}
	}
}

// A user's own system-shell setting beats the tier's in both directions, but
// not for the superuser tier (always) and not for the engineer tier (never).
func TestSystemShellForUsers(t *testing.T) {
	f := Defaults()
	f.SystemShellTiers = []tier.Tier{tier.Operator, tier.Superuser}
	f.SetSystemShellUser("carol", true, tier.Readonly)
	f.SetSystemShellUser("bob", false, "")
	f.SetSystemShellUser("alice", false, "")
	f.SetSystemShellUser("erin", true, tier.Operator)
	f.SetSystemShellUser("gus", true, tier.Operator)
	p := &Policy{File: f}
	for _, c := range []struct {
		user string
		t    tier.Tier
		want bool
		why  string
	}{
		{"carol", tier.Readonly, true, "user setting"},                                 // enabled for a user of a closed tier
		{"dave", tier.Readonly, false, "tier readonly"},                                // no setting: the tier
		{"bob", tier.Operator, false, "user setting"},                                  // disabled for a user of an open tier
		{"eve", tier.Operator, true, "tier operator"},                                  // no setting: the tier
		{"alice", tier.Superuser, true, "always"},                                      // cannot be taken
		{"erin", tier.Engineer, false, "never; stale: set for operator, now engineer"}, // cannot be given
		{"carol", tier.None, false, "no tier; stale: set for readonly, now none"},
		// an enable is for the tier it was set for: a move to another tier ends it
		{"gus", tier.Operator, true, "user setting"},
		{"gus", tier.Readonly, false, "tier readonly; stale: set for operator, now readonly"},
		{"gus", tier.Superuser, true, "always; stale: set for operator, now superuser"},
		{"carol", tier.Operator, true, "tier operator; stale: set for readonly, now operator"}, // the tier has it anyway
		// a disable holds at any tier that has the shell
		{"bob", tier.Readonly, false, "user setting"},
		{"carol", tier.Unrestricted, true, ""},
	} {
		if got := p.SystemShellFor(c.user, c.t); got != c.want {
			t.Errorf("%s at %s: %v, want %v", c.user, c.t, got, c.want)
		}
		if c.t == tier.Unrestricted {
			continue
		}
		if on, why := p.SystemShellWhy(c.user, c.t); on != c.want || why != c.why {
			t.Errorf("%s at %s: why %v %q, want %v %q", c.user, c.t, on, why, c.want, c.why)
		}
	}
}

// SetSystemShell writes the tiers that have the system shell with the
// superuser tier always among them, refuses the engineer tier on and the
// superuser tier off, and leaves the file as it was on a refusal.
func TestSetSystemShell(t *testing.T) {
	f := Defaults()
	for _, c := range []struct {
		t    tier.Tier
		on   bool
		want []tier.Tier
		err  string
	}{
		{tier.Operator, true, []tier.Tier{tier.Operator, tier.Superuser}, ""},
		{tier.Readonly, true, []tier.Tier{tier.Readonly, tier.Operator, tier.Superuser}, ""},
		{tier.Operator, false, []tier.Tier{tier.Readonly, tier.Superuser}, ""},
		{tier.Readonly, true, []tier.Tier{tier.Readonly, tier.Superuser}, ""},
		{tier.Engineer, true, []tier.Tier{tier.Readonly, tier.Superuser}, "The engineer tier cannot be given the system shell on this server: a shell here would reach the server's secrets. Nothing was changed."},
		{tier.Engineer, false, []tier.Tier{tier.Readonly, tier.Superuser}, ""},
		{tier.Superuser, false, []tier.Tier{tier.Readonly, tier.Superuser}, "The superuser tier always has the system shell; it cannot be disabled. Nothing was changed."},
		{tier.Readonly, false, []tier.Tier{tier.Superuser}, ""},
	} {
		err := f.SetSystemShell(c.t, c.on)
		if (err == nil) != (c.err == "") || (err != nil && err.Error() != c.err) {
			t.Errorf("%s %v: %v, want %q", c.t, c.on, err, c.err)
		}
		if !reflect.DeepEqual(f.SystemShellTiers, c.want) {
			t.Errorf("%s %v: tiers %v, want %v", c.t, c.on, f.SystemShellTiers, c.want)
		}
	}
	// A hand-edited list without the superuser tier is written with it.
	f.SystemShellTiers = nil
	if err := f.SetSystemShell(tier.Operator, true); err != nil || !reflect.DeepEqual(f.SystemShellTiers, []tier.Tier{tier.Operator, tier.Superuser}) {
		t.Errorf("empty list: %v %v", f.SystemShellTiers, err)
	}
}

// settings.system_shell_users is written only when a user has a setting,
// reads back, and is refused with a bad shape.
func TestSystemShellUsersSetting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.yaml")
	if _, err := Mutate(p, nil, func(f *File) error { f.Idle = 5; return nil }); err != nil {
		t.Fatal(err)
	}
	without, _ := os.ReadFile(p)
	if strings.Contains(string(without), "system_shell_users") {
		t.Errorf("the key is written while empty:\n%s", without)
	}
	if _, err := Mutate(p, nil, func(f *File) error {
		f.SetSystemShellUser("carol", true, tier.Readonly)
		f.SetSystemShellUser("alice.smith", false, "")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "  system_shell_users: {alice.smith: disable, carol: 'enable:readonly'}\n") {
		t.Errorf("the key is not written as a map:\n%s", got)
	}
	f, err := Load(p)
	if err != nil || !f.SystemShellUsers["carol"] || f.SystemShellUsers["alice.smith"] || len(f.SystemShellUsers) != 2 {
		t.Fatalf("round trip: %+v %v", f.SystemShellUsers, err)
	}
	if f.SystemShellUserTiers["carol"] != tier.Readonly || len(f.SystemShellUserTiers) != 1 {
		t.Errorf("the tiers of the enables: %v", f.SystemShellUserTiers)
	}
	if _, err := Mutate(p, nil, func(f *File) error { f.DropSystemShellUser("carol"); f.DropSystemShellUser("alice.smith"); return nil }); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(p); string(again) != string(without) {
		t.Errorf("empty again:\n%s\nwant\n%s", again, without)
	}
	for name, text := range map[string]string{
		"not a map":    "version: 1\nsettings: {system_shell_users: [carol]}\n",
		"a bool":       "version: 1\nsettings: {system_shell_users: {carol: true}}\n",
		"enable alone": "version: 1\nsettings: {system_shell_users: {carol: enable}}\n",
		"no tier":      "version: 1\nsettings: {system_shell_users: {carol: 'enable:'}}\n",
		"superuser":    "version: 1\nsettings: {system_shell_users: {carol: 'enable:superuser'}}\n",
		"engineer":     "version: 1\nsettings: {system_shell_users: {carol: 'enable:engineer'}}\n",
		"disable tier": "version: 1\nsettings: {system_shell_users: {carol: 'disable:operator'}}\n",
		"bad name":     "version: 1\nsettings: {system_shell_users: {'a b': disable}}\n",
		"dot leading":  "version: 1\nsettings: {system_shell_users: {.carol: disable}}\n",
	} {
		if _, err := Load(write(t, dir, "bad.yaml", text, 0o600)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if f, err := Load(write(t, dir, "empty.yaml", "version: 1\nsettings: {system_shell_users: }\n", 0o600)); err != nil || len(f.SystemShellUsers) != 0 {
		t.Errorf("empty value: %+v %v", f, err)
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
	// The superuser tier has it whatever the list says.
	if !p.SystemShell(tier.Readonly) || !p.SystemShell(tier.Superuser) || !p.SystemShell(tier.Unrestricted) || p.SystemShell(tier.None) {
		t.Error("custom tiers")
	}
	f.SystemShellTiers = nil
	if !p.SystemShell(tier.Superuser) || p.SystemShell(tier.Readonly) || !p.SystemShell(tier.Unrestricted) {
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

// accepts023 is the part of 0.2.3's console.yaml parser that matters for a
// rollback to it, as a fixture (parse and parseSettings of
// internal/console/config.go at the 0.2.3 tag): the top-level keys, the four
// tiers and the nine settings listed here are known; any other makes it
// fail, and the console falls back to the defaults.
func accepts023(text []byte) error {
	v, err := pyyaml.LoadBytes(text)
	if err != nil {
		return err
	}
	root := v.(*yamlpy.Map)
	for k := range root.All() {
		if !slices.Contains([]string{"version", "tiers", "users", "settings"}, k) {
			return errors.New("unknown key '" + k + "'")
		}
	}
	known := []struct {
		section string
		keys    []string
	}{
		{"tiers", []string{"readonly", "operator", "engineer", "superuser"}},
		{"settings", []string{"idle_timeout", "list_max", "agent_forwarding", "ssh_escape", "gateway_ports", "space_completion",
			"system_shell", "system_shell_tiers", "forwarding_tiers"}},
	}
	for _, kn := range known {
		sub, ok := root.Get(kn.section)
		if !ok {
			continue
		}
		for k := range sub.(*yamlpy.Map).All() {
			if !slices.Contains(kn.keys, k) {
				return errors.New(kn.section + ": unknown key '" + k + "'")
			}
		}
	}
	return nil
}

// A console.yaml is written with no 'tiers' and no 'users' mapping from
// 0.2.20, so the engineer tier's switch (tiers.engineer, which 0.2.2
// rejects) is no longer in it. What 0.2.2 still rejects is
// settings.space_completion, written only when it is off. A file that has
// the old mappings keeps them as it was (TestIgnoredSwitchesAreKept), and
// 'tacctl rollback' to 0.2.3 and later does not touch them.
func TestRollbackToTheOldParser(t *testing.T) {
	for _, off := range []bool{false, true} {
		f := Defaults()
		f.SpaceCompletion = !off
		text, err := f.Text()
		if err != nil {
			t.Fatal(err)
		}
		v, err := pyyaml.LoadBytes(text)
		if err != nil {
			t.Fatal(err)
		}
		root := v.(*yamlpy.Map)
		if root.Has("tiers") || root.Has("users") {
			t.Errorf("a console switch is written:\n%s", text)
		}
		settings, _ := root.Get("settings")
		if settings.(*yamlpy.Map).Has("space_completion") != off {
			t.Errorf("space_completion written: %v, off: %v:\n%s", !off, off, text)
		}
		err = accepts022(text)
		if off && (err == nil || !strings.Contains(err.Error(), "space_completion")) {
			t.Errorf("space completion off: want a rejection naming space_completion, got %v\n%s", err, text)
		}
		if !off && err != nil {
			t.Errorf("space completion on: rejected by 0.2.2: %v\n%s", err, text)
		}
		// The 0.2.3 parser reads the file, whatever the mappings.
		if err := accepts023(text); err != nil {
			t.Errorf("0.2.3 rejects the file: %v\n%s", err, text)
		}
	}
}

// settings.password_cache (D70) is written only when something in it is not
// the default, reads back, is checked, and is what the policy answers.
func TestPasswordCacheSetting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.yaml")
	if _, err := Mutate(p, nil, func(f *File) error { f.Idle = 5; return nil }); err != nil {
		t.Fatal(err)
	}
	plain, _ := os.ReadFile(p)
	if strings.Contains(string(plain), "password_cache") {
		t.Errorf("the key is written with its defaults:\n%s", plain)
	}
	f, err := Load(p)
	if err != nil || len(f.PasswordCacheTiers) != 0 || f.PasswordCacheIdle != 15 || f.PasswordCacheMax != 8 {
		t.Fatalf("defaults: %+v %v", f, err)
	}
	pol := NewPolicy(f, paths.Paths{})
	for _, tr := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer, tier.Superuser, tier.Unrestricted, tier.None} {
		if pol.PasswordCache(tr) {
			t.Errorf("the cache is on for %s by default", tr)
		}
	}
	if _, err := Mutate(p, nil, func(f *File) error {
		f.PasswordCacheTiers = []tier.Tier{tier.Engineer, tier.Superuser}
		f.PasswordCacheIdle, f.PasswordCacheMax = 30, 4
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	text, _ := os.ReadFile(p)
	if !strings.Contains(string(text), "password_cache:") || !strings.Contains(string(text), "idle: 30") || !strings.Contains(string(text), "max: 4") {
		t.Errorf("password_cache not written:\n%s", text)
	}
	f, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	pol = NewPolicy(f, paths.Paths{})
	if !pol.PasswordCache(tier.Engineer) || !pol.PasswordCache(tier.Superuser) || pol.PasswordCache(tier.Operator) || pol.PasswordCache(tier.Readonly) || pol.PasswordCache(tier.Unrestricted) {
		t.Errorf("tiers: %+v", f.PasswordCacheTiers)
	}
	if pol.PasswordCacheIdle() != 30*time.Minute || pol.PasswordCacheMax() != 4*time.Hour {
		t.Errorf("lifetimes: %v %v", pol.PasswordCacheIdle(), pol.PasswordCacheMax())
	}
	// Back to the defaults: the key disappears.
	if _, err := Mutate(p, nil, func(f *File) error {
		f.PasswordCacheTiers, f.PasswordCacheIdle, f.PasswordCacheMax = nil, 15, 8
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(p); string(again) != string(plain) {
		t.Errorf("defaults again:\n%s\nwant:\n%s", again, plain)
	}
	// What is refused.
	for _, c := range []struct{ name, text, err string }{
		{"readonly", "version: 1\nsettings: {password_cache: {tiers: [readonly]}}\n", "invalid or repeated tier"},
		{"twice", "version: 1\nsettings: {password_cache: {tiers: [operator, operator]}}\n", "invalid or repeated tier"},
		{"idle 0", "version: 1\nsettings: {password_cache: {idle: 0}}\n", "idle must be 1-120"},
		{"idle big", "version: 1\nsettings: {password_cache: {idle: 121}}\n", "idle must be 1-120"},
		{"max 25", "version: 1\nsettings: {password_cache: {max: 25}}\n", "max must be 1-24"},
		{"unknown", "version: 1\nsettings: {password_cache: {keep: 1}}\n", "unknown key 'keep'"},
		{"not a map", "version: 1\nsettings: {password_cache: yes}\n", "must be a mapping"},
	} {
		q := write(t, dir, "bad-"+strings.ReplaceAll(c.name, " ", "-")+".yaml", c.text, 0o600)
		if _, err := Load(q); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%s: %v, want %q", c.name, err, c.err)
		}
	}
	if _, err := ParsePasswordCacheTiers("operator,readonly"); err == nil {
		t.Error("readonly accepted for the cache")
	}
	if l, err := ParsePasswordCacheTiers("none"); err != nil || l != nil {
		t.Errorf("none: %v %v", l, err)
	}
	if l, err := ParsePasswordCacheTiers("superuser,engineer"); err != nil || len(l) != 2 {
		t.Errorf("list: %v %v", l, err)
	}
}

// The rollback to 0.2.3 takes settings.password_cache out and nothing else:
// the file as 0.2.3 reads it (rollback_test.go has the fixture of its parser).
func TestPasswordCacheRollback023(t *testing.T) {
	dir := t.TempDir()
	f := Defaults()
	f.PasswordCacheTiers = []tier.Tier{tier.Operator}
	f.SpaceCompletion = false
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	if err := accepts023(text); err == nil {
		t.Fatal("0.2.3's parser accepts a file with password_cache")
	}
	p := write(t, dir, "console.yaml", string(text), 0o600)
	plan, err := PlanRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(plan.Remove, func(s string) bool { return strings.HasPrefix(s, "settings.password_cache") }) {
		t.Errorf("the plan does not name the key: %q", plan.Remove)
	}
	if err := accepts023(plan.Text); err != nil {
		t.Errorf("0.2.3 rejects the converted file: %v\n%s", err, plan.Text)
	}
	if strings.Contains(string(plan.Text), "password_cache") || !strings.Contains(string(plan.Text), "space_completion: false") ||
		strings.Contains(string(plan.Text), "tiers: {") {
		t.Errorf("the converted file:\n%s", plan.Text)
	}
}

// A user name may hold periods (names.MatchUser): the ignored users mapping
// of the file writes and reads such a key back, and a bad shape is refused.
func TestUsersWithPeriods(t *testing.T) {
	p := filepath.Join(t.TempDir(), "console.yaml")
	if _, err := Mutate(p, nil, func(f *File) error {
		f.IgnoredUsers["alice.smith"] = true
		f.IgnoredUsers["1.5"] = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil || !f.IgnoredUsers["alice.smith"] || f.IgnoredUsers["1.5"] || len(f.IgnoredUsers) != 2 {
		t.Fatalf("round trip: %+v %v", f.IgnoredUsers, err)
	}
	for _, bad := range []string{".alice", "alice.", "alice..smith"} {
		if _, err := Mutate(p, nil, func(f *File) error { f.IgnoredUsers[bad] = true; return nil }); err == nil || !strings.Contains(err.Error(), "invalid user name '"+bad+"'") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// settings.password_cache_users is written only when a user is on, reads back,
// keeps only the users who are on, and is refused with a bad shape; the cache
// is active for a user when the tier is allowed and the user is on.
func TestPasswordCacheUsersSetting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.yaml")
	if _, err := Mutate(p, nil, func(f *File) error { f.Idle = 5; return nil }); err != nil {
		t.Fatal(err)
	}
	without, _ := os.ReadFile(p)
	if strings.Contains(string(without), "password_cache") {
		t.Errorf("a key is written while nobody is on:\n%s", without)
	}
	if _, err := Mutate(p, nil, func(f *File) error {
		f.PasswordCacheUsers["carol"] = true
		f.PasswordCacheUsers["alice.smith"] = true
		f.PasswordCacheUsers["dave"] = false // not stored: a user who is off is a user without a setting
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "  password_cache_users: {alice.smith: true, carol: true}\n") {
		t.Errorf("the key is not written as a map of the users who are on:\n%s", got)
	}
	f, err := Load(p)
	if err != nil || !f.PasswordCacheUsers["carol"] || f.PasswordCacheUsers["dave"] || !reflect.DeepEqual(f.PasswordCacheUserNames(), []string{"alice.smith", "carol"}) {
		t.Fatalf("round trip: %+v %v", f.PasswordCacheUsers, err)
	}
	if _, err := Mutate(p, nil, func(f *File) error { f.PasswordCacheUsers = map[string]bool{}; return nil }); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(p); string(again) != string(without) {
		t.Errorf("empty again:\n%s\nwant\n%s", again, without)
	}
	for name, text := range map[string]string{
		"not a map":  "version: 1\nsettings: {password_cache_users: [carol]}\n",
		"not a bool": "version: 1\nsettings: {password_cache_users: {carol: maybe}}\n",
		"bad name":   "version: 1\nsettings: {password_cache_users: {'a b': true}}\n",
	} {
		if _, err := Load(write(t, dir, "bad.yaml", text, 0o600)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The matrix: tier allowed x user on.
	f = Defaults()
	f.PasswordCacheTiers = []tier.Tier{tier.Operator, tier.Superuser}
	f.PasswordCacheUsers = map[string]bool{"bob": true, "carol": true}
	pol := &Policy{File: f}
	for _, c := range []struct {
		user string
		t    tier.Tier
		want bool
	}{
		{"bob", tier.Operator, true},    // allowed and on
		{"dave", tier.Operator, false},  // allowed, off (the default)
		{"carol", tier.Readonly, false}, // on, but the tier is not allowed
		{"erin", tier.Readonly, false},  // neither
		{"bob", tier.Engineer, false},   // the tier is not in the list
		{"", tier.Superuser, false},     // no user, no choice
	} {
		if got := pol.PasswordCacheActive(c.user, c.t); got != c.want {
			t.Errorf("%q at %s: %v, want %v", c.user, c.t, got, c.want)
		}
	}
	// The policy answer reads the permission apart from the choice.
	r, ok := ParseRemote("shell=console tier=operator password_cache=no pc_allowed=yes pc_idle=20 pc_max=3")
	if !ok || r.PasswordCache || !r.PCAllowed || r.PCIdle != 20*time.Minute || r.PCMax != 3*time.Hour {
		t.Errorf("parsed %+v", r)
	}
}

// Where the console cannot be provisioned an account gets bash only if it has
// the system shell, nologin otherwise (an engineer and a tier that is none
// included).
func TestShellWithoutTheConsole(t *testing.T) {
	f := Defaults()
	f.SystemShellTiers = []tier.Tier{tier.Operator, tier.Superuser}
	f.SetSystemShellUser("carol", true, tier.Readonly)
	f.SetSystemShellUser("bob", false, "")
	f.SetSystemShellUser("erin", true, tier.Operator)
	p := &Policy{File: f}
	for _, c := range []struct {
		user string
		t    tier.Tier
		want string
	}{
		{"alice", tier.Superuser, "/bin/bash"},
		{"dave", tier.Operator, "/bin/bash"},        // the tier has it
		{"bob", tier.Operator, "/usr/sbin/nologin"}, // taken from him
		{"carol", tier.Readonly, "/bin/bash"},       // given to her
		{"frank", tier.Readonly, "/usr/sbin/nologin"},
		{"erin", tier.Engineer, "/usr/sbin/nologin"},
		{"x", tier.None, "/usr/sbin/nologin"},
	} {
		if got := p.ShellWithoutConsole(c.user, c.t); got != c.want {
			t.Errorf("%s at %s: %q, want %q", c.user, c.t, got, c.want)
		}
	}
}
