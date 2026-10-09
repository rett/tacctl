package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
)

func TestCheckRollbackVersion(t *testing.T) {
	for _, ok := range []string{"0.2.2", "v0.2.2"} {
		if v, err := CheckRollbackVersion(ok); err != nil || v != "0.2.2" {
			t.Errorf("%q: %q %v", ok, v, err)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"0.2.1", "older than 0.2.2"},
		{"0.2.0", "older than 0.2.2"},
		{"0.1.16", "older than 0.2.2"},
		{"v0.2.1", "older than 0.2.2"},
		{"0.2.3", "prepares the state for 0.2.2 only"},
		{"0.3.0", "prepares the state for 0.2.2 only"},
		{"1.0.0", "prepares the state for 0.2.2 only"},
		{"0.2", "is not a release this tacctl knows"},
		{"main", "is not a release this tacctl knows"},
		{"", "is not a release this tacctl knows"},
		{"0.2.2-rc1", "is not a release this tacctl knows"},
	} {
		_, err := CheckRollbackVersion(c.in)
		var ref *RollbackRefusal
		if !errors.As(err, &ref) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v (want %q)", c.in, err, c.want)
		}
	}
	// The reason for 0.2.1 says what is not covered and what to do.
	_, err := CheckRollbackVersion("0.2.1")
	for _, want := range []string{"0.2.2 changed the state as well", "tacctl backup restore"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("0.2.1 refusal lacks %q: %v", want, err)
		}
	}
}

func TestTopLevelAlternation(t *testing.T) {
	for rx, want := range map[string]bool{
		"crypto|trace":        true,
		"a|b|c":               true,
		"^(a|b)$":             false,
		"(a|b)c":              false,
		"^crypto( .*)?$":      false,
		"[|]x":                false,
		"[^|]x":               false,
		"[]|]x":               false,
		`a\|b`:                false,
		`(a\)|b)`:             false,
		`(?:a|b)|c`:           true,
		"ip (route|addr)|vrf": true,
		"":                    false,
		"plain":               false,
	} {
		if got := TopLevelAlternation(rx); got != want {
			t.Errorf("TopLevelAlternation(%q) = %v, want %v", rx, got, want)
		}
	}
}

// --- a 0.2.3 state in a sandbox ---------------------------------------------------

const rbStore = `version: 1
groups:
  engineer: {priv_lvl: 15, juniper_class: EN-CLASS}
  ops: {priv_lvl: 15, juniper_class: RW-CLASS}
  lead: {priv_lvl: 10, juniper_class: OP-CLASS}
  operator: {priv_lvl: 7, juniper_class: OP-CLASS, builtin: true}
  readonly: {priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}
  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}
users:
  alice: {group: superuser, scopes: [lab, prod], hash: 24326224313224646f6e74636172652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e}
  erin: {group: engineer, scopes: [lab], hash: 24326224313224646f6e74636172652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e}
  evan: {group: engineer, scopes: [prod], hash: 24326224313224646f6e74636172652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e}
  olga: {group: ops, scopes: [lab], hash: 24326224313224646f6e74636172652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e}
  lena: {group: lead, scopes: [lab], hash: 24326224313224646f6e74636172652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e}
  gone: {group: engineer, scopes: [lab], disabled: true, hash: 24326224313224646f6e74636172652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e}
scopes:
  lab:
    prefixes: [172.16.0.0/12]
    secret: lab-secret-0123456789abcdef
  prod:
    prefixes: [10.0.0.0/8]
    secret: prod-secret-0123456789abcdef
filters:
  allow: []
  deny: []
`

// rbConf is a tacctl.yaml with every family 0.2.3 added, the settings 0.2.2
// has and a regex with a top-level alternation.
const rbConf = `bcrypt:
  cost: 11
commands:
  engineer:
  - name: show
    action: permit
    match:
    - crypto|trace
  - name: '*'
    action: deny
linux:
  uid_min: 70000
  uid_max: 79999
  engineer_sudo:
  - /usr/bin/systemctl
  - /usr/bin/journalctl
tier:
  engineer: engineer
  lead: engineer
  ops: operator
snmp:
  version: v2c
snmp_scope:
  lab:
    version: v3
    contact: NOC, building 2
    clients:
    - 10.1.0.0/16
    v3:
      auth: sha
  prod:
    port: 1161
breakglass_scope:
  lab:
    users:
    - bg-admin:admin
    - bg-ro:readonly
`

const rbDevices = `# tacctl device registry (header)
version: 1
settings: {stale_days: 30}
devices:
  core-sw1: {address: 10.99.0.1, vendor: cisco, description: DC1 core, location: 'Rack 4, DC1'}
  lab-rtr2: {address: 192.0.2.7, vendor: juniper}
  oob-con1: {address: 10.99.0.9, vendor: wti, location: Room 17}
`

type rbSandbox struct {
	t  *testing.T
	w  string
	p  paths.Paths
	c  *conf.Config
	in RollbackInput
}

func (s *rbSandbox) write(path, text string, mode os.FileMode) {
	s.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		s.t.Fatal(err)
	}
}

// newRBSandbox lays out a 0.2.3 state: every file the rollback converts, and
// every file it leaves.
func newRBSandbox(t *testing.T) *rbSandbox {
	t.Helper()
	w := t.TempDir()
	vars := []string{
		"TACCTL_ETC=" + filepath.Join(w, "etc"),
		"TACCTL_STATE_DIR=" + filepath.Join(w, "state"),
		"TACCTL_VAR_LIB=" + filepath.Join(w, "var-lib"),
		"TACCTL_SSHD_DROPIN=" + filepath.Join(w, "sshd_config.d", "tacctl-console.conf"),
	}
	s := &rbSandbox{t: t, w: w}
	s.p = paths.Resolve(paths.NewEnv(vars), "", func(string) bool { return false })
	s.write(s.p.StoreFile, rbStore, 0o600)
	s.write(s.p.Overrides, rbConf, 0o640)
	s.write(s.p.DevicesFile, rbDevices, 0o600)
	// console.yaml as 0.2.3 writes it, space completion off.
	s.write(s.p.ConsoleFile, "# tacctl login console\nversion: 1\ntiers:\n  readonly: enable\n  operator: enable\n  engineer: enable\n  superuser: enable\nusers:\n  jdoe: disable\nsettings:\n  idle_timeout: 12\n  agent_forwarding: false\n  ssh_escape: false\n  system_shell: /bin/bash\n  system_shell_tiers: [superuser]\n  forwarding_tiers: [superuser]\n  gateway_ports: false\n  list_max: 40\n  space_completion: false\n", 0o600)
	s.write(filepath.Join(s.p.SNMPDir, "lab.yaml"), "community: lab-community-1\n", 0o600)
	s.write(filepath.Join(s.p.HostRecords, "web1.json"), "{\n  \"provisioner\": {\"at\": \"2026-10-01T00:00:00Z\", \"by\": \"root\", \"old\": \"a\", \"new\": \"b\", \"auth\": \"key\", \"old_removed\": false}\n}\n", 0o600)
	s.write(filepath.Join(s.p.HostRecords, "web2.json"), "{}\n", 0o600)
	s.write(s.p.SSHDEngineerDropIn, "# Managed by tacctl\nMatch Group tac-engineer\n  AllowTcpForwarding no\n", 0o644)
	s.write(s.p.TierPinMarker, "", 0o644)
	s.reload()
	return s
}

// reload reads the model and tacctl.yaml again, as a new run would.
func (s *rbSandbox) reload() {
	s.t.Helper()
	s.c = conf.Load(s.p.Overrides, conf.DefaultBackends)
	s.c.Owner = nil
	_, m, err := model.LoadStore(s.p.StoreFile)
	s.in = RollbackInput{Paths: s.p, Conf: s.c, Model: m, ModelErr: err, HasStore: err == nil,
		Hosts:    []RollbackHost{{Name: "srv", Scope: "lab", Local: true}, {Name: "web1", Scope: "prod"}, {Name: "web2", Scope: "lab"}},
		AllHosts: []RollbackHost{{Name: "srv", Scope: "lab", Local: true}, {Name: "web1", Scope: "prod"}, {Name: "web2", Scope: "lab"}},
	}
}

// snapshotOf is every file under the sandbox, by path, with its bytes.
func (s *rbSandbox) snapshotOf() map[string]string {
	s.t.Helper()
	out := map[string]string{}
	err := filepath.Walk(s.w, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			out[p] = string(b)
		}
		return nil
	})
	if err != nil {
		s.t.Fatal(err)
	}
	return out
}

func stepText(p *RollbackPlan) string {
	var b strings.Builder
	for _, s := range p.Steps {
		b.WriteString(s.Title + "\n")
		for _, l := range s.Lines {
			b.WriteString("  " + l + "\n")
		}
	}
	return b.String()
}

func warnText(p *RollbackPlan) string {
	var b strings.Builder
	for _, w := range p.Warnings {
		b.WriteString(w.Title + "\n")
		for _, l := range w.Lines {
			b.WriteString("  " + l + "\n")
		}
	}
	return b.String()
}

// A plan reads and writes nothing, lists every step and every warning.
func TestPlanRollbackFull(t *testing.T) {
	s := newRBSandbox(t)
	s.in.WithHosts = true
	before := s.snapshotOf()
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Error("PlanRollback wrote something")
	}
	if !p.Pending() || !p.NeedsYes() {
		t.Errorf("pending %v needs-yes %v", p.Pending(), p.NeedsYes())
	}
	wantKeys := []string{"linux.engineer_sudo", "snmp_scope.lab.version", "snmp_scope.lab.contact", "snmp_scope.lab.clients",
		"snmp_scope.lab.v3.auth", "snmp_scope.prod.port", "breakglass_scope.lab.users"}
	if !reflect.DeepEqual(p.Keys(), wantKeys) {
		t.Errorf("keys %q, want %q", p.Keys(), wantKeys)
	}
	steps := stepText(p)
	for _, want := range []string{
		s.p.Overrides + ": remove the keys 0.2.2 does not know",
		"remove linux.engineer_sudo", "remove snmp_scope.lab.contact", "remove breakglass_scope.lab.users",
		"keep every tier.<group> setting",
		s.p.ConsoleFile + ": write it the way 0.2.2 reads it",
		"remove tiers.engineer: enable", "remove settings.space_completion: false",
		s.p.DevicesFile + ": remove the per-device location",
		"remove the location of 2 devices: core-sw1, oob-con1",
		"move aside " + s.p.SNMPDir, "moves " + filepath.Join(s.p.SNMPDir, "lab.yaml"),
		"1 record has a provisioner entry (the last 'host provisioner rotate'): web1",
		"leaves " + s.p.SSHDEngineerDropIn, "remove the tier-pin marker so the next upgrade pins again", "removes " + s.p.TierPinMarker,
		"leave " + s.p.StoreFile + " untouched",
		"re-render the enabled backends",
		"srv (scope 'lab') is this tacctl server: not synced",
		"sync web1 (scope 'prod') with TAC_REVOKE_ENGINEER=1", "sync web2 (scope 'lab') with TAC_REVOKE_ENGINEER=1",
	} {
		if !strings.Contains(steps, want) {
			t.Errorf("steps lack %q:\n%s", want, steps)
		}
	}
	for _, st := range p.Steps {
		wantTodo := strings.Contains(st.Title, "remove") || strings.Contains(st.Title, "move aside") || strings.Contains(st.Title, "write it") || strings.Contains(st.Title, "re-render") || strings.Contains(st.Title, "engineers' sudo")
		if st.Todo != wantTodo {
			t.Errorf("step %q: todo %v", st.Title, st.Todo)
		}
	}

	warns := warnText(p)
	for _, want := range []string{
		"Engineers become superusers under 0.2.2",
		// erin is an engineer at priv-lvl 15 in lab, the scope of the server; olga (group ops, tier operator) too.
		"This server (host srv, scope 'lab'): erin (group engineer, engineer now), olga (group ops, operator now) become superusers of tacctl here",
		// evan is in prod only: the host of that scope.
		"Host web1 (scope 'prod'): evan (group engineer, engineer now) join tac-superuser (full sudo)",
		"Host web2 (scope 'lab'): erin (group engineer, engineer now), olga (group ops, operator now) join tac-superuser",
		"Groups change tier",
		"group engineer (priv-lvl 15): engineer now, superuser under 0.2.2 (higher)",
		"group lead (priv-lvl 10): engineer now, operator under 0.2.2 (lower)",
		"group ops (priv-lvl 15): operator now, superuser under 0.2.2 (higher)",
		"Settings 0.2.2 cannot use are dropped",
		"linux.engineer_sudo (/usr/bin/systemctl, /usr/bin/journalctl) is removed",
		"of lab, prod are removed from tacctl.yaml",
		"The credentials (lab.yaml, mode 0600) are moved from " + s.p.SNMPDir + "/ to a snmp.rolled-back-<timestamp> directory beside it",
		"scope 'lab': bg-admin (admin), bg-ro (readonly)",
		"The location of 2 devices is removed from the device registry (core-sw1, oob-con1)",
		"stays in the snapshot --apply takes first",
	} {
		if !strings.Contains(warns, want) {
			t.Errorf("warnings lack %q:\n%s", want, warns)
		}
	}
	// lena (group lead, lab) is not at priv-lvl 15, so she does not become a superuser; the disabled engineer is not named.
	if strings.Contains(warns, "lena (") || strings.Contains(warns, "gone (") {
		t.Errorf("a user who does not become a superuser is named:\n%s", warns)
	}
	if len(p.Notes) < 2 || !strings.Contains(strings.Join(p.Notes, "\n"), "group engineer: rule show match crypto|trace") {
		t.Errorf("notes: %q", p.Notes)
	}
}

// Without --hosts there is no host step.
func TestPlanRollbackWithoutHosts(t *testing.T) {
	s := newRBSandbox(t)
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stepText(p), "TAC_REVOKE_ENGINEER") {
		t.Errorf("a host step without --hosts:\n%s", stepText(p))
	}
}

// --apply's conversions: each file is converted, everything else is left
// byte for byte, and a second run changes nothing.
func TestApplyRollbackConvertsAndIsIdempotent(t *testing.T) {
	s := newRBSandbox(t)
	before := s.snapshotOf()
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	done, err := ApplyRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 5 {
		t.Errorf("done %q", done)
	}
	after := s.snapshotOf()
	changed := map[string]bool{s.p.Overrides: true, s.p.ConsoleFile: true, s.p.DevicesFile: true}
	// The credentials directory is moved aside whole, the marker removed.
	moved := filepath.Join(s.p.SNMPDir, "lab.yaml")
	gone := map[string]bool{moved: true, s.p.TierPinMarker: true}
	var aside string
	for path, was := range before {
		if gone[path] {
			if _, there := after[path]; there {
				t.Errorf("%s is still there", path)
			}
			continue
		}
		if changed[path] {
			if after[path] == was {
				t.Errorf("%s was not converted", path)
			}
			continue
		}
		// Lock files appear beside the converted ones; the rest is as it was.
		if after[path] != was {
			t.Errorf("%s changed", path)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok && !strings.HasSuffix(path, ".lock") {
			if strings.HasPrefix(path, s.p.SNMPDir+".rolled-back-") && filepath.Base(path) == "lab.yaml" {
				aside = path
				if after[path] != before[moved] {
					t.Errorf("%s: the moved credentials changed", path)
				}
				if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
					t.Errorf("%s: mode %v %v", path, fi, err)
				}
				continue
			}
			t.Errorf("new file %s", path)
		}
	}
	if aside == "" {
		t.Error("the credentials were not moved aside")
	}
	if _, err := os.Stat(s.p.SNMPDir); err == nil {
		t.Errorf("%s is still live", s.p.SNMPDir)
	}
	if TierPinDone(s.p) {
		t.Error("the tier-pin marker is still there")
	}
	// store.yaml is byte-identical (D50).
	if after[s.p.StoreFile] != rbStore {
		t.Error("store.yaml changed")
	}
	// tacctl.yaml keeps what 0.2.2 knows and nothing else.
	got := after[s.p.Overrides]
	for _, gone := range []string{"engineer_sudo", "snmp_scope", "breakglass", "contact", "clients", "bg-admin"} {
		if strings.Contains(got, gone) {
			t.Errorf("tacctl.yaml still has %q:\n%s", gone, got)
		}
	}
	for _, kept := range []string{"cost: 11", "uid_min: 70000", "engineer: engineer", "lead: engineer", "ops: operator", "crypto|trace", "version: v2c"} {
		if !strings.Contains(got, kept) {
			t.Errorf("tacctl.yaml lost %q:\n%s", kept, got)
		}
	}
	if fi, _ := os.Stat(s.p.Overrides); fi.Mode().Perm() != 0o640 {
		t.Errorf("tacctl.yaml mode %v", fi.Mode().Perm())
	}
	if strings.Contains(after[s.p.ConsoleFile], "engineer") || strings.Contains(after[s.p.ConsoleFile], "space_completion") ||
		!strings.Contains(after[s.p.ConsoleFile], "jdoe: disable") || !strings.Contains(after[s.p.ConsoleFile], "idle_timeout: 12") {
		t.Errorf("console.yaml:\n%s", after[s.p.ConsoleFile])
	}
	if strings.Contains(after[s.p.DevicesFile], "location") || !strings.Contains(after[s.p.DevicesFile], "core-sw1") {
		t.Errorf("devices.yaml:\n%s", after[s.p.DevicesFile])
	}

	// The second run: nothing pending, no warning about files, nothing written.
	s.reload()
	p2, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Pending() || len(p2.Keys()) != 0 {
		t.Errorf("pending after the rollback: %v %q", p2.Pending(), p2.Keys())
	}
	for _, w := range p2.Warnings {
		if w.Title == "Settings 0.2.2 cannot use are dropped" {
			t.Errorf("the second plan still drops settings:\n%s", warnText(p2))
		}
	}
	done, err = ApplyRollback(p2)
	if err != nil || len(done) != 0 {
		t.Errorf("second apply: %q %v", done, err)
	}
	if !reflect.DeepEqual(after, s.snapshotOf()) {
		t.Error("the second apply changed a file")
	}
	// The tier warnings are about the model and stay until the groups change.
	if !strings.Contains(warnText(p2), "Engineers become superusers under 0.2.2") {
		t.Errorf("the superuser warning went with the files:\n%s", warnText(p2))
	}
}

// A state 0.2.2 can read has nothing to convert and no warning.
func TestPlanRollbackOfACleanState(t *testing.T) {
	w := t.TempDir()
	vars := []string{"TACCTL_ETC=" + w + "/etc", "TACCTL_STATE_DIR=" + w + "/state", "TACCTL_VAR_LIB=" + w + "/var"}
	pt := paths.Resolve(paths.NewEnv(vars), "", func(string) bool { return false })
	if err := os.MkdirAll(pt.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := strings.Replace(rbStore, "  engineer: {priv_lvl: 15, juniper_class: EN-CLASS}\n  ops: {priv_lvl: 15, juniper_class: RW-CLASS}\n  lead: {priv_lvl: 10, juniper_class: OP-CLASS}\n", "", 1)
	for _, u := range []string{"erin", "evan", "olga", "lena", "gone"} {
		i := strings.Index(store, "  "+u+":")
		j := strings.Index(store[i:], "\n")
		store = store[:i] + store[i+j+1:]
	}
	if err := os.WriteFile(pt.StoreFile, []byte(store), 0o600); err != nil {
		t.Fatal(err)
	}
	_, m, err := model.LoadStore(pt.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	in := RollbackInput{Paths: pt, Conf: conf.Load(pt.Overrides, conf.DefaultBackends), Model: m, HasStore: true,
		Hosts: []RollbackHost{{Name: "web1", Scope: "prod"}}, AllHosts: []RollbackHost{{Name: "web1", Scope: "prod"}}, WithHosts: true}
	p, err := PlanRollback(in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Pending() || p.NeedsYes() || len(p.Notes) != 0 {
		t.Errorf("pending %v, warnings %s, notes %q", p.Pending(), warnText(p), p.Notes)
	}
	// --hosts still has something to do (the sudoers of the hosts).
	if !strings.Contains(stepText(p), "sync web1 (scope 'prod') with TAC_REVOKE_ENGINEER=1") {
		t.Errorf("steps:\n%s", stepText(p))
	}
}

// A model that cannot be read is a warning of its own, and the other warnings
// still come.
func TestPlanRollbackWithoutAModel(t *testing.T) {
	s := newRBSandbox(t)
	s.in.Model, s.in.ModelErr = nil, errors.New("tacctl store: bad\nline")
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	w := warnText(p)
	if !strings.Contains(w, "Who changes tier cannot be told") || !strings.Contains(w, "tacctl store: bad line") ||
		!strings.Contains(w, "Settings 0.2.2 cannot use are dropped") || strings.Contains(w, "Groups change tier") {
		t.Errorf("warnings:\n%s", w)
	}
}

// A file that cannot be read stops the plan before anything is converted.
func TestPlanRollbackRefusesUnreadableFiles(t *testing.T) {
	for name, mut := range map[string]func(s *rbSandbox){
		"tacctl.yaml":  func(s *rbSandbox) { s.write(s.p.Overrides, "bcrypt: [\n", 0o640) },
		"console.yaml": func(s *rbSandbox) { s.write(s.p.ConsoleFile, "version: 1\nfoo: 1\n", 0o600) },
		"devices.yaml": func(s *rbSandbox) { s.write(s.p.DevicesFile, "devices: [\n", 0o600) },
	} {
		s := newRBSandbox(t)
		mut(s)
		s.reload()
		before := s.snapshotOf()
		if _, err := PlanRollback(s.in); err == nil {
			t.Errorf("%s: no error", name)
		}
		if !reflect.DeepEqual(before, s.snapshotOf()) {
			t.Errorf("%s: a file changed", name)
		}
	}
}

// Groups with a missing tier setting at priv-lvl 15 are held at operator in
// 0.2.3 and are superusers in 0.2.2.
func TestPlanRollbackAmbiguousGroup(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, "tier:\n  lead: engineer\n", 0o640)
	s.reload()
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	w := warnText(p)
	for _, want := range []string{"group engineer (priv-lvl 15): operator now, superuser under 0.2.2 (higher)",
		"group ops (priv-lvl 15): operator now, superuser under 0.2.2 (higher)",
		"erin (group engineer, operator now)"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
}
