package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

func TestCheckRollbackVersion(t *testing.T) {
	for _, ok := range []string{"0.2.3", "v0.2.3"} {
		if v, err := CheckRollbackVersion(ok); err != nil || v != "0.2.3" {
			t.Errorf("%q: %q %v", ok, v, err)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"0.2.2", "'tacctl rollback' converts what 0.2.4 changed and prepares the state for 0.2.3 only (0.2.2 is older)"},
		{"v0.2.2", "is older"},
		{"0.2.1", "is older"},
		{"0.1.16", "is older"},
		{"0.2.4", "prepares the state for 0.2.3 only"},
		{"0.3.0", "prepares the state for 0.2.3 only"},
		{"1.0.0", "prepares the state for 0.2.3 only"},
		{"0.2", "is not a release this tacctl knows"},
		{"main", "is not a release this tacctl knows"},
		{"", "is not a release this tacctl knows"},
		{"0.2.3-rc1", "is not a release this tacctl knows"},
	} {
		_, err := CheckRollbackVersion(c.in)
		var ref *RollbackRefusal
		if !errors.As(err, &ref) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v (want %q)", c.in, err, c.want)
		}
	}
	// The refusal of 0.2.2 names the two steps and the fallback.
	_, err := CheckRollbackVersion("0.2.2")
	for _, want := range []string{"one release at a time", "tacctl rollback 0.2.3 --apply", "tacctl upgrade --branch 0.2.3",
		"0.2.3's prepares the state for 0.2.2", "tacctl backup restore"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("0.2.2 refusal lacks %q: %v", want, err)
		}
	}
}

// --- a 0.2.4 state in a sandbox ---------------------------------------------------

// rbConf is a tacctl.yaml with the device.config keys of 0.2.4, every family
// 0.2.3 added (which stay) and the settings both have.
const rbConf = `bcrypt:
  cost: 11
commands:
  engineer:
  - name: show
    action: permit
    match:
    - crypto|trace
linux:
  uid_min: 70000
  uid_max: 79999
  engineer_sudo:
  - /usr/bin/systemctl
tier:
  engineer: engineer
snmp:
  version: v2c
snmp_scope:
  lab:
    version: v3
    contact: NOC, building 2
breakglass_scope:
  lab:
    users:
    - bg-admin:admin
device:
  config:
    max_concurrency: 16
    transport: ssh
    timeout: 120
`

// rbConsole is a console.yaml as 0.2.4 writes it: the engineer tier's
// switch and space completion off (0.2.3's own keys) and the password cache.
const rbConsole = "# tacctl login console\nversion: 1\ntiers:\n  readonly: enable\n  operator: enable\n  engineer: enable\n  superuser: enable\nusers:\n  jdoe: disable\n" +
	"settings:\n  idle_timeout: 12\n  agent_forwarding: false\n  ssh_escape: false\n  system_shell: /bin/bash\n  system_shell_tiers: [superuser]\n  forwarding_tiers: [superuser]\n" +
	"  gateway_ports: false\n  list_max: 40\n  space_completion: false\n  password_cache:\n    tiers: [engineer, superuser]\n    idle: 30\n    max: 4\n"

const rbDevices = `# tacctl device registry (header)
version: 1
settings: {stale_days: 30}
devices:
  core-sw1:
    address: 10.99.0.1
    vendor: cisco
    description: DC1 core
    location: Rack 4, DC1
    snmp:
      version: v3
      port: 2161
      timeout: 4
      clients: [10.1.0.0/16, 10.2.0.0/16]
  lab-rtr2: {address: 192.0.2.7, vendor: juniper}
  oob-con1:
    address: 10.99.0.9
    vendor: wti
    snmp: {port: 1161}
`

type rbSandbox struct {
	t   *testing.T
	w   string
	p   paths.Paths
	c   *conf.Config
	in  RollbackInput
	ins []string // the drop-ins InstallSudoers was asked for
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

// newRBSandbox lays out a 0.2.4 state: every file the rollback converts,
// and every file it leaves.
func newRBSandbox(t *testing.T) *rbSandbox {
	t.Helper()
	w := t.TempDir()
	vars := []string{
		"TACCTL_ETC=" + filepath.Join(w, "etc"),
		"TACCTL_STATE_DIR=" + filepath.Join(w, "state"),
		"TACCTL_VAR_LIB=" + filepath.Join(w, "var-lib"),
		"TACCTL_SSHD_DROPIN=" + filepath.Join(w, "sshd_config.d", "tacctl-console.conf"),
		"TACCTL_TIER_SUDOERS_FILE=" + filepath.Join(w, "sudoers.d", "tacctl-tiers"),
		"TACCTL_SUDOERS_FILE=" + filepath.Join(w, "sudoers.d", "tacctl"),
	}
	s := &rbSandbox{t: t, w: w}
	s.p = paths.Resolve(paths.NewEnv(vars), "", func(string) bool { return false })
	s.write(s.p.StoreFile, "version: 1\n", 0o600)
	s.write(s.p.Overrides, rbConf, 0o640)
	s.write(s.p.DevicesFile, rbDevices, 0o600)
	s.write(s.p.ConsoleFile, rbConsole, 0o600)
	s.write(filepath.Join(s.p.SNMPDir, "lab.yaml"), "community: lab-community-1\n", 0o600)
	s.write(filepath.Join(s.p.SNMPDir, "devices", "core-sw1.yaml"), "community: sw1-community\n", 0o600)
	s.write(s.p.ConfigRecords, "{\"version\": 1, \"devices\": {}}\n", 0o600)
	s.write(filepath.Join(s.p.ConfigDir, "core-sw1.yaml"), "aaa: []\n", 0o600)
	s.write(s.p.TierPinMarker, "", 0o644)
	s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
	s.write(s.p.SudoersFile, tier.GroupSudoers("ops"), 0o640)
	s.reload()
	s.in.InstallSudoers = func(body, dst string) error {
		s.ins = append(s.ins, dst)
		return os.WriteFile(dst, []byte(body), 0o640)
	}
	return s
}

// reload reads tacctl.yaml again, as a new run would.
func (s *rbSandbox) reload() {
	s.t.Helper()
	s.c = conf.Load(s.p.Overrides, conf.DefaultBackends)
	s.c.Owner = nil
	inst := s.in.InstallSudoers
	s.in = RollbackInput{Paths: s.p, Conf: s.c, HasStore: true, InstallSudoers: inst}
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

// old023Problems is what a reader of 0.2.3 refuses in the state, as fixtures
// of its three parsers (the tacctl.yaml schema, console.yaml and devices.yaml
// at the 0.2.3 tag): "<file>: <key>" for each. The sudoers drop-ins are
// not read by tacctl.
func old023Problems(t *testing.T, s *rbSandbox) []string {
	t.Helper()
	var out []string
	c := conf.Load(s.p.Overrides, conf.DefaultBackends)
	for _, k := range c.RollbackKeys023() {
		out = append(out, "tacctl.yaml: "+k)
	}
	load := func(path string) *yamlpy.Map {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		v, err := pyyaml.LoadBytes(b)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := v.(*yamlpy.Map)
		return m
	}
	if root := load(s.p.ConsoleFile); root != nil {
		for section, known := range map[string][]string{
			"tiers": {"readonly", "operator", "engineer", "superuser"},
			"settings": {"idle_timeout", "list_max", "agent_forwarding", "ssh_escape", "gateway_ports", "space_completion",
				"system_shell", "system_shell_tiers", "forwarding_tiers"},
		} {
			if sub, ok := root.Get(section); ok {
				for k := range sub.(*yamlpy.Map).All() {
					if !slices.Contains(known, k) {
						out = append(out, "console.yaml: "+section+"."+k)
					}
				}
			}
		}
	}
	if root := load(s.p.DevicesFile); root != nil {
		known := []string{"address", "vendor", "hostname", "description", "location", "port", "legacy_ssh", "host_keys", "ack"}
		if devs, ok := root.Get("devices"); ok && devs != nil {
			for name, d := range devs.(*yamlpy.Map).All() {
				for k := range d.(*yamlpy.Map).All() {
					if !slices.Contains(known, k) {
						out = append(out, "devices.yaml: device '"+name+"' has "+k)
					}
				}
			}
		}
	}
	return out
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
	if len(s.ins) != 0 {
		t.Errorf("the plan installed %q", s.ins)
	}
	if !p.Pending() || !p.PendingFiles() || !p.NeedsYes() {
		t.Errorf("pending %v files %v needs-yes %v", p.Pending(), p.PendingFiles(), p.NeedsYes())
	}
	wantKeys := []string{"device.config.max_concurrency", "device.config.transport", "device.config.timeout"}
	if !reflect.DeepEqual(p.Keys(), wantKeys) {
		t.Errorf("keys %q, want %q", p.Keys(), wantKeys)
	}
	steps := stepText(p)
	for _, want := range []string{
		s.p.Overrides + ": remove the keys 0.2.3 does not know",
		"remove device.config.max_concurrency", "remove device.config.transport", "remove device.config.timeout",
		s.p.ConsoleFile + ": write it the way 0.2.3 reads it",
		"remove settings.password_cache: tiers engineer,superuser, idle 30 min, max 4 h",
		s.p.DevicesFile + ": remove the per-device SNMP settings",
		"remove the snmp map of core-sw1 (version v3, port 2161, timeout 4 s, 2 client ranges)",
		"remove the snmp map of oob-con1 (port 1161)",
		"put back the sudoers drop-ins 0.2.3 writes",
		"rewrite " + s.p.TierSudoersFile + " (the per-tier drop-in: 0.2.3's text, after 'visudo -cf'; it loses the TACCTL_ASKPASS alias and env_keep line and the rows of 'device config', 'device snmp' and 'console forget')",
		"rewrite " + s.p.SudoersFile + " (the drop-in of group ops: 0.2.3's text",
		"leave " + filepath.Join(s.p.SNMPDir, "devices"),
		"1 file (mode 0600, kept): core-sw1",
		"leaves " + s.p.ConfigRecords, "leaves " + s.p.ConfigDir + " (1 file)",
		"leave " + s.p.StoreFile + " untouched",
		"the enrolled Linux hosts (--hosts)", "no host is synced",
	} {
		if !strings.Contains(steps, want) {
			t.Errorf("steps lack %q:\n%s", want, steps)
		}
	}
	for _, st := range p.Steps {
		wantTodo := strings.Contains(st.Title, "remove the") || strings.Contains(st.Title, "write it") || strings.Contains(st.Title, "put back")
		if st.Todo != wantTodo {
			t.Errorf("step %q: todo %v", st.Title, st.Todo)
		}
	}
	// What 0.2.3 has is not in the plan: not its keys, not its marker.
	for _, not := range []string{"linux.engineer_sudo", "snmp_scope", "breakglass", "space_completion", "tiers.engineer", "tier-pinned", "location"} {
		if strings.Contains(steps, not) {
			t.Errorf("steps name %q:\n%s", not, steps)
		}
	}
	if strings.Contains(steps, "re-render the enabled backends") {
		t.Errorf("a re-render is planned:\n%s", steps)
	}

	warns := warnText(p)
	for _, want := range []string{
		"Settings 0.2.3 cannot use are dropped",
		"core-sw1: version v3, port 2161, timeout 4 s, 2 client ranges",
		"oob-con1: port 1161",
		"The devices' own credentials (1 file in " + filepath.Join(s.p.SNMPDir, "devices") + ") stay, unused by 0.2.3.",
		"device.config.max_concurrency=16, device.config.transport=ssh, device.config.timeout=120",
		"The password cache's settings of console.yaml are removed (tiers engineer,superuser, idle 30 min, max 4 h)",
		"stays in the snapshot --apply takes first",
	} {
		if !strings.Contains(warns, want) {
			t.Errorf("warnings lack %q:\n%s", want, warns)
		}
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "restore it with 0.2.4") {
		t.Errorf("notes %q", p.Notes)
	}
}

// Without --hosts there is no host step.
func TestPlanRollbackWithoutHosts(t *testing.T) {
	s := newRBSandbox(t)
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stepText(p), "--hosts") || strings.Contains(stepText(p), "no host is synced") {
		t.Errorf("a host step without --hosts:\n%s", stepText(p))
	}
}

// --apply's conversions: each file is converted, everything else is left
// byte for byte, the state is then one a 0.2.3 reader accepts, and a second
// run changes nothing.
func TestApplyRollbackConvertsAndIsIdempotent(t *testing.T) {
	s := newRBSandbox(t)
	if p := old023Problems(t, s); len(p) < 5 {
		t.Fatalf("the 0.2.4 state is refused for only %q", p)
	}
	for _, want := range []string{"tacctl.yaml: device.config.timeout", "console.yaml: settings.password_cache", "devices.yaml: device 'core-sw1' has snmp", "devices.yaml: device 'oob-con1' has snmp"} {
		if !slices.Contains(old023Problems(t, s), want) {
			t.Errorf("the 0.2.4 state is not refused for %q", want)
		}
	}
	before := s.snapshotOf()
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	done, err := ApplyRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	wantDone := []string{
		s.p.Overrides + ": removed 3 keys",
		s.p.ConsoleFile + ": removed settings.password_cache",
		s.p.DevicesFile + ": removed the SNMP settings of 2 devices",
		s.p.TierSudoersFile + ": rewritten with the text 0.2.3 writes",
		s.p.SudoersFile + ": rewritten with the text 0.2.3 writes",
	}
	if !reflect.DeepEqual(done, wantDone) {
		t.Errorf("done %q\nwant %q", done, wantDone)
	}
	if len(p.NotWritten()) != 0 {
		t.Errorf("not written: %q", p.NotWritten())
	}
	after := s.snapshotOf()
	// The state is one 0.2.3 reads.
	if probs := old023Problems(t, s); len(probs) != 0 {
		t.Errorf("a 0.2.3 reader refuses the converted state: %q", probs)
	}
	// Only the five files changed.
	changed := map[string]bool{s.p.Overrides: true, s.p.ConsoleFile: true, s.p.DevicesFile: true, s.p.TierSudoersFile: true, s.p.SudoersFile: true}
	for path, b := range before {
		if a, ok := after[path]; !ok || (a != b) != changed[path] {
			t.Errorf("%s: changed %v, want %v", path, a != b, changed[path])
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok && !strings.HasSuffix(path, ".lock") {
			t.Errorf("a file appeared: %s", path)
		}
	}
	// What 0.2.3 has stays, key by key.
	ov := after[s.p.Overrides]
	for _, keep := range []string{"engineer_sudo:", "snmp_scope:", "breakglass_scope:", "tier:\n  engineer: engineer", "bcrypt:"} {
		if !strings.Contains(ov, keep) {
			t.Errorf("tacctl.yaml lost %q:\n%s", keep, ov)
		}
	}
	if strings.Contains(ov, "device:") || strings.Contains(ov, "max_concurrency") {
		t.Errorf("tacctl.yaml:\n%s", ov)
	}
	cs := after[s.p.ConsoleFile]
	for _, keep := range []string{"engineer: enable", "space_completion: false", "list_max: 40", "jdoe: disable"} {
		if !strings.Contains(cs, keep) {
			t.Errorf("console.yaml lost %q:\n%s", keep, cs)
		}
	}
	dv := after[s.p.DevicesFile]
	for _, keep := range []string{"location: 'Rack 4, DC1'", "address: 10.99.0.1", "description: DC1 core", "lab-rtr2"} {
		if !strings.Contains(dv, keep) {
			t.Errorf("devices.yaml lost %q:\n%s", keep, dv)
		}
	}
	if strings.Contains(dv, "snmp") || strings.Contains(dv, "2161") {
		t.Errorf("devices.yaml:\n%s", dv)
	}
	if after[s.p.TierSudoersFile] != tier.Sudoers023() || after[s.p.SudoersFile] != tier.GroupSudoers023("ops") {
		t.Error("a sudoers drop-in is not 0.2.3's text")
	}
	// The files 0.2.3 ignores, the credentials, the marker: untouched.
	for _, kept := range []string{filepath.Join(s.p.SNMPDir, "lab.yaml"), filepath.Join(s.p.SNMPDir, "devices", "core-sw1.yaml"),
		s.p.ConfigRecords, filepath.Join(s.p.ConfigDir, "core-sw1.yaml"), s.p.TierPinMarker, s.p.StoreFile} {
		if a, ok := after[kept]; !ok || a != before[kept] {
			t.Errorf("%s was not left alone", kept)
		}
	}

	// Idempotent: the dry run of the converted state has nothing to do and
	// the apply changes no byte.
	s.reload()
	p2, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Pending() || p2.PendingFiles() || p2.NeedsYes() || len(p2.Keys()) != 0 {
		t.Errorf("a converted state is pending: keys %q warnings %q", p2.Keys(), warnText(p2))
	}
	steps := stepText(p2)
	for _, want := range []string{"nothing to remove (every key is one 0.2.3 has)", "nothing to remove (settings.password_cache is not written)",
		"no device has SNMP settings of its own", "is already the text 0.2.3 writes"} {
		if !strings.Contains(steps, want) {
			t.Errorf("the second plan lacks %q:\n%s", want, steps)
		}
	}
	n := len(s.ins)
	done2, err := ApplyRollback(p2)
	if err != nil || len(done2) != 0 || len(s.ins) != n {
		t.Errorf("second apply: %q %v (installs %d -> %d)", done2, err, n, len(s.ins))
	}
	if !reflect.DeepEqual(after, s.snapshotOf()) {
		t.Error("the second apply changed a file")
	}
}

// A file that is not this release's text is left, a drop-in that cannot be
// installed is reported and does not stop the rest, and without an installer
// nothing is rewritten.
func TestRollbackSudoersCases(t *testing.T) {
	// Edited drop-ins are left; the plan says so.
	s := newRBSandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers()+"# local addition\n", 0o640)
	s.write(s.p.SudoersFile, tier.GroupSudoers("ops")+"%ops ALL=(ALL) NOPASSWD: /usr/bin/id\n", 0o640)
	before := s.snapshotOf()
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if st := stepText(p); !strings.Contains(st, "leaves "+s.p.TierSudoersFile+": it is not the text this release writes") ||
		!strings.Contains(st, "0.2.3's upgrade rewrites the per-tier drop-in") || !strings.Contains(st, "leaves "+s.p.SudoersFile) {
		t.Errorf("steps:\n%s", st)
	}
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	after := s.snapshotOf()
	if after[s.p.TierSudoersFile] != before[s.p.TierSudoersFile] || after[s.p.SudoersFile] != before[s.p.SudoersFile] || len(s.ins) != 0 {
		t.Errorf("an edited drop-in was rewritten: %q", s.ins)
	}

	// A drop-in of an older release (0.2.3's own text) is left, and said to be done.
	s = newRBSandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers023(), 0o640)
	s.write(s.p.SudoersFile, tier.GroupSudoers023("ops"), 0o640)
	p, _ = PlanRollback(s.in)
	if len(p.todoSudoers()) != 0 || strings.Count(stepText(p), "is already the text 0.2.3 writes") != 2 {
		t.Errorf("0.2.3's own text:\n%s", stepText(p))
	}

	// No drop-in at all: said, nothing to do.
	s = newRBSandbox(t)
	_ = os.Remove(s.p.TierSudoersFile)
	_ = os.Remove(s.p.SudoersFile)
	p, _ = PlanRollback(s.in)
	if !strings.Contains(stepText(p), "no tacctl sudoers drop-in is installed") {
		t.Errorf("no drop-ins:\n%s", stepText(p))
	}

	// An installer that fails: reported, the files are still converted.
	s = newRBSandbox(t)
	s.in.InstallSudoers = func(body, dst string) error { return errors.New("visudo validation failed") }
	p, _ = PlanRollback(s.in)
	done, err := ApplyRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(done) != 3 || len(p.NotWritten()) != 2 || !strings.Contains(p.NotWritten()[0], "visudo validation failed") {
		t.Errorf("done %q not written %q", done, p.NotWritten())
	}
	if len(old023Problems(t, s)) != 0 {
		t.Errorf("the files were not converted: %q", old023Problems(t, s))
	}

	// No installer: listed, left.
	s = newRBSandbox(t)
	s.in.InstallSudoers = nil
	p, _ = PlanRollback(s.in)
	done, _ = ApplyRollback(p)
	if len(done) != 3 || len(p.NotWritten()) != 2 {
		t.Errorf("done %q not written %q", done, p.NotWritten())
	}
}

// A state 0.2.3 can read has nothing to convert and no warning.
func TestPlanRollbackOfACleanState(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, "bcrypt:\n  cost: 11\nlinux:\n  engineer_sudo:\n  - /usr/bin/id\n", 0o640)
	s.write(s.p.ConsoleFile, "# tacctl login console\nversion: 1\ntiers: {readonly: enable, operator: enable, engineer: enable, superuser: enable}\nusers: {}\nsettings: {space_completion: false}\n", 0o600)
	s.write(s.p.DevicesFile, "version: 1\ndevices:\n  sw1: {address: 192.0.2.7, vendor: cisco, location: Rack 4}\n", 0o600)
	_ = os.Remove(s.p.TierSudoersFile)
	_ = os.Remove(s.p.SudoersFile)
	_ = os.RemoveAll(filepath.Join(s.p.SNMPDir, "devices"))
	_ = os.Remove(s.p.ConfigRecords)
	_ = os.RemoveAll(s.p.ConfigDir)
	s.reload()
	before := s.snapshotOf()
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if p.Pending() || p.NeedsYes() || len(p.Warnings) != 0 || len(p.Notes) != 0 {
		t.Errorf("pending %v warnings %q notes %q", p.Pending(), p.Warnings, p.Notes)
	}
	st := stepText(p)
	for _, want := range []string{"no file there", "no record of a configuration pull", "no device has SNMP settings of its own"} {
		if !strings.Contains(st, want) {
			t.Errorf("steps lack %q:\n%s", want, st)
		}
	}
	done, err := ApplyRollback(p)
	if err != nil || len(done) != 0 || !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Errorf("apply: %q %v", done, err)
	}
}

// A key neither release knows goes too and is named so.
func TestPlanRollbackNamesUnknownKeys(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, "bcrypt:\n  cost: 11\nfrobnicate:\n  level: 3\n", 0o640)
	s.reload()
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Keys(), []string{"frobnicate.level"}) || !strings.Contains(stepText(p), "remove frobnicate.level  (no release knows this key; 0.2.3 refuses a file that has it)") {
		t.Errorf("keys %q\n%s", p.Keys(), stepText(p))
	}
}

// Without a store there is no snapshot: a warning, as the other tools say.
func TestPlanRollbackWithoutAStore(t *testing.T) {
	s := newRBSandbox(t)
	s.in.HasStore = false
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warnText(p), "No snapshot can be taken") {
		t.Errorf("warnings:\n%s", warnText(p))
	}
}

// A file that cannot be read stops the plan before anything is converted.
func TestPlanRollbackRefusesUnreadableFiles(t *testing.T) {
	for name, file := range map[string]func(*rbSandbox) string{
		"console.yaml": func(s *rbSandbox) string { return s.p.ConsoleFile },
		"devices.yaml": func(s *rbSandbox) string { return s.p.DevicesFile },
	} {
		s := newRBSandbox(t)
		s.write(file(s), "version: 1\nfoo: [\n", 0o600)
		if _, err := PlanRollback(s.in); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	s := newRBSandbox(t)
	s.write(s.p.Overrides, "bcrypt: [\n", 0o640)
	s.reload()
	if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("tacctl.yaml: %v", err)
	}
}
