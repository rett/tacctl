package conf

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// Every key family of the schema is in exactly one of the two tables of
// rollback.go, and every entry of the tables is in the schema. A key family
// added to schema.go fails here until someone decides whether a 0.2.2
// binary knows it (a rollback strips the ones it does not).
func TestRollbackTablesMatchTheSchema(t *testing.T) {
	s := NewSchema(DefaultBackends)
	var schema []Family
	for _, k := range s.Keys() {
		schema = append(schema, Family{k, false})
	}
	seen := map[string]bool{}
	for _, w := range s.Wildcards() {
		if !seen[w] {
			seen[w] = true
			schema = append(schema, Family{w, true})
		}
	}
	for _, f := range schema {
		in022, in023, in024, in025, in027, in029, in0210, in0217, in0219, in0220, in0221, in0222 := slices.Contains(Known022, f), slices.Contains(Added023, f), slices.Contains(Added024, f), slices.Contains(Added025, f), slices.Contains(Added027, f), slices.Contains(Added029, f), slices.Contains(Added0210, f), slices.Contains(Added0217, f), slices.Contains(Added0219, f), slices.Contains(Added0220, f), slices.Contains(Added0221, f), slices.Contains(Added0222, f)
		n := 0
		for _, in := range []bool{in022, in023, in024, in025, in027, in029, in0210, in0217, in0219, in0220, in0221, in0222} {
			if in {
				n++
			}
		}
		switch {
		case n > 1:
			t.Errorf("%+v is in more than one of Known022, Added023, Added024, Added025, Added027, Added029, Added0210, Added0217, Added0219, Added0220, Added0221 and Added0222", f)
		case n == 0:
			t.Errorf("schema.go has the key family %+v, which rollback.go lists in none of Known022 (0.2.2 has it), Added023 (0.2.3 added it), Added024 (0.2.4 added it), Added025 (0.2.5 added it), Added027 (0.2.7 added it), Added029 (0.2.9 added it) and Added0210 (0.2.10 added it), Added0217 (0.2.17 added it), Added0219 (0.2.19 added it), Added0220 (0.2.20 added it), Added0221 (0.2.21 added it) and Added0222 (0.2.22 added it): decide, so a rollback knows what to remove", f)
		}
	}
	for _, tbl := range []struct {
		name string
		list []Family
	}{{"Known022", Known022}, {"Added023", Added023}, {"Added024", Added024}, {"Added025", Added025}, {"Added027", Added027}, {"Added029", Added029}, {"Added0210", Added0210}, {"Added0217", Added0217}, {"Added0219", Added0219}, {"Added0220", Added0220}, {"Added0221", Added0221}, {"Added0222", Added0222}} {
		for _, f := range tbl.list {
			if !slices.Contains(schema, f) {
				t.Errorf("%s lists %+v, which schema.go no longer has", tbl.name, f)
			}
		}
	}
}

var (
	reExactKey = regexp.MustCompile(`(?m)^\t\t\t"([a-z0-9_.]+)":\s+\{Type:`)
	reWildcard = regexp.MustCompile(`(?m)^\t\t\t\{"([a-z0-9_.]+\.)", Rule\{`)
)

// tagSchemaKeys are the exact keys and wildcard prefixes of the schema of a
// release tag, sorted, read from its source. The test is skipped only where
// git or the tag is genuinely absent, and says which; CI must fetch the tags
// (git fetch --tags) or the check never runs there. With the tag here, not
// being able to read it is a failure.
func tagSchemaKeys(t *testing.T, tag string) []string {
	t.Helper()
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the schema of the " + tag + " tag cannot be read")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", tag + "^{commit}"}})
	if err != nil || res.Code != 0 {
		t.Skip("the " + tag + " tag is not in this repository (CI must fetch tags: git fetch --tags), so its schema cannot be read")
	}
	res, err = r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", tag + ":internal/conf/schema.go"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the schema of the %s tag: %v %s", tag, err, res.Stderr)
	}
	out := res.Stdout
	var want []string
	for _, m := range reExactKey.FindAllStringSubmatch(string(out), -1) {
		want = append(want, m[1])
	}
	for _, m := range reWildcard.FindAllStringSubmatch(string(out), -1) {
		want = append(want, m[1])
	}
	sort.Strings(want)
	if len(want) < 20 {
		t.Fatalf("read only %d keys from the schema of the %s tag", len(want), tag)
	}
	return want
}

func familyPaths(lists ...[]Family) []string {
	var got []string
	for _, l := range lists {
		for _, f := range l {
			got = append(got, f.Path)
		}
	}
	sort.Strings(got)
	return got
}

// Where the 0.2.2 tag is in this repository, Known022 is that release's
// schema: its exact keys and wildcard prefixes, read from the source of the
// tag, are the table (an entry of Added023 is not in it).
func TestKnown022IsTheSchemaOfTheTag(t *testing.T) {
	want := tagSchemaKeys(t, "0.2.2")
	if got := familyPaths(Known022); !reflect.DeepEqual(got, want) {
		t.Errorf("Known022 differs from the schema of 0.2.2:\n got %q\nwant %q", got, want)
	}
}

// Where the 0.2.3 tag is here, Known022 and Added023 together are that
// release's schema, and Added024 holds nothing it has: the rollback to 0.2.3
// removes exactly what is not in it.
func TestKnown023IsTheSchemaOfTheTag(t *testing.T) {
	want := tagSchemaKeys(t, "0.2.3")
	// The per-scope SNMP keys are registered by snmp.go in that release, not
	// listed in schema.go: its prefix constant is the family.
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.3:internal/conf/snmp.go"}})
	if err != nil || res.Code != 0 || !strings.Contains(string(res.Stdout), `const SNMPScopePrefix = "snmp_scope."`) {
		t.Fatalf("cannot read the SNMP prefix of the 0.2.3 tag: %v %s", err, res.Stderr)
	}
	want = append(want, "snmp_scope.")
	sort.Strings(want)
	if got := familyPaths(Known022, Added023); !reflect.DeepEqual(got, want) {
		t.Errorf("Known022 and Added023 differ from the schema of 0.2.3:\n got %q\nwant %q", got, want)
	}
	for _, f := range Added024 {
		if slices.Contains(want, f.Path) {
			t.Errorf("Added024 lists %q, which the schema of 0.2.3 has", f.Path)
		}
	}
}

// Where the 0.2.8 tag is here, Added029 holds nothing its schema has: the
// rollback to 0.2.8 removes exactly the keys 0.2.9 added, and the settings
// of 'device config apply' are among them.
func TestAdded029IsNotInTheSchemaOfTheTag(t *testing.T) {
	want := tagSchemaKeys(t, "0.2.8")
	for _, f := range Added029 {
		if slices.Contains(want, f.Path) {
			t.Errorf("Added029 lists %q, which the schema of 0.2.8 has", f.Path)
		}
	}
	if !Added029Key("device.apply.pause") || !Added029Key("device.apply.confirm_timeout") ||
		Added029Key("device.config.confirm_timeout") || Added029Key("device.apply.pause.x") {
		t.Error("Added029Key is not the two device.apply keys")
	}
}

// Where the 0.2.9 tag is here, Added0210 holds nothing its schema has, and is
// exactly the NETCONF service keys of a scope.
func TestAdded0210IsNotInTheSchemaOfTheTag(t *testing.T) {
	want := tagSchemaKeys(t, "0.2.9")
	for _, f := range Added0210 {
		if slices.Contains(want, f.Path) {
			t.Errorf("Added0210 lists %q, which the schema of 0.2.9 has", f.Path)
		}
	}
	if !Added0210Key(NetconfPath("lab", NetconfKeyState)) || !Added0210Key(NetconfPath("lab", NetconfKeyRateLimit)) ||
		Added0210Key("snmp_scope.lab.version") || Added0210Key("netconf_scopex.lab.state") {
		t.Error("Added0210Key is not the netconf_scope keys")
	}
}

// Where the 0.2.16 tag is here, Added0217 holds nothing its schema has, so a
// 0.2.16 binary refuses audit.strict, and the rollback to 0.2.16 removes
// exactly it.
func TestAdded0217IsNotInTheSchemaOfTheTag(t *testing.T) {
	want := tagSchemaKeys(t, "0.2.16")
	for _, f := range Added0217 {
		if slices.Contains(want, f.Path) {
			t.Errorf("Added0217 lists %q, which the schema of 0.2.16 has", f.Path)
		}
	}
	if !Added0217Key("audit.strict") || Added0217Key("audit.strict.x") || Added0217Key("audit") || Added0217Key("auditx.strict") {
		t.Error("Added0217Key is not the key audit.strict")
	}
}

// Where the 0.2.18 tag is here, Added0219 holds nothing its schema has, so a
// 0.2.18 binary refuses the lockdown record, and the keys the rollbacks list
// are the leaves of that family.
func TestAdded0219IsNotInTheSchemaOfTheTag(t *testing.T) {
	want := tagSchemaKeys(t, "0.2.18")
	for _, f := range Added0219 {
		if slices.Contains(want, f.Path) {
			t.Errorf("Added0219 lists %q, which the schema of 0.2.18 has", f.Path)
		}
	}
	if !Added0219Key("emergency.lockdown.lab.groups") || !Added0219Key("emergency.lockdown.lab") || Added0219Key("emergency") || Added0219Key("emergencyx.lockdown.lab") {
		t.Error("Added0219Key is not the emergency.lockdown family")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	if err := os.WriteFile(path, []byte("audit:\n  strict: true\nemergency:\n  lockdown:\n    lab:\n      reason: drill\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	if got := strings.Join(c.RollbackKeys0218(), " "); got != "emergency.lockdown.lab.reason" {
		t.Errorf("RollbackKeys0218 = %q", got)
	}
	if got := strings.Join(c.RollbackKeys0216(), " "); got != "audit.strict emergency.lockdown.lab.reason" {
		t.Errorf("RollbackKeys0216 = %q", got)
	}
	if got := strings.Join(c.RollbackKeys029(), " "); got != "audit.strict emergency.lockdown.lab.reason" {
		t.Errorf("RollbackKeys029 = %q", got)
	}
}

// Where the 0.2.19 tag is here, Added0220 holds nothing its schema has, so a
// 0.2.19 binary refuses the mode key; every rollback lists the keys, and
// 0.2.3 lists them as keys it does not know.
func TestAdded0220IsNotInTheSchemaOfTheTag(t *testing.T) {
	want := tagSchemaKeys(t, "0.2.19")
	for _, f := range Added0220 {
		if slices.Contains(want, f.Path) {
			t.Errorf("Added0220 lists %q, which the schema of 0.2.19 has", f.Path)
		}
	}
	if !Added0220Key("scope_mgmt_acl.mode.lab") || Added0220Key("scope_mgmt_acl.permits.lab") || Added0220Key("scope_mgmt_acl.names.juniper.lab") || Added0220Key("scope_mgmt_acl.modes.lab") {
		t.Error("Added0220Key is not the scope_mgmt_acl.mode family")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	if err := os.WriteFile(path, []byte("audit:\n  strict: true\nscope_mgmt_acl:\n  permits:\n    lab: [10.0.0.0/8]\n  mode:\n    lab: strict\n    dmz: strict\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	for name, got := range map[string][]string{"0.2.18": c.RollbackKeys0218(), "0.2.16": c.RollbackKeys0216(), "0.2.9": c.RollbackKeys029(), "0.2.3": c.RollbackKeys023()} {
		if !slices.Contains(got, "scope_mgmt_acl.mode.lab") || !slices.Contains(got, "scope_mgmt_acl.mode.dmz") || slices.Contains(got, "scope_mgmt_acl.permits.lab") {
			t.Errorf("RollbackKeys for %s = %v", name, got)
		}
	}
	if got := c.MgmtACLStrictScopes(); !slices.Equal(got, []string{"dmz", "lab"}) {
		t.Errorf("MgmtACLStrictScopes = %v", got)
	}
}

// The mode of a scope: strict only when it is stored, ssh-only for a scope
// that has none, for the global list and for a word the schema refuses.
func TestMgmtACLMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	if err := os.WriteFile(path, []byte("scope_mgmt_acl:\n  mode:\n    lab: strict\n    dmz: ssh-only\n    odd: lax\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	for scope, want := range map[string]string{"lab": MgmtModeStrict, "dmz": MgmtModeSSHOnly, "odd": MgmtModeSSHOnly, "none": MgmtModeSSHOnly, "": MgmtModeSSHOnly} {
		if got := c.MgmtACLMode(scope); got != want {
			t.Errorf("MgmtACLMode(%q) = %q, want %q", scope, got, want)
		}
	}
	s := NewSchema(DefaultBackends)
	if lines := s.ValidateFile(path); len(lines) != 1 || !strings.HasPrefix(lines[0], "scope_mgmt_acl.mode.odd: must be one of: ssh-only, strict") {
		t.Errorf("a word that is no mode is not reported: %q", lines)
	}
	for value, ok := range map[any]bool{"strict": true, "ssh-only": true, "lax": false, "": false, 1: false} {
		if got := s.Validate("scope_mgmt_acl.mode.lab", value, false) == ""; got != ok {
			t.Errorf("Validate(%v) accepted = %v", value, got)
		}
	}
	if s.Validate("scope_mgmt_acl.mode.lab", []any{"strict"}, true) == "" {
		t.Error("a list is accepted as a mode")
	}
}

func TestUnknown023(t *testing.T) {
	for path, want := range map[string]bool{
		"linux.engineer_sudo":           false, // 0.2.3 added it
		"snmp_scope.lab.version":        false,
		"breakglass_scope.lab.users":    false,
		"tier.engineer":                 false,
		"snmp.timeout":                  false,
		"listeners.tacacs.main":         false,
		"device.config.max_concurrency": true, // 0.2.4 added it
		"device.config.transport":       true,
		"device.config.timeout":         true,
		"device.config.timeout.extra":   true,
		"cisco.source_interface.lab":    true, // 0.2.5 added it
		"nonsense.key":                  true,
		"snmp_scopex":                   true,
		"":                              true,
	} {
		if got := Unknown023(path); got != want {
			t.Errorf("Unknown023(%q) = %v, want %v", path, got, want)
		}
	}
}

// RollbackKeys023 is the device.config keys and what neither release knows;
// everything 0.2.3 has stays, and the keys go in one write.
func TestRollbackKeys023(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	text := "bcrypt:\n  cost: 11\nlinux:\n  engineer_sudo:\n  - /usr/bin/id\nsnmp_scope:\n  lab:\n    version: v2c\n" +
		"device:\n  config:\n    max_concurrency: 16\n    transport: ssh\n    timeout: 120\nfrobnicate:\n  level: 3\n"
	if err := os.WriteFile(path, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	keys := c.RollbackKeys023()
	want := []string{"device.config.max_concurrency", "device.config.transport", "device.config.timeout", "frobnicate.level"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys %q, want %q", keys, want)
	}
	for _, k := range keys[:3] {
		if !Added024Key(k) {
			t.Errorf("%s is not in the 0.2.4 table", k)
		}
	}
	if err := c.UnsetMany(keys); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !strings.HasSuffix(string(got), "bcrypt:\n  cost: 11\nlinux:\n  engineer_sudo:\n  - /usr/bin/id\nsnmp_scope:\n  lab:\n    version: v2c\n") ||
		strings.Contains(string(got), "device") || strings.Contains(string(got), "frobnicate") {
		t.Errorf("after:\n%s", got)
	}
	if left := c.RollbackKeys023(); len(left) != 0 {
		t.Errorf("keys left: %q", left)
	}
}

func TestUnknown022(t *testing.T) {
	for path, want := range map[string]bool{
		"linux.engineer_sudo":              true,
		"snmp_scope.lab.version":           true,
		"snmp_scope.lab.v3.auth":           true,
		"snmp_scope":                       true,
		"breakglass_scope.lab.users":       true,
		"breakglass_scope":                 true,
		"tier.engineer":                    false, // 0.2.2 has the key, and the value
		"tier.ops":                         false,
		"linux.uid_min":                    false,
		"snmp.version":                     false,
		"snmp.v3.auth":                     false,
		"commands.engineer":                false,
		"junos.engineer.deny_commands":     false,
		"wti_level.ops":                    false,
		"listeners.tacacs.main":            false,
		"mgmt_acl.permits":                 false,
		"scope_mgmt_acl.permits.lab":       false,
		"bcrypt.cost":                      false,
		"backends.enabled":                 false,
		"nonsense.key":                     true, // neither release knows it
		"linux.engineer_sudo_extra":        true,
		"device.config.timeout":            true, // 0.2.4 added it
		"snmp_scope_x.lab":                 true,
		"snmp_scopex":                      true,
		"snmp":                             true, // a scalar where a mapping belongs
		"linux":                            true,
		"":                                 true,
		"breakglass_scope.lab.users.extra": true,
	} {
		if got := Unknown022(path); got != want {
			t.Errorf("Unknown022(%q) = %v, want %v", path, got, want)
		}
	}
}

const rollbackSample = `# header
bcrypt:
  cost: 11
linux:
  uid_min: 70000
  uid_max: 79999
  engineer_sudo:
  - /usr/bin/systemctl
tier:
  ops: engineer
snmp_scope:
  lab:
    version: v2c
    contact: Rack 4
    clients:
    - 10.1.0.0/16
    v3:
      auth: sha
breakglass_scope:
  lab:
    users:
    - bg:admin
`

func TestRollbackKeysAndUnsetMany(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	if err := os.WriteFile(path, []byte(rollbackSample), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	keys := c.RollbackKeys022()
	want := []string{"linux.engineer_sudo", "snmp_scope.lab.version", "snmp_scope.lab.contact", "snmp_scope.lab.clients",
		"snmp_scope.lab.v3.auth", "breakglass_scope.lab.users"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys %q, want %q", keys, want)
	}
	if err := c.UnsetMany(keys); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	wantText := "bcrypt:\n  cost: 11\nlinux:\n  uid_min: 70000\n  uid_max: 79999\ntier:\n  ops: engineer\n"
	if !strings.HasSuffix(string(got), wantText) || strings.Contains(string(got), "snmp_scope") ||
		strings.Contains(string(got), "breakglass") || strings.Contains(string(got), "engineer_sudo") {
		t.Errorf("after:\n%s", got)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("mode: %v %v", fi, err)
	}
	if left := c.RollbackKeys022(); len(left) != 0 {
		t.Errorf("keys left: %q", left)
	}
	// Idempotent: nothing to remove writes nothing.
	before, _ := os.Stat(path)
	if err := c.UnsetMany(nil); err != nil {
		t.Fatal(err)
	}
	if err := c.UnsetMany([]string{"snmp_scope.lab.version", "linux.engineer_sudo"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("the file was rewritten for keys that are not there")
	}
	// The file goes when nothing is left.
	only := filepath.Join(dir, "only.yaml")
	if err := os.WriteFile(only, []byte("linux:\n  engineer_sudo:\n  - /usr/bin/id\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c2 := Load(only, DefaultBackends)
	if err := c2.UnsetMany(c2.RollbackKeys022()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(only); !os.IsNotExist(err) {
		t.Errorf("an emptied tacctl.yaml was kept: %v", err)
	}
	// A key too deep for its family is unknown to 0.2.2 as well.
	deep := filepath.Join(dir, "deep.yaml")
	if err := os.WriteFile(deep, []byte("tier:\n  ops:\n    x: engineer\n  lead: engineer\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if k := Load(deep, DefaultBackends).RollbackKeys022(); !reflect.DeepEqual(k, []string{"tier.ops.x"}) {
		t.Errorf("deep keys %q", k)
	}
	// A key neither release knows goes too, and is named.
	odd := filepath.Join(dir, "odd.yaml")
	if err := os.WriteFile(odd, []byte("bcrypt:\n  cost: 11\nfrobnicate:\n  level: 3\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c3 := Load(odd, DefaultBackends)
	if k := c3.RollbackKeys022(); !reflect.DeepEqual(k, []string{"frobnicate.level"}) {
		t.Errorf("odd keys %q", k)
	}
}

// audit.strict is what the rollback to 0.2.16 removes, and one of the keys the
// rollbacks to 0.2.9 and 0.2.3 remove with the others; an empty 'audit:' map
// holds no key. Removing it prunes the mapping it leaves empty.
func TestRollbackKeysOfAuditStrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	text := "bcrypt:\n  cost: 11\naudit:\n  strict: true\ndevice:\n  apply:\n    transport: netconf\n"
	if err := os.WriteFile(path, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	if got, want := c.RollbackKeys0216(), []string{"audit.strict"}; !reflect.DeepEqual(got, want) {
		t.Errorf("0.2.16 keys %q, want %q", got, want)
	}
	if got, want := c.RollbackKeys029(), []string{"audit.strict", "device.apply.transport"}; !reflect.DeepEqual(got, want) {
		t.Errorf("0.2.9 keys %q, want %q", got, want)
	}
	if got := c.RollbackKeys023(); !slices.Contains(got, "audit.strict") {
		t.Errorf("0.2.3 keys %q lack audit.strict", got)
	}
	if err := c.UnsetMany(c.RollbackKeys0216()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "audit") || !strings.Contains(string(got), "transport: netconf") {
		t.Errorf("after:\n%s", got)
	}
	if left := c.RollbackKeys0216(); len(left) != 0 {
		t.Errorf("keys left: %q", left)
	}
	if err := os.WriteFile(path, []byte("audit: {}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if keys := Load(path, DefaultBackends).RollbackKeys0216(); len(keys) != 0 {
		t.Errorf("an empty audit mapping yields %q", keys)
	}
}

// Where the 0.2.21 tag is here, Added0222 holds nothing its schema has, so a
// 0.2.21 binary refuses server.name; every rollback lists the key, and 0.2.3
// lists it as a key it does not know. The keys 0.2.21 added (server.addresses)
// are ones the rollback to 0.2.21 keeps.
func TestAdded0222IsNotInTheSchemaOfTheTag(t *testing.T) {
	want := tagSchemaKeys(t, "0.2.21")
	for _, f := range Added0222 {
		if slices.Contains(want, f.Path) {
			t.Errorf("Added0222 lists %q, which the schema of 0.2.21 has", f.Path)
		}
	}
	if !slices.Contains(want, "server.addresses") {
		t.Error("the schema of 0.2.21 lacks server.addresses")
	}
	if !Added0222Key("server.name") || Added0222Key("server.names") || Added0222Key("server.addresses") || Added0222Key("server") {
		t.Error("Added0222Key is not server.name")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	if err := os.WriteFile(path, []byte("audit:\n  strict: true\nserver:\n  addresses: [192.0.2.10]\n  name: core-1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c := Load(path, DefaultBackends)
	if got := c.RollbackKeys0221(); !slices.Equal(got, []string{"server.name"}) {
		t.Errorf("RollbackKeys0221 = %v", got)
	}
	for name, got := range map[string][]string{"0.2.20": c.RollbackKeys0220(), "0.2.18": c.RollbackKeys0218(), "0.2.16": c.RollbackKeys0216(), "0.2.9": c.RollbackKeys029(), "0.2.3": c.RollbackKeys023()} {
		if !slices.Contains(got, "server.name") || !slices.Contains(got, "server.addresses") {
			t.Errorf("RollbackKeys for %s = %v", name, got)
		}
	}
	if err := c.UnsetMany(c.RollbackKeys0221()); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "name") || !strings.Contains(string(got), "192.0.2.10") {
		t.Errorf("after:\n%s", got)
	}
}
