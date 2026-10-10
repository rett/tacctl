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
		in022, in023, in024 := slices.Contains(Known022, f), slices.Contains(Added023, f), slices.Contains(Added024, f)
		n := 0
		for _, in := range []bool{in022, in023, in024} {
			if in {
				n++
			}
		}
		switch {
		case n > 1:
			t.Errorf("%+v is in more than one of Known022, Added023 and Added024", f)
		case n == 0:
			t.Errorf("schema.go has the key family %+v, which rollback.go lists in none of Known022 (0.2.2 has it), Added023 (0.2.3 added it) and Added024 (0.2.4 added it): decide, so a rollback knows what to remove", f)
		}
	}
	for _, tbl := range []struct {
		name string
		list []Family
	}{{"Known022", Known022}, {"Added023", Added023}, {"Added024", Added024}} {
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
