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
		in022, in023 := slices.Contains(Known022, f), slices.Contains(Added023, f)
		switch {
		case in022 && in023:
			t.Errorf("%+v is in both Known022 and Added023", f)
		case !in022 && !in023:
			t.Errorf("schema.go has the key family %+v, which rollback.go lists in neither Known022 (0.2.2 has it) nor Added023 (0.2.3 added it): decide, so a rollback to 0.2.2 knows what to remove", f)
		}
	}
	for _, tbl := range []struct {
		name string
		list []Family
	}{{"Known022", Known022}, {"Added023", Added023}} {
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

// Where the 0.2.2 tag is in this repository, Known022 is that release's
// schema: its exact keys and wildcard prefixes, read from the source of the
// tag, are the table (an entry of Added023 is not in it).
func TestKnown022IsTheSchemaOfTheTag(t *testing.T) {
	r := execx.Real{}
	// Skipped only where git or the tag is genuinely absent, and says which;
	// CI must fetch the tags (git fetch --tags) or this check never runs
	// there. With the tag here, not being able to read it is a failure.
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the schema of the 0.2.2 tag cannot be read")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.2^{commit}"}})
	if err != nil || res.Code != 0 {
		t.Skip("the 0.2.2 tag is not in this repository (CI must fetch tags: git fetch --tags), so its schema cannot be read")
	}
	res, err = r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.2:internal/conf/schema.go"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the schema of the 0.2.2 tag: %v %s", err, res.Stderr)
	}
	out := res.Stdout
	var want []string
	for _, m := range reExactKey.FindAllStringSubmatch(string(out), -1) {
		want = append(want, m[1])
	}
	for _, m := range reWildcard.FindAllStringSubmatch(string(out), -1) {
		want = append(want, m[1])
	}
	var got []string
	for _, f := range Known022 {
		got = append(got, f.Path)
	}
	sort.Strings(want)
	sort.Strings(got)
	if len(want) < 20 {
		t.Fatalf("read only %d keys from the schema of the tag", len(want))
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Known022 differs from the schema of 0.2.2:\n got %q\nwant %q", got, want)
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
