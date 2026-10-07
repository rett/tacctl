package cli

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// goldenCases maps each usage block to the testdata/usage file (written by
// tests/tools/usage-goldens.sh from the 0.1.16 tag, with the minimal fixture
// loaded) and the slot values that state gives it.
var goldenCases = []struct {
	id, file string
	vars     UsageVars
}{
	{"top", "top", UsageVars{"version": "unknown"}},
	{"user", "user", nil},
	{"group", "group", nil},
	{"group-commands", "group-commands", UsageVars{"overrides": "/etc/tacctl/tacctl.yaml"}},
	{"group-privilege", "group-privilege", nil},
	{"group-junos", "group-junos", UsageVars{"overrides": "/etc/tacctl/tacctl.yaml"}},
	{"scope", "scope", UsageVars{"current": "Current scopes: 1\nDefault scope:  lab"}},
	{"scope-prefixes", "scope-prefixes", UsageVars{"scope": "lab", "current": "Current entries: 1"}},
	{"scope-secret", "scope-secret", UsageVars{"scope": "lab", "current": "Current length: 30 chars (min 16)"}},
	{"scope-mgmt-acl", "scope-mgmt-acl", UsageVars{"scope": "lab", "current": "Current entries: 0 (per-scope) / 0 (global fallback)"}},
	{"config", "config", nil},
	{"config-filter", "config-allow", UsageVars{"label": "allow", "current": "Current entries: 0"}},
	{"config-filter", "config-deny", UsageVars{"label": "deny", "current": "Current entries: 0"}},
	{"config-mgmt-acl", "config-mgmt-acl", UsageVars{"current": "         cisco=VTY-ACL  juniper=MGMT-ACL\nCurrent entries: 0"}},
	{"config-linux", "config-linux", nil},
	{"host", "host", nil},
	{"backend", "backend", UsageVars{"backends": "tacacs radius"}},
	{"store", "store", nil},
	{"log", "log", nil},
	{"backup", "backup", nil},
	{"hash", "hash", nil},
}

func TestUsageMatchesBash(t *testing.T) {
	seen := map[string]bool{}
	files := map[string]bool{}
	for _, c := range goldenCases {
		seen[c.id] = true
		files[c.file] = true
		want, err := os.ReadFile(filepath.Join("testdata", "usage", c.file+".out"))
		if err != nil {
			t.Fatal(err)
		}
		if got := Usage(c.id, c.vars); got != string(want) {
			t.Errorf("usage %s (%s.out) differs from bash:\n--- got\n%s\n--- want\n%s", c.id, c.file, got, want)
		}
	}
	for _, id := range UsageIDs() {
		if !seen[id] {
			t.Errorf("usage block %q has no golden case", id)
		}
	}
	// Every golden file the generator wrote is checked.
	f, err := os.Open(filepath.Join("testdata", "usage", "cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		name := strings.SplitN(line, "\t", 2)[0]
		if !files[name] {
			t.Errorf("testdata/usage/%s.out is not compared with any usage block", name)
		}
	}
}

func TestUsagePanics(t *testing.T) {
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: no panic", name)
			}
		}()
		f()
	}
	mustPanic("unknown block", func() { Usage("nope", nil) })
	mustPanic("unfilled slot", func() { Usage("top", nil) })
	mustPanic("unfilled second slot", func() { Usage("scope-prefixes", UsageVars{"scope": "lab"}) })
}

func TestUsageIDs(t *testing.T) {
	ids := UsageIDs()
	if len(ids) != len(usageBlocks) || !reflect.DeepEqual(ids[:2], []string{"backend", "backup"}) {
		t.Errorf("UsageIDs = %q", ids)
	}
}
