package cli

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/ui"
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
		// The markup only wraps text that was there: with the escapes
		// stripped, the usage is the bytes the golden holds.
		if got := stripSGR(Usage(c.id, c.vars)); got != stripSGR(string(want)) {
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

// stripSGR is s without its SGR sequences (ui.StripSGR).
func stripSGR(s string) string {
	var b bytes.Buffer
	w := ui.StripSGR(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.String()
}

// Every <b> and <o> of a usage block is closed on its own line by its own
// closing marker, none nests, and no other closing marker is there: a
// marker that is not one of these would reach the terminal as text.
func TestUsageMarkupBalanced(t *testing.T) {
	for _, id := range UsageIDs() {
		open := ""
		for n, line := range strings.Split(usageBlocks[id], "\n") {
			for i := 0; i < len(line); {
				switch {
				case strings.HasPrefix(line[i:], "<b>"), strings.HasPrefix(line[i:], "<o>"):
					if open != "" {
						t.Errorf("block %q line %d: <%s> opened inside <%s>", id, n+1, line[i+1:i+2], open)
					}
					open = line[i+1 : i+2]
					i += 3
				case strings.HasPrefix(line[i:], "</"):
					if !strings.HasPrefix(line[i:], "</b>") && !strings.HasPrefix(line[i:], "</o>") {
						t.Errorf("block %q line %d: unknown closing marker at %q", id, n+1, line[i:])
						i += 2
						continue
					}
					if open != line[i+2:i+3] {
						t.Errorf("block %q line %d: </%s> closes <%s>", id, n+1, line[i+2:i+3], open)
					}
					open = ""
					i += 4
				default:
					i++
				}
			}
			if open != "" {
				t.Errorf("block %q line %d: <%s> is not closed on its line", id, n+1, open)
				open = ""
			}
		}
	}
}

// The markup never reaches the output as text, and a styled block has
// both kinds of highlight in it.
func TestUsageResolvesMarkup(t *testing.T) {
	for _, c := range goldenCases {
		got := Usage(c.id, c.vars)
		for _, m := range []string{"<b>", "</b>", "<o>", "</o>"} {
			if strings.Contains(got, m) {
				t.Errorf("usage %s holds the marker %s", c.id, m)
			}
		}
	}
	top := Usage("top", UsageVars{"version": "v"})
	for _, want := range []string{ui.Bold + "install" + ui.NC, ui.Cyan + "--branch <name>" + ui.NC} {
		if !strings.Contains(top, want) {
			t.Errorf("top usage lacks %q", want)
		}
	}
}

// The shell reads its lists from the blocks with the markup in them (raw or
// resolved): the rows are the ones of the plain text.
func TestUsageRowsIgnoreMarkup(t *testing.T) {
	for _, c := range goldenCases {
		want, err := os.ReadFile(filepath.Join("testdata", "usage", c.file+".out"))
		if err != nil {
			t.Fatal(err)
		}
		plain := stripSGR(string(want))
		for _, heading := range []string{"Commands:", "Subcommands:", "Usage:"} {
			got := usageRows(Usage(c.id, c.vars), heading)
			if exp := usageRows(plain, heading); !reflect.DeepEqual(got, exp) {
				t.Errorf("usage %s %s rows: %q, plain %q", c.id, heading, got, exp)
			}
		}
	}
	rows := topRows()
	if len(rows) == 0 || rows[0].Name != "install" || rows[0].Left != "install [--branch <name>] [-y|--yes]" {
		t.Errorf("topRows %q", rows)
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
