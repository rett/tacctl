package fakedev

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wtiFixtures is the directory of the captures, absolute: a manifest in a
// temporary directory names it.
var wtiFixtures = func() string {
	p, err := filepath.Abs("../../../tests/fixtures/devconf/wti")
	if err != nil {
		panic(err)
	}
	return p
}()

func menuDir(t *testing.T, manifest string, files map[string]string) transcript {
	t.Helper()
	dir := t.TempDir()
	files["menu"] = manifest
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return transcript{dir: dir}
}

func TestMenuManifestErrors(t *testing.T) {
	scr := "screens " + wtiFixtures + "\n"
	for name, c := range map[string]struct{ manifest, want string }{
		"unknown key":        {scr + "levl user\n", `unknown key "levl"`},
		"bad level":          {scr + "level root\n", "viewonly, user, superuser, administrator"},
		"bad version":        {scr + "version eight\n", "a version like 8.10"},
		"bad sessions":       {scr + "sessions 40\n", "0 to 31"},
		"more users":         {scr + "sessions 1\nsession-users a b\n", "2 session-users for 1 sessions"},
		"bad iptables":       {scr + "iptables some\n", "'empty', 'filled' or 'file <path>'"},
		"iptables file":      {scr + "iptables file nothing\n", "nothing"},
		"page needs =":       {scr + "page /N > 28\n", "'<path> = <file>'"},
		"page file missing":  {scr + "page /N > 99 = none.txt\n", "page /N > 99"},
		"screens not a dir":  {"screens /nonexistent\n", "help of level"},
		"no screens default": {"level user\n", "help of level"},
	} {
		t.Run(name, func(t *testing.T) {
			tr := menuDir(t, c.manifest, map[string]string{})
			_, err := loadMenu(tr, "")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestMenuManifestDefaultsAndPageOverride(t *testing.T) {
	tr := menuDir(t, "screens "+wtiFixtures+"\n# comment\n\npage /N > 28 > 6 = screen.txt\nsessions 2\n",
		map[string]string{"screen.txt": "# path: whatever\n# ---\n6\n\nFALLBACK LOCAL:\n"})
	c, err := loadMenu(tr, "")
	if err != nil {
		t.Fatal(err)
	}
	if c.version != "8.10" || c.level != "administrator" || c.prompt != "DSM> " || c.sessions != 2 || len(c.iptables) != 0 {
		t.Errorf("defaults: %+v", c)
	}
	if body, ok := c.page("/N > 28 > 6"); !ok || !strings.Contains(body, "FALLBACK LOCAL:") {
		t.Errorf("the page override: %q %v", body, ok)
	}
	if !c.allowed["/N"] || !c.allowed["/UFW"] || c.allowed["/ZZ"] {
		t.Errorf("allowed: %v", c.allowed)
	}
	// The captures' headers name the pages.
	for _, k := range []string{"/N", "/F", "/P", "/AC", "/N > 28 > 8", "/N > 5", "/F > 1", "/F > 1 > 1", "/F > 1 > 1 > localadmin"} {
		if _, ok := c.pages[k]; !ok {
			t.Errorf("no page %q", k)
		}
	}
	if c.hasChildren("/N > 28 > 1") || !c.hasChildren("/N > 28") {
		t.Error("hasChildren")
	}
}

func TestMenuLevelsListTheirCommands(t *testing.T) {
	want := map[string][]string{
		"viewonly":      {"/S", "/SN", "/H", "/J", "/X", "/TELNET"},
		"user":          {"/C", "/D", "/R", "/E"},
		"superuser":     {"/N", "/F", "/P", "/AC", "/TEST", "/I"},
		"administrator": {"/UFW", "/VPN", "/DF", "/WOF"},
	}
	notWant := map[string][]string{
		"viewonly":      {"/N", "/C"},
		"user":          {"/N", "/F", "/AC", "/TEST"},
		"superuser":     {"/UFW", "/WOF"},
		"administrator": {},
	}
	for _, level := range menuLevels {
		tr := menuDir(t, "screens "+wtiFixtures+"\nlevel "+level+"\n", map[string]string{})
		c, err := loadMenu(tr, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range want[level] {
			if !c.allowed[w] {
				t.Errorf("%s: %s is not listed", level, w)
			}
		}
		for _, w := range notWant[level] {
			if c.allowed[w] {
				t.Errorf("%s: %s is listed", level, w)
			}
		}
	}
}

// The generated IP tables screens are what the unit printed: the three
// captured pages of the filled list, byte for byte.
func TestMenuIPTablesScreensEqualTheCaptures(t *testing.T) {
	tr := menuDir(t, "screens "+wtiFixtures+"\niptables filled\n", map[string]string{})
	c, err := loadMenu(tr, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.iptables) != 25 {
		t.Fatalf("%d entries, want 25", len(c.iptables))
	}
	for n, f := range screenIPTables {
		body, err := readCapture(filepath.Join(wtiFixtures, f))
		if err != nil {
			t.Fatal(err)
		}
		_, want := splitEcho(body)
		got, ok := c.ipTablesScreen(n)
		if !ok {
			t.Fatal("no screen")
		}
		// The unit's own paint of a page follows the echo of the key and a
		// blank line; a capture without the echo starts at the title.
		if strings.Trim(got, "\n") != strings.Trim(want, "\n") {
			t.Errorf("page %d differs from %s:\n--- got\n%s\n--- want\n%s", n+1, f, got, want)
		}
	}
	// The empty list's first page is the capture network-5 as it is.
	empty := menuDir(t, "screens "+wtiFixtures+"\n", map[string]string{})
	e, err := loadMenu(empty, "")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readCapture(filepath.Join(wtiFixtures, "pages", "network-5.txt"))
	_, want := splitEcho(body)
	if got, _ := e.ipTablesScreen(0); strings.Trim(got, "\n") != strings.Trim(want, "\n") {
		t.Errorf("empty list differs from network-5:\n%s", got)
	}
}

func TestSplitEcho(t *testing.T) {
	for _, c := range []struct{ in, echo, rest string }{
		{"/H\n\nCOMMAND MENU:\n", "/H", "\nCOMMAND MENU:\n"},
		{"/J\nSite ID: x\n", "/J", "Site ID: x\n"},
		{"28\n\nTACACS: [Shared]\n", "28", "\nTACACS: [Shared]\n"},
		{"localadmin\n\nVIEW\n", "localadmin", "\nVIEW\n"},
		{"IPTABLES ENTRIES: IPv4\n\n1.\n", "", "IPTABLES ENTRIES: IPv4\n\n1.\n"},
		{"NETWORK PARAMETERS: [eth0] IPv4\n\n", "", "NETWORK PARAMETERS: [eth0] IPv4\n\n"},
		{"Console Server           Site ID: x\n\nPORT|\n", "", "Console Server           Site ID: x\n\nPORT|\n"},
	} {
		echo, rest := splitEcho(c.in)
		if echo != c.echo || rest != c.rest {
			t.Errorf("splitEcho(%q) = %q, %q; want %q, %q", c.in, echo, rest, c.echo, c.rest)
		}
	}
}

func TestHelpItemsSplitAtThePager(t *testing.T) {
	body, err := readCapture(filepath.Join(wtiFixtures, "03-help-administrator.txt"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest := splitEcho(body)
	items := helpItems(rest)
	pagers := 0
	for _, it := range items {
		if it.pager {
			pagers++
		}
		if strings.ContainsRune(it.text, '\b') || strings.Contains(it.text, "DSM>") {
			t.Errorf("residue in %q", it.text)
		}
	}
	if pagers != 2 {
		t.Errorf("%d pager prompts, want the capture's 2", pagers)
	}
	var texts []string
	for _, it := range items {
		texts = append(texts, it.text)
	}
	all := strings.Join(texts, "\n")
	for _, want := range []string{"/TEST         Test Network Options", "CONFIGURATION COMMANDS", "| n   Port #/name", "+---------------------------------+"} {
		if !strings.Contains(all, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}

func TestStatusCellIsTheCapturedRow(t *testing.T) {
	got := statusCell(1, true, "user1") + statusCell(17, false, "")
	want := "N1  |      22|Active|user1           |N17 |        | Free |                |"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}
