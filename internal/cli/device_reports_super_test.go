package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A superuser reaches the reports of other users, and every such access is
// one audit line; nobody else does, and no verb writes into another home.

// loggerLines are the audit lines the last run wrote.
func (b *reportsBox) loggerLines() string {
	var out []string
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "logger" {
			out = append(out, strings.Join(c.Args, " "))
		}
	}
	return strings.Join(out, "\n")
}

func TestReportsSuperuserListsOtherUsers(t *testing.T) {
	b := newReportsBox(t)
	a := b.generate("alice", asSuper, "--type", "inventory")
	bn := b.generate("bob", asOperator, "--type", "software", "--format", "json")

	// his own: no audit line
	b.as("alice", asSuper, "list", "--user", "alice")
	b.as("alice", asSuper, "list")
	if l := b.audits(); len(l) != 0 {
		t.Errorf("own reports audited: %v", l)
	}

	out := b.as("alice", asSuper, "list", "--user", "bob")
	if b.sb.code != 0 || !strings.Contains(out, bn) || strings.Contains(out, a) || !strings.Contains(out, "USER") {
		t.Errorf("list --user: %d\n%s", b.sb.code, out)
	}
	if l := b.audits(); len(l) != 1 || !strings.Contains(l[0], "device reports access verb=list owner=bob report=\"*\" by=alice") {
		t.Errorf("audit: %v", l)
	}

	out = b.as("alice", asSuper, "list", "--all-users")
	if b.sb.code != 0 || !strings.Contains(out, bn) || !strings.Contains(out, a) || !strings.Contains(out, "2 reports") {
		t.Errorf("list --all-users: %d\n%s", b.sb.code, out)
	}
	for _, row := range strings.Split(out, "\n") {
		if f := strings.Fields(row); len(f) > 1 && f[1] == bn && f[0] != "bob" {
			t.Errorf("the owner column: %q", row)
		}
	}
	if l := b.audits(); len(l) != 1 || !strings.Contains(l[0], "verb=list owner=\"*\" report=\"*\" by=alice") {
		t.Errorf("audit: %v", l)
	}
	if out = b.as("alice", asSuper, "list", "--all-users", "--json"); !strings.Contains(out, `"owner": "bob"`) || !strings.Contains(out, `"owner": "alice"`) {
		t.Errorf("json:\n%s", out)
	}
	b.as("alice", asSuper, "list", "--user", "bob", "--all-users")
	if b.sb.code != 2 {
		t.Errorf("both: %d", b.sb.code)
	}
}

func TestReportsSuperuserWorksOnOtherUsersReports(t *testing.T) {
	b := newReportsBox(t)
	name := b.generate("bob", asOperator, "--type", "inventory", "--format", "csv")
	ref := "bob/" + name
	bobFile := filepath.Join(b.dir("bob"), name+".csv")
	body, _ := os.ReadFile(bobFile)

	// the audit line is one per access, and never has a content
	check := func(verb string) {
		t.Helper()
		l := b.audits()
		if len(l) != 1 || !strings.Contains(l[0], "device reports access verb="+verb+" owner=bob report="+name+" by=alice") {
			t.Errorf("%s: audit lines %v", verb, l)
		}
		for _, w := range []string{"sw1", "192.168.1.10", "SN000001"} {
			if strings.Contains(b.loggerLines(), w) {
				t.Errorf("%s: the log holds %q", verb, w)
			}
		}
	}

	out := b.as("alice", asSuper, "show", ref, "--content")
	if b.sb.code != 0 || !strings.Contains(out, "User:         bob") || !strings.Contains(out, "sw1,192.168.1.10") ||
		!strings.Contains(out, "scp bob@tacctl:reports/devices/"+name+".csv .") {
		t.Errorf("show: %d\n%s", b.sb.code, out)
	}
	check("show")

	if out = b.as("alice", asSuper, "export", ref); out != string(body) {
		t.Errorf("export: %q", out)
	}
	check("export")

	dest := filepath.Join(b.sb.homePath(""), "bobs.csv")
	b.as("alice", asSuper, "export", ref, "--out", dest)
	if got, _ := os.ReadFile(dest); string(got) != string(body) || b.sb.code != 0 {
		t.Errorf("export --out: %d %q", b.sb.code, got)
	}
	check("export")
	// nothing is written into the home of alice
	if _, err := os.Stat(b.dir("alice")); !os.IsNotExist(err) {
		t.Error("a copy was made in the superuser's home")
	}

	b.as("alice", asSuper, "rename", ref, "from-bob")
	if b.sb.code != 0 {
		t.Fatalf("rename: %d %q", b.sb.code, b.sb.stderr())
	}
	check("rename")
	if _, err := os.Stat(filepath.Join(b.dir("bob"), "from-bob.csv")); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(bobFile); !os.IsNotExist(err) {
		t.Error("the old name is still there")
	}

	b.as("alice", asSuper, "remove", "bob/from-bob", "--yes")
	if b.sb.code != 0 || !strings.Contains(b.sb.out.String(), "Removed the report from-bob of bob.") {
		t.Errorf("remove: %d %q", b.sb.code, b.sb.out.String())
	}
	if l := b.audits(); len(l) != 1 || !strings.Contains(l[0], "verb=remove owner=bob report=from-bob") {
		t.Errorf("remove: %v", l)
	}
	if ents, _ := os.ReadDir(b.dir("bob")); len(ents) != 0 {
		t.Errorf("files left: %v", ents)
	}

	// an attempt at a report that is not there is audited too, and refused
	b.as("alice", asSuper, "show", "bob/nothing")
	if b.sb.code != 1 || len(b.audits()) != 1 || !strings.Contains(b.sb.stderr(), "there is no report 'nothing'") {
		t.Errorf("missing: %d %v %q", b.sb.code, b.audits(), b.sb.stderr())
	}
	// a name that cannot be a report never reaches a path
	for _, ref := range []string{"bob/../x", "bob/a/b", "bob/", "bob/x.meta", "../bob/x"} {
		b.as("alice", asSuper, "show", ref)
		if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "is not the name of a report") {
			t.Errorf("%q: %d %q", ref, b.sb.code, b.sb.stderr())
		}
	}
	// a user with no account has no reports
	b.as("alice", asSuper, "list", "--user", "no/body")
	if b.sb.code != 1 {
		t.Errorf("a bad user name: %d", b.sb.code)
	}
	// the user's own name is his own directory
	mine := b.generate("alice", asSuper, "--type", "config")
	b.as("alice", asSuper, "show", "alice/"+mine)
	if b.sb.code != 0 || len(b.audits()) != 0 {
		t.Errorf("own: %d %v", b.sb.code, b.audits())
	}
}

func TestReportsOthersAreRefusedTheReportsOfOtherUsers(t *testing.T) {
	b := newReportsBox(t)
	name := b.generate("alice", asSuper, "--type", "inventory")
	file := filepath.Join(b.dir("alice"), name+".txt")
	before, _ := os.ReadFile(file)
	for _, who := range []struct{ user, groups string }{{"bob", asOperator}, {"carol", asReadonly}} {
		for _, args := range [][]string{
			{"list", "--user", "alice"},
			{"list", "--all-users"},
			{"show", "alice/" + name},
			{"export", "alice/" + name},
			{"export", "alice/" + name, "--out", filepath.Join(b.sb.homePath(""), "x")},
			{"rename", "alice/" + name, "mine"},
			{"remove", "alice/" + name, "--yes"},
		} {
			out := b.as(who.user, who.groups, args...)
			if b.sb.code != 1 || out != "" || !strings.Contains(b.sb.stderr(), "is the superuser's: you reach your own reports only. Nothing was done.") {
				t.Errorf("%s %v: %d %q %q", who.user, args, b.sb.code, out, b.sb.stderr())
			}
			if l := b.loggerLines(); !strings.Contains(l, "cmd DENY") || !strings.Contains(l, "reason=superuser") {
				t.Errorf("%s %v: the denial is not logged:\n%s", who.user, args, l)
			}
			if len(b.audits()) != 0 {
				t.Errorf("%s %v: an access line for a refused access", who.user, args)
			}
		}
	}
	if got, err := os.ReadFile(file); err != nil || string(got) != string(before) {
		t.Errorf("the report changed: %v", err)
	}
	if ents, _ := os.ReadDir(filepath.Join(b.sb.dir, "home", "bob")); len(ents) != 0 {
		t.Errorf("something was made in bob's home: %v", ents)
	}
}

// 'list --json' cleans every string as the text list does: a file name or a
// metadata field is the user's to write, and a control character in it is a
// '?' and never a character of the output.
func TestReportsListJSONCleansTheStrings(t *testing.T) {
	b := newReportsBox(t)
	name := b.generate("bob", asOperator, "--type", "inventory", "--format", "csv", "--scope", "lab")
	dir := b.dir("bob")
	if err := os.WriteFile(filepath.Join(dir, "evil\x1b[31m.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	metaPath := filepath.Join(dir, name+".csv.meta")
	meta, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	// the filter value and the type carry a control character and a bidi mark
	edited := strings.Replace(string(meta), `"lab"`, `"l\u001bab\u202e"`, 1)
	edited = strings.Replace(edited, `"type": "inventory"`, `"type": "inven\u001btory"`, 1)
	if edited == string(meta) {
		t.Fatalf("the metadata has no filter to edit:\n%s", meta)
	}
	if err := os.WriteFile(metaPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	out := b.as("alice", asSuper, "list", "--user", "bob", "--json")
	if b.sb.code != 0 {
		t.Fatalf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	for _, bad := range []string{`\u001b`, `\u202e`, "\x1b"} {
		if strings.Contains(out, bad) {
			t.Errorf("the JSON holds %q:\n%s", bad, out)
		}
	}
	// the edited metadata is still read (the row is a report, not an other file)
	// and its fields came through cleaned
	if !strings.Contains(out, `"type": "inven?tory"`) || !strings.Contains(out, `"scope": "l?ab?"`) {
		t.Errorf("the metadata fields are not cleaned:\n%s", out)
	}
	if !strings.Contains(out, "evil?[31m.txt") {
		t.Errorf("the file name is not cleaned:\n%s", out)
	}
}

// What another user wrote is not trusted with the superuser's terminal, and
// the metadata file cannot vouch for it: the owner makes that file too (a copy
// of a genuine one next to any file). 'export <user>/<report>' to the standard
// output cleans each line as 'show --content' does, for a file with no
// metadata and for one with a genuine one; --out copies the bytes as they are;
// the superuser's own file prints raw.
func TestReportsExportOfAnotherUsersFileIsCleaned(t *testing.T) {
	b := newReportsBox(t)
	name := b.generate("bob", asOperator, "--type", "inventory", "--format", "csv")
	evil := "title\x1b[31m red\x1b[0m\ttab\u202e\n\x1b]0;owned\x07second\n"
	clean := "title?[31m red?[0m?tab?\n?]0;owned?second\n"
	// a file with no metadata
	if err := os.WriteFile(filepath.Join(b.dir("bob"), "notes.txt"), []byte(evil), 0o600); err != nil {
		t.Fatal(err)
	}
	// and a report with a genuine metadata file whose body the owner replaced
	if err := os.WriteFile(filepath.Join(b.dir("bob"), name+".csv"), []byte(evil), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b.dir("alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.dir("alice"), "mine.txt"), []byte("my\town file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"bob/notes.txt", "bob/" + name} {
		out := b.as("alice", asSuper, "export", ref)
		if b.sb.code != 0 || out != clean {
			t.Errorf("export %s: %d %q (want %q) %q", ref, b.sb.code, out, clean, b.sb.stderr())
		}
		dest := filepath.Join(b.sb.homePath(""), strings.ReplaceAll(ref, "/", "-")+".copy")
		b.as("alice", asSuper, "export", ref, "--out", dest)
		if got, _ := os.ReadFile(dest); b.sb.code != 0 || string(got) != evil {
			t.Errorf("export %s --out: %d %q", ref, b.sb.code, got)
		}
	}
	// a name that does not end in a newline is printed as it is, cleaned
	if err := os.WriteFile(filepath.Join(b.dir("bob"), "tail.txt"), []byte("a\x1b[2Jb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := b.as("alice", asSuper, "export", "bob/tail.txt"); b.sb.code != 0 || out != "a?[2Jb" {
		t.Errorf("no final newline: %d %q", b.sb.code, out)
	}
	if out := b.as("alice", asSuper, "export", "mine.txt"); b.sb.code != 0 || out != "my\town file\n" {
		t.Errorf("an own file: %d %q", b.sb.code, out)
	}
}
