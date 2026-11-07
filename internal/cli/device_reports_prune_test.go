package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/reports"
)

// 'device reports prune' on the sandbox of device_reports_test.go. The
// reports are written straight into the directories, with the generated date
// each test wants (the command reads the clock, so the dates are relative to
// now, with a margin of hours).

const day = 24 * time.Hour

// seed writes a report of a user, generated ago before now, and returns the
// path of its file. Its file time is the time of the call.
func (b *reportsBox) seed(user, name, typ string, ago time.Duration) string {
	b.t.Helper()
	dir := b.dir(user)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		b.t.Fatal(err)
	}
	mb, err := reports.MarshalMeta(reports.Meta{Name: name, Type: typ, Format: reports.FormatText, User: user,
		Command: "tacctl device reports generate --type " + typ, Generated: time.Now().Add(-ago).UTC(), Count: 2})
	if err != nil {
		b.t.Fatal(err)
	}
	p := filepath.Join(dir, name+".txt")
	if err := os.WriteFile(p, []byte("report "+name+"\n"), 0o600); err != nil {
		b.t.Fatal(err)
	}
	if err := os.WriteFile(p+".meta", mb, 0o600); err != nil {
		b.t.Fatal(err)
	}
	return p
}

// asYes is as, with an answer for the question.
func (b *reportsBox) asYes(answer, user, groups string, args ...string) string {
	b.t.Helper()
	return plain(b.sb.cfgRun(answer, append([]string{"device", "reports"}, args...), idAs(user, "tac-users "+groups), "SUDO_USER="+user))
}

// exists says whether a path is there (a link is not followed).
func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestReportsPruneRemovesOnlyTheOlderReports(t *testing.T) {
	b := newReportsBox(t)
	old := b.seed("alice", "old-inv", "inventory", 10*day)
	mid := b.seed("alice", "mid-sw", "software", 8*day)
	young := b.seed("alice", "young-cfg", "config", 36*time.Hour)
	fresh := b.seed("alice", "fresh-mem", "members", time.Hour)
	other := b.seed("bob", "bobs-old", "inventory", 40*day)

	out := b.as("alice", asSuper, "prune", "--older-than", "7d", "--yes")
	if b.sb.code != 0 {
		t.Fatalf("prune: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	for _, w := range []string{"Reports older than 7d (2)", "NAME", "TYPE", "GENERATED", "SIZE", "old-inv", "inventory", "mid-sw", "software",
		time.Now().Add(-10 * day).UTC().Format("2006-01-02"), "2 reports, ", " in all", "Removed 2 reports"} {
		if !strings.Contains(out, w) {
			t.Errorf("the output lacks %q:\n%s", w, out)
		}
	}
	for _, w := range []string{"young-cfg", "fresh-mem", "USER"} {
		if strings.Contains(out, w) {
			t.Errorf("the output has %q:\n%s", w, out)
		}
	}
	for _, p := range []string{old, mid} {
		if exists(t, p) || exists(t, p+".meta") {
			t.Errorf("%s is still there", p)
		}
	}
	for _, p := range []string{young, fresh, other} {
		if !exists(t, p) || !exists(t, p+".meta") {
			t.Errorf("%s was removed", p)
		}
	}
	// his own prune is one ordinary detail line, with the number and no names
	l := b.loggerLines()
	if !strings.Contains(l, "device reports prune older-than=7d removed=2 by=alice") {
		t.Errorf("no detail line:\n%s", l)
	}
	if strings.Contains(l, "old-inv") || len(b.audits()) != 0 {
		t.Errorf("the log:\n%s", l)
	}

	// the same line again has nothing to do
	out = b.as("alice", asSuper, "prune", "--older-than", "7d", "--yes")
	if b.sb.code != 0 || !strings.Contains(out, "Nothing to prune: no report of yours is older than 7d.") || strings.Contains(out, "Removed") {
		t.Errorf("again: %d %q", b.sb.code, out)
	}
	// the units: the report of 36 hours is older than 24h and not older than 48h or 2d
	b.as("alice", asSuper, "prune", "--older-than", "48h", "--dry-run")
	if b.sb.code != 0 || !strings.Contains(b.sb.out.String(), "Nothing to prune") {
		t.Errorf("48h: %d %q", b.sb.code, b.sb.out.String())
	}
	out = b.as("alice", asSuper, "prune", "--older-than", "1w", "--yes")
	if !strings.Contains(out, "Nothing to prune") || !exists(t, young) {
		t.Errorf("1w: %q", out)
	}
	out = b.as("alice", asSuper, "prune", "--older-than", "24h", "--yes")
	if b.sb.code != 0 || !strings.Contains(out, "young-cfg") || !strings.Contains(out, "Removed 1 report ") || exists(t, young) || !exists(t, fresh) {
		t.Errorf("24h: %d %q", b.sb.code, out)
	}
}

func TestReportsPruneGoesByTheGeneratedDateNotTheFileTime(t *testing.T) {
	b := newReportsBox(t)
	longAgo := time.Now().Add(-400 * day)
	// generated long ago, file time now
	was := b.seed("alice", "was-old", "inventory", 90*day)
	// generated now, file time long ago
	is := b.seed("alice", "is-new", "inventory", time.Minute)
	for _, p := range []string{is, is + ".meta"} {
		if err := os.Chtimes(p, longAgo, longAgo); err != nil {
			t.Fatal(err)
		}
	}
	out := b.as("alice", asSuper, "prune", "--older-than", "30d", "--yes")
	if b.sb.code != 0 || !strings.Contains(out, "was-old") || strings.Contains(out, "is-new") {
		t.Errorf("%d %q", b.sb.code, out)
	}
	if exists(t, was) || !exists(t, is) || !exists(t, is+".meta") {
		t.Error("the file time decided")
	}
}

func TestReportsPruneNeverRemovesWhatIsNotAReport(t *testing.T) {
	b := newReportsBox(t)
	old := b.seed("alice", "old-inv", "inventory", 90*day)
	dir := b.dir("alice")
	longAgo := time.Now().Add(-900 * day)
	keep := map[string]string{
		"notes.md":        "# mine\n",  // no metadata: 'other'
		"notes.txt":       "text\n",    //
		"broken.txt":      "x\n",       // damaged metadata
		"broken.txt.meta": "{not json", //
		"stray.csv.meta":  "{}",        // a metadata file without its report
		"nodate.txt":      "x\n",       // metadata with no generated date
		"nodate.txt.meta": `{"schema":1,"name":"nodate","type":"inventory","format":"text"}`,
		".hidden-report":  "x\n",
	}
	for n, c := range keep {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, longAgo, longAgo); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "inner.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// a file next to the reports directory is not in it
	beside := filepath.Join(filepath.Dir(dir), "beside.txt")
	if err := os.WriteFile(beside, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	out := b.as("alice", asSuper, "prune", "--older-than", "1h", "--yes")
	if b.sb.code != 0 || !strings.Contains(out, "old-inv") || !strings.Contains(out, "Removed 1 report ") {
		t.Fatalf("%d %q %q", b.sb.code, out, b.sb.stderr())
	}
	for _, w := range []string{"notes", "broken", "nodate", "stray", "hidden", "inner"} {
		if strings.Contains(out, w) {
			t.Errorf("the output names %q:\n%s", w, out)
		}
	}
	if exists(t, old) {
		t.Error("the old report is still there")
	}
	for n := range keep {
		if !exists(t, filepath.Join(dir, n)) {
			t.Errorf("%s was removed", n)
		}
	}
	for _, p := range []string{filepath.Join(dir, "sub", "inner.txt"), beside} {
		if !exists(t, p) {
			t.Errorf("%s was removed", p)
		}
	}
}

func TestReportsPruneDoesNotFollowLinks(t *testing.T) {
	b := newReportsBox(t)
	b.seed("alice", "old-inv", "inventory", 90*day)
	dir := b.dir("alice")
	out := filepath.Join(b.sb.dir, "outside")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	// an old report and its old metadata, outside the directory
	outside := b.seed("carol", "theirs", "inventory", 90*day)
	if err := os.Rename(outside, filepath.Join(out, "theirs.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(outside+".meta", filepath.Join(out, "theirs.txt.meta")); err != nil {
		t.Fatal(err)
	}
	// a report that is a link, with a metadata file of its own
	if err := os.Symlink(filepath.Join(out, "theirs.txt"), filepath.Join(dir, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	mb, err := os.ReadFile(filepath.Join(out, "theirs.txt.meta"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "linked.txt.meta"), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	// a report whose metadata is a link
	if err := os.WriteFile(filepath.Join(dir, "meta-linked.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(out, "theirs.txt.meta"), filepath.Join(dir, "meta-linked.txt.meta")); err != nil {
		t.Fatal(err)
	}
	// a link to a directory
	if err := os.Symlink(out, filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}

	got := b.as("alice", asSuper, "prune", "--older-than", "1d", "--yes")
	if b.sb.code != 0 || !strings.Contains(got, "Removed 1 report ") || strings.Contains(got, "linked") || strings.Contains(got, "theirs") {
		t.Fatalf("%d %q %q", b.sb.code, got, b.sb.stderr())
	}
	for _, p := range []string{filepath.Join(out, "theirs.txt"), filepath.Join(out, "theirs.txt.meta"),
		filepath.Join(dir, "linked.txt"), filepath.Join(dir, "linked.txt.meta"),
		filepath.Join(dir, "meta-linked.txt"), filepath.Join(dir, "meta-linked.txt.meta"), filepath.Join(dir, "dirlink")} {
		if !exists(t, p) {
			t.Errorf("%s was removed", p)
		}
	}
	if exists(t, filepath.Join(dir, "old-inv.txt")) {
		t.Error("the old report is still there")
	}
}

func TestReportsPruneDryRunRemovesNothing(t *testing.T) {
	b := newReportsBox(t)
	old := b.seed("alice", "old-inv", "inventory", 20*day)
	for _, args := range [][]string{
		{"prune", "--older-than", "7d", "--dry-run"},
		{"prune", "--older-than", "7d", "--dry-run", "--yes"},
		{"prune", "--yes", "--dry-run", "--older-than=7d"},
	} {
		out := b.asYes("y\n", "alice", asSuper, args...)
		if b.sb.code != 0 || !strings.Contains(out, "Reports older than 7d (1)") || !strings.Contains(out, "old-inv") ||
			!strings.Contains(out, "Dry run: nothing was removed.") || strings.Contains(out, "Confirm") || strings.Contains(out, "Removed") {
			t.Errorf("%v: %d %q", args, b.sb.code, out)
		}
		if !exists(t, old) || !exists(t, old+".meta") {
			t.Fatalf("%v removed the report", args)
		}
		if strings.Contains(b.loggerLines(), "device reports prune") {
			t.Errorf("%v: a prune line for a dry run:\n%s", args, b.loggerLines())
		}
	}
}

func TestReportsPruneAsksOnce(t *testing.T) {
	b := newReportsBox(t)
	a := b.seed("alice", "old-a", "inventory", 20*day)
	c := b.seed("alice", "old-b", "members", 21*day)
	args := []string{"prune", "--older-than", "7d"}

	for _, answer := range []string{"", "n\n", "no\n", "\n", "maybe\n"} {
		out := b.asYes(answer, "alice", asSuper, args...)
		if b.sb.code != 0 || !strings.Contains(out, "About to remove 2 reports") || !strings.Contains(out, "Aborted.") || strings.Contains(out, "Removed") {
			t.Errorf("answer %q: %d %q", answer, b.sb.code, out)
		}
		if !exists(t, a) || !exists(t, c) {
			t.Fatalf("answer %q removed a report", answer)
		}
		if strings.Contains(b.loggerLines(), "device reports prune") {
			t.Errorf("answer %q: a prune line for an abort", answer)
		}
	}
	// the question is asked once for all, not once per report: the second
	// answer is never read
	out := b.asYes("y\nn\n", "alice", asSuper, args...)
	if b.sb.code != 0 || !strings.Contains(out, "Removed 2 reports") || exists(t, a) || exists(t, c) {
		t.Errorf("yes: %d %q", b.sb.code, out)
	}

	// --yes does not ask
	d := b.seed("alice", "old-c", "software", 30*day)
	out = b.asYes("", "alice", asSuper, append(args, "--yes")...)
	if b.sb.code != 0 || strings.Contains(b.sb.stderr(), "Confirm") || !strings.Contains(out, "Removed 1 report ") || exists(t, d) {
		t.Errorf("--yes: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
}

func TestReportsPruneWithNothingToPrune(t *testing.T) {
	b := newReportsBox(t)
	// no directory at all
	out := b.asYes("y\n", "bob", asOperator, "prune", "--older-than", "1d")
	if b.sb.code != 0 || !strings.Contains(out, "Nothing to prune: no report of yours is older than 1d.") ||
		strings.Contains(out, "Confirm") || strings.Contains(out, "About to") {
		t.Errorf("no directory: %d %q", b.sb.code, out)
	}
	if exists(t, filepath.Join(b.sb.dir, "home", "bob")) {
		t.Error("the command made a directory")
	}
	// reports, none old enough
	b.seed("bob", "new-one", "inventory", time.Hour)
	out = b.as("bob", asOperator, "prune", "--older-than", "1d", "--dry-run")
	if b.sb.code != 0 || !strings.Contains(out, "Nothing to prune") {
		t.Errorf("none old: %d %q", b.sb.code, out)
	}
}

// Every tier prunes its own reports, as it removes them.
func TestReportsPruneIsOpenToEveryTier(t *testing.T) {
	b := newReportsBox(t)
	for _, u := range []struct{ user, groups string }{{"bob", asOperator}, {"carol", asReadonly}} {
		p := b.seed(u.user, "old", "inventory", 9*day)
		out := b.as(u.user, u.groups, "prune", "--older-than", "1w", "--yes")
		if b.sb.code != 0 || !strings.Contains(out, "Removed 1 report ") || exists(t, p) {
			t.Errorf("%s: %d %q %q", u.user, b.sb.code, out, b.sb.stderr())
		}
	}
}

func TestReportsPruneArguments(t *testing.T) {
	b := newReportsBox(t)
	old := b.seed("alice", "old-inv", "inventory", 90*day)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"prune"}, "--older-than is required"},
		{[]string{"prune", "--yes"}, "--older-than is required"},
		{[]string{"prune", "--older-than"}, "--older-than"},
		{[]string{"prune", "--older-than", ""}, "a whole number and one unit"},
		{[]string{"prune", "--older-than", "30"}, "a whole number and one unit"},
		{[]string{"prune", "--older-than", "0d"}, "more than zero"},
		{[]string{"prune", "--older-than", "-1d"}, "a whole number and one unit"},
		{[]string{"prune", "--older-than", "3m"}, "a whole number and one unit"},
		{[]string{"prune", "--older-than", "1y"}, "a whole number and one unit"},
		{[]string{"prune", "--older-than", "99999999999999999999d"}, "too large"},
		{[]string{"prune", "--older-than", "1d", "old-inv"}, "Usage: tacctl device reports prune"},
		{[]string{"prune", "--older-than", "1d", "--force"}, "Unknown option: '--force'"},
	} {
		out := b.as("alice", asSuper, c.args...)
		if b.sb.code != 2 || out != "" || !strings.Contains(b.sb.stderr(), c.want) || !strings.Contains(b.sb.stderr(), "Usage: tacctl device reports prune --older-than <age>") {
			t.Errorf("%v: %d %q %q", c.args, b.sb.code, out, b.sb.stderr())
		}
		if !exists(t, old) {
			t.Fatalf("%v removed a report", c.args)
		}
	}
}

// A removal that fails is said and the exit status is not 0. A test cannot
// fail one removal of a directory and not another, so here all of them fail
// (a read-only directory); the superuser's test has a user's directory fail
// and another's not.
func TestReportsPruneFailureIsAnExitStatus(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root removes from a directory whatever its mode")
	}
	b := newReportsBox(t)
	a := b.seed("alice", "old-a", "inventory", 20*day)
	c := b.seed("alice", "old-b", "members", 21*day)
	dir := b.dir("alice")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	out := b.as("alice", asSuper, "prune", "--older-than", "7d", "--yes")
	if b.sb.code != 1 || strings.Contains(out, "Removed") || !strings.Contains(b.sb.stderr(), "Cannot remove old-a.txt:") ||
		!strings.Contains(b.sb.stderr(), "Cannot remove old-b.txt:") || !strings.Contains(b.sb.stderr(), "2 reports could not be removed") {
		t.Errorf("%d %q %q", b.sb.code, out, b.sb.stderr())
	}
	if !exists(t, a) || !exists(t, c) {
		t.Error("a report went in a read-only directory")
	}
	if strings.Contains(b.loggerLines(), "device reports prune") {
		t.Errorf("a prune line for nothing removed:\n%s", b.loggerLines())
	}
}

func TestReportsPruneCompletion(t *testing.T) {
	has := func(got []string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !slices.Contains(got, w) {
				t.Errorf("%q is not offered: %q", w, got)
			}
		}
	}
	got, _ := completeWords(t, liveNames, "device", "reports", "")
	has(got, "generate", "list", "show", "export", "rename", "remove", "prune")
	got, _ = completeWords(t, liveNames, "device", "reports", "pr")
	if !slices.Equal(got, []string{"prune"}) {
		t.Errorf("pr: %q", got)
	}
	got, _ = completeWords(t, liveNames, "device", "reports", "prune", "")
	has(got, "--older-than", "--dry-run", "--yes")
	got, _ = completeWords(t, liveNames, "device", "reports", "prune", "--older-than", "")
	has(got, "24h", "7d", "30d", "4w")
	got, _ = completeWords(t, liveNames, "device", "reports", "prune", "--older-than", "7d", "")
	if slices.Contains(got, "--older-than") {
		t.Errorf("--older-than again: %q", got)
	}
	has(got, "--dry-run", "--yes")
}
