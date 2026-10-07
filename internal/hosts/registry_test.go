package hosts

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRegistryLoadAndEntries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "linux-hosts")
	r, err := LoadRegistry(p)
	if err != nil || r.Exists() || !r.Empty() || r.Entries() != nil || r.Names() != nil {
		t.Fatalf("missing file: %v %+v", err, r)
	}
	if err := r.Forget("x"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("Forget created the file")
	}

	writeFile(t, p, "web1|admin@web1||lab|192.0.2.1|\n"+
		"web2|web2|2222|linux-web2|192.0.2.1|/k|radius\n"+
		"\n"+
		"odd\n"+
		"web3|web3||lab|192.0.2.1||ldap|extra\n"+
		"tail|no-newline")
	if err := r.Load(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range r.Entries() {
		got = append(got, e.Name+"="+e.Target+","+e.Port+","+e.Scope+","+e.Server+","+e.Identity+","+e.Method+"/"+e.EffectiveMethod())
	}
	want := []string{
		"web1=admin@web1,,lab,192.0.2.1,,/tacplus",
		"web2=web2,2222,linux-web2,192.0.2.1,/k,radius/radius",
		"odd=,,,,,/tacplus",
		"web3=web3,,lab,192.0.2.1,,ldap/tacplus",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("entries\n got %q\nwant %q", got, want)
	}
	if n := r.Names(); !reflect.DeepEqual(n, []string{"web1", "web2", "", "odd", "web3", "tail"}) {
		t.Errorf("names %q", n)
	}
	for name, m := range map[string]string{"web1": "tacplus", "web2": "radius", "web3": "tacplus", "odd": "tacplus", "ghost": ""} {
		if got := r.Method(name); got != m {
			t.Errorf("Method(%s) = %q, want %q", name, got, m)
		}
	}
	if e, ok := r.Find("web2"); !ok || e.Port != "2222" {
		t.Errorf("Find %+v", e)
	}
	if !r.ScopeInUse("lab") || r.ScopeInUse("dmz") {
		t.Error("ScopeInUse")
	}
	if !r.OtherHostsUse("lab", "web1") || r.OtherHostsUse("linux-web2", "web2") {
		t.Error("OtherHostsUse")
	}
}

func TestRegistryRememberForget(t *testing.T) {
	p := filepath.Join(t.TempDir(), "linux-hosts")
	r := &Registry{Path: p}
	if err := r.Remember(Entry{Name: "web1", Target: "web1", Scope: "lab", Server: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if err := r.Remember(Entry{Name: "web2", Target: "a@web2", Port: "22", Scope: "lab", Server: "s", Identity: "/k", Method: Radius}); err != nil {
		t.Fatal(err)
	}
	// Re-remembered: the old line goes, the new one is last; tacplus is
	// written with six fields.
	if err := r.Remember(Entry{Name: "web1", Target: "web1", Scope: "lab", Server: "198.51.100.7", Method: Tacplus}); err != nil {
		t.Fatal(err)
	}
	want := "web2|a@web2|22|lab|s|/k|radius\nweb1|web1||lab|198.51.100.7|\n"
	if got := readFile(t, p); got != want {
		t.Errorf("file %q", got)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if err := r.Forget("web2"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); got != "web1|web1||lab|198.51.100.7|\n" {
		t.Errorf("after forget %q", got)
	}
	if err := r.Forget("web1"); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, p); got != "" || !r.Empty() || !r.Exists() {
		t.Errorf("emptied %q", got)
	}
}

func TestUIDs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "linux-uids")
	u := UIDs{Path: p}
	for _, step := range []struct{ name, want string }{{"alice", "80000"}, {"bob", "80001"}, {"alice", "80000"}} {
		got, err := u.For(step.name)
		if err != nil || got != step.want {
			t.Fatalf("For(%s) = %q %v", step.name, got, err)
		}
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	// A new file records its range first.
	if got := readFile(t, p); got != "# range 80000-89999\nalice:80000\nbob:80001\n" {
		t.Errorf("new file %q", got)
	}
	// A legacy entry outside the range (before 0.2.1 'config linux uid'
	// took any number from 1000): not counted, the next user still goes
	// after the highest number of the range, never into a gap.
	writeFile(t, p, "alice:80000\nbob:1001\n")
	if got, _ := u.For("carol"); got != "80001" {
		t.Errorf("carol %q", got)
	}
	if got := readFile(t, p); got != "alice:80000\nbob:1001\ncarol:80001\n" {
		t.Errorf("file %q", got)
	}
	if h, _ := u.Holder("80000"); h != "alice" {
		t.Errorf("holder %q", h)
	}
	if h, _ := u.Holder("4242"); h != "" {
		t.Errorf("holder %q", h)
	}
	if v, _ := u.Lookup("bob"); v != "1001" {
		t.Errorf("lookup %q", v)
	}
	if v, _ := u.Lookup("dave"); v != "" {
		t.Errorf("lookup %q", v)
	}
	l, err := u.Listing()
	if err != nil {
		t.Fatal(err)
	}
	want := "  bob                      1001   outside 80000-89999: not used on hosts\n  alice                    80000\n  carol                    80001\n"
	if l != want {
		t.Errorf("listing\n%q\n%q", l, want)
	}
	// Garbage and numbers above the range do not count.
	writeFile(t, p, "x:90000\ny\nz:abc\nw:80005\n")
	if got, _ := (UIDs{Path: p}).next(); got != "80006" {
		t.Errorf("next after garbage %q", got)
	}
	// The last number of the range is given out; after it, nothing.
	writeFile(t, p, "x:89998\n")
	if got, err := u.For("last"); got != "89999" || err != nil {
		t.Errorf("last %q %v", got, err)
	}
	if got, err := u.For("past"); got != "" || !errors.Is(err, ErrUIDRangeFull) {
		t.Errorf("past %q %v", got, err)
	}
	if got := readFile(t, p); got != "x:89998\nlast:89999\n" {
		t.Errorf("a refused allocation wrote %q", got)
	}
	for _, c := range []struct {
		uid string
		in  bool
	}{{"80000", true}, {"89999", true}, {"79999", false}, {"90000", false}, {"20000", false}, {"", false}, {"8e4", false}, {"-80000", false}, {"0080000", false}, {"080000", false}} {
		if DefaultRange.Contains(c.uid) != c.in {
			t.Errorf("Contains(%q)", c.uid)
		}
	}
	// Another range: allocation, listing and Assign keep to it.
	o := UIDs{Path: filepath.Join(t.TempDir(), "o"), Range: Range{40000, 40999}}
	if got, _ := o.For("ann"); got != "40000" {
		t.Errorf("other range %q", got)
	}
	if err := o.Assign("ann", "40500"); err != nil || readFile(t, o.Path) != "# range 40000-40999\nann:40500\n" {
		t.Errorf("assign %v %q", err, readFile(t, o.Path))
	}
	if l, _ := o.Listing(); l != "  ann                      40500\n" {
		t.Errorf("listing %q", l)
	}
	// Touch creates.
	q := filepath.Join(t.TempDir(), "new")
	if err := (UIDs{Path: q}).Touch(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(q); err != nil || st.Size() != 0 {
		t.Errorf("touch %v", err)
	}
}

// The UID file numbered for a range: a file without a record and with
// entries in 20000-29999 moves them by offset (users and removed users
// alike), the old file kept, the record written; a second run changes
// nothing; a change of range moves the entries again and remembers the
// ranges before; refusals change nothing.
func TestUIDsRenumberTo(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "linux-uids")
	u := UIDs{Path: p}
	if res, err := u.RenumberTo(p+".bak", false); res.N != 0 || res.Changed || err != nil {
		t.Fatalf("missing file: %+v %v", res, err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("a missing file was created")
	}
	old := "alice:20000\nbob:1001\ncarol:20001\nzed:25000\nnew:80002\njunk\nx:30000\n"
	writeFile(t, p, old)
	// dry: reported, nothing written.
	if res, err := u.RenumberTo(p+".bak", true); res.N != 3 || !res.Changed || res.From != LegacyRange || err != nil || readFile(t, p) != old {
		t.Fatalf("dry %+v %v", res, err)
	}
	res, err := u.RenumberTo(p+".bak", false)
	if res.N != 3 || res.From != LegacyRange || err != nil {
		t.Fatalf("renumber %+v %v", res, err)
	}
	if got := readFile(t, p); got != "# range 80000-89999\n# previous 20000-29999\nalice:80000\nbob:1001\ncarol:80001\nzed:85000\nnew:80002\njunk\nx:30000\n" {
		t.Errorf("renumbered %q", got)
	}
	if got := readFile(t, p+".bak"); got != old {
		t.Errorf("backup %q", got)
	}
	for _, f := range []string{p, p + ".bak"} {
		if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, st.Mode())
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("left behind %v", entries)
	}
	if cur, prev, _ := u.Recorded(); cur != DefaultRange || len(prev) != 1 || prev[0] != LegacyRange {
		t.Errorf("recorded %v %v", cur, prev)
	}
	// Idempotent.
	if res, err := u.RenumberTo(p+".bak2", false); res.N != 0 || res.Changed || err != nil {
		t.Errorf("second run %+v %v", res, err)
	}
	if _, err := os.Stat(p + ".bak2"); !os.IsNotExist(err) {
		t.Error("a second run made a backup")
	}
	if got, _ := u.For("dora"); got != "85001" {
		t.Errorf("next after renumbering %q", got)
	}

	// Another range: moved by offset, both earlier ranges remembered.
	writeFile(t, p, "# range 80000-89999\n# previous 20000-29999\nalice:80000\nzed:85000\n")
	w := UIDs{Path: p, Range: Range{40000, 49999}}
	if res, err := w.RenumberTo(p+".bak4", false); res.N != 2 || res.From != DefaultRange || err != nil {
		t.Fatalf("move %+v %v", res, err)
	}
	if got := readFile(t, p); got != "# range 40000-49999\n# previous 20000-29999 80000-89999\nalice:40000\nzed:45000\n" {
		t.Errorf("moved %q", got)
	}
	// Grown at the same start: nothing moves, the record changes.
	g := UIDs{Path: p, Range: Range{40000, 59999}}
	if res, err := g.RenumberTo(p+".bak5", false); res.N != 0 || !res.Changed || err != nil {
		t.Errorf("grow %+v %v", res, err)
	}
	if got := readFile(t, p); got != "# range 40000-59999\n# previous 20000-29999 80000-89999\nalice:40000\nzed:45000\n" {
		t.Errorf("grown %q", got)
	}
	if _, err := os.Stat(p + ".bak5"); !os.IsNotExist(err) {
		t.Error("a record-only change made a backup")
	}

	// Refusals: nothing changed, no backup.
	keep := readFile(t, p)
	var ov *RangeOverlap
	if _, err := (UIDs{Path: p, Range: Range{85000, 95000}}).RenumberTo(p+".x", false); !errors.As(err, &ov) || ov.With != DefaultRange {
		t.Errorf("overlap with a previous range: %v", err)
	}
	if _, err := (UIDs{Path: p, Range: Range{50000, 69999}}).RenumberTo(p+".x", false); !errors.As(err, &ov) || ov.With != (Range{40000, 59999}) {
		t.Errorf("overlap with the current range: %v", err)
	}
	var small *RangeTooSmall
	if _, err := (UIDs{Path: p, Range: Range{40000, 44999}}).RenumberTo(p+".x", false); !errors.As(err, &small) || small.Name != "zed" || small.New != 45000 {
		t.Errorf("shrunk below an entry: %v", err)
	}
	if _, err := (UIDs{Path: p, Range: Range{300000, 304999}}).RenumberTo(p+".x", false); !errors.As(err, &small) {
		t.Errorf("too small elsewhere: %v", err)
	}
	if readFile(t, p) != keep {
		t.Error("a refused renumbering wrote")
	}
	if _, err := os.Stat(p + ".x"); !os.IsNotExist(err) {
		t.Error("a refused renumbering made a backup")
	}

	// A collision: nothing changed, no backup.
	coll := "alice:20000\nbob:20001\ncarl:80001\n"
	writeFile(t, p, coll)
	_, err = u.RenumberTo(p+".bak6", false)
	var c *UIDCollision
	if !errors.As(err, &c) || *c != (UIDCollision{Name: "bob", Old: "20001", New: "80001", Holder: "carl"}) {
		t.Fatalf("collision %v", err)
	}
	if got := readFile(t, p); got != coll {
		t.Errorf("a refused renumbering wrote %q", got)
	}
	// The same name at both numbers is no collision.
	writeFile(t, p, "bob:20001\nbob:80001\n")
	if res, err := u.RenumberTo(p+".bak7", false); res.N != 1 || err != nil || readFile(t, p) != "# range 80000-89999\n# previous 20000-29999\nbob:80001\nbob:80001\n" {
		t.Errorf("same name %+v %v %q", res, err, readFile(t, p))
	}
	// A file without a record and nothing in 20000-29999 only gets the record.
	writeFile(t, p, "ann:80004\n")
	if res, err := u.RenumberTo(p+".bak8", false); res.N != 0 || res.From != DefaultRange || err != nil || readFile(t, p) != "# range 80000-89999\nann:80004\n" {
		t.Errorf("unrecorded %+v %v %q", res, err, readFile(t, p))
	}
	// ... and one numbered for 80000-89999 before anything recorded it
	// moves when another range is configured.
	writeFile(t, p, "ann:80004\n")
	if res, err := (UIDs{Path: p, Range: Range{100000, 109999}}).RenumberTo(p+".bak9", false); res.N != 1 || res.From != DefaultRange || err != nil ||
		readFile(t, p) != "# range 100000-109999\n# previous 80000-89999\nann:100004\n" {
		t.Errorf("unrecorded default %+v %v %q", res, err, readFile(t, p))
	}
	// A new file written by Assign records its range too.
	q := filepath.Join(dir, "assigned")
	if err := (UIDs{Path: q, Range: Range{40000, 49999}}).Assign("ann", "40007"); err != nil || readFile(t, q) != "# range 40000-49999\nann:40007\n" {
		t.Errorf("assign to a new file: %v %q", err, readFile(t, q))
	}
}

// The range rules and words.
func TestRangeRules(t *testing.T) {
	for _, c := range []struct {
		r       Range
		problem string
	}{
		{DefaultRange, ""},
		{Range{1000, 1999}, ""},
		{Range{100000, 199999}, ""},
		{Range{66000, 524287}, ""},
		{Range{999, 5000}, "it starts below 1000 (system accounts)"},
		{Range{5000, 4000}, "uid_min must be below uid_max"},
		{Range{80000, 80998}, "it holds 999 numbers; at least 1000 are needed (numbers are never reused)"},
		{Range{59000, 60001}, "it overlaps 60001-60513, which systemd reserves"},
		{Range{61000, 62000}, "it overlaps 61184-65519, which systemd reserves"},
		{Range{64000, 65535}, "it overlaps 61184-65519, which systemd reserves"},
		{Range{65520, 66600}, "it overlaps 65534-65535, which systemd reserves"},
		{Range{524000, 525000}, "it reaches 524288 and up, where systemd gives out container UIDs"},
		{Range{600000, 4294967294}, "it ends above 4294967293"},
	} {
		if got := RangeProblem(c.r); got != c.problem {
			t.Errorf("%v: %q, want %q", c.r, got, c.problem)
		}
	}
	if RangeWarning(DefaultRange) != "" || !strings.Contains(RangeWarning(Range{50000, 59999}), "overlaps 1000-60000, where local useradd") {
		t.Error("RangeWarning")
	}
	for s, want := range map[string]Range{"80000-89999": DefaultRange, " 1000-2000 ": {1000, 2000}} {
		if r, ok := ParseRange(s); !ok || r != want {
			t.Errorf("ParseRange(%q) = %v %v", s, r, ok)
		}
	}
	for _, bad := range []string{"", "80000", "80000-", "a-b", "080000-89999", "-1-5", "1e5-2e5"} {
		if _, ok := ParseRange(bad); ok {
			t.Errorf("ParseRange(%q) accepted", bad)
		}
	}
}

// What a host's user namespace maps: a plain host maps everything, a
// rootless container 0-65535 only.
func TestIDMaps(t *testing.T) {
	host := ParseIDMaps("uid_map\n         0          0 4294967295\ngid_map\n         0          0 4294967295\n")
	if host.Lacks(DefaultRange) != "" {
		t.Errorf("host %+v", host)
	}
	ct := ParseIDMaps("uid_map\n0 100000 65536\ngid_map\n0 100000 65536\n")
	if got := ct.Lacks(DefaultRange); got != "0-65535" {
		t.Errorf("container %q", got)
	}
	if ct.Lacks(Range{40000, 49999}) != "" {
		t.Error("a range inside the map refused")
	}
	split := ParseIDMaps("uid_map\n0 1 55534\n65534 55535 2\n80000 55537 10000\ngid_map\n0 1 65536\n")
	if split.Lacks(DefaultRange) != "GIDs 0-65535" {
		t.Errorf("split %q", split.Lacks(DefaultRange))
	}
	joined := ParseIDMaps("uid_map\n0 1 85000\n85000 200000 5000\n")
	if joined.Lacks(DefaultRange) != "" {
		t.Error("adjacent extents not joined")
	}
	if (IDMaps{}).Lacks(DefaultRange) != "" {
		t.Error("nothing read refused")
	}
	if got := IDMapRefusal("c1", DefaultRange, "0-65535"); got != "'c1' cannot hold UIDs 80000-89999: its user namespace maps only 0-65535 (an unprivileged container). Give it an ID map that covers 80000-89999, run it privileged, or choose a range it can hold: tacctl config linux uid-range <min>-<max> (one range for all hosts)." {
		t.Errorf("refusal %q", got)
	}
}

func TestAwkHelpers(t *testing.T) {
	for _, c := range []struct {
		a, b string
		eq   bool
	}{{"20000", "020000", true}, {"1e3", "1000", true}, {"web1", "web1", true}, {"a", "b", false}, {"", "", true}, {" 5", "5", true}, {"0x10", "16", false}} {
		if awkEqual(c.a, c.b) != c.eq {
			t.Errorf("awkEqual(%q, %q)", c.a, c.b)
		}
	}
	if sortNumber("20000") != 20000 || sortNumber("x") != 0 || sortNumber(" -5.5:z") != -5.5 {
		t.Error("sortNumber")
	}
}

func TestScopeUsersAndCounts(t *testing.T) {
	e, _, errb := testEnv(t)
	got, keep, err := e.ScopeUsers(nil, nil)
	if err != nil || got != "" || keep != nil {
		t.Fatalf("empty %q %v", got, err)
	}
	if _, err := os.Stat(e.Paths.UIDs); !os.IsNotExist(err) {
		t.Error("no users, but the UID file was made")
	}
	got, keep, _ = e.ScopeUsers([]string{"op|7", "x|0", "root|15", "Bad|1", "np|"}, nil)
	if got != "op:operator:80000\nx:readonly:80001" || strings.Join(keep, ",") != "np" {
		t.Errorf("users %q keep %q", got, keep)
	}
	if !strings.Contains(errb.String(), "\033[1;33m[WARN]\033[0m Skipping 'Bad'") {
		t.Errorf("warn %q", errb.String())
	}
	if n := UserCount([]string{"op|7", "root|15", "Bad|1", "x|"}); n != 2 {
		t.Errorf("count %d", n)
	}
	if CountLines("a\n\nb") != 2 || CountLines("") != 0 {
		t.Error("CountLines")
	}
	if MethodLabel(Radius) != "RADIUS" || MethodLabel("x") != "TACACS+" || MethodList() != "tacplus, radius" {
		t.Error("labels")
	}
	if b, ok := MethodBackend("ldap"); ok || b != "" {
		t.Error("ldap")
	}
	if !LinuxName("a_b-1") || LinuxName("root") || LinuxName("Ab") || LinuxName(strings.Repeat("a", 33)) {
		t.Error("LinuxName")
	}
	if Machine() == "" {
		t.Error("Machine")
	}
}
