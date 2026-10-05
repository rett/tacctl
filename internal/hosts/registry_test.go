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
		if UIDInRange(c.uid) != c.in {
			t.Errorf("UIDInRange(%q)", c.uid)
		}
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

// The one-time move from the legacy range: every legacy entry (users and
// removed users alike) to the same offset, the old file kept, the rest of
// the file as it was; a second run changes nothing; a number that would
// collide with another name's refuses the whole renumbering.
func TestUIDsRenumberLegacy(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "linux-uids")
	u := UIDs{Path: p}
	if n, err := u.RenumberLegacy(p + ".bak"); n != 0 || err != nil {
		t.Fatalf("missing file: %d %v", n, err)
	}
	old := "alice:20000\nbob:1001\ncarol:20001\nzed:25000\nnew:80002\njunk\nx:30000\n"
	writeFile(t, p, old)
	n, err := u.RenumberLegacy(p + ".bak")
	if n != 3 || err != nil {
		t.Fatalf("renumber %d %v", n, err)
	}
	if got := readFile(t, p); got != "alice:80000\nbob:1001\ncarol:80001\nzed:85000\nnew:80002\njunk\nx:30000\n" {
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
	// Idempotent: nothing left in the legacy range, nothing written.
	if n, err := u.RenumberLegacy(p + ".bak2"); n != 0 || err != nil {
		t.Errorf("second run %d %v", n, err)
	}
	if _, err := os.Stat(p + ".bak2"); !os.IsNotExist(err) {
		t.Error("a second run made a backup")
	}
	if got, _ := u.For("dora"); got != "85001" {
		t.Errorf("next after renumbering %q", got)
	}

	// A collision: nothing changed, no backup.
	coll := "alice:20000\nbob:20001\ncarl:80001\n"
	writeFile(t, p, coll)
	n, err = u.RenumberLegacy(p + ".bak3")
	var c *UIDCollision
	if n != 0 || !errors.As(err, &c) || *c != (UIDCollision{Name: "bob", Old: "20001", New: "80001", Holder: "carl"}) {
		t.Fatalf("collision %d %v", n, err)
	}
	if got := readFile(t, p); got != coll {
		t.Errorf("a refused renumbering wrote %q", got)
	}
	if _, err := os.Stat(p + ".bak3"); !os.IsNotExist(err) {
		t.Error("a refused renumbering made a backup")
	}
	// The same name at both numbers is no collision.
	writeFile(t, p, "bob:20001\nbob:80001\n")
	if n, err := u.RenumberLegacy(p + ".bak4"); n != 1 || err != nil || readFile(t, p) != "bob:80001\nbob:80001\n" {
		t.Errorf("same name %d %v %q", n, err, readFile(t, p))
	}

	for _, c := range []struct {
		uid    string
		legacy bool
	}{{"20000", true}, {"29999", true}, {"19999", false}, {"30000", false}, {"80000", false}, {"020000", false}, {"", false}} {
		if LegacyUID(c.uid) != c.legacy {
			t.Errorf("LegacyUID(%q)", c.uid)
		}
	}
	if Renumbered(20000) != 80000 || Renumbered(29999) != 89999 || Renumbered(20123) != 80123 {
		t.Error("Renumbered")
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
	got, keep, err := e.ScopeUsers(nil)
	if err != nil || got != "" || keep != nil {
		t.Fatalf("empty %q %v", got, err)
	}
	if _, err := os.Stat(e.Paths.UIDs); !os.IsNotExist(err) {
		t.Error("no users, but the UID file was made")
	}
	got, keep, _ = e.ScopeUsers([]string{"op|7", "x|0", "root|15", "Bad|1", "np|"})
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
