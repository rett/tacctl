package hosts

import (
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
	for _, step := range []struct{ name, want string }{{"alice", "20000"}, {"bob", "20001"}, {"alice", "20000"}} {
		got, err := u.For(step.name)
		if err != nil || got != step.want {
			t.Fatalf("For(%s) = %q %v", step.name, got, err)
		}
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	// A reassignment below the others: the next user still goes after the
	// highest number, never into the gap.
	if err := u.Assign("bob", "1001"); err != nil {
		t.Fatal(err)
	}
	if got, _ := u.For("carol"); got != "20001" {
		t.Errorf("carol %q", got)
	}
	if got := readFile(t, p); got != "alice:20000\nbob:1001\ncarol:20001\n" {
		t.Errorf("file %q", got)
	}
	if h, _ := u.Holder("20000"); h != "alice" {
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
	want := "  bob                      1001\n  alice                    20000\n  carol                    20001\n"
	if l != want {
		t.Errorf("listing\n%q\n%q", l, want)
	}
	// Above the base, a hand-edited number counts too; garbage does not
	// break the allocation.
	writeFile(t, p, "x:30000\ny\nz:abc\n")
	if got, _ := (UIDs{Path: p}).next(); got != "1" {
		// awk compares "abc" > "30000" as strings and prints "abc"+1.
		t.Errorf("next after garbage %q", got)
	}
	writeFile(t, p, "x:30000\ny\n")
	if got, _ := (UIDs{Path: p}).next(); got != "30001" {
		t.Errorf("next %q", got)
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

func TestAwkHelpers(t *testing.T) {
	for _, c := range []struct {
		a, b string
		eq   bool
	}{{"20000", "020000", true}, {"1e3", "1000", true}, {"web1", "web1", true}, {"a", "b", false}, {"", "", true}, {" 5", "5", true}, {"0x10", "16", false}} {
		if awkEqual(c.a, c.b) != c.eq {
			t.Errorf("awkEqual(%q, %q)", c.a, c.b)
		}
	}
	if awkPrefixNumber("12abc") != 12 || awkPrefixNumber("abc") != 0 {
		t.Error("prefix number")
	}
	if awkString(3) != "3" || awkString(2.5) != "2.5" {
		t.Error("awkString")
	}
	if sortNumber("20000") != 20000 || sortNumber("x") != 0 || sortNumber(" -5.5:z") != -5.5 {
		t.Error("sortNumber")
	}
}

func TestScopeUsersAndCounts(t *testing.T) {
	e, _, errb := testEnv(t)
	got, err := e.ScopeUsers(nil)
	if err != nil || got != "" {
		t.Fatalf("empty %q %v", got, err)
	}
	if _, err := os.Stat(e.Paths.UIDs); !os.IsNotExist(err) {
		t.Error("no users, but the UID file was made")
	}
	got, _ = e.ScopeUsers([]string{"op|7", "x|0", "root|15", "Bad|1"})
	if got != "op:operator:20000\nx:readonly:20001" {
		t.Errorf("users %q", got)
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
