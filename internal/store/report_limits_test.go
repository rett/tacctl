package store_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
)

// reports_max_size and reports_max_count (0.2.26) are optional user keys
// written only when set: a store that never used them is what 0.2.25 wrote,
// byte for byte, and 0 is a limit (no cap), not the absence of one.
func TestReportLimitsRoundTrip(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	before := string(readFile(t, e.path))
	e.mustMutate(userSet("alice", "reports_max_size=20971520", "reports_max_count=0"))
	text := string(readFile(t, e.path))
	if strings.Count(text, "reports_max_size: 20971520") != 1 || strings.Count(text, "reports_max_count: 0") != 1 {
		t.Fatalf("the keys are not written once:\n%s", text)
	}
	equal(t, e.mustGet("users", "alice", "reports_max_size"), "20971520")
	equal(t, e.mustGet("users", "alice", "reports_max_count"), "0")
	if out, _ := e.get("users", "bob", "reports_max_size"); out != "" {
		t.Errorf("bob has the key: %q", out)
	}
	s, err := store.Load(e.path)
	if err != nil {
		t.Fatal(err)
	}
	m := model.FromStore(s)
	a, b := m.User("alice"), m.User("bob")
	if a.ReportsMaxSize == nil || *a.ReportsMaxSize != 20971520 || a.ReportsMaxCount == nil || *a.ReportsMaxCount != 0 {
		t.Errorf("the model does not carry the limits: %v %v", a.ReportsMaxSize, a.ReportsMaxCount)
	}
	if b.ReportsMaxSize != nil || b.ReportsMaxCount != nil {
		t.Error("the model gives bob a limit")
	}
	lines, _ := m.UserInfo("alice")
	if got := strings.Join(lines, "\n"); !strings.Contains(got, "reports_max_size=20971520\n") || !strings.HasSuffix(got, "reports_max_count=0") {
		t.Errorf("UserInfo:\n%s", got)
	}
	if lines, _ := m.UserInfo("bob"); strings.Contains(strings.Join(lines, "\n"), "reports_") {
		t.Errorf("UserInfo of bob: %v", lines)
	}

	// null (or nothing) removes one key, and the file is the one it was
	e.mustMutate(userSet("alice", "reports_max_size=null"))
	if text := string(readFile(t, e.path)); strings.Contains(text, "reports_max_size") || !strings.Contains(text, "reports_max_count: 0") {
		t.Errorf("after removing one key:\n%s", text)
	}
	e.mustMutate(userSet("alice", "reports_max_count="))
	equal(t, string(readFile(t, e.path)), before)
	// a user the keys were never set on has no key at all
	e.mustMutate(userSet("bob", "reports_max_size=null", "reports_max_count=null"))
	equal(t, string(readFile(t, e.path)), before)
}

func TestReportLimitsFollowARename(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(userSet("bob", "reports_max_size=1024", "reports_max_count=7"))
	e.mustMutate(func(s *store.Store) error { return s.UserRename("bob", "robert") })
	equal(t, e.mustGet("users", "robert", "reports_max_size"), "1024")
	equal(t, e.mustGet("users", "robert", "reports_max_count"), "7")
}

// The validator takes 0 to 1 GiB and 0 to 100000, whole numbers only.
func TestReportLimitsValidation(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	before := string(readFile(t, e.path))
	for _, c := range []struct{ field, want string }{
		{"reports_max_size=1073741825", "user 'alice': reports_max_size must be 0-1073741824"},
		{"reports_max_count=100001", "user 'alice': reports_max_count must be 0-100000"},
		{"reports_max_size=-1", "user 'alice': reports_max_size must be a whole number"},
		{"reports_max_size=10Mi", "user 'alice': reports_max_size must be a whole number"},
		{"reports_max_count=1.5", "user 'alice': reports_max_count must be a whole number"},
		{"reports_max_count=many", "user 'alice': reports_max_count must be a whole number"},
	} {
		contains(t, e.mutate(userSet("alice", c.field)), c.want)
		equal(t, string(readFile(t, e.path)), before)
	}
	for _, ok := range []string{"reports_max_size=0", "reports_max_size=1073741824", "reports_max_count=0", "reports_max_count=100000"} {
		e.mustMutate(userSet("alice", ok))
	}
	for _, bad := range []string{"reports_max_size: '20'", "reports_max_size: 20.5", "reports_max_count: true", "reports_max_size: null", "reports_max_count: -3", "reports_max_size: 2000000000"} {
		if out, valid := e.validateYAML("version: 1\n" + builtins + "\nusers:\n  alice: {group: readonly, scopes: [], hash: null, disabled: true, " + bad + "}\n"); valid {
			t.Errorf("%s is valid", bad)
		} else if !strings.Contains(out, "user 'alice': reports_max_") {
			t.Errorf("%s: %s", bad, out)
		}
	}
	if out, valid := e.validateYAML("version: 1\n" + builtins + "\nusers:\n  alice: {group: readonly, scopes: [], hash: null, disabled: true, reports_max_size: 0, reports_max_count: 100}\n"); !valid {
		t.Errorf("the limits are refused: %s", out)
	}
}

func TestReportLimitsSinkCarriesNone(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	out, ok := e.validateYAML("version: 1\n" + builtins + `
users:
  root: {group: readonly, scopes: [], hash: null, disabled: true, accounting_sink: true, reports_max_count: 5}
`)
	if ok {
		t.Fatal("the sink with a limit is valid")
	}
	contains(t, out, "user 'root': the accounting sink must not carry a limit of the stored reports")
	contains(t, e.mutate(userSet("root", "group=readonly", "reports_max_count=5")), "accounting sink")
}

// A rendered or legacy file cannot hold a limit: a replacing import keeps the
// ones the existing store has.
func TestImportReplaceKeepsReportLimits(t *testing.T) {
	e := newImportEnv(t)
	e.place("legacy.import-edge.yaml")
	e.edgeSidecars()
	e.mustImport()
	e.mustMutate(userSet("alice", "reports_max_size=0"))
	out := e.mustImport("--replace")
	contains(t, out, "kept the report limits of 1 user(s)")
	equal(t, e.mustGet("users", "alice", "reports_max_size"), "0")
}

func TestReportLimitHoldersAndRollback(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	if got, err := store.ReportLimitHolders(e.path); err != nil || len(got) != 0 {
		t.Fatalf("holders of a store without: %v %v", got, err)
	}
	e.mustMutate(userSet("alice", "reports_max_size=20971520"))
	e.mustMutate(userSet("bob", "reports_max_count=0"))
	got, err := store.ReportLimitHolders(e.path)
	if err != nil || len(got) != 2 || got[0] != (store.ReportLimitHolder{User: "alice", Size: "20971520"}) || got[1] != (store.ReportLimitHolder{User: "bob", Count: "0"}) {
		t.Fatalf("holders: %+v %v", got, err)
	}
	snaps := 0
	removed, changed, err := store.RollbackReportLimits(e.path, func() error { snaps++; return nil })
	if err != nil || !changed || snaps != 1 || strings.Join(removed, ",") != "alice,bob" {
		t.Fatalf("rollback: %v %v %d %v", removed, changed, snaps, err)
	}
	if text := string(readFile(t, e.path)); strings.Contains(text, "reports_max") {
		t.Errorf("the keys stay:\n%s", text)
	}
	// nothing there: not written, and before still runs first
	mtime := func() int64 { fi, _ := os.Stat(e.path); return fi.ModTime().UnixNano() }
	was := mtime()
	removed, changed, err = store.RollbackReportLimits(e.path, nil)
	if err != nil || changed || len(removed) != 0 || mtime() != was {
		t.Errorf("second rollback: %v %v %v", removed, changed, err)
	}
	// an error of before stops the write
	e.mustMutate(userSet("alice", "reports_max_count=3"))
	if _, changed, err := store.RollbackReportLimits(e.path, func() error { return os.ErrPermission }); err == nil || changed {
		t.Errorf("before failed: %v %v", changed, err)
	}
	if text := string(readFile(t, e.path)); !strings.Contains(text, "reports_max_count: 3") {
		t.Errorf("the keys went although the snapshot failed:\n%s", text)
	}
	// a store that cannot be read is an error, not an empty list
	if _, err := store.ReportLimitHolders(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("an absent store reads as empty")
	}
}
