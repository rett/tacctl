package devconf

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devices"
)

func newStore(t *testing.T) Store {
	t.Helper()
	d := t.TempDir()
	return Store{Records: filepath.Join(d, "devices-config.json"), Dir: filepath.Join(d, "device-config")}
}

var at = time.Date(2026, 10, 9, 14, 2, 0, 0, time.UTC)

func sampleRecord() Record {
	return Record{Address: "192.0.2.10", Vendor: "juniper", Transport: "netconf", Netconf: "hello ok", NetconfAt: at,
		Pulled: at, By: "alice", Result: ResultOK, DurationMS: 1234, SecretsVisible: true,
		Sections: map[string]SectionRecord{SectionAAA: {SHA256: "ab", State: "ok"}}}
}

func TestRecordsRoundTrip(t *testing.T) {
	s := newStore(t)
	r, err := s.Load()
	if err != nil || len(r.Devices) != 0 || r.Version != RecordsVersion {
		t.Fatalf("absent file: %+v %v", r, err)
	}
	r.Put("Core-SW1", sampleRecord())
	r.Updated = at
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(s.Records)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", st, err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := got.Of("core-sw1")
	if !ok || rec.By != "alice" || rec.Sections[SectionAAA].State != "ok" || !rec.Pulled.Equal(at) || !rec.SecretsVisible {
		t.Fatalf("%+v %v", rec, ok)
	}
	if _, ok := got.Of("CORE-SW1"); !ok {
		t.Error("lookup is case-insensitive")
	}
	if !slices.Equal(got.Names(), []string{"core-sw1"}) {
		t.Errorf("names %q", got.Names())
	}
	// the file is JSON with the version
	var raw map[string]any
	data, _ := os.ReadFile(s.Records)
	if err := json.Unmarshal(data, &raw); err != nil || raw["version"] != float64(1) {
		t.Errorf("%s", data)
	}
	// No temporary file is left behind.
	ents, _ := os.ReadDir(filepath.Dir(s.Records))
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("left %s", e.Name())
		}
	}
	// Put copies: a change to the argument's map does not reach the store.
	in := sampleRecord()
	r.Put("x", in)
	in.Sections[SectionAAA] = SectionRecord{State: "changed"}
	if x, _ := r.Of("x"); x.Sections[SectionAAA].State != "ok" {
		t.Error("Put did not copy")
	}
}

func TestRecordsCorruptIsRebuilt(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":       "{not json",
		"other version": `{"version": 7, "devices": {}}`,
		"wrong shape":   `[1,2]`,
	} {
		s := newStore(t)
		if err := os.WriteFile(s.Records, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := s.Load()
		if err == nil || r == nil || len(r.Devices) != 0 {
			t.Errorf("%s: %v %+v", name, err, r)
			continue
		}
		var ne interface{ Lines() []string }
		if !errors.As(err, &ne) || !strings.Contains(err.Error(), "device config pull") {
			t.Errorf("%s: %v", name, err)
		}
		// A save over it works.
		r.Put("a", sampleRecord())
		if err := s.Save(r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Load(); err != nil {
			t.Errorf("%s: after save: %v", name, err)
		}
	}
}

func TestRecordsRenameForget(t *testing.T) {
	r := NewRecords()
	r.Put("a", sampleRecord())
	r.Put("b", sampleRecord())
	if err := r.Rename("a", "c"); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Of("a"); ok {
		t.Error("old name kept")
	}
	if _, ok := r.Of("c"); !ok {
		t.Error("new name missing")
	}
	if err := r.Rename("c", "b"); err == nil {
		t.Error("rename onto a record")
	}
	if err := r.Rename("zz", "yy"); err != nil {
		t.Errorf("rename of nothing: %v", err)
	}
	if !r.Delete("c") || r.Delete("c") {
		t.Error("Delete")
	}
}

func TestSectionsRoundTrip(t *testing.T) {
	s := newStore(t)
	secs := map[string]devices.Section{
		SectionAAA: {Name: SectionAAA, Lines: []string{
			"set system tacplus-server 192.0.2.10 secret $9$abc", "set system authentication-order tacplus"}},
		SectionSNMP:       {Name: SectionSNMP, Lines: []string{`set snmp location "Rack 4, DC1"`, `set snmp contact "NOC <noc@example.net>"`}},
		SectionNetconf:    {Name: SectionNetconf},
		SectionBreakGlass: {Name: SectionBreakGlass, Lines: []string{"# not a comment but a statement: x", "set a: b", "- c", "'quoted'"}},
	}
	if err := s.SaveSections("Core-SW1", "junos", secs); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.Dir, "core-sw1.yaml")
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	if dst, _ := os.Stat(s.Dir); dst.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", dst.Mode().Perm())
	}
	text, _ := os.ReadFile(p)
	if !strings.Contains(string(text), "aaa: |\n  set system tacplus-server") || !strings.Contains(string(text), "netconf: \"\"") {
		t.Errorf("layout:\n%s", text)
	}
	got, err := s.Sections("core-sw1", "junos")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range secs {
		g, ok := got[name]
		if !ok {
			t.Errorf("[%s] lost", name)
			continue
		}
		if len(want.Lines) == 0 && len(g.Lines) == 0 {
			continue
		}
		// Statements come back canonical: quotes as the device prints them.
		norm, _ := Normalise("junos", want)
		gn, _ := Normalise("junos", g)
		if name != SectionBreakGlass && !slices.Equal(norm.Lines, gn.Lines) {
			t.Errorf("[%s] %q != %q", name, gn.Lines, norm.Lines)
		}
	}
	// the secret marks are found again
	if !got[SectionAAA].Secret[0] || got[SectionAAA].Secret[1] {
		t.Errorf("marks %v", got[SectionAAA].Secret)
	}
	// an absent file
	none, err := s.Sections("other", "junos")
	if err != nil || none != nil {
		t.Errorf("absent: %v %v", none, err)
	}
	// a corrupt one is an error naming the verb that rebuilds it
	if err := os.WriteFile(p, []byte("aaa: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sections("core-sw1", "junos"); err == nil || !strings.Contains(err.Error(), "device config pull") {
		t.Errorf("%v", err)
	}
	// device names that would leave the directory are refused
	for _, bad := range []string{"", "../x", "a/b", ".hidden", ".."} {
		if err := s.SaveSections(bad, "junos", secs); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSectionsCiscoRoundTrip(t *testing.T) {
	s := newStore(t)
	ex, err := Extract("ios", capture(t, "ios/reference-lab/running-config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSections("sw1", "ios", ex.Sections); err != nil {
		t.Fatal(err)
	}
	got, err := s.Sections("sw1", "ios")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range SectionNames {
		if !slices.Equal(got[n].Lines, ex.Sections[n].Lines) {
			t.Errorf("[%s]\n got %q\nwant %q", n, got[n].Lines, ex.Sections[n].Lines)
		}
		if !slices.Equal(got[n].Secret, ex.Sections[n].Secret) {
			t.Errorf("[%s] marks %v != %v", n, got[n].Secret, ex.Sections[n].Secret)
		}
	}
	// and what comes back compares the same as the extraction did
	expected := expectedSections(t, "ios/reference-lab/expected.txt")
	rec := Record{Vendor: "cisco", Result: ResultOK, SecretsVisible: true}
	r1, _ := CompareAll(expected, ex)
	r2, _ := CompareAll(expected, rec.Extracted(got))
	if resultText(ex, r1) != resultText(ex, r2) {
		t.Error("the stored sections compare differently")
	}
}

func TestStoreForgetRenameAll(t *testing.T) {
	s := newStore(t)
	put := func(name string) {
		unlock, err := s.Lock()
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		r, _ := s.Load()
		r.Put(name, sampleRecord())
		if err := s.Save(r); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveSections(name, "junos", map[string]devices.Section{SectionAAA: {Name: SectionAAA, Lines: []string{"set a b"}}}); err != nil {
			t.Fatal(err)
		}
	}
	put("a")
	put("b")
	if err := s.Rename("a", "c"); err != nil {
		t.Fatal(err)
	}
	r, _ := s.Load()
	if _, ok := r.Of("c"); !ok || len(r.Devices) != 2 {
		t.Errorf("%v", r.Names())
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "c.yaml")); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "a.yaml")); err == nil {
		t.Error("old sections file kept")
	}
	had, err := s.Forget("c")
	if err != nil || !had {
		t.Errorf("%v %v", had, err)
	}
	if had, _ := s.Forget("c"); had {
		t.Error("forgot twice")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "c.yaml")); err == nil {
		t.Error("sections file kept")
	}
	n, err := s.ForgetAll()
	if err != nil || n != 1 {
		t.Errorf("%d %v", n, err)
	}
	if r, _ := s.Load(); len(r.Devices) != 0 {
		t.Errorf("%v", r.Names())
	}
	if ents, _ := os.ReadDir(s.Dir); len(ents) != 0 {
		t.Errorf("%d files left", len(ents))
	}
}

// The plain view (Junos, D97) lives beside the sections file, is 0600, goes
// with Forget, ForgetAll and Rename, is no device of its own, is removed by a
// pull that read none, and is read only for the pull it was made with.
func TestPlainViewFollowsTheDevice(t *testing.T) {
	s := newStore(t)
	pulled := time.Date(2026, 10, 10, 14, 2, 0, 123456789, time.UTC)
	secs := map[string]devices.Section{SectionAAA: {Name: SectionAAA, Lines: []string{"set system tacplus-server 192.0.2.10 single-connection"}}}
	for _, n := range []string{"a", "b"} {
		unlock, err := s.Lock()
		if err != nil {
			t.Fatal(err)
		}
		r, _ := s.Load()
		r.Put(n, sampleRecord())
		if err := s.Save(r); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveSections(n, "junos", secs); err != nil {
			t.Fatal(err)
		}
		if err := s.SavePlain(n, "junos", secs, pulled); err != nil {
			t.Fatal(err)
		}
		unlock()
	}
	if st, err := os.Stat(filepath.Join(s.Dir, "a.plain")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("plain file: %v %v", st, err)
	}
	got, err := s.Plain("a", "junos", pulled)
	if err != nil || !slices.Equal(got[SectionAAA].Lines, secs[SectionAAA].Lines) {
		t.Fatalf("plain: %+v %v", got, err)
	}
	// the sections file does not read the stamp as a section
	if secs, err := s.Sections("a", "junos"); err != nil || len(secs) != 1 {
		t.Errorf("sections read the plain stamp: %+v %v", secs, err)
	}
	// a view of another pull is no view of this one
	if got, err := s.Plain("a", "junos", pulled.Add(time.Second)); got != nil || err != nil {
		t.Errorf("a plain view of another pull was read: %v %v", got, err)
	}
	if got, err := s.Plain("a", "junos", time.Time{}); got != nil || err != nil {
		t.Errorf("a plain view for a record with no pull was read: %v %v", got, err)
	}
	if got, err := s.Plain("zzz", "junos", pulled); got != nil || err != nil {
		t.Errorf("no file: %v %v", got, err)
	}
	// a view with no stamp (an earlier build's) is read for no pull
	if err := os.WriteFile(filepath.Join(s.Dir, "old.plain"), []byte("version: 1\naaa: |\n  set a b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Plain("old", "junos", pulled); got != nil || err != nil {
		t.Errorf("an unstamped plain view was read: %v %v", got, err)
	}
	_ = os.Remove(filepath.Join(s.Dir, "old.plain"))
	// a pull that read none leaves none
	if err := s.SavePlain("b", "junos", nil, pulled); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "b.plain")); err == nil {
		t.Error("the plain view of the last pull is kept")
	}
	if err := s.SavePlain("b", "junos", nil, pulled); err != nil {
		t.Errorf("removing what is not there: %v", err)
	}
	// rename and forget carry it
	if err := s.Rename("a", "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "c.plain")); err != nil {
		t.Error("the plain view did not move with its device")
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "a.plain")); err == nil {
		t.Error("the old plain view stayed")
	}
	if got, err := s.Plain("c", "junos", pulled); err != nil || got == nil {
		t.Errorf("the moved plain view: %v %v", got, err)
	}
	if had, err := s.Forget("c"); err != nil || !had {
		t.Fatalf("%v %v", had, err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "c.plain")); err == nil {
		t.Error("forget left the plain view")
	}
	if err := s.SavePlain("b", "junos", secs, pulled); err != nil {
		t.Fatal(err)
	}
	n, err := s.ForgetAll()
	if err != nil || n != 1 {
		t.Errorf("ForgetAll counted %d (a plain view is no device): %v", n, err)
	}
	if ents, _ := os.ReadDir(s.Dir); len(ents) != 0 {
		t.Errorf("%d files left", len(ents))
	}
}

// A rename of a device with no plain view drops the stale one the new name
// had (the comment on Rename says it does).
func TestRenameDropsAStalePlainViewOfTheTarget(t *testing.T) {
	s := newStore(t)
	pulled := time.Date(2026, 10, 10, 14, 2, 0, 0, time.UTC)
	secs := map[string]devices.Section{SectionAAA: {Name: SectionAAA, Lines: []string{"set a b"}}}
	r, _ := s.Load()
	r.Put("old", sampleRecord())
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveSections("old", "junos", secs); err != nil {
		t.Fatal(err)
	}
	// the target name has a plain view left from a device that was forgotten
	if err := s.SavePlain("new", "junos", secs, pulled); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveBackout("new", StoredBackout{Pulled: pulled, Vendor: "junos", Address: "192.0.2.1", Text: "# x\n"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("old", "new"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"new.plain", "new.backout"} {
		if _, err := os.Stat(filepath.Join(s.Dir, f)); err == nil {
			t.Errorf("a stale %s stayed under the new name", f)
		}
	}
}

// The stored back-out (D111, amended): beside the record, 0600, stamped with
// the pull it was computed from, replaced by the next plan, and carried by
// Rename, Forget and ForgetAll like the plain view.
func TestStoredBackoutFollowsTheDevice(t *testing.T) {
	s := newStore(t)
	pulled := time.Date(2026, 10, 10, 14, 2, 0, 987654321, time.UTC)
	secs := map[string]devices.Section{SectionAAA: {Name: SectionAAA, Lines: []string{"set a b"}}}
	r, _ := s.Load()
	for _, n := range []string{"a", "b"} {
		r.Put(n, sampleRecord())
		if err := s.SaveSections(n, "juniper", secs); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(r); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Backout("a"); got != nil || err != nil {
		t.Fatalf("a back-out before any plan: %v %v", got, err)
	}
	text := "##### box #####\n# BACK-OUT\n##### BACK-OUT FROM HERE: a #####\nconfigure private\nset a b\n"
	if err := s.SaveBackout("a", StoredBackout{Pulled: pulled, Vendor: "juniper", Address: "192.0.2.1", Sections: []string{"aaa", "snmp"}, Text: text}); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(s.Dir, "a.backout")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("back-out file: %v %v", st, err)
	}
	got, err := s.Backout("a")
	if err != nil || got == nil || got.Text != text || !got.Pulled.Equal(pulled) || got.Vendor != "juniper" ||
		got.Address != "192.0.2.1" || strings.Join(got.Sections, ",") != "aaa,snmp" {
		t.Fatalf("back-out: %+v %v", got, err)
	}
	// a stamp and the address are required
	if err := s.SaveBackout("a", StoredBackout{Vendor: "juniper", Address: "192.0.2.1", Text: text}); err == nil {
		t.Error("a back-out with no stamp was stored")
	}
	if err := s.SaveBackout("a", StoredBackout{Pulled: pulled, Vendor: "juniper", Text: text}); err == nil {
		t.Error("a back-out with no address was stored")
	}
	// the next plan replaces it
	later := pulled.Add(time.Hour)
	if err := s.SaveBackout("a", StoredBackout{Pulled: later, Vendor: "juniper", Address: "192.0.2.1", Text: "# two\n"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Backout("a"); got == nil || got.Text != "# two\n" || !got.Pulled.Equal(later) || len(got.Sections) != 0 {
		t.Errorf("replaced back-out: %+v", got)
	}
	// a file that is none of ours is no back-out
	if err := os.WriteFile(filepath.Join(s.Dir, "junk.backout"), []byte("not a back-out"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Backout("junk"); got != nil || err != nil {
		t.Errorf("junk read as a back-out: %v %v", got, err)
	}
	_ = os.Remove(filepath.Join(s.Dir, "junk.backout"))
	// rename carries it, the sections file's listing does not take it for a device
	if err := s.Rename("a", "c"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Backout("c"); got == nil || got.Text != "# two\n" {
		t.Errorf("the back-out did not move: %+v", got)
	}
	if got, _ := s.Backout("a"); got != nil {
		t.Error("the old back-out stayed")
	}
	if err := s.SaveBackout("b", StoredBackout{Pulled: pulled, Vendor: "juniper", Address: "192.0.2.2", Text: "# b\n"}); err != nil {
		t.Fatal(err)
	}
	// a plan with changes and nothing to type removes the kept one
	if err := s.RemoveBackout("b"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Backout("b"); got != nil {
		t.Errorf("RemoveBackout left it: %+v", got)
	}
	if err := s.RemoveBackout("b"); err != nil {
		t.Errorf("removing a back-out that is not there: %v", err)
	}
	if err := s.SaveBackout("b", StoredBackout{Pulled: pulled, Vendor: "juniper", Address: "192.0.2.2", Text: "# b\n"}); err != nil {
		t.Fatal(err)
	}
	if had, err := s.Forget("c"); err != nil || !had {
		t.Fatalf("%v %v", had, err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "c.backout")); err == nil {
		t.Error("forget left the back-out")
	}
	n, err := s.ForgetAll()
	if err != nil || n != 1 {
		t.Errorf("ForgetAll counted %d (a back-out is no device): %v", n, err)
	}
	if ents, _ := os.ReadDir(s.Dir); len(ents) != 0 {
		t.Errorf("%d files left", len(ents))
	}
}

// Writers hold the lock across load and save: concurrent updates all land.
func TestStoreLockSerialises(t *testing.T) {
	s := newStore(t)
	var wg sync.WaitGroup
	names := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for _, n := range names {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := s.Lock()
			if err != nil {
				t.Error(err)
				return
			}
			defer unlock()
			r, err := s.Load()
			if err != nil {
				t.Error(err)
				return
			}
			r.Put(n, sampleRecord())
			if err := s.Save(r); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	r, _ := s.Load()
	if !slices.Equal(r.Names(), names) {
		t.Errorf("%q", r.Names())
	}
}

func TestStaleness(t *testing.T) {
	expected := expectedSections(t, "ios/reference-lab/expected.txt")
	ex, _ := Extract("ios", capture(t, "ios/reference-lab/running-config.txt"))
	// A device that agrees on every rendered section: the rendering itself.
	agree := map[string]devices.Section{}
	for _, e := range expected {
		agree[e.Name] = e
	}
	rec := &Record{Vendor: "cisco", Result: ResultOK, SecretsVisible: true}

	for _, tc := range []struct {
		name   string
		rec    *Record
		stored map[string]devices.Section
		want   Staleness
	}{
		{"no record", nil, nil, StaleNever},
		{"zero record", &Record{}, nil, StaleNever},
		{"failed", &Record{Vendor: "cisco", Result: ResultAuthFailed}, ex.Sections, StaleFailed},
		{"interrupted", &Record{Vendor: "cisco", Result: ResultInterrupted}, ex.Sections, StaleFailed},
		{"unsupported", &Record{Vendor: "wti", Result: ResultUnsupported}, nil, StaleOK},
		// Only a WTI unit's pull is unsupported; another vendor's record of
		// that result is a refusal that read nothing.
		{"unsupported of another vendor", &Record{Vendor: "cisco", Result: ResultUnsupported}, nil, StaleFailed},
		{"ok without sections", rec, nil, StaleNever},
		{"differs", rec, ex.Sections, StaleDiffers},
		{"agrees", rec, agree, StaleOK},
	} {
		got, err := Stale(tc.rec, tc.stored, expected)
		if err != nil || got != tc.want {
			t.Errorf("%s: %q %v, want %q", tc.name, got, err, tc.want)
		}
		if got.IsStale() == (tc.want == StaleOK) {
			t.Errorf("%s: IsStale", tc.name)
		}
	}
	// A change of the rendering makes a stored pull stale without a pull.
	changed := slices.Clone(expected)
	for i := range changed {
		if changed[i].Name == SectionAAA {
			changed[i].Lines = append(slices.Clone(changed[i].Lines), "aaa authorization console")
			changed[i].Secret = append(slices.Clone(changed[i].Secret), false)
		}
	}
	if got, _ := Stale(rec, agree, changed); got != StaleDiffers {
		t.Errorf("after a change: %q", got)
	}
	// Sections tacctl no longer renders are n/a: not stale.
	if got, _ := Stale(rec, ex.Sections, nil); got != StaleOK {
		t.Errorf("nothing rendered: %q", got)
	}
	// Secrets the login could not see do not make a device stale.
	jx, _ := Extract("junos", capture(t, "juniper/synthetic-lab/display-set-engineer.txt"))
	only := []devices.Section{{Name: SectionAAA, Lines: []string{
		"set system authentication-order [ password tacplus ]",
		"set system tacplus-server 192.0.2.10 secret lab-secret",
		"set system tacplus-server 192.0.2.10 single-connection",
		"set system tacplus-server 192.0.2.99 secret other-secret",
		"set system accounting events [ login change-log ]",
		"set system accounting destination tacplus"}, Secret: []bool{false, true, false, true, false, false}}}
	jrec := &Record{Vendor: "juniper", Result: ResultOK, SecretsVisible: false}
	if got, _ := Stale(jrec, jx.Sections, only); got != StaleOK {
		t.Errorf("not visible: %q", got)
	}
	jrec.SecretsVisible = true
	if got, _ := Stale(jrec, jx.Sections, only); got != StaleDiffers {
		t.Errorf("visible: %q", got)
	}
}

func TestRecordedAndSetSections(t *testing.T) {
	expected := expectedSections(t, "ios/reference-lab/expected.txt")
	ex, err := Extract("ios", capture(t, "ios/reference-lab/running-config.txt"), expected...)
	if err != nil {
		t.Fatal(err)
	}
	results, _ := CompareAll(expected, ex)
	rec := Record{Vendor: "cisco", Result: ResultOK, SecretsVisible: ex.SecretsVisible}
	if err := rec.SetSections(ex, results); err != nil {
		t.Fatal(err)
	}
	if rec.Sections[SectionAAA].State != "differs" || rec.Sections[SectionRoles].State != "ok" ||
		rec.Sections[SectionNetconf].State != "n/a" || len(rec.Sections[SectionAAA].SHA256) != 64 {
		t.Errorf("%+v", rec.Sections)
	}
	if got := Recorded(&rec); got != StaleDiffers {
		t.Errorf("%q", got)
	}
	for _, s := range []string{"ok", "n/a", "not visible"} {
		rec.Sections = map[string]SectionRecord{"aaa": {State: s}}
		if got := Recorded(&rec); got != StaleOK {
			t.Errorf("%s: %q", s, got)
		}
	}
	rec.Sections["x"] = SectionRecord{State: "missing"}
	if got := Recorded(&rec); got != StaleDiffers {
		t.Errorf("%q", got)
	}
	if Recorded(&Record{Vendor: "wti", Result: ResultUnsupported}) != StaleOK ||
		Recorded(&Record{Vendor: "cisco", Result: ResultUnsupported}) != StaleFailed ||
		Recorded(&Record{Result: ResultUnsupported}) != StaleFailed {
		t.Error("unsupported is ok for a WTI unit only")
	}
	if Recorded(nil) != StaleNever || Recorded(&Record{Result: ResultTimeout}) != StaleFailed {
		t.Error("Recorded")
	}
}

// A character a YAML reader rejects (DEL, the C1 controls, the non-characters)
// or that is a line break (NEL, U+2028, U+2029) in a device's text must not
// make the sections file unreadable or split a statement: it is shown as '?'
// and the file reads back with every statement in one piece.
func TestUnsafeCharactersDoNotBreakTheSectionsFile(t *testing.T) {
	bad := []string{"\x7f", "\u0085", "\u0090", "\u009f", " ", " ", "￾", "￿"}
	for _, tc := range []struct {
		vendor, raw string
		section     string
		line        string
	}{
		{"junos", "set system host-name x\nset snmp location \"Rack%s4\"\nset snmp contact \"NOC%s\"\n", SectionSNMP, "set snmp location"},
		{"ios", "version 15.2\nhostname x\nsnmp-server location Rack%s4\nsnmp-server contact NOC%s\nend\n", SectionSNMP, "snmp-server location"},
	} {
		for _, ch := range bad {
			raw := strings.ReplaceAll(tc.raw, "%s", ch)
			ex, err := Extract(tc.vendor, raw)
			if err != nil {
				t.Fatalf("%s %q: %v", tc.vendor, ch, err)
			}
			want := ex.Sections[tc.section].Lines
			if len(want) != 2 {
				t.Fatalf("%s %q: %d statements, %q", tc.vendor, ch, len(want), want)
			}
			for _, l := range want {
				for _, b := range bad {
					if strings.Contains(l, b) {
						t.Errorf("%s %q: statement %q keeps %q", tc.vendor, ch, l, b)
					}
				}
			}
			if !strings.Contains(want[0], "?") {
				t.Errorf("%s %q: the character is not shown: %q", tc.vendor, ch, want[0])
			}
			s := newStore(t)
			if err := s.SaveSections("sw", tc.vendor, ex.Sections); err != nil {
				t.Fatal(err)
			}
			got, err := s.Sections("sw", tc.vendor)
			if err != nil {
				t.Fatalf("%s %q: the file does not read back: %v", tc.vendor, ch, err)
			}
			if !slices.Equal(got[tc.section].Lines, want) {
				t.Errorf("%s %q: read back %q, want %q", tc.vendor, ch, got[tc.section].Lines, want)
			}
		}
	}
	// SaveSections is no weaker than Extract: lines handed in directly.
	s := newStore(t)
	secs := map[string]devices.Section{SectionSNMP: {Name: SectionSNMP, Lines: []string{"set snmp location \"a b\x7fc\u0085d\""}}}
	if err := s.SaveSections("direct", "junos", secs); err != nil {
		t.Fatal(err)
	}
	got, err := s.Sections("direct", "junos")
	if err != nil || len(got[SectionSNMP].Lines) != 1 {
		t.Fatalf("direct: %v %q", err, got[SectionSNMP].Lines)
	}
}
