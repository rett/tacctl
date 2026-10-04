package rendered

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/store"
)

var goldenDir = filepath.Join("..", "..", "tests", "fixtures", "golden")

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func check(t *testing.T, json, path string) (string, int) {
	t.Helper()
	w, err := Check(json, path)
	if err != nil {
		return "", 4
	}
	return w, CheckCode(w)
}

// Ported from tests/unit/render_tacacs.bats, "rendered.json bookkeeping".

func TestCheckUnrecordedOKDriftMissing(t *testing.T) {
	d := t.TempDir()
	json, out := filepath.Join(d, "state", "rendered.json"), filepath.Join(d, "rendered.yaml")
	write(t, out, "one\n")
	if w, c := check(t, json, out); w != Unrecorded || c != 3 {
		t.Fatalf("%s %d", w, c)
	}
	if err := Record(json, out); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(json); st.Mode().Perm() != 0o600 {
		t.Fatalf("rendered.json mode %v", st.Mode().Perm())
	}
	if w, c := check(t, json, out); w != OK || c != 0 {
		t.Fatalf("%s %d", w, c)
	}
	write(t, out, "one\ntwo\n")
	if w, c := check(t, json, out); w != Drift || c != 1 {
		t.Fatalf("%s %d", w, c)
	}
	if err := os.Remove(out); err != nil {
		t.Fatal(err)
	}
	if w, c := check(t, json, out); w != Missing || c != 2 {
		t.Fatalf("%s %d", w, c)
	}
}

func TestRecordAndForgetKeepOtherEntries(t *testing.T) {
	d := t.TempDir()
	json := filepath.Join(d, "rendered.json")
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	write(t, a, "one\n")
	write(t, b, "other\n")
	if err := Record(json, a); err != nil {
		t.Fatal(err)
	}
	if err := Record(json, b); err != nil {
		t.Fatal(err)
	}
	r, err := Load(json)
	if err != nil {
		t.Fatal(err)
	}
	sa, _ := FileSHA256(a)
	sb, _ := FileSHA256(b)
	if len(r) != 2 || r[a] != sa || r[b] != sb {
		t.Fatalf("records %v", r)
	}
	if err := Forget(json, a); err != nil {
		t.Fatal(err)
	}
	if w, _ := check(t, json, a); w != Unrecorded {
		t.Fatal(w)
	}
	if w, _ := check(t, json, b); w != OK {
		t.Fatal(w)
	}
	// Forgetting what is not recorded writes nothing; without a
	// rendered.json it creates none.
	st1, _ := os.Stat(json)
	if err := Forget(json, a); err != nil {
		t.Fatal(err)
	}
	if st2, _ := os.Stat(json); !os.SameFile(st1, st2) {
		t.Fatal("rendered.json rewritten")
	}
	other := filepath.Join(d, "none", "rendered.json")
	if err := Forget(other, a); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(other)); err == nil {
		t.Fatal("created")
	}
	// No temp files are left; the lock file is the store's.
	entries, _ := os.ReadDir(d)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, " ") != ".store.lock a b rendered.json" {
		t.Fatalf("dir holds %v", names)
	}
}

func TestRecordUsesTheAbsolutePath(t *testing.T) {
	d := t.TempDir()
	t.Chdir(d)
	write(t, "f", "x")
	if err := Record("rendered.json", "f"); err != nil {
		t.Fatal(err)
	}
	r, _ := Load("rendered.json")
	if _, ok := r[filepath.Join(d, "f")]; !ok || len(r) != 1 {
		t.Fatalf("records %v", r)
	}
	if w, _ := check(t, "rendered.json", "./f"); w != OK {
		t.Fatal(w)
	}
}

func TestCorruptRecordsAreAFailureNeverOK(t *testing.T) {
	d := t.TempDir()
	json, out := filepath.Join(d, "rendered.json"), filepath.Join(d, "f")
	write(t, out, "one\n")
	for text, want := range map[string]string{
		"{not json\n":         json + ": not valid JSON",
		"":                    json + ": not valid JSON",
		"\ufeff{}":            json + ": not valid JSON",
		"\xff\n":              json + ": not valid JSON",
		"[]\n":                json + ": not a path-to-sha256 mapping",
		`{"/x": 1}` + "\n":    json + ": not a path-to-sha256 mapping",
		`{"/x": null}` + "\n": json + ": not a path-to-sha256 mapping",
	} {
		write(t, json, text)
		_, err := Check(json, out)
		var re *Error
		if !errors.As(err, &re) || err.Error() != want {
			t.Fatalf("%q: %v", text, err)
		}
		if Report(err) != "tacctl render: "+want {
			t.Fatal(Report(err))
		}
		if w, c := check(t, json, out); w != "" || c != 4 {
			t.Fatalf("%q: %s %d", text, w, c)
		}
		// Recording refuses too, and leaves the file alone.
		if err := Record(json, out); err == nil {
			t.Fatal("recorded over corrupt records")
		}
	}
	// What Python's json and text-mode reading accept.
	write(t, json, "\r\n{ \"/x\" :\r\n \"a\", \"/x\": \"b\" }\r\n")
	if r, err := Load(json); err != nil || r["/x"] != "b" || len(r) != 1 {
		t.Fatalf("%v %v", r, err)
	}
	// A directory where the file should be is the file-system error.
	if err := os.Remove(json); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(json, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Load(json)
	var re *Error
	if err == nil || errors.As(err, &re) || Report(err) != "tacctl render: "+json+": Is a directory" {
		t.Fatalf("got %v (%s)", err, Report(err))
	}
}

func TestCheckDriftListsDriftedAndMissing(t *testing.T) {
	d := t.TempDir()
	json := filepath.Join(d, "rendered.json")
	a, b := filepath.Join(d, "a"), filepath.Join(d, "b")
	if got := CheckDrift(json); got != nil {
		t.Fatalf("before any render: %v", got)
	}
	write(t, a, "one\n")
	write(t, b, "other\n")
	_ = Record(json, a)
	_ = Record(json, b)
	if got := CheckDrift(json); got != nil {
		t.Fatalf("all ok: %v", got)
	}
	write(t, a, "one\nedit\n")
	_ = os.Remove(b)
	got := CheckDrift(json)
	if len(got) != 2 || got[0].Line() != "drift\t"+a || got[1].Line() != "missing\t"+b {
		t.Fatalf("got %v", got)
	}
	write(t, json, "{not json\n")
	got = CheckDrift(json)
	if len(got) != 1 || got[0].Line() != "unreadable\t"+json {
		t.Fatalf("got %v", got)
	}
	if _, err := ListDrift(json); err == nil {
		t.Fatal("ListDrift of corrupt records")
	}
	// A recorded path that cannot be read: what was listed before it
	// stands (0.1.16 printed it before failing).
	if err := os.Mkdir(filepath.Join(d, "zz"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, json, `{"`+a+`": "x", "`+filepath.Join(d, "zz")+`": "y"}`)
	got = CheckDrift(json)
	if len(got) != 1 || got[0].Line() != "drift\t"+a {
		t.Fatalf("got %v", got)
	}
}

// The file 0.1.16 writes for a set of records, byte for byte: the golden
// was written by json.dumps(indent=2, sort_keys=True) over the sums of
// the golden artifacts at their production paths.
func TestMarshalGolden(t *testing.T) {
	sum := func(name string) string {
		s, err := FileSHA256(filepath.Join(goldenDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	r := Records{
		"/etc/tacquito/tacquito.yaml":                             sum("tacquito.multiscope.rendered.yaml"),
		"/etc/systemd/system/tacquito.service.d/tacctl.conf":      sum("dropin.default-override.conf"),
		"/etc/systemd/system/tacquito@mgmt.service.d/tacctl.conf": sum("dropin.mgmt.conf"),
		"/etc/systemd/system/tacquito@alt6.service.d/tacctl.conf": sum("dropin.alt6.conf"),
		"/etc/freeradius/3.0/tacctl-radius.conf":                  sum("radius.debian.conf"),
		"/etc/freeradius/3.0/tacctl-radius.users":                 sum("radius.debian.users"),
		"/etc/freeradius/3.0/tacctl-radius-dictionary/dictionary": sum("radius.dictionary"),
	}
	want, err := os.ReadFile(filepath.Join(goldenDir, "rendered.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := Marshal(r); string(got) != string(want) {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	// And it reads back.
	d := t.TempDir()
	write(t, filepath.Join(d, "r.json"), string(want))
	back, err := Load(filepath.Join(d, "r.json"))
	if err != nil || len(back) != len(r) {
		t.Fatalf("%v %v", back, err)
	}
	for k, v := range r {
		if back[k] != v {
			t.Fatalf("%s", k)
		}
	}
}

func TestMarshalEscapesAsPython(t *testing.T) {
	// python3 -c 'print(json.dumps({...}, indent=2, sort_keys=True))'
	got := string(Marshal(Records{"/a\"b\\c\u00e9\U0001f511\x7f\n": "x", "/z": "y", "/A": ""}))
	want := "{\n  \"/A\": \"\",\n  \"/a\\\"b\\\\c\\u00e9\\ud83d\\udd11\\u007f\\n\": \"x\",\n  \"/z\": \"y\"\n}\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if string(Marshal(nil)) != "{}\n" {
		t.Fatal("empty")
	}
}

// The words of a live artifact against a fresh render (the drift matrix;
// the corpus of internal/render/tacacs checks the same against 0.1.16).
func TestLiveStatusMatrix(t *testing.T) {
	render := []byte("rendered\n")
	edited := "rendered\n# hand edit\n"
	for _, tc := range []struct {
		live    *string // nil: absent
		records string  // "": no rendered.json; "match", "live", "other", or the file text
		want    string
	}{
		{nil, "", Missing},
		{nil, "match", Missing},
		{nil, "{bad", Unreadable},
		{ptr("rendered\n"), "", Same},
		{ptr("rendered\n"), "match", Current},
		{ptr("rendered\n"), "other", Same},
		{ptr("rendered\n"), "{bad", Same},
		{ptr("rendered\n"), "[]", Same},
		{ptr(edited), "", Unrecorded},
		{ptr(edited), "match", Drift},
		{ptr(edited), "live", OK},
		{ptr(edited), "other", Drift},
		{ptr(edited), "{bad", Unreadable},
		{ptr(edited), `{"/x": 1}`, Unreadable},
	} {
		d := t.TempDir()
		json, live := filepath.Join(d, "rendered.json"), filepath.Join(d, "live")
		if tc.live != nil {
			write(t, live, *tc.live)
		}
		switch tc.records {
		case "":
		case "match":
			write(t, live+".tmp", string(render))
			s, _ := FileSHA256(live + ".tmp")
			write(t, json, string(Marshal(Records{live: s})))
		case "live":
			s, _ := FileSHA256(live)
			write(t, json, string(Marshal(Records{live: s})))
		case "other":
			write(t, json, string(Marshal(Records{live: "0000"})))
		default:
			write(t, json, tc.records)
		}
		got, err := LiveStatus(json, live, render)
		if err != nil || got != tc.want {
			t.Fatalf("%+v: got %s %v", tc, got, err)
		}
		records, err := LoadOrNil(json)
		if err != nil {
			t.Fatal(err)
		}
		if u, err := UnitStatus(records, live, render); err != nil || u != tc.want {
			t.Fatalf("%+v: UnitStatus %s %v", tc, u, err)
		}
	}
}

func ptr(s string) *string { return &s }

func TestFurthestAndCodes(t *testing.T) {
	for _, tc := range []struct {
		states []string
		want   string
	}{
		{[]string{Current}, Current},
		{[]string{Current, Same}, Same},
		{[]string{Same, OK, Current}, OK},
		{[]string{OK, Missing}, Missing},
		{[]string{Missing, Unrecorded}, Unrecorded},
		{[]string{Unrecorded, Drift, Current}, Drift},
		{[]string{Drift, Unreadable}, Unreadable},
	} {
		if got, ok := Furthest(tc.states); !ok || got != tc.want {
			t.Fatalf("%v: %s", tc.states, got)
		}
	}
	if _, ok := Furthest([]string{"bogus", ""}); ok {
		t.Fatal("bogus")
	}
	for w, c := range map[string]int{OK: 0, Drift: 1, Missing: 2, Unrecorded: 3, Unreadable: 4, "": 4, Current: 4} {
		if CheckCode(w) != c {
			t.Fatalf("%s", w)
		}
	}
}

func TestReport(t *testing.T) {
	if got := Report(&store.Error{Msg: "x: y"}); got != "tacctl render: x: y" {
		t.Fatal(got)
	}
	_, err := os.ReadFile("/nonexistent/tacctl-test")
	if got := Report(err); got != "tacctl render: /nonexistent/tacctl-test: No such file or directory" {
		t.Fatal(got)
	}
	if got := Report(errors.New("plain")); got != "plain" {
		t.Fatal(got)
	}
	if _, ok := OSErrorText(errors.New("x")); ok {
		t.Fatal("OSErrorText of a plain error")
	}
}
