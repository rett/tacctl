package store_test

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// loadRun is one command of testdata/load/expected.jsonl (gen.py).
type loadRun struct {
	RC       int     `json:"rc"`
	Stdout   string  `json:"stdout"`
	Stderr   *string `json:"stderr"`
	Crash    string  `json:"crash"`
	NotFound bool    `json:"not_found"`
}

type loadCase struct {
	Name       string  `json:"name"`
	YAML       *string `json:"yaml"`
	YAMLHex    string  `json:"yaml_hex"`
	Fixture    string  `json:"fixture"`
	Kind       string  `json:"kind"`
	Unreadable bool    `json:"unreadable"`
	Dump       loadRun `json:"dump"`
	Validate   loadRun `json:"validate"`
}

// goWorded are the cases tacctl words itself on purpose: 0.1.16 died with
// a Python traceback (plan 3.9 item 16), or read YAML that tacctl refuses
// (item 15). Both 'dump-store' and 'validate' report the message after
// "tacctl store: FILE: ", with status 1.
var goWorded = map[string]struct {
	item int
	msg  string
}{
	"not-utf8":           {16, "'utf-8' codec can't decode byte 0xe9 in position 20: invalid continuation byte"},
	"not-utf8-late":      {16, "'utf-8' codec can't decode byte 0xff in position 828: invalid start byte"},
	"bad-int":            {16, "line 1, column 10: invalid literal for int() with base 10: (value not shown)"},
	"bad-bool":           {16, "line 2, column 27: (value not shown) is not a boolean"},
	"bad-float":          {16, "line 1, column 10: could not convert string to float: (value not shown)"},
	"impossible-date":    {16, "line 7, column 86: day is out of range for month"},
	"bad-unicode-escape": {16, "line 2, column 10: chr() arg not in range(0x110000): \\UFFFFFFFF"},
	"alias":              {15, "line 4, column 9: an alias is not supported in this file"},
	"merge-key":          {15, "line 4, column 10: a merge key ('<<') is not supported in this file"},
	"merge-key-only":     {15, "line 4, column 3: a merge key ('<<') is not supported in this file"},
	"int-key":            {15, "line 3, column 3: a key that is not a string is not supported in this file"},
	"bool-key":           {15, "line 2, column 11: a key that is not a string is not supported in this file"},
	"set":                {15, "line 2, column 8: a set (!!set) is not supported in this file"},
	"omap":               {15, "line 2, column 8: an ordered map (!!omap) is not supported in this file"},
	"pairs":              {15, "line 2, column 8: an ordered map (!!pairs) is not supported in this file"},
	"binary":             {15, "line 2, column 24: binary data (!!binary) is not supported in this file"},
	"datetime":           {15, "line 7, column 86: a timestamp with a time of day is not supported in this file"},
	"big-int":            {15, "line 3, column 44: an integer beyond 64 bits is not supported in this file"},
}

// TestLoadErrorsAs0116 replays testdata/load/expected.jsonl, 0.1.16's
// 'dump-store' and 'validate' of each file (gen.sh): the same model JSON
// for a file that loads, and the same message for one that does not
// (yaml_problem's '<path>: <problem> (line L, column C)', a top level that
// is not a mapping, an unreadable file), except for the goWorded cases.
func TestLoadErrorsAs0116(t *testing.T) {
	f, err := os.Open("testdata/load/expected.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	n, worded := 0, 0
	for sc.Scan() {
		n++
		var c loadCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		t.Run(c.Name, func(t *testing.T) {
			if c.Unreadable && os.Geteuid() == 0 {
				t.Skip("root reads a mode-000 file")
			}
			path := placeLoadCase(t, c)
			dump, validate := goLoadRuns(path)
			if w, ok := goWorded[c.Name]; ok {
				worded++
				checkWorded(t, c, w.item)
				want := "tacctl store: FILE: " + w.msg + "\n"
				if dump.RC != 1 || *dump.Stderr != want || dump.Stdout != "" {
					t.Errorf("dump-store: rc=%d %q, want %q", dump.RC, *dump.Stderr, want)
				}
				if validate.RC != 1 || *validate.Stderr != want {
					t.Errorf("validate: rc=%d %q, want %q", validate.RC, *validate.Stderr, want)
				}
				return
			}
			compareRun(t, "dump-store", dump, c.Dump)
			compareRun(t, "validate", validate, c.Validate)
		})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 50 || worded != len(goWorded) {
		t.Fatalf("%d cases, %d of the %d Go-worded ones", n, worded, len(goWorded))
	}
}

// checkWorded asserts that a goWorded case is what its plan item says:
// 0.1.16 died on it (16), or read it (15: its validate got past the load).
func checkWorded(t *testing.T, c loadCase, item int) {
	t.Helper()
	switch item {
	case 16:
		if c.Dump.Crash == "" || c.Validate.Crash == "" {
			t.Errorf("0.1.16 did not crash on it: %+v", c.Dump)
		}
	case 15:
		if c.Validate.Crash != "" || c.Validate.Stderr == nil || strings.Contains(*c.Validate.Stderr, "FILE") {
			t.Errorf("0.1.16 did not read it: %+v", c.Validate)
		}
	}
}

func compareRun(t *testing.T, what string, got, want loadRun) {
	t.Helper()
	if want.Crash != "" {
		t.Fatalf("%s: 0.1.16 crashed (%s), and the case is not in goWorded", what, want.Crash)
	}
	if got.NotFound || want.NotFound {
		if got.NotFound != want.NotFound {
			t.Errorf("%s: not found %v, want %v", what, got.NotFound, want.NotFound)
		}
		return
	}
	if got.RC != want.RC || *got.Stderr != *want.Stderr || got.Stdout != want.Stdout {
		t.Errorf("%s:\n got: rc=%d stderr=%q stdout=%q\nwant: rc=%d stderr=%q stdout=%q",
			what, got.RC, *got.Stderr, got.Stdout, want.RC, *want.Stderr, want.Stdout)
	}
}

// placeLoadCase writes the case's file (or directory, or nothing) and
// returns its path.
func placeLoadCase(t *testing.T, c loadCase) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.yaml")
	var data []byte
	switch {
	case c.Kind == "missing":
		return path
	case c.Kind == "directory":
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	case c.Fixture != "":
		data = readFile(t, fixtures+c.Fixture)
	case c.YAMLHex != "":
		var err error
		if data, err = hex.DecodeString(c.YAMLHex); err != nil {
			t.Fatal(err)
		}
	case c.YAML != nil:
		data = []byte(*c.YAML)
	default:
		t.Fatal("no content")
	}
	mode := os.FileMode(0o600)
	if c.Unreadable {
		mode = 0
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// goLoadRuns is what 'dump-store <path>' (store.Load and the model JSON)
// and 'validate <path>' (store_validate: store.ValidateFile) print, with
// the path written as FILE.
func goLoadRuns(path string) (dump, validate loadRun) {
	hide := func(s string) *string {
		s = strings.ReplaceAll(s, path, "FILE")
		return &s
	}
	if s, err := store.Load(path); err != nil {
		dump = loadRun{RC: 1, Stderr: hide(store.Report(err) + "\n")}
	} else if js, err := model.StoreJSON(s); err != nil {
		dump = loadRun{RC: 1, Stderr: hide(err.Error() + "\n")}
	} else {
		dump = loadRun{Stdout: js + "\n", Stderr: hide("")}
	}
	errs, err := store.ValidateFile(path)
	var nf *store.NotFoundError
	switch {
	case errors.As(err, &nf):
		validate = loadRun{NotFound: true}
	case err != nil:
		validate = loadRun{RC: 1, Stderr: hide(store.Report(err) + "\n")}
	default:
		var b strings.Builder
		for _, m := range errs {
			b.WriteString("tacctl store: " + m + "\n")
		}
		validate = loadRun{Stderr: hide(b.String())}
		if len(errs) > 0 {
			validate.RC = 1
		}
	}
	return dump, validate
}

// storeFixtureFiles are the store.yaml files the tests use: the three
// shared fixtures and the hand-edited ones of internal/model and the
// importer.
func storeFixtureFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pat := range []string{
		fixtures + "store.*.yaml",
		"../model/testdata/store.*.yaml",
		"testdata/import/existing/*.yaml",
	} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 9 {
		t.Fatalf("only %d store fixtures: %v", len(files), files)
	}
	return files
}

// TestFixturesLoadAsBefore: every store fixture reads the same through the
// store's reader (LoadRaw, the PyYAML port) as through the yaml.v3 path it
// replaced (yamlpy.Decode), and normalises to the same model JSON.
func TestFixturesLoadAsBefore(t *testing.T) {
	for _, p := range storeFixtureFiles(t) {
		t.Run(filepath.Base(filepath.Dir(p))+"/"+filepath.Base(p), func(t *testing.T) {
			got, err := store.LoadRaw(p)
			old, oldErr := yamlpy.Decode(readFile(t, p))
			if err != nil || oldErr != nil {
				// testdata/import/existing/broken.yaml does not parse.
				if err == nil || oldErr == nil {
					t.Fatalf("only one reader refuses it: %v | %v", err, oldErr)
				}
				return
			}
			if !yamlpy.Equal(got, old) {
				t.Fatal("the port and yamlpy.Decode read different values")
			}
			sGot, errGot := store.Normalize(got)
			sOld, errOld := store.Normalize(old)
			if (errGot == nil) != (errOld == nil) {
				t.Fatalf("Normalize: %v vs %v", errGot, errOld)
			}
			if errGot != nil {
				return
			}
			jGot, _ := model.StoreJSON(sGot)
			jOld, _ := model.StoreJSON(sOld)
			if jGot != jOld {
				t.Errorf("model JSON differs:\n%s\n%s", jGot, jOld)
			}
		})
	}
}
