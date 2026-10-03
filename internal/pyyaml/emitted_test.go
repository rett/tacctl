package pyyaml

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/yamlpy"
)

// emittedFiles are the YAML files internal/yamlpy's writer is checked
// against (PyYAML 6.0.1's output for the corpus, the store fixtures and
// tacctl.yaml's golden): what this reader must read back.
func emittedFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, pat := range []string{
		"../yamlpy/testdata/corpus/*.yaml",
		"../yamlpy/testdata/fixtures/*.yaml",
		"../yamlpy/testdata/decode/*.yaml",
		"../conf/testdata/pyyaml/*.yaml",
		"../../tests/fixtures/store.*.yaml",
		"../../tests/fixtures/golden/tacctl.overrides.yaml",
	} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 150 {
		t.Fatalf("only %d files", len(files))
	}
	return files
}

// TestReadsWhatYamlpyWrites: every file of the writer's corpus reads back
// through LoadBytes as the same value yamlpy.Decode (yaml.v3, the reader
// it replaces for tacctl's own files) gives, and the writer's output
// re-emits through yamlpy.EmitChecked with LoadBytes as the self-check
// reader.
func TestReadsWhatYamlpyWrites(t *testing.T) {
	for _, f := range emittedFiles(t) {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		got, err := LoadBytes(data)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		want, err := yamlpy.Decode(data)
		if err != nil {
			t.Errorf("%s: yamlpy.Decode: %v", f, err)
			continue
		}
		if !yamlpy.Equal(got, want) {
			t.Errorf("%s: LoadBytes and yamlpy.Decode differ", f)
			continue
		}
		if strings.Contains(f, "/decode/") {
			continue // reader input, not writer output (a literal block's final newline)
		}
		opts := yamlpy.ConfOptions
		if strings.Contains(f, ".store.") || strings.Contains(filepath.Base(f), "store.") {
			opts = yamlpy.StoreOptions
		}
		if _, err := yamlpy.EmitChecked(got, opts, "", LoadBytes); err != nil {
			t.Errorf("%s: EmitChecked: %v", f, err)
		}
	}
}

func TestLoadBytesSelfCheck(t *testing.T) {
	m := yamlpy.NewMap("a", 1, "when", yamlpy.Date{Year: 2026, Month: 10, Day: 1}, "s", "2026-10-01")
	got, err := yamlpy.EmitChecked(m, yamlpy.ConfOptions, "# h\n\n", LoadBytes)
	if err != nil || string(got) != "# h\n\na: 1\nwhen: 2026-10-01\ns: '2026-10-01'\n" {
		t.Errorf("EmitChecked = %q, %v", got, err)
	}
	// A header that is not YAML comments breaks the read-back.
	for _, header := range []string{"b: 2\n", "[\n", "x: &a 1\n"} {
		if _, err := yamlpy.EmitChecked(m, yamlpy.ConfOptions, header, LoadBytes); !errors.Is(err, yamlpy.ErrSelfCheck) {
			t.Errorf("header %q: err = %v, want ErrSelfCheck", header, err)
		}
	}
	if v, err := LoadBytes([]byte("a: [1, x]\n")); err != nil || !yamlpy.Equal(v, yamlpy.NewMap("a", []any{1, "x"})) {
		t.Errorf("LoadBytes = %v, %v", v, err)
	}
}

// YAMLProblem is yaml_problem's text after the path (lib/store.sh).
func TestYAMLProblem(t *testing.T) {
	for in, want := range map[string]string{
		"a: [1\n":       "expected ',' or ']', but got '<stream end>' (line 2, column 1)",
		"a: 1\n---\nb:": "but found another document (line 2, column 1)",
		"a: \x01\n":     "invalid YAML",
		"a: \"x\\q\"\n": "found unknown escape character 'q' (line 1, column 7)",
	} {
		_, err := Load([]byte(in), "F")
		var e *Error
		if !errors.As(err, &e) || e.YAMLProblem() != want {
			t.Errorf("Load(%q) = %v, want %q", in, err, want)
		}
	}
}

var (
	roundTripFile = flag.String("roundtrip", "", "a tacctl-written file to re-emit from its parsed form (TestRoundTripFile)")
	roundTripMode = flag.String("roundtrip.mode", "conf", "store or conf: the dump arguments of -roundtrip")
)

// TestRoundTripFile reads a real tacctl-written file as tacctl does (this
// package), re-emits it with the self-check and compares, header
// stripped. It runs only when -roundtrip is given, and reports line
// numbers only, never content (the file may hold settings, hashes or
// secrets). For a root-owned file without a copy:
//
//	go test -c -o dist/pyyaml.test ./internal/pyyaml
//	sudo cat /etc/tacctl/store.yaml | dist/pyyaml.test -test.run TestRoundTripFile -roundtrip /dev/stdin -roundtrip.mode store
func TestRoundTripFile(t *testing.T) {
	if *roundTripFile == "" {
		t.Skip("no -roundtrip file given")
	}
	opts := yamlpy.ConfOptions
	switch *roundTripMode {
	case "store":
		opts = yamlpy.StoreOptions
	case "conf":
	default:
		t.Fatalf("-roundtrip.mode %q: want store or conf", *roundTripMode)
	}
	raw, err := os.ReadFile(*roundTripFile)
	if err != nil {
		t.Fatal(err)
	}
	header, body := splitHeader(raw)
	v, err := Load(raw, *roundTripFile)
	if err != nil {
		// The kind only: a reason may quote a value.
		t.Fatalf("Load failed: %T", err)
	}
	got, err := yamlpy.EmitChecked(v, opts, string(header), LoadBytes)
	if err != nil {
		t.Fatalf("EmitChecked failed (self-check: %v)", errors.Is(err, yamlpy.ErrSelfCheck))
	}
	got = got[len(header):]
	if bytes.Equal(got, body) {
		t.Logf("identical: %d lines", bytes.Count(body, []byte("\n")))
		return
	}
	wl := strings.Split(string(body), "\n")
	gl := strings.Split(string(got), "\n")
	var differ []int
	for i := 0; i < max(len(wl), len(gl)); i++ {
		if i >= len(wl) || i >= len(gl) || wl[i] != gl[i] {
			differ = append(differ, i+1)
		}
	}
	t.Errorf("differs: %d of %d lines (line numbers after the header): %v", len(differ), len(wl), differ[:min(len(differ), 40)])
}

// splitHeader splits a tacctl-written file into its leading comment block
// (comment lines and the blank line after them) and the YAML after it.
func splitHeader(raw []byte) (header, body []byte) {
	rest := raw
	for bytes.HasPrefix(rest, []byte("#")) {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			return raw, nil
		}
		rest = rest[i+1:]
	}
	rest = bytes.TrimPrefix(rest, []byte("\n"))
	return raw[:len(raw)-len(rest)], rest
}
