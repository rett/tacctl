package yamlpy

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"
)

// splitHeader splits a tacctl-written file into its leading comment block
// (comment lines and the blank line after them: STORE_HEADER in
// lib/store.sh, the overrides header in lib/conf.sh) and the YAML PyYAML
// wrote after it.
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

// TestStoreFixtures re-emits the three store fixtures from their parsed
// form and compares with PyYAML's re-emit of the same fixture
// (testdata/fixtures, written by tests/tools/pyyaml-corpus.py). The
// fixture bodies are PyYAML output, so the result must also equal the
// fixture itself (after its header).
func TestStoreFixtures(t *testing.T) {
	for _, name := range []string{"minimal", "multiscope", "radius"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("../../tests/fixtures/store." + name + ".yaml")
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile("testdata/fixtures/store." + name + ".yaml")
			if err != nil {
				t.Fatal(err)
			}
			header, body := splitHeader(raw)
			v, err := Decode(raw)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			got, err := EmitChecked(v, StoreOptions, string(header))
			if err != nil {
				t.Fatalf("EmitChecked: %v", err)
			}
			got = got[len(header):]
			if !bytes.Equal(got, want) {
				t.Errorf("differs from PyYAML's re-emit of store.%s.yaml:\n%s", name, firstDiff(want, got))
			}
			if !bytes.Equal(got, body) {
				t.Errorf("differs from store.%s.yaml:\n%s", name, firstDiff(body, got))
			}
		})
	}
}

var (
	roundTripFile = flag.String("roundtrip", "", "a tacctl-written file to re-emit from its parsed form (TestRoundTripFile)")
	roundTripMode = flag.String("roundtrip.mode", "conf", "store or conf: the dump arguments of -roundtrip")
)

// TestRoundTripFile re-emits a real tacctl-written file from its parsed
// form and compares, header stripped. It runs only when -roundtrip is
// given, and reports line numbers only, never content (the file may hold
// settings, hashes or secrets). For a root-owned file without a copy:
//
//	go test -c -o dist/yamlpy.test ./internal/yamlpy
//	sudo cat /etc/tacctl/tacctl.yaml | dist/yamlpy.test -test.run TestRoundTripFile -roundtrip /dev/stdin
func TestRoundTripFile(t *testing.T) {
	if *roundTripFile == "" {
		t.Skip("no -roundtrip file given")
	}
	opts := ConfOptions
	switch *roundTripMode {
	case "store":
		opts = StoreOptions
	case "conf":
	default:
		t.Fatalf("-roundtrip.mode %q: want store or conf", *roundTripMode)
	}
	raw, err := os.ReadFile(*roundTripFile)
	if err != nil {
		t.Fatal(err)
	}
	_, body := splitHeader(raw)
	v, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got, err := EmitChecked(v, opts, "")
	if err != nil {
		t.Fatalf("EmitChecked: %v", err)
	}
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
