package yamlpy

import (
	"bytes"
	"os"
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
			got, err := EmitChecked(v, StoreOptions, string(header), Decode)
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
