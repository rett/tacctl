//go:build roundtrip

package pyyaml

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/yamlpy"
)

var (
	roundTripFile = flag.String("roundtrip", "", "a tacctl-written file to re-emit from its parsed form (TestRoundTripFile)")
	roundTripMode = flag.String("roundtrip.mode", "conf", "store or conf: the dump arguments of -roundtrip")
)

// TestRoundTripFile reads a real tacctl-written file as tacctl does (this
// package), re-emits it with the self-check and compares, header
// stripped. It runs only when -roundtrip is given, and reports line
// numbers only, never content (the file may hold settings, hashes or
// secrets). It is a tool, not part of the suite: the file is compiled only
// with -tags roundtrip. For a root-owned file without a copy:
//
//	go test -c -tags roundtrip -o dist/pyyaml.test ./internal/pyyaml
//	sudo cat /etc/tacctl/store.yaml | dist/pyyaml.test -test.run TestRoundTripFile -roundtrip /dev/stdin -roundtrip.mode store
func TestRoundTripFile(t *testing.T) {
	if *roundTripFile == "" {
		t.Fatal("no -roundtrip file given")
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
