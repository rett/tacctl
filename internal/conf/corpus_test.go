package conf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/ui"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The corpora in testdata/ are tacctl 0.1.16's own answers (testdata/gen.py
// runs the tag's Python and bash); every case must agree.

// TestParseCorpus: what load_overrides makes of 2000 documents (the
// problem line, a Python crash, the value, or YAML tacctl does not
// represent).
func TestParseCorpus(t *testing.T) {
	type rec struct {
		YAML        *string         `json:"yaml"`
		YAMLHex     string          `json:"yaml_hex"`
		Why         string          `json:"why"`
		Crash       string          `json:"crash"`
		Value       json.RawMessage `json:"value"`
		Unsupported string          `json:"unsupported"`
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	n := forEachRecord(t, "parse.jsonl", func(line int, r rec) {
		var data []byte
		if r.YAML != nil {
			data = []byte(*r.YAML)
		} else {
			var err error
			if data, err = hex.DecodeString(r.YAMLHex); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		m, why := ReadOverrides(path)
		why = strings.ReplaceAll(why, path, "@FILE@")
		switch {
		case r.Crash != "":
			var ve *pyyaml.ValueError
			if _, err := pyyaml.Load(data, path); !errors.As(err, &ve) {
				t.Errorf("parse.jsonl:%d %q: Python raised %s, Go: %v", line, data, r.Crash, err)
			}
		case r.Unsupported != "":
			var ue *pyyaml.UnsupportedError
			if _, err := pyyaml.Load(data, path); !errors.As(err, &ue) {
				t.Errorf("parse.jsonl:%d %q: 0.1.16 reads it (%s), Go should refuse it: %v", line, data, r.Unsupported, err)
			}
		case why != r.Why:
			t.Errorf("parse.jsonl:%d %q:\n got: %s\nwant: %s", line, data, why, r.Why)
		case r.Value != nil:
			if want := fromJSON(t, r.Value); !yamlpy.Equal(m, want) {
				t.Errorf("parse.jsonl:%d %q: value %s, want %s", line, data, py.Repr(m), py.Repr(want))
			}
		default:
			if m.Len() != 0 {
				t.Errorf("parse.jsonl:%d %q: want an empty mapping, got %s", line, data, py.Repr(m))
			}
		}
	})
	if n < 2000 {
		t.Fatalf("parse.jsonl has %d cases", n)
	}
}

// TestValidateCorpus: validate(path, value, is_list) for every schema path
// (and some that are not) against many values; listener_compact and
// implicit_default for the listener values the schema accepts.
func TestValidateCorpus(t *testing.T) {
	type rec struct {
		Path     string          `json:"path"`
		Value    json.RawMessage `json:"value"`
		IsList   bool            `json:"is_list"`
		Msg      string          `json:"msg"`
		Compact  json.RawMessage `json:"compact"`
		Implicit json.RawMessage `json:"implicit"`
	}
	s := NewSchema(DefaultBackends)
	forEachRecord(t, "validate.jsonl", func(line int, r rec) {
		v := fromJSON(t, r.Value)
		if got := s.Validate(r.Path, v, r.IsList); got != r.Msg {
			t.Errorf("validate.jsonl:%d validate(%q, %s, %v):\n got: %q\nwant: %q", line, r.Path, r.Value, r.IsList, got, r.Msg)
		}
		if r.Compact != nil {
			backend := strings.Split(r.Path, ".")[1]
			if got, want := ListenerCompact(backend, v), fromJSON(t, r.Compact); !py.Equal(got, want) || py.Repr(got) != py.Repr(want) {
				t.Errorf("validate.jsonl:%d listener_compact(%s) = %s, want %s", line, r.Value, py.Repr(got), py.Repr(want))
			}
			got, _ := s.ImplicitDefault(r.Path)
			if want := fromJSON(t, r.Implicit); !py.Equal(got, want) {
				t.Errorf("validate.jsonl:%d implicit_default(%s) = %s, want %s", line, r.Path, py.Repr(got), py.Repr(want))
			}
		}
	})
}

// TestCoerceCorpus: coerce_scalar of command-line words.
func TestCoerceCorpus(t *testing.T) {
	type rec struct {
		In   string `json:"in"`
		Type string `json:"type"`
		Repr string `json:"repr"`
	}
	forEachRecord(t, "coerce.jsonl", func(line int, r rec) {
		v := CoerceScalar(r.In)
		if py.TypeName(v) != r.Type || py.Repr(v) != r.Repr {
			t.Errorf("coerce.jsonl:%d coerce_scalar(%q) = %s %s, want %s %s", line, r.In, py.TypeName(v), py.Repr(v), r.Type, r.Repr)
		}
	})
}

func listenerJSON(l Listener) *yamlpy.Map {
	return yamlpy.NewMap("network", l.Network, "address", l.Address, "role", l.Role,
		"metrics_address", l.MetricsAddress, "tls", yamlpy.NewMap(
			"enabled", l.TLS.Enabled, "cert", l.TLS.Cert, "key", l.TLS.Key, "ca", l.TLS.CA,
			"require_client_cert", l.TLS.RequireClientCert), "name", l.Name)
}

// TestListenersCorpus: listeners_effective and listeners_problems (whole
// document and per listener) of 300 documents.
func TestListenersCorpus(t *testing.T) {
	type rec struct {
		Doc       json.RawMessage            `json:"doc"`
		Effective map[string]json.RawMessage `json:"effective"`
		Problems  []string                   `json:"problems"`
		Only      map[string][]string        `json:"only"`
	}
	forEachRecord(t, "listeners.jsonl", func(line int, r rec) {
		doc := fromJSON(t, r.Doc)
		if got := ListenersProblems(doc, "", false); strings.Join(got, "\n") != strings.Join(r.Problems, "\n") {
			t.Errorf("listeners.jsonl:%d problems of %s:\n got: %q\nwant: %q", line, r.Doc, got, r.Problems)
		}
		for path, want := range r.Only {
			if got := ListenersProblems(doc, path, true); strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("listeners.jsonl:%d problems of %s only %s:\n got: %q\nwant: %q", line, r.Doc, path, got, want)
			}
		}
		for backend, raw := range r.Effective {
			want := fromJSON(t, raw).([]any)
			got := ListenersEffective(doc, backend)
			gotList := make([]any, len(got))
			for i, l := range got {
				gotList[i] = listenerJSON(l)
			}
			if !py.Equal(gotList, want) {
				t.Errorf("listeners.jsonl:%d effective %s of %s:\n got: %s\nwant: %s", line, backend, r.Doc, py.Repr(gotList), py.Repr(want))
			}
		}
	})
}

type bashRecord struct {
	Before    *string             `json:"before"`
	Ops       [][]json.RawMessage `json:"ops"`
	SourceErr string              `json:"source_err"`
	Results   []bashResult        `json:"results"`
	After     *string             `json:"after"`
}

type bashResult struct {
	RC  int    `json:"rc"`
	Out string `json:"out"`
	Err string `json:"err"`
}

func opArg(t *testing.T, op []json.RawMessage, i int) any {
	t.Helper()
	if i >= len(op) {
		return nil
	}
	var s string
	if err := json.Unmarshal(op[i], &s); err == nil {
		return s
	}
	var l []string
	if err := json.Unmarshal(op[i], &l); err != nil {
		t.Fatal(err)
	}
	return l
}

// runOp does what one op of testdata/gen.py's bash script does, printing
// as the bash prints.
func runOp(t *testing.T, c *Config, tun Tunables, op []json.RawMessage) bashResult {
	t.Helper()
	var kind string
	if err := json.Unmarshal(op[0], &kind); err != nil {
		t.Fatal(err)
	}
	str := func(i int) string { s, _ := opArg(t, op, i).(string); return s }
	var r bashResult
	var out, errOut bytes.Buffer
	write := func(err error) {
		if err == nil {
			return
		}
		r.RC = 1
		var ve *ValidationError
		var pe *ParseError
		switch {
		case errors.As(err, &ve):
			errOut.WriteString(ve.Error() + "\n")
		case errors.As(err, &pe):
			ui.Output{Stdout: &out, Stderr: &errOut}.ErrorLines(pe)
		default:
			t.Fatalf("%s: unexpected error %v", kind, err)
		}
	}
	switch kind {
	case "set":
		write(c.Set(str(1), str(2)))
	case "set_json":
		write(c.SetJSON(str(1), str(2)))
	case "set_list":
		items, _ := opArg(t, op, 2).([]string)
		text := strings.Join(items, "\n")
		if len(items) > 0 {
			text += "\n"
		}
		write(c.SetList(str(1), ListItems(text)))
	case "set_raw_list":
		write(c.SetList(str(1), ListItems(str(2))))
	case "unset":
		write(c.Unset(str(1)))
	case "get":
		if text, ok := c.Get(str(1), str(2)); ok {
			out.WriteString(text + "\n")
		}
	case "get_list":
		for _, l := range c.GetList(str(1)) {
			out.WriteString(l + "\n")
		}
	case "get_keys":
		for _, l := range c.GetKeys(str(1)) {
			out.WriteString(l + "\n")
		}
	case "get_json":
		s, err := c.GetJSON(str(1))
		if err != nil {
			t.Fatal(err)
		}
		out.WriteString(s + "\n")
	case "has_override":
		if !c.HasOverride(str(1)) {
			r.RC = 1
		}
	case "validate":
		for _, l := range c.Schema.ValidateFile(c.Path) {
			out.WriteString(l + "\n")
		}
	case "dump":
		if err := c.Dump(&out); err != nil {
			t.Fatal(err)
		}
	case "tunables":
		fmt.Fprintf(&out, "%d %d %d %d", tun.PasswordMaxAgeDays, tun.BcryptCost, tun.PasswordMinLength, tun.SecretMinLength)
	default:
		t.Fatalf("unknown op %q", kind)
	}
	r.Out = strings.ReplaceAll(out.String(), c.Path, "@FILE@")
	r.Err = strings.ReplaceAll(errOut.String(), c.Path, "@FILE@")
	return r
}

// reInvalidRegex is the one message known to differ from 0.1.16: a
// command rule's match regex is compiled by Go's regexp (RE2, as tacquito
// does), not Python's re, so the reason in "invalid regex (<reason>)" is
// worded differently (proposed docs/plans/go-rewrite.md 3.9 item).
var reInvalidRegex = regexp.MustCompile(`invalid regex \(.*\)`)

func knownDeviation(s string) string {
	return reInvalidRegex.ReplaceAllString(s, "invalid regex (...)")
}

// replay loads a Config on before and runs ops, comparing with what the
// bash did when results is not nil; it returns the file left behind.
func replay(t *testing.T, name string, before *string, ops [][]json.RawMessage, sourceErr *string, results []bashResult) *string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tacctl.yaml")
	if before != nil {
		writeFile(t, path, *before)
	}
	c := Load(path, DefaultBackends)
	c.Owner = nil
	var warn bytes.Buffer
	c.WarnOnce(&warn)
	c.WarnOnce(&warn)
	if sourceErr != nil {
		if got := strings.ReplaceAll(warn.String(), path, "@FILE@"); got != *sourceErr {
			t.Errorf("%s: start-up stderr:\n got: %q\nwant: %q", name, got, *sourceErr)
		}
	}
	tun := c.Tunables()
	for i, op := range ops {
		got := runOp(t, c, tun, op)
		if results != nil {
			got.Out, results[i].Out = knownDeviation(got.Out), knownDeviation(results[i].Out)
		}
		if results != nil && got != results[i] {
			t.Errorf("%s op %d %s:\n got: %+v\nwant: %+v", name, i, op, got, results[i])
		}
	}
	if !exists(path) {
		return nil
	}
	s := readFile(t, path)
	return &s
}

// TestBashCorpus: the 0.1.16 functions run end to end on a file: output,
// exit status, the start-up warning, the tunables and the file left.
func TestBashCorpus(t *testing.T) {
	forEachRecord(t, "bash.jsonl", func(line int, r bashRecord) {
		name := fmt.Sprintf("bash.jsonl:%d", line)
		after := replay(t, name, r.Before, r.Ops, &r.SourceErr, r.Results)
		switch {
		case (after == nil) != (r.After == nil):
			t.Errorf("%s: file left: %v, want %v", name, after != nil, r.After != nil)
		case after != nil && *after != *r.After:
			t.Errorf("%s: file left:\n%s\nwant:\n%s", name, *after, *r.After)
		}
	})
}

// TestGolden: the writes of testdata/golden-ops.json (every schema key
// once) leave tests/fixtures/golden/tacctl.overrides.yaml, the file 0.1.16
// leaves; without its header it is PyYAML's safe_dump of the same value
// (testdata/pyyaml, made by tests/tools/pyyaml-corpus.py) and reads back
// as that value.
func TestGolden(t *testing.T) {
	var ops [][]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, "testdata/golden-ops.json")), &ops); err != nil {
		t.Fatal(err)
	}
	got := replay(t, "golden", nil, ops, nil, nil)
	if got == nil {
		t.Fatal("no file written")
	}
	want := readFile(t, "../../tests/fixtures/golden/tacctl.overrides.yaml")
	if *got != want {
		t.Errorf("golden differs:\n%s\nwant:\n%s", *got, want)
	}
	body, ok := strings.CutPrefix(*got, Header)
	if !ok {
		t.Fatal("no header")
	}
	if pyBytes := readFile(t, "testdata/pyyaml/every-key.conf.yaml"); body != pyBytes {
		t.Errorf("not PyYAML's bytes:\n%s\nwant:\n%s", body, pyBytes)
	}
	value := fromJSON(t, json.RawMessage(readFile(t, "testdata/pyyaml/every-key.json")))
	back, err := pyyaml.Load([]byte(*got), "golden")
	if err != nil || !yamlpy.Equal(back, value) {
		t.Errorf("golden does not read back as every-key.json: %v", err)
	}
	// Every schema path is in it.
	s := NewSchema(DefaultBackends)
	m := back.(*yamlpy.Map)
	for _, k := range s.Keys() {
		if _, ok := walk(m, k, false); !ok {
			t.Errorf("golden lacks %s", k)
		}
	}
	for _, prefix := range s.Wildcards() {
		v, ok := walk(m, strings.TrimSuffix(prefix, "."), false)
		if sub, isMap := v.(*yamlpy.Map); !ok || !isMap || sub.Len() == 0 {
			t.Errorf("golden lacks a %s<name> key", prefix)
		}
	}
}
