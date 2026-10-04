package pyyaml

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The 2000 documents of ../conf/testdata/parse.jsonl are checked through
// conf.ReadOverrides (internal/conf); here, the error classes Load returns
// for them, and the cases that need the error values themselves.

func TestParseCorpusErrorClasses(t *testing.T) {
	f, err := os.Open("../conf/testdata/parse.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	n := 0
	for sc.Scan() {
		n++
		var rec struct {
			YAML        *string `json:"yaml"`
			YAMLHex     string  `json:"yaml_hex"`
			Why         string  `json:"why"`
			Crash       string  `json:"crash"`
			Unsupported string  `json:"unsupported"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		var data []byte
		if rec.YAML != nil {
			data = []byte(*rec.YAML)
		} else {
			data, _ = hex.DecodeString(rec.YAMLHex)
		}
		v, err := Load(data, "@FILE@")
		var e *Error
		var de *DecodeError
		var ve *ValueError
		var ue *UnsupportedError
		switch {
		case rec.Crash != "":
			if !errors.As(err, &ve) {
				t.Errorf("line %d: want a ValueError, got %v", n, err)
			}
		case rec.Unsupported != "":
			if !errors.As(err, &ue) {
				t.Errorf("line %d: want an UnsupportedError, got %v", n, err)
			}
		case strings.HasPrefix(rec.Why, "the top level is a "):
			name := py.TypeName(v)
			if u, ok := v.(Unrepresentable); ok {
				name = u.TypeName
			}
			if err != nil || "the top level is a "+name+", not a mapping" != rec.Why {
				t.Errorf("line %d: %v %s, want %s", n, err, name, rec.Why)
			}
		case strings.HasPrefix(rec.Why, "'utf-8' codec"):
			if !errors.As(err, &de) || de.Why() != rec.Why {
				t.Errorf("line %d: %v, want %s", n, err, rec.Why)
			}
		case rec.Why != "":
			if !errors.As(err, &e) || e.Why() != rec.Why {
				t.Errorf("line %d: %v, want %s", n, err, rec.Why)
			}
		default:
			if err != nil {
				t.Errorf("line %d: %v", n, err)
			}
		}
	}
	if n != 2000 {
		t.Fatalf("%d cases", n)
	}
}

// Error() is str(e) for a file stream (no snippets), as PyYAML prints it.
func TestErrorStrings(t *testing.T) {
	for in, want := range map[string]string{
		"a: \"abc\n": "while scanning a quoted scalar\n  in \"F\", line 1, column 4\nfound unexpected end of stream\n  in \"F\", line 2, column 1",
		"a: &x 1\nb: &x 2\n": "found duplicate anchor 'x'; first occurrence\n  in \"F\", line 1, column 4\nsecond occurrence\n" +
			"  in \"F\", line 2, column 4",
		"a: 1\n---\nb: 2\n": "expected a single document in the stream\n  in \"F\", line 1, column 1\nbut found another document\n" +
			"  in \"F\", line 2, column 1",
		// The reader checks a chunk only when it reads it: the scalar runs
		// into the second chunk before the bad character is met.
		"a: [\n" + strings.Repeat("b\n", 50) + strings.Repeat("x", 9000) + "\x01\n": "unacceptable character #x0001: special characters are not allowed\n  in \"F\", position 9105",
		"a: 1\n" + strings.Repeat("k: v\n", 1000) + "z: \x02\n":                     "unacceptable character #x0002: special characters are not allowed\n  in \"F\", position 5008",
		"k: " + strings.Repeat("v", 9000) + "\x03\n":                                "unacceptable character #x0003: special characters are not allowed\n  in \"F\", position 9003",
	} {
		_, err := Load([]byte(in), "F")
		var e *Error
		if !errors.As(err, &e) || e.Error() != want {
			t.Errorf("Load(%.40q) = %v\nwant %q", in, err, want)
		}
	}
}

func TestLoadValues(t *testing.T) {
	v, err := Load([]byte("b: 1\na: [x, 1.5, ~, yes, 2026-10-01, 0x1f, '012', {c: d}]\nb: 2\n"), "F")
	if err != nil {
		t.Fatal(err)
	}
	if got := py.Repr(v); got != "{'b': 2, 'a': ['x', 1.5, None, True, datetime.date(2026, 10, 1), 31, '012', {'c': 'd'}]}" {
		t.Fatalf("got %s", got)
	}
	for _, empty := range []string{"", "# c\n", "---\n", "~\n"} {
		if v, err := Load([]byte(empty), "F"); v != nil || err != nil {
			t.Errorf("Load(%q) = %v %v", empty, v, err)
		}
	}
	if v, _ := Load([]byte("!!set {a}\n"), "F"); v != (Unrepresentable{TypeName: "set"}) {
		t.Errorf("set root: %v", v)
	}
	if v, _ := Load([]byte("[1, [2]]\n"), "F"); py.Repr(v) != "[1, [2]]" {
		t.Errorf("list root: %v", v)
	}
	if v, _ := Load([]byte("\r\na: 1\r\nb: x\r  y\r"), "F"); py.Repr(v) != "{'a': 1, 'b': 'x y'}" {
		t.Errorf("newlines: %s", py.Repr(v))
	}
	if _, ok := v.(*yamlpy.Map); !ok {
		t.Fatal("not a map")
	}
}

func TestUnsupportedAndValueErrors(t *testing.T) {
	for in, want := range map[string]string{
		"a: &x 1\nb: *x\n":              "line 2, column 4: an alias is not supported in this file",
		"b: {x: 1}\nc:\n  <<: {y: 2}\n": "line 3, column 3: a merge key ('<<') is not supported in this file",
		"a:\n  1: x\n":                  "line 2, column 3: a key that is not a string is not supported in this file",
		"a: 2026-10-01 10:00:00\n":      "line 1, column 4: a timestamp with a time of day is not supported in this file",
		"a: 99999999999999999999\n":     "line 1, column 4: an integer beyond 64 bits is not supported in this file",
		"a: !!binary aGk=\n":            "line 1, column 4: binary data (!!binary) is not supported in this file",
		"a: !!omap [x: 1]\n":            "line 1, column 4: an ordered map (!!omap) is not supported in this file",
		"a: !!int abc\n":                "line 1, column 4: invalid literal for int() with base 10: 'abc'",
		"a: 2026-02-30\n":               "line 1, column 4: day is out of range for month",
		"a: \"\\UFFFFFFFF\"\n":          "line 1, column 7: chr() arg not in range(0x110000): \\UFFFFFFFF",
	} {
		_, err := Load([]byte(in), "F")
		w, ok := err.(interface{ Why() string })
		if !ok || w.Why() != want || err.Error() != want {
			t.Errorf("Load(%q) = %v, want %q", in, err, want)
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	for in, want := range map[string]string{
		"a: \xff\n":         "'utf-8' codec can't decode byte 0xff in position 3: invalid start byte",
		"a: \xe2\x82x\n":    "'utf-8' codec can't decode bytes in position 3-4: invalid continuation byte",
		"a: \xed\xa0\x80\n": "'utf-8' codec can't decode byte 0xed in position 3: invalid continuation byte",
		"\xe2\x82":          "'utf-8' codec can't decode bytes in position 0-1: unexpected end of data",
	} {
		_, err := Load([]byte(in), "F")
		var de *DecodeError
		if !errors.As(err, &de) || de.Error() != want || de.Why() != want {
			t.Errorf("Load(%q) = %v, want %q", in, err, want)
		}
	}
	if utf8ErrorText([]byte{0xc0}) != "'utf-8' codec can't decode byte 0xc0 in position 0: invalid start byte" {
		t.Error("utf8ErrorText")
	}
	if _, err := Load([]byte("a: !<%ff> x\n"), "F"); err == nil || !strings.Contains(err.Error(), "can't decode byte 0xff") {
		t.Errorf("URI escape: %v", err)
	}
}
