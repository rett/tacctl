package tacacs

import (
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/rendered"
)

// Python's shlex.split on each input (CPython 3.12, recorded).
func TestShlexSplitIsPythons(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
		err  error
	}{
		{"", nil, nil},
		{"a b", []string{"a", "b"}, nil},
		{`"TACQUITO_NETWORK=tcp6" "TACQUITO_ADDRESS=[::]:49"`, []string{"TACQUITO_NETWORK=tcp6", "TACQUITO_ADDRESS=[::]:49"}, nil},
		{"TACQUITO_LEVEL=30", []string{"TACQUITO_LEVEL=30"}, nil},
		{`a"b c"d`, []string{"ab cd"}, nil},
		{`'x y'z`, []string{"x yz"}, nil},
		{`""`, []string{""}, nil},
		{`a ""`, []string{"a", ""}, nil},
		{`a\ b`, []string{"a b"}, nil},
		{`a\`, nil, ErrNoEscapedCharacter},
		{`"a\"b"`, []string{`a"b`}, nil},
		{`"a\b"`, []string{`a\b`}, nil},
		{`"a\\b"`, []string{`a\b`}, nil},
		{`'a\b'`, []string{`a\b`}, nil},
		{`"open`, nil, ErrNoClosingQuotation},
		{`'open`, nil, ErrNoClosingQuotation},
		{`"x\`, nil, ErrNoEscapedCharacter},
		{" \t a \t ", []string{"a"}, nil},
		{"a#b", []string{"a#b"}, nil},
		{`é "ü x"`, []string{"é", "ü x"}, nil},
		{`''''`, []string{""}, nil},
	} {
		got, err := ShlexSplit(c.in)
		if !errors.Is(err, c.err) || !slices.Equal(got, c.want) {
			t.Fatalf("%q: %q %v, want %q %v", c.in, got, err, c.want, c.err)
		}
	}
}

func TestPySplitLines(t *testing.T) {
	got := pySplitLines("a\nb\r\nc\rd\ve\x1cf g\n\nh")
	if !slices.Equal(got, []string{"a", "b", "c", "d", "e", "f", "g", "", "h"}) {
		t.Fatalf("%q", got)
	}
	if got := pySplitLines("a\n"); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("%q", got)
	}
	if got := pySplitLines(""); got != nil {
		t.Fatalf("%q", got)
	}
}

// units_convert.bats "convert: unquoted and multi-assignment Environment=
// lines are read as systemd reads them", "failure: a drop-in line tacctl
// did not write stops the conversion, by line" (the reading half).
func TestLegacyDropInValues(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tacctl-overrides.conf")
	writeFile(t, p, "[Service]\n# by hand\n; also\n\nEnvironment=TACQUITO_LEVEL=30\nEnvironment=\"TACQUITO_NETWORK=tcp6\" \"TACQUITO_ADDRESS=[::]:49\"\n  Environment=\"TACQUITO_LEVEL=10\"  \n")
	v, err := LegacyDropInValues(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"TACQUITO_LEVEL": "10", "TACQUITO_NETWORK": "tcp6", "TACQUITO_ADDRESS": "[::]:49"}
	if !maps.Equal(v, want) {
		t.Fatalf("%v", v)
	}

	writeFile(t, p, "[Service]\nEnvironment=\"TACQUITO_LEVEL=30\"\nLimitNOFILE=65536\nEnvironment=\"HTTP_PROXY=http://proxy:3128\"\n"+
		"Environment=\"TACQUITO_LEVEL=30\" \"OTHER=1\"\nEnvironment=\"TACQUITO_LEVEL\"\nEnvironment=\"open\nEnvironment=\n[Unit]\n")
	_, err = LegacyDropInValues(p)
	var re *rendered.Error
	if !errors.As(err, &re) {
		t.Fatalf("%v", err)
	}
	want2 := p + " holds lines tacctl did not write and cannot carry over:\n" +
		"  line 3: LimitNOFILE=65536\n" +
		"  line 4: Environment=\"HTTP_PROXY=http://proxy:3128\"\n" +
		"  line 5: Environment=\"TACQUITO_LEVEL=30\" \"OTHER=1\"\n" +
		"  line 6: Environment=\"TACQUITO_LEVEL\"\n" +
		"  line 7: Environment=\"open\n" +
		"  line 8: Environment=\n" +
		"  line 9: [Unit]\n" +
		"Move them to a drop-in of your own in that directory (another .conf file) and run this again."
	if re.Msg != want2 {
		t.Fatalf("got\n%s\nwant\n%s", re.Msg, want2)
	}
	if got := rendered.Report(err); !strings.HasPrefix(got, "tacctl render: "+p+" holds lines") {
		t.Fatal(got)
	}

	// No file: the OS error, worded as Python's.
	_, err = LegacyDropInValues(filepath.Join(dir, "nope"))
	if got := rendered.Report(err); got != "tacctl render: "+filepath.Join(dir, "nope")+": No such file or directory" {
		t.Fatal(got)
	}
}
