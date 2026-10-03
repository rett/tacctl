package radius

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/ui"
)

func TestEchoE(t *testing.T) {
	for _, c := range []struct {
		in, out string
		stop    bool
	}{
		{"plain", "plain", false},
		{`a\tb`, "a\tb", false},
		{`a\\b`, `a\b`, false},
		{`\x41\x4a`, "AJ", false},
		{`\x`, `\x`, false},
		{`\0101`, "A", false},
		{`é`, "é", false},
		{`\U0001F511`, "\U0001F511", false},
		{`\q`, `\q`, false},
		{`end\`, `end\`, false},
		{`cut\cmore`, "cut", true},
		{`\e[0m`, "\x1b[0m", false},
		{`user=ev\il`, `user=ev\il`, false},
		{`a\nb`, "a\nb", false},
	} {
		got, stop := echoE(c.in)
		if got != c.out || stop != c.stop {
			t.Errorf("echoE(%q) = %q, %v; want %q, %v", c.in, got, stop, c.out, c.stop)
		}
	}
}

func TestCompileBRE(t *testing.T) {
	for _, c := range []struct {
		re, line string
		match    bool
	}{
		{"alice", "user=ALICE", true},    // -i
		{"a.c", "xabcx", true},           // .
		{"a.c", "ac", false},             //
		{"ab*c", "ac", true},             // *
		{"*a", "x*a", true},              // a leading * is literal
		{"*a", "xa", false},              //
		{`^*a`, "*a", true},              // so is one after ^
		{"^user", "user=x", true},        //
		{"^user", "a user", false},       //
		{"x$", "ax", true},               //
		{"a^b", "a^b", true},             // ^ elsewhere is literal
		{"a$b", "a$b", true},             // $ elsewhere is literal
		{`a\|b`, "xb", true},             // GNU alternation
		{"a|b", "a|b", true},             // plain | is literal
		{"a|b", "b", false},              //
		{`a\+`, "caat", true},            // GNU \+
		{"a+", "a+", true},               // plain + is literal
		{"a+", "aa", false},              //
		{`\(ab\)*c`, "ababc", true},      // groups
		{"(ab)", "(ab)", true},           // plain parentheses are literal
		{`a\{2\}`, "caa", true},          // interval
		{`^a\{2\}$`, "aaa", false},       //
		{"a{2}", "a{2}", true},           // plain braces are literal
		{`[a-c]x`, "bx", true},           // bracket
		{`[^a-c]x`, "bx", false},         //
		{`[[:digit:]]x`, "3x", true},     // class
		{`[]]x`, "]x", true},             // ] first
		{`[a\]x`, `\x`, true},            // backslash is literal in a bracket
		{`\.`, "a.b", true},              // escaped dot
		{`\.`, "ab", false},              //
		{`\<alice\>`, "x alice y", true}, // word edges
		{`\<alice\>`, "xalicey", false},  //
		{"café", "CAFÉ", true},           // non-ASCII
		{"user=alice bob", "user=alice bob", true},
	} {
		re, err := compileBRE(c.re)
		if err != nil {
			t.Errorf("compileBRE(%q): %v", c.re, err)
			continue
		}
		if got := re.MatchString(c.line); got != c.match {
			t.Errorf("%q on %q: %v, want %v (%s)", c.re, c.line, got, c.match, re)
		}
	}
	for _, bad := range []string{`a\`, `[a`, `\(a\)\1`, `a\{x\}`, `a\{2`, `[[.a.]]`} {
		if _, err := compileBRE(bad); err == nil {
			t.Errorf("compileBRE(%q) accepted", bad)
		}
	}
}

func TestTail(t *testing.T) {
	dir := t.TempDir()
	m := &Module{}
	text := "1\n2\n3\n4\n5\n"
	noNL := "1\n2\n3\n4\n5"
	big := strings.Repeat("0123456789\n", 20000) // spans several 64 KiB blocks
	for _, c := range []struct {
		content, count, want string
		ok                   bool
	}{
		{text, "2", "4\n5\n", true},
		{text, "5", text, true},
		{text, "9", text, true},
		{text, "0", "", true},
		{text, "-2", "4\n5\n", true},
		{text, "+4", "4\n5\n", true},
		{text, "+1", text, true},
		{text, "+0", text, true},
		{noNL, "2", "4\n5", true},
		{noNL, "+5", "5", true},
		{"", "3", "", true},
		{"\n\n", "1", "\n", true},
		{big, "3", "0123456789\n0123456789\n0123456789\n", true},
		{big, "20000", big, true},
		{text, "x", "", false},
		{text, "", "", false},
		{text, "+", "", false},
		{text, "--2", "", false},
		{text, "1.5", "", false},
	} {
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		m.env = &backend.Env{Out: ui.Output{Stdout: &out, Stderr: &errb}}
		err := m.tail(&out, p, c.count)
		if (err == nil) != c.ok || out.String() != c.want {
			t.Errorf("tail %q of %.20q: %q, %v (stderr %q); want %q ok=%v", c.count, c.content, out.String(), err, errb.String(), c.want, c.ok)
		}
		if !c.ok && !strings.Contains(errb.String(), "tail: invalid number of lines: '"+c.count+"'") {
			t.Errorf("tail %q: stderr %q", c.count, errb.String())
		}
	}
}

func TestLastParagraphs(t *testing.T) {
	text := "\n\nA1\nA2\n\nB1\n\n\n\nC1\nC2\n\n"
	for _, c := range []struct{ count, want string }{
		{"1", "C1\nC2\n\n"},
		{"2", "B1\n\nC1\nC2\n\n"},
		{"3", "A1\nA2\n\nB1\n\nC1\nC2\n\n"},
		{"20", "A1\nA2\n\nB1\n\nC1\nC2\n\n"},
		{"0", ""},
		{"-1", ""},
		{"abc", "A1\nA2\n\nB1\n\nC1\nC2\n\n"}, // a string compares above every record number
		{"1.5", "\n\n"},                       // the start, 2.5, is no record: an empty one
	} {
		if got := lastParagraphs(text, c.count); got != c.want {
			t.Errorf("count %q: %q, want %q", c.count, got, c.want)
		}
	}
	if got := lastParagraphs("", "5"); got != "" {
		t.Errorf("empty: %q", got)
	}
	if got := lastParagraphs("\n\n\n", "5"); got != "" {
		t.Errorf("blank: %q", got)
	}
}

func TestDuHuman(t *testing.T) {
	for _, c := range []struct {
		n    int64
		want string
	}{
		{0, "0"}, {1, "1"}, {512, "512"}, {1023, "1023"},
		{1024, "1.0K"}, {4096, "4.0K"}, {4097, "4.1K"}, {9 * 1024, "9.0K"}, {10 * 1024, "10K"}, {10*1024 + 1, "11K"},
		{1023 * 1024, "1023K"}, {1024 * 1024, "1.0M"}, {1024*1024 + 1, "1.1M"}, {5 * 1024 * 1024 * 1024, "5.0G"},
	} {
		if got := duHuman(c.n); got != c.want {
			t.Errorf("duHuman(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestAwkHelpers(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"2048\n", "2.0 MB"}, {"  512 \n", "0.5 MB"}, {"", ""}, {"junk\n", "0.0 MB"}, {"1024abc\n", "1.0 MB"}, {"1e3\n", "1.0 MB"},
		{"1024\n2048\n", "1.0 MB2.0 MB"},
	} {
		if got := awkMegabytes(c.in); got != c.want {
			t.Errorf("awkMegabytes(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := cutField2("MainPID=4242"); got != "4242" {
		t.Error(got)
	}
	if got := cutField2("no equals"); got != "no equals" {
		t.Error(got)
	}
	if got := cutField2("a=b=c"); got != "b" {
		t.Error(got)
	}
	if got := strings.Join(awkFields(" a\tb  c\n"), "|"); got != "a|b|c" {
		t.Error(got)
	}
	if portOf(":1812") != "1812" || portOf("10.0.0.1:11812") != "11812" || portOf("[::]:1812") != "1812" {
		t.Error("portOf")
	}
}

// The kept tacctl.yaml comes back with its bytes and mode, or is removed
// when there was none.
func TestKeptRestore(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tacctl.yaml")
	k, err := readKept(p)
	if err != nil || k.exists {
		t.Fatalf("absent: %+v %v", k, err)
	}
	if err := os.WriteFile(p, []byte("x: 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := k.restore(p); err != nil || fileExists(p) {
		t.Errorf("restore of absent: %v", err)
	}
	if err := k.restore(p); err != nil { // already gone
		t.Errorf("restore twice: %v", err)
	}
	if err := os.WriteFile(p, []byte("a: 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	k, err = readKept(p)
	if err != nil || !k.exists {
		t.Fatalf("present: %+v %v", k, err)
	}
	if err := os.WriteFile(p, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := k.restore(p); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	st, _ := os.Stat(p)
	if string(data) != "a: 1\n" || st.Mode().Perm() != 0o640 {
		t.Errorf("restored %q (%o)", data, st.Mode().Perm())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("left %v", ents)
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
