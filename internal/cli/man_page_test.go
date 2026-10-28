package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/assets"
	"github.com/rett/tacctl/internal/execx"
)

// shippedTopics are the headings and entries of the page as shipped.
func shippedTopics(t *testing.T) []manTopic {
	t.Helper()
	topics := manTopics(assets.ManPage())
	if len(topics) < 300 {
		t.Fatalf("the page has %d headings and entries", len(topics))
	}
	return topics
}

func TestManTopicsReadHeadingsAndTags(t *testing.T) {
	src := []byte(`.TH TACCTL 1
.SH TIERS
.SS User management \fB(tacctl user)\fR
.TP
.BI "user add " "username group"
text
.TP
.B "config allow { list | add } [cidr]"
.TQ
.BR --version ", " -v
.\" a comment
.TP
.\" a comment between
.B version
.SS Per-scope thing \fB(tacctl scope a, tacctl scope b)\fR
.B not a tag
`)
	got := manTopics(src)
	var texts []string
	for _, e := range got {
		texts = append(texts, e.text)
	}
	want := []string{"TIERS", "User management (tacctl user)", "user add username group",
		"config allow { list | add } [cidr]", "version", "Per-scope thing (tacctl scope a, tacctl scope b)"}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("topics %q, want %q", texts, want)
	}
	if got[1].names[1] != "user" || strings.Join(got[5].names[1:], ",") != "scope a,scope b" {
		t.Errorf("group names %q %q", got[1].names, got[5].names)
	}
	if strings.Join(got[3].tags, "|") != "config allow list [cidr]|config allow add [cidr]" {
		t.Errorf("alternatives %q", got[3].tags)
	}
}

func TestManLookup(t *testing.T) {
	topics := shippedTopics(t)
	for _, c := range []struct {
		words []string
		want  string
	}{
		{[]string{"tiers"}, "TIERS"},
		{[]string{"TIERS"}, "TIERS"},
		{[]string{"audit", "log"}, "AUDIT LOG"},
		{[]string{"audit log"}, "AUDIT LOG"},
		{[]string{"exit", "status"}, "EXIT STATUS"},
		{[]string{"user"}, "User management (tacctl user)"},
		{[]string{"device"}, "Device registry (tacctl device)"},
		{[]string{"completion"}, "completion bash|zsh|fish"},
		{[]string{"man"}, "man [ --path ] [ word... ]"},
		{[]string{"version"}, "version [--long]"},
		{[]string{"device", "config", "plan"}, "device config plan "},
	} {
		e, ok := manLookup(topics, c.words)
		if !ok || !strings.HasPrefix(e.text, c.want) {
			t.Errorf("%q: %q (%v), want %q", c.words, e.text, ok, c.want)
		}
	}
	for _, words := range [][]string{nil, {""}, {"nosuch"}, {"device", "nosuch"}, {"--path"}, {"user", "ad"}} {
		if e, ok := manLookup(topics, words); ok {
			t.Errorf("%q found %q", words, e.text)
		}
	}
	// A heading wins over a command of the same name, then the first tag of
	// the page that is the words or starts with them.
	src := manTopics([]byte(".SH ADD\n.TP\n.B add\n.TP\n.B add more\n.TP\n.B add\n"))
	if e, _ := manLookup(src, []string{"add"}); !e.heading {
		t.Errorf("heading: %+v", e)
	}
	src = manTopics([]byte(".TP\n.B add more\n.TP\n.B add\n.TP\n.B add other\n"))
	if e, _ := manLookup(src, []string{"add"}); e.text != "add more" {
		t.Errorf("page order: %+v", e)
	}
	if e, _ := manLookup(src, []string{"ADD"}); e.text != "add more" {
		t.Errorf("case: %+v", e)
	}
}

func TestManSearchPattern(t *testing.T) {
	for _, c := range []struct {
		topic manTopic
		want  string
	}{
		{manTopic{text: "TIERS", heading: true}, `^ *TIERS *$`},
		{manTopic{text: "User management (tacctl user)", heading: true}, `^ *User  *management  *.tacctl  *user. *$`},
		{manTopic{text: "completion bash|zsh|fish", indent: 7}, `^       completion  *bash.zsh.fish *$`},
		{manTopic{text: "device config plan name[,name...] | --all | --scope scope | --vendor vendor", indent: 14}, `^              device  *config  *plan  *name.,name\.\.\..  *.  *--all  *.  *--scope  *scope  *.`},
		{manTopic{text: "a.b*c^d$e\\f[g]h(i)j+k?l{m}n'o\"p;q"}, `^ *a\.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q *$`},
		{manTopic{text: "scope.default"}, `^ *scope\.default *$`},
		{manTopic{text: "scope.default", indent: 7}, `^       scope\.default *$`},
		{manTopic{text: "status", indent: 7, lead: "Show"}, `^       status  *Show`},
		{manTopic{text: "mode", indent: 14}, `^              mode`},
		{manTopic{text: "tacacs", indent: 7, lead: "TACACS+,"}, `^       tacacs  *TACACS.,`},
	} {
		if got := c.topic.searchPattern(); got != c.want {
			t.Errorf("%q: %q, want %q", c.topic.text, got, c.want)
		}
	}
	// Whatever the text, the pattern is made of the literal characters, '.',
	// '\.', blanks as ' *' after a blank and the anchors, and fits on a line.
	ok := regexp.MustCompile(`^\^ *[A-Za-z0-9_:,=/@%.* \\-]*( \*\$)?$`)
	for _, e := range shippedTopics(t) {
		p := e.searchPattern()
		if !ok.MatchString(p) || len(p) > 4*manPatternMax {
			t.Errorf("%q: pattern %q", e.text, p)
		}
		if _, err := regexp.Compile(p); err != nil {
			t.Errorf("%q: %v", e.text, err)
		}
	}
}

// markedPage is the page source with the text of every heading and entry
// that manTopics lists replaced by marker letters (X, then Y for the next
// one, and so on) of the same width and with the same blanks, so that groff
// lays it out as it lays out the page. The lines that differ in its rendering
// are where the entries are.
func markedPage(src []byte) []byte {
	n := 0
	mark := func(text string) string {
		letter := "XY"[n%2]
		n++
		return strings.Map(func(r rune) rune {
			if r == ' ' {
				return r
			}
			return rune(letter)
		}, text)
	}
	lines := strings.Split(string(src), "\n")
	wantTag := false
	for i, l := range lines {
		name, _, _ := strings.Cut(l, " ")
		switch {
		case strings.HasPrefix(l, `.\"`):
			continue
		case l == ".TP", l == ".TQ":
			wantTag = true
		case name == ".SH", name == ".SS":
			wantTag = false
			if text, ok := manLineText(l); ok && text != "" {
				lines[i] = name + ` "` + mark(text) + `"`
			}
		case wantTag:
			wantTag = false
			if text, ok := manLineText(l); ok && manCommandLike.MatchString(text) {
				lines[i] = `.B "` + mark(text) + `"`
			}
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// entryLines are the lines on which the marked page differs from the page,
// reduced to the first line of each entry: a line that begins with the
// marker letter of the line above it continues that entry. ok is false when
// the pages differ anywhere else, because groff laid them out differently.
func entryLines(plain, marked []string) (at []int, ok bool) {
	prev := ""
	for i := range plain {
		if plain[i] == marked[i] {
			prev = ""
			continue
		}
		lead := strings.TrimSpace(marked[i])
		if lead == "" || (lead[0] != 'X' && lead[0] != 'Y') {
			return nil, false
		}
		if lead[:1] != prev {
			at = append(at, i)
		}
		prev = lead[:1]
	}
	return at, true
}

// renderPage is the page as groff prints it for a terminal of width columns,
// without the sequences that style it, one string per line. Hyphenation is
// off: a marker is not hyphenated where the text it replaces is, and the two
// renderings should differ in the entries' lines alone.
func renderPage(t *testing.T, groff, dir string, src []byte, width int) []string {
	t.Helper()
	src = bytes.Replace(src, []byte("\n.SH "), []byte("\n.nh\n.SH "), 1)
	page := filepath.Join(dir, "page."+strconv.Itoa(len(src))+"."+strconv.Itoa(width)+".1")
	if err := os.WriteFile(page, src, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: groff,
		Args: []string{"-man", "-Tutf8", "-rLL=" + strconv.Itoa(width) + "n", "-P-c", page},
		Env:  []string{"PATH=/usr/bin:/bin", "LC_ALL=C.UTF-8"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("groff: %v: %s", err, res.Stderr)
	}
	return strings.Split(regexp.MustCompile("\x1b\\[[0-9;]*m|.\x08").ReplaceAllString(string(res.Stdout), ""), "\n")
}

// With groff at hand, the search of each heading and entry of the shipped
// page lands on that heading or entry: the first line the pattern matches in
// the rendering is the line where the entry is printed (found by laying the
// page out again with markers in place of the entries' texts), at several
// widths of terminal.
func TestManSearchFindsEachEntry(t *testing.T) {
	groff, err := execx.Real{}.LookPath("groff")
	if err != nil {
		t.Skip("groff is not installed: the search of the page cannot be checked against its rendering")
	}
	dir := t.TempDir()
	topics := shippedTopics(t)
	compared := 0
	for _, width := range []int{140, 160, 200} {
		plain := renderPage(t, groff, dir, assets.ManPage(), width)
		marked := renderPage(t, groff, dir, markedPage(assets.ManPage()), width)
		if len(plain) != len(marked) {
			// A tag that wraps is laid out by its width in the source, which
			// the markers cannot copy: the entries cannot be told apart here.
			t.Logf("width %d: the marked page has %d lines, the page %d: not compared", width, len(marked), len(plain))
			continue
		}
		at, same := entryLines(plain, marked)
		if !same {
			t.Logf("width %d: the marked page is laid out differently: not compared", width)
			continue
		}
		if len(at) != len(topics) {
			t.Fatalf("width %d: %d marked entries found for %d topics", width, len(at), len(topics))
		}
		compared++
		// The first entry with a pattern is the one that is found: later ones
		// with the same pattern (the same text in a list further on, or the
		// first 40 characters of a long tag) are not told apart by a search.
		firstWith := map[string]int{}
		for i, e := range topics {
			if _, dup := firstWith[e.searchPattern()]; !dup {
				firstWith[e.searchPattern()] = i
			}
		}
		for _, e := range topics {
			i := firstWith[e.searchPattern()]
			re := regexp.MustCompile(e.searchPattern())
			first := -1
			for n, l := range plain {
				if re.MatchString(l) {
					first = n
					break
				}
			}
			switch {
			case first < 0:
				t.Errorf("width %d: %q: pattern %q matches no line", width, e.text, e.searchPattern())
			case first != at[i]:
				t.Errorf("width %d: %q: pattern %q lands on line %d (%q), the entry is on line %d (%q)",
					width, e.text, e.searchPattern(), first+1, strings.TrimSpace(plain[first]), at[i]+1, strings.TrimSpace(plain[at[i]]))
			}
		}
	}
	if compared == 0 {
		t.Skip("groff lays the marked page out differently at every width tried")
	}
}
