package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/assets"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/testpty"
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

// A topic is searched for after the topics just before it.
func TestManSearchArgsStartNearTheTopic(t *testing.T) {
	topics := manTopics([]byte(".SH A\n.TP\n.B one\n.TP\n.B two\n.TP\n.B three\n.TP\n.B four\n.TP\n.B five\n.TP\n.B six\n.TP\n.B seven\n.TP\n.B eight\n"))
	if len(topics) != 9 {
		t.Fatalf("%d topics", len(topics))
	}
	if got := topics[0].searchArgs(); len(got) != 1 {
		t.Errorf("first: %q", got)
	}
	last := topics[8].searchArgs()
	if len(last) != manChain+1 || last[manChain] != topics[8].searchPattern() || last[0] != topics[8-manChain].searchPattern() {
		t.Errorf("last: %q", last)
	}
}

func TestManSearchPattern(t *testing.T) {
	for _, c := range []struct {
		topic manTopic
		want  string
	}{
		{manTopic{text: "TIERS", heading: true}, `^TIERS`},
		{manTopic{text: "User management (tacctl user)", heading: true, indent: 3}, `^   User  *management  *.tacctl  *user.`},
		{manTopic{text: "completion bash|zsh|fish", indent: 7}, `^       completion  *bash.zsh.fish`},
		{manTopic{text: "device config plan name[,name...] | --all | --scope scope | --vendor vendor", indent: 14}, `^              device  *config  *plan  *name.,name\.\.\..  *.  *--all  *.  *--scope  *scope  *.`},
		{manTopic{text: "a.b*c^d$e\\f[g]h(i)j+k?l{m}n'o\"p;q"}, `^ *a\.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q`},
		{manTopic{text: "scope.default"}, `^ *scope\.default`},
		{manTopic{text: "scope.default", indent: 7}, `^       scope\.default`},
		{manTopic{text: "status", indent: 7, lead: "Show"}, `^       status  *Show`},
		{manTopic{text: "mode", indent: 14}, `^              mode`},
		{manTopic{text: "tacacs", indent: 7, lead: "TACACS+,"}, `^       tacacs  *TACACS.,`},
	} {
		if got := c.topic.searchPattern(); got != c.want {
			t.Errorf("%q: %q, want %q", c.topic.text, got, c.want)
		}
	}
	// Whatever the text, the pattern is made of the literal characters, '.',
	// '\.', blanks as ' *' after a blank and the start of the line, and fits
	// on a line.
	ok := regexp.MustCompile(`^\^ *[A-Za-z0-9_:,=/@%.* \\-]*$`)
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
// that manTopics lists written in marker letters (X, then Y for the next
// one, and so on): every letter and digit of the line, outside the macro's
// name and the escapes, becomes the marker, so that groff lays the page out
// as it lays out the page itself, the entries' lines excepted.
func markedPage(src []byte) []byte {
	n := 0
	mark := func(l string) string {
		letter := "XY"[n%2]
		n++
		var b strings.Builder
		rest := l
		if strings.HasPrefix(l, ".") { // the macro's name stays
			name, _, _ := strings.Cut(l, " ")
			b.WriteString(name)
			rest = l[len(name):]
		}
		for i := 0; i < len(rest); i++ {
			c := rest[i]
			switch {
			case c == '\\' && i+1 < len(rest):
				// an escape: \fB, \(xx, \-, \e ... stays as it is
				w := 2
				switch rest[i+1] {
				case 'f':
					w = 3
				case '(':
					w = 4
				}
				w = min(w, len(rest)-i)
				b.WriteString(rest[i : i+w])
				i += w - 1
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
				b.WriteByte(letter)
			default:
				b.WriteByte(c)
			}
		}
		return b.String()
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
				lines[i] = mark(l)
			}
		case wantTag:
			wantTag = false
			if text, ok := manLineText(l); ok && manCommandLike.MatchString(text) {
				lines[i] = mark(l)
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
		lead := strings.IndexAny(marked[i], "XY")
		if lead < 0 {
			return nil, false
		}
		letter := marked[i][lead : lead+1]
		if letter != prev {
			at = append(at, i)
		}
		prev = letter
	}
	return at, true
}

// renderPage is the page as groff prints it for a terminal of width columns
// (styled as man shows it to less), one string per line. Hyphenation is off:
// a marker is not hyphenated where the text it replaces is, and the two
// renderings should differ in the entries' lines alone.
func renderPage(t *testing.T, groff, dir string, src []byte, width int) string {
	t.Helper()
	src = bytes.Replace(src, []byte("\n.SH "), []byte("\n.nh\n.SH "), 1)
	page := filepath.Join(dir, "page."+strconv.Itoa(len(src))+"."+strconv.Itoa(width)+".1")
	if err := os.WriteFile(page, src, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: groff,
		Args: []string{"-man", "-Tutf8", "-rLL=" + strconv.Itoa(width) + "n", page},
		Env:  []string{"PATH=/usr/bin:/bin", "LC_ALL=C.UTF-8"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("groff: %v: %s", err, res.Stderr)
	}
	return string(res.Stdout)
}

var reStyle = regexp.MustCompile("\x1b\\[[0-9;]*m|.\x08")

// unstyled is a rendering as lines of text, without the sequences that style it.
func unstyled(rendering string) []string {
	return strings.Split(reStyle.ReplaceAllString(rendering, ""), "\n")
}

// reachableTopics are the topics that a person can get to: the ones
// manLookup returns for the words of a heading, of a command group or of the
// start of a tag (a later topic with the same words is shadowed by the first,
// as the second "device block" of the TIERS notes is by the command's entry).
// The result is the index of each, with the words that find it.
func reachableTopics(topics []manTopic) map[int][]string {
	words := regexp.MustCompile(`^[a-z0-9_.-]+$`)
	out := map[int][]string{}
	try := func(w []string) {
		if i, ok := manFind(topics, w); ok {
			if _, seen := out[i]; !seen {
				out[i] = w
			}
		}
	}
	for _, e := range topics {
		for _, n := range e.names {
			try(strings.Fields(n))
		}
		for _, tag := range e.tags {
			f := strings.Fields(tag)
			for k := 1; k <= len(f) && words.MatchString(f[k-1]); k++ {
				try(f[:k])
			}
		}
	}
	return out
}

// firstLineShown runs the real less on the rendering in a terminal of width
// columns with the search as manShow gives it ('+/pattern' on the command
// line) and returns the number of the first line on the screen, from the
// prompt (-M) that says "lines first-last/total".
func firstLineShown(less, file string, width int, searches []string) (int, error) {
	argv := []string{less, "-R", "-M"}
	for _, p := range searches {
		argv = append(argv, "+/"+p)
	}
	s, err := testpty.Start(testpty.Options{Path: less, Argv: append(argv, file),
		Env:  []string{"PATH=/usr/bin:/bin", "TERM=xterm", "LC_ALL=C.UTF-8", "LESSSECURE=1", "LESSHISTFILE=-"},
		Rows: 30, Cols: uint16(width), Deadline: 20 * time.Second})
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if err := s.Expect(`lines \d+-\d+/\d+|\(press RETURN\)`, 15*time.Second); err != nil {
		return 0, err
	}
	out := reStyle.ReplaceAllString(s.Output(), "")
	if strings.Contains(out, "Pattern not found") {
		return 0, errors.New("less: Pattern not found")
	}
	m := regexp.MustCompile(`lines (\d+)-\d+/\d+`).FindAllStringSubmatch(out, -1)
	if len(m) == 0 {
		return 0, fmt.Errorf("less printed no position: %q", out)
	}
	return strconv.Atoi(m[len(m)-1][1])
}

// With the real less, the search of each heading and entry of the shipped
// page that a person can reach lands on that heading or entry: the entry's
// line is the first one on the screen. The entry's line is found by laying
// the page out again with markers in the place of the entries' texts, and
// both are laid out by groff at the widths of terminal below, as the pager
// shows them (the page is shown by less at these widths by man).
func TestManSearchLandsOnEachEntry(t *testing.T) {
	groff, err := execx.Real{}.LookPath("groff")
	if err != nil {
		t.Skip("groff is not installed: the search of the page cannot be checked against its rendering")
	}
	less, err := execx.Real{}.LookPath("less")
	if err != nil {
		t.Skip("less is not installed: the search of the page cannot be checked in a pager")
	}
	dir := t.TempDir()
	topics := shippedTopics(t)
	reach := reachableTopics(topics)
	if len(reach) < 250 {
		t.Fatalf("%d topics are reachable", len(reach))
	}
	for _, width := range []int{80, 100, 140, 200} {
		rendering := renderPage(t, groff, dir, assets.ManPage(), width)
		plain, marked := unstyled(rendering), unstyled(renderPage(t, groff, dir, markedPage(assets.ManPage()), width))
		if len(plain) != len(marked) {
			t.Fatalf("width %d: the marked page has %d lines, the page %d: groff lays it out differently, so the entries cannot be told apart", width, len(marked), len(plain))
		}
		at, same := entryLines(plain, marked)
		if !same || len(at) != len(topics) {
			t.Fatalf("width %d: the marked page is laid out differently (%d entries marked for %d topics)", width, len(at), len(topics))
		}
		file := filepath.Join(dir, "rendered."+strconv.Itoa(width))
		if err := os.WriteFile(file, []byte(rendering), 0o600); err != nil {
			t.Fatal(err)
		}
		work := make(chan int)
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range work {
					e := topics[i]
					got, err := firstLineShown(less, file, width, e.searchArgs())
					switch {
					case err != nil:
						t.Errorf("width %d: %q (man %s): searches %q: %v", width, e.text, strings.Join(reach[i], " "), e.searchArgs(), err)
					case got != at[i]+1:
						t.Errorf("width %d: %q (man %s): searches %q show line %d (%q) first, the entry is on line %d (%q)", width, e.text,
							strings.Join(reach[i], " "), e.searchArgs(), got, strings.TrimSpace(plain[got-1]), at[i]+1, strings.TrimSpace(plain[at[i]]))
					}
				}
			}()
		}
		for i := range topics {
			if _, ok := reach[i]; ok {
				work <- i
			}
		}
		close(work)
		wg.Wait()
	}
}
