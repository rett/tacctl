package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The man page is hand-written (man/tacctl.1). These tests keep it honest
// against the command tree: every command of the tree has an entry, and no
// entry names a command the tree lacks, so a removed verb cannot linger.

var (
	manFontEsc = regexp.MustCompile(`\\f[BIRP1-4]|\\\(..|\\[&|^]`)
	manSpaces  = regexp.MustCompile(`\s+`)
)

// manArgs splits the arguments of a roff macro line: words, or "quoted
// words" with "" for a quote inside.
func manArgs(s string) []string {
	var out []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		if s[0] == '"' {
			i := 1
			var b strings.Builder
			for i < len(s) {
				if s[i] == '"' {
					if i+1 < len(s) && s[i+1] == '"' {
						b.WriteByte('"')
						i += 2
						continue
					}
					break
				}
				b.WriteByte(s[i])
				i++
			}
			out = append(out, b.String())
			if i < len(s) {
				i++
			}
			s = s[i:]
			continue
		}
		i := strings.IndexAny(s, " \t")
		if i < 0 {
			i = len(s)
		}
		out = append(out, s[:i])
		s = s[i:]
	}
	return out
}

// manText is the page as a reader sees it, one string per output line of
// source: font macros and escapes removed. tags are the lines that head a
// .TP entry.
func manText(t *testing.T) (lines, tags []string) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "man", "tacctl.1"))
	if err != nil {
		t.Fatal(err)
	}
	clean := func(s string) string {
		s = strings.ReplaceAll(s, `\-`, "-")
		s = strings.ReplaceAll(s, `\e`, `\`)
		return strings.TrimSpace(manSpaces.ReplaceAllString(manFontEsc.ReplaceAllString(s, ""), " "))
	}
	afterTP := false
	for _, l := range strings.Split(string(src), "\n") {
		var text string
		switch {
		case strings.HasPrefix(l, `.\"`):
			continue
		case l == ".TP":
			afterTP = true
			continue
		case strings.HasPrefix(l, "."):
			name, rest, _ := strings.Cut(l[1:], " ")
			args := manArgs(rest)
			switch name {
			case "B", "I", "SM", "SS", "SH":
				text = strings.Join(args, " ")
			case "BI", "BR", "IR", "IB", "RB", "RI":
				text = strings.Join(args, "")
			default:
				afterTP = false
				continue
			}
		default:
			text = l
		}
		text = clean(text)
		lines = append(lines, text)
		if afterTP {
			tags = append(tags, expandAlternatives(text)...)
			afterTP = false
		}
	}
	return lines, tags
}

var manAlternatives = regexp.MustCompile(`\{ ([a-z :-]+(?: \| [a-z :-]+)+) \}`)

// expandAlternatives turns "config allow { list | add } [cidr]" into one
// string per alternative ("config allow list [cidr]", ...); a string
// without a braced group is returned as it is.
func expandAlternatives(s string) []string {
	m := manAlternatives.FindStringSubmatchIndex(s)
	if m == nil {
		return []string{s}
	}
	var out []string
	for _, alt := range strings.Split(s[m[2]:m[3]], " | ") {
		out = append(out, expandAlternatives(s[:m[0]]+strings.TrimSpace(alt)+s[m[1]:])...)
	}
	return out
}

// treeVerbs lists the commands of the tree (hidden ones left out) as their
// words after 'tacctl'.
func treeVerbs(c *cobra.Command, prefix []string, out *[][]string) {
	for _, sub := range c.Commands() {
		if sub.Hidden {
			continue
		}
		p := append(append([]string(nil), prefix...), sub.Name())
		*out = append(*out, p)
		treeVerbs(sub, p, out)
	}
}

// Every command of the tree has an entry in the man page: a '.TP' tag that
// starts with its words, or a mention as 'tacctl <words>'.
func TestManPageNamesEveryCommand(t *testing.T) {
	lines, tags := manText(t)
	text := strings.Join(lines, "\n")
	var all [][]string
	treeVerbs(newRoot(&invocation{app: newHarness(t, nil).app}), nil, &all)
	if len(all) < 100 {
		t.Fatalf("the tree has %d commands", len(all))
	}
	for _, p := range all {
		words := strings.Join(p, " ")
		found := strings.Contains(text, "tacctl "+words)
		for _, tag := range tags {
			found = found || tag == words || strings.HasPrefix(tag, words+" ")
		}
		if !found {
			t.Errorf("man/tacctl.1 has no entry for 'tacctl %s'", words)
		}
	}
}

// removedPhrases are verbs that no longer exist (the policy of docs/plans/
// go-rewrite.md 7: only the CHANGELOG mentions them).
var removedPhrases = []*regexp.Regexp{
	regexp.MustCompile(`user scope \S+ (set|clear)\b`),
	regexp.MustCompile(`scope prefixes \S+ clear\b`),
}

// The man page names no command the tree lacks: a '.TP' tag or a 'tacctl
// <family> <word>' mention whose word is no sub-command of a family that has
// sub-commands, and none of the removed verbs.
func TestManPageNamesNoMissingCommand(t *testing.T) {
	lines, tags := manText(t)
	root := newRoot(&invocation{app: newHarness(t, nil).app})
	word := regexp.MustCompile(`^[a-z][a-z-]*$`)
	check := func(where string, words []string) {
		c := root
		for _, w := range words {
			if !word.MatchString(w) {
				return
			}
			next := child(c, w)
			if next == nil {
				if c != root && len(c.Commands()) > 0 && !c.Hidden {
					t.Errorf("man/tacctl.1 (%s): 'tacctl %s' is no command: %q has no sub-command %q",
						where, strings.Join(words, " "), c.Name(), w)
				}
				return
			}
			c = next
		}
	}
	mention := regexp.MustCompile(`\btacctl ((?:[a-z][a-z-]* ?){2,4})`)
	for _, l := range lines {
		for _, m := range mention.FindAllStringSubmatch(l, -1) {
			words := strings.Fields(m[1])
			if child(root, words[0]) != nil {
				check("text", words)
			}
		}
		for _, re := range removedPhrases {
			if re.MatchString(l) {
				t.Errorf("man/tacctl.1 names a removed verb: %q", l)
			}
		}
	}
	for _, tag := range tags {
		words := strings.Fields(tag)
		if len(words) > 1 && child(root, words[0]) != nil {
			check("tag", words)
		}
	}
}
