package cli

// The length and the form of the one-line descriptions, held by ratchets.
// A description of a command or of a flag is one line of at most
// summaryMax characters (aim for 60); a flag's text does not open with the
// verbs it applies to ('(pull, diff, plan, apply, list) Only the devices
// ...'), since each verb has the text of its own flag. What does not meet
// the rule yet is listed in testdata/style/<rule>.txt, one entry per line:
// a new offender fails the test, and so does an entry that meets the rule
// now (it is to be removed). The lists only shrink: -update-style drops the
// entries that are fixed, and never adds one.

import (
	"bufio"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/spf13/cobra"
)

var updateStyle = flag.Bool("update-style", false, "drop the entries of internal/cli/testdata/style that meet their rule now")

// summaryMax is the longest description of a command or a flag.
const summaryMax = 72

// longSummaries are the commands whose description is over summaryMax, by
// their words ('device collect'): the description the scripts and the shell
// list.
func longSummaries(root *cobra.Command) []string {
	var all [][]string
	treeVerbs(root, nil, &all)
	var out []string
	for _, p := range all {
		c, _ := resolve(root, p)
		if utf8.RuneCountInString(c.Short) > summaryMax {
			out = append(out, strings.Join(p, " "))
		}
	}
	return out
}

// flagTexts are the descriptions of every flag of every leaf command, by
// 'command words flag' ('device config plan --scope'), as the lists show
// them (flagHelp).
func flagTexts(t *testing.T) map[string]string {
	t.Helper()
	inv, root, _ := shellTestInv(t)
	paths, cmds := visibleLeaves(root)
	out := map[string]string{}
	for i, p := range paths {
		spec, ok := specFor(p)
		if !ok {
			continue
		}
		rows, block := inv.shellUsage(cmds[i], p)
		for _, f := range spec.Flags {
			_, desc := flagHelp(block, rows, f)
			out[strings.Join(p, " ")+" "+f.Names[0]] = desc
		}
	}
	return out
}

// ratchet compares the offenders found with the entries of the rule's list.
func ratchet(t *testing.T, rule string, found []string) {
	t.Helper()
	path := filepath.Join("testdata", "style", rule+".txt")
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var header, listed []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := sc.Text(); strings.HasPrefix(l, "#") {
			header = append(header, l)
		} else if l != "" {
			listed = append(listed, l)
		}
	}
	if !slices.IsSorted(listed) {
		t.Errorf("%s is not sorted", path)
	}
	var kept []string
	for _, k := range found {
		if !slices.Contains(listed, k) {
			t.Errorf("%s: %q breaks the rule and is not in %s (fix it; the list does not take new entries)", rule, k, path)
		}
	}
	for _, k := range listed {
		if slices.Contains(found, k) {
			kept = append(kept, k)
		} else {
			t.Errorf("%s: %q meets the rule now: remove it from %s (go test ./internal/cli -run TestStyleRatchets -update-style)", rule, k, path)
		}
	}
	if *updateStyle {
		text := strings.Join(header, "\n") + "\n" + strings.Join(kept, "\n") + "\n"
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStyleRatchets(t *testing.T) {
	_, root, _ := shellTestInv(t)
	ratchet(t, "summary-length", longSummaries(root))

	var long, prefixed []string
	for k, d := range flagTexts(t) {
		if utf8.RuneCountInString(d) > summaryMax {
			long = append(long, k)
		}
		if strings.HasPrefix(d, "(") {
			prefixed = append(prefixed, k)
		}
	}
	slices.Sort(long)
	slices.Sort(prefixed)
	ratchet(t, "flag-length", long)
	ratchet(t, "flag-prefix", prefixed)
}

// The ratchet's lists name commands and flags that exist: a renamed or
// removed one leaves the list by its own, since it can no longer break the
// rule (the test above says so); this is the check that the keys have the
// shape the tests write.
func TestStyleRatchetKeysHaveTheirShape(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "style", "*.txt"))
	if len(files) != 3 {
		t.Fatalf("testdata/style has %d lists, want 3", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l != strings.TrimSpace(l) || strings.Contains(l, "  ") {
				t.Errorf("%s: %q has blanks at an end or doubled", f, l)
			}
		}
	}
}
