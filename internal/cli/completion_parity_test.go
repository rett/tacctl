package cli

// The two surfaces that list the command tree: the generated bash, zsh
// and fish scripts (cobra's __complete, surface A) and the words, flags
// and descriptions the shell and the console list on Tab and '?' (surface
// B, shell.go). They are held to one text per command and to the same
// flags. A command whose two texts differ is in textAllowList until it is
// made equal; the list may only shrink.

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// textAllowList are the commands whose description differs between the
// scripts and the shell today (path, words joined by a blank). A command
// leaves the list when its two texts are equal; a command that stays in it
// while they are equal fails the test, so the list only shrinks.
var textAllowList = map[string]bool{}

// surfaceInv is an invocation for one surface: its own, as the shell mode
// is a field of it (completer sets it).
func surfaceInv(t *testing.T) (*invocation, *cobra.Command) {
	t.Helper()
	inv, root, _ := shellTestInv(t)
	return inv, root
}

// scriptOffers runs cobra's __complete over the tree as the generated
// scripts do and returns the words offered after words, with their
// descriptions.
func scriptOffers(t *testing.T, inv *invocation, root *cobra.Command, words []string, partial string) map[string]string {
	t.Helper()
	var buf bytes.Buffer
	root.SetArgs(append(append([]string{"__complete"}, words...), partial))
	root.SetOut(&buf)
	root.SetErr(&bytes.Buffer{})
	root.SetIn(strings.NewReader(""))
	if err := root.ExecuteContext(t.Context()); err != nil {
		t.Fatalf("__complete %v: %v", words, err)
	}
	out := map[string]string{}
	for _, l := range strings.Split(buf.String(), "\n") {
		if l == "" || strings.HasPrefix(l, ":") || strings.HasPrefix(l, "Completion ended") {
			continue
		}
		w, d, _ := strings.Cut(l, "\t")
		out[w] = d
	}
	return out
}

// shellOffers is the same question to the shell's completer.
func shellOffers(inv *invocation, root *cobra.Command, words []string, partial string) map[string]string {
	out := map[string]string{}
	for _, c := range inv.shellCompleter(root)(words, partial) {
		out[c.Word] = c.Desc
	}
	return out
}

// The scripts and the shell describe every command with one text, and a
// leaf offers the same flags in both.
func TestSurfacesAgreeOnTheTree(t *testing.T) {
	invA, rootA := surfaceInv(t)
	invB, rootB := surfaceInv(t)
	var all [][]string
	treeVerbs(rootA, nil, &all)
	seen := map[string]bool{}
	checkedText, checkedFlags := 0, 0
	for _, p := range all {
		parent, name := p[:len(p)-1], p[len(p)-1]
		key := strings.Join(p, " ")
		// the text under the parent's listing
		a := scriptOffers(t, invA, rootA, parent, "")
		b := shellOffers(invB, rootB, parent, "")
		if _, ok := a[name]; ok {
			if _, ok := b[name]; ok {
				checkedText++
				seen[key] = true
				switch {
				case a[name] == b[name] && textAllowList[key]:
					t.Errorf("%s: the two texts are equal now; remove it from textAllowList", key)
				case a[name] != b[name] && !textAllowList[key]:
					t.Errorf("%s: the scripts say %q, the shell says %q", key, a[name], b[name])
				}
			}
		}
		node, _ := resolve(rootA, p)
		if len(node.Commands()) > 0 {
			continue
		}
		if _, ok := specFor(p); !ok {
			continue
		}
		checkedFlags++
		fa, fb := flagWords(scriptOffers(t, invA, rootA, p, "-")), flagWords(shellOffers(invB, rootB, p, "-"))
		if !slices.Equal(fa, fb) {
			t.Errorf("%s: the scripts offer the flags %v, the shell %v", key, fa, fb)
		}
	}
	for k := range textAllowList {
		if !seen[k] {
			t.Errorf("textAllowList names %q, which is no command", k)
		}
	}
	if checkedText < 200 || checkedFlags < 150 {
		t.Errorf("only %d texts and %d flag lists compared", checkedText, checkedFlags)
	}
}

// flagWords are the words that start with '-', sorted.
func flagWords(m map[string]string) []string {
	var out []string
	for w := range m {
		if strings.HasPrefix(w, "-") {
			out = append(out, w)
		}
	}
	slices.Sort(out)
	return out
}

// A fixed word after a name or another word ('scope mgmt-acl lab '),
// which is not a node of the tree, is described in the scripts as the
// shell's '?' describes it.
func TestScriptsDescribeFixedWords(t *testing.T) {
	invA, rootA := surfaceInv(t)
	invB, rootB := surfaceInv(t)
	for _, words := range [][]string{
		{"scope", "mgmt-acl", "lab"},
		{"scope", "snmp", "lab"},
		{"scope", "block", "lab"},
		{"scope", "prefixes", "lab"},
		{"scope", "breakglass", "lab"},
		{"user", "scope", "alice"},
		{"group", "edit", "ops"},
		{"console", "forwarding"},
	} {
		a, b := shellOnly(scriptOffers(t, invA, rootA, words, "")), shellOnly(shellOffers(invB, rootB, words, ""))
		described := 0
		for w, d := range b {
			if d != "" {
				described++
			}
			if got, ok := a[w]; !ok || got != d {
				t.Errorf("%v: %q is %q in the scripts (offered %v), %q in the shell", words, w, got, ok, d)
			}
		}
		for w := range a {
			if _, ok := b[w]; !ok {
				t.Errorf("%v: the scripts offer %q, the shell not", words, w)
			}
		}
		t.Logf("%v: %d words, %d described", words, len(b), described)
	}
	a := scriptOffers(t, invA, rootA, []string{"scope", "mgmt-acl", "lab"}, "")
	if a["cisco-name"] != "Per-scope Cisco VTY-ACL name" {
		t.Errorf("scope mgmt-acl lab: cisco-name is %q", a["cisco-name"])
	}
}

// shellOnly is the words of an offer that are not flags (the scripts
// offer the flags on an empty word, the shell after a '-').
func shellOnly(m map[string]string) map[string]string {
	out := map[string]string{}
	for w, d := range m {
		if !strings.HasPrefix(w, "-") {
			out[w] = d
		}
	}
	return out
}
