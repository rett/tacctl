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
var textAllowList = map[string]bool{
	"backend disable":    true,
	"backup diff":        true,
	"backup restore":     true,
	"config allow":       true,
	"config cisco":       true,
	"config deny":        true,
	"config devices":     true,
	"config listen":      true,
	"config render":      true,
	"config restore":     true,
	"config wti":         true,
	"device config":      true,
	"emergency lockdown": true,
	"group edit":         true,
	"group preset":       true,
	"group reset":        true,
	"group show":         true,
	"log accounting":     true,
	"log clear":          true,
	"log tail":           true,
	"scope aaa-order":    true,
	"scope auth-method":  true,
	"scope breakglass":   true,
	"scope devices":      true,
	"scope exec-timeout": true,
	"scope mgmt-acl":     true,
	"scope protocols":    true,
	"scope radius-group": true,
	"scope staging":      true,
	"scope tacacs-group": true,
	"scope vendor-attrs": true,
}

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
