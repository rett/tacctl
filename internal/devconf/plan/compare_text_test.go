package plan

// The text of a Junos compare (plan D135, the landed check): parsed,
// normalised, held for equality and against the delta that meant to make it.

import (
	"slices"
	"strings"
	"testing"
)

// checkCompare is a `show | compare` of the change the delta below makes, as
// a release prints it: brace layout, a trailing SECRET-DATA, a community's
// name in clear, the prompt's prefix before it.
const checkCompare = `{master:0}
[edit system]
+   authentication-order [ password tacplus ];
[edit system login]
+    class RW-CLASS {
+        permissions all;
+    }
+    user RW-CLASS {
+        class RW-CLASS;
+    }
[edit system tacplus-server]
+   192.0.2.8 {
+       secret "$9$abcDEFghi"; ## SECRET-DATA
+       single-connection;
+   }
[edit snmp]
-  location "Rack 3";
+  location "Rack 4";
+   community lab-ro-community {
+       authorization read-only;
+       client-list-name MGMT;
+   }
[edit firewall family inet filter MGMT-ACL term permit-mgmt from]
+       source-address {
+           192.0.2.0/24;
+       }
`

// landedCompare is the same change as `show system rollback compare 1 0`
// prints it after the commit: another order of the hierarchies, the uid
// Junos gave the new user, no prompt prefix.
const landedCompare = `[edit snmp]
+   community lab-ro-community {
+       authorization read-only;
+       client-list-name MGMT;
+   }
-  location "Rack 3";
+  location "Rack 4";
[edit firewall family inet filter MGMT-ACL term permit-mgmt from]
+       source-address 192.0.2.0/24;
[edit system]
+   authentication-order [ tacplus password ];
[edit system login]
+    user RW-CLASS {
+        uid 2001;
+        class RW-CLASS;
+    }
+    class RW-CLASS {
+        permissions all;
+    }
[edit system tacplus-server]
+   192.0.2.8 {
+       secret "$9$zyxWVUtsr"; ## SECRET-DATA
+       single-connection;
+   }
`

func compareDelta() Delta {
	set := func(sec, text string) Line { return Line{Section: sec, Op: OpSet, Text: text} }
	return Delta{Vendor: "junos", Lines: []Line{
		set("roles", "set system login class RW-CLASS permissions all"),
		set("roles", "set system login user RW-CLASS class RW-CLASS"),
		{Section: "aaa", Op: OpDelete, Text: "delete system authentication-order"},
		set("aaa", "set system authentication-order [ password tacplus ]"),
		{Section: "aaa", Op: OpSet, Text: "set system tacplus-server 192.0.2.8 secret lab-secret-0123456789abcdef",
			Secret: true, HasValue: true, Elided: "set system tacplus-server 192.0.2.8 secret <secret>"},
		set("aaa", "set system tacplus-server 192.0.2.8 single-connection"),
		set("snmp", `set snmp location "Rack 4"`),
		{Section: "snmp", Op: OpSet, Text: "set snmp community lab-ro-community authorization read-only", Secret: true, HasValue: true,
			Elided: "set snmp community <secret:1> authorization read-only"},
		{Section: "snmp", Op: OpSet, Text: "set snmp community lab-ro-community client-list-name MGMT", Secret: true, HasValue: true,
			Elided: "set snmp community <secret:1> client-list-name MGMT"},
		set("mgmt-acl", "set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 192.0.2.0/24"),
	}}
}

func TestParseCompare(t *testing.T) {
	c, err := ParseCompare(checkCompare)
	if err != nil {
		t.Fatal(err)
	}
	got := c.String()
	for _, secret := range []string{"$9$", "lab-ro-community", "abcDEF"} {
		if strings.Contains(got, secret) {
			t.Errorf("the normalised compare holds %q:\n%s", secret, got)
		}
	}
	for _, want := range []string{
		"+ system authentication-order password\n",
		"+ system authentication-order tacplus\n",
		"+ system login class RW-CLASS permissions all\n",
		"+ system login user RW-CLASS class RW-CLASS\n",
		"+ system tacplus-server 192.0.2.8 secret <secret>\n",
		"+ system tacplus-server 192.0.2.8 single-connection\n",
		"- snmp location Rack 3\n",
		"+ snmp location Rack 4\n",
		"+ snmp community <secret> authorization read-only\n",
		"+ firewall family inet filter MGMT-ACL term permit-mgmt from source-address 192.0.2.0/24\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	keys := make([]string, len(lines))
	for i, l := range lines {
		keys[i] = l[2:]
	}
	if !slices.IsSorted(keys) {
		t.Errorf("not sorted by path:\n%s", got)
	}
	shapeGolden(t, "compare.txt", got)
}

// The landed check: what landed is the change the check showed. The order of
// the hierarchies, the layout, the uid and the encrypted form of a secret do
// not matter; another statement does.
func TestCompareEqualLanded(t *testing.T) {
	a, err := ParseCompare(checkCompare)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseCompare(landedCompare)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Errorf("the check and the landed compare differ:\n%s\n---\n%s", a, b)
	}
	if strings.Contains(b.String(), "uid") {
		t.Error("the uid line was not dropped")
	}
	// the uid rule is for a login user's uid only
	other, err := ParseCompare("[edit system login user alice]\n+   full-name x;\n[edit protocols ospf]\n+   uid 7;\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(other.String(), "uid 7") {
		t.Error("another uid leaf was dropped")
	}
	// what landed is not what was checked
	for name, text := range map[string]string{
		"a statement more":  landedCompare + "[edit system]\n+   time-zone UTC;\n",
		"a value":           strings.Replace(landedCompare, "permissions all", "permissions view", 1),
		"a statement fewer": strings.Replace(landedCompare, "-  location \"Rack 3\";\n", "", 1),
	} {
		c, err := ParseCompare(text)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if a.Equal(c) {
			t.Errorf("%s: equal", name)
		}
	}
}

func TestCompareEmpty(t *testing.T) {
	for _, s := range []string{"", "\n", "{master:0}\n", "{master:0}\n\n"} {
		c, err := ParseCompare(s)
		if err != nil || !c.Empty() || c.String() != "" {
			t.Errorf("%q: %v %v", s, c, err)
		}
	}
	// context alone changes nothing
	c, err := ParseCompare("[edit system]\n     host-name x;\n")
	if err != nil || !c.Empty() {
		t.Errorf("context lines: %v %v", c, err)
	}
}

// Text the parser does not know is an error, never an empty compare.
func TestCompareFailsClosed(t *testing.T) {
	for name, s := range map[string]string{
		"an error":          "error: syntax error\n",
		"a prompt":          "user@host# \n",
		"unclosed header":   "[edit system\n+   x;\n",
		"unclosed block":    "[edit]\n+  system {\n+      host-name x;\n",
		"stray brace":       "[edit]\n+  }\n",
		"a bare word":       "[edit]\n+  host-name x\n",
		"text after a semi": "[edit]\n+  host-name x; garbage\n",
		"load complete":     "load complete\n",
	} {
		if _, err := ParseCompare(s); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestCompareUnexplained(t *testing.T) {
	d := compareDelta()
	c, err := ParseCompare(checkCompare)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Unexplained(d); len(got) != 0 {
		t.Errorf("the change is not explained by its own delta: %v", got)
	}
	l, err := ParseCompare(landedCompare)
	if err != nil {
		t.Fatal(err)
	}
	if got := l.Unexplained(d); len(got) != 0 {
		t.Errorf("the landed compare is not explained: %v", got)
	}
	// a stranger's staged work rides along: named, a secret masked
	stranger, err := ParseCompare(checkCompare +
		"[edit system]\n+   time-zone UTC;\n[edit snmp community other-community]\n+   authorization read-write;\n" +
		"[edit system login]\n-   class OLD-CLASS {\n-       permissions all;\n-   }\n")
	if err != nil {
		t.Fatal(err)
	}
	got := stranger.Unexplained(d)
	want := []string{
		"+ snmp community <secret> authorization read-write",
		"+ system time-zone UTC",
		"- system login class OLD-CLASS permissions all",
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("unexplained %q, want %q", got, want)
	}
	for _, s := range got {
		if strings.Contains(s, "other-community") {
			t.Errorf("a community's name in %q", s)
		}
	}
	// a delete of an object the delta deletes explains the statements under it
	del := Delta{Vendor: "junos", Lines: []Line{{Section: "snmp", Op: OpDelete, Text: "delete snmp community pubstr clients 10.0.0.0/8"}}}
	gone, err := ParseCompare("[edit snmp community pubstr clients]\n-   10.0.0.0/8;\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := gone.Unexplained(del); len(got) != 0 {
		t.Errorf("a removed client: %v", got)
	}
	gone2, _ := ParseCompare("[edit snmp community pubstr clients]\n-   172.16.0.0/12;\n")
	if got := gone2.Unexplained(del); len(got) != 1 {
		t.Errorf("another client removed: %v", got)
	}
	// an insert explains the term it moves
	ins := Delta{Vendor: "junos", Lines: []Line{{Section: "mgmt-acl", Op: OpInsert, Text: "insert firewall family inet filter F term b before term a"}}}
	moved, err := ParseCompare("[edit firewall family inet filter F]\n!   term b;\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := moved.Unexplained(ins); len(got) != 0 {
		t.Errorf("a moved term: %v", got)
	}
}

// The secret rules hold every statement the rendering flags as a secret: a
// rule that drifts from devices.Managed's flags fails here.
func TestCompareSecretRulesCoverTheRendering(t *testing.T) {
	n := 0
	for _, f := range fixtures(t) {
		if f.vendor != "juniper" {
			continue
		}
		for _, s := range expectedSections(t, f.expected) {
			for i, line := range s.Lines {
				if i >= len(s.Secret) || !s.Secret[i] {
					continue
				}
				toks := splitTokens(line)
				if len(toks) < 2 || toks[0] != "set" {
					continue
				}
				// the value is the statement's last word, a community's or
				// trap group's name its third
				value := toks[len(toks)-1]
				if len(toks) > 3 && toks[1] == "snmp" && (toks[2] == "community" || toks[2] == "trap-group") {
					value = toks[3]
				}
				for _, p := range expandBrackets(toks[1:]) {
					for _, w := range maskSecretTokens(p) {
						if w == value {
							t.Errorf("%s: the value of %q is not masked", f.name, line)
						}
					}
					n++
				}
			}
		}
	}
	if n < 5 {
		t.Errorf("only %d secret statements were checked", n)
	}
}

func TestRolloutWords(t *testing.T) {
	for _, w := range RolloutWords() {
		if !IsRolloutWord(w) {
			t.Errorf("%q is not a rollout word", w)
		}
		if err := Allowed("juniper", w); err == nil {
			t.Errorf("the word %q passes the statement allow-list", w)
		}
	}
	for _, w := range []string{
		RolloutCommitConfirmed(10, "20261013-ab12", "alice"),
		RolloutConfirm("20261013-ab12", "alice"),
		RolloutCancel("20261013-ab12"),
	} {
		if !IsRolloutWord(w) {
			t.Errorf("%q is not a rollout word", w)
		}
	}
	if got := RolloutCommitConfirmed(7, "id1", "alice"); got != `commit confirmed 7 comment "tacctl rollout id1 by alice"` {
		t.Errorf("%q", got)
	}
	if got := RolloutCommitConfirmed(0, "id 1", `a"b`); got != `commit confirmed 5 comment "tacctl rollout id_1 by a_b"` {
		t.Errorf("%q", got)
	}
	if got := RolloutCommitConfirmed(500, "i", "u"); !strings.HasPrefix(got, "commit confirmed 60 ") {
		t.Errorf("%q", got)
	}
	if got := RolloutConfirm("id1", "alice"); got != `commit comment "tacctl rollout confirm id1 by alice"` {
		t.Errorf("%q", got)
	}
	if got := RolloutCancel("id1"); got != `commit comment "tacctl rollout cancel id1"` {
		t.Errorf("%q", got)
	}
	if got := RolloutConfirmedNote(7); got != "commit confirmed will be rolled back in 7 minutes" {
		t.Errorf("%q", got)
	}
	// the region's own confirmed commit is a rollout-word shape too, with
	// another comment: the plan's region is not the rollout's
	for _, w := range []string{
		"commit", "commit and-quit", "commit confirmed 5", `commit confirmed 5 comment "x"`,
		`commit comment "tacctl rollout confirm a b by c"`, `commit confirmed 5 comment "tacctl rollout a by b"; delete`,
		"rollback 2", "configure exclusive now", "request system reboot", "",
	} {
		if IsRolloutWord(w) {
			t.Errorf("%q is a rollout word", w)
		}
	}
	// the wrapper's check and the region's last line are the paste's words
	// and stay as they are
	if err := CheckRegion("junos", []string{"configure private", "set snmp contact x", RolloutCompare, RolloutCommitCheck, "commit confirmed 5"}); err != nil {
		t.Errorf("the region's own words: %v", err)
	}
}
