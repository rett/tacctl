package plan

// The context lines of a compare (live acceptance 2026-10-14): a delta that
// adds an entry next to existing entries of a list prints the unchanged
// neighbours without an op, a block collapsed as '{ ... }'. They are
// skipped, never a change, and never weaken the fail-closed rules.

import (
	"errors"
	"strings"
	"testing"
)

// capturedTrapGroup is the device's 'show | compare' of a staged trap group
// beside an existing one (names sanitised; the capture also stands in
// tests/fixtures/devconf/juniper/apply/texts.txt), with the CR bytes the
// device sends.
const capturedTrapGroup = "[edit snmp]\r\n" +
	"    trap-group zz-tacctl-tg { ... }\r\n" +
	"+   trap-group zz-tacctl-staged {\r\n" +
	"+       version v2;\r\n" +
	"+   }\r\n"

// contextCompares are the list shapes of the defect: an added name server,
// NTP server, community, trap target and filter term beside existing ones,
// in the layout of the capture (the op column, then the indentation).
var contextCompares = map[string]struct {
	text, delta, want string
}{
	"trap group (captured)": {capturedTrapGroup,
		"set snmp trap-group zz-tacctl-staged version v2",
		"+ snmp trap-group <secret:1> version v2\n"},
	"name server": {"[edit system name-server]\n     192.0.2.1 { ... }\n+    192.0.2.2;\n",
		"set system name-server 192.0.2.2",
		"+ system name-server 192.0.2.2\n"},
	"ntp server": {"[edit system ntp]\n    server 192.0.2.123 { ... }\n    server 192.0.2.124;\n+   server 192.0.2.125;\n",
		"set system ntp server 192.0.2.125",
		"+ system ntp server 192.0.2.125\n"},
	"community": {"[edit snmp]\n    community zz-tacctl-c1 { ... }\n+   community zz-tacctl-c2 {\n+       authorization read-only;\n+   }\n",
		"set snmp community zz-tacctl-c2 authorization read-only",
		"+ snmp community <secret:1> authorization read-only\n"},
	"trap target": {"[edit snmp trap-group zz-tacctl-tg]\n     version v2;\n     categories { ... }\n     targets {\n         192.0.2.201;\n+        192.0.2.203;\n     }\n",
		"set snmp trap-group zz-tacctl-tg targets 192.0.2.203",
		"+ snmp trap-group <secret:1> targets 192.0.2.203\n"},
	"filter term": {"[edit firewall family inet filter MGMT-ACL]\n     term permit-mgmt { ... }\n+    term permit-noc {\n+        from {\n+            source-address {\n+                192.0.2.64/26;\n+            }\n+        }\n+        then accept;\n+    }\n     term deny-rest { ... }\n",
		"set firewall family inet filter MGMT-ACL term permit-noc from source-address 192.0.2.64/26\nset firewall family inet filter MGMT-ACL term permit-noc then accept",
		"+ firewall family inet filter MGMT-ACL term permit-noc from source-address 192.0.2.64/26\n+ firewall family inet filter MGMT-ACL term permit-noc then accept\n"},
}

func contextDelta(text string) Delta {
	d := Delta{Vendor: "junos"}
	for _, l := range strings.Split(text, "\n") {
		d.Lines = append(d.Lines, Line{Section: "snmp", Op: OpSet, Text: l})
	}
	return d
}

func TestCompareContextLines(t *testing.T) {
	for name, c := range contextCompares {
		d := contextDelta(c.delta)
		got, err := ParseCompareFor(c.text, d)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("%s:\n%s\nwant\n%s", name, got, c.want)
		}
		if un := got.Unexplained(d); len(un) != 0 {
			t.Errorf("%s: unexplained %q", name, un)
		}
		for _, w := range []string{"zz-tacctl-tg", "zz-tacctl-c1", "{ ... }"} {
			if strings.Contains(got.String(), w) {
				t.Errorf("%s: %q stands in\n%s", name, w, got)
			}
		}
	}
	// context alone is no change, and the delta's success is never read
	// from it: only '+' and '-' lines are changes
	only, err := ParseCompare("[edit snmp]\n    trap-group zz-tacctl-tg { ... }\n    community zz-tacctl-c1 { ... }\n")
	if err != nil || !only.Empty() {
		t.Errorf("context alone: %v %v", only, err)
	}
	// a context line beside a change outside the delta does not hide it
	c, err := ParseCompare("[edit snmp]\n    trap-group zz-tacctl-tg { ... }\n+   contact stranger;\n")
	if err != nil {
		t.Fatal(err)
	}
	if un := c.Unexplained(contextDelta("set snmp trap-group zz-tacctl-tg version v2")); len(un) != 1 || un[0] != "+ snmp contact stranger" {
		t.Errorf("unexplained %q", un)
	}
}

// The context forms are context only where a compare puts them: with no op,
// inside a hunk, not inside an added or removed block. Everything else is
// still an error.
func TestCompareContextFailsClosed(t *testing.T) {
	for name, s := range map[string]string{
		"collapsed with +":        "[edit snmp]\n+   trap-group zz-tacctl-tg { ... }\n",
		"collapsed with -":        "[edit snmp]\n-   trap-group zz-tacctl-tg { ... }\n",
		"collapsed with !":        "[edit snmp]\n!   trap-group zz-tacctl-tg { ... }\n",
		"collapsed before a hunk": "    trap-group zz-tacctl-tg { ... }\n[edit snmp]\n+   contact x;\n",
		"leaf before a hunk":      "    contact x;\n",
		"opener before a hunk":    "    community x {\n    }\n",
		"collapsed in an added":   "[edit snmp]\n+   community x {\n        clients { ... }\n+   }\n",
		"collapsed with no name":  "[edit snmp]\n    { ... }\n",
		"a bare word":             "[edit snmp]\n    trap-group zz-tacctl-tg\n",
		"half a collapse":         "[edit snmp]\n    trap-group zz-tacctl-tg { ...\n",
		"text after a collapse":   "[edit snmp]\n    trap-group zz-tacctl-tg { ... } x\n",
		"a header in a block":     "[edit snmp]\n    community x {\n[edit system]\n    }\n",
	} {
		if _, err := ParseCompare(s); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	_, err := ParseCompare("[edit snmp]\n+   trap-group zz-tacctl-tg { ... }\n")
	var le *CompareLineError
	if !errors.As(err, &le) || le.Line != 2 || le.Why != "a collapsed block with an op" {
		t.Errorf("%#v", err)
	}
}

// The settle's compares are apply words for the rollbacks a device keeps,
// and nothing more.
func TestApplyRollbackCompareWords(t *testing.T) {
	for _, n := range []int{0, 1, 2, 9, 10, 49} {
		if w := ApplyRollbackCompare(n); !IsApplyWord(w) {
			t.Errorf("%q is not an apply word", w)
		}
	}
	for _, w := range []string{ApplyRollbackCompare(50), ApplyRollbackCompare(-1), "show configuration | compare rollback 01 | no-more",
		"show configuration | compare rollback 2", "show configuration | compare rollback 2 | no-more | save x", "show | compare rollback 2 | no-more"} {
		if IsApplyWord(w) {
			t.Errorf("%q is an apply word", w)
		}
	}
	if ApplyRollbackCompare(1) != ApplyLandedCompare {
		t.Errorf("%q", ApplyRollbackCompare(1))
	}
}
