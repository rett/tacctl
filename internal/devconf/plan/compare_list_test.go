package plan

// A bracket list (live acceptance 2026-10-14, defect C): a change of one
// element of 'system accounting events [ ... ]' or 'system domain-search
// [ ... ]' makes Junos print the whole list removed and added. The elements
// on both sides net out; only the net change is held against the delta, and
// the netting never hides a change of someone else's.

import (
	"slices"
	"testing"
)

// The two hunks of the failed check (item 1 of the lab run, sanitised; the
// device prints the op column, then the indentation, and CR bytes).
const (
	// the full check: the plan deletes one accounting event
	listEventsHunk = "[edit system accounting]\r\n" +
		"-   events [ login change-log interactive-commands ];\r\n" +
		"+   events [ login change-log ];\r\n"
	// --section system: the plan adds a search domain beside the device's
	// one, printed bare (one element) before and as a list after
	listSearchHunk = "[edit system]\r\n" +
		"-  domain-search example.net;\r\n" +
		"+  domain-search [ example.net example.org ];\r\n"
)

func junosDelta(lines ...string) Delta {
	d := Delta{Vendor: "junos"}
	for _, l := range lines {
		op := OpSet
		if l[:6] == "delete" {
			op = OpDelete
		}
		d.Lines = append(d.Lines, Line{Section: "system", Op: op, Text: l})
	}
	return d
}

func TestCompareListElementNetsOut(t *testing.T) {
	cases := map[string]struct {
		text  string
		delta Delta
		// want is the netted compare, unexplained the statements the delta
		// does not account for
		want, unexplained []string
	}{
		"events: one deleted (captured)": {listEventsHunk,
			junosDelta("delete system accounting events interactive-commands"),
			[]string{"- system accounting events interactive-commands"}, nil},
		"domain-search: one added (captured)": {listSearchHunk,
			junosDelta("set system domain-search example.org"),
			[]string{"+ system domain-search example.org"}, nil},
		"domain-search: an element added beside the planned one": {
			"[edit system]\n-  domain-search example.net;\n+  domain-search [ example.net example.org stranger.test ];\n",
			junosDelta("set system domain-search example.org"),
			[]string{"+ system domain-search example.org", "+ system domain-search stranger.test"},
			[]string{"+ system domain-search stranger.test"}},
		"events: a second element removed beside the planned one": {
			"[edit system accounting]\n-   events [ login change-log interactive-commands ];\n+   events login;\n",
			junosDelta("delete system accounting events interactive-commands"),
			[]string{"- system accounting events change-log", "- system accounting events interactive-commands"},
			[]string{"- system accounting events change-log"}},
		"events: the whole list replaced, the delta sets the new ones only": {
			"[edit system accounting]\n-   events [ login change-log ];\n+   events [ interactive-commands ];\n",
			junosDelta("set system accounting events interactive-commands"),
			[]string{"- system accounting events change-log", "+ system accounting events interactive-commands", "- system accounting events login"},
			[]string{"- system accounting events change-log", "- system accounting events login"}},
		"events: the whole list replaced, the delta deletes and sets": {
			"[edit system accounting]\n-   events [ login change-log ];\n+   events [ interactive-commands ];\n",
			junosDelta("delete system accounting events login", "delete system accounting events change-log",
				"set system accounting events interactive-commands"),
			[]string{"- system accounting events change-log", "+ system accounting events interactive-commands", "- system accounting events login"},
			nil},
		"quoting folds before netting": {
			"[edit system]\n-  domain-search [ \"example.net\" a.test ];\n+  domain-search [ example.net a.test b.test ];\n",
			junosDelta("set system domain-search b.test"),
			[]string{"+ system domain-search b.test"}, nil},
		"a reorder is a change": {
			"[edit system]\n-  domain-search [ a.test b.test ];\n+  domain-search [ b.test a.test c.test ];\n",
			junosDelta("set system domain-search c.test"),
			[]string{"+ system domain-search a.test", "- system domain-search a.test", "+ system domain-search b.test",
				"- system domain-search b.test", "+ system domain-search c.test"},
			[]string{"+ system domain-search a.test", "+ system domain-search b.test",
				"- system domain-search a.test", "- system domain-search b.test"}},
		"not across paths": {
			"[edit system]\n-  domain-search [ a.test b.test ];\n+  domain-search [ b.test ];\n[edit system services dns]\n+  domain-search a.test;\n",
			junosDelta("delete system domain-search a.test"),
			[]string{"- system domain-search a.test", "+ system services dns domain-search a.test"},
			[]string{"+ system services dns domain-search a.test"}},
		"a removal with no addition stays": {
			"[edit system]\n-  domain-search [ a.test b.test ];\n",
			junosDelta("delete system domain-search a.test"),
			[]string{"- system domain-search a.test", "- system domain-search b.test"},
			[]string{"- system domain-search b.test"}},
		"two names are never alike": {
			"[edit snmp]\n-   community zz-one;\n+   community zz-two;\n",
			Delta{Vendor: "junos"},
			[]string{"- snmp community <secret:1>", "+ snmp community <secret:2>"},
			[]string{"+ snmp community <secret:2>", "- snmp community <secret:1>"}},
		"a hidden secret never nets out": {
			"[edit system tacplus-server 192.0.2.10]\n-    secret /* SECRET-DATA */;\n+    secret /* SECRET-DATA */;\n",
			junosDelta("set system tacplus-server 192.0.2.10 secret x"),
			[]string{"+ system tacplus-server 192.0.2.10 secret <secret>", "- system tacplus-server 192.0.2.10 secret <secret>"},
			nil},
		"a shown secret nets out only when equal": {
			"[edit system tacplus-server 192.0.2.10]\n-    secret \"$9$abc\";\n+    secret \"$9$def\";\n",
			Delta{Vendor: "junos"},
			[]string{"+ system tacplus-server 192.0.2.10 secret <secret>", "- system tacplus-server 192.0.2.10 secret <secret>"},
			[]string{"+ system tacplus-server 192.0.2.10 secret <secret>", "- system tacplus-server 192.0.2.10 secret <secret>"}},
		"an annotation is never cancelled": {
			"[edit system]\n-  /* old */\n-  domain-search a.test;\n+  /* old */\n+  domain-search a.test;\n",
			Delta{Vendor: "junos"},
			[]string{"+ system " + CompareAnnotationMark, "- system " + CompareAnnotationMark},
			[]string{"+ system " + CompareAnnotationMark, "- system " + CompareAnnotationMark}},
	}
	for name, tc := range cases {
		c, err := ParseCompareFor(tc.text, tc.delta)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got []string
		for _, s := range c.Stmts {
			got = append(got, s.Text())
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: netted\n%q, want\n%q", name, got, tc.want)
		}
		un := c.Unexplained(tc.delta)
		slices.Sort(un)
		if !slices.Equal(un, tc.unexplained) {
			t.Errorf("%s: unexplained %q, want %q", name, un, tc.unexplained)
		}
	}
}

// The check's compare (the whole list removed and added) and the landed one
// (a rollback compare may print only the element) are equal once netted; a
// stranger's extra element makes them differ.
func TestCompareListEqualNetted(t *testing.T) {
	check, err := ParseCompare(listEventsHunk)
	if err != nil {
		t.Fatal(err)
	}
	for _, landed := range []string{
		listEventsHunk,
		"[edit system accounting]\n-   events interactive-commands;\n",
		"[edit system accounting]\n-   events [ login change-log interactive-commands ];\n+   events [ change-log login ];\n",
	} {
		l, err := ParseCompare(landed)
		if err != nil {
			t.Fatal(err)
		}
		want := landed != "[edit system accounting]\n-   events [ login change-log interactive-commands ];\n+   events [ change-log login ];\n"
		if got := check.Equal(l); got != want {
			t.Errorf("Equal(%q) = %v, want %v", landed, got, want)
		}
	}
	other, _ := ParseCompare("[edit system accounting]\n-   events [ login change-log interactive-commands ];\n+   events [ login ];\n")
	if check.Equal(other) {
		t.Error("a second element removed compares equal")
	}
	// the inverse of a netted compare is the netted compare of the undo
	undo, _ := ParseCompare("[edit system accounting]\n-   events [ login change-log ];\n+   events [ login change-log interactive-commands ];\n")
	if !check.Inverse().Equal(undo) {
		t.Errorf("inverse %v, undo %v", check.Inverse(), undo)
	}
}
