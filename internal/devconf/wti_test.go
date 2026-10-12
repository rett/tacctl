package devconf

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf/wti"
	"github.com/rett/tacctl/internal/devices"
)

// labUnitScreens are the screens of the lab unit's document, in the order a
// reader captures them: the header's path and the fixture the screen is from.
var labUnitScreens = []struct{ path, file string }{
	{"/H", "wti/03-help-superuser.txt"},
	{"/SN", "wti/04-network-status.txt"},
	{"/N", "wti/31-network-iptables-on.txt"},
	{"/N > 25", "wti/08-snmp-access.txt"},
	{"/N > 26", "wti/09-snmp-trap.txt"},
	{"/N > 28", "wti/07-tacacs.txt"},
	{"/N > 28 > 8", "wti/pages/network-28-8.txt"},
	{"/N > 29", "wti/12-radius.txt"},
	{"/N > 5", "wti/30-iptables-uploaded-page.txt"},
	{"/N > 5", "wti/30-iptables-uploaded-page-2.txt"},
	{"/N > 5", "wti/30-iptables-uploaded-page-3.txt"},
	{"/N > 5", "wti/lab-unit/iptables-page-4.txt"},
	{"/F", "wti/pages/system-top.txt"},
	{"/F > 1 > 1", "wti/32-user-directory-view.txt"},
	{"/F > 1 > 1 > localadmin", "wti/33-user-directory-details.txt"},
	{"/J", "wti/16-site-id.txt"},
}

const labDocumentHeader = "# vendor: wti\n# os: 8.10 (command menu version)\n" +
	"# source: composed from the screens of this directory's parent (and iptables-page-4.txt) in the order a reader captures them\n" +
	"# ---\n"

// labDocument composes the lab unit's document (and keeps
// lab-unit/document.txt in step with it).
func labDocument(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(labDocumentHeader)
	for _, s := range labUnitScreens {
		b.WriteString("# page: " + s.path + "\n")
		b.WriteString(strings.TrimRight(capture(t, s.file), "\n") + "\n")
	}
	doc := b.String()
	golden(t, "wti/lab-unit/document.txt", doc)
	return doc
}

// wtiExpected is the hand-written expected side of the lab unit.
func wtiExpected(t *testing.T) []devices.Section {
	t.Helper()
	return expectedSections(t, "wti/lab-unit/expected.txt")
}

// without returns the expected sections with the lines of one section
// replaced.
func withSection(exp []devices.Section, name string, lines []string, marks []bool) []devices.Section {
	out := slices.Clone(exp)
	for i, s := range out {
		if s.Name == name {
			out[i] = devices.Section{Name: name, Lines: lines, Secret: marks}
			return out
		}
	}
	return append(out, devices.Section{Name: name, Lines: lines, Secret: marks})
}

// edit replaces one occurrence of old in doc and fails when it is not there.
func edit(t *testing.T, doc, old, repl string) string {
	t.Helper()
	if !strings.Contains(doc, old) {
		t.Fatalf("the document has no %q", old)
	}
	return strings.Replace(doc, old, repl, 1)
}

// sectionsText is an extraction as the golden file holds it.
func sectionsText(ex Extracted) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# secrets visible: %v\n", ex.SecretsVisible)
	for _, n := range SectionNames {
		s, ok := ex.Sections[n]
		if !ok {
			b.WriteString("[" + n + "] not extracted\n")
			continue
		}
		b.WriteString("[" + n + "]\n")
		for i, l := range s.Lines {
			mark := "|"
			if s.Secret[i] {
				mark = "*"
			}
			b.WriteString(mark + " " + l + "\n")
		}
	}
	return b.String()
}

func wtiPull(t *testing.T, doc string, exp []devices.Section) (Extracted, map[string]SectionResult) {
	t.Helper()
	ex, err := Extract("wti", doc, exp...)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := CompareAll(exp, ex)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]SectionResult{}
	for _, r := range rs {
		by[r.Name] = r
	}
	return ex, by
}

// ops lines of a result as 'op text'.
func wtiLines(r SectionResult) []string {
	var out []string
	for _, l := range r.Lines {
		out = append(out, string(l.Op)+" "+l.Text)
	}
	return out
}

func wtiHas(r SectionResult, want string) bool { return slices.Contains(wtiLines(r), want) }

func TestWTIFamily(t *testing.T) {
	for _, v := range []string{"wti", "WTI"} {
		if got, err := Family(v); err != nil || got != FamilyWTI {
			t.Errorf("%q: %q %v", v, got, err)
		}
	}
	// a configuration text cannot be read from a WTI unit: its reader is the
	// terminal walker's
	if _, _, err := Commands("wti"); !errors.Is(err, ErrUnsupportedVendor) {
		t.Errorf("Commands: %v", err)
	}
	if _, err := Extract("wti", "set system host-name a\n"); !errors.Is(err, ErrParse) {
		t.Errorf("a configuration text is no document: %v", err)
	}
}

func TestWTIExtractLabUnit(t *testing.T) {
	doc := labDocument(t)
	exp := wtiExpected(t)
	ex, err := Extract("wti", doc, exp...)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "wti/lab-unit/extract.golden", sectionsText(ex))

	// the statements, written out (not only the golden)
	want := map[string][]string{
		SectionAAA: {
			"tacacs enable on", "tacacs primary 192.0.2.42", "tacacs secret <secret>", "tacacs fallback-timer 15",
			"tacacs fallback-local on-transport-failure", "tacacs port 49", "tacacs default-access on",
			"tacacs account-module enabled", "tacacs session-module enabled", "tacacs service-name wti", "tacacs debug off",
			"tacacs default-level viewonly", "tacacs default-services serial,telnet-ssh,web,restful-api",
			"radius enable off", "radius fallback-timer 3", "radius fallback-local off", "radius retries 3", "radius port 1812",
			"radius accounting-port 1813", "radius default-access on", "radius onetime-auth off", "radius onetime-timer 5",
			"radius onetime-type dbm", "radius session-module enabled", "radius message-authenticator off", "radius debug off",
		},
		SectionSNMP: {
			"snmp enable on", "snmp version v1-v2-only", "snmp read-only yes", `snmp contact "Example NOC"`,
			`snmp location "Example City"`, "snmp system-name wti.site.exam...", "snmp ro-community <secret:1>",
			"snmp rw-community <other:1>", "snmp trap manager 1 192.0.2.34", "snmp trap community <secret:1>", "snmp trap version v2",
		},
		SectionBreakGlass: {"user localadmin level administrator", "user localadmin password <secret>"},
		SectionRoles:      nil, SectionNetconf: nil,
	}
	for name, lines := range want {
		got := ex.Sections[name].Lines
		if name == SectionAAA || name == SectionSNMP {
			// the order of the statements is the table's; compare as sets here
			a, b := slices.Clone(got), slices.Clone(lines)
			slices.Sort(a)
			slices.Sort(b)
			if !slices.Equal(a, b) {
				t.Errorf("%s:\n got %q\nwant %q", name, got, lines)
			}
			continue
		}
		if !slices.Equal(got, lines) {
			t.Errorf("%s: got %q want %q", name, got, lines)
		}
	}
	if n := len(ex.Sections[SectionMgmtACL].Lines); n != 25 {
		t.Errorf("mgmt-acl: %d statements, want 25", n)
	}
	if first := ex.Sections[SectionMgmtACL].Lines[0]; first != "iptables -A INPUT -i lo -j ACCEPT" {
		t.Errorf("first entry: %q", first)
	}
	if _, ok := ex.Sections[SectionSystem]; ok {
		t.Errorf("a WTI unit has no system section")
	}
	if !ex.SecretsVisible || ex.Vendor != FamilyWTI {
		t.Errorf("%+v", ex)
	}
	for _, name := range []string{SectionAAA, SectionSNMP, SectionBreakGlass} {
		s := ex.Sections[name]
		for i, l := range s.Lines {
			secret := strings.Contains(l, "<secret") || strings.Contains(l, "<other") || strings.HasSuffix(l, "password <secret>")
			if s.Secret[i] != secret {
				t.Errorf("%s: %q secret=%v", name, l, s.Secret[i])
			}
		}
	}
}

func TestWTICompareLabUnit(t *testing.T) {
	exp := wtiExpected(t)
	ex, by := wtiPull(t, labDocument(t), exp)
	var all []SectionResult
	for _, n := range SectionNames {
		if r, ok := by[n]; ok {
			all = append(all, r)
		}
	}
	golden(t, "wti/lab-unit/compare.golden", resultText(ex, all))

	for name, want := range map[string]string{
		SectionAAA:        "ok (+13 unmanaged)",
		SectionMgmtACL:    "ok (+5 unmanaged)",
		SectionSNMP:       "differs",
		SectionBreakGlass: "ok",
		SectionRoles:      "n/a",
		SectionNetconf:    "n/a",
	} {
		if got := by[name].StateText(); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if _, ok := by[SectionSystem]; ok {
		t.Errorf("a system section for a unit")
	}
	// the one finding of the snmp section: a read/write community
	snmp := by[SectionSNMP]
	if !wtiHas(snmp, "+ snmp rw-community <other:1> (present, not compared)") || snmp.Unmanaged != 4 {
		t.Errorf("snmp: %q unmanaged %d", wtiLines(snmp), snmp.Unmanaged)
	}
	for _, l := range snmp.Lines {
		if l.Op == OpExtra && l.Unmanaged != !strings.Contains(l.Text, "rw-community") {
			t.Errorf("%q unmanaged %v", l.Text, l.Unmanaged)
		}
	}
	// the services the unit allows beyond the standard's are a note
	if !slices.ContainsFunc(by[SectionAAA].Notes, func(n string) bool { return strings.Contains(n, "default-services") }) {
		t.Errorf("aaa notes: %q", by[SectionAAA].Notes)
	}
	if !slices.Contains(by[SectionMgmtACL].Notes, NoteWTITail) {
		t.Errorf("mgmt-acl notes: %q", by[SectionMgmtACL].Notes)
	}
	// the stale test of the whole pull
	rec := &Record{Vendor: "wti", Result: ResultOK, SecretsVisible: true}
	st, err := Stale(rec, ex.Sections, exp)
	if err != nil || st != StaleDiffers {
		t.Errorf("stale: %v %v", st, err)
	}
}

// The comparisons: a unit that follows the standard, then the irregularities
// the design names, each on its own.
func TestWTICompareIrregularities(t *testing.T) {
	exp := wtiExpected(t)
	base := labDocument(t)
	noRW := edit(t, base, "8. Read/Write Community:   rw-community", "8. Read/Write Community:   (undefined)")

	t.Run("consistent", func(t *testing.T) {
		_, by := wtiPull(t, noRW, exp)
		for name, want := range map[string]string{SectionAAA: "ok (+13 unmanaged)", SectionMgmtACL: "ok (+5 unmanaged)",
			SectionSNMP: "ok (+4 unmanaged)", SectionBreakGlass: "ok"} {
			if got := by[name].StateText(); got != want {
				t.Errorf("%s: %q, want %q: %q", name, got, want, wtiLines(by[name]))
			}
		}
	})

	t.Run("secondary host set", func(t *testing.T) {
		doc := edit(t, noRW, "3.  Secondary host/address:\n", "3.  Secondary host/address:     192.0.2.43\n")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionAAA]
		if r.State != StateDiffers || !wtiHas(r, "+ tacacs secondary 192.0.2.43") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		for _, l := range r.Lines {
			if l.Text == "tacacs secondary 192.0.2.43" && l.Unmanaged {
				t.Errorf("a second server is a finding, not the device's own")
			}
		}
		if WTISeverity(SectionAAA, "tacacs secondary 192.0.2.43") != "ACCESS" {
			t.Errorf("severity")
		}
	})

	t.Run("list reordered", func(t *testing.T) {
		a := "3.  iptables -A INPUT -s 10.1.100.0/23 -p tcp --dport 22 -j ACCEPT"
		b := "4.  iptables -A INPUT -s 10.0.20.0/24 -p tcp --dport 22 -j ACCEPT"
		doc := edit(t, noRW, a+"\n"+b, "3.  "+strings.TrimPrefix(b, "4.  ")+"\n4.  "+strings.TrimPrefix(a, "3.  "))
		_, by := wtiPull(t, doc, exp)
		r := by[SectionMgmtACL]
		if r.State != StateDiffers || !slices.ContainsFunc(wtiLines(r), func(l string) bool { return strings.HasPrefix(l, "! iptables: order differs") }) {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		if ops(r)[:20] != strings.Repeat("=", 20) {
			t.Errorf("every entry is still there: %s", ops(r))
		}
	})

	t.Run("an entry missing and one added", func(t *testing.T) {
		doc := edit(t, noRW, "5.  iptables -A INPUT -s 10.0.28.34 -p tcp --dport 22 -j ACCEPT",
			"5.  iptables -A INPUT -s 198.51.100.7 -p tcp --dport 22 -j ACCEPT")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionMgmtACL]
		if r.State != StateDiffers || !wtiHas(r, "- iptables -A INPUT -s 10.0.28.34 -p tcp --dport 22 -j ACCEPT") ||
			!wtiHas(r, "+ iptables -A INPUT -s 198.51.100.7 -p tcp --dport 22 -j ACCEPT") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("RADIUS on a TACACS+ scope", func(t *testing.T) {
		doc := edit(t, noRW, "1.  Enable:                     Off\n2.  Primary Host/Address:", "1.  Enable:                     On\n2.  Primary Host/Address:")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionAAA]
		if r.State != StateDiffers || !wtiHas(r, "+ radius enable on") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		for _, l := range r.Lines {
			if l.Op == OpExtra && strings.HasPrefix(l.Text, "radius enable") && l.Unmanaged {
				t.Errorf("the other protocol turned on is a finding")
			}
		}
	})

	t.Run("a read/write community", func(t *testing.T) {
		_, by := wtiPull(t, base, exp)
		r := by[SectionSNMP]
		if r.State != StateDiffers || !wtiHas(r, "+ snmp rw-community <other:1> (present, not compared)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		if WTISeverity(SectionSNMP, "snmp rw-community <other:1>") != "MONITORING" {
			t.Errorf("severity")
		}
	})

	t.Run("a read community that is not the scope's", func(t *testing.T) {
		doc := edit(t, noRW, "7. Read-Only Community:    ro-community", "7. Read-Only Community:    another-string")
		doc = edit(t, doc, "5. Community:          ro-community", "5. Community:          another-string")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionSNMP]
		if r.State != StateDiffers || !wtiHas(r, "- snmp ro-community <secret:1> (not present)") ||
			!wtiHas(r, "+ snmp ro-community <other:1> (present, not compared)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		// the trap community is the device's own: its label is the other one
		if !wtiHas(r, "+ snmp trap community <other:1> (present, not compared)") {
			t.Errorf("trap community: %q", wtiLines(r))
		}
	})

	t.Run("a truncated contact", func(t *testing.T) {
		doc := edit(t, noRW, "5. Contact:                Example NOC", "5. Contact:                Example Network Op...")
		long := withSection(exp, SectionSNMP, []string{"snmp enable on", "snmp version v1-v2-only", "snmp read-only yes",
			"snmp contact Example Network Operations", "snmp location Example City", "snmp ro-community ro-community"},
			[]bool{false, false, false, false, false, true})
		_, by := wtiPull(t, doc, long)
		r := by[SectionSNMP]
		if r.State != StateOK || !slices.ContainsFunc(r.Notes, func(n string) bool { return strings.Contains(n, "snmp contact: the unit shows a truncated value") }) {
			t.Errorf("%s: %q %q", r.StateText(), wtiLines(r), r.Notes)
		}
		// a truncated value that is not the rendered one's beginning differs
		other := withSection(long, SectionSNMP, []string{"snmp enable on", "snmp version v1-v2-only", "snmp read-only yes",
			"snmp contact Someone Else", "snmp location Example City", "snmp ro-community ro-community"},
			[]bool{false, false, false, false, false, true})
		_, by = wtiPull(t, doc, other)
		if by[SectionSNMP].State != StateDiffers {
			t.Errorf("not the same contact: %q", wtiLines(by[SectionSNMP]))
		}
	})

	t.Run("default services", func(t *testing.T) {
		// fewer services than the standard asks for is a difference
		doc := edit(t, noRW, "4.  Service Access:       Serial Port, Telnet/SSH, Web, RESTful API", "4.  Service Access:       Serial Port, Web")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionAAA]
		if r.State != StateDiffers || !wtiHas(r, "- tacacs default-services telnet-ssh") || !wtiHas(r, "+ tacacs default-services serial,web") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("debug on", func(t *testing.T) {
		doc := edit(t, noRW, "12. Debug:                      Off\n13. Ping Test", "12. Debug:                      On\n13. Ping Test")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionAAA]
		if r.State != StateDiffers || !wtiHas(r, "+ tacacs debug on") || !wtiHas(r, "- tacacs debug off") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		if WTISeverity(SectionAAA, "tacacs debug on") != "COSMETIC" || WTISeverity(SectionAAA, "tacacs session-module enabled") != "COSMETIC" ||
			WTISeverity(SectionSNMP, "snmp contact x") != "COSMETIC" || WTISeverity(SectionMgmtACL, "iptables -A INPUT -j DROP") != "ACCESS" {
			t.Errorf("severities")
		}
	})

	t.Run("a secret that is not defined", func(t *testing.T) {
		doc := edit(t, noRW, "4.  Secret Word:                (defined)", "4.  Secret Word:                (undefined)")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionAAA]
		if r.State != StateDiffers || !wtiHas(r, "- tacacs secret <secret> (not present)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("the tail", func(t *testing.T) {
		// no final DROP and no policies: the list restricts nothing
		doc := noRW
		for _, n := range []string{"21. iptables -A INPUT -j DROP", "22. iptables -A OUTPUT -j ACCEPT"} {
			doc = edit(t, doc, n, n[:3])
		}
		doc = edit(t, doc, "23. iptables -P INPUT DROP", "23.")
		doc = edit(t, doc, "24. iptables -P OUTPUT DROP", "24.")
		doc = edit(t, doc, "25. iptables -P FORWARD DROP", "25.")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionMgmtACL]
		if r.State != StateOK || r.Unmanaged != 0 || !slices.Contains(r.Notes, NoteWTINoTail) || slices.Contains(r.Notes, NoteWTITail) {
			t.Errorf("%s: %q %q", r.StateText(), wtiLines(r), r.Notes)
		}
		// a rule after the DROP: the DROP is no tail, and the rule is a finding
		doc = edit(t, noRW, "25. iptables -P FORWARD DROP", "25. iptables -A INPUT -s 198.51.100.9 -j ACCEPT")
		_, by = wtiPull(t, doc, exp)
		r = by[SectionMgmtACL]
		if r.State != StateDiffers || !wtiHas(r, "+ iptables -A INPUT -s 198.51.100.9 -j ACCEPT") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		for _, l := range r.Lines {
			if l.Op == OpExtra && l.Text == "iptables -A INPUT -j DROP" && l.Unmanaged {
				t.Errorf("a DROP with a rule after it is not the tail")
			}
		}
	})

	t.Run("the policies first", func(t *testing.T) {
		// the site's own order puts the policies first
		doc := noRW
		for i, l := range []string{"-P INPUT DROP", "-P OUTPUT DROP", "-P FORWARD DROP"} {
			doc = edit(t, doc, fmt.Sprintf("%d. iptables %s", 23+i, l), fmt.Sprintf("%d.", 23+i))
		}
		doc = edit(t, doc, "26.\n", "26. iptables -P INPUT DROP\n27. iptables -P OUTPUT DROP\n28. iptables -P FORWARD DROP\n")
		doc = edit(t, doc, "\n27.\n28.\n", "\n")
		_, by := wtiPull(t, doc, exp)
		if r := by[SectionMgmtACL]; r.StateText() != "ok (+5 unmanaged)" {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("a scope with no list", func(t *testing.T) {
		none := withSection(exp, SectionMgmtACL, nil, nil)
		_, by := wtiPull(t, noRW, none)
		r := by[SectionMgmtACL]
		if r.State != StateNA || len(r.Lines) != 25 || r.Lines[0].Op != OpInfo {
			t.Errorf("%s: %d lines", r.StateText(), len(r.Lines))
		}
	})

	t.Run("an snmp v3 scope", func(t *testing.T) {
		v3 := withSection(exp, SectionSNMP, []string{"snmp enable on", "snmp version v3-only", "snmp v3-user nms"}, nil)
		_, by := wtiPull(t, noRW, v3)
		r := by[SectionSNMP]
		if r.State != StateNA || !slices.Contains(r.Notes, NoteWTIv3) || len(r.Lines) == 0 || r.Lines[0].Op != OpInfo {
			t.Errorf("%s: %q %q", r.StateText(), wtiLines(r), r.Notes)
		}
	})

	t.Run("a RADIUS scope", func(t *testing.T) {
		rad := withSection(exp, SectionAAA, []string{
			"radius enable on", "radius primary 192.0.2.42", "radius primary-secret S3", "radius fallback-timer 3",
			"radius fallback-local off", "radius retries 3", "radius port 1812", "radius accounting-port 1813",
			"radius onetime-auth off", "radius default-access on", "radius debug off"},
			[]bool{false, false, true})
		// the unit has TACACS+ on and RADIUS off: every difference and no
		// unmanaged page
		_, by := wtiPull(t, noRW, rad)
		if r := by[SectionAAA]; r.State != StateDiffers || r.Unmanaged != 4 || !wtiHas(r, "+ tacacs enable on") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		// RADIUS is configured and TACACS+ is off: the TACACS+ page is the
		// device's own
		d := edit(t, noRW, "1.  Enable:                     On\n2.  Primary host/address:", "1.  Enable:                     Off\n2.  Primary host/address:")
		d = edit(t, d, "1.  Enable:                     Off\n2.  Primary Host/Address:       (undefined)\n3.  Primary Secret Word:        (undefined)",
			"1.  Enable:                     On\n2.  Primary Host/Address:       192.0.2.42\n3.  Primary Secret Word:        (defined)")
		_, by = wtiPull(t, d, rad)
		r := by[SectionAAA]
		if r.State != StateOK || r.Unmanaged != 13+4 {
			// the tacacs page: enable off, timer, fallback, port, default
			// access, two modules, name, debug, level, services (11), plus
			// the radius items the walkthrough leaves alone (session module,
			// one-time timer and type, message authenticator)
			t.Errorf("radius scope: %s %q", r.StateText(), wtiLines(r))
		}
	})
}

func TestWTIBreakGlass(t *testing.T) {
	exp := wtiExpected(t)
	base := labDocument(t)

	t.Run("an unrecorded local account is a finding", func(t *testing.T) {
		doc := edit(t, base, "localadmin\n\n\nEnter: username<CR>", "localadmin   backdoor\n\n\nEnter: username<CR>")
		doc += "# page: /F > 1 > 1 > backdoor\n" + strings.Replace(capture(t, "wti/33-user-directory-details.txt"), "localadmin", "backdoor", 2)
		ex, by := wtiPull(t, doc, exp)
		r := by[SectionBreakGlass]
		if r.State != StateDiffers || !wtiHas(r, "+ user backdoor level administrator") || !wtiHas(r, "+ user backdoor password <secret> (present, not compared)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		for _, l := range r.Lines {
			if l.Unmanaged {
				t.Errorf("%q is unmanaged: a local account is never the device's own", l.Text)
			}
		}
		if got := ex.Sections[SectionBreakGlass].Lines; len(got) != 4 {
			t.Errorf("%q", got)
		}
	})

	t.Run("a scope with no break-glass user lists the accounts", func(t *testing.T) {
		none := withSection(exp, SectionBreakGlass, nil, nil)
		_, by := wtiPull(t, base, none)
		r := by[SectionBreakGlass]
		if r.State != StateNA || !wtiHas(r, "~ user localadmin level administrator") || !wtiHas(r, "~ user localadmin password <secret> (present, not compared)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("a recorded user that is not on the unit", func(t *testing.T) {
		more := withSection(exp, SectionBreakGlass, []string{"user localadmin level administrator", "user localadmin password <PASSWORD>",
			"user spare level user", "user spare password <PASSWORD>"}, []bool{false, true, false, true})
		_, by := wtiPull(t, base, more)
		r := by[SectionBreakGlass]
		if r.State != StateDiffers || !wtiHas(r, "- user spare level user") || !wtiHas(r, "- user spare password <secret> (not present)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("the wrong level", func(t *testing.T) {
		doc := edit(t, base, "4.  Access Level:          Administrator", "4.  Access Level:          Super User")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionBreakGlass]
		if r.State != StateDiffers || !wtiHas(r, "- user localadmin level administrator") || !wtiHas(r, "+ user localadmin level superuser") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("an account without a password", func(t *testing.T) {
		doc := edit(t, base, "2.  Password:              (defined)", "2.  Password:              (undefined)")
		_, by := wtiPull(t, doc, exp)
		if r := by[SectionBreakGlass]; r.State != StateDiffers || !wtiHas(r, "- user localadmin password <secret> (not present)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("a key or an API token on the account", func(t *testing.T) {
		doc := edit(t, base, "3.  Authorization Keys:    (undefined)", "3.  Authorization Keys:    (defined)")
		_, by := wtiPull(t, doc, exp)
		if r := by[SectionBreakGlass]; r.State != StateDiffers || !wtiHas(r, "+ user localadmin keys <secret> (present, not compared)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("names that differ only in case", func(t *testing.T) {
		doc := strings.ReplaceAll(base, "localadmin", "LocalAdmin")
		_, by := wtiPull(t, doc, exp)
		r := by[SectionBreakGlass]
		if r.State != StateOK || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "differ only in case") {
			t.Errorf("%s: %q %q", r.StateText(), wtiLines(r), r.Notes)
		}
	})

	t.Run("the directory was not read", func(t *testing.T) {
		i := strings.Index(base, "# page: /F > 1 > 1\n")
		j := strings.Index(base, "# page: /J\n")
		doc := base[:i] + base[j:]
		ex, by := wtiPull(t, doc, exp)
		if _, ok := ex.Sections[SectionBreakGlass]; ok {
			t.Errorf("a section for users that were not read")
		}
		r := by[SectionBreakGlass]
		if r.State != StateNA || !slices.Contains(r.Notes, NoteWTIUsersNotRead) {
			t.Errorf("%s: %q", r.StateText(), r.Notes)
		}
	})

	t.Run("a listed user without its details", func(t *testing.T) {
		i := strings.Index(base, "# page: /F > 1 > 1 > localadmin\n")
		j := strings.Index(base, "# page: /J\n")
		if _, err := Extract("wti", base[:i]+base[j:], exp...); !errors.Is(err, ErrParse) || !strings.Contains(err.Error(), "lacks the page") {
			t.Errorf("%v", err)
		}
	})
}

func TestWTIExtractRefusals(t *testing.T) {
	base := labDocument(t)
	exp := wtiExpected(t)
	for name, c := range map[string]struct{ doc, in string }{
		"an unknown page":    {base + "# page: /N > 24\n" + capture(t, "wti/11-syslog.txt"), "SYSLOG"},
		"a page not asked":   {strings.Replace(base, "# page: /N > 29\n", "# page: /N > 28\n", 1), ""},
		"no header":          {capture(t, "wti/07-tacacs.txt"), ""},
		"a required page":    {strings.Replace(base, "# page: /N > 26\n", "# page: /J\n", 1), ""},
		"another version":    {strings.Replace(base, "Version 8.10", "Version 7.30", 1), "7.30"},
		"an incomplete list": {edit(t, base, "# page: /N > 5\n", "# page: /J\n"), ""},
	} {
		_, err := Extract("wti", c.doc, exp...)
		if !errors.Is(err, ErrParse) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if c.in != "" && !strings.Contains(err.Error(), c.in) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// an unknown page names its title and nothing of its lines
	doc := base + "# page: /N > 24\nSYSLOG:\n\n1. Client\n2. Server  SENTINEL-NOT-IN-ERROR\n\nEnter: #<CR> to change,\n"
	_, err := Extract("wti", doc)
	if !errors.Is(err, ErrParse) || !errors.Is(err, wti.ErrUnknownPage) || strings.Contains(err.Error(), "SENTINEL") || !strings.Contains(err.Error(), "SYSLOG") {
		t.Errorf("%v", err)
	}
}

// No community, secret, key or token the unit prints is in any stored,
// printed or JSON form.
func TestWTINoSecretIsKept(t *testing.T) {
	sentinels := []string{"SENTINEL-RO-COMMUNITY", "SENTINEL-RW-COMMUNITY", "SENTINEL-TRAP-COMMUNITY",
		"SENTINEL-KEY-TEXT", "SENTINEL-API-TOKEN", "SENTINEL-EXPECTED-SECRET", "SENTINEL-EXPECTED-COMMUNITY", "SENTINEL-EXPECTED-PASSWORD"}
	doc := labDocument(t)
	doc = edit(t, doc, "7. Read-Only Community:    ro-community", "7. Read-Only Community:    SENTINEL-RO-COMMUNITY")
	doc = edit(t, doc, "8. Read/Write Community:   rw-community", "8. Read/Write Community:   SENTINEL-RW-COMMUNITY")
	doc = edit(t, doc, "5. Community:          ro-community", "5. Community:          SENTINEL-TRAP-COMMUNITY")
	doc = edit(t, doc, "3.  Authorization Keys:    (undefined)", "3.  Authorization Keys:    SENTINEL-KEY-TEXT")
	doc = edit(t, doc, "8.  User API Token:        undefined", "8.  User API Token:        SENTINEL-API-TOKEN")
	exp := withSection(wtiExpected(t), SectionAAA, []string{"tacacs enable on", "tacacs secret SENTINEL-EXPECTED-SECRET"}, []bool{false, true})
	exp = withSection(exp, SectionSNMP, []string{"snmp enable on", "snmp ro-community SENTINEL-EXPECTED-COMMUNITY"}, []bool{false, true})
	exp = withSection(exp, SectionBreakGlass, []string{"user localadmin level administrator", "user localadmin password SENTINEL-EXPECTED-PASSWORD"}, []bool{false, true})

	ex, err := Extract("wti", doc, exp...)
	if err != nil {
		t.Fatal(err)
	}
	results, err := CompareAll(exp, ex)
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	seen = append(seen, sectionsText(ex), resultText(ex, results), allText(results), fmt.Sprintf("%+v %#v", ex, results))
	for _, r := range results {
		seen = append(seen, r.StateText(), strings.Join(r.Notes, "\n"), r.UnmanagedNote())
	}
	for _, v := range []any{ex, results} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, string(b))
	}
	// normalised, elided and fingerprinted forms, the stored file, the
	// records
	for _, s := range ex.Sections {
		n, err := Normalise("wti", s)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, strings.Join(n.Lines, "\n"))
	}
	for _, s := range exp {
		n, err := Normalise("wti", s)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, strings.Join(n.Lines, "\n"))
		e, err := Elide("wti", s.Lines, s.Secret)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, strings.Join(e, "\n"))
	}
	s := newStore(t)
	if err := s.SaveSections("lab-unit", "wti", ex.Sections); err != nil {
		t.Fatal(err)
	}
	if err := s.SavePlain("lab-unit", "wti", ex.Sections, at); err != nil {
		t.Fatal(err)
	}
	rec := Record{Vendor: "wti", Result: ResultOK, SecretsVisible: true, OS: "8.10"}
	if err := rec.SetSections(ex, results); err != nil {
		t.Fatal(err)
	}
	rb, _ := json.Marshal(rec)
	seen = append(seen, string(rb))
	files, _ := filepath.Glob(filepath.Join(s.Dir, "*"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, string(data))
	}
	all := strings.Join(seen, "\n")
	for _, sent := range sentinels {
		if strings.Contains(all, sent) {
			t.Errorf("%q is in a stored, printed or JSON form", sent)
		}
	}
	// the labels are there instead
	if !strings.Contains(all, "snmp ro-community <other:1>") || !strings.Contains(all, "snmp rw-community <other:2>") ||
		!strings.Contains(all, "snmp trap community <other:3>") {
		t.Errorf("labels:\n%s", sectionsText(ex))
	}
	if !strings.Contains(all, "user localadmin keys <secret>") || !strings.Contains(all, "user localadmin api-token <secret>") {
		t.Errorf("credential marks:\n%s", sectionsText(ex))
	}

	// a secret the unit prints in clear is refused, and the error holds no
	// value
	bad := edit(t, labDocument(t), "4.  Secret Word:                (defined)", "4.  Secret Word:                SENTINEL-CLEAR-SECRET")
	if _, err := Extract("wti", bad, exp...); !errors.Is(err, ErrParse) || strings.Contains(err.Error(), "SENTINEL") {
		t.Errorf("clear secret: %v", err)
	}
	bad = edit(t, labDocument(t), "2.  Password:              (defined)", "2.  Password:              SENTINEL-CLEAR-PASSWORD")
	if _, err := Extract("wti", bad, exp...); !errors.Is(err, ErrParse) || strings.Contains(err.Error(), "SENTINEL") {
		t.Errorf("clear password: %v", err)
	}
}

// The extracted sections go through the store and come back as they were,
// and the compared form is a fixed point of Normalise.
func TestWTISectionsRoundTrip(t *testing.T) {
	exp := wtiExpected(t)
	ex, err := Extract("wti", labDocument(t), exp...)
	if err != nil {
		t.Fatal(err)
	}
	s := newStore(t)
	if err := s.SaveSections("Lab-Unit", "wti", ex.Sections); err != nil {
		t.Fatal(err)
	}
	back, err := s.Sections("lab-unit", "wti")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range SectionNames {
		want, ok := ex.Sections[n]
		if !ok {
			if _, has := back[n]; has && n != SectionSystem {
				t.Errorf("%s: read back but not extracted", n)
			}
			continue
		}
		got := back[n]
		if !slices.Equal(got.Lines, want.Lines) || !slices.Equal(got.Secret, want.Secret) {
			t.Errorf("%s:\n got %q %v\nwant %q %v", n, got.Lines, got.Secret, want.Lines, want.Secret)
		}
		norm, err := Normalise("wti", want)
		if err != nil || !slices.Equal(norm.Lines, want.Lines) || !slices.Equal(norm.Secret, want.Secret) {
			t.Errorf("%s: Normalise is not a fixed point: %q %v", n, norm.Lines, err)
		}
		a, _ := Fingerprint("wti", want)
		b, _ := Fingerprint("wti", got)
		if a != b || a == "" {
			t.Errorf("%s: fingerprint %q %q", n, a, b)
		}
	}
	// a second save of what was read is the same file
	p := filepath.Join(s.Dir, "lab-unit.yaml")
	first, _ := os.ReadFile(p)
	if err := s.SaveSections("lab-unit", "wti", back); err != nil {
		t.Fatal(err)
	}
	if second, _ := os.ReadFile(p); string(first) != string(second) {
		t.Errorf("the file changed on a second save:\n%s\n---\n%s", first, second)
	}
	// the comparison of the stored sections is the comparison of the pull
	rec := &Record{Vendor: "wti", Result: ResultOK, SecretsVisible: true}
	res1, _ := CompareAll(exp, ex)
	res2, err := CompareAll(exp, rec.Extracted(back))
	if err != nil || len(res1) != len(res2) {
		t.Fatal(err)
	}
	for i := range res1 {
		if res1[i].StateText() != res2[i].StateText() || !slices.Equal(wtiLines(res1[i]), wtiLines(res2[i])) {
			t.Errorf("%s: %q vs %q", res1[i].Name, wtiLines(res1[i]), wtiLines(res2[i]))
		}
	}
	// the quoting of a text survives
	for _, l := range back[SectionSNMP].Lines {
		if strings.HasPrefix(l, "snmp contact") && l != `snmp contact "Example NOC"` {
			t.Errorf("contact: %q", l)
		}
	}
}

// The rendered side may hand statements in the forms the design lists: the
// slot number of an IP tables entry and the unquoted text are folded.
func TestWTIRenderedForms(t *testing.T) {
	got, err := Elide("wti", []string{
		"iptables 1 iptables -A INPUT -i lo -j ACCEPT",
		"iptables 2 -A INPUT -j DROP",
		"snmp contact Example NOC",
		"tacacs secret hunter2",
		"snmp ro-community lab-ro",
		"snmp trap community lab-ro",
		"user admin1 password hunter2",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"iptables -A INPUT -i lo -j ACCEPT", "iptables -A INPUT -j DROP", `snmp contact "Example NOC"`, "tacacs secret <secret>",
		"snmp ro-community <secret:1>", "snmp trap community <secret:1>", "user admin1 password <secret>",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	lab, err := CommunityLabels("wti", []string{"snmp enable on", "snmp ro-community lab-ro"})
	if err != nil || lab["<secret:1>"] != "lab-ro" {
		t.Errorf("%v %v", lab, err)
	}
	shapes := KeptShapes(FamilyWTI)
	if len(shapes) == 0 {
		t.Fatal("no shapes")
	}
	for _, s := range shapes {
		if !strings.HasPrefix(s.Row, "wti.") || s.Pattern == "" {
			t.Errorf("%+v", s)
		}
	}
}
