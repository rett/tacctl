package devconf

// The comparison of a WTI unit with what devices.Managed renders for its
// scope (the expected side the 0.2.7 pull uses): a unit that follows the
// walkthrough reads ok, and each irregularity of the design reads as the
// finding it is. wti_test.go does the same against a hand-written rendering
// of the lab unit; here the rendering is Managed's, and the unit's document
// is the lab unit's with its IP tables list made the rendered one.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devconf/wti"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/model"
)

// wtiManagedWorld is the request and data of the lab scope for the lab unit:
// the server's address the unit's pages name, its community and contact, two
// permitted ranges and one recorded account.
func wtiManagedWorld(t *testing.T, protocol string, snmp devices.SNMPInput) (devices.Request, devices.Data) {
	t.Helper()
	dir := t.TempDir()
	store, err := os.ReadFile("../../tests/fixtures/store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "store.yaml"), store, 0o600); err != nil {
		t.Fatal(err)
	}
	_, m, err := model.LoadStore(filepath.Join(dir, "store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "tacctl.yaml")
	if err := os.WriteFile(p, []byte("breakglass_scope:\n  lab:\n    users: [localadmin:admin]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := devices.Data{
		Model: m, Conf: conf.Load(p, []string{"tacacs", "radius"}), ServerIP: "192.0.2.42",
		ACL:  devices.MgmtACL{CIDRs: []string{"10.1.100.0/23", "10.0.20.0/24"}},
		SNMP: snmp,
	}
	req := devices.Request{Vendor: "wti", Scope: "lab", Protocol: protocol, Source: devices.SourceDefault}
	if protocol == devices.RADIUS {
		d.Radius = &devices.Radius{AuthPort: "1812", AcctPort: "1813", Secret: m.Scope("lab").Secret, VendorSent: "scope"}
	}
	return req, d
}

// wtiLabSNMP is the lab unit's SNMP page as the scope renders it.
func wtiLabSNMP() devices.SNMPInput {
	return devices.SNMPInput{Scope: "lab", Version: "v2c", Community: "ro-community", CredFrom: "scope",
		Contact: "Example NOC (555) 0100", Location: "Example City, Example State", Ranges: []string{"10.1.101.0/24"}}
}

func wtiManaged(t *testing.T, protocol string, snmp devices.SNMPInput) []devices.Section {
	t.Helper()
	req, d := wtiManagedWorld(t, protocol, snmp)
	secs, err := devices.Managed(req, d)
	if err != nil {
		t.Fatal(err)
	}
	return secs
}

// wtiIPTablesPages are the screens of the unit's IP tables page for a list
// (12 entries to a page, 48 in all), as the unit prints them.
func wtiIPTablesPages(entries []string) []string {
	const footer = "\n\n   Multiple iptables commands can be uploaded here in the format:\n   <iptables>\n" +
		"   COMMANDS (1 per line, 256 char max per command)\n   </iptables>\n" +
		"   WARNING: Upload will replace and overwrite all current entries.\n\n" +
		"Enter #<CR> to change, '<' for previous entries, '>' for next entries,\n" +
		"       <ESC> to return to previous menu ...\n"
	var pages []string
	for p := 0; p < 4; p++ {
		var b strings.Builder
		if p > 0 {
			b.WriteString(">\n\n")
		}
		b.WriteString("IPTABLES ENTRIES: IPv4\n\n")
		for i := p * 12; i < p*12+12; i++ {
			num := fmt.Sprintf("%d.", i+1)
			switch {
			case i >= len(entries):
				b.WriteString(num + "\n")
			case i < 9:
				b.WriteString(num + "  " + entries[i] + "\n")
			default:
				b.WriteString(num + " " + entries[i] + "\n")
			}
		}
		pages = append(pages, b.String()+footer)
	}
	return pages
}

// wtiUnitDocument is the lab unit's document with its IP tables list the
// rendering's (then the walkthrough's tail), edit applied to the list first,
// and no read/write community.
func wtiUnitDocument(t *testing.T, exp []devices.Section, edit func([]string) []string) string {
	t.Helper()
	var entries []string
	for _, s := range exp {
		if s.Name == SectionMgmtACL {
			entries = append(entries, s.Lines...)
		}
	}
	if len(entries) == 0 {
		t.Fatal("the rendering has no list")
	}
	for _, c := range wti.TailCommands() {
		entries = append(entries, "iptables "+c)
	}
	if edit != nil {
		entries = edit(slices.Clone(entries))
	}
	var b strings.Builder
	b.WriteString(labDocumentHeader)
	done := false
	for _, s := range labUnitScreens {
		if s.path == "/N > 5" {
			if !done {
				for _, p := range wtiIPTablesPages(entries) {
					b.WriteString("# page: /N > 5\n" + p)
				}
				done = true
			}
			continue
		}
		b.WriteString("# page: " + s.path + "\n" + strings.TrimRight(capture(t, s.file), "\n") + "\n")
	}
	return strings.Replace(b.String(), "8. Read/Write Community:   rw-community", "8. Read/Write Community:   (undefined)", 1)
}

func TestWTIManagedRenderingAgainstItsUnit(t *testing.T) {
	exp := wtiManaged(t, devices.TACACS, wtiLabSNMP())
	doc := wtiUnitDocument(t, exp, nil)

	t.Run("a unit that follows the walkthrough", func(t *testing.T) {
		ex, by := wtiPull(t, doc, exp)
		for name, want := range map[string]string{
			SectionAAA: "ok (+13 unmanaged)", SectionMgmtACL: "ok (+5 unmanaged)", SectionSNMP: "ok (+4 unmanaged)",
			SectionBreakGlass: "ok",
		} {
			if got := by[name].StateText(); got != want {
				t.Errorf("%s: %q, want %q: %q", name, got, want, wtiLines(by[name]))
			}
		}
		// every statement the rendering has is on the unit: no '-'
		for _, r := range by {
			for _, l := range r.Lines {
				if l.Op == OpMissing {
					t.Errorf("%s: %q is missing", r.Name, l.Text)
				}
			}
		}
		if !slices.ContainsFunc(by[SectionAAA].Notes, func(n string) bool { return strings.Contains(n, "default-services") }) {
			t.Errorf("aaa notes: %q", by[SectionAAA].Notes)
		}
		if !slices.Contains(by[SectionMgmtACL].Notes, NoteWTITail) {
			t.Errorf("mgmt-acl notes: %q", by[SectionMgmtACL].Notes)
		}
		// nothing of a secret in any shown form
		if all := resultText(ex, flat(by)); strings.Contains(all, "lab-secret-0123456789abcdef") || strings.Contains(all, "<PASSWORD>") {
			t.Errorf("a secret or placeholder in the comparison:\n%s", all)
		}
	})

	t.Run("a secondary host", func(t *testing.T) {
		d := edit(t, doc, "3.  Secondary host/address:\n", "3.  Secondary host/address:     192.0.2.43\n")
		_, by := wtiPull(t, d, exp)
		r := by[SectionAAA]
		if r.State != StateDiffers || !wtiHas(r, "+ tacacs secondary 192.0.2.43") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		for _, l := range r.Lines {
			if l.Op == OpExtra && l.Text == "tacacs secondary 192.0.2.43" && l.Unmanaged {
				t.Errorf("a second server is a finding")
			}
		}
		if WTISeverity(SectionAAA, "tacacs secondary 192.0.2.43") != "ACCESS" {
			t.Errorf("severity")
		}
	})

	t.Run("a reordered list", func(t *testing.T) {
		d := wtiUnitDocument(t, exp, func(l []string) []string {
			l[2], l[3] = l[3], l[2]
			return l
		})
		_, by := wtiPull(t, d, exp)
		r := by[SectionMgmtACL]
		if r.State != StateDiffers || !slices.ContainsFunc(wtiLines(r), func(l string) bool { return strings.HasPrefix(l, "! iptables: order differs") }) {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		// every entry is still there
		for _, l := range r.Lines {
			if l.Op == OpMissing || l.Op == OpExtra && !l.Unmanaged {
				t.Errorf("%c %q", l.Op, l.Text)
			}
		}
	})

	t.Run("an entry the rendering lacks", func(t *testing.T) {
		d := wtiUnitDocument(t, exp, func(l []string) []string {
			return slices.Insert(l, 4, "iptables -A INPUT -s 198.51.100.7 -p tcp --dport 22 -j ACCEPT")
		})
		_, by := wtiPull(t, d, exp)
		r := by[SectionMgmtACL]
		if r.State != StateDiffers || !wtiHas(r, "+ iptables -A INPUT -s 198.51.100.7 -p tcp --dport 22 -j ACCEPT") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		if WTISeverity(SectionMgmtACL, "iptables -A INPUT -s 198.51.100.7 -p tcp --dport 22 -j ACCEPT") != "ACCESS" {
			t.Errorf("severity")
		}
	})

	t.Run("RADIUS turned on for a TACACS+ scope", func(t *testing.T) {
		d := edit(t, doc, "1.  Enable:                     Off\n2.  Primary Host/Address:", "1.  Enable:                     On\n2.  Primary Host/Address:")
		_, by := wtiPull(t, d, exp)
		r := by[SectionAAA]
		if r.State != StateDiffers || !wtiHas(r, "+ radius enable on") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		for _, l := range r.Lines {
			if l.Op == OpExtra && strings.HasPrefix(l.Text, "radius enable") && l.Unmanaged {
				t.Errorf("the other protocol turned on is a finding")
			}
		}
		if WTISeverity(SectionAAA, "radius enable on") != "ACCESS" {
			t.Errorf("severity")
		}
	})

	t.Run("an account nobody recorded", func(t *testing.T) {
		d := edit(t, doc, "localadmin\n\n\nEnter: username<CR>", "localadmin   backdoor\n\n\nEnter: username<CR>")
		d += "# page: /F > 1 > 1 > backdoor\n" + strings.Replace(capture(t, "wti/33-user-directory-details.txt"), "localadmin", "backdoor", 2)
		_, by := wtiPull(t, d, exp)
		r := by[SectionBreakGlass]
		if r.State != StateDiffers || !wtiHas(r, "+ user backdoor level administrator") || !wtiHas(r, "+ user backdoor password <secret> (present, not compared)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
		for _, l := range r.Lines {
			if l.Unmanaged {
				t.Errorf("%q is the device's own", l.Text)
			}
		}
		if WTISeverity(SectionBreakGlass, "user backdoor level administrator") != "ACCESS" {
			t.Errorf("severity")
		}
	})

	t.Run("a read/write community", func(t *testing.T) {
		d := strings.Replace(doc, "8. Read/Write Community:   (undefined)", "8. Read/Write Community:   rw-community", 1)
		_, by := wtiPull(t, d, exp)
		r := by[SectionSNMP]
		if r.State != StateDiffers || !wtiHas(r, "+ snmp rw-community <other:1> (present, not compared)") {
			t.Errorf("%s: %q", r.StateText(), wtiLines(r))
		}
	})

	t.Run("a unit with no tail", func(t *testing.T) {
		d := wtiUnitDocument(t, exp, func(l []string) []string { return l[:len(l)-len(wti.TailCommands())] })
		_, by := wtiPull(t, d, exp)
		r := by[SectionMgmtACL]
		if r.State != StateOK || r.Unmanaged != 0 || !slices.Contains(r.Notes, NoteWTINoTail) {
			t.Errorf("%s: %q %q", r.StateText(), wtiLines(r), r.Notes)
		}
	})

	t.Run("a scope with SNMPv3", func(t *testing.T) {
		v3 := devices.SNMPInput{Scope: "lab", Version: "v3", V3User: "tacctl-ro", V3Auth: "sha", V3Priv: "aes128",
			V3AuthPass: "auth-pass-0123", V3PrivPass: "priv-pass-4567", CredFrom: "scope", Contact: "Example NOC (555) 0100", Location: "Example City, Example State"}
		exp3 := wtiManaged(t, devices.TACACS, v3)
		_, by := wtiPull(t, doc, exp3)
		r := by[SectionSNMP]
		if r.State != StateNA || !slices.Contains(r.Notes, NoteWTIv3) {
			t.Errorf("%s: %q %q", r.StateText(), wtiLines(r), r.Notes)
		}
		// no passphrase in what the comparison shows
		if all := allText(flat(by)); strings.Contains(all, "auth-pass-0123") || strings.Contains(all, "priv-pass-4567") {
			t.Errorf("a passphrase in the comparison:\n%s", all)
		}
	})
}

// A RADIUS scope's unit: RADIUS on with the rendered values, TACACS+ off, so
// its whole page and the RADIUS items the walkthrough leaves alone are the
// unit's own.
func TestWTIManagedRadiusAgainstItsUnit(t *testing.T) {
	exp := wtiManaged(t, devices.RADIUS, wtiLabSNMP())
	doc := wtiUnitDocument(t, exp, nil)
	doc = edit(t, doc, "1.  Enable:                     On\n2.  Primary host/address:", "1.  Enable:                     Off\n2.  Primary host/address:")
	doc = edit(t, doc, "1.  Enable:                     Off\n2.  Primary Host/Address:       (undefined)\n3.  Primary Secret Word:        (undefined)",
		"1.  Enable:                     On\n2.  Primary Host/Address:       192.0.2.42\n3.  Primary Secret Word:        (defined)")
	doc = edit(t, doc, "7.  Fallback Local:             Off", "7.  Fallback Local:             On (Transport failure)")
	_, by := wtiPull(t, doc, exp)
	if r := by[SectionAAA]; r.State != StateOK || r.Unmanaged != 13+4 {
		t.Errorf("aaa: %s (%d unmanaged): %q", r.StateText(), r.Unmanaged, wtiLines(r))
	}
	// the secret is defined and the primary is the server's: nothing of the
	// rendering is missing
	for _, l := range by[SectionAAA].Lines {
		if l.Op == OpMissing {
			t.Errorf("missing %q", l.Text)
		}
	}
	// a different fallback is a difference, an ACCESS finding
	d := edit(t, doc, "7.  Fallback Local:             On (Transport failure)", "7.  Fallback Local:             Off")
	_, by = wtiPull(t, d, exp)
	r := by[SectionAAA]
	if r.State != StateDiffers || !wtiHas(r, "- radius fallback-local on-transport-failure") || !wtiHas(r, "+ radius fallback-local off") {
		t.Errorf("%s: %q", r.StateText(), wtiLines(r))
	}
}

func flat(by map[string]SectionResult) []SectionResult {
	var out []SectionResult
	for _, n := range SectionNames {
		if r, ok := by[n]; ok {
			out = append(out, r)
		}
	}
	return out
}

// Every golden of what Managed renders for a unit, taken as the unit's own
// statements, reads back as itself: each section ok, and nothing of the
// scope's secrets, the communities or the placeholders in what the
// comparison shows. (A unit prints menu pages, not configuration lines, so
// the Junos and IOS round trip over configuration text has no WTI case; the
// pages are in TestWTIManagedRenderingAgainstItsUnit.)
func TestWTIManagedGoldensAreTheirOwnUnit(t *testing.T) {
	files, err := filepath.Glob("../../tests/fixtures/golden/managed.wti*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no managed goldens in this tree")
	}
	for _, f := range files {
		base := filepath.Base(f)
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var expected []devices.Section
		var cur *devices.Section
		for _, l := range strings.Split(string(data), "\n") {
			switch {
			case strings.HasPrefix(l, "["):
				name, rest, _ := strings.Cut(strings.TrimPrefix(l, "["), "]")
				if strings.TrimSpace(rest) == "not rendered" {
					cur = nil
					continue
				}
				expected = append(expected, devices.Section{Name: name})
				cur = &expected[len(expected)-1]
			case (strings.HasPrefix(l, "| ") || strings.HasPrefix(l, "* ")) && cur != nil:
				cur.Lines = append(cur.Lines, l[2:])
				cur.Secret = append(cur.Secret, l[0] == '*')
			}
		}
		var shown strings.Builder
		for _, s := range expected {
			// the statements as a unit's pages give them back: a secret as
			// its presence mark
			dev := devices.Section{Name: s.Name}
			for i, l := range s.Lines {
				if f := strings.Fields(l); s.Secret[i] && len(f) > 0 && !strings.Contains(l, "ro-community") {
					f[len(f)-1] = "<secret>"
					l = strings.Join(f, " ")
				}
				dev.Lines = append(dev.Lines, l)
			}
			r, err := Compare(FamilyWTI, s, dev, true)
			if err != nil {
				t.Fatal(err)
			}
			want := StateOK
			if slices.ContainsFunc(s.Lines, wtiHasV3) {
				want = StateNA
			}
			if r.State != want || r.Unmanaged != 0 {
				t.Errorf("%s [%s] %s, want %s:\n%s", base, s.Name, r.State, want, allText([]SectionResult{r}))
			}
			shown.WriteString(allText([]SectionResult{r}))
		}
		for _, leak := range []string{"-secret-0123456789abcdef", "<PASSWORD>", "lab-ro-community", "auth-pass-0123", "priv-pass-4567"} {
			if strings.Contains(shown.String(), leak) {
				t.Errorf("%s: %q is in what the comparison shows", base, leak)
			}
		}
	}
}

// wtiHasV3 is a statement about SNMPv3 users.
func wtiHasV3(l string) bool { return strings.HasPrefix(l, "snmp v3 ") }
