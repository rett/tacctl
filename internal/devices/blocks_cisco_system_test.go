package devices

// The scope's IOS system block in the walkthrough and in the managed sections
// (0.2.7): its lines follow the SNMP step, are the section 'system' of
// Managed, all marked as the block's, and the walkthrough and Managed stay
// one renderer. The banner is text between its delimiters.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
)

const ciscoSystemText = `banner login <<'EOF'
Authorized use only.

! Activity is logged.
  Indented, with a blank line above.
EOF
ip domain name lab.example.net
ip domain list lab.example.net
clock timezone CET 1
ip name-server 192.0.2.53 192.0.2.54
ntp authentication-key 5 md5 lab-ntp-key-0123
ntp trusted-key 5
ntp server 192.0.2.123 version 4 key 5 prefer
ntp authenticate
`

var ciscoSystemLines = []string{
	"banner login ^",
	"Authorized use only.",
	"",
	"! Activity is logged.",
	"  Indented, with a blank line above.",
	"^",
	"ip domain name lab.example.net",
	"ip domain list lab.example.net",
	"clock timezone CET 1",
	"ip name-server 192.0.2.53",
	"ip name-server 192.0.2.54",
	"ntp authentication-key 5 md5 lab-ntp-key-0123",
	"ntp trusted-key 5",
	"ntp server 192.0.2.123 version 4 key 5 prefer",
	"ntp authenticate",
}

func parsedCiscoSystem(t *testing.T, text string) *blocks.IOSSystemBlock {
	t.Helper()
	b, fs := blocks.LintIOSSystem(text, blocks.LayerScope)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	return b
}

func ciscoSystemInput(t *testing.T, profile managedProfile, v variant, block string) (Request, Data) {
	t.Helper()
	m, c := managedWorld(t)
	req, d := profile.input(m, c, v)
	if block != "" {
		d.Blocks = Blocks{Scope: profile.scope, CiscoSystem: parsedCiscoSystem(t, block)}
	}
	return req, d
}

func TestCiscoSystemInTheWalkthroughAndManaged(t *testing.T) {
	lab := managedProfiles()[0]
	for _, v := range variants[:3] {
		req, d := ciscoSystemInput(t, lab, v, ciscoSystemText)
		_, plain := ciscoSystemInput(t, lab, v, "")
		secs := mustManaged(t, req, d)
		noBlock := mustManaged(t, req, plain)
		// the sections of a device with none are the same, and the system
		// section is new
		for _, s := range noBlock {
			if s.Name == "system" {
				t.Fatalf("%s: a system section with no block", v.name)
			}
			g, ok := sectionOf(secs, s.Name)
			if !ok || !sectionEqual(g, s) {
				t.Errorf("%s: section %s changed", v.name, s.Name)
			}
		}
		sys, ok := sectionOf(secs, "system")
		if !ok {
			t.Fatalf("%s: no system section", v.name)
		}
		if !slices.Equal(sys.Lines, ciscoSystemLines) {
			t.Errorf("%s: the system section:\n%s\nwant\n%s", v.name, strings.Join(sys.Lines, "\n"), strings.Join(ciscoSystemLines, "\n"))
		}
		if len(sys.Block) != len(sys.Lines) || len(sys.Secret) != len(sys.Lines) {
			t.Fatalf("%s: Block %d, Secret %d for %d lines", v.name, len(sys.Block), len(sys.Secret), len(sys.Lines))
		}
		for i, l := range sys.Lines {
			if !sys.Block[i] {
				t.Errorf("%s: %q is not marked as the block's", v.name, l)
			}
			if want := strings.HasPrefix(l, "ntp authentication-key "); sys.Secret[i] != want {
				t.Errorf("%s: %q: Secret is %v", v.name, l, sys.Secret[i])
			}
		}
		// the section comes after snmp, before netconf
		var order []string
		for _, s := range secs {
			order = append(order, s.Name)
		}
		if i := slices.Index(order, "system"); i < 1 || order[i-1] != "snmp" {
			t.Errorf("%s: the order of the sections: %q", v.name, order)
		}
		// the walkthrough holds the block's lines one after another, the
		// banner whole (a blank line and a bang line are in it), after the
		// SNMP step and before the access list of the lines
		text := renderText(t, req, d)
		if !strings.Contains(text, strings.Join(ciscoSystemLines, "\n")+"\n") {
			t.Errorf("%s: the walkthrough lacks the block's lines as they are:\n%s", v.name, text)
		}
		iSNMP, iSys := strings.Index(text, "snmp-server community "), strings.Index(text, "banner login ^\n")
		iACL := strings.Index(text, "ip access-list standard VTY-ACL")
		if iSNMP < 0 || iSys < iSNMP || iACL < iSys {
			t.Errorf("%s: the place of the block: snmp %d, system %d, acl %d", v.name, iSNMP, iSys, iACL)
		}
		_, commented := walkBody(t, text)
		if !commented["The system block of scope 'lab' (tacctl scope block lab cisco show system): the login banner, domain, time zone, name servers and NTP."] {
			t.Errorf("%s: no comment names the block: %v", v.name, commented)
		}
		for c := range commented {
			if strings.Contains(c, "Authorized use only") || strings.Contains(c, "lab-ntp-key") {
				t.Errorf("%s: a comment holds a value: %q", v.name, c)
			}
		}
		// the Step 0 line for the domain names the block, not a placeholder
		if strings.Contains(text, "ip domain name <DOMAIN>") || !strings.Contains(text, "ip domain name lab.example.net  ") {
			t.Errorf("%s: the Step 0 domain line:\n%s", v.name, text)
		}
		if text == renderText(t, req, plain) {
			t.Errorf("%s: the block changed nothing", v.name)
		}
	}
}

// A device in the IOS 12.x syntax stores 'ntp server H version 3' bare: the
// walkthrough and the managed section render the bare line for a legacy
// request and the line as typed for a modern one, one renderer for both.
func TestCiscoSystemNTPVersion3InTheDialects(t *testing.T) {
	lab := managedProfiles()[0]
	const block = "ntp server 192.0.2.123 version 3 key 5 prefer\nntp server 192.0.2.124 version 3\nntp server 192.0.2.125 version 2\n"
	typed := []string{"ntp server 192.0.2.123 version 3 key 5 prefer", "ntp server 192.0.2.124 version 3", "ntp server 192.0.2.125 version 2"}
	bare := []string{"ntp server 192.0.2.123 key 5 prefer", "ntp server 192.0.2.124", "ntp server 192.0.2.125 version 2"}
	for _, c := range []struct {
		v    variant
		want []string
	}{{variants[0], typed}, {variants[1], bare}, {variants[2], typed}} {
		req, d := ciscoSystemInput(t, lab, c.v, block)
		sys, ok := sectionOf(mustManaged(t, req, d), "system")
		if !ok {
			t.Fatalf("%s: no system section", c.v.name)
		}
		if !slices.Equal(sys.Lines, c.want) {
			t.Errorf("%s: the system section:\n%s\nwant\n%s", c.v.name, strings.Join(sys.Lines, "\n"), strings.Join(c.want, "\n"))
		}
		if text := renderText(t, req, d); !strings.Contains(text, strings.Join(c.want, "\n")+"\n") {
			t.Errorf("%s: the walkthrough lacks the lines:\n%s", c.v.name, text)
		}
	}
	// the legacy walkthrough does not hold the line the device would not keep
	req, d := ciscoSystemInput(t, lab, variants[1], block)
	if text := renderText(t, req, d); strings.Contains(text, "192.0.2.124 version 3") || strings.Contains(text, "192.0.2.123 version 3") {
		t.Errorf("the legacy walkthrough types version 3:\n%s", text)
	}
}

// With no block the walkthrough keeps the placeholder, and a block of another
// vendor is no business of this one.
func TestCiscoSystemOtherVendorAndNoBlock(t *testing.T) {
	lab := managedProfiles()[0]
	req, d := ciscoSystemInput(t, lab, variants[0], "")
	if text := renderText(t, req, d); !strings.Contains(text, "ip domain name <DOMAIN>") {
		t.Error("the placeholder is gone with no block")
	}
	// a Junos system block in Data is not rendered for a Cisco request
	jb, fs := blocks.LintSystem("set system domain-name lab.example.net\n", blocks.LayerScope)
	if blocks.HasErrors(fs) {
		t.Fatal(fs)
	}
	d.Blocks = Blocks{Scope: "lab", System: jb}
	if _, ok := sectionOf(mustManaged(t, req, d), "system"); ok {
		t.Error("a Cisco request renders the Junos system block")
	}
	// and the IOS system block is not rendered for a Junos one
	jreq, jd := ciscoSystemInput(t, lab, variants[3], "")
	jd.Blocks = Blocks{Scope: "lab", CiscoSystem: parsedCiscoSystem(t, ciscoSystemText)}
	if s, ok := sectionOf(mustManaged(t, jreq, jd), "system"); ok {
		t.Errorf("a Junos request renders the IOS system block: %v", s)
	}
}

// A device's own block laid over the scope's: the comment names the layers.
func TestCiscoSystemCommentNamesTheDevicesLayer(t *testing.T) {
	lab := managedProfiles()[0]
	req, d := ciscoSystemInput(t, lab, variants[0], "")
	d.Blocks = Blocks{Scope: "lab", Device: "rt1", CiscoSystem: parsedCiscoSystem(t, ciscoSystemText), SystemLayer: LayerScopeDevice}
	_, commented := walkBody(t, renderText(t, req, d))
	want := "The system block of scope 'lab' with the block of device 'rt1' over it (tacctl device block rt1 show system --effective): the login banner, domain, time zone, name servers and NTP."
	if !commented[want] {
		t.Errorf("no comment names the layers: %v", commented)
	}
}

// The delimiter is the first candidate the text does not contain, and the
// walkthrough says which.
func TestCiscoSystemBannerDelimiter(t *testing.T) {
	lab := managedProfiles()[0]
	req, d := ciscoSystemInput(t, lab, variants[0], "banner login <<'EOF'\ncaret ^ and tilde ~\nEOF\n")
	sys, _ := sectionOf(mustManaged(t, req, d), "system")
	if !slices.Equal(sys.Lines, []string{"banner login %", "caret ^ and tilde ~", "%"}) {
		t.Errorf("%q", sys.Lines)
	}
	_, commented := walkBody(t, renderText(t, req, d))
	found := false
	for c := range commented {
		found = found || strings.Contains(c, "The banner is typed with the delimiter %, the first of ^ ~ % # @ $ &")
	}
	if !found {
		t.Errorf("the walkthrough does not name the delimiter: %v", commented)
	}
}

// DropBlank leaves a login banner alone: a blank line of it is text, any
// other blank line is dropped as it was.
func TestDropBlankKeepsTheBannersText(t *testing.T) {
	in := "a\n\n   \nbanner login ^\nline 1\n\n   \n! line 4\n^\n\nb\n\nbanner login #\nx\n#\n"
	want := "a\nbanner login ^\nline 1\n\n   \n! line 4\n^\nb\nbanner login #\nx\n#\n"
	if got := DropBlank(in); got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	// a banner of a template's own, with another delimiter, is as it was
	if got := DropBlank("banner login ^C\n\nx\n^C\n"); got != "banner login ^C\nx\n^C\n" {
		t.Errorf("%q", got)
	}
}
