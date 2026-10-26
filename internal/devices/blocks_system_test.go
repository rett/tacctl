package devices

// The scope's system configuration block in the walkthrough and in the
// managed sections (0.2.7): its statements follow the SNMP step as the live
// lines of a section of their own, rendered only where a block is in force,
// and Managed and the walkthrough stay one renderer.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
)

const systemBlockText = `# the lab's system settings
set system login message <<'EOF'
Authorized use only.
  *** jsw1.lab.example.net ***
Say "hello" and back\slash
EOF
set system domain-name lab.example.net
set system domain-search lab.example.net
set system domain-search example.net
set system time-zone UTC
set system name-server 192.0.2.53
set system name-server 198.51.100.53
set system ntp server 192.0.2.123 prefer version 4 key 1
set system ntp boot-server 192.0.2.123
set system ntp source-address 192.0.2.250
set system ntp authentication-key 1 type md5 value ntp-key-0123456789
set system ntp trusted-key 1
`

func parsedSystemBlock(t *testing.T, text string) *blocks.SystemBlock {
	t.Helper()
	b, fs := blocks.LintSystem(text, blocks.LayerDevice)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	return blocks.ResolveSystem(nil, b, nil)
}

func systemInput(t *testing.T, profile managedProfile, v variant, text string) (Request, Data) {
	t.Helper()
	m, c := managedWorld(t)
	req, d := profile.input(m, c, v)
	if text != "" {
		d.Blocks = Blocks{Scope: profile.scope, System: parsedSystemBlock(t, text)}
	}
	return req, d
}

func TestSystemBlockInTheWalkthroughAndManaged(t *testing.T) {
	lab := managedProfiles()[0]
	for _, v := range []variant{variants[3], variants[4]} {
		req, d := systemInput(t, lab, v, systemBlockText)
		_, plain := systemInput(t, lab, v, "")
		want := blocks.SystemStatements(d.Blocks.System)
		if len(want) != 12 {
			t.Fatalf("statements: %q", want)
		}

		secs := mustManaged(t, req, d)
		noBlock := mustManaged(t, req, plain)

		// every other section is as it was, and the new one sits after snmp
		var names []string
		for _, s := range secs {
			names = append(names, s.Name)
			if s.Name == "system" {
				continue
			}
			o, ok := sectionOf(noBlock, s.Name)
			if !ok || !sectionEqual(s, o) || s.Block != nil {
				t.Errorf("%s: section %s changed", v.name, s.Name)
			}
		}
		if i := slices.Index(names, "system"); i < 0 || names[i-1] != "snmp" {
			t.Errorf("%s: sections %v", v.name, names)
		}
		for _, s := range noBlock {
			if s.Name == "system" {
				t.Errorf("%s: a scope with no block has a system section", v.name)
			}
		}

		sys, ok := sectionOf(secs, "system")
		if !ok {
			t.Fatalf("%s: no system section", v.name)
		}
		if !slices.Equal(sys.Lines, want) {
			t.Errorf("%s: the lines:\n%s\nwant\n%s", v.name, strings.Join(sys.Lines, "\n"), strings.Join(want, "\n"))
		}
		if len(sys.Block) != len(sys.Lines) || len(sys.Secret) != len(sys.Lines) {
			t.Fatalf("%s: Block %d, Secret %d for %d lines", v.name, len(sys.Block), len(sys.Secret), len(sys.Lines))
		}
		for i, l := range sys.Lines {
			if !sys.Block[i] {
				t.Errorf("%s: %q is not marked as the block's", v.name, l)
			}
			// the key is a secret, the message and the rest are none
			if wantSecret := strings.HasPrefix(l, "set system ntp authentication-key "); sys.Secret[i] != wantSecret {
				t.Errorf("%s: %q: Secret is %v", v.name, l, sys.Secret[i])
			}
		}
		if got := sys.Lines[0]; got != `set system login message "Authorized use only.\n  *** jsw1.lab.example.net ***\nSay \"hello\" and back\\slash"` {
			t.Errorf("%s: the message statement %q", v.name, got)
		}

		// the walkthrough: every statement is a live line of it, the comment
		// names the scope's block, and no comment holds a word of the message
		// or the key
		text := renderText(t, req, d)
		live, commented := walkBody(t, text)
		for _, l := range sys.Lines {
			if !live[l] {
				t.Errorf("%s: %q is not a live line of the walkthrough", v.name, l)
			}
		}
		if !commented["The system block of scope 'lab' (tacctl scope block lab juniper show system): the login message, domain, time zone, name servers and NTP."] {
			t.Errorf("%s: no comment names the block", v.name)
		}
		for c := range commented {
			for _, bad := range []string{"Authorized", "jsw1.lab", "Say \"", "back\\slash", "ntp-key-0123456789"} {
				if strings.Contains(c, bad) {
					t.Errorf("%s: a comment holds %q: %q", v.name, bad, c)
				}
			}
		}
		for _, h := range []string{"show configuration system login message", "show configuration system domain-name",
			"show configuration system domain-search", "show configuration system time-zone", "show configuration system name-server",
			"show configuration system ntp"} {
			if !strings.Contains(text, h) {
				t.Errorf("%s: the verify commands lack %q", v.name, h)
			}
		}
		// the step comes after the SNMP lines: the template's steps keep their
		// numbers
		if strings.Index(text, "# Step 6: (optional) NETCONF") < strings.Index(text, "The system block of scope 'lab'") {
			t.Errorf("%s: the system block is after Step 6", v.name)
		}

		// without a block the walkthrough is as it was, and nothing in it is a
		// system statement
		withText := text
		plainText := renderText(t, req, plain)
		if plainText == withText {
			t.Errorf("%s: the block changed nothing", v.name)
		}
		if strings.Contains(plainText, "set system ntp") || strings.Contains(plainText, "set system login message") {
			t.Errorf("%s: a walkthrough with no block holds system statements", v.name)
		}

		// and the snmp section is still the structured settings alone
		a, _ := sectionOf(secs, "snmp")
		b, _ := sectionOf(noBlock, "snmp")
		if !sectionEqual(a, b) {
			t.Errorf("%s: the snmp section changed", v.name)
		}
	}
}

// Both blocks at once: the snmp block's statements stay in the snmp section,
// the system block's in the system section.
func TestSystemBlockBesideTheSNMPBlock(t *testing.T) {
	lab := managedProfiles()[0]
	req, d := systemInput(t, lab, variants[3], systemBlockText)
	d.Blocks.SNMP = parsedBlock(t, blockText)
	secs := mustManaged(t, req, d)
	snmp, _ := sectionOf(secs, "snmp")
	sys, _ := sectionOf(secs, "system")
	for _, l := range snmp.Lines {
		if strings.HasPrefix(l, "set system ") {
			t.Errorf("a system statement in the snmp section: %q", l)
		}
	}
	for _, l := range sys.Lines {
		if strings.HasPrefix(l, "set snmp ") {
			t.Errorf("a snmp statement in the system section: %q", l)
		}
	}
	text := renderText(t, req, d)
	live, _ := walkBody(t, text)
	for _, s := range []devSection{{"snmp", snmp.Lines}, {"system", sys.Lines}} {
		for _, l := range s.lines {
			if !live[l] {
				t.Errorf("%s: %q is not live", s.name, l)
			}
		}
	}
}

type devSection struct {
	name  string
	lines []string
}

// A block of delete lines only renders no statement: no section.
func TestSystemBlockOfDeleteLinesOnly(t *testing.T) {
	lab := managedProfiles()[0]
	req, d := systemInput(t, lab, variants[3], "delete system ntp\n")
	if st := blocks.SystemStatements(d.Blocks.System); len(st) != 0 {
		t.Fatalf("statements: %q", st)
	}
	for _, s := range mustManaged(t, req, d) {
		if s.Name == "system" {
			t.Errorf("a system section for a block with no statement")
		}
	}
}

// IOS blocks are the release after: a Cisco request ignores the system block.
func TestCiscoIgnoresTheSystemBlock(t *testing.T) {
	lab := managedProfiles()[0]
	for _, v := range variants[:3] {
		m, c := managedWorld(t)
		req, d := lab.input(m, c, v)
		want := mustManaged(t, req, d)
		wantText := renderText(t, req, d)
		d.Blocks = Blocks{Scope: "lab", System: parsedSystemBlock(t, systemBlockText)}
		got := mustManaged(t, req, d)
		if !slices.EqualFunc(want, got, sectionEqual) {
			t.Errorf("%s: Managed changed", v.name)
		}
		if renderText(t, req, d) != wantText {
			t.Errorf("%s: the walkthrough changed", v.name)
		}
	}
}
