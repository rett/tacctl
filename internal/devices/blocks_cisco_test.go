package devices

// The scope's IOS snmp block in the walkthrough and in the managed sections
// (0.2.7): its statements follow the structured settings as live lines of the
// same step, are marked as the block's by position, and Managed and the
// walkthrough stay one renderer.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
)

const ciscoBlockText = `# the monitoring system's access, its trap host and the types it wants
ip access-list standard NMS-POLLERS
 permit host 192.0.2.50
 permit 198.51.100.0 0.0.0.255
snmp-server community nms-ro RO NMS-POLLERS
snmp-server host 198.51.100.7 version 2c nms-traps udp-port 162 config
snmp-server enable traps config
`

func parsedCiscoBlock(t *testing.T, text string) *blocks.IOSSNMPBlock {
	t.Helper()
	b, fs := blocks.LintIOSSNMP(text, blocks.LayerScope)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	return b
}

func ciscoInput(t *testing.T, profile managedProfile, v variant, block string) (Request, Data) {
	t.Helper()
	m, c := managedWorld(t)
	req, d := profile.input(m, c, v)
	if block != "" {
		d.Blocks = Blocks{Scope: profile.scope, CiscoSNMP: parsedCiscoBlock(t, block)}
	}
	return req, d
}

var ciscoBlockLines = []string{
	"ip access-list standard NMS-POLLERS",
	"  permit host 192.0.2.50",
	"  permit 198.51.100.0 0.0.0.255",
	"snmp-server community nms-ro RO NMS-POLLERS",
	"snmp-server host 198.51.100.7 version 2c nms-traps udp-port 162 config",
	"snmp-server enable traps config",
}

func TestCiscoBlockInTheWalkthroughAndManaged(t *testing.T) {
	lab := managedProfiles()[0]
	for _, v := range variants[:3] {
		req, d := ciscoInput(t, lab, v, ciscoBlockText)
		_, plain := ciscoInput(t, lab, v, "")
		secs := mustManaged(t, req, d)
		noBlock := mustManaged(t, req, plain)
		for _, s := range secs {
			o, ok := sectionOf(noBlock, s.Name)
			if !ok {
				t.Fatalf("%s: section %s is new", v.name, s.Name)
			}
			if s.Name != "snmp" {
				if !sectionEqual(s, o) || s.Block != nil {
					t.Errorf("%s: section %s changed", v.name, s.Name)
				}
				continue
			}
			if got := s.Lines[:len(o.Lines)]; !slices.Equal(got, o.Lines) {
				t.Errorf("%s: the structured lines moved:\n%s", v.name, strings.Join(got, "\n"))
			}
			if got := s.Lines[len(o.Lines):]; !slices.Equal(got, ciscoBlockLines) {
				t.Errorf("%s: the block's lines:\n%s\nwant\n%s", v.name, strings.Join(got, "\n"), strings.Join(ciscoBlockLines, "\n"))
			}
			if len(s.Block) != len(s.Lines) || len(s.Secret) != len(s.Lines) {
				t.Fatalf("%s: Block %d, Secret %d for %d lines", v.name, len(s.Block), len(s.Secret), len(s.Lines))
			}
			for i, l := range s.Lines {
				if fromBlock := i >= len(o.Lines); s.Block[i] != fromBlock {
					t.Errorf("%s: %q: Block is %v", v.name, l, s.Block[i])
				}
				// a community string and the community of a host are secrets
				wantSecret := strings.HasPrefix(l, "snmp-server community ") || strings.HasPrefix(l, "snmp-server host ") ||
					strings.HasPrefix(l, "snmp-server user ")
				if s.Secret[i] != wantSecret {
					t.Errorf("%s: %q: Secret is %v", v.name, l, s.Secret[i])
				}
			}
		}
		// the walkthrough: every statement is a live line of it, the comment
		// names the scope's block, and no comment holds a string
		text := renderText(t, req, d)
		live, commented := walkBody(t, text)
		for _, s := range secs {
			for _, l := range s.Lines {
				if s.Name != "breakglass" && !live[l] {
					t.Errorf("%s/%s: %q is not a live line of the walkthrough", v.name, s.Name, l)
				}
			}
		}
		if !commented["The snmp block of scope 'lab' (tacctl scope block lab cisco show snmp): its communities, access lists, trap hosts and trap types."] {
			t.Errorf("%s: no comment names the block", v.name)
		}
		for c := range commented {
			for _, bad := range []string{"nms-ro", "nms-traps"} {
				if strings.Contains(c, bad) {
					t.Errorf("%s: a comment holds a string: %q", v.name, c)
				}
			}
		}
		if renderText(t, req, plain) == text {
			t.Errorf("%s: the block changed nothing", v.name)
		}
	}
}

// The block is independent of the structured settings: with none configured
// the step says so and still renders the block.
func TestCiscoBlockWithoutStructuredSNMP(t *testing.T) {
	m, c := managedWorld(t)
	prof := managedProfile{scope: "lab", cidrs: []string{"192.0.2.0/24"}}
	req, d := prof.input(m, c, variants[0])
	d.Blocks = Blocks{Scope: "lab", CiscoSNMP: parsedCiscoBlock(t, ciscoBlockText)}
	snmp, ok := sectionOf(mustManaged(t, req, d), "snmp")
	if !ok {
		t.Fatal("no snmp section")
	}
	if !slices.Equal(snmp.Lines, ciscoBlockLines) {
		t.Errorf("the snmp section:\n%s", strings.Join(snmp.Lines, "\n"))
	}
	for i := range snmp.Lines {
		if !snmp.Block[i] {
			t.Errorf("%q is not marked as the block's", snmp.Lines[i])
		}
	}
	text := renderText(t, req, d)
	live, commented := walkBody(t, text)
	for _, l := range snmp.Lines {
		if !live[l] {
			t.Errorf("%q is not live", l)
		}
	}
	found := false
	for c := range commented {
		found = found || strings.Contains(c, "SNMP is not configured in tacctl for scope 'lab'")
		if strings.Contains(c, "nothing is rendered here") {
			t.Errorf("the step says nothing is rendered: %q", c)
		}
	}
	if !found {
		t.Errorf("the step does not say SNMP is not configured")
	}
}

// A block community whose string is the scope's own community, and a block
// access list that is the scope's management list: refused by Managed and by
// the walkthrough, without a string.
func TestCiscoBlockCollisions(t *testing.T) {
	lab := managedProfiles()[0]
	text := "snmp-server community other-example RO\nsnmp-server community " + lab.snmp.Community + " RO\n"
	req, d := ciscoInput(t, lab, variants[0], text)
	_, err := Managed(req, d)
	if err == nil {
		t.Fatal("Managed accepted it")
	}
	if strings.Contains(err.Error(), lab.snmp.Community) || strings.Contains(err.Error(), "other-example") {
		t.Errorf("the error holds a string: %v", err)
	}
	for _, want := range []string{"Community 2 of the SNMP block of scope 'lab'", "tacctl scope block lab cisco edit snmp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	var buf strings.Builder
	if err := Render(&buf, req, d); err == nil || strings.Contains(err.Error(), lab.snmp.Community) {
		t.Errorf("Render: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Render wrote %d bytes before it refused", buf.Len())
	}
	// SNMPv3 has no community string to clash with
	prod := managedProfiles()[1]
	req, d = ciscoInput(t, prod, variants[0], text)
	if _, err := Managed(req, d); err != nil {
		t.Errorf("v3: %v", err)
	}
	// the management access list is the scope's own
	req, d = ciscoInput(t, lab, variants[0], "ip access-list standard VTY-ACL\n permit 192.0.2.50\n")
	_, err = Managed(req, d)
	if err == nil || !strings.Contains(err.Error(), "Access list 1 of the SNMP block of scope 'lab'") {
		t.Errorf("a block list named as the management list: %v", err)
	}
}

// A device's own block laid over the scope's: the comment names the layers,
// and the refusal of a community that is the scope's own names the layer that
// holds it and its place there.
func TestCiscoBlockCommentAndRefusalNameTheDevicesLayer(t *testing.T) {
	lab := managedProfiles()[0]
	req, d := ciscoInput(t, lab, variants[0], "")
	d.Blocks = Blocks{Scope: "lab", Device: "rt1", CiscoSNMP: parsedCiscoBlock(t, ciscoBlockText), SNMPLayer: LayerScopeDevice}
	_, commented := walkBody(t, renderText(t, req, d))
	want := "The snmp block of scope 'lab' with the block of device 'rt1' over it (tacctl device block rt1 show snmp --effective): its communities, access lists, trap hosts and trap types."
	if !commented[want] {
		t.Errorf("no comment names the layers: %v", commented)
	}
	dev := parsedCiscoBlock(t, "snmp-server community "+lab.snmp.Community+" RO\n")
	d.Blocks = Blocks{Scope: "lab", Device: "rt1", CiscoSNMP: dev, DeviceCiscoSNMP: dev, SNMPLayer: LayerDevice}
	_, err := Managed(req, d)
	if err == nil || !strings.Contains(err.Error(), "Community 1 of the SNMP block of device 'rt1'") ||
		!strings.Contains(err.Error(), "tacctl device block rt1 edit snmp") {
		t.Errorf("the refusal: %v", err)
	}
}
