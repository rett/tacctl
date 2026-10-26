package devices

// The scope's snmp configuration block in the walkthrough and in the managed
// sections (0.2.7): its statements follow the structured settings as live
// lines of the same step, are marked as the block's, and Managed and the
// walkthrough stay one renderer.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
)

const blockText = `# the monitoring system's own community, and its trap group
set snmp community nms-ro authorization read-only
set snmp community nms-ro clients 192.0.2.50/32
set snmp community nms-ro clients 198.51.100.0/24
set snmp trap-group nms-traps version v2
set snmp trap-group nms-traps categories authentication
set snmp trap-group nms-traps targets 198.51.100.7
set snmp trap-options agent-address outgoing-interface
`

func parsedBlock(t *testing.T, text string) *blocks.SNMPBlock {
	t.Helper()
	b, fs := blocks.Lint(text, blocks.LayerScope)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	return b
}

func juniperInput(t *testing.T, profile managedProfile, v variant, block string) (Request, Data) {
	t.Helper()
	m, c := managedWorld(t)
	req, d := profile.input(m, c, v)
	if block != "" {
		d.Blocks = Blocks{Scope: profile.scope, SNMP: parsedBlock(t, block)}
	}
	return req, d
}

func TestBlockInTheWalkthroughAndManaged(t *testing.T) {
	lab := managedProfiles()[0]
	for _, v := range []variant{variants[3], variants[4]} {
		req, d := juniperInput(t, lab, v, blockText)
		_, plain := juniperInput(t, lab, v, "")
		want := blocks.Statements(d.Blocks.SNMP)
		if len(want) != 7 {
			t.Fatalf("statements: %q", want)
		}

		// the sections: the snmp section is the structured one and the block's
		secs := mustManaged(t, req, d)
		noBlock := mustManaged(t, req, plain)
		for _, s := range secs {
			o, ok := sectionOf(noBlock, s.Name)
			if !ok {
				t.Fatalf("%s: section %s is new", v.name, s.Name)
			}
			if s.Name == "mgmt-acl" {
				// the filter's udp 161 term also permits the clients of the
				// block's communities: nothing else of the section changes
				drop := func(sec Section) Section {
					var out Section
					for i, l := range sec.Lines {
						if strings.Contains(l, " term permit-snmp from source-address ") {
							continue
						}
						out.Lines = append(out.Lines, l)
						out.Secret = append(out.Secret, sec.Secret[i])
					}
					return out
				}
				a, b := drop(s), drop(o)
				if !slices.Equal(a.Lines, b.Lines) || s.Block != nil {
					t.Errorf("%s: section %s changed beyond its snmp permits", v.name, s.Name)
				}
				continue
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
			if got := s.Lines[len(o.Lines):]; !slices.Equal(got, want) {
				t.Errorf("%s: the block's lines:\n%s\nwant\n%s", v.name, strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if len(s.Block) != len(s.Lines) || len(s.Secret) != len(s.Lines) {
				t.Fatalf("%s: Block %d, Secret %d for %d lines", v.name, len(s.Block), len(s.Secret), len(s.Lines))
			}
			for i, l := range s.Lines {
				fromBlock := i >= len(o.Lines)
				if s.Block[i] != fromBlock {
					t.Errorf("%s: %q: Block is %v", v.name, l, s.Block[i])
				}
				// a community string and a trap group name are secrets, a
				// trap option is none
				wantSecret := strings.HasPrefix(l, "set snmp community ") || strings.HasPrefix(l, "set snmp trap-group ") ||
					strings.Contains(l, "authentication-password") || strings.Contains(l, "privacy-password")
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
		if !commented["The snmp block of scope 'lab' (tacctl scope block lab juniper show snmp): its communities, trap groups and trap options."] {
			t.Errorf("%s: no comment names the block", v.name)
		}
		for c := range commented {
			for _, bad := range []string{"nms-ro", "nms-traps"} {
				if strings.Contains(c, bad) {
					t.Errorf("%s: a comment holds a string: %q", v.name, c)
				}
			}
		}
		if !strings.Contains(text, "show configuration snmp") {
			t.Errorf("%s: the verify commands lack the snmp hierarchy", v.name)
		}

		// without a block the walkthrough is as it was
		if renderText(t, req, plain) == text {
			t.Errorf("%s: the block changed nothing", v.name)
		}
	}
}

// The block is independent of the structured settings: with none configured
// the step says so and still renders the block.
func TestBlockWithoutStructuredSNMP(t *testing.T) {
	m, c := managedWorld(t)
	prof := managedProfile{scope: "lab", cidrs: []string{"192.0.2.0/24"}}
	req, d := prof.input(m, c, variants[3])
	d.Blocks = Blocks{Scope: "lab", SNMP: parsedBlock(t, blockText)}
	snmp, ok := sectionOf(mustManaged(t, req, d), "snmp")
	if !ok {
		t.Fatal("no snmp section")
	}
	if !slices.Equal(snmp.Lines, blocks.Statements(d.Blocks.SNMP)) {
		t.Errorf("the snmp section:\n%s", strings.Join(snmp.Lines, "\n"))
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

// A block community whose string is the scope's own community: refused by
// Managed and by the walkthrough, without the string.
func TestBlockCommunityEqualToTheStructuredOne(t *testing.T) {
	lab := managedProfiles()[0]
	text := "set snmp community other-example authorization read-only\nset snmp community other-example clients 192.0.2.50/32\n" +
		"set snmp community " + lab.snmp.Community + " authorization read-only\nset snmp community " + lab.snmp.Community + " clients 192.0.2.60/32\n"
	req, d := juniperInput(t, lab, variants[3], text)
	_, err := Managed(req, d)
	if err == nil {
		t.Fatal("Managed accepted it")
	}
	if strings.Contains(err.Error(), lab.snmp.Community) || strings.Contains(err.Error(), "other-example") {
		t.Errorf("the error holds a string: %v", err)
	}
	for _, want := range []string{"Community 2 of the SNMP block of scope 'lab'", "tacctl scope block lab juniper"} {
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
	req, d = juniperInput(t, prod, variants[3], text)
	if _, err := Managed(req, d); err != nil {
		t.Errorf("v3: %v", err)
	}
}

// A request renders the blocks of its own vendor: a Cisco request ignores the
// Junos block, and a Junos request the IOS one.
func TestRequestsIgnoreTheOtherVendorsBlock(t *testing.T) {
	lab := managedProfiles()[0]
	for _, v := range variants[:5] {
		m, c := managedWorld(t)
		req, d := lab.input(m, c, v)
		want := mustManaged(t, req, d)
		wantText := renderText(t, req, d)
		d.Blocks = Blocks{Scope: "lab", SNMP: parsedBlock(t, blockText), CiscoSNMP: parsedCiscoBlock(t, ciscoBlockText)}
		if v.vendor == "cisco" {
			d.Blocks.SNMP = nil
		} else {
			d.Blocks.CiscoSNMP = nil
		}
		got := mustManaged(t, req, d)
		// the vendor's own block is rendered; the other vendor's is not: the
		// same request with the other vendor's block alone is unchanged
		_, d2 := lab.input(m, c, v)
		if v.vendor == "cisco" {
			d2.Blocks = Blocks{Scope: "lab", SNMP: parsedBlock(t, blockText)}
		} else {
			d2.Blocks = Blocks{Scope: "lab", CiscoSNMP: parsedCiscoBlock(t, ciscoBlockText)}
		}
		got2 := mustManaged(t, req, d2)
		if !slices.EqualFunc(want, got2, sectionEqual) {
			t.Errorf("%s: Managed changed", v.name)
		}
		for _, s := range got2 {
			if s.Block != nil {
				t.Errorf("%s: %s has Block", v.name, s.Name)
			}
		}
		if renderText(t, req, d2) != wantText {
			t.Errorf("%s: the walkthrough changed", v.name)
		}
		if slices.EqualFunc(want, got, sectionEqual) {
			t.Errorf("%s: its own block changed nothing", v.name)
		}
	}
}

// A device's own block laid over the scope's: the comment above the block's
// statements names the layers and the verb that shows the result, and the
// refusal of a community that is the scope's own names the layer that holds
// it and its place there.
func TestBlockCommentAndRefusalNameTheDevicesLayer(t *testing.T) {
	lab := managedProfiles()[0]
	req, d := juniperInput(t, lab, variants[3], blockText)
	comment := func(d Data) string {
		t.Helper()
		var buf strings.Builder
		if err := Render(&buf, req, d); err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(buf.String(), "\n") {
			if strings.HasPrefix(l, "# The snmp block of ") {
				return l
			}
		}
		t.Fatalf("no comment in:\n%s", buf.String())
		return ""
	}
	tail := ": its communities, trap groups and trap options."
	if got, want := comment(d), "# The snmp block of scope 'lab' (tacctl scope block lab juniper show snmp)"+tail; got != want {
		t.Errorf("scope only:\n%s\nwant\n%s", got, want)
	}
	d.Blocks.Device, d.Blocks.SNMPLayer = "jsw1.lab.example.net", LayerScopeDevice
	if got, want := comment(d), "# The snmp block of scope 'lab' with the block of device 'jsw1.lab.example.net' over it (tacctl device block jsw1.lab.example.net show snmp --effective)"+tail; got != want {
		t.Errorf("both:\n%s\nwant\n%s", got, want)
	}
	d.Blocks.SNMPLayer = LayerDevice
	if got, want := comment(d), "# The snmp block of device 'jsw1.lab.example.net' (tacctl device block jsw1.lab.example.net show snmp)"+tail; got != want {
		t.Errorf("device only:\n%s\nwant\n%s", got, want)
	}

	// the refusal: the device's layer holds the community, at its own place
	text := "set snmp community other-example authorization read-only\nset snmp community other-example clients 192.0.2.50/32\n" +
		"set snmp community " + lab.snmp.Community + " authorization read-only\nset snmp community " + lab.snmp.Community + " clients 192.0.2.60/32\n"
	dev := parsedBlock(t, "set snmp community "+lab.snmp.Community+" authorization read-only\nset snmp community "+lab.snmp.Community+" clients 192.0.2.60/32\n")
	scope := parsedBlock(t, blockText)
	req, d = juniperInput(t, lab, variants[3], text)
	d.Blocks = Blocks{Scope: lab.scope, Device: "jsw1.lab.example.net", SNMP: parsedBlock(t, text), ScopeSNMP: scope, DeviceSNMP: dev, SNMPLayer: LayerScopeDevice}
	_, err := Managed(req, d)
	if err == nil {
		t.Fatal("Managed accepted it")
	}
	for _, want := range []string{"Community 1 of the SNMP block of device 'jsw1.lab.example.net'", "tacctl device block jsw1.lab.example.net edit snmp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lacks %q: %v", want, err)
		}
	}
	// the scope's layer holds it
	d.Blocks.DeviceSNMP = parsedBlock(t, "set snmp community other-example authorization read-only\nset snmp community other-example clients 192.0.2.50/32\n")
	d.Blocks.ScopeSNMP = parsedBlock(t, text)
	_, err = Managed(req, d)
	if err == nil || !strings.Contains(err.Error(), "Community 2 of the SNMP block of scope 'lab'") || !strings.Contains(err.Error(), "tacctl scope block lab juniper edit snmp") {
		t.Errorf("scope layer: %v", err)
	}
	if err != nil && (strings.Contains(err.Error(), lab.snmp.Community) || strings.Contains(err.Error(), "other-example")) {
		t.Errorf("the error holds a string: %v", err)
	}
}
