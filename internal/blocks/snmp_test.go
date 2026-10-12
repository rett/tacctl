package blocks

import (
	"fmt"
	"strings"
	"testing"
)

// the secrets of the fixtures: no finding may ever hold one.
const (
	secA = "lab-ro-7QxM"
	secB = "lab-rw-ZpL2"
	secG = "traps-Kd93"
)

func hasFinding(fs []Finding, sev Severity, line int, frag string) bool {
	for _, f := range fs {
		if f.Severity == sev && (line < 0 || f.Line == line) && strings.Contains(f.Text, frag) {
			return true
		}
	}
	return false
}

func dump(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.String() + "\n")
	}
	return b.String()
}

const goodBlock = `# the lab's own pollers
set snmp community lab-ro-7QxM authorization read-only
set snmp community lab-ro-7QxM clients 192.0.2.0/24
set snmp community lab-ro-7QxM clients 198.51.100.7/32

set snmp community "lab rw ZpL2" authorization read-write
set snmp community "lab rw ZpL2" client-list-name POLLERS
set snmp trap-group traps-Kd93 version v2
set snmp trap-group traps-Kd93 categories authentication
set snmp trap-group traps-Kd93 categories link
set snmp trap-group traps-Kd93 targets 192.0.2.50
set snmp trap-group traps-Kd93 targets 2001:db8::50
set snmp trap-options agent-address outgoing-interface
delete snmp community old-string
`

func TestParseGoodBlock(t *testing.T) {
	b, fs := Lint(goodBlock, LayerScope)
	if HasErrors(fs) {
		t.Fatalf("errors:\n%s", dump(fs))
	}
	if len(b.Communities) != 2 || b.Communities[0].String != secA || b.Communities[1].String != "lab rw ZpL2" {
		t.Fatalf("communities: %+v", b.Communities)
	}
	c := b.Communities[0]
	if c.Authorization != AuthReadOnly || len(c.Clients) != 2 || c.Clients[1].Prefix.String() != "198.51.100.7/32" {
		t.Errorf("community 1: %+v", c)
	}
	if b.Communities[1].ClientListName != "POLLERS" || b.Communities[1].Authorization != AuthReadWrite {
		t.Errorf("community 2: %+v", b.Communities[1])
	}
	g := b.TrapGroups[0]
	if g.Version != "v2" || len(g.Categories) != 2 || len(g.Targets) != 2 || g.Targets[1].String() != "2001:db8::50" {
		t.Errorf("trap group: %+v", g)
	}
	if len(b.TrapOptions) != 1 || b.TrapOptions[0].Leaf != "agent-address" {
		t.Errorf("trap options: %+v", b.TrapOptions)
	}
	if len(b.NotManaged) != 1 || b.NotManaged[0].Kind != "community" || b.NotManaged[0].Name != "old-string" || b.NotManaged[0].Line != 14 {
		t.Errorf("not managed: %+v", b.NotManaged)
	}
	// Lines of the objects.
	if got := lineList(c.Lines); got != "lines 2, 3, 4" {
		t.Errorf("lines of community 1: %s", got)
	}
}

// Every refusal, with the line it is on. None of the texts may hold a
// string of the input.
func TestParseRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		line int
		frag string
	}{
		{"not set or delete", "edit snmp\n", 1, "'set' and 'delete' statements only"},
		{"commit", "commit\n", 1, "'set' and 'delete' statements only"},
		{"other hierarchy", "set system host-name x\n", 1, "only 'set snmp"},
		{"set alone", "set\n", 1, "only 'set snmp"},
		{"snmp alone", "set snmp\n", 1, "needs community, trap-group or trap-options"},
		{"snmp v3", "set snmp v3 usm local-engine user u\n", 1, "word 3 is not one of community"},
		{"location", "set snmp location rack-4\n", 1, "word 3 is not one of community"},
		{"client-list", "set snmp client-list L 192.0.2.0/24\n", 1, "word 3 is not one of community"},
		{"community no name", "set snmp community\n", 1, "needs a community string"},
		{"community no leaf", "set snmp community s1\n", 1, "needs authorization, clients or client-list-name"},
		{"community bad leaf", "set snmp community s1 view all\n", 1, "word 5 is not one of authorization"},
		{"authorization value", "set snmp community s1 authorization read-everything\n", 1, "read-only or read-write"},
		{"authorization extra", "set snmp community s1 authorization read-only now\n", 1, "read-only or read-write and nothing else"},
		{"authorization twice", "set snmp community s1 authorization read-only\nset snmp community s1 authorization read-write\n", 2, "authorization is stated twice"},
		{"clients no prefix", "set snmp community s1 clients 192.0.2.1\n", 1, "needs a prefix length"},
		{"clients junk", "set snmp community s1 clients not-an-address/24\n", 1, "not an IPv4 or IPv6 address with a prefix length"},
		{"clients host bits", "set snmp community s1 clients 192.0.2.5/24\n", 1, "host bits set (write the network: 192.0.2.0/24)"},
		{"clients noncanonical", "set snmp community s1 clients 2001:DB8::/32\n", 1, "canonical form 2001:db8::/32"},
		{"clients mapped", "set snmp community s1 clients ::ffff:192.0.2.1/128\n", 1, "not accepted"},
		{"clients extra word", "set snmp community s1 clients 192.0.2.0/24 permit\n", 1, "optionally, restrict"},
		{"clients twice", "set snmp community s1 clients 192.0.2.0/24\nset snmp community s1 clients 192.0.2.0/24 restrict\n", 2, "listed twice"},
		{"client list twice", "set snmp community s1 client-list-name A\nset snmp community s1 client-list-name B\n", 2, "client-list-name is stated twice"},
		{"client list two words", "set snmp community s1 client-list-name A B\n", 1, "takes one client list name"},
		{"trap group no name", "set snmp trap-group\n", 1, "needs a trap group name"},
		{"trap group no leaf", "set snmp trap-group g1\n", 1, "needs version, categories or targets"},
		{"trap group leaf", "set snmp trap-group g1 destination-port 162\n", 1, "word 5 is not one of version"},
		{"version v3", "set snmp trap-group g1 version v3\n", 1, "version takes v1 or v2"},
		{"version all", "set snmp trap-group g1 version all\n", 1, "version takes v1 or v2"},
		{"version twice", "set snmp trap-group g1 version v1\nset snmp trap-group g1 version v2\n", 2, "version is stated twice"},
		{"category", "set snmp trap-group g1 categories everything\n", 1, "categories takes one category of"},
		{"category twice", "set snmp trap-group g1 categories link\nset snmp trap-group g1 categories link\n", 2, "listed twice"},
		{"target name", "set snmp trap-group g1 targets nms.example.net\n", 1, "not an IPv4 or IPv6 address"},
		{"target prefix", "set snmp trap-group g1 targets 192.0.2.0/24\n", 1, "not an IPv4 or IPv6 address"},
		{"target unspecified", "set snmp trap-group g1 targets 0.0.0.0\n", 1, "not a host address"},
		{"target multicast", "set snmp trap-group g1 targets 224.0.0.1\n", 1, "not a host address"},
		{"target twice", "set snmp trap-group g1 targets 192.0.2.9\nset snmp trap-group g1 targets 192.0.2.9\n", 2, "listed twice"},
		{"options no leaf", "set snmp trap-options\n", 1, "needs a leaf"},
		{"options source-address", "set snmp trap-options source-address 192.0.2.1\n", 1, "source-address is not accepted"},
		{"options source-address lo0", "set snmp trap-options source-address lo0\n", 1, "source-address is not accepted"},
		{"options unknown leaf", "set snmp trap-options logical-system x\n", 1, "not a trap-options leaf a block takes"},
		{"options bad value", "set snmp trap-options agent-address 192.0.2.1\n", 1, "takes outgoing-interface"},
		{"options twice", "set snmp trap-options agent-address outgoing-interface\nset snmp trap-options agent-address outgoing-interface\n", 2, "stated twice"},
		{"own client list name", "set snmp community s1 client-list-name TACCTL-SNMP\n", 1, "name tacctl renders itself"},
		{"own community", "set snmp community TACCTL-SNMP authorization read-only\n", 1, "name tacctl renders itself"},
		{"own view as community", "set snmp community TACCTL-VIEW clients 192.0.2.0/24\n", 1, "name tacctl renders itself"},
		{"own group as trap group", "set snmp trap-group TACCTL-GROUP version v1\n", 1, "name tacctl renders itself"},
		{"own name in delete", "delete snmp community TACCTL-SNMP\n", 1, "name tacctl renders itself"},
		{"placeholder secret", "set snmp community <secret> authorization read-only\n", 1, "is a placeholder"},
		{"placeholder mark", "set snmp community <secret:1> authorization read-only\n", 1, "is a placeholder"},
		{"placeholder group", "set snmp trap-group <group:1> version v1\n", 1, "is a placeholder"},
		{"placeholder client list", "set snmp community s1 client-list-name <other:2>\n", 1, "is a placeholder"},
		{"tab", "set snmp community s1\tauthorization read-only\n", 1, "a tab at column"},
		{"control character", "set snmp community s1 authorization read-only\x07\n", 1, "a control character (0x07)"},
		{"carriage return", "set snmp community s1 authorization read-only\r\n", 1, "a control character (0x0d)"},
		{"non-ascii", "set snmp community caf\u00e9 authorization read-only\n", 1, "not ASCII"},
		{"question mark", "set snmp community s1? authorization read-only\n", 1, "reads specially"},
		{"brace", "set snmp community s{1} authorization read-only\n", 1, "reads specially"},
		{"unterminated quote", "set snmp community \"a b authorization read-only\n", 1, "never closed"},
		{"quote inside", "set snmp community a\"b authorization read-only\n", 1, "holds a quote"},
		{"text after quote", "set snmp community \"a b\"x authorization read-only\n", 1, "followed by more text"},
		{"backslash in quotes", "set snmp community \"a\\b\" authorization read-only\n", 1, "backslash"},
		{"empty quoted", "set snmp community \"\" authorization read-only\n", 1, "is empty"},
		{"blank edge", "set snmp community \" a\" authorization read-only\n", 1, "starts or ends with a blank"},
		{"too long", "set snmp community " + strings.Repeat("a", 65) + " authorization read-only\n", 1, "longer than 64"},
		{"long line", "set snmp community s1 clients 192.0.2.0/24 " + strings.Repeat("x", 1000) + "\n", 1, "longer than 1000"},
		{"quoted keyword", "set snmp community s1 \"authorization\" read-only\n", 1, "word 5 is not one of"},
		{"quoted set", "\"set\" snmp community s1 authorization read-only\n", 1, "'set' and 'delete' statements only"},
		{"delete other", "delete system host-name\n", 1, "only 'delete snmp"},
		{"delete bare", "delete snmp\n", 1, "only 'delete snmp"},
		{"delete v3", "delete snmp v3\n", 1, "word 3 is not one of community"},
		{"delete no name", "delete snmp community\n", 1, "needs the community string"},
		{"delete leaf", "delete snmp community s1 view\n", 1, "not a leaf of the grammar"},
		{"delete bad client", "delete snmp community s1 clients nope\n", 1, "address with a prefix length"},
		{"delete bad version", "delete snmp trap-group g1 version v3\n", 1, "takes no value, or a value of the grammar"},
		{"delete bad category", "delete snmp trap-group g1 categories nope\n", 1, "one category of the grammar"},
		{"delete bad target", "delete snmp trap-group g1 targets nope\n", 1, "one address"},
		{"delete trap option", "delete snmp trap-options source-address\n", 1, "not a trap-options leaf a block takes"},
		{"delete trap option extra", "delete snmp trap-options agent-address now\n", 1, "takes nothing after the leaf"},
		{"second line", "# ok\nset snmp community s1 authorization read-only\nset snmp frob\n", 3, "word 3 is not one of community"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := Parse(tc.text)
			if !hasFinding(fs, SevError, tc.line, tc.frag) {
				t.Errorf("want an error at line %d with %q, got:\n%s", tc.line, tc.frag, dump(fs))
			}
			for _, f := range fs {
				for _, secret := range []string{"s1", "g1", "caf", "<secret:1", "lab rw", "nope", "nms.example"} {
					if strings.Contains(f.Text, secret) && !strings.Contains(tc.frag, secret) {
						t.Errorf("finding %q holds %q", f, secret)
					}
				}
			}
		})
	}
}

func TestCheckLayersAndNotes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		text  string
		layer Layer
		want  []string // "<severity>@<line>:<fragment>"
	}{
		{
			"no clients", "set snmp community s1 authorization read-only\n", LayerScope,
			[]string{"error@1:community 1 has neither clients nor client-list-name"},
		},
		{
			"no clients on a device", "set snmp community s1 authorization read-only\n", LayerDevice,
			[]string{"error@1:community 1 has neither clients nor client-list-name"},
		},
		{
			"default layer wants none", "set snmp community s1 authorization read-only\n", LayerDefault,
			[]string{"note@1:community 1 becomes owned by tacctl"},
		},
		{
			"default layer refuses clients", "set snmp community s1 clients 192.0.2.0/24\n", LayerDefault,
			[]string{"error@1:community 1: the default block names no client and no client list"},
		},
		{
			"default layer refuses a client list", "set snmp community s1 client-list-name L\n", LayerDefault,
			[]string{"error@1:community 1: the default block names no client"},
		},
		{
			"default layer refuses targets", "set snmp trap-group g1 targets 192.0.2.9\n", LayerDefault,
			[]string{"error@1:trap-group 1: the default block names no target"},
		},
		{
			"world open", "set snmp community s1 clients 0.0.0.0/0\n", LayerScope,
			[]string{"note@1:community 1 is open to every client (0.0.0.0/0 without restrict)"},
		},
		{
			"world open v6", "set snmp community s1 clients ::/0\n", LayerDevice,
			[]string{"note@1:community 1 is open to every client (::/0 without restrict)"},
		},
		{
			"world restricted is quiet", "set snmp community s1 clients 192.0.2.0/24\nset snmp community s1 clients 0.0.0.0/0 restrict\n", LayerScope,
			nil,
		},
		{
			"trap group without target", "set snmp trap-group g1 version v2\n", LayerScope,
			[]string{"note@1:trap-group 1 has no target: no trap is sent"},
		},
		{
			"owned and secret notes", goodBlock, LayerScope,
			[]string{
				"note@2:community 1 becomes owned by tacctl",
				"note@2:community 1 carries a community string, a secret, on lines 2, 3, 4",
				"note@6:community 2 becomes owned by tacctl",
				"note@8:trap-group 1 becomes owned by tacctl",
				"note@8:trap-group 1 carries a name that is the community string traps are sent with, a secret, on lines 8, 9, 10, 11, 12",
				"note@13:trap-options agent-address becomes owned by tacctl",
				"note@14:a delete line",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := Lint(tc.text, tc.layer)
			var got []string
			for _, f := range fs {
				got = append(got, fmt.Sprintf("%s@%d:%s", f.Severity, f.Line, f.Text))
			}
			// Every wanted finding is there; the quiet cases hold no
			// error or note about openness.
			for _, w := range tc.want {
				found := false
				for _, g := range got {
					if strings.HasPrefix(g, w) {
						found = true
					}
				}
				if !found {
					t.Errorf("missing %q in:\n%s", w, strings.Join(got, "\n"))
				}
			}
			if tc.want == nil {
				for _, f := range fs {
					if strings.Contains(f.Text, "open to every client") || f.Severity == SevError {
						t.Errorf("unexpected %s", f)
					}
				}
			}
			for _, f := range fs {
				for _, s := range []string{secA, secB, secG, "lab rw", "s1", "g1"} {
					if strings.Contains(f.Text, s) {
						t.Errorf("finding %q holds the string %q", f, s)
					}
				}
			}
		})
	}
}

// Findings come in line order, and Check does not run on a block that does
// not parse.
func TestLintOrderAndNoDoubleReport(t *testing.T) {
	_, fs := Lint("set snmp community s1 authorization read-only\nset snmp frob\n", LayerScope)
	if len(fs) != 1 || fs[0].Line != 2 || fs[0].Severity != SevError {
		t.Errorf("a parse error alone: %s", dump(fs))
	}
	_, fs = Lint(goodBlock, LayerScope)
	for i := 1; i < len(fs); i++ {
		if fs[i].Line < fs[i-1].Line {
			t.Errorf("findings out of line order:\n%s", dump(fs))
			break
		}
	}
	_, fs = Lint("", LayerScope)
	if len(fs) != 0 {
		t.Errorf("an empty block: %s", dump(fs))
	}
	_, fs = Lint("# only comments\n\n   \n", LayerDevice)
	if len(fs) != 0 {
		t.Errorf("comments only: %s", dump(fs))
	}
}

// Parse then String is stable, and String of the block read back is the
// same text.
func TestRoundTripIsStable(t *testing.T) {
	for _, text := range []string{
		goodBlock,
		"",
		"set snmp community \"a  b\" clients 0.0.0.0/0 restrict\nset snmp community \"a  b\" authorization read-write\n",
		"# only a comment\nset snmp trap-group g1 targets 192.0.2.9\nset snmp trap-group g1 version v1\n",
		"delete snmp community \"a b\" clients 192.0.2.0/24 restrict\ndelete snmp trap-group g1\ndelete snmp trap-options\ndelete snmp community c client-list-name \"x y\"\n",
	} {
		b, fs := Parse(text)
		if HasErrors(fs) {
			t.Fatalf("%q: %s", text, dump(fs))
		}
		once := b.String(false)
		b2, fs := Parse(once)
		if HasErrors(fs) {
			t.Fatalf("the output does not parse: %s\n%s", dump(fs), once)
		}
		if twice := b2.String(false); twice != once {
			t.Errorf("not stable:\n%s\n--\n%s", once, twice)
		}
	}
	// Canonical order: authorization, clients, client list; then trap
	// groups; then options.
	b, _ := Parse("set snmp trap-group g1 targets 192.0.2.9\nset snmp community c clients 192.0.2.0/24\nset snmp community c authorization read-only\nset snmp trap-group g1 version v2\n")
	want := "set snmp community c authorization read-only\nset snmp community c clients 192.0.2.0/24\nset snmp trap-group g1 version v2\nset snmp trap-group g1 targets 192.0.2.9\n"
	if got := b.String(false); got != want {
		t.Errorf("canonical text:\n%s\nwant:\n%s", got, want)
	}
}

func TestStatements(t *testing.T) {
	b, _ := Parse(goodBlock)
	want := []string{
		"set snmp community lab-ro-7QxM authorization read-only",
		"set snmp community lab-ro-7QxM clients 192.0.2.0/24",
		"set snmp community lab-ro-7QxM clients 198.51.100.7/32",
		`set snmp community "lab rw ZpL2" authorization read-write`,
		`set snmp community "lab rw ZpL2" client-list-name POLLERS`,
		"set snmp trap-group traps-Kd93 version v2",
		"set snmp trap-group traps-Kd93 categories authentication",
		"set snmp trap-group traps-Kd93 categories link",
		"set snmp trap-group traps-Kd93 targets 192.0.2.50",
		"set snmp trap-group traps-Kd93 targets 2001:db8::50",
		"set snmp trap-options agent-address outgoing-interface",
	}
	got := Statements(b)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Statements:\n%s", strings.Join(got, "\n"))
	}
	if Statements(nil) != nil || Statements(&SNMPBlock{}) != nil {
		t.Error("an empty block has statements")
	}
	// A delete line is never a statement.
	for _, s := range got {
		if strings.HasPrefix(s, "delete") {
			t.Errorf("a delete line in the statements: %s", s)
		}
	}
	// A line appearing first for a community puts it first, whatever the
	// order of its statements.
	b2, _ := Parse("set snmp community b clients 192.0.2.0/24\nset snmp community a clients 192.0.2.0/24\nset snmp community b authorization read-only\n")
	if got := Statements(b2); got[0] != "set snmp community b clients 192.0.2.0/24" && got[0] != "set snmp community b authorization read-only" {
		t.Errorf("order: %q", got)
	}
	if !strings.Contains(strings.Join(Statements(b2)[:2], "|"), "community b") {
		t.Errorf("communities are not in order of first appearance: %q", Statements(b2))
	}
}

func TestElide(t *testing.T) {
	text := goodBlock + "delete snmp trap-group traps-Kd93\ndelete snmp community only-in-delete clients 192.0.2.0/24\n"
	b, fs := Parse(text)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	el := b.String(true)
	for _, s := range []string{secA, secB, "lab rw", secG, "old-string", "only-in-delete"} {
		if strings.Contains(el, s) {
			t.Errorf("elided text holds %q:\n%s", s, el)
		}
	}
	for _, w := range []string{
		"set snmp community <secret:1> authorization read-only",
		"set snmp community <secret:2> client-list-name POLLERS",
		"set snmp trap-group <group:1> targets 192.0.2.50",
		"delete snmp community <secret:3>\n",
		"delete snmp trap-group <group:1>\n",
		"delete snmp community <secret:4> clients 192.0.2.0/24\n",
		"set snmp trap-options agent-address outgoing-interface",
	} {
		if !strings.Contains(el, w) {
			t.Errorf("elided text lacks %q:\n%s", w, el)
		}
	}
	// The block itself is untouched, and the same string has the same mark.
	if b.Communities[0].String != secA {
		t.Error("Elide changed the block")
	}
	if Elide(nil) != nil {
		t.Error("Elide(nil)")
	}
	// An elided text is not a block: its marks are refused.
	_, fs = Parse(el)
	if !HasErrors(fs) || !hasFinding(fs, SevError, -1, "is a placeholder") {
		t.Errorf("an elided text parsed:\n%s", dump(fs))
	}
}

func TestResolve(t *testing.T) {
	def, fs := Parse(`set snmp community shared authorization read-only
set snmp community dflt-only authorization read-only
set snmp trap-group tg-shared version v1
set snmp trap-group tg-shared categories link
set snmp trap-options agent-address outgoing-interface
`)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	scope, fs := Parse(`set snmp community shared authorization read-write
set snmp community shared clients 192.0.2.0/24
set snmp community scope-only clients 198.51.100.0/24
set snmp trap-group tg-shared targets 192.0.2.50
`)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	dev, fs := Parse(`set snmp community shared clients 203.0.113.0/24
set snmp community dev-only client-list-name L
delete snmp community scope-only
delete snmp community dflt-only
delete snmp trap-options agent-address
delete snmp community unrelated clients 192.0.2.1/32
`)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}

	// Default and scope: the scope's object replaces the default's whole.
	got := Resolve(def, scope, nil)
	want := "set snmp community shared authorization read-write\nset snmp community shared clients 192.0.2.0/24\n" +
		"set snmp community dflt-only authorization read-only\nset snmp community scope-only clients 198.51.100.0/24\n" +
		"set snmp trap-group tg-shared targets 192.0.2.50\n" +
		"set snmp trap-options agent-address outgoing-interface\n"
	if s := strings.Join(Statements(got), "\n") + "\n"; s != want {
		t.Errorf("default + scope:\n%s\nwant:\n%s", s, want)
	}
	// With the device: its community replaces the scope's whole (the
	// authorization the scope stated is gone), and its deletes take the
	// less specific objects out.
	got = Resolve(def, scope, dev)
	want = "set snmp community shared clients 203.0.113.0/24\n" +
		"set snmp community dev-only client-list-name L\n" +
		"set snmp trap-group tg-shared targets 192.0.2.50\n"
	if s := strings.Join(Statements(got), "\n") + "\n"; s != want {
		t.Errorf("default + scope + device:\n%s\nwant:\n%s", s, want)
	}
	if len(got.NotManaged) != 4 {
		t.Errorf("not managed: %+v", got.NotManaged)
	}
	// Inputs are untouched.
	if len(scope.Communities) != 2 || len(def.Communities) != 2 || len(def.TrapOptions) != 1 {
		t.Error("Resolve changed an input")
	}
	got.Communities[0].Clients[0].Restrict = true
	if dev.Communities[0].Clients[0].Restrict {
		t.Error("the result shares a client slice with its input")
	}
	// Nil layers, and nothing at all.
	if r := Resolve(nil, nil, nil); !r.Empty() || len(Statements(r)) != 0 {
		t.Errorf("Resolve of nothing: %+v", r)
	}
	if s := strings.Join(Statements(Resolve(nil, scope, nil)), "\n"); !strings.Contains(s, "community scope-only clients 198.51.100.0/24") {
		t.Errorf("scope alone: %s", s)
	}
	// A delete in the same layer as the object keeps the object, and the
	// less specific one goes.
	same, _ := Parse("delete snmp community shared\nset snmp community shared clients 192.0.2.9/32\n")
	r := Resolve(def, same, nil)
	if s := strings.Join(Statements(r), "\n"); s != "set snmp community dflt-only authorization read-only\nset snmp community shared clients 192.0.2.9/32\n"+
		"set snmp trap-group tg-shared version v1\nset snmp trap-group tg-shared categories link\nset snmp trap-options agent-address outgoing-interface" {
		t.Errorf("same layer: %s", s)
	}
	// A bare 'delete snmp trap-options' takes every leaf.
	all, _ := Parse("delete snmp trap-options\n")
	if r := Resolve(def, all, nil); len(r.TrapOptions) != 0 {
		t.Errorf("trap options left: %+v", r.TrapOptions)
	}
}

// An elided or resolved block never leaks into a finding: the strings are
// only in the block.
func TestFindingsNeverHoldAString(t *testing.T) {
	_, fs := Lint(goodBlock+"set snmp community "+secB+" authorization read-everything\nset snmp trap-group "+secG+" targets nope\n", LayerScope)
	if !HasErrors(fs) {
		t.Fatal("no errors")
	}
	for _, f := range fs {
		for _, s := range []string{secA, secB, secG} {
			if strings.Contains(f.String(), s) {
				t.Errorf("%q holds %q", f, s)
			}
		}
	}
}
