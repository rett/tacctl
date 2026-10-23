package radius_test

import (
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/render/radius"
)

// The break-glass hold in clients.conf (docs/plans/0.2.5-plan.md D123): the
// held addresses are taken out of every client, tagged addresses included.

func holdConf(t *testing.T, tacctlYAML string) *conf.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	if tacctlYAML != "" {
		if err := os.WriteFile(p, []byte(tacctlYAML), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return conf.Load(p, backends)
}

func holdRender(t *testing.T, withHolds bool) *radius.Output {
	t.Helper()
	text := ""
	if withHolds {
		text = read(t, fixtures+"tacctl.hold.yaml")
	}
	out, err := radius.Render(loadModel(t, fixtures+"store.hold.yaml"), holdConf(t, text).Merged(), params("debian"))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type holdClient struct {
	addr   string
	scope  string
	device string
}

var (
	reClientAddr  = regexp.MustCompile(`^\t\t(?:ipaddr|ipv6addr) = (\S+)$`)
	reClientScope = regexp.MustCompile(`^\t\ttacctl_scope = "(.*)"$`)
	reClientDev   = regexp.MustCompile(`^\t\ttacctl_device = "(.*)"$`)
)

func clientsOf(out *radius.Output) []holdClient {
	var cs []holdClient
	var cur holdClient
	for _, l := range lines(out.Conf) {
		if m := reClientAddr.FindStringSubmatch(l); m != nil {
			cur = holdClient{addr: m[1]}
		} else if m := reClientScope.FindStringSubmatch(l); m != nil {
			cur.scope = m[1]
		} else if m := reClientDev.FindStringSubmatch(l); m != nil {
			cur.device = m[1]
			cs = append(cs, cur)
		}
	}
	return cs
}

// answeredBy is the client FreeRADIUS picks for an address: the longest
// prefix that holds it.
func answeredBy(cs []holdClient, addr string) (holdClient, bool) {
	best, ok := holdClient{}, false
	bestLen := -1
	for _, c := range cs {
		if !cidr.ContainsAddr(c.addr, addr) {
			continue
		}
		n, _ := cidr.Parse(c.addr)
		if n.PrefixLen() > bestLen {
			best, ok, bestLen = c, true, n.PrefixLen()
		}
	}
	return best, ok
}

func TestHoldGolden(t *testing.T) {
	out := holdRender(t, true)
	compareGolden(t, out, golden+"radius.hold.conf", "", "")
	for _, reason := range []string{"console recovery", "lab console", "radius only", "v6 console"} {
		if strings.Contains(out.Conf, reason) || strings.Contains(out.Users, reason) {
			t.Errorf("%q is in a rendered file", reason)
		}
	}
}

// A hold whose name is an enrolled host reads (host ...) in the comment
// block and a device keeps (device ...) (D237); only the word changes.
func TestHoldCommentNamesAHostAsAHost(t *testing.T) {
	p := params("debian")
	p.Hosts = map[string]bool{"sw-lab-1": true, "unrelated": true}
	out, err := radius.Render(loadModel(t, fixtures+"store.hold.yaml"),
		holdConf(t, read(t, fixtures+"tacctl.hold.yaml")).Merged(), p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"\t# break-glass held: 10.0.1.5 (device sw-core-1) is answered by no client;",
		"\t# break-glass held: 192.0.2.21 (host sw-lab-1) is answered by no client;",
	} {
		if !strings.Contains(out.Conf, want) {
			t.Errorf("no comment %q", want)
		}
	}
	if strings.Contains(out.Conf, "(device sw-lab-1)") {
		t.Error("the held host is still worded as a device")
	}
	// The render id covers the comment, so it differs too; with each id
	// taken out the files differ in that one word.
	plainOut := holdRender(t, true)
	norm := func(text, id string) string { return strings.ReplaceAll(text, id, "ID") }
	want := strings.Replace(norm(plainOut.Conf, plainOut.RenderID), "(device sw-lab-1)", "(host sw-lab-1)", 1)
	if got := norm(out.Conf, out.RenderID); got != want {
		t.Error("the host set changed more than the word of the comment")
	}
}

func TestHoldCarvesPrefixesAndTaggedAddresses(t *testing.T) {
	cs := clientsOf(holdRender(t, true))
	for _, h := range []string{"10.0.1.5", "192.0.2.21", "198.51.100.7", "198.51.100.200", "2001:db8:0:1::5", "203.0.113.9"} {
		if c, ok := answeredBy(cs, h); ok {
			t.Errorf("%s is answered by %+v while held", h, c)
		}
	}
	// 10.0.1.5 is the tagged /32 (juniper) and inside the tagged /28 (cisco):
	// the /32 is gone and the /28 is its covering pieces, still tagged cisco.
	if c, ok := answeredBy(cs, "10.0.1.4"); !ok || c.device != "cisco" || c.scope != "lab" {
		t.Errorf("10.0.1.4 (next to the held one, in the tagged /28): %+v %v", c, ok)
	}
	if c, ok := answeredBy(cs, "10.0.1.200"); !ok || c.device != "generic" || c.scope != "lab" {
		t.Errorf("10.0.1.200 (lab's /24, outside the tag): %+v %v", c, ok)
	}
	if c, ok := answeredBy(cs, "10.0.9.9"); !ok || c.scope != "core" {
		t.Errorf("10.0.9.9 (core's /16 only): %+v %v", c, ok)
	}
	for _, c := range cs {
		if c.device == "juniper" {
			t.Errorf("the tagged /32 equal to the hole is still a client: %+v", c)
		}
	}
	// TACACS+-only scopes have no client.
	for _, c := range cs {
		if c.scope == "edge" {
			t.Errorf("edge is TACACS+ only: %+v", c)
		}
	}
}

// Every address that is not held is answered by the scope it had before.
func TestHoldKeepsTheScopeOfEveryOtherAddress(t *testing.T) {
	before := clientsOf(holdRender(t, false))
	after := clientsOf(holdRender(t, true))
	held := conf.HeldAddresses(holdConf(t, read(t, fixtures+"tacctl.hold.yaml")).Merged())
	rng := rand.New(rand.NewSource(11))
	var probes []string
	for _, c := range before {
		p := netip.MustParsePrefix(c.addr)
		for i := 0; i < 150; i++ {
			b := p.Addr().AsSlice()
			for bit := p.Bits(); bit < len(b)*8; bit++ {
				if rng.Intn(2) == 1 {
					b[bit/8] ^= 1 << (7 - uint(bit%8))
				}
			}
			a, _ := netip.AddrFromSlice(b)
			probes = append(probes, a.String())
		}
	}
	for _, h := range held {
		a := netip.MustParseAddr(h)
		for k := 0; k < 8; k++ {
			b := a.AsSlice()
			bit := len(b)*8 - 1 - k
			b[bit/8] ^= 1 << (7 - uint(bit%8))
			n, _ := netip.AddrFromSlice(b)
			probes = append(probes, n.String())
		}
	}
	for _, a := range probes {
		isHeld := false
		for _, h := range held {
			isHeld = isHeld || h == a
		}
		w, wok := answeredBy(before, a)
		g, gok := answeredBy(after, a)
		if isHeld {
			wok = false
		}
		if gok != wok || (gok && (g.scope != w.scope || g.device != w.device)) {
			t.Errorf("%s: %+v (%v) with the holds, %+v (%v) without", a, g, gok, w, wok)
		}
	}
}

// The model with the holds, then without them, is the original bytes.
func TestHoldThenReleaseIsByteIdentical(t *testing.T) {
	plain, again := holdRender(t, false), holdRender(t, false)
	held := holdRender(t, true)
	if plain.Conf == held.Conf || plain.RenderID == held.RenderID {
		t.Fatal("the holds changed nothing")
	}
	if plain.Conf != again.Conf || plain.Users != again.Users || plain.Dictionary != again.Dictionary {
		t.Error("two renders of the same state differ")
	}
	if strings.Contains(plain.Conf, "break-glass") {
		t.Error("a render with no hold carries the hold comment")
	}
}
