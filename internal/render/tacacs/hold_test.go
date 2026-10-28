package tacacs

import (
	"flag"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The break-glass hold (docs/plans/0.2.5-plan.md D123): the renderer takes
// the held addresses out of every prefix, and nothing else changes.

var updateHoldGolden = flag.Bool("update", false, "rewrite the golden files")

type holdEntry struct{ scope, prefix string }

// entriesOf is the (scope, prefix) pairs of a rendered file, in file order.
func entriesOf(t *testing.T, data []byte) []holdEntry {
	t.Helper()
	var out []holdEntry
	d := decoded(t, data)
	secrets, _ := d["secrets"].([]any)
	for _, s := range secrets {
		m := s.(map[string]any)
		block := m["options"].(map[string]any)["prefixes"].(string)
		for _, l := range strings.Split(block, "\n") {
			if l = strings.TrimSpace(l); strings.HasPrefix(l, `"`) {
				out = append(out, holdEntry{m["name"].(string), strings.Trim(l, `"`)})
			}
		}
	}
	return out
}

// firstScope is the scope of the first entry that holds addr ("" when none).
func firstScope(entries []holdEntry, addr string) string {
	for _, e := range entries {
		if cidr.ContainsAddr(e.prefix, addr) {
			return e.scope
		}
	}
	return ""
}

func holdView(t *testing.T) *yamlpy.Map {
	return viewOf(t, string(readFile(t, filepath.Join(fixDir, "tacctl.hold.yaml")))).Merged()
}

func TestRenderHoldGolden(t *testing.T) {
	st := loadStore(t, "store.hold.yaml")
	got := render(t, st, holdView(t))
	golden := filepath.Join(goldenDir, "tacquito.hold.rendered.yaml")
	if *updateHoldGolden {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	diffText(t, got, readFile(t, golden), "hold")
	// The reason of a hold is free text: it never reaches the file.
	for _, reason := range []string{"console recovery", "lab console", "radius only", "v6 console"} {
		if strings.Contains(string(got), reason) {
			t.Errorf("the reason %q is in the rendered file", reason)
		}
	}
	// Written through RenderToFile the read-back passes with the holds.
	if _, err := renderFile(t, loadStore(t, "store.hold.yaml"), holdView(t)); err != nil {
		t.Fatalf("the read-back refused a render with holds: %v", err)
	}
}

func TestRenderHoldCarvesEveryPrefixThatHoldsTheAddress(t *testing.T) {
	st := loadStore(t, "store.hold.yaml")
	got := entriesOf(t, render(t, st, holdView(t)))
	count := map[string]int{}
	for _, e := range got {
		count[e.scope]++
	}
	// 10.0.1.5 is in core's /16 (16 pieces: /17 to /32) and lab's /24 (8
	// pieces); 192.0.2.21 in lab's /24 (8 more) and mgmt's /32 (gone).
	// edge's /24 minus two holes: 7 pieces for the first, and the /25 of
	// the second is cut again into 7.
	want := map[string]int{"core": 16, "lab": 16, "edge": 14, "v6": 64}
	for scope, n := range want {
		if count[scope] != n {
			t.Errorf("scope %s: %d entries, want %d", scope, count[scope], n)
		}
	}
	if count["mgmt"] != 0 {
		t.Errorf("mgmt's /32 equal to the hole is still listed: %d", count["mgmt"])
	}
	if count["wifi"] != 0 {
		t.Errorf("wifi is RADIUS only, TACACS+ lists it: %d", count["wifi"])
	}
	for _, h := range []string{"10.0.1.5", "192.0.2.21", "198.51.100.7", "198.51.100.200", "2001:db8:0:1::5"} {
		if s := firstScope(got, h); s != "" {
			t.Errorf("%s is answered by scope %s while held", h, s)
		}
	}
	// The comment names the address, the device and where it was carved
	// from, once per address that carves something out of this file.
	text := string(render(t, st, holdView(t)))
	for _, want := range []string{
		"# break-glass held: 10.0.1.5 (device sw-core-1) is answered by no entry; carved out of 10.0.0.0/16 (core), 10.0.1.0/24 (lab)\n",
		"# break-glass held: 192.0.2.21 (device sw-lab-1) is answered by no entry; carved out of 192.0.2.0/24 (lab), 192.0.2.21/32 (mgmt)\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no comment %q", want)
		}
	}
	if strings.Contains(text, "ap-1") {
		t.Error("the RADIUS-only hold is named in the TACACS+ file")
	}
}

// A hold whose name is an enrolled host reads (host ...) in the comment
// block and a device keeps (device ...) (D237); only the word changes, and a
// registry that names nobody is the plain rendering.
func TestRenderHoldCommentNamesAHostAsAHost(t *testing.T) {
	st := loadStore(t, "store.hold.yaml")
	view := holdView(t)
	plain := string(render(t, st, view))
	got, err := Render(st, view, map[string]bool{"sw-lab-1": true, "unrelated": true}, pwchange.Server{})
	if err != nil {
		t.Fatal(err)
	}
	text := string(got)
	for _, want := range []string{
		"# break-glass held: 10.0.1.5 (device sw-core-1) is answered by no entry;",
		"# break-glass held: 192.0.2.21 (host sw-lab-1) is answered by no entry;",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no comment %q", want)
		}
	}
	if strings.Contains(text, "(device sw-lab-1)") {
		t.Error("the held host is still worded as a device")
	}
	// Nothing but that word differs from the rendering without hosts, and
	// that rendering is the golden's.
	if want := strings.Replace(plain, "(device sw-lab-1)", "(host sw-lab-1)", 1); text != want {
		t.Error("the host set changed more than the word of the comment")
	}
	if empty, err := Render(st, view, map[string]bool{}, pwchange.Server{}); err != nil || string(empty) != plain {
		t.Errorf("an empty host set renders differently from none (err %v)", err)
	}
}

// With a hold standing the same scope answers every address that is not
// held, for addresses all over the prefixes and their neighbours.
func TestRenderHoldKeepsTheScopeOfEveryOtherAddress(t *testing.T) {
	st := loadStore(t, "store.hold.yaml")
	before := entriesOf(t, render(t, st, defaultView(t)))
	after := entriesOf(t, render(t, loadStore(t, "store.hold.yaml"), holdView(t)))
	held := conf.HeldAddresses(holdView(t))
	rng := rand.New(rand.NewSource(7))
	var probes []string
	for _, e := range before {
		p := netip.MustParsePrefix(e.prefix)
		for i := 0; i < 200; i++ {
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
	// Addresses right beside every hole: the siblings along its path.
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
		want := firstScope(before, a)
		got := firstScope(after, a)
		if isHeld {
			want = ""
		}
		if got != want {
			t.Errorf("%s: scope %q with the holds, %q without", a, got, want)
		}
	}
}

// hold then release is the original bytes, byte for byte, and a view with
// no hold key renders as it always did.
func TestRenderHoldThenReleaseIsByteIdentical(t *testing.T) {
	plain := render(t, loadStore(t, "store.hold.yaml"), defaultView(t))
	held := render(t, loadStore(t, "store.hold.yaml"), holdView(t))
	if string(plain) == string(held) {
		t.Fatal("the hold changed nothing")
	}
	again := render(t, loadStore(t, "store.hold.yaml"), defaultView(t))
	diffText(t, again, plain, "after the release")
	if strings.Contains(string(plain), "break-glass") {
		t.Error("a render with no hold carries the hold comment")
	}
}

// A hold whose address no prefix holds changes nothing in the file.
func TestRenderHoldOfAnUncoveredAddressChangesNothing(t *testing.T) {
	// 100.64.0.1 is outside every scope.
	v := viewOf(t, "breakglass_hold:\n  sw-x:\n    address: 100.64.0.1\n    since: '2026-10-10T14:02:00+00:00'\n    by: alice\n    reason: x\n").Merged()
	plain := render(t, loadStore(t, "store.hold.yaml"), defaultView(t))
	held := render(t, loadStore(t, "store.hold.yaml"), v)
	diffText(t, held, plain, "uncovered hold")
}

func TestCarvedIsThePureModelWithoutTheAddresses(t *testing.T) {
	st := loadStore(t, "store.hold.yaml")
	m := model.FromStore(st)
	c := Carved(m, holdView(t), pwchange.Server{})
	if len(m.Scope("lab").Prefixes) != 2 {
		t.Fatal("the model was changed")
	}
	if len(c.Scope("lab").Prefixes) != 16 {
		t.Errorf("lab has %d prefixes, want 16: %v", len(c.Scope("lab").Prefixes), c.Scope("lab").Prefixes)
	}
	if got := fmt.Sprint(c.Scope("mgmt").Prefixes); got != "[]" {
		t.Errorf("mgmt: %s", got)
	}
}
