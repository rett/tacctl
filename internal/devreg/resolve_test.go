package devreg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
)

func fixtureModel(t *testing.T, name string) *model.Model {
	t.Helper()
	_, m, err := model.LoadStore(filepath.Join("..", "..", "tests", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func hostRegistry(t *testing.T, text string) *hosts.Registry {
	t.Helper()
	p := filepath.Join(t.TempDir(), "linux-hosts")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := hosts.LoadRegistry(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func entryNames(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name)
	}
	return out
}

func multiscope(t *testing.T) *Resolver {
	f := Empty()
	f.Devices = []*Device{
		{Name: "core-sw1", Address: "10.1.2.3", Vendor: "cisco"},
		{Name: "inner-sw", Address: "10.10.99.7", Vendor: "juniper"},
		{Name: "lab-rtr2", Address: "192.168.4.4", Vendor: "juniper", Port: 830, Login: "admin"},
		{Name: "dmz-fw", Address: "203.0.113.9", Vendor: "other"},
		{Name: "stray", Address: "100.64.7.1", Vendor: "wti"},
		{Name: "v6", Address: "2001:db8::1", Vendor: "other"},
	}
	reg := hostRegistry(t, "web1|root@192.0.2.10|2222|lab|192.0.2.1|/keys/id\n"+
		"db1|dba@db.example.net||prod|192.0.2.1|\n"+
		"me|local||dmz|127.0.0.1|\n"+
		"orphan|root@192.0.2.40||gone|192.0.2.1|\n")
	return NewResolver(f, reg, fixtureModel(t, "store.multiscope.yaml"))
}

func TestDerivationOverMultiscope(t *testing.T) {
	r := multiscope(t)
	want := map[string]struct {
		scope, state string
		shadowed     []string
	}{
		"core-sw1": {"prod", "configured", nil},
		"inner-sw": {"prod-inner", "configured", []string{"prod"}},
		"lab-rtr2": {"lab", "configured", nil},
		"dmz-fw":   {"dmz", "configured", nil},
		"stray":    {"", "unconfigured", nil},
		"v6":       {"", "unconfigured", nil},
		"web1":     {"lab", "configured", nil},
		"db1":      {"prod", "configured", nil},
		"me":       {"dmz", "configured", nil},
		"orphan":   {"gone", "unconfigured", nil},
	}
	got := r.All()
	if len(got) != len(want) {
		t.Fatalf("%d entries: %v", len(got), entryNames(got))
	}
	for _, e := range got {
		w := want[e.Name]
		if e.Scope != w.scope || e.State() != w.state || !reflect.DeepEqual(e.Shadowed, w.shadowed) {
			t.Errorf("%s: scope %q state %s shadowed %v; want %+v", e.Name, e.Scope, e.State(), e.Shadowed, w)
		}
	}
	if !reflect.DeepEqual(entryNames(got)[:6], []string{"core-sw1", "inner-sw", "lab-rtr2", "dmz-fw", "stray", "v6"}) {
		t.Errorf("devices come first, in file order: %v", entryNames(got))
	}
}

func TestHostEntriesAreLinuxDevices(t *testing.T) {
	r := multiscope(t)
	e, ok := r.Lookup("web1", ScopeFilter{})
	if !ok || e.Source != SourceHost || e.Vendor != "linux" || e.Hostname != "192.0.2.10" || e.Login != "root" || e.Port != 2222 || e.Identity != "/keys/id" {
		t.Errorf("web1 = %+v", e)
	}
	if e, _ := r.Lookup("db1", ScopeFilter{}); e.Hostname != "db.example.net" || e.Login != "dba" || e.SSHPort() != 22 {
		t.Errorf("db1 = %+v", e)
	}
	if e, _ := r.Lookup("me", ScopeFilter{}); e.Hostname != "local" || e.Login != "" {
		t.Errorf("me = %+v", e)
	}
}

func TestHostAddressFromSingleHostPrefix(t *testing.T) {
	store := `version: 1
groups:
  readonly: {priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}
users: {}
scopes:
  linux-web1:
    prefixes: [192.0.2.10/32]
    secret: web1-secret-0123456789abcdef
  linux-v6:
    prefixes: ['2001:db8::5/128']
    secret: v6-secret-0123456789abcdefgh
  lab:
    prefixes: [172.16.0.0/12]
    secret: lab-secret-0123456789abcdef
filters: {allow: [], deny: []}
`
	p := filepath.Join(t.TempDir(), "store.yaml")
	_ = os.WriteFile(p, []byte(store), 0o600)
	_, m, err := model.LoadStore(p)
	if err != nil {
		t.Fatal(err)
	}
	reg := hostRegistry(t, "web1|root@192.0.2.10||linux-web1|192.0.2.1|\nv6|root@h6||linux-v6|192.0.2.1|\nbox|root@b||lab|192.0.2.1|\n")
	r := NewResolver(Empty(), reg, m)
	for name, addr := range map[string]string{"web1": "192.0.2.10", "v6": "2001:db8::5", "box": ""} {
		if e, ok := r.Lookup(name, ScopeFilter{}); !ok || e.Address != addr {
			t.Errorf("%s address = %q, want %q (%v)", name, e.Address, addr, ok)
		}
	}
	// By address.
	if e, ok := r.Lookup("2001:DB8:0:0:0:0:0:5", ScopeFilter{}); !ok || e.Name != "v6" {
		t.Errorf("lookup of the host's address: %+v %v", e, ok)
	}
}

func TestLookupByNameOrAddress(t *testing.T) {
	r := multiscope(t)
	for _, key := range []string{"core-sw1", "CORE-SW1", "10.1.2.3", "2001:0db8:0:0:0:0:0:1"} {
		if e, ok := r.Lookup(key, ScopeFilter{}); !ok || (e.Name != "core-sw1" && e.Name != "v6") {
			t.Errorf("Lookup(%q) = %+v, %v", key, e, ok)
		}
	}
	// An unregistered address stays unknown: the registry is the allow-list.
	for _, key := range []string{"10.1.2.4", "nope", "", "10.1.2.0/24"} {
		if e, ok := r.Lookup(key, ScopeFilter{}); ok {
			t.Errorf("Lookup(%q) found %+v", key, e)
		}
	}
}

// The caller's scopes decide what is visible (design 8): an entry no scope
// answers is nobody's.
func TestTierFiltering(t *testing.T) {
	r := multiscope(t)
	cases := []struct {
		name   string
		filter ScopeFilter
		want   []string
	}{
		{"unrestricted", ScopeFilter{}, []string{"core-sw1", "inner-sw", "lab-rtr2", "dmz-fw", "stray", "v6", "web1", "db1", "me", "orphan"}},
		{"carol: lab, dmz", ScopeFilter{Restricted: true, Scopes: []string{"lab", "dmz"}}, []string{"lab-rtr2", "dmz-fw", "web1", "me"}},
		{"bob: lab", ScopeFilter{Restricted: true, Scopes: []string{"lab"}}, []string{"lab-rtr2", "web1"}},
		{"prod only", ScopeFilter{Restricted: true, Scopes: []string{"prod"}}, []string{"core-sw1", "db1"}},
		{"no scopes", ScopeFilter{Restricted: true}, nil},
		{"a scope that routes nothing", ScopeFilter{Restricted: true, Scopes: []string{"gone"}}, []string{"orphan"}},
	}
	for _, c := range cases {
		if got := entryNames(r.Visible(c.filter)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// A hidden entry is not found, by name or by address.
	bob := ScopeFilter{Restricted: true, Scopes: []string{"lab"}}
	for _, key := range []string{"core-sw1", "10.1.2.3", "db1", "stray"} {
		if _, ok := r.Lookup(key, bob); ok {
			t.Errorf("bob found %q", key)
		}
	}
	if _, ok := r.Lookup("lab-rtr2", bob); !ok {
		t.Error("bob cannot find his own device")
	}
}

func TestDerivationOverRadiusAndMinimalFixtures(t *testing.T) {
	for _, fx := range []string{"store.minimal.yaml", "store.radius.yaml"} {
		m := fixtureModel(t, fx)
		f := Empty()
		f.Devices = []*Device{{Name: "sw", Address: "100.64.7.1", Vendor: "cisco"}}
		r := NewResolver(f, nil, m)
		if e, _ := r.Lookup("sw", ScopeFilter{}); e.Configured || e.State() != "unconfigured" {
			t.Errorf("%s: 100.64.7.1 is configured: %+v", fx, e)
		}
		// Any address a prefix of the fixture holds is configured.
		for _, s := range m.ScopeNames() {
			for _, pfx := range m.ScopePrefixes(s) {
				addr := strings.TrimSuffix(strings.SplitN(pfx, "/", 2)[0], ".0")
				if strings.Count(addr, ".") == 2 {
					addr += ".5"
				}
				f.Devices[0].Address = addr
				e, _ := NewResolver(f, nil, m).Lookup("sw", ScopeFilter{})
				if strings.Contains(pfx, ":") {
					continue
				}
				if !e.Configured {
					t.Errorf("%s: %s (in %s %s) is unconfigured", fx, addr, s, pfx)
				}
			}
		}
	}
}

func TestSharedNamespaceChecks(t *testing.T) {
	r := multiscope(t)
	cases := []struct {
		name         string
		allowGeneric bool
		want         string // "" = free
	}{
		{"core-sw1", false, "'core-sw1' is already registered (10.1.2.3); choose another name, or see 'tacctl device show core-sw1'"},
		{"Core-SW1", false, "'core-sw1' is already registered (10.1.2.3)"},
		{"WEB1", false, "'WEB1' is an enrolled host"},
		{"switch", false, "'switch' is a generic name"},
		{"switch", true, ""},
		{"fresh-sw", false, ""},
	}
	for _, c := range cases {
		err := r.CheckName(c.name, "cisco", c.allowGeneric, "keep it")
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	if err := r.CheckAddress("10.1.2.3", ""); err == nil || !strings.Contains(err.Error(), "10.1.2.3 is already registered as 'core-sw1'; rename it with 'tacctl device rename core-sw1 <new>'") {
		t.Errorf("duplicate address: %v", err)
	}
	if err := r.CheckAddress("10.1.2.3", "CORE-SW1"); err != nil {
		t.Errorf("a device may keep its own address: %v", err)
	}
	if err := r.CheckAddress("10.1.2.99", ""); err != nil {
		t.Error(err)
	}
}

func TestCheckHostName(t *testing.T) {
	f := Empty()
	f.Devices = []*Device{{Name: "core-sw1", Address: "10.0.0.1", Vendor: "cisco"}}
	f.GenericNames = []string{`lab-\d`}
	cases := []struct {
		name     string
		enrolled bool
		want     string
	}{
		{"web1", false, ""},
		{"core-sw1", false, "already registered as a device (10.0.0.1)"},
		{"CORE-sw1", true, "already registered as a device"},
		{"switch", false, "generic name"},
		{"ubuntu", false, "generic name"},
		{"lab-1", false, "generic name"},
		{"ubuntu", true, ""}, // enrolled before the registry: not refused retroactively
	}
	for _, c := range cases {
		err := CheckHostName(f, c.name, c.enrolled)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s (enrolled %v): %v, want %q", c.name, c.enrolled, err, c.want)
		}
	}
}

func TestNotices(t *testing.T) {
	f := Empty()
	f.Devices = []*Device{
		{Name: "router", Address: "10.0.0.1", Vendor: "cisco", Ack: []string{"generic-name"}},
		{Name: "pinned", Address: "10.0.0.2", Vendor: "juniper", HostKeys: []string{"ssh-ed25519 AAAA"}},
		{Name: "bare", Address: "10.0.0.3", Vendor: "wti"},
		{Name: "Switch2", Address: "10.0.0.4", Vendor: "other"},
	}
	reg := hostRegistry(t, "ubuntu|root@h||lab|1.1.1.1|\nweb1|root@w||lab|1.1.1.1|\n")
	r := NewResolver(f, reg, nil)
	kinds := func(name string) (open, all []string) {
		e, _ := r.Lookup(name, ScopeFilter{})
		ns := r.NoticesFor(e)
		for _, n := range ns {
			all = append(all, n.Kind)
		}
		for _, n := range Open(ns) {
			open = append(open, n.Kind)
		}
		return
	}
	for name, want := range map[string]struct{ open, all []string }{
		"router":  {[]string{"hostkey-unpinned"}, []string{"generic-name", "hostkey-unpinned"}},
		"pinned":  {nil, nil},
		"bare":    {[]string{"hostkey-unpinned"}, []string{"hostkey-unpinned"}},
		"Switch2": {[]string{"generic-name", "hostkey-unpinned"}, []string{"generic-name", "hostkey-unpinned"}},
		"ubuntu":  {[]string{"generic-name"}, []string{"generic-name"}},
		"web1":    {nil, nil},
	} {
		open, all := kinds(name)
		if !reflect.DeepEqual(open, want.open) || !reflect.DeepEqual(all, want.all) {
			t.Errorf("%s: open %v all %v; want %+v", name, open, all, want)
		}
	}
	e, _ := r.Lookup("Switch2", ScopeFilter{})
	for _, n := range r.NoticesFor(e) {
		if !strings.Contains(n.Text, "tacctl device notice Switch2 ack "+n.Kind) {
			t.Errorf("%s notice does not end in its command: %s", n.Kind, n.Text)
		}
	}
	h, _ := r.Lookup("ubuntu", ScopeFilter{})
	if txt := r.NoticesFor(h)[0].Text; !strings.Contains(txt, "hostnamectl set-hostname") || !strings.Contains(txt, "tacctl host enroll") {
		t.Errorf("host notice: %s", txt)
	}
}
