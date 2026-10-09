package devices

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/model"
)

// --- envsubst, awk 'NF', the route lookup -------------------------------------

// The cases are GNU envsubst 0.21's answers (probed on the dev server).
func TestExpandIsEnvsubst(t *testing.T) {
	vars := map[string]string{"X": "1", "Y": "2", "Z": "zz"}
	for _, c := range []struct{ in, want string }{
		{"a $X ${X} ${X ${Y} $Y_ $ ${} ${1}\n", "a 1 1 ${X 2 $Y_ $ ${} ${1}\n"},
		{"$Z ${Z} stay", "$Z ${Z} stay"}, // not allowed: kept as written
		{"$$X${X}$", "$11$"},
		{"${UNSET}|$UNSET|", "||"}, // allowed, not set: nothing
		{"${X}${Y}x$X_y", "12x$X_y"},
		{"$9 $_ ${_}", "$9  "},
		{"no dollars", "no dollars"},
		{"multi\n${X}\nline", "multi\n1\nline"},
	} {
		if got := Expand(c.in, []string{"X", "Y", "UNSET", "_"}, vars); got != c.want {
			t.Errorf("Expand(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// mawk 'NF': blanks and tabs are no field; \r, \v and \f are.
func TestDropBlankIsAwkNF(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{" \r\n\v\n\f\nx\n \t \n", " \r\n\v\n\f\nx\n"},
		{"a\n\n!\nb", "a\n!\nb\n"},
		{"", ""},
		{"\n\n", ""},
	} {
		if got := DropBlank(c.in); got != c.want {
			t.Errorf("DropBlank(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestServerIP(t *testing.T) {
	ctx := context.Background()
	r := &fake.Runner{}
	r.On([]string{"ip", "-4", "route", "get", "1.0.0.0"},
		execx.Result{Stdout: []byte("1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0\n    cache\n")})
	if got := ServerIP(ctx, r); got != "10.0.0.42" {
		t.Errorf("got %q", got)
	}
	if !r.Called("ip", "-4", "route", "get", "1.0.0.0") {
		t.Error("ip was not asked")
	}
	r.On([]string{"ip"}, execx.Result{Stdout: []byte("unreachable\n"), Code: 2})
	if got := ServerIP(ctx, r); got != UnknownServer {
		t.Errorf("no src: %q", got)
	}
	r.On([]string{"ip"}, execx.Result{Stdout: []byte("x src 1.1.1.1\ny src\tsrc 2.2.2.2\n")})
	if got := ServerIP(ctx, r); got != "1.1.1.1\nsrc\n2.2.2.2" {
		t.Errorf("several: %q", got)
	}
	r.Missing("ip")
	if got := ServerIP(ctx, r); got != UnknownServer {
		t.Errorf("no ip: %q", got)
	}
}

// --- protocols ---------------------------------------------------------------------

func TestProtocols(t *testing.T) {
	if ProtocolValid("tacacs") != "" || ProtocolValid("radius") != "" {
		t.Error("known protocols refused")
	}
	if got := ProtocolValid("ldap"); got != "Unknown protocol 'ldap'. Known protocols: tacacs, radius" {
		t.Error(got)
	}
	for _, c := range []struct{ given, choice, src, proto, source, note string }{
		{"radius", "tacacs", "auth-method", "radius", SourceFlag, ", protocol: RADIUS"},
		{"tacacs", "radius", "auth-method", "tacacs", SourceFlag, ""},
		{"", "radius", "auth-method", "radius", SourceScope, ", protocol: RADIUS — the scope's auth-method"},
		{"", "radius", "protocols", "radius", SourceProtocols, ", protocol: RADIUS — the scope's only protocol"},
		{"", "tacacs", "protocols", "tacacs", SourceProtocols, ""},
		{"", "", "", "tacacs", SourceDefault, ""},
	} {
		p, s := ResolveProtocol(c.given, c.choice, c.src)
		if p != c.proto || s != c.source || protocolNote(p, s) != c.note {
			t.Errorf("%+v: got %s %s %q", c, p, s, protocolNote(p, s))
		}
	}
	if CiscoTemplate(false, TACACS) != "cisco" || CiscoTemplate(true, TACACS) != "cisco-legacy" ||
		CiscoTemplate(false, RADIUS) != "cisco-radius" || JuniperTemplate(TACACS) != "juniper" ||
		JuniperTemplate(RADIUS) != "juniper-radius" || WTITemplate(TACACS) != "wti" || WTITemplate(RADIUS) != "wti-radius" {
		t.Error("template names")
	}
}

// --- templates ----------------------------------------------------------------------

func TestResolveTemplate(t *testing.T) {
	dir := t.TempDir()
	tp, err := ResolveTemplate(dir, "cisco")
	if err != nil || tp.Path != "" || tp.Origin() != "built-in cisco.template" || !strings.Contains(tp.Text, "tacacs server TACACS") {
		t.Fatalf("built-in: %+v %v", tp, err)
	}
	// A directory of that name is no template; a file is.
	if err := os.Mkdir(filepath.Join(dir, "wti.template"), 0o700); err != nil {
		t.Fatal(err)
	}
	if tp, _ := ResolveTemplate(dir, "wti"); tp.Path != "" {
		t.Errorf("directory taken: %+v", tp)
	}
	p := filepath.Join(dir, "cisco.template")
	if err := os.WriteFile(p, []byte("MINE ${SERVER_IP}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tp, err = ResolveTemplate(dir, "cisco")
	if err != nil || tp.Path != p || tp.Origin() != p || tp.Text != "MINE ${SERVER_IP}\n" {
		t.Errorf("override: %+v %v", tp, err)
	}
	if _, err := ResolveTemplate(dir, "nosuch"); err == nil {
		t.Error("no error for an unknown template")
	}
	if tp, _ := ResolveTemplate("", "juniper"); tp.Path != "" || tp.Text == "" {
		t.Errorf("no override dir: %+v", tp)
	}
}

// --- WTI --------------------------------------------------------------------------------

// [[:space:]] or [^[:print:]] in C.UTF-8 (glibc 2.39).
func TestWTIUnsafe(t *testing.T) {
	for s, want := range map[string]bool{
		"abc-DEF_123": false, "ab+cd/ef=": false, "café": false, "a b": true, "a\tb": true, "\x01": true,
		"\u00a0": false, "\u2007": false, "\u202f": false, // no-break spaces are printable, not space
		"\u3000": true, "\u1680": true, "\u2000": true, "\u205f": true, "\u2028": true, "\u2029": true,
		"\u0085": true, "\u0378": true, "\u200b": false, "\U000F0000": false, "\U0001F511": false,
	} {
		if got := wtiUnsafe(s); got != want {
			t.Errorf("wtiUnsafe(%q) = %v", s, got)
		}
	}
	for priv, want := range map[string]string{"0": "ViewOnly", "4": "ViewOnly", "5": "User", "9": "User",
		"10": "SuperUser", "14": "SuperUser", "15": "Administrator", "x": "ViewOnly"} {
		if _, got := wtiLevel(priv); got != want {
			t.Errorf("wtiLevel(%s) = %s", priv, got)
		}
	}
}

// --- RADIUS prepare --------------------------------------------------------------------

type fakeListeners struct {
	ls  []backend.Listener
	err error
}

func (f fakeListeners) List() ([]backend.Listener, error)               { return f.ls, f.err }
func (fakeListeners) Show(context.Context, string) (string, error)      { return "", nil }
func (fakeListeners) Set(context.Context, string, string, string) error { return nil }
func (fakeListeners) Reset(context.Context, string) error               { return nil }

type fakeRadius struct {
	vars map[string]string
	c    backend.Constraints
	l    fakeListeners
}

func (f *fakeRadius) DeviceVars(context.Context, string, string) (map[string]string, error) {
	return f.vars, nil
}
func (f *fakeRadius) SecretConstraints() backend.Constraints { return f.c }
func (f *fakeRadius) Listeners() backend.ListenerOps         { return f.l }

func defaultRadius() *fakeRadius {
	return &fakeRadius{
		vars: map[string]string{"AUTH_PORT": "1812", "ACCT_PORT": "1813", "SECRET": "lab-secret-0123456789abcdef"},
		c:    backend.Constraints{MaxLen: 63, Charset: "[!-~]"},
		l: fakeListeners{ls: []backend.Listener{{Name: "auth", Network: "udp", Address: ":1812"},
			{Name: "acct", Network: "udp", Address: ":1813"}}},
	}
}

// fixture loads tests/fixtures/<store> and a tacctl.yaml with overrides.
func fixture(t *testing.T, store, overrides string) (*model.Model, *conf.Config) {
	t.Helper()
	_, m, err := model.LoadStore("../../tests/fixtures/" + store)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	if overrides != "" {
		if err := os.WriteFile(p, []byte(overrides), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return m, conf.Load(p, []string{"tacacs", "radius"})
}

func refusal(t *testing.T, err error) string {
	t.Helper()
	var r *RefusedError
	if !errors.As(err, &r) {
		t.Fatalf("not refused: %v", err)
	}
	return strings.Join(r.Lines, "\n")
}

func TestPrepareRefusals(t *testing.T) {
	ctx := context.Background()
	m, _ := fixture(t, "store.radius.yaml", "")
	// store.radius.yaml: no scope enables a vendor attribute.
	if got := refusal(t, func() error { _, err := Prepare(ctx, "cisco", "lab", m, false, defaultRadius()); return err }()); !strings.Contains(got, "The RADIUS backend is not enabled") {
		t.Error(got)
	}
	got := refusal(t, func() error { _, err := Prepare(ctx, "juniper", "lab", m, true, defaultRadius()); return err }())
	for _, want := range []string{"Scope 'lab' sends no Juniper attribute over RADIUS (Juniper-Local-User-Name): juniper is not enabled for the scope and no address of it is tagged juniper.",
		"or for one device only:            tacctl scope devices lab set <device-ip> juniper"} {
		if !strings.Contains(got, want) {
			t.Errorf("vendor refusal lacks %q:\n%s", want, got)
		}
	}
	// A scope whose protocols leave RADIUS out.
	for _, s := range m.Scopes {
		if len(s.Protocols) > 0 && !s.ServedBy("radius") {
			got := refusal(t, func() error { _, err := Prepare(ctx, "cisco", s.Name, m, true, defaultRadius()); return err }())
			if !strings.Contains(got, "Scope '"+s.Name+"' is limited to tacacs (tacctl scope protocols)") ||
				!strings.Contains(got, "tacctl scope protocols "+s.Name+" set tacacs,radius") {
				t.Error(got)
			}
		}
	}
}

func TestPrepare(t *testing.T) {
	ctx := context.Background()
	m, _ := fixture(t, "store.multiscope.yaml", "")
	lab := m.Scope("lab")
	lab.VendorAttrs = []string{"cisco"}
	r, err := Prepare(ctx, "cisco", "lab", m, true, defaultRadius())
	if err != nil || r.AuthPort != "1812" || r.AcctPort != "1813" || r.Secret != "lab-secret-0123456789abcdef" ||
		r.VendorSent != "scope" || r.ServerAddr != "" || r.Warnings != "" {
		t.Fatalf("%+v %v", r, err)
	}
	// Only tagged addresses get the attribute.
	lab.VendorAttrs = nil
	lab.Devices = []model.Device{{CIDR: "192.168.8.0/24", Vendor: "wti"}, {CIDR: "192.168.7.7/32", Vendor: "wti"}}
	r, err = Prepare(ctx, "wti", "lab", m, true, defaultRadius())
	if err != nil || r.VendorSent != "tagged" || !strings.Contains(r.Warnings,
		"  - Scope 'lab' does not enable the WTI attribute; only its addresses tagged wti get it: 192.168.7.7/32 192.168.8.0/24.\n"+
			"    Configure only those devices from this, or enable it: tacctl scope vendor-attrs lab enable wti\n") {
		t.Fatalf("%+v %v", r, err)
	}
	lab.VendorAttrs = []string{"wti"}

	// Ports, secret, the secret's characters.
	for _, c := range []struct {
		vars map[string]string
		want string
	}{
		{map[string]string{"AUTH_PORT": "1812", "SECRET": "x"}, "Could not read the RADIUS auth and acct listener ports"},
		{map[string]string{"AUTH_PORT": "1812", "ACCT_PORT": "1813"}, "Scope 'lab' has no shared secret: set one with 'tacctl scope secret lab generate'."},
		{map[string]string{"AUTH_PORT": "1812", "ACCT_PORT": "1813", "SECRET": "has space-0123456789"}, "cannot be pasted into a device configuration"},
		{map[string]string{"AUTH_PORT": "1812", "ACCT_PORT": "1813", "SECRET": "café-0123456789abcdef"}, "? ! # $ \\ ; { } [ ] | & < > , * ( ) ` or a non-ASCII character"},
	} {
		f := defaultRadius()
		f.vars = c.vars
		if got := refusal(t, func() error { _, err := Prepare(ctx, "wti", "lab", m, true, f); return err }()); !strings.Contains(got, c.want) {
			t.Errorf("%v: %s", c.vars, got)
		}
	}
	// Long secret, charset, listeners.
	f := defaultRadius()
	f.vars["SECRET"] = strings.Repeat("a", 70) + "A"
	f.c.Charset = "[a-z]"
	f.l.ls = []backend.Listener{{Name: "auth", Network: "udp", Address: "10.0.0.77:1812"},
		{Name: "acct", Network: "udp", Address: "127.0.0.1:1813"}, {Name: "extra", Network: "udp", Address: "10.9.9.9:1"}}
	r, err = Prepare(ctx, "wti", "lab", m, true, f)
	if err != nil {
		t.Fatal(err)
	}
	want := "  - The secret is 71 characters; some RADIUS clients take no more than 63. FreeRADIUS accepts it, but check your\n" +
		"    device's limit before pasting (tacctl scope secret lab generate makes a 32-character one; the scope's secret is shared with TACACS+)\n" +
		"  - The secret has characters outside [a-z], which some RADIUS clients do not take\n" +
		"  - The acct listener is bound to 127.0.0.1: no device can reach it (tacctl config listen --backend radius)\n" +
		"  - The auth and acct listeners are bound to different addresses (10.0.0.77, 127.0.0.1); the device takes one address for both, this uses 10.0.0.77\n"
	if r.Warnings != want || r.ServerAddr != "10.0.0.77" {
		t.Errorf("warnings:\n%s\nwant:\n%s", r.Warnings, want)
	}
	f = defaultRadius()
	f.l.ls = []backend.Listener{{Name: "auth", Network: "udp6", Address: "[::]:1812"}, {Name: "acct", Network: "udp", Address: "[fd00::1]:1813"}}
	r, _ = Prepare(ctx, "wti", "lab", m, true, f)
	if r.Warnings != "  - IPv6 listener(s): auth (udp6 [::]:1812), acct (udp [fd00::1]:1813). This configuration addresses the server over IPv4 and will not reach them;\n    adapt the server address by hand\n" {
		t.Errorf("v6: %q", r.Warnings)
	}
	f.l.err = errors.New("no")
	if r, err = Prepare(ctx, "wti", "lab", m, true, f); err != nil || r.Warnings != "" {
		t.Errorf("listener error: %+v %v", r, err)
	}
}

// --- whole configs against the goldens ---------------------------------------------------

var reANSI = regexp.MustCompile("\x1b\\[[0-9;]*m")

// The eight goldens of tests/fixtures/golden (bats renders them from the
// imported tacquito.multiscope.yaml, which is store.multiscope.yaml; the
// RADIUS ones with every vendor enabled and the backend's default
// listeners).
func TestRenderGoldens(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", "")
	acl := func(v string) MgmtACL {
		n := "VTY-ACL"
		if v == "juniper" {
			n = "MGMT-ACL"
		}
		return MgmtACL{Name: n}
	}
	for _, g := range []struct {
		golden, vendor, scope string
		legacy                bool
		protocol              string
	}{
		{"cisco-lab.conf", "cisco", "lab", false, TACACS},
		{"cisco-prod.conf", "cisco", "prod", false, TACACS},
		{"cisco-legacy-lab.conf", "cisco", "lab", true, TACACS},
		{"juniper-lab.conf", "juniper", "lab", false, TACACS},
		{"wti-lab.conf", "wti", "lab", false, TACACS},
		{"cisco-radius-lab.conf", "cisco", "lab", false, RADIUS},
		{"juniper-radius-lab.conf", "juniper", "lab", false, RADIUS},
		{"wti-radius-lab.conf", "wti", "lab", false, RADIUS},
	} {
		d := Data{Model: m, Conf: c, TemplateDir: t.TempDir(), ServerIP: "10.0.0.42", ACL: acl(g.vendor)}
		source := SourceDefault
		if g.protocol == RADIUS {
			source = SourceFlag
			d.Radius = &Radius{AuthPort: "1812", AcctPort: "1813", Secret: m.Scope(g.scope).Secret, VendorSent: "scope"}
		}
		var buf bytes.Buffer
		if err := Render(&buf, Request{Vendor: g.vendor, Scope: g.scope, Legacy: g.legacy, Protocol: g.protocol, Source: source}, d); err != nil {
			t.Fatal(err)
		}
		golden(t, g.golden, reANSI.ReplaceAllString(buf.String(), ""))
	}
}

// golden is checkGolden (snmp_test.go; -update rewrites the goldens, the bats
// files use UPDATE_GOLDEN=1).
func golden(t *testing.T, name, got string) {
	t.Helper()
	checkGolden(t, name, got)
}

func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var a, b string
		if i < len(g) {
			a = g[i]
		}
		if i < len(w) {
			b = w[i]
		}
		if a != b {
			return "line " + strconv.Itoa(i+1) + ":\n got  " + a + "\n want " + b
		}
	}
	return ""
}

// An operator template: its variables are those of the whitelist only, and
// the note names its path.
func TestRenderOverride(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", "aaa:\n  order:\n    lab: local-first\nexec_timeout:\n  lab: 15\n")
	dir := t.TempDir()
	tmpl := "MY ${SERVER_IP} ${SECRET} ${AUTHN_METHODS} ${EXEC_TIMEOUT} ${RADIUS_GROUP} $TACACS_GROUP\n\n  \n${GROUP_SUMMARY}"
	if err := os.WriteFile(filepath.Join(dir, "cisco.template"), []byte(tmpl), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	d := Data{Model: m, Conf: c, TemplateDir: dir, ServerIP: "192.0.2.1", ACL: MgmtACL{Name: "VTY-ACL", CIDRs: []string{"10.0.0.0/8", "fd00::/64"}}}
	if err := Render(&buf, Request{Vendor: "cisco", Scope: "lab", Protocol: TACACS, Source: SourceDefault}, d); err != nil {
		t.Fatal(err)
	}
	out := reANSI.ReplaceAllString(buf.String(), "")
	for _, want := range []string{
		"MY 192.0.2.1 lab-secret-0123456789abcdef local group TACACS-GROUP 15 ${RADIUS_GROUP} TACACS-GROUP\n  readonly: priv-lvl 1\n  operator: priv-lvl 7\n  superuser: priv-lvl 15\n\n---",
		"  - Using template: " + filepath.Join(dir, "cisco.template") + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	// The ACL block: IPv4 only, as wildcards.
	vars := CiscoVars(Request{Vendor: "cisco", Scope: "lab", Protocol: TACACS}, d)
	if vars["VTY_ACL_BLOCK"] != "ip access-list standard VTY-ACL\n  remark Managed by tacctl — edit with 'tacctl config mgmt-acl'\n  permit 192.0.2.1 0.0.0.0\n  permit 10.0.0.0 0.255.255.255\n  deny   any log" ||
		vars["VTY_ACCESS_CLASS"] != "  access-class VTY-ACL in" {
		t.Errorf("%q %q", vars["VTY_ACL_BLOCK"], vars["VTY_ACCESS_CLASS"])
	}
	jv := JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, Data{Model: m, Conf: c, ServerIP: "x",
		ACL: MgmtACL{Name: "MGMT-ACL", CIDRs: []string{"fd00::/64", "10.0.0.0/8"}}})
	if !strings.HasPrefix(jv["MGMT_ACL_BLOCK"], "# Restrict SSH") || strings.Contains(jv["MGMT_ACL_BLOCK"], "fd00") ||
		!strings.Contains(jv["MGMT_ACL_BLOCK"], "set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 10.0.0.0/8\n") ||
		jv["authn_order"] != "[ password tacplus ]" {
		t.Errorf("%q", jv["MGMT_ACL_BLOCK"])
	}
}

// The WTI warnings: a long secret, punctuation, whitespace, a long user.
func TestWTIWarnings(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", "")
	render := func(secret string) string {
		m.Scope("lab").Secret = secret
		var buf bytes.Buffer
		if err := Render(&buf, Request{Vendor: "wti", Scope: "lab", Protocol: TACACS, Source: SourceDefault},
			Data{Model: m, Conf: c, ServerIP: "x"}); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if out := render("plain-key_0123456789"); strings.Contains(out, "Warnings:") {
		t.Error("warned for a plain key")
	}
	out := render("has space 0123456789abcdefghijklmnopq")
	for _, want := range []string{"\x1b[1;33mWarnings:\x1b[0m\n",
		"  - \x1b[0;31mSecret contains whitespace or non-printable characters — WTI rejects\x1b[0m\n",
		"      tacctl scope secret lab set $(openssl rand -hex 16)\n",
		"  - Secret is 37 chars. WTI documents no Secret Word maximum, but its other\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if out := render("ab+cd/ef=0123456789xyz"); !strings.Contains(out, "Secret contains punctuation (e.g. + / =); the WTI menu prompt is untested\n") {
		t.Error(out)
	}
}
