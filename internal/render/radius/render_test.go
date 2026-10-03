package radius_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/render/radius"
)

// Ports of tests/unit/render_radius.bats (the 0.1.16 renderer's pure
// pieces). The tests of the contract verbs the module owns (describe,
// installed, device_vars, status summary, the listeners CLI and schema) wait
// for WP2.3; the schema half of the listener tests is internal/conf's.

func TestHashRaw(t *testing.T) {
	hexof := func(s string) string { return fmt.Sprintf("%x", s) }
	for _, raw := range []string{
		"$2b$12$abcdefghijklmnopqrstuuLkZ0xN8Zr5Qe9u1F0mWqkO4d2c3V4sW",
		"$2a$10$abc./XYZ",
		"$2y$05$",
	} {
		got, err := radius.HashRaw(hexof(raw))
		if err != nil || got != raw {
			t.Errorf("HashRaw(%q) = %q, %v", raw, got, err)
		}
	}
	// Upper-case hex digits are hex.
	if got, err := radius.HashRaw(strings.ToUpper(hexof("$2b$12$abc"))); err != nil || got != "$2b$12$abc" {
		t.Errorf("upper-case hex: %q, %v", got, err)
	}
	for _, c := range []struct{ in, msg string }{
		{"zz", "a password hash is not hex-encoded bcrypt"},
		{"abc", "a password hash is not hex-encoded bcrypt"}, // odd length
		{hexof("$2b$12$caf\xc3\xa9"), "a password hash is not hex-encoded bcrypt"},
		{hexof(`$2b$12$abc"def`), "a password hash holds characters no bcrypt hash has"},
		{hexof(`$2b$12$abc\def`), "a password hash holds characters no bcrypt hash has"},
		{hexof("plaintext"), "a password hash holds characters no bcrypt hash has"},
		{hexof("$2c$12$abc"), "a password hash holds characters no bcrypt hash has"},
		{hexof("$2b$12$abc\n"), "a password hash holds characters no bcrypt hash has"},
		{"", "a password hash holds characters no bcrypt hash has"},
	} {
		got, err := radius.HashRaw(c.in)
		if err == nil || err.Error() != c.msg || got != "" {
			t.Errorf("HashRaw(%q) = %q, %v; want error %q", c.in, got, err, c.msg)
		}
	}
}

func TestFRSecret(t *testing.T) {
	cases := []struct{ in, want string }{
		// Without a backslash: single-quoted, only ' escaped.
		{`abc+/=._-0123456789`, `'abc+/=._-0123456789'`},
		{`two words #1 ; {x} %{User-Name}`, `'two words #1 ; {x} %{User-Name}'`},
		{`a"b`, `'a"b'`},
		{`it's`, `'it\'s'`},
		// '${...}' is expanded inside double quotes, never inside single ones.
		{`a${confdir}b $ENV{HOME}`, `'a${confdir}b $ENV{HOME}'`},
		// With a backslash: double-quoted, backslash and " escaped.
		{`a\b`, `"a\\b"`},
		{`ends\`, `"ends\\"`},
		{`a\"b'c`, `"a\\\"b'c"`},
		{`back\nslash-n`, `"back\\nslash-n"`},
		// Non-ASCII goes in as UTF-8 (0.1.16 wrote the same bytes).
		{"p\u00e4ss-\u20ac", "'p\u00e4ss-\u20ac'"},
		{"p\u00e4ss\\\u20ac", "\"p\u00e4ss\\\\\u20ac\""},
	}
	for _, c := range cases {
		got, ok := radius.FRSecret(c.in)
		if !ok || got != c.want {
			t.Errorf("FRSecret(%q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
	// No safe form: a backslash with a dollar sign, nothing, a control
	// character, DEL.
	for _, in := range []string{`a\b$c`, "", "tab\there", "nl\n", "nul\x00", "del\x7f"} {
		if got, ok := radius.FRSecret(in); ok || got != "" {
			t.Errorf("FRSecret(%q) = %q, %v; want refusal", in, got, ok)
		}
	}
}

func TestSecretThatCannotBeWrittenRefusesTheRender(t *testing.T) {
	m := radiusModel(t)
	scope(t, m, "prod").Secret = `top\\secret$value-0123456789`
	msg := renderErr(t, m)
	for _, want := range []string{"scope 'prod'", "tacctl scope protocols prod set tacacs", "tacctl scope secret prod generate"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "secret$value") {
		t.Errorf("the message names the secret: %s", msg)
	}
	_, err := radius.Render(m, cfg(t).Merged(), params("debian"))
	if got := radius.Report(err); got != "tacctl render: "+msg {
		t.Errorf("Report = %q", got)
	}
	if got := radius.Report(os.ErrNotExist); got != os.ErrNotExist.Error() {
		t.Errorf("Report of another error = %q", got)
	}
}

func TestSecretInTacacsOnlyScopeDoesNotStopTheRender(t *testing.T) {
	m := radiusModel(t)
	scope(t, m, "legacy").Secret = `top\\secret$value-0123456789`
	out := render(t, m, "debian")
	if strings.Contains(out.Conf, "secret$value") {
		t.Error("the secret of a TACACS+-only scope is in the conf")
	}
}

func TestClientsPerPrefixMostSpecificFirst(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	re := regexp.MustCompile(`^\s+(client|ipaddr|ipv6addr|secret|tacctl_scope) `)
	var got []string
	for _, l := range between(out.Conf, regexp.MustCompile(`One client per prefix`), regexp.MustCompile(`authorize \{`)) {
		if re.MatchString(l) {
			got = append(got, l)
		}
	}
	want := `	client prod-inner.1 {
		ipaddr = 10.10.99.0/24
		secret = "inner\\secret \"quoted\" 0123456789"
		tacctl_scope = "prod-inner"
	client wifi.1 {
		ipaddr = 10.20.0.0/16
		secret = 'wifi-radius-only-0123456789'
		tacctl_scope = "wifi"
	client prod.1 {
		ipaddr = 10.0.0.0/8
		secret = 'prod-secret-0123456789abcdef'
		tacctl_scope = "prod"
	client lab.1 {
		ipaddr = 172.16.0.0/12
		secret = 'it\'s a "lab" secret ${confdir} #1'
		tacctl_scope = "lab"
	client lab.2 {
		ipaddr = 192.168.0.0/16
		secret = 'it\'s a "lab" secret ${confdir} #1'
		tacctl_scope = "lab"
	client lab.3 {
		ipv6addr = fd00:10::/64
		secret = 'it\'s a "lab" secret ${confdir} #1'
		tacctl_scope = "lab"`
	if strings.Join(got, "\n") != want {
		t.Errorf("clients:\n%s\nwant:\n%s", strings.Join(got, "\n"), want)
	}
}

func TestScopeNotServedHasNoClient(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	for _, s := range []string{"legacy", "198.51.100"} {
		if strings.Contains(out.Conf, s) {
			t.Errorf("conf mentions %q", s)
		}
	}
	if strings.Contains(out.Users, "legacy") {
		t.Error("users mentions legacy")
	}
}

func TestNoScopeForRadiusRendersServerWithoutClients(t *testing.T) {
	m := radiusModel(t)
	for _, s := range m.Scopes {
		s.Protocols = []string{"tacacs"}
	}
	out := render(t, m, "debian")
	if regexp.MustCompile(`(?m)^\sclient `).MatchString(out.Conf) {
		t.Error("a client is rendered")
	}
	if !strings.Contains(out.Conf, "\nserver tacctl {\n") {
		t.Error("no server section")
	}
	if regexp.MustCompile(`(?m)^[a-z]`).MatchString(out.Users) {
		t.Error("the users file has an entry")
	}
}

func TestUsersEntries(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	rid := renderID(t, out.Conf)
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(rid) || rid != out.RenderID {
		t.Fatalf("render id %q (output says %q)", rid, out.RenderID)
	}
	if n := count(out.Users, regexp.MustCompile(`(?m)^[A-Za-z0-9_-]`)); n != 6 {
		t.Errorf("%d entries, want 6", n)
	}
	wantBob := fmt.Sprintf("bob\tTmp-String-0 == \"%s/lab\", Crypt-Password := \"$2a$12$bob..........................................................\", "+
		"Tacctl-Priv-Lvl := 7, Tacctl-Juniper-Class := \"OP-CLASS\", Tacctl-WTI-Super := 1\n"+
		"\tService-Type = NAS-Prompt-User,\n\tFall-Through = No\n", rid)
	if !strings.Contains(out.Users, "\n"+wantBob) {
		t.Errorf("bob's entry differs:\n%s", out.Users)
	}
	// alice: three served scopes, superuser.
	if n := count(out.Users, regexp.MustCompile(`(?m)^alice`)); n != 3 {
		t.Errorf("alice has %d entries, want 3", n)
	}
	alice := fmt.Sprintf("alice\tTmp-String-0 == \"%s/wifi\", Crypt-Password := ", rid)
	i := strings.Index(out.Users, alice)
	if i < 0 {
		t.Fatal("no alice entry for wifi")
	}
	ls := lines(out.Users[i:])
	if !strings.HasSuffix(ls[0], `, Tacctl-Priv-Lvl := 15, Tacctl-Juniper-Class := "RW-CLASS", Tacctl-WTI-Super := 3`) ||
		ls[1] != "\tService-Type = Administrative-User," {
		t.Errorf("alice:\n%s\n%s", ls[0], ls[1])
	}
	// erin: a custom group (priv 10: the SuperUser band).
	erin := fmt.Sprintf("erin\tTmp-String-0 == \"%s/prod-inner\"", rid)
	if !strings.Contains(out.Users, erin) ||
		!strings.Contains(out.Users, `, Tacctl-Priv-Lvl := 10, Tacctl-Juniper-Class := "NETOPS_class-1", Tacctl-WTI-Super := 2`) {
		t.Errorf("erin's entry differs")
	}
}

func TestUsersReplyIsServiceTypeAlone(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	seen := map[string]bool{}
	for _, l := range lines(out.Users) {
		if strings.HasPrefix(l, "\t") {
			seen[strings.TrimSuffix(l, ",")] = true
		}
	}
	want := map[string]bool{"\tFall-Through = No": true, "\tService-Type = Administrative-User": true, "\tService-Type = NAS-Prompt-User": true}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("reply lines: %v", seen)
	}
	var body []string
	for _, l := range lines(out.Users) {
		if !strings.HasPrefix(l, "#") {
			body = append(body, l)
		}
	}
	if regexp.MustCompile(`(^|[^-])(Cisco-AVPair|Juniper-Local-User-Name|WTI-Super)`).MatchString(strings.Join(body, "\n")) {
		t.Error("a vendor attribute is in the users file")
	}
	re := regexp.MustCompile(`(?m), Tacctl-Priv-Lvl := [0-9]*, Tacctl-Juniper-Class := "[A-Za-z0-9_-]*", Tacctl-WTI-Super := [0-3]$`)
	if n := count(out.Users, re); n != 6 {
		t.Errorf("%d control lines, want 6", n)
	}
}

func TestUsersWithoutEntry(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	for _, u := range []string{"carol", "root", "dave"} {
		if regexp.MustCompile(`(?m)^` + u).MatchString(out.Users) {
			t.Errorf("%s has an entry", u)
		}
	}
	// ...and their hashes are not in the file at all.
	if strings.Contains(out.Users, "carol...") {
		t.Error("carol's hash is in the users file")
	}
}

func TestDefaultNameRefusesTheRender(t *testing.T) {
	m := radiusModel(t)
	alice := *m.User("alice")
	alice.Name = "DEFAULT-admin"
	m.Users = append(m.Users, &alice)
	msg := renderErr(t, m)
	if !strings.Contains(msg, "user 'DEFAULT-admin' cannot be served over RADIUS") {
		t.Errorf("message: %s", msg)
	}
	// Out of RADIUS's scopes it is nobody's problem.
	m = radiusModel(t)
	dave := *m.User("dave")
	dave.Name = "DEFAULT-admin"
	m.Users = append(m.Users, &dave)
	render(t, m, "debian")
}

func TestRenderID(t *testing.T) {
	m := radiusModel(t)
	out := render(t, m, "debian")
	rid := renderID(t, out.Conf)
	if !strings.Contains(out.Conf, fmt.Sprintf("&Tmp-String-0 := \"%s/%%{client:tacctl_scope}\"", rid)) {
		t.Error("the policy does not carry the id")
	}
	if n := count(out.Users, regexp.MustCompile(`Tmp-String-0 == "`+rid+`/`)); n != 6 {
		t.Errorf("%d users entries carry the id, want 6", n)
	}
	if strings.Contains(out.Conf+out.Users, "@TACCTL_RENDER_ID@") {
		t.Error("the placeholder is left")
	}
	if strings.Contains(out.Dictionary, rid) {
		t.Error("the dictionary carries the id")
	}
	again := render(t, m, "debian")
	if again.Conf != out.Conf || again.Users != out.Users || again.Dictionary != out.Dictionary {
		t.Error("a second render differs")
	}
	// A change that touches only the users file moves the id in both.
	m.User("bob").Disabled = true
	changed := render(t, m, "debian")
	if got := renderID(t, changed.Conf); got == rid {
		t.Error("the id did not change")
	}
	if strings.Contains(changed.Users, rid) {
		t.Error("the old id is in the new users file")
	}
	// ...and the id is the hash of the three texts with the placeholder.
	if changed.RenderID != renderID(t, changed.Conf) {
		t.Error("Output.RenderID is not the id in the conf")
	}
}

func TestRenderIDChangesWithTheDictionary(t *testing.T) {
	m := radiusModel(t)
	p := params("debian")
	a, err := radius.Render(m, cfg(t).Merged(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Dictionary, "\n$INCLUDE /usr/share/freeradius/dictionary\n") {
		t.Error("the dictionary does not include the package's")
	}
	p.SystemDict = "/somewhere/else/dictionary"
	b, err := radius.Render(m, cfg(t).Merged(), p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.Dictionary, "\n$INCLUDE /somewhere/else/dictionary\n") {
		t.Error("the dictionary does not follow TACCTL_RADIUS_DICT")
	}
	if a.RenderID == b.RenderID || a.Conf == b.Conf {
		t.Error("the id did not follow the dictionary")
	}
	if a.Users == b.Users {
		t.Error("the users file does not carry the new id")
	}
}

func TestFilters(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	for _, want := range []string{
		`if ((&Packet-Src-IP-Address && (&Packet-Src-IP-Address <= 10.66.0.0/16)) || (&Packet-Src-IPv6-Address && (&Packet-Src-IPv6-Address <= fd00:10::bad/128))) {`,
		`if (!((&Packet-Src-IP-Address && (&Packet-Src-IP-Address <= 10.0.0.0/8)) || `,
		`&Response-Packet-Type := Do-Not-Respond`,
	} {
		if !strings.Contains(out.Conf, want) {
			t.Errorf("conf lacks %q", want)
		}
	}
	// Deny is tested before allow.
	if strings.Index(out.Conf, "filters.deny") > strings.Index(out.Conf, "filters.allow") {
		t.Error("allow before deny")
	}
	if n := count(out.Conf, regexp.MustCompile(`(?m)^\t\ttacctl_filter$`)); n != 2 {
		t.Errorf("tacctl_filter used %d times, want 2 (authorize, preacct)", n)
	}
}

func TestFilterOrderIsMostSpecificFirst(t *testing.T) {
	m := radiusModel(t)
	m.Filters.Deny = []string{"10.0.0.0/8", "10.1.0.0/16", "192.0.2.1/32", "fd00::/8", "10.1.2.0/24"}
	out := render(t, m, "debian")
	var order []string
	for _, mm := range regexp.MustCompile(`<= ([^)]+)\)`).FindAllStringSubmatch(between(out.Conf, regexp.MustCompile(`filters.deny`), regexp.MustCompile(`^\t\t\}`))[1], -1) {
		order = append(order, mm[1])
	}
	want := []string{"10.1.2.0/24", "10.1.0.0/16", "10.0.0.0/8", "192.0.2.1/32", "fd00::/8"}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("deny order %v, want %v", order, want)
	}
}

func TestNoFiltersNoPolicy(t *testing.T) {
	m := radiusModel(t)
	m.Filters.Allow, m.Filters.Deny = nil, nil
	out := render(t, m, "debian")
	if regexp.MustCompile(`(?m)^\s*tacctl_filter`).MatchString(out.Conf) || regexp.MustCompile(`(?m)^policy`).MatchString(out.Conf) {
		t.Error("a filter policy is rendered")
	}
}

func TestVendorClientsDefault(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	want := []string{
		"client prod.1 {", "ipaddr = 10.0.0.0/8", "secret = 'prod-secret-0123456789abcdef'",
		`tacctl_scope = "prod"`, `tacctl_device = "generic"`,
		`tacctl_send_cisco = "no"`, `tacctl_send_juniper = "no"`, `tacctl_send_wti = "no"`, "}",
	}
	if got := clientBlock(out.Conf, "prod.1"); !reflect.DeepEqual(got, want) {
		t.Errorf("block:\n%s", strings.Join(got, "\n"))
	}
	if n := count(out.Conf, regexp.MustCompile(`tacctl_send_[a-z]* = "yes"`)); n != 0 {
		t.Errorf("%d yes", n)
	}
}

func TestVendorClientsEnabledOnGenericOnly(t *testing.T) {
	m := radiusModel(t)
	scope(t, m, "lab").VendorAttrs = []string{"cisco", "wti"}
	out := render(t, m, "debian")
	for _, c := range []string{"lab.1", "lab.2", "lab.3"} {
		b := clientBlock(out.Conf, c)
		for _, want := range []string{`tacctl_send_cisco = "yes"`, `tacctl_send_juniper = "no"`, `tacctl_send_wti = "yes"`} {
			if !has(b, want) {
				t.Errorf("%s lacks %s", c, want)
			}
		}
	}
	if !has(clientBlock(out.Conf, "prod.1"), `tacctl_send_cisco = "no"`) {
		t.Error("prod.1 sends cisco")
	}
}

func TestVendorClientsTaggedAddress(t *testing.T) {
	m := radiusModel(t)
	prod := scope(t, m, "prod")
	prod.VendorAttrs = []string{"cisco", "juniper", "wti"}
	prod.Devices = []model.Device{{CIDR: "10.1.2.3/32", Vendor: "wti"}, {CIDR: "10.2.0.0/16", Vendor: "juniper"}}
	out := render(t, m, "debian")
	want := []string{
		"client prod.wti.1 {", "ipaddr = 10.1.2.3/32", "secret = 'prod-secret-0123456789abcdef'",
		`tacctl_scope = "prod"`, `tacctl_device = "wti"`,
		`tacctl_send_cisco = "no"`, `tacctl_send_juniper = "no"`, `tacctl_send_wti = "yes"`, "}",
	}
	if got := clientBlock(out.Conf, "prod.wti.1"); !reflect.DeepEqual(got, want) {
		t.Errorf("block:\n%s", strings.Join(got, "\n"))
	}
	b := clientBlock(out.Conf, "prod.juniper.1")
	for _, w := range []string{"ipaddr = 10.2.0.0/16", `tacctl_send_cisco = "no"`, `tacctl_send_juniper = "yes"`, `tacctl_send_wti = "no"`} {
		if !has(b, w) {
			t.Errorf("prod.juniper.1 lacks %s", w)
		}
	}
	// Most specific first: the /32 and the /16 before the scope's /8.
	var order []string
	for _, mm := range regexp.MustCompile(`(?m)^\tclient (prod\.\S+) \{`).FindAllStringSubmatch(out.Conf, -1) {
		order = append(order, mm[1])
	}
	if !reflect.DeepEqual(order, []string{"prod.wti.1", "prod.juniper.1", "prod.1"}) {
		t.Errorf("order %v", order)
	}
}

func TestVendorClientTagOnPrefixIsOneClient(t *testing.T) {
	m := radiusModel(t)
	scope(t, m, "prod-inner").Devices = []model.Device{{CIDR: "10.10.99.0/24", Vendor: "cisco"}}
	out := render(t, m, "debian")
	if n := count(out.Conf, regexp.MustCompile(`ipaddr = 10.10.99.0/24\n`)); n != 1 {
		t.Errorf("%d clients for the prefix", n)
	}
	if !has(clientBlock(out.Conf, "prod-inner.cisco.1"), `tacctl_device = "cisco"`) {
		t.Error("the tagged client is missing")
	}
	if strings.Contains(out.Conf, "client prod-inner.1 ") {
		t.Error("the untagged client is still there")
	}
}

func TestVendorTagsOfUnservedScopeNotRendered(t *testing.T) {
	m := radiusModel(t)
	legacy := scope(t, m, "legacy")
	legacy.Devices = []model.Device{{CIDR: "198.51.100.7/32", Vendor: "cisco"}}
	legacy.VendorAttrs = []string{"cisco"}
	if strings.Contains(render(t, m, "debian").Conf, "198.51.100") {
		t.Error("the tag of a TACACS+-only scope is rendered")
	}
}

func TestVendorPolicy(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	body := strings.Join(between(out.Conf, regexp.MustCompile(`^\tpost-auth \{`), regexp.MustCompile(`^\t\tPost-Auth-Type REJECT \{`)), "\n")
	if n := count(body, regexp.MustCompile(`(?m)^\s+if \(\("%\{client:tacctl_send_(cisco|juniper|wti)\}" == "yes"\) && &control:Tacctl-`)); n != 3 {
		t.Errorf("%d vendor conditions, want 3", n)
	}
	for _, want := range []string{
		`&Cisco-AVPair := "shell:priv-lvl=%{control:Tacctl-Priv-Lvl}"`,
		`&Juniper-Local-User-Name := &control:Tacctl-Juniper-Class`,
		`&WTI-Super := &control:Tacctl-WTI-Super`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("post-auth lacks %s", want)
		}
	}
	// The three are inside the branch a filtered packet does not take,
	// before the auth log.
	n, in := 0, false
	for _, l := range lines(body) {
		if strings.Contains(l, "if (!&control:Response-Packet-Type)") {
			in = true
		}
		if in && strings.Contains(l, "update reply") {
			n++
		}
		if in && strings.Contains(l, "tacctl_auth") {
			break
		}
	}
	if n != 3 {
		t.Errorf("%d update reply before tacctl_auth, want 3", n)
	}
	// Nothing tacctl-internal is ever put into the reply: no line of an
	// "update reply { ... }" block sets a Tacctl-* attribute.
	inReply := false
	for _, l := range lines(out.Conf) {
		switch {
		case strings.HasSuffix(l, "update reply {"):
			inReply = true
		case inReply && strings.TrimSpace(l) == "}":
			inReply = false
		case inReply && strings.HasPrefix(strings.TrimSpace(l), "&Tacctl-"):
			t.Errorf("internal attribute in a reply: %s", l)
		}
	}
	// A reject strips every vendor attribute.
	reject := strings.Join(between(out.Conf, regexp.MustCompile(`Post-Auth-Type REJECT \{`), regexp.MustCompile(`^\t\t\}`)), "\n")
	for _, a := range []string{"Service-Type", "Cisco-AVPair", "Juniper-Local-User-Name", "WTI-Super"} {
		if !strings.Contains(reject, "&"+a+" !* ANY") {
			t.Errorf("a reject does not strip %s", a)
		}
	}
}

func TestAuthLogNamesDeviceTag(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	if !strings.Contains(out.Conf, "scope=%{client:tacctl_scope} device=%{client:tacctl_device} client=") {
		t.Error("the auth log line does not name the device tag")
	}
}

func TestDictionary(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	var first string
	for _, l := range lines(out.Dictionary) {
		if !strings.HasPrefix(l, "#") && strings.TrimSpace(l) != "" {
			first = l
			break
		}
	}
	if first != "$INCLUDE /usr/share/freeradius/dictionary" {
		t.Errorf("first statement %q", first)
	}
	ls := lines(out.Dictionary)
	for _, want := range []string{"VENDOR\t\tWTI\t\t\t24496", "ATTRIBUTE\tWTI-Super\t\t41\tinteger"} {
		if !has(ls, want) {
			t.Errorf("dictionary lacks %q", want)
		}
	}
	for _, v := range []string{"ViewOnly\t0", "User\t1", "SuperUser\t2", "Administrator\t3"} {
		if want := "VALUE\t\tWTI-Super\t\t" + v; !has(ls, want) {
			t.Errorf("dictionary lacks %q", want)
		}
	}
	var internal []string
	for _, l := range ls {
		if f := strings.Fields(l); len(f) == 4 && f[0] == "ATTRIBUTE" && strings.HasPrefix(f[1], "Tacctl-") {
			internal = append(internal, f[1]+" "+f[2]+" "+f[3])
		}
	}
	if !reflect.DeepEqual(internal, []string{"Tacctl-Priv-Lvl 3990 integer", "Tacctl-Juniper-Class 3991 string", "Tacctl-WTI-Super 3992 integer"}) {
		t.Errorf("internal attributes %v", internal)
	}
	if !strings.Contains(out.Dictionary, "https://ftp.wti.com/InfoCenter/rsa/dictionary/dictionary.wti") {
		t.Error("the WTI source is not named")
	}
	// Nothing of the model is in it.
	if regexp.MustCompile(`prod|alice|secret-0123`).MatchString(out.Dictionary) {
		t.Error("the dictionary holds something of the model")
	}
}

func TestWTISuperBands(t *testing.T) {
	// The mapping of wti_access_level_for_privlvl / wti_super_for_privlvl in
	// lib/render_devices.sh at 0.1.16.
	for lvl := -2; lvl <= 20; lvl++ {
		wantV, wantL := 0, "ViewOnly"
		switch {
		case lvl >= 15:
			wantV, wantL = 3, "Administrator"
		case lvl >= 10:
			wantV, wantL = 2, "SuperUser"
		case lvl >= 5:
			wantV, wantL = 1, "User"
		}
		if v, l := radius.WTISuper(lvl); v != wantV || l != wantL {
			t.Errorf("WTISuper(%d) = %d %s, want %d %s", lvl, v, l, wantV, wantL)
		}
	}
}

func TestConfStructure(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	for _, want := range []string{"\nproxy_requests = no\n", "\n\tstatus_server = no\n"} {
		if !strings.Contains(out.Conf, want) {
			t.Errorf("conf lacks %q", want)
		}
	}
	if strings.Contains(out.Conf, "INCLUDE") {
		t.Error("the conf includes something of the package")
	}
	if regexp.MustCompile(`(?i)eap|mschap|chap `).MatchString(out.Conf) {
		t.Error("the conf mentions EAP or CHAP")
	}
	if n := count(out.Conf, regexp.MustCompile(`(?m)^\t(files|pap|always|detail|linelog) tacctl_`)); n != 6 {
		t.Errorf("%d module instances, want 6", n)
	}
	for _, a := range []string{"Cisco-AVPair", "Juniper-Local-User-Name", "WTI-Super", "Service-Type"} {
		if !strings.Contains(out.Conf, "&"+a+" !* ANY") {
			t.Errorf("a reject keeps %s", a)
		}
	}
}

func TestCommandRulesAreNotRendered(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	if regexp.MustCompile(`(?i)allow-commands|deny-commands|traceroute`).MatchString(out.Conf + out.Users) {
		t.Error("command rules are rendered")
	}
}

// goldenCase is a store, a family and the golden files it renders to.
func checkGolden(t *testing.T, m *model.Model, family, confGolden, usersGolden, dictGolden string) {
	t.Helper()
	out := render(t, m, family)
	for _, c := range []struct{ name, got, golden string }{
		{"conf", out.Conf, confGolden}, {"users", out.Users, usersGolden}, {"dictionary", out.Dictionary, dictGolden},
	} {
		if want := read(t, c.golden); c.got != want {
			t.Errorf("%s differs from %s:\n%s", c.name, c.golden, firstDiff(c.got, want))
		}
	}
}

func firstDiff(got, want string) string {
	g, w := lines(got), lines(want)
	for i := 0; i < len(g) || i < len(w); i++ {
		var a, b string
		if i < len(g) {
			a = g[i]
		}
		if i < len(w) {
			b = w[i]
		}
		if a != b {
			return fmt.Sprintf("line %d:\n  got:  %q\n  want: %q", i+1, a, b)
		}
	}
	return "(no difference in lines)"
}

func TestGoldenDebian(t *testing.T) {
	m := radiusModel(t)
	checkGolden(t, m, "debian", golden+"radius.debian.conf", golden+"radius.debian.users", golden+"radius.dictionary")
	out := render(t, m, "debian")
	for _, want := range []string{"\nlogdir = /var/log/freeradius\n", "\npidfile = /run/freeradius/freeradius.pid\n",
		"\nlibdir = /usr/lib/freeradius\n", "\n\tuser = freerad\n"} {
		if !strings.Contains(out.Conf, want) {
			t.Errorf("conf lacks %q", want)
		}
	}
}

func TestGoldenRHEL(t *testing.T) {
	m := radiusModel(t)
	// The same dictionary: both families keep the package's main one in one place.
	checkGolden(t, m, "rhel", golden+"radius.rhel.conf", golden+"radius.rhel.users", golden+"radius.dictionary")
	out := render(t, m, "rhel")
	for _, want := range []string{"\nlogdir = /var/log/radius\n", "\npidfile = /run/radiusd/radiusd.pid\n",
		"\nlibdir = /usr/lib64/freeradius\n", "\n\tuser = radiusd\n", "\n\tgroup = radiusd\n"} {
		if !strings.Contains(out.Conf, want) {
			t.Errorf("conf lacks %q", want)
		}
	}
}

// The store of tests/containers/radius (vendor attributes and tagged
// addresses on 127.0.0.0/8, an IPv6 prefix, a user named 007): the goldens
// were rendered from the snapshot by the 0.1.16 bash renderer.
func TestGoldenContainerStore(t *testing.T) {
	m := loadModel(t, "testdata/container.store.yaml")
	checkGolden(t, m, "debian", "testdata/container.debian.conf", "testdata/container.debian.users", "testdata/container.dictionary")
	checkGolden(t, m, "rhel", "testdata/container.rhel.conf", "testdata/container.rhel.users", "testdata/container.dictionary")
}

func TestLayoutsDifferInMainSettingsOnly(t *testing.T) {
	m := radiusModel(t)
	tail := func(conf string) string {
		var keep []string
		in := false
		for _, l := range lines(conf) {
			if strings.HasPrefix(l, "server tacctl") {
				in = true
			}
			if in && !strings.Contains(l, "Tmp-String-0") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	d, r := render(t, m, "debian"), render(t, m, "rhel")
	if tail(d.Conf) != tail(r.Conf) {
		t.Error("the server sections differ between the layouts")
	}
	if d.Dictionary != r.Dictionary {
		t.Error("the dictionaries differ")
	}
}

func TestListenersRenderedAsListenSections(t *testing.T) {
	m := radiusModel(t)
	merged := mergedWith(t, map[string]string{
		"auth":  `{"network": "udp", "address": "10.1.1.1:11812", "role": "auth"}`,
		"auth6": `{"network": "udp6", "address": "[::]:1812"}`,
	}, "auth", "auth6")
	out, err := radius.Render(m, merged, params("debian"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i, l := range lines(out.Conf) {
		if strings.Contains(l, "listeners.radius") {
			got = append(got, lines(out.Conf)[i:i+5]...)
		}
	}
	want := `	# listeners.radius.auth
	listen {
		type = auth
		ipaddr = 10.1.1.1
		port = 11812
	# listeners.radius.acct
	listen {
		type = acct
		ipaddr = *
		port = 1813
	# listeners.radius.auth6
	listen {
		type = auth
		ipv6addr = ::
		port = 1812`
	if strings.Join(got, "\n") != want {
		t.Errorf("listeners:\n%s", strings.Join(got, "\n"))
	}
}

func TestListenerProblemsRefuseTheRender(t *testing.T) {
	m := radiusModel(t)
	// Two udp listeners on one port: conf's setter refuses it, so the
	// problem is built into the view directly (a hand-edited tacctl.yaml).
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	if err := os.WriteFile(path, []byte("listeners:\n  radius:\n    again:\n      network: udp\n      address: 10.1.0.1:1812\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := loadConf(path)
	merged, err := radius.ConfView(c)
	if err != nil {
		t.Fatal(err)
	}
	_, err = radius.Render(m, merged, params("debian"))
	if err == nil || !strings.HasPrefix(err.Error(), "tacctl.yaml: listeners.radius.again: udp 10.1.0.1:1812 is already used by listeners.radius.auth") {
		t.Errorf("error: %v", err)
	}
}

// TestConfViewRefusals pins the messages of radius_conf_view at 0.1.16
// (yaml_problem's "<path>: <problem> (line L, column C)", the not-a-mapping
// text and the " -- fix it before rendering" suffix); the expected text was
// printed by the 0.1.16 bash program (the radius render program's `notes`
// command) for each file.
func TestConfViewRefusals(t *testing.T) {
	cases := []struct{ name, content, want string }{
		{"syntax error", "a: [\n", "expected the node content, but found '<stream end>' (line 2, column 1)"},
		{"mapping value", "a: b: c\n", "mapping values are not allowed here (line 1, column 5)"},
		{"unterminated quote", "a: \"unterminated\n", "found unexpected end of stream (line 2, column 1)"},
		{"tab", "a:\n\t- x\n", "found character '\\t' that cannot start any token (line 2, column 1)"},
		{"two documents", "x: 1\n---\ny: 2\n", "but found another document (line 2, column 1)"},
		{"control character", "a: b\x01c\n", "invalid YAML"},
		{"list", "- a\n- b\n", "not a YAML mapping"},
		{"set", "!!set {a}\n", "not a YAML mapping"},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "tacctl.yaml")
		if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := radius.ConfView(loadConf(path))
		want := path + ": " + c.want + " -- fix it before rendering"
		if err == nil || err.Error() != want {
			t.Errorf("%s: error %v, want %q", c.name, err, want)
		} else if got := radius.Report(err); got != "tacctl render: "+want {
			t.Errorf("%s: Report = %q", c.name, got)
		}
	}
	// A missing file, an empty one and one of comments are the defaults.
	dir := t.TempDir()
	for name, content := range map[string]string{"missing": "", "empty": "", "comments": "# nothing\n"} {
		path := filepath.Join(dir, name+".yaml")
		if name != "missing" {
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := radius.ConfView(loadConf(path)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNonASCIISecretIsWrittenAsUTF8(t *testing.T) {
	m := radiusModel(t)
	scope(t, m, "prod").Secret = "s\u00e9cret-\u20ac"
	out := render(t, m, "debian")
	if !strings.Contains(out.Conf, "secret = 's\u00e9cret-\u20ac'\n") {
		t.Error("the secret is not written as raw UTF-8")
	}
	var odd []string
	for _, n := range out.Notes {
		if n.Kind == "secret" {
			odd = append(odd, n.Detail)
		}
	}
	if !reflect.DeepEqual(odd, []string{"lab, prod, prod-inner"}) {
		t.Errorf("secret notes %v", odd)
	}
}

func TestRenderStoreValidates(t *testing.T) {
	s, _, err := model.LoadStore(fixtures + "store.radius.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := radius.RenderStore(s, cfg(t).Merged(), params("debian")); err != nil {
		t.Fatal(err)
	}
	// A store with a user in a scope that does not exist is invalid.
	bad, err := os.ReadFile(fixtures + "store.radius.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "store.yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(bad), "scopes: [lab]\n    hash: 243262243132246361726f6c", "scopes: [nowhere]\n    hash: 243262243132246361726f6c", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _, err = model.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = radius.RenderStore(s, cfg(t).Merged(), params("debian"))
	if err == nil || !strings.HasPrefix(err.Error(), "cannot render an invalid model:\n  - ") {
		t.Errorf("error: %v", err)
	}
}

func TestOutputWriteDir(t *testing.T) {
	out := render(t, radiusModel(t), "debian")
	dir := t.TempDir()
	if err := out.WriteDir(dir); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"conf": out.Conf, "users": out.Users, "dictionary": out.Dictionary} {
		if got := read(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s differs", name)
		}
		if st, _ := os.Stat(filepath.Join(dir, name)); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", name, st.Mode().Perm())
		}
	}
}
