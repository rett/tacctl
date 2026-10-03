package conf

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/py"
)

// The schema half of tests/unit/listeners.bats (tacctl 0.1.16), named after
// the bats tests. The unit-file, logrotate and renderer-constant tests
// belong to the TACACS+ backend packages.

func listener(c *Config, name, json string) error {
	return c.SetJSON("listeners.tacacs."+name, json)
}

func TestListenerSchemaStoredWithOnlyWhatDiffersFromTheDefaults(t *testing.T) {
	c := tempConf(t)
	must(t, listener(c, "mgmt", `{"network": "tcp", "address": "10.1.0.1:4949", "role": "both", "tls": {"enabled": false}}`))
	text := readFile(t, c.Path)
	for _, want := range []string{"mgmt:", "network: tcp", "address: 10.1.0.1:4949"} {
		if !strings.Contains(text, want) {
			t.Fatalf("lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "role") || strings.Contains(text, "tls") {
		t.Fatalf("defaults written:\n%s", text)
	}
}

func TestListenerSchemaTheDefaultListenerSetToItsDefaultIsNotWrittenDown(t *testing.T) {
	c := tempConf(t)
	must(t, listener(c, "default", `{"network": "tcp", "address": "10.1.0.1:49"}`))
	hasFile(t, c)
	must(t, listener(c, "default", `{"network": "tcp", "address": ":49"}`))
	noFile(t, c)
	if strings.Contains(DefaultsText, "listeners") {
		t.Fatal("the listener model is a shipped default line")
	}
}

func TestListenerSchemaTcp6TakesABracketedIPv6AddressTcpAnIPv4One(t *testing.T) {
	c := tempConf(t)
	must(t, listener(c, "a", `{"network": "tcp6", "address": "[::1]:4949"}`))
	must(t, listener(c, "b", `{"network": "tcp", "address": "127.0.0.1:4950"}`))
	must(t, listener(c, "c", `{"network": "tcp6", "address": ":4951"}`))
	refused(t, listener(c, "d", `{"network": "tcp", "address": "[::1]:4952"}`), "tcp takes an IPv4 address")
	refused(t, listener(c, "d", `{"network": "tcp6", "address": "127.0.0.1:4952"}`), "tcp6 takes an IPv6 address")
}

func TestListenerSchemaTheReservedTLSFieldsAreAcceptedWhileTLSEnabledIsFalse(t *testing.T) {
	c := tempConf(t)
	must(t, listener(c, "tls", `{"network": "tcp", "address": ":300", "tls": {"enabled": false, "cert": "/etc/tacctl/tls/cert.pem", "key": "/etc/tacctl/tls/key.pem", "ca": "/etc/tacctl/tls/ca.pem", "require_client_cert": true}}`))
	text := readFile(t, c.Path)
	if !strings.Contains(text, "cert: /etc/tacctl/tls/cert.pem") || !strings.Contains(text, "require_client_cert: true") ||
		strings.Contains(text, "enabled") {
		t.Fatalf("file:\n%s", text)
	}
	assertLines(t, c.Schema.ValidateFile(c.Path))
}

func TestListenerSchemaTLSEnabledTrueIsRefusedAsReservedAndNothingIsWritten(t *testing.T) {
	c := tempConf(t)
	refused(t, listener(c, "tls", `{"network": "tcp", "address": ":300", "tls": {"enabled": true, "cert": "/a", "key": "/b"}}`),
		"listeners.tacacs.tls: tls.enabled: true is reserved for a future release")
	noFile(t, c)
}

func TestListenerSchemaAHandWrittenTLSEnabledTrueIsReportedByTheOverridesWalk(t *testing.T) {
	got := validateText(t, "listeners:\n  tacacs:\n    tls: {network: tcp, address: \":300\", tls: {enabled: true}}\n")
	if !strings.Contains(got, "listeners.tacacs.tls: tls.enabled: true is reserved for a future release") {
		t.Fatalf("got %q", got)
	}
}

func TestListenerSchemaBadAddressesNetworksRolesNamesKeysAndBackendsAreRefused(t *testing.T) {
	c := tempConf(t)
	for _, tc := range []struct{ name, json, want string }{
		{"x", `{"network": "tcp", "address": "nonsense"}`, "must be host:port"},
		{"x", `{"network": "tcp", "address": ":0"}`, "port must be 1..65535"},
		{"x", `{"network": "tcp", "address": ":70000"}`, "port must be 1..65535"},
		{"x", `{"network": "tcp", "address": "host.example:49"}`, "is not an IP address"},
		{"x", `{"network": "tcp"}`, "address is required"},
		{"x", `{"network": "sctp", "address": ":300"}`, "network must be one of tcp, tcp6, udp, udp6"},
		{"x", `{"network": "udp", "address": ":300"}`, "the tacacs backend listens on tcp or tcp6 only"},
		{"x", `{"network": "tcp", "address": ":300", "role": "auth"}`, "a tacacs listener has role both"},
		{"x", `{"network": "tcp", "address": ":300", "role": "bogus"}`, "role must be one of auth, acct, both"},
		{"x", `{"network": "tcp", "address": ":300", "port": 49}`, "unknown keys ['port']"},
		{"x", `{"network": "tcp", "address": ":300", "tls": {"cipher": "x"}}`, "tls: unknown keys ['cipher']"},
		{"x", `{"network": "tcp", "address": ":300", "tls": {"enabled": "yes"}}`, "tls.enabled must be true or false"},
		{"x", `{"network": "tcp", "address": ":300", "metrics_address": "nope"}`, "metrics_address: must be host:port"},
		{"Bad", `{"network": "tcp", "address": ":300"}`, "a listener name is a lowercase letter"},
		{"x", `"tcp :300"`, "must be a mapping"},
	} {
		refused(t, listener(c, tc.name, tc.json), tc.want)
	}
	refused(t, c.SetJSON("listeners.ldap.auth", `{"network": "udp", "address": ":1812"}`), "'ldap' is not a backend with listeners")
	refused(t, c.SetJSON("listeners.tacacs", `{"x": {"address": ":300"}}`), "unknown config key")
	refused(t, c.Set("listeners.tacacs.x", ":300"), "listeners.tacacs.x:")
	noFile(t, c)
}

func TestListenerSchemaTwoListenersOnOneNetworkAndAddressAreRefused(t *testing.T) {
	c := tempConf(t)
	refused(t, listener(c, "a", `{"network": "tcp", "address": "10.1.0.1:49"}`),
		"listeners.tacacs.a: tcp 10.1.0.1:49 is already used by listeners.tacacs.default (tcp :49)")
	refused(t, listener(c, "a", `{"network": "tcp6", "address": "[::]:49"}`), "already used by")
	noFile(t, c)
	must(t, listener(c, "a", `{"network": "tcp", "address": "10.1.0.1:4949"}`))
	refused(t, listener(c, "b", `{"network": "tcp", "address": "10.1.0.1:4949"}`), "already used by listeners.tacacs.a")
	refused(t, listener(c, "b", `{"network": "tcp", "address": ":4949"}`), "already used by")
	must(t, listener(c, "b", `{"network": "tcp", "address": "10.1.0.2:4949"}`))
	must(t, listener(c, "a", `{"network": "tcp", "address": "10.1.0.1:4949"}`))
	refused(t, listener(c, "default", `{"network": "tcp", "address": "10.1.0.2:4949"}`), "already used by")
}

func TestListenerSchemaAHandWrittenCollisionIsReportedByTheOverridesWalk(t *testing.T) {
	got := validateText(t, "listeners:\n  tacacs:\n    a: {address: \":49\"}\n    b: 5\n")
	for _, want := range []string{"listeners.tacacs.b: must be a mapping",
		"listeners.tacacs.a: tcp :49 is already used by listeners.tacacs.default"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q lacks %q", got, want)
		}
	}
}

func TestListenerSchemaTwoListenersMayNotShareAMetricsAddressExceptTheSink(t *testing.T) {
	c := tempConf(t)
	must(t, listener(c, "a", `{"network": "tcp", "address": ":300", "metrics_address": "127.0.0.1:9100"}`))
	refused(t, listener(c, "b", `{"network": "tcp", "address": ":301", "metrics_address": "127.0.0.1:9100"}`),
		"metrics_address 127.0.0.1:9100 is already used by listeners.tacacs.a")
	must(t, listener(c, "b", `{"network": "tcp", "address": ":301", "metrics_address": "127.0.0.1:0"}`))
	must(t, listener(c, "c", `{"network": "tcp", "address": ":302", "metrics_address": "127.0.0.1:0"}`))
}

func TestListenerSchemaBackendsTacacsLevelIsAnIntegerLevel(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("backends.tacacs.level", "30"))
	if get(t, c, "backends.tacacs.level") != "30" {
		t.Fatal("not 30")
	}
	must(t, c.Set("backends.tacacs.level", "20"))
	noFile(t, c)
	refused(t, c.Set("backends.tacacs.level", "debug"), "must be an integer")
	refused(t, c.Set("backends.tacacs.level", "101"), "backends.tacacs.level:")
}

func TestListenerSchemaBackendsTacacsMetricsAddressIsHostPort(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("backends.tacacs.metrics_address", ":9090"))
	if get(t, c, "backends.tacacs.metrics_address") != ":9090" {
		t.Fatal("not :9090")
	}
	for _, v := range []string{"localhost:9090", "[::1]:9090", "127.0.0.1:0", "127.0.0.1:8080"} {
		must(t, c.Set("backends.tacacs.metrics_address", v))
	}
	noFile(t, c)
	refused(t, c.Set("backends.tacacs.metrics_address", "127.0.0.1"), "must be host:port")
	refused(t, c.Set("backends.tacacs.metrics_address", "127.0.0.1:99999"), "backends.tacacs.metrics_address:")
}

// backends_enabled itself is lib/backend.sh's (the backend registry
// package); its default comes from the schema entry checked here.
func TestListenerSchemaPerBackendSettingsDoNotDisturbBackendsEnabled(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("backends.tacacs.level", "30"))
	if c.HasOverride("backends.enabled") {
		t.Fatal("backends.enabled written")
	}
	if def, _ := c.Schema.ImplicitDefault("backends.enabled"); py.Repr(def) != "['tacacs']" {
		t.Fatalf("default %s", py.Repr(def))
	}
	assertLines(t, c.Schema.ValidateFile(c.Path))
}

// The conf half of "the shell constants are the python renderer's and the
// unit's defaults": the schema's defaults and the built-in listener.
func TestListenerSchemaDefaultsOfTheSettingsAndTheBuiltInListener(t *testing.T) {
	s := NewSchema(DefaultBackends)
	level, _ := s.ImplicitDefault("backends.tacacs.level")
	metrics, _ := s.ImplicitDefault("backends.tacacs.metrics_address")
	if py.Str(level)+" "+py.Str(metrics) != "20 127.0.0.1:8080" {
		t.Fatalf("got %v %v", level, metrics)
	}
	b, _ := ListenerBackendByID("tacacs")
	if len(b.Defaults) != 1 || b.Defaults[0].Name != "default" || py.Repr(b.Defaults[0].Value) != "{'network': 'tcp', 'address': ':49'}" {
		t.Fatalf("got %+v", b.Defaults)
	}
}

func effective(t *testing.T, c *Config) []string {
	t.Helper()
	var out []string
	for _, l := range ListenersEffective(c.Merged(), "tacacs") {
		m := l.MetricsAddress
		if m == "" {
			m = "-"
		}
		out = append(out, strings.Join([]string{l.Name, l.Network, l.Address, l.Role, m}, "\t"))
	}
	return out
}

func TestBackendListenersTheBuiltInDefaultWithoutATacctlYaml(t *testing.T) {
	assertLines(t, effective(t, tempConf(t)), "default\ttcp\t:49\tboth\t-")
}

func TestBackendListenersTheDefaultFirstThenTheOthersByName(t *testing.T) {
	c := tempConf(t)
	must(t, listener(c, "zeta", `{"network": "tcp6", "address": "[::1]:4951"}`))
	must(t, listener(c, "alpha", `{"network": "tcp", "address": "127.0.0.1:4950", "metrics_address": "127.0.0.1:9100"}`))
	must(t, listener(c, "default", `{"network": "tcp", "address": "10.1.0.1:49"}`))
	assertLines(t, effective(t, c),
		"default\ttcp\t10.1.0.1:49\tboth\t-",
		"alpha\ttcp\t127.0.0.1:4950\tboth\t127.0.0.1:9100",
		"zeta\ttcp6\t[::1]:4951\tboth\t-")
}

func TestBackendListenersAnInvalidHandWrittenEntryIsLeftOutAnInvalidDefaultFallsBack(t *testing.T) {
	c := tempConf(t)
	writeFile(t, c.Path, "listeners:\n  tacacs:\n    default: {address: \"nonsense\"}\n    bad: {network: udp, address: \":300\"}\n    good: {address: \":301\"}\n")
	c.Reload()
	assertLines(t, effective(t, c), "default\ttcp\t:49\tboth\t-", "good\ttcp\t:301\tboth\t-")
}

// validate_listen_address's verdicts (its "Invalid <net> address" message
// is the CLI's).
func TestValidateListenAddressUnchangedVerdicts(t *testing.T) {
	for _, ok := range [][2]string{{"tcp", ":49"}, {"tcp", "10.1.0.1:49"}, {"tcp6", "[::]:49"}} {
		if why := ListenAddressProblem(ok[0], ok[1]); why != "" {
			t.Errorf("%v refused: %s", ok, why)
		}
	}
	for _, bad := range [][2]string{{"tcp", "10.1.0.1"}, {"tcp", "[::1]:49"}, {"tcp6", "10.1.0.1:49"}, {"tcp", ":0"}, {"tcp", "example.net:49"}} {
		if ListenAddressProblem(bad[0], bad[1]) == "" {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestSplitListenAddressAndHostPort(t *testing.T) {
	for _, tc := range []struct {
		in   any
		host string
		port int
		ok   bool
	}{
		{":49", "", 49, true}, {"[::1]:4949", "::1", 4949, true}, {"10.0.0.1:049", "10.0.0.1", 49, true},
		{":" + strings.Repeat("9", 30), "", -1, true}, {"x", "", 0, false}, {49, "", 0, false}, {"a:b:1", "", 0, false},
	} {
		h, p, ok := SplitListenAddress(tc.in)
		if h != tc.host || p != tc.port || ok != tc.ok {
			t.Errorf("SplitListenAddress(%v) = %q %d %v", tc.in, h, p, ok)
		}
	}
	if HostPortProblem(":8080") != "" || HostPortProblem(5) == "" || HostPortProblem(":99999") != "port must be 0..65535" {
		t.Error("HostPortProblem")
	}
}

func TestListenerNormalizeFillsDefaults(t *testing.T) {
	l := ListenerNormalize("radius", "x", fromJSON(t, []byte(`{"address": ":1812", "tls": {"cert": "/c"}}`)))
	if l.Network != "udp" || l.Role != "auth" || l.TLS.Cert != "/c" || l.TLS.Enabled || l.Name != "x" {
		t.Fatalf("got %+v", l)
	}
	if _, ok := ListenerBackendByID("ldap"); ok {
		t.Fatal("ldap")
	}
}
