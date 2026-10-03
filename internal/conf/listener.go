package conf

import (
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The listener model (lib/conf.sh _listener_py, plan 3.4):
// listeners.<backend>.<name> in tacctl.yaml says where a backend's daemon
// listens. Keys: network (tcp|tcp6|udp|udp6), address (host:port,
// [v6]:port or :port), role (auth|acct|both), metrics_address (host:port)
// and tls {enabled, cert, key, ca, require_client_cert}, reserved:
// 'enabled: true' is refused until a release implements TLS.

// ListenerBackend is one entry of LISTENER_BACKENDS: what a backend's
// daemon can do, and the listeners that exist without being written down
// (they can be changed and reset, not removed).
type ListenerBackend struct {
	ID       string
	Networks []string // the first is the default network
	Roles    []string // the last is the default role
	// Defaults are the built-in listeners in order, each as the mapping
	// tacctl.yaml would hold.
	Defaults []NamedValue
}

// NamedValue is a listener name with its tacctl.yaml mapping.
type NamedValue struct {
	Name  string
	Value *yamlpy.Map
}

// ListenerBackends is LISTENER_BACKENDS, in its order (which is the order
// collisions are looked for in).
var ListenerBackends = []ListenerBackend{
	// One tacquito process serves one stream listener, authentication and
	// accounting together.
	{ID: "tacacs", Networks: []string{"tcp", "tcp6"}, Roles: []string{"both"},
		Defaults: []NamedValue{{"default", yamlpy.NewMap("network", "tcp", "address", ":49")}}},
	// One FreeRADIUS process serves every listener; a listener answers
	// authentication or accounting, never both (a listener written without
	// a role is an authentication one).
	{ID: "radius", Networks: []string{"udp", "udp6"}, Roles: []string{"acct", "auth"},
		Defaults: []NamedValue{
			{"auth", yamlpy.NewMap("network", "udp", "address", ":1812", "role", "auth")},
			{"acct", yamlpy.NewMap("network", "udp", "address", ":1813", "role", "acct")},
		}},
}

// The listener vocabulary.
var (
	ListenerNetworks = []string{"tcp", "tcp6", "udp", "udp6"}
	ListenerRoles    = []string{"auth", "acct", "both"}
	ListenerKeys     = []string{"network", "address", "role", "metrics_address", "tls"}
	ListenerTLSKeys  = []string{"enabled", "cert", "key", "ca", "require_client_cert"}
)

var (
	reListenerName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	reHostPort     = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]*):([0-9]{1,5})$`)
	// Python's \d in a str pattern is any decimal digit (category Nd).
	reListenBracket = regexp.MustCompile(`^\[([^\]]+)\]:(\p{Nd}+)$`)
	reListenPlain   = regexp.MustCompile(`^([^:]*):(\p{Nd}+)$`)
)

// wildcardHosts are the hosts that bind every address.
var wildcardHosts = []string{"", "0.0.0.0", "::"}

// ListenerBackendByID returns the LISTENER_BACKENDS entry of id.
func ListenerBackendByID(id string) (ListenerBackend, bool) {
	for _, b := range ListenerBackends {
		if b.ID == id {
			return b, true
		}
	}
	return ListenerBackend{}, false
}

func (b ListenerBackend) defaultValue(name string) (*yamlpy.Map, bool) {
	for _, d := range b.Defaults {
		if d.Name == name {
			return d.Value, true
		}
	}
	return nil, false
}

// listenerIDs is ', '.join(LISTENER_BACKENDS).
func listenerIDs() string {
	ids := make([]string, len(ListenerBackends))
	for i, b := range ListenerBackends {
		ids[i] = b.ID
	}
	return strings.Join(ids, ", ")
}

// SplitListenAddress is split_listen_address: 'host:port' or '[v6]:port'
// into host and port; ok is false when addr is neither (or not a string).
// A port too long to matter is returned as -1.
func SplitListenAddress(addr any) (host string, port int, ok bool) {
	s, isStr := addr.(string)
	if !isStr {
		return "", 0, false
	}
	m := reListenBracket.FindStringSubmatch(s)
	if m == nil {
		m = reListenPlain.FindStringSubmatch(s)
	}
	if m == nil {
		return "", 0, false
	}
	n, _ := py.Int(m[2])
	if n == nil || n.Cmp(big.NewInt(1<<20)) > 0 {
		return m[1], -1, true
	}
	return m[1], int(n.Int64()), true
}

// ipAddress is ipaddress.ip_address(s) for a string: the parsed address
// (an IPv4 or IPv6 host network) or ok false.
func ipAddress(s string) (cidr.Network, bool) {
	if strings.Contains(s, "/") {
		return cidr.Network{}, false
	}
	n, err := cidr.Parse(s)
	return n, err == nil
}

// ListenAddressProblem is listen_address_problem: "" when addr is a listen
// address of the network's family, else why not. The host is empty (every
// address) or an IP literal, never a name.
func ListenAddressProblem(network string, addr any) string {
	host, port, ok := SplitListenAddress(addr)
	if !ok {
		return "must be host:port, [ipv6]:port or :port"
	}
	if port < 1 || port > 65535 {
		return "port must be 1..65535"
	}
	if host != "" {
		ip, ok := ipAddress(host)
		if !ok {
			return fmt.Sprintf("%s is not an IP address", py.ReprString(host))
		}
		if (network == "tcp" || network == "udp") && ip.IsIPv6() {
			return fmt.Sprintf("%s takes an IPv4 address (%s6 for IPv6)", network, network)
		}
		if (network == "tcp6" || network == "udp6") && !ip.IsIPv6() {
			return fmt.Sprintf("%s takes an IPv6 address in brackets", network)
		}
	}
	return ""
}

// HostPortProblem is host_port_problem: "" when value is host:port (the
// host may be empty or a name; port 0 is the kernel's choice), else why
// not.
func HostPortProblem(value any) string {
	s, ok := value.(string)
	if !ok {
		return "must be a string host:port"
	}
	m := reHostPort.FindStringSubmatch(s)
	if m == nil {
		return "must be host:port (e.g. '127.0.0.1:8080' or ':8080')"
	}
	if n, _ := py.Int(m[2]); n.Cmp(big.NewInt(65535)) > 0 {
		return "port must be 0..65535"
	}
	return ""
}

// Listener is a listener with every key present (listener_normalize).
type Listener struct {
	Name           string
	Network        string
	Address        string
	Role           string
	MetricsAddress string // "" for none
	TLS            ListenerTLS
}

// ListenerTLS is the reserved tls block; Enabled is always false.
type ListenerTLS struct {
	Enabled           bool
	Cert, Key, CA     string
	RequireClientCert bool
}

// mget is dict.get on a value that should be a mapping.
func mget(v any, key string) (any, bool) {
	m, ok := v.(*yamlpy.Map)
	if !ok {
		return nil, false
	}
	return m.Get(key)
}

// truthy is Python's bool(v).
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case *yamlpy.Map:
		return x.Len() > 0
	}
	if b := py.BigInt(v); b != nil {
		return b.Sign() != 0
	}
	if l, ok := py.List(v); ok {
		return len(l) > 0
	}
	return true
}

func strOr(v any, ok bool, def string) string {
	if ok && truthy(v) {
		if s, isStr := v.(string); isStr {
			return s
		}
	}
	return def
}

// ListenerNormalize is listener_normalize: value (which must have passed
// ListenerProblem) with the defaults filled in.
func ListenerNormalize(backend, name string, value any) Listener {
	spec, _ := ListenerBackendByID(backend)
	l := Listener{Name: name}
	v, ok := mget(value, "network")
	l.Network = strOr(v, ok, spec.Networks[0])
	v, _ = mget(value, "address")
	l.Address, _ = v.(string)
	v, ok = mget(value, "role")
	l.Role = strOr(v, ok, spec.Roles[len(spec.Roles)-1])
	v, ok = mget(value, "metrics_address")
	l.MetricsAddress = strOr(v, ok, "")
	tls, ok := mget(value, "tls")
	if !ok || !truthy(tls) {
		tls = yamlpy.NewMap()
	}
	v, ok = mget(tls, "cert")
	l.TLS.Cert = strOr(v, ok, "")
	v, ok = mget(tls, "key")
	l.TLS.Key = strOr(v, ok, "")
	v, ok = mget(tls, "ca")
	l.TLS.CA = strOr(v, ok, "")
	v, _ = mget(tls, "require_client_cert")
	l.TLS.RequireClientCert = truthy(v)
	return l
}

// ListenerCompact is listener_compact: what tacctl.yaml stores for a
// listener, only what differs from the defaults.
func ListenerCompact(backend string, value any) *yamlpy.Map {
	spec, _ := ListenerBackendByID(backend)
	full := ListenerNormalize(backend, "", value)
	out := yamlpy.NewMap("network", full.Network, "address", full.Address)
	if full.Role != spec.Roles[len(spec.Roles)-1] {
		out.Set("role", full.Role)
	}
	if full.MetricsAddress != "" {
		out.Set("metrics_address", full.MetricsAddress)
	}
	tls := yamlpy.NewMap()
	for _, kv := range []struct {
		k string
		v any
	}{{"cert", full.TLS.Cert}, {"key", full.TLS.Key}, {"ca", full.TLS.CA}, {"require_client_cert", full.TLS.RequireClientCert}} {
		if truthy(kv.v) {
			tls.Set(kv.k, kv.v)
		}
	}
	if tls.Len() > 0 {
		out.Set("tls", tls)
	}
	return out
}

// sortedExtra is sorted(set(m) - set(known)).
func sortedExtra(m *yamlpy.Map, known []string) []string {
	var extra []string
	for _, k := range m.Keys() {
		if !slices.Contains(known, k) {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	return extra
}

// inStrings is 'v in (strings...)' with Python equality.
func inStrings(v any, set []string) bool {
	s, ok := v.(string)
	return ok && slices.Contains(set, s)
}

// ListenerProblem is listener_problem: "" when value is a valid
// listeners.<backend>.<name>, else why not.
func ListenerProblem(backend, name string, value any) string {
	spec, ok := ListenerBackendByID(backend)
	if !ok {
		return fmt.Sprintf("'%s' is not a backend with listeners (known: %s)", backend, listenerIDs())
	}
	if !reListenerName.MatchString(name) {
		return "a listener name is a lowercase letter, then up to 31 of [a-z0-9_-]"
	}
	m, isMap := value.(*yamlpy.Map)
	if !isMap {
		return "must be a mapping {network, address, role?, metrics_address?, tls?}"
	}
	if extra := sortedExtra(m, ListenerKeys); len(extra) > 0 {
		return fmt.Sprintf("unknown keys %s (known: %s)", py.Repr(extra), strings.Join(ListenerKeys, ", "))
	}
	network, ok := m.Get("network")
	if !ok {
		network = spec.Networks[0]
	}
	if !inStrings(network, ListenerNetworks) {
		return fmt.Sprintf("network must be one of %s (got %s)", strings.Join(ListenerNetworks, ", "), py.Repr(network))
	}
	if !inStrings(network, spec.Networks) {
		return fmt.Sprintf("the %s backend listens on %s only (got %s)", backend, strings.Join(spec.Networks, " or "), py.Str(network))
	}
	addr, ok := m.Get("address")
	if !ok {
		return "address is required"
	}
	if why := ListenAddressProblem(network.(string), addr); why != "" {
		return fmt.Sprintf("address %s: %s", py.Repr(addr), why)
	}
	role, ok := m.Get("role")
	if !ok {
		role = spec.Roles[len(spec.Roles)-1]
	}
	if !inStrings(role, ListenerRoles) {
		return fmt.Sprintf("role must be one of %s (got %s)", strings.Join(ListenerRoles, ", "), py.Repr(role))
	}
	if !inStrings(role, spec.Roles) {
		return fmt.Sprintf("a %s listener has role %s (got %s)", backend, strings.Join(spec.Roles, " or "), py.Str(role))
	}
	if ma, _ := m.Get("metrics_address"); ma != nil && !py.Equal(ma, "") {
		if why := HostPortProblem(ma); why != "" {
			return "metrics_address: " + why
		}
	}
	tlsV, ok := m.Get("tls")
	if ok && tlsV != nil {
		tls, isMap := tlsV.(*yamlpy.Map)
		if !isMap {
			return fmt.Sprintf("tls must be a mapping {%s}", strings.Join(ListenerTLSKeys, ", "))
		}
		if extra := sortedExtra(tls, ListenerTLSKeys); len(extra) > 0 {
			return fmt.Sprintf("tls: unknown keys %s (known: %s)", py.Repr(extra), strings.Join(ListenerTLSKeys, ", "))
		}
		for _, k := range []string{"enabled", "require_client_cert"} {
			if v, ok := tls.Get(k); ok {
				if _, isBool := v.(bool); !isBool {
					return fmt.Sprintf("tls.%s must be true or false", k)
				}
			}
		}
		for _, k := range []string{"cert", "key", "ca"} {
			if v, ok := tls.Get(k); ok {
				if _, isStr := v.(string); !isStr {
					return fmt.Sprintf("tls.%s must be a file path", k)
				}
			}
		}
		if v, _ := tls.Get("enabled"); truthy(v) {
			return "tls.enabled: true is reserved for a future release (TLS listeners are not implemented)"
		}
	}
	return ""
}

// listenersSection is (doc or {}).get('listeners') for a document.
func listenersSection(doc any) (any, bool) {
	return mget(doc, "listeners")
}

// ListenersEffective is listeners_effective: one backend's listeners, the
// built-in ones first (as overridden), then the others by name. An entry
// that does not validate is left out, or falls back to the built-in one of
// its name. doc is a tacctl.yaml document (the merged view, as the
// renderers use it).
func ListenersEffective(doc any, backend string) []Listener {
	spec, _ := ListenerBackendByID(backend)
	section, _ := listenersSection(doc)
	if !truthy(section) {
		section = yamlpy.NewMap()
	}
	mine, _ := mget(section, backend)
	mineMap, ok := mine.(*yamlpy.Map)
	if !ok {
		mineMap = yamlpy.NewMap()
	}
	var names []string
	for _, d := range spec.Defaults {
		names = append(names, d.Name)
	}
	var others []string
	for _, n := range mineMap.Keys() {
		if _, isDefault := spec.defaultValue(n); !isDefault {
			others = append(others, n)
		}
	}
	sort.Strings(others)
	names = append(names, others...)
	var out []Listener
	for _, name := range names {
		value, _ := mineMap.Get(name)
		if value == nil || ListenerProblem(backend, name, value) != "" {
			def, ok := spec.defaultValue(name)
			if !ok {
				continue
			}
			value = def
		}
		out = append(out, ListenerNormalize(backend, name, value))
	}
	return out
}

// bindsCollide is _binds_collide: two listeners that cannot both bind.
func bindsCollide(a, b Listener) bool {
	if a.Network[:3] != b.Network[:3] {
		return false
	}
	// FreeRADIUS, the one udp daemon, binds a socket per family.
	if a.Network[:3] == "udp" && a.Network != b.Network {
		return false
	}
	ha, pa, _ := SplitListenAddress(a.Address)
	hb, pb, _ := SplitListenAddress(b.Address)
	if pa != pb {
		return false
	}
	if slices.Contains(wildcardHosts, ha) || slices.Contains(wildcardHosts, hb) {
		return true
	}
	ia, _ := ipAddress(ha)
	ib, _ := ipAddress(hb)
	return ia.String() == ib.String()
}

// ListenersProblems is listeners_problems: every problem of a tacctl.yaml
// document's listeners section as '<path>: <reason>' lines, invalid
// entries and listeners (of any backends) on one network and address.
// With only (a listener path, hasOnly true), the problems of that one
// listener, a collision told from its side.
func ListenersProblems(doc any, only string, hasOnly bool) []string {
	var problems []string
	section, _ := listenersSection(doc)
	if section == nil {
		section = yamlpy.NewMap()
	}
	sm, ok := section.(*yamlpy.Map)
	if !ok {
		return []string{"listeners: must be a mapping of backends"}
	}
	for backend, mine := range sm.All() {
		mm, ok := mine.(*yamlpy.Map)
		if !ok {
			problems = append(problems, fmt.Sprintf("listeners.%s: must be a mapping of listener names", backend))
			continue
		}
		for name, value := range mm.All() {
			if why := ListenerProblem(backend, name, value); why != "" {
				problems = append(problems, fmt.Sprintf("listeners.%s.%s: %s", backend, name, why))
			}
		}
	}
	if hasOnly {
		kept := problems[:0:0]
		for _, p := range problems {
			if strings.HasPrefix(p, only+":") {
				kept = append(kept, p)
			}
		}
		problems = kept
	}
	type seenL struct {
		path string
		l    Listener
	}
	var seen []seenL
	for _, b := range ListenerBackends {
		for _, l := range ListenersEffective(doc, b.ID) {
			path := fmt.Sprintf("listeners.%s.%s", b.ID, l.Name)
			for _, o := range seen {
				if hasOnly && only != path && only != o.path {
					continue
				}
				pa, a, pb, bb := path, l, o.path, o.l
				if hasOnly && only == o.path {
					pa, a, pb, bb = o.path, o.l, path, l
				}
				if bindsCollide(a, bb) {
					problems = append(problems, fmt.Sprintf("%s: %s %s is already used by %s (%s %s)",
						pa, a.Network, a.Address, pb, bb.Network, bb.Address))
				}
				if a.MetricsAddress != "" && a.MetricsAddress == bb.MetricsAddress && !strings.HasSuffix(a.MetricsAddress, ":0") {
					problems = append(problems, fmt.Sprintf("%s: metrics_address %s is already used by %s", pa, a.MetricsAddress, pb))
				}
			}
			seen = append(seen, seenL{path, l})
		}
	}
	return problems
}
