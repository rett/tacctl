// Package devreg is the device registry (docs/plans/operator-console.md 3):
// the names and addresses of the network devices that authenticate against
// this server, kept in /etc/tacctl/devices.yaml, and the view that joins it
// with the enrolled Linux hosts and the store's scopes. The registry never
// touches store.yaml: scope and vendor tag are derived per display.
package devreg

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/names"
)

// Device is one registry entry. The name is the key of the file.
type Device struct {
	Name string
	// Address is the AAA identity: canonical, unique across the registry.
	Address string
	// Hostname is the optional DNS name (display, and the ssh target when set).
	Hostname string
	// Vendor is cisco, juniper, wti or other ("linux" belongs to enrolled hosts).
	Vendor string
	// Port is the ssh port; 0 is the default (22).
	Port        int
	Description string
	// Location is the optional place the device is (SNMP location in the
	// walkthroughs, 'tacctl device location'); empty is not set.
	Location  string
	LegacySSH bool
	// Ack are the acknowledged notice kinds.
	Ack []string
	// HostKeys are the pinned host keys ('<type> <base64>', hostkey.go),
	// in type order; known_hosts is generated from them.
	HostKeys []string
	// SNMP is the device's own SNMP settings (D72 of docs/plans/0.2.4-
	// plan.md, 'tacctl device snmp'): the device's value wins over its
	// scope's and the default's. Its credentials are not here (they are
	// StateDir/snmp/devices/<name>.yaml, internal/snmpcred). The zero value
	// is "nothing of its own"; the file has the map only when it is set.
	SNMP SNMP
}

// SNMP is a device's own SNMP settings: the non-secret ones. Zero is "not
// set here" for every field.
type SNMP struct {
	// Version is v2c or v3.
	Version string
	// Port is the agent's UDP port, Timeout the wait for an answer in
	// seconds.
	Port, Timeout int
	// Clients are the allowed client ranges as stored (IPv4 CIDRs in
	// canonical form, in the order given); the device's list replaces its
	// scope's.
	Clients []string
}

// The bounds of a device's SNMP settings: the scope's (internal/snmp's
// MinTimeout and MaxTimeout, cidr.MaxSNMPClients; a test holds them equal).
const (
	SNMPMinTimeout = 1
	SNMPMaxTimeout = 10
	// SNMPVersionV2c and SNMPVersionV3 are the versions a device may set.
	SNMPVersionV2c = "v2c"
	SNMPVersionV3  = "v3"
)

// Empty reports whether nothing is set.
func (s SNMP) Empty() bool {
	return s.Version == "" && s.Port == 0 && s.Timeout == 0 && len(s.Clients) == 0
}

// Clone is a deep copy.
func (s SNMP) Clone() SNMP {
	s.Clients = slices.Clone(s.Clients)
	return s
}

// validate is every field rule of the settings.
func (s SNMP) validate() error {
	if s.Version != "" && s.Version != SNMPVersionV2c && s.Version != SNMPVersionV3 {
		return fail("Invalid snmp version '" + s.Version + "': v2c or v3.")
	}
	if s.Port != 0 && (s.Port < 1 || s.Port > 65535) {
		return fail("Invalid snmp port " + strconv.Itoa(s.Port) + ": expected 1-65535.")
	}
	if s.Timeout != 0 && (s.Timeout < SNMPMinTimeout || s.Timeout > SNMPMaxTimeout) {
		return fail("Invalid snmp timeout " + strconv.Itoa(s.Timeout) + ": expected " + strconv.Itoa(SNMPMinTimeout) + "-" + strconv.Itoa(SNMPMaxTimeout) + ".")
	}
	if len(s.Clients) > cidr.MaxSNMPClients {
		return fail("At most " + strconv.Itoa(cidr.MaxSNMPClients) + " snmp client ranges.")
	}
	seen := map[string]bool{}
	for _, c := range s.Clients {
		if why := cidr.ClientProblem(c); why != "" {
			return fail("Invalid snmp client '" + c + "': it " + why + ".")
		}
		if seen[c] {
			return fail("The snmp client '" + c + "' is listed twice.")
		}
		seen[c] = true
	}
	return nil
}

// The defaults and limits of the fields.
const (
	DefaultPort      = 22
	DefaultStaleDays = 30
	MaxStaleDays     = 3650
	MaxDescription   = 120
	MaxLocation      = 120
	// VendorLinux is the vendor of enrolled hosts; the registry refuses it.
	VendorLinux = "linux"
	VendorOther = "other"
)

// Vendors are the vendors a registry entry may have.
var Vendors = []string{"cisco", "juniper", "wti", VendorOther}

// SSHPort is the port ssh uses for the device.
func (d Device) SSHPort() int {
	if d.Port == 0 {
		return DefaultPort
	}
	return d.Port
}

var (
	reName      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$`)
	reHostEntry = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`) // an enrolled host's: 63 at most
	reHostname  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)
)

// ReservedNames are words a device may not be called: the tacctl commands
// (so 'tacctl <word>' is never ambiguous) and the registry's own words.
var ReservedNames = []string{
	"install", "upgrade", "uninstall", "status", "passwd", "user", "group", "scope", "host",
	"backend", "store", "config", "log", "backup", "hash", "version", "completion", "device",
	"console", "ssh", "shell", "help", "local", "all",
}

func fail(lines ...string) error { return &names.Error{Msgs: lines} }

// ValidateName checks the shape of a device name and that it is no
// reserved word. Uniqueness is the registry's business (File, Resolver).
// A fully qualified name is a name: at most 253 characters, each dotted
// part 1-63.
func ValidateName(name string) error {
	if !reName.MatchString(name) || !labelsOK(name) {
		return fail("Invalid device name '" + name + "'. Use letters, digits, '.', '_' or '-', starting with a letter or digit; at most 253 characters, each dotted part at most 63.")
	}
	if slices.Contains(ReservedNames, strings.ToLower(name)) {
		return fail("'" + name + "' is a tacctl word and cannot name a device.")
	}
	return nil
}

// labelsOK reports whether every dotted part of name has 1 to 63
// characters (no '..', no trailing dot).
func labelsOK(name string) bool {
	for l := range strings.SplitSeq(name, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
	}
	return true
}

// firstLabel is a name up to its first dot (the whole name without one).
func firstLabel(name string) string {
	first, _, _ := strings.Cut(name, ".")
	return first
}

// NormalizeAddress is the canonical text of an IPv4 or IPv6 address (no
// prefix length, no zone).
func NormalizeAddress(s string) (string, error) {
	bad := fail("Invalid address '" + s + "': expected an IPv4 or IPv6 address (no prefix length).")
	if s == "" || strings.ContainsAny(s, "/%") {
		return "", bad
	}
	n, err := cidr.Parse(s)
	if err != nil {
		return "", bad
	}
	c := n.String()
	c = c[:strings.LastIndexByte(c, '/')]
	if a, err := netip.ParseAddr(c); err != nil || a.IsUnspecified() {
		return "", bad
	}
	return c, nil
}

// ValidatePort parses a port (1-65535); the default port is stored as 0.
func ValidatePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != s {
		return 0, fail("Invalid port '" + s + "': expected 1-65535.")
	}
	if n == DefaultPort {
		n = 0
	}
	return n, nil
}

// ValidateVendor checks a vendor a registry entry may have.
func ValidateVendor(v string) error {
	if v == VendorLinux {
		return fail("Vendor 'linux' is for enrolled hosts: enroll one with 'tacctl host enroll'.")
	}
	if !slices.Contains(Vendors, v) {
		return fail("Invalid vendor '" + v + "'. Use: " + strings.Join(Vendors, ", ") + ".")
	}
	return nil
}

// ValidateHostname checks a DNS name.
func ValidateHostname(s string) error {
	if len(s) > 253 || !reHostname.MatchString(s) {
		return fail("Invalid hostname '" + s + "': expected a DNS name.")
	}
	return nil
}

// ValidateDescription checks the free text: at most 120 characters, no
// control characters.
func ValidateDescription(s string) error {
	if utf8.RuneCountInString(s) > MaxDescription || !utf8.ValidString(s) {
		return fail("The description is limited to 120 characters.")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fail("The description may not contain control characters.")
		}
	}
	return nil
}

// ValidateNewDescription is ValidateDescription for a description being set
// (device add, description, import): also no '?', which the description
// shares with the location because the Junos walkthrough pastes it into
// 'set snmp description' (a CLI treats a pasted '?' as a request for help).
// A description already stored with one (it was valid before 0.2.3) is still
// read; the walkthrough renders it as a commented line.
func ValidateNewDescription(s string) error {
	if err := ValidateDescription(s); err != nil {
		return err
	}
	if strings.Contains(s, "?") {
		return fail("The description may not contain '?' (a device CLI treats it as a request for help).")
	}
	return nil
}

// ValidateLocation checks a device location: 1 to 120 characters, no control
// characters, no '?' (a device CLI treats a pasted '?' as a request for
// help).
func ValidateLocation(s string) error {
	switch {
	case strings.TrimSpace(s) == "":
		return fail("The location may not be empty; to remove it: tacctl device location <name> clear")
	case utf8.RuneCountInString(s) > MaxLocation || !utf8.ValidString(s):
		return fail("The location is limited to 120 characters.")
	case strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return fail("The location may not contain control characters.")
	case strings.Contains(s, "?"):
		return fail("The location may not contain '?' (a device CLI treats it as a request for help).")
	}
	return nil
}

// validate is every field rule, for a device read from a file or an import.
func (d Device) validate() error {
	if err := ValidateName(d.Name); err != nil {
		return err
	}
	if _, err := NormalizeAddress(d.Address); err != nil || d.Address != mustAddr(d.Address) {
		return fail("Invalid address '" + d.Address + "': expected a canonical IPv4 or IPv6 address.")
	}
	if err := ValidateVendor(d.Vendor); err != nil {
		return err
	}
	if d.Port != 0 && (d.Port < 1 || d.Port > 65535 || d.Port == DefaultPort) {
		return fail("Invalid port " + strconv.Itoa(d.Port) + ".")
	}
	if d.Hostname != "" {
		if err := ValidateHostname(d.Hostname); err != nil {
			return err
		}
	}
	if err := ValidateDescription(d.Description); err != nil {
		return err
	}
	if d.Location != "" {
		if err := ValidateLocation(d.Location); err != nil {
			return err
		}
	}
	for _, k := range d.HostKeys {
		if _, err := ParseHostKey(k); err != nil {
			return err
		}
	}
	for _, k := range d.Ack {
		if !slices.Contains(AckableKinds, k) {
			return fail("Unknown notice kind '" + k + "'.")
		}
	}
	return d.SNMP.validate()
}

func mustAddr(s string) string {
	c, _ := NormalizeAddress(s)
	return c
}

// Clone is a deep copy.
func (d Device) Clone() Device {
	d.Ack = slices.Clone(d.Ack)
	d.HostKeys = slices.Clone(d.HostKeys)
	d.SNMP = d.SNMP.Clone()
	return d
}

// --- generic names ------------------------------------------------------------------

// genericNames are the factory and image default names (docs/plans/
// operator-console.md 3.6): regular expressions matched against the whole
// name, case-insensitively. A registry extends them with 'generic_names:'.
var genericNames = []string{
	`switch\d*`, `router\d*`, `cisco`, `juniper`, `wti`, `default`, `localhost`, `localhost\.localdomain`,
	`ubuntu`, `debian`, `raspberrypi`, `ip-\d+-\d+-\d+-\d+`, `host`, `server`, `device`,
	`fedora`, `centos`, `rocky`, `almalinux`, `kali`,
}

// GenericNames are the built-in generic name patterns.
func GenericNames() []string { return slices.Clone(genericNames) }

// IsGeneric reports whether name is a generic name: one of the built-in
// patterns or of extra (the registry's 'generic_names'; a pattern that does
// not compile is ignored here and refused when the registry is read).
func IsGeneric(name string, extra []string) bool {
	for _, p := range slices.Concat(genericNames, extra) {
		if re, err := regexp.Compile(`(?i)^(?:` + p + `)$`); err == nil && re.MatchString(name) {
			return true
		}
	}
	return false
}
