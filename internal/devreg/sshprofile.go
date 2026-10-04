package devreg

// The ssh profile of an entry (docs/plans/operator-console.md 5.2 and 3.7):
// the options 'tacctl ssh' gives ssh for it and the lines 'device ssh-config'
// writes into its Host block. One table serves both, so a plain 'ssh <name>'
// through the generated Include behaves as 'tacctl ssh <name>' does. No
// free-form option is ever stored: that is ~/.ssh/config's job.

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/hosts"
)

// SSHOption is one ssh_config keyword and its value: '-o Key=Value' on the
// command line, 'Key Value' in a Host block.
type SSHOption struct{ Key, Value string }

// Arg is the option as ssh's '-o' takes it.
func (o SSHOption) Arg() string { return o.Key + "=" + o.Value }

// ConfigLine is the option as an indented ssh_config line; a value with a
// blank in it is quoted.
func (o SSHOption) ConfigLine() string { return "    " + o.Key + " " + configWord(o.Value) }

func configWord(v string) string {
	if strings.ContainsAny(v, " \t") {
		return `"` + v + `"`
	}
	return v
}

// SSHConnectTimeout is the ConnectTimeout of every 'tacctl ssh' (as 'tacctl
// host' has it).
const SSHConnectTimeout = 10

// legacyOptions are the algorithms old IOS still needs (SHA-1 key
// exchange, ssh-rsa host keys and signatures). '+' appends them to
// OpenSSH's defaults, so a modern unit still negotiates the strong set; the
// option names are those of current OpenSSH (PubkeyAcceptedAlgorithms
// since 8.5), which the 0.2.1 lab acceptance verifies on argv only.
var legacyOptions = []SSHOption{
	{"KexAlgorithms", "+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"},
	{"HostKeyAlgorithms", "+ssh-rsa"},
	{"PubkeyAcceptedAlgorithms", "+ssh-rsa"},
}

// vendorOptions are the options a vendor always gets. WTI units hold no
// user keys and may close the session when a key attempt comes first and
// their lockout is armed (README, WTI Console Servers), so they get the
// password method alone. Juniper, Linux and other run a current OpenSSH:
// nothing.
var vendorOptions = map[string][]SSHOption{
	"wti": {{"PreferredAuthentications", "password"}, {"PubkeyAuthentication", "no"}},
}

// Profile is the entry's vendor options, then the legacy algorithms when the
// device has legacy-ssh (an opt-in per device; enrolled hosts never have
// it).
func Profile(e Entry) []SSHOption {
	out := append([]SSHOption(nil), vendorOptions[e.Vendor]...)
	if e.LegacySSH {
		out = append(out, legacyOptions...)
	}
	return out
}

// Pinned reports whether the entry has pinned host keys: ssh then checks
// them, and nothing else, through the generated known_hosts.
func Pinned(e Entry) bool { return len(e.HostKeys) > 0 }

// PinOptions make ssh check the host key against the generated known_hosts
// alone, under the entry's name: a key that is not pinned there is refused
// (no prompt, no learning, no update from the server).
func PinOptions(name, knownHosts string) []SSHOption {
	return []SSHOption{
		{"UserKnownHostsFile", knownHosts},
		{"StrictHostKeyChecking", "yes"},
		{"HostKeyAlias", name},
		{"UpdateHostKeys", "no"},
	}
}

// SSHOptions are the options of 'tacctl ssh' for the entry, in order: the
// connect timeout, the profile, and the pinning options for a pinned entry
// (an unpinned one is checked against the user's own known_hosts). Extra
// arguments the user passes come after them, so ssh, which keeps the first
// value of an option, cannot be talked out of the pin by them.
func SSHOptions(e Entry, knownHosts string) []SSHOption {
	out := []SSHOption{{"ConnectTimeout", strconv.Itoa(SSHConnectTimeout)}}
	out = append(out, Profile(e)...)
	if Pinned(e) {
		out = append(out, PinOptions(e.Name, knownHosts)...)
	}
	return out
}

// OptionArgs are options as ssh arguments: '-o', 'Key=Value' each.
func OptionArgs(opts []SSHOption) []string {
	out := make([]string, 0, 2*len(opts))
	for _, o := range opts {
		out = append(out, "-o", o.Arg())
	}
	return out
}

// SSHTarget is where ssh connects for the entry: a device's hostname when
// it has one, else its address; an enrolled host's host part of
// '[user@]host'. ok is false for a host enrolled with --local (this
// server, reached without ssh) and for an entry with nothing to connect to.
func SSHTarget(e Entry) (target string, ok bool) {
	if e.Source == SourceHost {
		if e.Target == hosts.Local || e.Target == "" {
			return "", false
		}
		return e.Hostname, e.Hostname != ""
	}
	if e.Hostname != "" {
		return e.Hostname, true
	}
	return e.Address, e.Address != ""
}
