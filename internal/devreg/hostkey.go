package devreg

// Host-key pinning (docs/plans/operator-console.md 3.7): the keys a device
// offers are read with ssh-keyscan (through the runner, as root, outbound
// only, no authentication), pinned in devices.yaml as '<type> <base64>', and
// shown as the SHA256 fingerprints ssh prints. Fingerprints are computed
// here with the standard library: base64 (unpadded) of the SHA-256 of the
// key blob, as 'ssh-keygen -l' does.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/execx"
)

// KeyscanTimeout is ssh-keyscan's -T: seconds to wait for a device.
const KeyscanTimeout = 5

// keyTypes are the host-key types tacctl pins, in the order they are kept
// and shown: the order ssh prefers them in.
var keyTypes = []string{
	"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa",
}

// HostKey is one public host key: its type and its blob (the base64 of
// known_hosts and of devices.yaml's host_keys).
type HostKey struct {
	Type string
	Blob string
}

// String is the key as devices.yaml and known_hosts hold it.
func (k HostKey) String() string { return k.Type + " " + k.Blob }

// Fingerprint is 'SHA256:<base64>' as ssh-keygen -l prints it.
func (k HostKey) Fingerprint() string {
	raw, err := base64.StdEncoding.DecodeString(k.Blob)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Label is the short name ssh-keygen prints for the type.
func (k HostKey) Label() string {
	switch {
	case k.Type == "ssh-ed25519":
		return "ED25519"
	case strings.HasPrefix(k.Type, "ecdsa-"):
		return "ECDSA"
	case k.Type == "ssh-rsa":
		return "RSA"
	}
	return strings.ToUpper(k.Type)
}

// Display is the label and the fingerprint, aligned for a list.
func (k HostKey) Display() string { return padRight(k.Label(), 8) + " " + k.Fingerprint() }

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// ParseHostKey reads '<type> <base64>' (a pinned key); the blob must be
// valid base64 whose own type string is type, and type one tacctl pins.
func ParseHostKey(s string) (HostKey, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return HostKey{}, fail("Invalid host key '" + s + "'.")
	}
	return checkKey(f[0], f[1])
}

func checkKey(typ, blob string) (HostKey, error) {
	bad := fail("Invalid host key '" + typ + " " + blob + "'.")
	if !slices.Contains(keyTypes, typ) {
		return HostKey{}, bad
	}
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil || len(raw) < 4 {
		return HostKey{}, bad
	}
	n := binary.BigEndian.Uint32(raw)
	if uint64(n)+4 > uint64(len(raw)) || string(raw[4:4+n]) != typ {
		return HostKey{}, bad
	}
	return HostKey{Type: typ, Blob: blob}, nil
}

// ParseHostKeys parses pinned keys; one that does not parse is skipped
// (the registry refuses such a key when it is read).
func ParseHostKeys(keys []string) []HostKey {
	var out []HostKey
	for _, s := range keys {
		if k, err := ParseHostKey(s); err == nil {
			out = append(out, k)
		}
	}
	return out
}

// KeyStrings are the keys as devices.yaml holds them.
func KeyStrings(keys []HostKey) []string {
	var out []string
	for _, k := range keys {
		out = append(out, k.String())
	}
	return out
}

// sortKeys orders keys by type preference and drops duplicates.
func sortKeys(keys []HostKey) []HostKey {
	out := slices.Clone(keys)
	slices.SortStableFunc(out, func(a, b HostKey) int {
		return slices.Index(keyTypes, a.Type) - slices.Index(keyTypes, b.Type)
	})
	return slices.CompactFunc(out, func(a, b HostKey) bool { return a == b })
}

// ParseKeyscan reads ssh-keyscan's standard output: '<host> <type> <base64>'
// lines ('[host]:port' for a port other than 22). Comments, blank lines,
// key types tacctl does not pin and anything that does not parse are
// skipped. The keys come back in type order, without duplicates.
func ParseKeyscan(out []byte) []HostKey {
	var keys []HostKey
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		if k, err := checkKey(f[1], f[2]); err == nil {
			keys = append(keys, k)
		}
	}
	return sortKeys(keys)
}

// KeyscanCmd is the ssh-keyscan of a device at address and port. Every key
// type tacctl pins is asked for; a device with legacy-ssh is asked for the
// ssh-rsa type by its algorithm name too. ssh-keyscan offers ssh-rsa
// signatures for the rsa type already, but not the SHA-1 key exchanges old
// IOS needs: whether a legacy unit answers at all is to be confirmed in the
// 0.2.1 lab acceptance (WP6.11); when it does not, '--no-host-key' and a
// later 'tacctl device hostkey <name> set SHA256:<fp>' remain.
func KeyscanCmd(address string, port int, legacy bool) execx.Cmd {
	types := "ed25519,ecdsa,rsa"
	if legacy {
		types += ",ssh-rsa"
	}
	if port == 0 {
		port = DefaultPort
	}
	return execx.Cmd{Name: "ssh-keyscan", Args: []string{
		"-T", strconv.Itoa(KeyscanTimeout), "-p", strconv.Itoa(port), "-t", types, address,
	}}
}

// ErrNoAnswer is a scan that read no key: the device did not answer on the
// port, or offered no key type tacctl pins.
var ErrNoAnswer = errors.New("no host key could be read")

// Scan reads the host keys address offers on port. A device that does not
// answer is ErrNoAnswer; ssh-keyscan missing is an error that says so.
func Scan(ctx context.Context, r execx.Runner, address string, port int, legacy bool) ([]HostKey, error) {
	res, err := r.Run(ctx, KeyscanCmd(address, port, legacy))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fail("ssh-keyscan could not be run (" + firstLine(err.Error()) + "); it comes with the openssh-client package.")
	}
	keys := ParseKeyscan(res.Stdout)
	if len(keys) == 0 {
		return nil, ErrNoAnswer
	}
	return keys, nil
}

var reFingerprint = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// ValidFingerprint reports whether fp has the form 'SHA256:<43 base64>'.
func ValidFingerprint(fp string) bool { return reFingerprint.MatchString(fp) }

// MatchFingerprint is the key among keys whose fingerprint is fp.
func MatchFingerprint(keys []HostKey, fp string) (HostKey, bool) {
	for _, k := range keys {
		if k.Fingerprint() == fp {
			return k, true
		}
	}
	return HostKey{}, false
}

// Comparison is pinned keys against the keys a device offers now.
type Comparison struct {
	// Changed: a pinned key's type is offered with another key, or none of
	// the pinned keys is offered at all (the hostkey-changed notice, which
	// only re-pinning clears).
	Changed bool
	// Added are offered keys of types nothing is pinned for
	// (hostkey-added).
	Added []HostKey
	// Missing are pinned keys the device no longer offers.
	Missing []HostKey
}

// Same reports whether the offered keys are exactly the pinned ones.
func (c Comparison) Same() bool { return !c.Changed && len(c.Added) == 0 && len(c.Missing) == 0 }

// Compare compares the pinned keys with the offered ones. With nothing
// pinned, every offered key is Added and nothing is Changed.
func Compare(pinned []string, offered []HostKey) Comparison {
	var c Comparison
	pk := ParseHostKeys(pinned)
	pinnedType := map[string]HostKey{}
	for _, k := range pk {
		pinnedType[k.Type] = k
	}
	matched := false
	for _, k := range offered {
		p, ok := pinnedType[k.Type]
		switch {
		case !ok:
			c.Added = append(c.Added, k)
		case p.Blob != k.Blob:
			c.Changed = true
		default:
			matched = true
		}
	}
	for _, k := range pk {
		if !slices.Contains(offered, k) {
			c.Missing = append(c.Missing, k)
		}
	}
	if len(pk) > 0 && !matched {
		c.Changed = true
	}
	return c
}

// verifyHints are the commands that show a device's host-key fingerprint
// on its own console, per vendor. The Cisco, Junos and WTI texts are the
// design's and are to be confirmed on hardware in the 0.2.1 lab acceptance
// (WP6.11: Junos live, Cisco and WTI remain to be verified on a unit); the
// Linux one is ssh-keygen's own.
var verifyHints = map[string]string{
	"cisco":     "Cisco IOS/IOS-XE: 'show ip ssh' and 'show crypto key mypubkey rsa' (the fingerprint form varies by release)",
	"juniper":   "Junos: 'show system ssh host-key', or from the shell 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'",
	"wti":       "WTI: verify on the device console (where the host key is shown varies by firmware)",
	VendorLinux: "Linux: 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub' (and the ecdsa and rsa .pub files beside it)",
	VendorOther: "on the device console, the fingerprint of its ssh host key ('ssh-keygen -lf <key>.pub' where a shell is available)",
}

// VerifyHint is how to see the host-key fingerprint on a device of vendor.
func VerifyHint(vendor string) string {
	if h, ok := verifyHints[vendor]; ok {
		return h
	}
	return verifyHints[VendorOther]
}

// keysEqual reports whether two pinned lists hold the same keys.
func keysEqual(a, b []string) bool {
	x, y := sortKeys(ParseHostKeys(a)), sortKeys(ParseHostKeys(b))
	return slices.Equal(x, y)
}

// KeysEqual reports whether the pinned keys are exactly keys.
func KeysEqual(pinned []string, keys []HostKey) bool { return keysEqual(pinned, KeyStrings(keys)) }

// joinDisplays is the keys as 'LABEL SHA256:...' joined with sep.
func joinDisplays(keys []HostKey, sep string) string {
	var b bytes.Buffer
	for i, k := range keys {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(k.Label() + " " + k.Fingerprint())
	}
	return b.String()
}

// Displays is the keys as 'LABEL SHA256:...', comma-separated.
func Displays(keys []HostKey) string { return joinDisplays(keys, ", ") }

// PinAction is what 'host enroll' and 'host sync' do with the keys a host
// offers, given what is pinned for it: they pin a host once and never
// change a pin (only 'tacctl device hostkey <name> accept|set' does).
type PinAction int

// The actions: pin the offered keys (nothing pinned yet); nothing to do
// (the pinned keys are offered, nothing new); report new key types (left
// unpinned); report a changed key (the pin stays).
const (
	PinFirst PinAction = iota
	PinKeep
	PinAdded
	PinChanged
)

// HostPinAction decides what to do with offered keys given pinned ones.
func HostPinAction(pinned []string, offered []HostKey) PinAction {
	if len(pinned) == 0 {
		return PinFirst
	}
	c := Compare(pinned, offered)
	switch {
	case c.Changed:
		return PinChanged
	case len(c.Added) > 0:
		return PinAdded
	}
	return PinKeep
}
