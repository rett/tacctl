package devreg

// Host-key pinning (docs/plans/operator-console.md 3.7): the keys a device
// offers are read with ssh-keyscan (through the runner, as root, outbound
// only, no authentication; for a device that answers it with no key, and for
// a legacy-ssh device, which ssh-keyscan cannot negotiate with, the built-in
// client is the fallback), pinned in
// devices.yaml as '<type> <base64>', and shown as the SHA256 fingerprints
// ssh prints. Fingerprints are computed here with the standard library:
// base64 (unpadded) of the SHA-256 of the key blob, as 'ssh-keygen -l'
// does.

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
	"time"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/execx"
)

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

// SortKeys is keys in the type order tacctl keeps and shows them in
// (ssh-ed25519, the ECDSA curves, ssh-rsa), without duplicates; keys is not
// changed.
func SortKeys(keys []HostKey) []HostKey { return sortKeys(keys) }

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

// ParsePubKeys reads public key files as 'cat /etc/ssh/ssh_host_*_key.pub'
// prints them: '<type> <base64> [comment]' lines. Anything else, and key
// types tacctl does not pin, are skipped; the keys come back in type
// order, without duplicates.
func ParsePubKeys(out []byte) []HostKey {
	var keys []HostKey
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if k, err := checkKey(f[0], f[1]); err == nil {
			keys = append(keys, k)
		}
	}
	return sortKeys(keys)
}

// CrossCheck is what two independent reads of a host's keys agree on: the
// keys read over the authenticated enrolment session (the host's own .pub
// files) and the keys ssh-keyscan was offered.
type CrossCheck struct {
	// Agreed are the keys both reads hold: the only ones that may be pinned.
	Agreed []HostKey
	// Conflict: a key type both reads hold with different keys (Session and
	// Scan list the two sides' keys of those types).
	Conflict      bool
	Session, Scan []HostKey
	// OnlySession and OnlyScan are key types one read holds and the other
	// does not: reported, never pinned.
	OnlySession, OnlyScan []HostKey
}

// CrossCheckKeys compares the session's keys with the scan's, type by type.
func CrossCheckKeys(session, scan []HostKey) CrossCheck {
	var c CrossCheck
	byType := func(keys []HostKey, t string) (HostKey, bool) {
		for _, k := range keys {
			if k.Type == t {
				return k, true
			}
		}
		return HostKey{}, false
	}
	for _, k := range sortKeys(session) {
		o, ok := byType(scan, k.Type)
		switch {
		case !ok:
			c.OnlySession = append(c.OnlySession, k)
		case o.Blob == k.Blob:
			c.Agreed = append(c.Agreed, k)
		default:
			c.Conflict = true
			c.Session, c.Scan = append(c.Session, k), append(c.Scan, o)
		}
	}
	for _, k := range sortKeys(scan) {
		if _, ok := byType(session, k.Type); !ok {
			c.OnlyScan = append(c.OnlyScan, k)
		}
	}
	return c
}

// KeyscanCmd is the ssh-keyscan of a device at address and port. Every key
// type tacctl pins is asked for; a device with legacy-ssh is asked for the
// ssh-rsa type by its algorithm name too, which only makes ssh-keyscan offer
// the SHA-1 signature: it still cannot do the SHA-1 key exchanges and CBC
// ciphers old IOS needs, so it reads nothing from such a device (ErrNoAnswer
// after its banner). Scan therefore falls back to a KeyFallback, the built-in
// ssh client (internal/devssh), which negotiates them; '--no-host-key' and a
// later 'tacctl device hostkey <name> set SHA256:<fp>' remain for a device
// neither can read.
//
// ssh-keyscan opens one connection per key type at once, so a device that
// limits or drops parallel connections, or mishandles the long algorithm
// offer, answers this command with nothing: ScanWith then asks for one type
// at a time (KeyscanTypeCmd).
func KeyscanCmd(address string, port int, legacy bool) execx.Cmd {
	return keyscanCombined(address, port, legacy, devssh.DefaultScanTiming())
}

// keyscanCombined is KeyscanCmd with the timing tm (Keyscan is its -T).
func keyscanCombined(address string, port int, legacy bool, tm devssh.ScanTiming) execx.Cmd {
	types := "ed25519,ecdsa,rsa"
	if legacy {
		types += ",ssh-rsa"
	}
	return keyscanCmd(address, port, seconds(tm.Keyscan), types)
}

// KeyscanTypeCmd is the ssh-keyscan of one key type (ssh-keyscan's own
// name for it: ed25519, ecdsa, rsa or ssh-rsa) at address and port, as ScanWith
// retries a device that did not answer the combined scan. Its -T is the
// KeyscanRetry of the timing: a device that answers a single connection does
// so at once, and the attempts (three, four with legacy-ssh) must stay short
// in sum.
func KeyscanTypeCmd(address string, port int, typ string) execx.Cmd {
	return keyscanTyped(address, port, typ, devssh.DefaultScanTiming())
}

func keyscanTyped(address string, port int, typ string, tm devssh.ScanTiming) execx.Cmd {
	return keyscanCmd(address, port, seconds(tm.KeyscanRetry), typ)
}

// seconds is d as ssh-keyscan's -T takes it: whole seconds, at least 1.
func seconds(d time.Duration) int {
	return max(1, int((d+time.Second-1)/time.Second))
}

func keyscanCmd(address string, port, timeout int, types string) execx.Cmd {
	if port == 0 {
		port = DefaultPort
	}
	return execx.Cmd{Name: "ssh-keyscan", Args: []string{
		"-T", strconv.Itoa(timeout), "-p", strconv.Itoa(port), "-t", types, address,
	}}
}

// retryTypes are the key types asked for one at a time, in the order of
// keyTypes; ssh-rsa (the SHA-1 signature) only for a legacy-ssh device.
func retryTypes(legacy bool) []string {
	types := []string{"ed25519", "ecdsa", "rsa"}
	if legacy {
		types = append(types, "ssh-rsa")
	}
	return types
}

// ErrNoAnswer is a scan that read no key: the device did not answer on the
// port, or offered no key type tacctl pins.
var ErrNoAnswer = errors.New("no host key could be read")

// NoAnswerError is ErrNoAnswer (errors.Is finds it) for a scan that read no
// key and went beyond ssh-keyscan: a device that answered (the one-type
// retry, the built-in client), or one ssh-keyscan said nothing about (the
// built-in client alone), or a legacy-ssh device (the built-in client). A
// scan that stopped at one ssh-keyscan is ErrNoAnswer itself.
type NoAnswerError struct {
	// OneByOne are the key types asked for one at a time with ssh-keyscan
	// after the combined scan read nothing, in the order tried.
	OneByOne []string
	// Builtin: the built-in ssh client was tried as well.
	Builtin bool
	// Silent: ssh-keyscan read no key and printed nothing about the device
	// (it prints nothing for a refused connection, an address nobody
	// answers at and a server slow to greet alike), so only the built-in
	// client was tried after it, not the one-type retry. Set for a device
	// that is not legacy-ssh.
	Silent bool
}

func (e *NoAnswerError) Error() string { return ErrNoAnswer.Error() }
func (e *NoAnswerError) Unwrap() error { return ErrNoAnswer }

// reReached matches what ssh-keyscan prints on standard error for a device
// whose ssh server accepted the connection: the banner line it prints for
// every server that greets ('# <host>:<port> SSH-2.0-...'), or the error it
// reports when the server then closed or reset the connection or the
// negotiation failed.
var reReached = regexp.MustCompile(`(?im)^#\s+\S+\s+SSH-|closed by remote host|connection reset|exchange_identification|no matching `)

// Reached reports whether what ssh-keyscan printed on standard error shows
// that the device's ssh server accepted a connection, which is worth asking
// again one key type at a time. The exit status cannot tell a device that
// answered from one that did not (it is 0 or 1 whatever the reason, by
// version), the messages can.
func Reached(stderr []byte) bool { return reReached.Match(stderr) }

// reDown matches the one failure OpenSSH's ssh-keyscan reports that no
// second try helps: a name that does not resolve. It prints
// "getaddrinfo <host>: <resolver's text>" (OpenSSH 9.6 was observed to
// print "getaddrinfo nosuchhost.invalid: Name or service not known"). That
// is all it was observed to print without -v about a device it got no key
// from: a refused connection, a filtered or powered-off address and a
// server that never greets all print nothing, and so cannot be told apart
// from each other here.
var reDown = regexp.MustCompile(`(?im)^getaddrinfo\s+\S+:`)

// Down reports whether what ssh-keyscan printed on standard error shows an
// address that does not resolve (reDown), so that nothing more is tried.
// Silence is not Down.
func Down(stderr []byte) bool { return reDown.Match(stderr) }

// KeyFallback reads the host keys at address and port another way than
// ssh-keyscan: the built-in ssh client, which negotiates the algorithms of a
// legacy-ssh device. quick is set for a device nothing has answered from
// yet (ssh-keyscan printed nothing): the fallback then bounds the TCP
// connect shortly, so that a filtered or powered-off address does not cost
// the whole handshake budget. It is a parameter (the cli hands in the real
// one, a test its own) so that this package never dials. Keys it returns are
// ordinary HostKeys; an error, or none, leaves the ssh-keyscan outcome. tm is
// the timing of the scan (no zero field; a scaled one for a slow or distant
// device, devssh.ScanTiming.Scaled): the fallback reads with it, so that its
// connect, handshake and per-type attempt are the scan's, not a default.
type KeyFallback func(ctx context.Context, address string, port int, quick bool, tm devssh.ScanTiming) ([]HostKey, error)

// Scan reads the host keys address offers on port with ssh-keyscan. A
// device that does not answer is ErrNoAnswer; ssh-keyscan missing is an
// error that says so.
func Scan(ctx context.Context, r execx.Runner, address string, port int, legacy bool) ([]HostKey, error) {
	return ScanWith(ctx, r, address, port, legacy, nil)
}

// ScanWith is Scan with a fallback. When the combined ssh-keyscan reads no
// key from a device that accepted a connection (Reached), the key types are
// asked for one at a time, in order (ed25519, ecdsa, rsa, and ssh-rsa for a
// legacy device), each with a short timeout: a device that drops or limits
// the several connections ssh-keyscan opens at once, or mishandles its long
// offer, answers one. A type that fails does not end the scan, and the keys
// of all the types that answer are returned, as ssh-keyscan's would be. If
// still no key was read, the fallback is tried (a nil fallback is Scan):
//   - for a device that was reached;
//   - for a legacy device, whatever ssh-keyscan said, also when it could
//     not be run;
//   - for a device that answered nothing at all (ssh-keyscan printed
//     nothing: a server slow to greet, which plain ssh reaches since it
//     waits longer; a refused connection; an address nobody answers at),
//     once and without the one-type retry, as nothing shows it accepted a
//     connection. The fallback is asked to bound the connect shortly
//     (quick). A refused device fails it at once, a filtered one costs the
//     short connect budget.
//
// A name that does not resolve (Down) gets nothing more: one ssh-keyscan,
// for a modern device. The fallback's keys are returned as ssh-keyscan's
// would be. When all fail the error is ssh-keyscan's (a NoAnswerError when
// anything beyond ssh-keyscan was tried), so a caller's ErrNoAnswer handling
// is unchanged; a cancelled context is returned as it is.
func ScanWith(ctx context.Context, r execx.Runner, address string, port int, legacy bool, fallback KeyFallback) ([]HostKey, error) {
	return scanWith(ctx, r, address, port, legacy, fallback, true, devssh.ScanTiming{})
}

// ScanWithTiming is ScanWith with the timing tm of ssh-keyscan's two -T and
// of the built-in client's reads (its zero fields are the defaults of
// devssh.DefaultScanTiming); the fallback is handed the same timing, and this
// package never dials.
func ScanWithTiming(ctx context.Context, r execx.Runner, address string, port int, legacy bool, fallback KeyFallback, tm devssh.ScanTiming) ([]HostKey, error) {
	return scanWith(ctx, r, address, port, legacy, fallback, true, tm)
}

// ScanWithAnswered is ScanWith without the read of a device that answered
// nothing: the fallback is only tried for a device that was reached and for
// a legacy one. It is the scan of a caller that must not wait longer than
// ssh-keyscan and, for a device that answered, the fallback.
func ScanWithAnswered(ctx context.Context, r execx.Runner, address string, port int, legacy bool, fallback KeyFallback, tm devssh.ScanTiming) ([]HostKey, error) {
	return scanWith(ctx, r, address, port, legacy, fallback, false, tm)
}

func scanWith(ctx context.Context, r execx.Runner, address string, port int, legacy bool, fallback KeyFallback, readSilent bool, tm devssh.ScanTiming) ([]HostKey, error) {
	tm = tm.WithDefaults()
	keys, seen, err := keyscan(ctx, r, keyscanCombined(address, port, legacy, tm))
	if err == nil || ctx.Err() != nil {
		return keys, err
	}
	noAnswer := errors.Is(err, ErrNoAnswer)
	reached := seen.reached
	// silent: ssh-keyscan read nothing and printed nothing about the
	// device.
	silent := noAnswer && !reached && !seen.down
	var tried NoAnswerError
	if noAnswer && reached {
		tried.OneByOne = retryTypes(legacy)
		found, rerr := scanOneByOne(ctx, r, address, port, tried.OneByOne, tm)
		if rerr != nil {
			return nil, rerr
		}
		if len(found) > 0 {
			return found, nil
		}
	}
	// The built-in client reads a legacy device whatever ssh-keyscan said,
	// and a modern one that answered or (readSilent) that said nothing.
	builtin := legacy || (noAnswer && (reached || (silent && readSilent)))
	if fallback == nil || !builtin {
		return nil, scanFailure(err, tried)
	}
	tried.Silent = silent && !legacy
	fk, ferr := fallback(ctx, address, port, silent && !legacy, tm)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if ferr == nil && len(fk) > 0 {
		return sortKeys(fk), nil
	}
	tried.Builtin = true
	return nil, scanFailure(err, tried)
}

// scanFailure is the error of a scan that read nothing: err (ssh-keyscan's),
// or for a device that was reached the NoAnswerError that says what was
// tried.
func scanFailure(err error, tried NoAnswerError) error {
	if errors.Is(err, ErrNoAnswer) && (len(tried.OneByOne) > 0 || tried.Builtin) {
		return &tried
	}
	return err
}

// scanOneByOne runs ssh-keyscan once per key type, one after the other, and
// returns the keys of every type that answered (in type order, without
// duplicates). A type that fails, or an ssh-keyscan that cannot be run, is
// skipped; only a cancelled context is an error.
func scanOneByOne(ctx context.Context, r execx.Runner, address string, port int, types []string, tm devssh.ScanTiming) ([]HostKey, error) {
	var found []HostKey
	for _, t := range types {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		keys, _, err := keyscan(ctx, r, keyscanTyped(address, port, t, tm))
		if err == nil {
			found = append(found, keys...)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return sortKeys(found), nil
}

// keyscanSeen is what an ssh-keyscan printed on standard error shows of the
// device.
type keyscanSeen struct {
	reached bool // Reached
	down    bool // Down
}

// keyscan runs one ssh-keyscan: its keys, what its standard error shows of
// the device and the error: ErrNoAnswer when it read no key, another when
// ssh-keyscan could not be run, the context's own when it ended.
func keyscan(ctx context.Context, r execx.Runner, c execx.Cmd) (keys []HostKey, seen keyscanSeen, err error) {
	res, err := r.Run(ctx, c)
	if err != nil {
		if ctx.Err() != nil {
			return nil, seen, ctx.Err()
		}
		return nil, seen, fail("ssh-keyscan could not be run (" + firstLine(err.Error()) + "); it comes with the openssh-client package.")
	}
	seen.reached = Reached(res.Stderr)
	seen.down = !seen.reached && Down(res.Stderr)
	keys = ParseKeyscan(res.Stdout)
	if len(keys) == 0 {
		return nil, seen, ErrNoAnswer
	}
	seen.reached = true
	return keys, seen, nil
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
// on its own console, per vendor. The Junos text was verified on an EX4300
// (Junos 25.4; there is no 'show system ssh host-key'); the Cisco and WTI
// texts are still unconfirmed on a unit; the Linux one is ssh-keygen's own.
var verifyHints = map[string]string{
	"cisco":     "Cisco IOS/IOS-XE: 'show ip ssh' and 'show crypto key mypubkey rsa' (the fingerprint form varies by release)",
	"juniper":   "Junos: 'file show /etc/ssh/ssh_host_ed25519_key.pub' (also the ecdsa and rsa .pub files beside it; compare with 'tacctl device hostkey <name> show'), or from 'start shell' 'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub'",
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
