package devssh

// A host-key scan with the built-in client (the fallback of 'device add'
// and the re-scans for a legacy-ssh device, for a device that answered
// ssh-keyscan with no key, and for one ssh-keyscan printed nothing about): the system's ssh-keyscan cannot negotiate the
// SHA-1 key exchanges and CBC ciphers old IOS offers, so it reads nothing
// from such a device, while this client does (the Legacy lists of Dial). The key exchange ends before authentication, so the scan
// stops in the host key callback: no credential is ever sent.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// ScanTiming is every timing of a host-key read, in one place, so that a
// later scale (per device, per scope, for a link with a long round trip) has
// one value to change. Its zero fields are the defaults of DefaultScanTiming.
type ScanTiming struct {
	// Keyscan is ssh-keyscan's -T for the combined scan of every key type.
	Keyscan time.Duration
	// KeyscanRetry is ssh-keyscan's -T for each of the one-type attempts
	// that follow a combined scan which read nothing.
	KeyscanRetry time.Duration
	// Connect is the budget of the built-in client's TCP connect, for the
	// read of a device nothing has answered from yet (ssh-keyscan printed
	// nothing). A server that is merely slow to greet accepts the
	// connection at once, a refused connection fails at once, and only a
	// filtered or powered-off address runs this budget out: such a device
	// costs this much, not the whole Handshake. The connect shares the
	// Handshake budget (it is not added to it).
	Connect time.Duration
	// Handshake bounds the built-in client's first connection as a whole:
	// the TCP connect, the server's banner and the key exchange up to the
	// host key.
	Handshake time.Duration
	// Attempt bounds each connection after the first of a read: the device
	// has already answered once, so a key type it does not hold fails the
	// handshake at once and a slow one is not worth waiting for.
	Attempt time.Duration
}

// DefaultScanTiming is the timing of every host-key read.
//
// Connect is 3 s for a link with a 600 ms round trip: a lost SYN is sent
// again after 1 s (the first retransmission timeout), so a connect that
// survives one retransmit takes 1 s plus the round trip, 1.6 s; 3 s is that
// with room for a second round trip, and also the 3 s the second
// retransmission would take, so it is the floor: shorter would give up on a
// distant device that one lost packet delays. It is also short enough that a
// filtered or powered-off address costs little. Handshake is 10 s, the
// DefaultConnectTimeout of the sessions: a banner and the key exchange take
// four round trips (2.4 s at 600 ms) after a connect of up to 3 s, with room
// for a server that is slow to greet by several seconds. Attempt is 5 s: a
// device measured to send its banner 3 to 4 s after the connect passes it,
// one that is both that slow and 600 ms away does not. ssh-keyscan's 5 s and
// 3 s are the values it has always had.
func DefaultScanTiming() ScanTiming {
	return ScanTiming{
		Keyscan:      5 * time.Second,
		KeyscanRetry: 3 * time.Second,
		Connect:      3 * time.Second,
		Handshake:    DefaultConnectTimeout,
		Attempt:      5 * time.Second,
	}
}

// WithDefaults is t with its zero fields set to those of DefaultScanTiming.
func (t ScanTiming) WithDefaults() ScanTiming {
	d := DefaultScanTiming()
	if t.Keyscan <= 0 {
		t.Keyscan = d.Keyscan
	}
	if t.KeyscanRetry <= 0 {
		t.KeyscanRetry = d.KeyscanRetry
	}
	if t.Connect <= 0 {
		t.Connect = d.Connect
	}
	if t.Handshake <= 0 {
		t.Handshake = d.Handshake
	}
	if t.Attempt <= 0 {
		t.Attempt = d.Attempt
	}
	return t
}

// scanFamily is one host key type and the signature algorithms that name
// it. A device offers one key per negotiated algorithm, so a scan asks for
// each type it has not read yet with a connection of its own.
type scanFamily struct {
	typ  string
	algs []string
}

// scanFamilies are the key types a scan asks for, in the order the system
// ssh prefers them in. An RSA key is one key whichever of its signature
// algorithms is negotiated, so the three share a connection (SHA-1 'ssh-rsa'
// last: it is all an old device has).
var scanFamilies = []scanFamily{
	{ssh.KeyAlgoED25519, []string{ssh.KeyAlgoED25519}},
	{ssh.KeyAlgoECDSA256, []string{ssh.KeyAlgoECDSA256}},
	{ssh.KeyAlgoECDSA384, []string{ssh.KeyAlgoECDSA384}},
	{ssh.KeyAlgoECDSA521, []string{ssh.KeyAlgoECDSA521}},
	{ssh.KeyAlgoRSA, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}},
}

// errScanned ends the handshake in the host key callback once the key is
// held: the scan has what it came for and authentication never starts.
var errScanned = errors.New("host key read")

// ScanHostKeys reads the host keys the ssh server at host:port offers, as
// '<type> <base64>' texts (devreg.HostKey.String's form), in the order of
// ssh-ed25519, ecdsa-sha2-*, ssh-rsa. Each connection ends in the host key
// callback, before authentication: no password or other credential is sent,
// and nothing is verified (what the scan reads is what the caller shows the
// operator to compare). A nil dialer dials the address; timeout 0 is
// DefaultConnectTimeout, and each later connection has the default
// ScanTiming.Attempt.
//
// A device may drop a connection whose key exchange offer is long, as the
// one that includes the legacy algorithms is. The scan therefore starts
// with the short offer of the library's defaults and a single host key
// algorithm, ed25519 first, then each of the other key types in turn (one
// connection per type, one after the other, the failures ignored); a device
// that shows a key to that is done. Only when no key was read that way does
// it make the connections of an old device: the first one offers every
// algorithm, with the Legacy lists of Dial (a superset of the defaults), and
// reads the device's preferred key, and one more short connection
// (ScanTiming.Attempt) is made per key type that is still missing, ignoring
// those that fail, so that a device with several key types shows them all.
// Only a failure of the first connection is an error (the typed errors of
// errors.go: ErrUnreachable, ErrTimeout, ErrHandshake, or the context's own
// error); a device that does not answer the first one is not asked again,
// and no key read and no error does not happen.
func ScanHostKeys(ctx context.Context, host string, port int, timeout time.Duration, dialer Dialer) ([]string, error) {
	tm := ScanTiming{Handshake: timeout}.WithDefaults()
	return scanHostKeys(ctx, host, port, 0, tm, dialer)
}

// ScanHostKeysTiming is ScanHostKeys with the timing tm (zero fields are the
// defaults). With quick set the TCP connect of the first connection is
// bounded by tm.Connect, shorter than tm.Handshake: a connect that does not
// finish in it is ErrTimeout, as one that runs out the whole Handshake is,
// while the handshake that follows keeps its budget, so that a server that
// accepts at once and is slow to greet is read, and an address nobody
// answers at is given up on after the short budget. Every later connection
// of the read is bounded by tm.Attempt.
func ScanHostKeysTiming(ctx context.Context, host string, port int, tm ScanTiming, quick bool, dialer Dialer) ([]string, error) {
	tm = tm.WithDefaults()
	connect := time.Duration(0)
	if quick {
		connect = tm.Connect
	}
	return scanHostKeys(ctx, host, port, connect, tm, dialer)
}

// scanHostKeys reads the keys with the connect budget of the first
// connection (connect <= 0: the whole Handshake); tm has no zero field.
func scanHostKeys(ctx context.Context, host string, port int, connect time.Duration, tm ScanTiming, dialer Dialer) ([]string, error) {
	timeout := tm.Handshake
	if port == 0 {
		port = DefaultPort
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var got []ssh.PublicKey
families:
	for i, f := range scanFamilies {
		if err := ctx.Err(); err != nil {
			return nil, contextError(ctx, addr)
		}
		t, c := min(timeout, tm.Attempt), time.Duration(0)
		if i == 0 {
			t, c = timeout, connect
		}
		k, err := scanOnce(ctx, addr, f.algs, false, c, t, dialer)
		switch {
		case err == nil:
			got = append(got, k)
		case i == 0 && (errors.Is(err, ErrUnreachable) || errors.Is(err, ErrTimeout) || ctx.Err() != nil):
			// Nobody answers: asking again for the other types would only
			// wait again.
			return nil, err
		case errors.Is(err, ErrUnreachable) || errors.Is(err, ErrTimeout):
			// The device went away between two connections.
			break families
		}
	}
	if len(got) == 0 {
		// An old device: its key exchanges and ciphers are not the defaults.
		first, err := scanOnce(ctx, addr, hostKeyAlgorithms(nil, true), true, 0, timeout, dialer)
		if err != nil {
			return nil, err
		}
		got = []ssh.PublicKey{first}
		for _, f := range scanFamilies {
			if err := ctx.Err(); err != nil {
				return nil, contextError(ctx, addr)
			}
			if hasKeyType(got, f.typ) {
				continue
			}
			// A type the device does not hold fails the handshake (no common
			// algorithm); a failure here only means that key is not offered.
			if k, err := scanOnce(ctx, addr, f.algs, true, 0, min(timeout, tm.Attempt), dialer); err == nil && !hasKeyType(got, k.Type()) {
				got = append(got, k)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, contextError(ctx, addr)
	}
	var out []string
	for _, f := range scanFamilies {
		for _, k := range got {
			if k.Type() == f.typ {
				out = append(out, keyText(k))
			}
		}
	}
	// A key type outside scanFamilies (a first connection that negotiated
	// something else) is kept too, after the known ones.
	for _, k := range got {
		if !knownScanType(k.Type()) {
			out = append(out, keyText(k))
		}
	}
	return out, nil
}

func hasKeyType(keys []ssh.PublicKey, typ string) bool {
	for _, k := range keys {
		if k.Type() == typ {
			return true
		}
	}
	return false
}

func knownScanType(typ string) bool {
	for _, f := range scanFamilies {
		if f.typ == typ {
			return true
		}
	}
	return false
}

// scanOnce connects, offers algs as host key algorithms (with the legacy key
// exchanges and ciphers added when legacy is set, the library's defaults
// otherwise) and returns the key the device presents; the connection is
// closed before it returns. timeout bounds the connect and the handshake
// together; a connect budget (connect > 0, shorter than timeout) bounds the
// TCP connect alone, and a connect that does not finish in it is ErrTimeout.
func scanOnce(ctx context.Context, addr string, algs []string, legacy bool, connect, timeout time.Duration, dialer Dialer) (ssh.PublicKey, error) {
	hs, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := dialer
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	dctx, dcancel := hs, context.CancelFunc(func() {})
	if connect > 0 && connect < timeout {
		dctx, dcancel = context.WithTimeout(hs, connect)
	}
	conn, err := dial(dctx, "tcp", addr)
	dcancel()
	if err != nil {
		return nil, dialError(ctx, dctx, addr, err)
	}
	defer func() { _ = conn.Close() }()

	var offered ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "tacctl",
		// No Auth: the callback ends the handshake before it is asked for.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			offered = key
			return errScanned
		},
		HostKeyAlgorithms: algs,
		ClientVersion:     "SSH-2.0-tacctl",
	}
	if legacy {
		addLegacyAlgorithms(cfg)
	}
	unhook := context.AfterFunc(hs, func() { _ = conn.Close() })
	_, _, _, err = ssh.NewClientConn(conn, addr, cfg)
	unhook()
	if offered != nil {
		return offered, nil
	}
	switch {
	case ctx.Err() != nil:
		return nil, contextError(ctx, addr)
	case errors.Is(hs.Err(), context.DeadlineExceeded):
		return nil, fmt.Errorf("%w: connecting to %s", ErrTimeout, addr)
	case err == nil:
		// Cannot happen: the callback always refuses.
		err = errors.New("no host key offered")
	}
	return nil, fmt.Errorf("%w: %s: %s", ErrHandshake, addr, sanitize(err.Error()))
}
