package devssh

// A host-key scan with the built-in client (the fallback of 'device add'
// and the re-scans for a legacy-ssh device, and for a device that answered
// ssh-keyscan with no key): the system's ssh-keyscan cannot negotiate the
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

// ScanAttemptTimeout bounds each connection after the first of a scan: the
// device has already answered once, so a key type it does not hold fails
// the handshake at once and a slow one is not worth waiting for.
const ScanAttemptTimeout = 5 * time.Second

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
// DefaultConnectTimeout.
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
// (ScanAttemptTimeout) is made per key type that is still missing, ignoring
// those that fail, so that a device with several key types shows them all.
// Only a failure of the first connection is an error (the typed errors of
// errors.go: ErrUnreachable, ErrTimeout, ErrHandshake, or the context's own
// error); a device that does not answer the first one is not asked again,
// and no key read and no error does not happen.
func ScanHostKeys(ctx context.Context, host string, port int, timeout time.Duration, dialer Dialer) ([]string, error) {
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}
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
		t := min(timeout, ScanAttemptTimeout)
		if i == 0 {
			t = timeout
		}
		k, err := scanOnce(ctx, addr, f.algs, false, t, dialer)
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
		first, err := scanOnce(ctx, addr, hostKeyAlgorithms(nil, true), true, timeout, dialer)
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
			if k, err := scanOnce(ctx, addr, f.algs, true, min(timeout, ScanAttemptTimeout), dialer); err == nil && !hasKeyType(got, k.Type()) {
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
// closed before it returns.
func scanOnce(ctx context.Context, addr string, algs []string, legacy bool, timeout time.Duration, dialer Dialer) (ssh.PublicKey, error) {
	hs, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := dialer
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(hs, "tcp", addr)
	if err != nil {
		return nil, dialError(ctx, hs, addr, err)
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
