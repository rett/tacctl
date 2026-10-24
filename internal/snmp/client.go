// Package snmp reads values from a device by SNMP: a GetRequest of one
// object (or of sysObjectID.0 with sysDescr.0), over UDP, as v2c (a community) or as v3 with the User-based
// Security Model at authPriv (HMAC-SHA-96 or HMAC-SHA-256-192, AES-128),
// with the engine discovery v3 needs. 'device add' and 'device check' read
// sysName.0 with it for a name hint (docs/plans/0.2.2-plan.md 5.10) and
// the identity for the vendor (vendor.go, 0.2.17 D260); it is
// the standard library only, so tacctl needs neither a module nor
// net-snmp for it. The settings are in tacctl.yaml (snmp.*), the
// community and the v3 passphrases in StateDir/snmp.yaml (secrets.go).
package snmp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// SysNameOID is sysName.0 (RFC 3418): the device's own name for itself.
const SysNameOID = "1.3.6.1.2.1.1.5.0"

// SysLocationOID is sysLocation.0 (RFC 3418): where the device says it is.
const SysLocationOID = "1.3.6.1.2.1.1.6.0"

// SysDescrOID is sysDescr.0 (RFC 3418): the device's description of its
// hardware and software.
const SysDescrOID = "1.3.6.1.2.1.1.1.0"

// SysObjectIDOID is sysObjectID.0 (RFC 3418): the vendor's identification
// of the device, under the vendor's enterprise number.
const SysObjectIDOID = "1.3.6.1.2.1.1.2.0"

// The versions tacctl.yaml's snmp.version takes.
const (
	V2c = "v2c"
	V3  = "v3"
)

// Versions are the snmp.version words.
var Versions = []string{V2c, V3}

// The defaults of snmp.port and snmp.timeout, and the timeout's range.
const (
	DefaultPort    = 161
	DefaultTimeout = 2
	MinTimeout     = 1
	MaxTimeout     = 10
)

// Getter reads a device's sysName.0 and sysLocation.0, and its sysObjectID.0
// with its sysDescr.0. Config is the real one; the CLI's tests put a stub in
// its place (app.App's SNMP).
type Getter interface {
	SysName(ctx context.Context, address string) (string, error)
	SysLocation(ctx context.Context, address string) (string, error)
	SysIdentity(ctx context.Context, address string) (Identity, error)
}

// Identity is what a device says it is: its sysObjectID.0 (dotted) and its
// sysDescr.0 text, either empty when the agent has none.
type Identity struct {
	ObjectID string
	Descr    string
}

// Config is how to ask: the version and its credentials, the port and the
// wait for each try (one retry after the first).
type Config struct {
	Version   string
	Port      int
	Timeout   time.Duration
	Retries   int
	Community string
	// The v3 user, its authentication and privacy passphrases and
	// protocols (sha or sha256; aes128).
	User, AuthPass, PrivPass string
	Auth, Priv               string
}

// TimeoutError is no answer: on v2c also what a wrong community looks
// like, since an agent drops such a request without a word.
type TimeoutError struct {
	Timeout time.Duration
	Tries   int
}

func (e *TimeoutError) Error() string {
	return "no answer (" + strconv.Itoa(e.Tries) + " tries, " + e.Timeout.String() + " each)"
}

// AnswerError is an answer that came and could not be read: an error-status,
// another object than asked for, or a value of the wrong type. The device
// answered; what it said is not used.
type AnswerError struct{ Why string }

func (e *AnswerError) Error() string { return e.Why }

// ReportError is a v3 Report: the agent refused the request, and says why
// in the name of the usmStats counter it raised (unknownUserName,
// wrongDigest, ...).
type ReportError struct{ Name string }

func (e *ReportError) Error() string {
	why := map[string]string{
		"unknownUserName":     "the agent has no such user",
		"wrongDigest":         "wrong authentication passphrase or protocol",
		"decryptionError":     "wrong privacy passphrase",
		"unsupportedSecLevel": "the user is not set up for authentication and privacy",
		"notInTimeWindow":     "the agent's clock moved during the request",
		"unknownEngineID":     "the agent did not accept its own engine ID",
	}[e.Name]
	if why == "" {
		return "the agent sent a report (" + e.Name + ")"
	}
	return e.Name + " (" + why + ")"
}

// usmStats are the report counters of RFC 3414 (usmStats, 1.3.6.1.6.3.15.1.1)
// by name.
var usmStats = map[string]string{
	"1.3.6.1.6.3.15.1.1.1.0": "unsupportedSecLevel",
	"1.3.6.1.6.3.15.1.1.2.0": "notInTimeWindow",
	"1.3.6.1.6.3.15.1.1.3.0": "unknownUserName",
	"1.3.6.1.6.3.15.1.1.4.0": "unknownEngineID",
	"1.3.6.1.6.3.15.1.1.5.0": "wrongDigest",
	"1.3.6.1.6.3.15.1.1.6.0": "decryptionError",
}

// reportName is the name of the counter a Report carries.
func reportName(p pdu) string {
	if len(p.varbinds) == 0 {
		return "report"
	}
	if n, ok := usmStats[p.varbinds[0].oid]; ok {
		return n
	}
	return "report " + p.varbinds[0].oid
}

// randRead is the source of request IDs and salts.
var randRead = rand.Read

func randID() int64 {
	var b [4]byte
	_, _ = randRead(b[:])
	return int64(binary.BigEndian.Uint32(b[:]) & 0x7fffffff)
}

// SysName reads sysName.0 from address: the text of its OCTET STRING.
func (c Config) SysName(ctx context.Context, address string) (string, error) {
	v, err := c.Get(ctx, address, SysNameOID)
	if err != nil {
		return "", err
	}
	if v.tag != tagOctetString {
		return "", fmt.Errorf("sysName.0 is not text (tag 0x%02x)", v.tag)
	}
	return string(v.val), nil
}

// SysLocation reads sysLocation.0 from address: the text of its OCTET
// STRING (empty when the device has none set).
func (c Config) SysLocation(ctx context.Context, address string) (string, error) {
	v, err := c.Get(ctx, address, SysLocationOID)
	if err != nil {
		return "", err
	}
	if v.tag != tagOctetString {
		return "", fmt.Errorf("sysLocation.0 is not text (tag 0x%02x)", v.tag)
	}
	return string(v.val), nil
}

// SysIdentity reads sysObjectID.0 and sysDescr.0 from address in one
// request. An object the agent does not have is empty, not an error: the
// vendor detection says what is missing.
func (c Config) SysIdentity(ctx context.Context, address string) (Identity, error) {
	vs, err := c.getAll(ctx, address, []string{SysObjectIDOID, SysDescrOID})
	if err != nil {
		return Identity{}, err
	}
	var id Identity
	switch v := vs[0]; v.tag {
	case tagOID:
		if id.ObjectID, err = decOID(v.val); err != nil {
			return Identity{}, &AnswerError{Why: "sysObjectID.0 is not an object identifier"}
		}
	case tagNoSuchObject, tagNoSuchInstance, tagEndOfMibView:
	default:
		return Identity{}, &AnswerError{Why: fmt.Sprintf("sysObjectID.0 is not an object identifier (tag 0x%02x)", v.tag)}
	}
	switch v := vs[1]; v.tag {
	case tagOctetString:
		id.Descr = string(v.val)
	case tagNoSuchObject, tagNoSuchInstance, tagEndOfMibView:
	default:
		return Identity{}, &AnswerError{Why: fmt.Sprintf("sysDescr.0 is not text (tag 0x%02x)", v.tag)}
	}
	return id, nil
}

// Get reads one object from address.
func (c Config) Get(ctx context.Context, address, oid string) (tlv, error) {
	vs, err := c.getAll(ctx, address, []string{oid})
	if err != nil {
		return tlv{}, err
	}
	switch v := vs[0]; v.tag {
	case tagNoSuchObject, tagNoSuchInstance, tagEndOfMibView:
		return tlv{}, errors.New("the agent has no " + oid)
	}
	return vs[0], nil
}

// getAll reads the objects oids from address in one GetRequest: their
// values in that order, a varbind exception (noSuchObject and the like)
// among them as it came.
func (c Config) getAll(ctx context.Context, address string, oids []string) ([]tlv, error) {
	port := c.Port
	if port == 0 {
		port = DefaultPort
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	switch c.Version {
	case V2c:
		return c.getV2c(ctx, conn, oids)
	case V3:
		return c.getV3(ctx, conn, oids)
	}
	return nil, errors.New("unknown SNMP version '" + c.Version + "' (v2c or v3)")
}

// varbindsOf are the request's varbinds: each oid with no value.
func varbindsOf(oids []string) []varbind {
	vbs := make([]varbind, len(oids))
	for i, o := range oids {
		vbs[i] = varbind{oid: o}
	}
	return vbs
}

// exchange sends req and reads answers until match takes one (true), for
// the timeout, once more after a resend for each retry. An answer match
// does not want (another request's, garbage) is skipped.
func (c Config) exchange(ctx context.Context, conn net.Conn, req []byte, match func([]byte) (bool, error)) error {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout * time.Second
	}
	buf := make([]byte, maxMsgSize)
	tries := c.Retries + 1
	for range tries {
		if _, err := conn.Write(req); err != nil {
			return err
		}
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetReadDeadline(deadline)
		for {
			n, err := conn.Read(buf)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}
			if err != nil {
				// An ICMP port unreachable reads as a refused connection:
				// no agent there, which is no answer too.
				break
			}
			ok, err := match(buf[:n])
			if err != nil {
				return err
			}
			if ok {
				return nil
			}
		}
		// A refused read returns at once: wait out the rest of the try
		// before the resend, as for a silent agent.
		if wait := time.Until(deadline); wait > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	return &TimeoutError{Timeout: timeout, Tries: tries}
}

// getV2c is one community-based GetRequest.
func (c Config) getV2c(ctx context.Context, conn net.Conn, oids []string) ([]tlv, error) {
	id := randID()
	req, err := v2cMsg{community: []byte(c.Community), pdu: pdu{tag: tagGetRequest, requestID: id,
		varbinds: varbindsOf(oids)}}.encode()
	if err != nil {
		return nil, err
	}
	var got []tlv
	err = c.exchange(ctx, conn, req, func(b []byte) (bool, error) {
		m, err := decodeV2c(b)
		if err != nil || m.pdu.requestID != id || m.pdu.tag != tagGetResponse {
			return false, nil
		}
		got, err = answer(m.pdu, oids)
		return true, err
	})
	return got, err
}

// answer is the values of oids in a GetResponse, in that order.
func answer(p pdu, oids []string) ([]tlv, error) {
	if p.errorStatus != 0 {
		return nil, &AnswerError{Why: fmt.Sprintf("the agent answered with error-status %d", p.errorStatus)}
	}
	if len(p.varbinds) != len(oids) {
		return nil, &AnswerError{Why: "the agent answered for other objects"}
	}
	out := make([]tlv, len(oids))
	for i, o := range oids {
		if p.varbinds[i].oid != o {
			return nil, &AnswerError{Why: "the agent answered for another object"}
		}
		out[i] = p.varbinds[i].value
	}
	return out, nil
}

// engine is what discovery learns of the agent: its engine ID, its boots
// and its time when learnt.
type engine struct {
	id          []byte
	boots, time int64
	at          time.Time
}

// now is the agent's engine time at this moment, by its time when learnt.
func (e engine) now() int64 { return e.time + int64(time.Since(e.at)/time.Second) }

// getV3 discovers the engine, then sends one authPriv GetRequest; a
// notInTimeWindow report (the agent's clock, from discovery, was stale)
// gives the right time and the request is sent once more.
func (c Config) getV3(ctx context.Context, conn net.Conn, oids []string) ([]tlv, error) {
	alg, err := authOf(c.Auth)
	if err != nil {
		return nil, err
	}
	if c.Priv != "" && c.Priv != PrivAES128 {
		return nil, errors.New("unknown SNMPv3 privacy protocol '" + c.Priv + "' (aes128)")
	}
	eng, err := c.discover(ctx, conn)
	if err != nil {
		return nil, err
	}
	authKey, err := LocalizedKey(c.Auth, c.AuthPass, eng.id)
	if err != nil {
		return nil, errors.New("the v3 authentication passphrase is not set")
	}
	privKey, err := LocalizedKey(c.Auth, c.PrivPass, eng.id)
	if err != nil {
		return nil, errors.New("the v3 privacy passphrase is not set")
	}
	for attempt := 0; ; attempt++ {
		v, fresh, err := c.getAuthPriv(ctx, conn, oids, alg, authKey, privKey, eng)
		var rep *ReportError
		if attempt == 0 && errors.As(err, &rep) && rep.Name == "notInTimeWindow" && fresh != nil {
			eng = *fresh
			continue
		}
		return v, err
	}
}

// discover sends the empty, unauthenticated request that makes the agent
// report its engine ID, boots and time (RFC 3414 4).
func (c Config) discover(ctx context.Context, conn net.Conn) (engine, error) {
	id := randID()
	probe := v3Msg{msgID: id, maxSize: maxMsgSize, flags: flagReportable,
		pdu: pdu{tag: tagGetRequest, requestID: randID()}}
	scoped, err := probe.scopedPDU()
	if err != nil {
		return engine{}, err
	}
	req, _ := probe.encode(scoped)
	var eng engine
	err = c.exchange(ctx, conn, req, func(b []byte) (bool, error) {
		m, _, err := decodeV3(b)
		if err != nil || m.msgID != id || m.flags&flagPriv != 0 {
			return false, nil
		}
		if len(m.engineID) == 0 {
			return true, errors.New("the agent sent no engine ID")
		}
		eng = engine{id: append([]byte(nil), m.engineID...), boots: m.boots, time: m.time, at: time.Now()}
		return true, nil
	})
	return eng, err
}

// getAuthPriv is one authPriv GetRequest. A report that came authenticated
// also returns the engine's boots and time it carries (fresh).
func (c Config) getAuthPriv(ctx context.Context, conn net.Conn, oids []string, alg authAlg, authKey, privKey []byte,
	eng engine) (got []tlv, fresh *engine, err error) {
	salt := make([]byte, 8)
	if _, err := randRead(salt); err != nil {
		return nil, nil, err
	}
	id, reqID := randID(), randID()
	m := v3Msg{msgID: id, maxSize: maxMsgSize, flags: flagAuth | flagPriv | flagReportable,
		engineID: eng.id, boots: eng.boots, time: eng.now(), user: []byte(c.User),
		authParams: make([]byte, alg.macLen), privParams: salt,
		contextEngineID: eng.id, pdu: pdu{tag: tagGetRequest, requestID: reqID, varbinds: varbindsOf(oids)}}
	scoped, err := m.scopedPDU()
	if err != nil {
		return nil, nil, err
	}
	ct, err := aesCFB(true, privKey, m.boots, m.time, salt, scoped)
	if err != nil {
		return nil, nil, err
	}
	req, authAt := m.encode(encString(ct))
	copy(req[authAt:], mac(alg, authKey, req))
	err = c.exchange(ctx, conn, req, func(b []byte) (bool, error) {
		r, at, err := decodeV3(b)
		if err != nil || r.msgID != id {
			return false, nil
		}
		authed := r.flags&flagAuth != 0
		if authed && !macOK(alg, authKey, b, at, r.authParams) {
			return false, nil // not from the agent that has our key
		}
		if r.flags&flagPriv != 0 {
			if err := r.decryptScoped(privKey); err != nil {
				return true, err
			}
		}
		if r.pdu.tag == tagReport {
			if authed {
				fresh = &engine{id: eng.id, boots: r.boots, time: r.time, at: time.Now()}
			}
			return true, &ReportError{Name: reportName(r.pdu)}
		}
		if r.pdu.tag != tagGetResponse || r.pdu.requestID != reqID {
			return false, nil
		}
		if !authed || r.flags&flagPriv == 0 {
			return true, errors.New("the agent answered without authentication and privacy")
		}
		got, err = answer(r.pdu, oids)
		return true, err
	})
	return got, fresh, err
}
