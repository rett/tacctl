package snmp

// The SNMP messages: v2c (RFC 3416, community-based) and v3 (RFC 3412 6,
// with the USM security parameters of RFC 3414 2.4), encoded and decoded by
// the client and by the test agent alike.

import (
	"bytes"
	"crypto/hmac"
	"errors"
)

// The message versions on the wire.
const (
	wireV2c = 1
	wireV3  = 3
)

// The v3 msgFlags bits and the USM security model.
const (
	flagAuth       = 0x01
	flagPriv       = 0x02
	flagReportable = 0x04
	securityUSM    = 3
	// maxMsgSize is what this side accepts (the largest UDP payload).
	maxMsgSize = 65507
)

// v2cMsg is a community-based message.
type v2cMsg struct {
	community []byte
	pdu       pdu
}

func (m v2cMsg) encode() ([]byte, error) {
	p, err := encPDU(m.pdu)
	if err != nil {
		return nil, err
	}
	return enc(tagSequence, encInt(tagInteger, wireV2c), encString(m.community), p), nil
}

// v3Msg is a USM message. pdu, contextEngineID and contextName are the
// scoped PDU in the clear; with flagPriv the wire carries it encrypted.
type v3Msg struct {
	msgID      int64
	maxSize    int64
	flags      byte
	engineID   []byte
	boots      int64
	time       int64
	user       []byte
	authParams []byte
	privParams []byte

	contextEngineID []byte
	contextName     []byte
	pdu             pdu
	// encrypted is the scoped PDU as it came off the wire, when flagPriv
	// is set (decode leaves the decryption to the caller, who has the key).
	encrypted []byte
}

// hdrLen is the length of the tag and length octets of a value of n bytes.
func hdrLen(n int) int { return 1 + len(encLength(n)) }

// scopedPDU is the plaintext scoped PDU.
func (m v3Msg) scopedPDU() ([]byte, error) {
	p, err := encPDU(m.pdu)
	if err != nil {
		return nil, err
	}
	return enc(tagSequence, encString(m.contextEngineID), encString(m.contextName), p), nil
}

// encode is the message with data as its msgData (the scoped PDU, or the
// OCTET STRING of the encrypted one), and the offset of the
// msgAuthenticationParameters contents in it (which hold m.authParams).
func (m v3Msg) encode(data []byte) (msg []byte, authAt int) {
	global := enc(tagSequence, encInt(tagInteger, m.msgID), encInt(tagInteger, m.maxSize),
		encString([]byte{m.flags}), encInt(tagInteger, securityUSM))
	prefix := bytes.Join([][]byte{encString(m.engineID), encInt(tagInteger, m.boots),
		encInt(tagInteger, m.time), encString(m.user)}, nil)
	authTLV := encString(m.authParams)
	privTLV := encString(m.privParams)
	inner := len(prefix) + len(authTLV) + len(privTLV)
	secSeq := enc(tagSequence, prefix, authTLV, privTLV)
	secOS := encString(secSeq)
	ver := encInt(tagInteger, wireV3)
	body := len(ver) + len(global) + len(secOS) + len(data)
	msg = enc(tagSequence, ver, global, secOS, data)
	// The outer SEQUENCE's header, the version and global data, the OCTET
	// STRING's and the security SEQUENCE's headers, the parameters before
	// the MAC and the MAC's own header.
	authAt = hdrLen(body) + len(ver) + len(global) + hdrLen(len(secSeq)) + hdrLen(inner) +
		len(prefix) + hdrLen(len(m.authParams))
	return msg, authAt
}

// wireVersion is the msgVersion of a message.
func wireVersion(b []byte) (int64, error) {
	t, err := expect(b, tagSequence)
	if err != nil {
		return 0, err
	}
	v, _, err := next(t.val)
	if err != nil || v.tag != tagInteger {
		return 0, errBER
	}
	return decInt(v.val)
}

func decodeV2c(b []byte) (v2cMsg, error) {
	var m v2cMsg
	t, err := expect(b, tagSequence)
	if err != nil {
		return m, err
	}
	c, err := seqOf(t, tagInteger, tagOctetString, 0)
	if err != nil {
		return m, err
	}
	if v, err := decInt(c[0].val); err != nil || v != wireV2c {
		return m, errBER
	}
	m.community = c[1].val
	m.pdu, err = decPDU(c[2])
	return m, err
}

// decodeV3 reads a v3 message; authAt is the offset in b of the
// msgAuthenticationParameters contents (for the MAC check).
func decodeV3(b []byte) (m v3Msg, authAt int, err error) {
	t, err := expect(b, tagSequence)
	if err != nil {
		return m, 0, err
	}
	c, err := seqOf(t, tagInteger, tagSequence, tagOctetString, 0)
	if err != nil {
		return m, 0, err
	}
	if v, err := decInt(c[0].val); err != nil || v != wireV3 {
		return m, 0, errBER
	}
	g, err := seqOf(c[1], tagInteger, tagInteger, tagOctetString, tagInteger)
	if err != nil {
		return m, 0, err
	}
	if m.msgID, err = decInt(g[0].val); err != nil {
		return m, 0, err
	}
	if m.maxSize, err = decInt(g[1].val); err != nil {
		return m, 0, err
	}
	if len(g[2].val) != 1 {
		return m, 0, errBER
	}
	m.flags = g[2].val[0]
	if model, err := decInt(g[3].val); err != nil || model != securityUSM {
		return m, 0, errors.New("not a USM message")
	}
	st, err := expect(c[2].val, tagSequence)
	if err != nil {
		return m, 0, err
	}
	s, err := seqOf(st, tagOctetString, tagInteger, tagInteger, tagOctetString, tagOctetString, tagOctetString)
	if err != nil {
		return m, 0, err
	}
	m.engineID = s[0].val
	if m.boots, err = decInt(s[1].val); err != nil {
		return m, 0, err
	}
	if m.time, err = decInt(s[2].val); err != nil {
		return m, 0, err
	}
	m.user, m.authParams, m.privParams = s[3].val, s[4].val, s[5].val
	// Every value is a slice of b: its offset is how far its capacity
	// falls short of b's.
	authAt = cap(b) - cap(s[4].val)
	if m.flags&flagPriv != 0 {
		if c[3].tag != tagOctetString {
			return m, 0, errBER
		}
		m.encrypted = c[3].val
		return m, authAt, nil
	}
	if c[3].tag != tagSequence {
		return m, 0, errBER
	}
	err = m.decodeScoped(c[3])
	return m, authAt, err
}

// decodeScoped fills the scoped PDU from its SEQUENCE.
func (m *v3Msg) decodeScoped(t tlv) error {
	c, err := seqOf(t, tagOctetString, tagOctetString, 0)
	if err != nil {
		return err
	}
	m.contextEngineID, m.contextName = c[0].val, c[1].val
	m.pdu, err = decPDU(c[2])
	return err
}

// decryptScoped decrypts m.encrypted (the plaintext may carry padding
// after the SEQUENCE, which is ignored) and fills the scoped PDU.
func (m *v3Msg) decryptScoped(privKey []byte) error {
	plain, err := aesCFB(false, privKey, m.boots, m.time, m.privParams, m.encrypted)
	if err != nil {
		return err
	}
	t, _, err := next(plain)
	if err != nil || t.tag != tagSequence {
		return errDecrypt
	}
	if err := m.decodeScoped(t); err != nil {
		return errDecrypt
	}
	return nil
}

var errDecrypt = errors.New("the answer could not be decrypted (wrong privacy passphrase?)")

// macOK reports whether b, a message whose authentication parameters are
// at authAt, carries the right MAC for key.
func macOK(a authAlg, key, b []byte, authAt int, got []byte) bool {
	if len(got) != a.macLen || authAt < 0 || authAt+a.macLen > len(b) {
		return false
	}
	zeroed := bytes.Clone(b)
	clear(zeroed[authAt : authAt+a.macLen])
	return hmac.Equal(mac(a, key, zeroed), got)
}
