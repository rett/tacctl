package snmp

// Agent is a minimal SNMP agent that answers sysName.0, for the tests and
// for the bats suite's stub (the '_snmp-agent' command of a -tags
// testknobs build): v2c with one community (any other is dropped without
// an answer, as real agents do), and v3 with one authPriv user, with the
// discovery and the unknownUserName, wrongDigest and decryptionError
// reports of a real one. It is not a general agent: every other object is
// noSuchObject.

import (
	"bytes"
	"net"
	"sync/atomic"
	"time"
)

// Agent answers on one UDP socket.
type Agent struct {
	SysName   string
	Community string
	// The v3 user (empty: v3 requests get unknownUserName reports).
	User, AuthPass, PrivPass, Auth string
	EngineID                       []byte
	Boots                          int64
	// Requests counts the messages read (for the tests' retry checks).
	Requests atomic.Int64

	started time.Time
	boots   atomic.Int64
}

// SetBoots changes the engine's boots while it serves (a restart, as the
// time-window tests need it).
func (a *Agent) SetBoots(n int64) { a.boots.Store(n) }

// Listen binds addr ("127.0.0.1:0" for any port) and serves until the
// connection is closed; the connection is returned at once.
func (a *Agent) Listen(addr string) (*net.UDPConn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	go a.Serve(conn)
	return conn, nil
}

// Serve answers on conn until it is closed.
func (a *Agent) Serve(conn *net.UDPConn) {
	a.started = time.Now()
	a.boots.Store(a.Boots)
	if len(a.EngineID) == 0 {
		a.EngineID = []byte{0x80, 0x00, 0x1f, 0x88, 0x04, 't', 'a', 'c', 'c', 't', 'l'}
	}
	buf := make([]byte, maxMsgSize)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		a.Requests.Add(1)
		if out := a.Handle(bytes.Clone(buf[:n])); out != nil {
			_, _ = conn.WriteToUDP(out, from)
		}
	}
}

// Handle is the answer to one message (nil: none).
func (a *Agent) Handle(b []byte) []byte {
	v, err := wireVersion(b)
	if err != nil {
		return nil
	}
	switch v {
	case wireV2c:
		return a.v2c(b)
	case wireV3:
		return a.v3(b)
	}
	return nil
}

// response is the GetResponse to a GetRequest.
func (a *Agent) response(req pdu) pdu {
	out := pdu{tag: tagGetResponse, requestID: req.requestID}
	for _, vb := range req.varbinds {
		v := tlv{tag: tagNoSuchObject}
		if vb.oid == SysNameOID {
			v = tlv{tag: tagOctetString, val: []byte(a.SysName)}
		}
		out.varbinds = append(out.varbinds, varbind{oid: vb.oid, value: v})
	}
	return out
}

func (a *Agent) v2c(b []byte) []byte {
	m, err := decodeV2c(b)
	if err != nil || string(m.community) != a.Community || m.pdu.tag != tagGetRequest {
		return nil
	}
	out, _ := v2cMsg{community: m.community, pdu: a.response(m.pdu)}.encode()
	return out
}

func (a *Agent) engineTime() int64 { return int64(time.Since(a.started) / time.Second) }

// report is a Report PDU raising one usmStats counter, sent without
// authentication unless keys are given.
func (a *Agent) report(req v3Msg, counter string, authKey []byte, alg authAlg) []byte {
	var oid string
	for o, n := range usmStats {
		if n == counter {
			oid = o
		}
	}
	r := v3Msg{msgID: req.msgID, maxSize: maxMsgSize, engineID: a.EngineID, boots: a.boots.Load(), time: a.engineTime(),
		user: req.user, contextEngineID: a.EngineID,
		pdu: pdu{tag: tagReport, requestID: req.pdu.requestID,
			varbinds: []varbind{{oid: oid, value: tlv{tag: tagCounter32, val: []byte{1}}}}}}
	if authKey != nil {
		r.flags = flagAuth
		r.authParams = make([]byte, alg.macLen)
	}
	scoped, err := r.scopedPDU()
	if err != nil {
		return nil
	}
	out, at := r.encode(scoped)
	if authKey != nil {
		copy(out[at:], mac(alg, authKey, out))
	}
	return out
}

func (a *Agent) v3(b []byte) []byte {
	m, at, err := decodeV3(b)
	if err != nil {
		return nil
	}
	// Discovery: no engine ID, no user.
	if len(m.engineID) == 0 {
		return a.report(m, "unknownEngineID", nil, authAlg{})
	}
	if !bytes.Equal(m.engineID, a.EngineID) {
		return a.report(m, "unknownEngineID", nil, authAlg{})
	}
	if a.User == "" || string(m.user) != a.User {
		return a.report(m, "unknownUserName", nil, authAlg{})
	}
	if m.flags&(flagAuth|flagPriv) != flagAuth|flagPriv {
		return a.report(m, "unsupportedSecLevel", nil, authAlg{})
	}
	alg, err := authOf(a.Auth)
	if err != nil {
		return nil
	}
	authKey, _ := LocalizedKey(a.Auth, a.AuthPass, a.EngineID)
	privKey, _ := LocalizedKey(a.Auth, a.PrivPass, a.EngineID)
	if !macOK(alg, authKey, b, at, m.authParams) {
		return a.report(m, "wrongDigest", nil, authAlg{})
	}
	if d := m.time - a.engineTime(); m.boots != a.boots.Load() || d > 150 || d < -150 {
		return a.report(m, "notInTimeWindow", authKey, alg)
	}
	if err := m.decryptScoped(privKey); err != nil {
		return a.report(m, "decryptionError", nil, authAlg{})
	}
	if m.pdu.tag != tagGetRequest {
		return nil
	}
	salt := make([]byte, 8)
	_, _ = randRead(salt)
	r := v3Msg{msgID: m.msgID, maxSize: maxMsgSize, flags: flagAuth | flagPriv, engineID: a.EngineID,
		boots: a.boots.Load(), time: a.engineTime(), user: m.user, authParams: make([]byte, alg.macLen),
		privParams: salt, contextEngineID: a.EngineID, contextName: m.contextName, pdu: a.response(m.pdu)}
	scoped, err := r.scopedPDU()
	if err != nil {
		return nil
	}
	ct, err := aesCFB(true, privKey, r.boots, r.time, salt, scoped)
	if err != nil {
		return nil
	}
	out, oat := r.encode(encString(ct))
	copy(out[oat:], mac(alg, authKey, out))
	return out
}
