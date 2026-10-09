package snmp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

// RFC 3414 A.3.2: "maplesyrup" and engine ID 00...02 with SHA-1; the
// SHA-256 pair is the same procedure (RFC 7860 4.2.2 points back to A.2),
// computed independently with Python's hashlib.
func TestKeyLocalisation(t *testing.T) {
	engine, _ := hex.DecodeString("000000000000000000000002")
	for _, c := range []struct{ auth, ku, kul string }{
		{AuthSHA, "9fb5cc0381497b3793528939ff788d5d79145211", "6695febc9288e36282235fc7151f128497b38f3f"},
		{AuthSHA256, "ab51014d1e077f6017df2b12bee5f5aa72993177e9bb569c4dff5a4ca0b4afac",
			"8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"},
	} {
		a, err := authOf(c.auth)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(passwordToKey(a, "maplesyrup")); got != c.ku {
			t.Errorf("%s Ku = %s, want %s", c.auth, got, c.ku)
		}
		kul, err := LocalizedKey(c.auth, "maplesyrup", engine)
		if err != nil || hex.EncodeToString(kul) != c.kul {
			t.Errorf("%s Kul = %x (%v), want %s", c.auth, kul, err, c.kul)
		}
	}
	if _, err := LocalizedKey("md5", "maplesyrup", engine); err == nil {
		t.Error("md5 accepted")
	}
	if _, err := LocalizedKey(AuthSHA, "", engine); err == nil {
		t.Error("an empty passphrase accepted")
	}
}

func TestBERIntegers(t *testing.T) {
	for _, c := range []struct {
		v    int64
		want string
	}{
		{0, "020100"}, {127, "02017f"}, {128, "02020080"}, {255, "020200ff"}, {256, "02020100"},
		{-1, "0201ff"}, {-128, "020180"}, {-129, "0202ff7f"}, {2147483647, "02047fffffff"},
	} {
		b := encInt(tagInteger, c.v)
		if hex.EncodeToString(b) != c.want {
			t.Errorf("encInt(%d) = %x, want %s", c.v, b, c.want)
		}
		x, err := expect(b, tagInteger)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := decInt(x.val); err != nil || got != c.v {
			t.Errorf("decInt(%x) = %d %v", b, got, err)
		}
	}
}

func TestBEROIDsAndLengths(t *testing.T) {
	b, err := encOID(SysNameOID)
	if err != nil || hex.EncodeToString(b) != "06082b06010201010500" {
		t.Fatalf("sysName.0 = %x %v", b, err)
	}
	for _, oid := range []string{SysNameOID, "1.3.6.1.6.3.15.1.1.4.0", "1.3.6.1.4.1.2636.3.1.2.0", "2.999.3", "0.0"} {
		b, err := encOID(oid)
		if err != nil {
			t.Fatal(oid, err)
		}
		x, _ := expect(b, tagOID)
		if got, err := decOID(x.val); err != nil || got != oid {
			t.Errorf("%s round trip: %s %v", oid, got, err)
		}
	}
	for _, bad := range []string{"1", "3.1", "1.40", "1.x.2", ""} {
		if _, err := encOID(bad); err == nil {
			t.Errorf("encOID(%q) accepted", bad)
		}
	}
	// Long form lengths.
	for _, n := range []int{0, 127, 128, 255, 256, 65535, 70000} {
		v := bytes.Repeat([]byte{'x'}, n)
		x, err := expect(encString(v), tagOctetString)
		if err != nil || !bytes.Equal(x.val, v) {
			t.Errorf("length %d: %v", n, err)
		}
	}
	// Truncated and overlong input.
	for _, bad := range []string{"", "04", "0405616263", "048100", "0485ffffffffff", "1f0100"} {
		b, _ := hex.DecodeString(bad)
		if _, _, err := next(b); err == nil && bad != "048100" {
			t.Errorf("next(%s) accepted", bad)
		}
	}
}

func TestBERMessagesRoundTrip(t *testing.T) {
	p := pdu{tag: tagGetResponse, requestID: 1234567, varbinds: []varbind{
		{oid: SysNameOID, value: tlv{tag: tagOctetString, val: []byte("sw1.site-a.example")}}}}
	b, err := v2cMsg{community: []byte("public"), pdu: p}.encode()
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodeV2c(b)
	if err != nil || string(m.community) != "public" || m.pdu.requestID != 1234567 || m.pdu.tag != tagGetResponse ||
		len(m.pdu.varbinds) != 1 || m.pdu.varbinds[0].oid != SysNameOID || string(m.pdu.varbinds[0].value.val) != "sw1.site-a.example" {
		t.Errorf("v2c round trip: %+v %v", m, err)
	}
	if v, _ := wireVersion(b); v != wireV2c {
		t.Errorf("version %d", v)
	}
	// v3, in the clear, with the MAC offset pointing at the parameters.
	v3 := v3Msg{msgID: 99, maxSize: maxMsgSize, flags: flagAuth | flagReportable, engineID: []byte{0x80, 0, 0, 9, 3},
		boots: 3, time: 100000, user: []byte("alice"), authParams: bytes.Repeat([]byte{0xab}, 12),
		privParams: []byte{}, contextEngineID: []byte{1}, pdu: p}
	scoped, err := v3.scopedPDU()
	if err != nil {
		t.Fatal(err)
	}
	enc, at := v3.encode(scoped)
	if !bytes.Equal(enc[at:at+12], v3.authParams) {
		t.Fatalf("authAt %d does not point at the MAC", at)
	}
	back, at2, err := decodeV3(enc)
	if err != nil || at2 != at || back.msgID != 99 || back.boots != 3 || back.time != 100000 || string(back.user) != "alice" ||
		back.pdu.requestID != 1234567 || string(back.pdu.varbinds[0].value.val) != "sw1.site-a.example" {
		t.Errorf("v3 round trip: %+v at %d %v", back, at2, err)
	}
	// AES-CFB is its own inverse with the same parameters.
	key := bytes.Repeat([]byte{7}, 20)
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ct, _ := aesCFB(true, key, 3, 100, salt, scoped)
	pt, _ := aesCFB(false, key, 3, 100, salt, ct)
	if !bytes.Equal(pt, scoped) || bytes.Equal(ct, scoped) {
		t.Error("AES-CFB round trip")
	}
}

// startAgent runs a on 127.0.0.1 and returns its port.
func startAgent(t *testing.T, a *Agent) int {
	t.Helper()
	conn, err := a.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func fast(c Config) Config {
	c.Timeout = 300 * time.Millisecond
	c.Retries = 1
	return c
}

func TestV2cAgainstTheAgent(t *testing.T) {
	a := &Agent{SysName: "sw1.site-a.example", Community: "c0mmunity"}
	port := startAgent(t, a)
	ctx := context.Background()
	name, err := fast(Config{Version: V2c, Port: port, Community: "c0mmunity"}).SysName(ctx, "127.0.0.1")
	if err != nil || name != "sw1.site-a.example" {
		t.Fatalf("SysName = %q, %v", name, err)
	}
	// A wrong community is dropped: a timeout, after one retry.
	before := a.Requests.Load()
	_, err = fast(Config{Version: V2c, Port: port, Community: "wrong"}).SysName(ctx, "127.0.0.1")
	var te *TimeoutError
	if !errors.As(err, &te) || te.Tries != 2 {
		t.Errorf("wrong community: %v", err)
	}
	if n := a.Requests.Load() - before; n != 2 {
		t.Errorf("wrong community: %d requests, want 2 (one retry)", n)
	}
	// Another object is noSuchObject.
	if _, err := fast(Config{Version: V2c, Port: port, Community: "c0mmunity"}).Get(ctx, "127.0.0.1", "1.3.6.1.2.1.1.1.0"); err == nil {
		t.Error("noSuchObject read as a value")
	}
}

// sysLocation.0 over v2c and v3, set and empty.
func TestSysLocationAgainstTheAgent(t *testing.T) {
	ctx := context.Background()
	a := &Agent{SysName: "sw1", SysLocation: "Site A, row 3", Community: "c0mmunity"}
	port := startAgent(t, a)
	c := fast(Config{Version: V2c, Port: port, Community: "c0mmunity"})
	if loc, err := c.SysLocation(ctx, "127.0.0.1"); err != nil || loc != "Site A, row 3" {
		t.Fatalf("v2c SysLocation = %q, %v", loc, err)
	}
	if _, err := fast(Config{Version: V2c, Port: port, Community: "wrong"}).SysLocation(ctx, "127.0.0.1"); err == nil {
		t.Error("wrong community answered")
	}
	empty := &Agent{SysName: "sw2", Community: "c0mmunity"}
	port = startAgent(t, empty)
	if loc, err := fast(Config{Version: V2c, Port: port, Community: "c0mmunity"}).SysLocation(ctx, "127.0.0.1"); err != nil || loc != "" {
		t.Errorf("empty SysLocation = %q, %v", loc, err)
	}
	v3 := &Agent{SysName: "rtr1", SysLocation: "Site B", User: "alice", AuthPass: "auth-passphrase", PrivPass: "priv-passphrase", Auth: AuthSHA, Boots: 2}
	port = startAgent(t, v3)
	c3 := fast(Config{Version: V3, Port: port, User: "alice", AuthPass: "auth-passphrase", PrivPass: "priv-passphrase", Auth: AuthSHA, Priv: PrivAES128})
	if loc, err := c3.SysLocation(ctx, "127.0.0.1"); err != nil || loc != "Site B" {
		t.Errorf("v3 SysLocation = %q, %v", loc, err)
	}
}

func TestNoAgentIsATimeout(t *testing.T) {
	// A port nothing listens on: refused reads count as silence.
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	start := time.Now()
	_, err = fast(Config{Version: V2c, Port: port, Community: "x"}).SysName(context.Background(), "127.0.0.1")
	var te *TimeoutError
	if !errors.As(err, &te) {
		t.Fatalf("no agent: %v", err)
	}
	if d := time.Since(start); d < 500*time.Millisecond {
		t.Errorf("gave up after %v; want the two tries waited out", d)
	}
	if want := "no answer (2 tries, 300ms each)"; err.Error() != want {
		t.Errorf("text %q", err)
	}
}

func TestV3AgainstTheAgent(t *testing.T) {
	for _, auth := range []string{AuthSHA, AuthSHA256} {
		t.Run(auth, func(t *testing.T) {
			a := &Agent{SysName: "rtr1.site-b.example", User: "alice", AuthPass: "auth-passphrase", PrivPass: "priv-passphrase", Auth: auth, Boots: 4}
			port := startAgent(t, a)
			ctx := context.Background()
			c := fast(Config{Version: V3, Port: port, User: "alice", AuthPass: "auth-passphrase", PrivPass: "priv-passphrase", Auth: auth, Priv: PrivAES128})
			name, err := c.SysName(ctx, "127.0.0.1")
			if err != nil || name != "rtr1.site-b.example" {
				t.Fatalf("SysName = %q, %v", name, err)
			}
			report := func(c Config, want string) {
				t.Helper()
				_, err := c.SysName(ctx, "127.0.0.1")
				var re *ReportError
				if !errors.As(err, &re) || re.Name != want {
					t.Errorf("want %s, got %v", want, err)
				}
			}
			u := c
			u.User = "bob"
			report(u, "unknownUserName")
			w := c
			w.AuthPass = "another-passphrase"
			report(w, "wrongDigest")
			p := c
			p.PrivPass = "another-passphrase"
			report(p, "decryptionError")
			other := AuthSHA256
			if auth == AuthSHA256 {
				other = AuthSHA
			}
			x := c
			x.Auth = other
			report(x, "wrongDigest")
		})
	}
}

func TestV3NotInTimeWindowIsRetried(t *testing.T) {
	a := &Agent{SysName: "sw2", User: "alice", AuthPass: "auth-passphrase", PrivPass: "priv-passphrase", Auth: AuthSHA, Boots: 1}
	port := startAgent(t, a)
	c := fast(Config{Version: V3, Port: port, User: "alice", AuthPass: "auth-passphrase", PrivPass: "priv-passphrase", Auth: AuthSHA})
	// The discovery report says boots 1; bump the agent's boots after it,
	// so the request is out of the window once and corrected once.
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	eng, err := c.discover(context.Background(), conn)
	if err != nil || eng.boots != 1 {
		t.Fatalf("discover: %+v %v", eng, err)
	}
	a.SetBoots(2)
	alg, _ := authOf(AuthSHA)
	ak, _ := LocalizedKey(AuthSHA, "auth-passphrase", eng.id)
	pk, _ := LocalizedKey(AuthSHA, "priv-passphrase", eng.id)
	_, fresh, err := c.getAuthPriv(context.Background(), conn, SysNameOID, alg, ak, pk, eng)
	var re *ReportError
	if !errors.As(err, &re) || re.Name != "notInTimeWindow" || fresh == nil || fresh.boots != 2 {
		t.Fatalf("notInTimeWindow: %v %+v", err, fresh)
	}
	v, _, err := c.getAuthPriv(context.Background(), conn, SysNameOID, alg, ak, pk, *fresh)
	if err != nil || string(v.val) != "sw2" {
		t.Errorf("after the window was corrected: %q %v", v.val, err)
	}
}

func TestReportErrorText(t *testing.T) {
	if got := (&ReportError{Name: "unknownUserName"}).Error(); got != "unknownUserName (the agent has no such user)" {
		t.Error(got)
	}
	if got := (&ReportError{Name: "report 1.2.3"}).Error(); got != "the agent sent a report (report 1.2.3)" {
		t.Error(got)
	}
}
