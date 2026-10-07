package snmp

// The User-based Security Model of SNMPv3 (RFC 3414), authPriv only:
// password-to-key and key localisation (RFC 3414 A.2), HMAC-SHA-96 (RFC
// 3414 7) and HMAC-SHA-256-192 (RFC 7860), and AES-128-CFB privacy (RFC
// 3826).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA-96 is what SNMPv3 'SHA' means (RFC 3414)
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

// The authentication protocols.
const (
	AuthSHA    = "sha"
	AuthSHA256 = "sha256"
)

// PrivAES128 is the one privacy protocol.
const PrivAES128 = "aes128"

// AuthProtocols and PrivProtocols are the words tacctl.yaml takes.
var (
	AuthProtocols = []string{AuthSHA, AuthSHA256}
	PrivProtocols = []string{PrivAES128}
)

// authAlg is an authentication protocol: its hash and the length of the
// MAC it sends (msgAuthenticationParameters).
type authAlg struct {
	hash   func() hash.Hash
	macLen int
}

func authOf(name string) (authAlg, error) {
	switch name {
	case AuthSHA, "":
		return authAlg{sha1.New, 12}, nil
	case AuthSHA256:
		return authAlg{sha256.New, 24}, nil
	}
	return authAlg{}, errors.New("unknown SNMPv3 authentication protocol '" + name + "' (sha or sha256)")
}

// passwordToKey is Ku: the hash of the password repeated to 1 MB (RFC 3414
// A.2.1, A.2.2).
func passwordToKey(a authAlg, password string) []byte {
	h := a.hash()
	pw := []byte(password)
	buf := make([]byte, 64)
	j := 0
	for n := 0; n < 1048576; n += 64 {
		for i := range buf {
			buf[i] = pw[j%len(pw)]
			j++
		}
		h.Write(buf)
	}
	return h.Sum(nil)
}

// localize is Kul = H(Ku || engineID || Ku) (RFC 3414 2.6).
func localize(a authAlg, ku, engineID []byte) []byte {
	h := a.hash()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	return h.Sum(nil)
}

// LocalizedKey is a passphrase's key localised to an engine: what the auth
// and priv keys of a user are on that agent.
func LocalizedKey(auth, password string, engineID []byte) ([]byte, error) {
	a, err := authOf(auth)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("empty passphrase")
	}
	return localize(a, passwordToKey(a, password), engineID), nil
}

// mac is the truncated HMAC of a whole message.
func mac(a authAlg, key, msg []byte) []byte {
	m := hmac.New(a.hash, key)
	m.Write(msg)
	return m.Sum(nil)[:a.macLen]
}

// aesIV is the IV of RFC 3826 3.1.2.1: engine boots, engine time and the
// 64-bit salt.
func aesIV(boots, time int64, salt []byte) []byte {
	iv := make([]byte, 16)
	binary.BigEndian.PutUint32(iv[0:4], uint32(boots))
	binary.BigEndian.PutUint32(iv[4:8], uint32(time))
	copy(iv[8:], salt)
	return iv
}

// aesCFB encrypts or decrypts with AES-128 in CFB-128 mode; the key is the
// first 16 bytes of the localised privacy key.
func aesCFB(encrypt bool, privKey []byte, boots, time int64, salt, data []byte) ([]byte, error) {
	if len(privKey) < 16 || len(salt) != 8 {
		return nil, errors.New("bad privacy parameters")
	}
	block, err := aes.NewCipher(privKey[:16])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	iv := aesIV(boots, time, salt)
	if encrypt {
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, data) //nolint:staticcheck // RFC 3826 is CFB
	} else {
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(out, data) //nolint:staticcheck // RFC 3826 is CFB
	}
	return out, nil
}
