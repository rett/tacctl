package snmp

// The BER of the few ASN.1 types one GetRequest and its GetResponse (or
// Report) use (X.690, RFC 3416): INTEGER, OCTET STRING, NULL, OBJECT
// IDENTIFIER, SEQUENCE, the PDU tags and the exceptions and counters a
// varbind can hold. Definite lengths only, as SNMP requires.

import (
	"errors"
	"strconv"
	"strings"
)

// The tags.
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagSequence    = 0x30
	tagCounter32   = 0x41
	tagGetRequest  = 0xa0
	tagGetResponse = 0xa2
	tagReport      = 0xa8
	// The varbind exceptions (RFC 3416 3).
	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82
)

var errBER = errors.New("malformed BER")

// tlv is one decoded element: its tag and its contents.
type tlv struct {
	tag byte
	val []byte
}

// encLength is a definite length.
func encLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for ; n > 0; n >>= 8 {
		b = append([]byte{byte(n)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

// enc is one element: tag, length and the contents (concatenated).
func enc(tag byte, parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := append([]byte{tag}, encLength(n)...)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// encInt is an INTEGER (or another integer-encoded tag): the shortest
// two's complement.
func encInt(tag byte, v int64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		if (v >= -128 && v < 128) || len(b) == 8 {
			break
		}
		v >>= 8
	}
	return enc(tag, b)
}

func encString(s []byte) []byte { return enc(tagOctetString, s) }

func encNull() []byte { return []byte{tagNull, 0} }

// encOID is an OBJECT IDENTIFIER from its dotted text.
func encOID(oid string) ([]byte, error) {
	arcs, err := parseOID(oid)
	if err != nil {
		return nil, err
	}
	var b []byte
	for _, a := range append([]uint32{arcs[0]*40 + arcs[1]}, arcs[2:]...) {
		var sub []byte
		sub = append(sub, byte(a&0x7f))
		for a >>= 7; a > 0; a >>= 7 {
			sub = append([]byte{byte(a&0x7f) | 0x80}, sub...)
		}
		b = append(b, sub...)
	}
	return enc(tagOID, b), nil
}

func parseOID(oid string) ([]uint32, error) {
	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	if len(parts) < 2 {
		return nil, errors.New("invalid OID " + oid)
	}
	arcs := make([]uint32, len(parts))
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, errors.New("invalid OID " + oid)
		}
		arcs[i] = uint32(n)
	}
	if arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) {
		return nil, errors.New("invalid OID " + oid)
	}
	return arcs, nil
}

// decOID is the dotted text of an OBJECT IDENTIFIER's contents.
func decOID(b []byte) (string, error) {
	if len(b) == 0 {
		return "", errBER
	}
	var arcs []string
	first := true
	var v uint64
	for i, c := range b {
		v = v<<7 | uint64(c&0x7f)
		if v > 1<<32 {
			return "", errBER
		}
		if c&0x80 != 0 {
			if i == len(b)-1 {
				return "", errBER
			}
			continue
		}
		if first {
			x, y := v/40, v%40
			if x > 2 {
				x, y = 2, v-80
			}
			arcs = append(arcs, strconv.FormatUint(x, 10), strconv.FormatUint(y, 10))
			first = false
		} else {
			arcs = append(arcs, strconv.FormatUint(v, 10))
		}
		v = 0
	}
	return strings.Join(arcs, "."), nil
}

// decInt is the value of an integer's contents.
func decInt(b []byte) (int64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, errBER
	}
	v := int64(int8(b[0]))
	for _, c := range b[1:] {
		v = v<<8 | int64(c)
	}
	return v, nil
}

// next reads one element from b; rest is what follows it.
func next(b []byte) (t tlv, rest []byte, err error) {
	if len(b) < 2 {
		return t, nil, errBER
	}
	t.tag = b[0]
	if t.tag&0x1f == 0x1f {
		return t, nil, errBER // multi-byte tags: not in SNMP
	}
	n, i := int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(b) < 2+k {
			return t, nil, errBER
		}
		n = 0
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		i = 2 + k
	}
	if n < 0 || len(b)-i < n {
		return t, nil, errBER
	}
	t.val = b[i : i+n]
	return t, b[i+n:], nil
}

// children reads the elements of a constructed value.
func children(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		t, rest, err := next(b)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		b = rest
	}
	return out, nil
}

// expect reads the one element of b, which must have tag and be all of b.
func expect(b []byte, tag byte) (tlv, error) {
	t, rest, err := next(b)
	if err != nil {
		return t, err
	}
	if t.tag != tag || len(rest) != 0 {
		return t, errBER
	}
	return t, nil
}

// seqOf reads a constructed element's children, checking their tags (0:
// any).
func seqOf(t tlv, tags ...byte) ([]tlv, error) {
	c, err := children(t.val)
	if err != nil {
		return nil, err
	}
	if len(c) != len(tags) {
		return nil, errBER
	}
	for i, want := range tags {
		if want != 0 && c[i].tag != want {
			return nil, errBER
		}
	}
	return c, nil
}

// --- PDUs -----------------------------------------------------------------------

// pdu is a GetRequest, GetResponse or Report.
type pdu struct {
	tag         byte
	requestID   int64
	errorStatus int64
	errorIndex  int64
	varbinds    []varbind
}

// varbind is one name and its value: tag and contents.
type varbind struct {
	oid   string
	value tlv
}

// encPDU is a PDU; a varbind with a zero value tag carries NULL.
func encPDU(p pdu) ([]byte, error) {
	var vbs [][]byte
	for _, vb := range p.varbinds {
		o, err := encOID(vb.oid)
		if err != nil {
			return nil, err
		}
		v := encNull()
		if vb.value.tag != 0 {
			v = enc(vb.value.tag, vb.value.val)
		}
		vbs = append(vbs, enc(tagSequence, o, v))
	}
	return enc(p.tag, encInt(tagInteger, p.requestID), encInt(tagInteger, p.errorStatus),
		encInt(tagInteger, p.errorIndex), enc(tagSequence, vbs...)), nil
}

// decPDU reads a PDU element.
func decPDU(t tlv) (pdu, error) {
	p := pdu{tag: t.tag}
	c, err := seqOf(t, tagInteger, tagInteger, tagInteger, tagSequence)
	if err != nil {
		return p, err
	}
	if p.requestID, err = decInt(c[0].val); err != nil {
		return p, err
	}
	if p.errorStatus, err = decInt(c[1].val); err != nil {
		return p, err
	}
	if p.errorIndex, err = decInt(c[2].val); err != nil {
		return p, err
	}
	list, err := children(c[3].val)
	if err != nil {
		return p, err
	}
	for _, l := range list {
		if l.tag != tagSequence {
			return p, errBER
		}
		pair, err := seqOf(l, tagOID, 0)
		if err != nil {
			return p, err
		}
		oid, err := decOID(pair[0].val)
		if err != nil {
			return p, err
		}
		p.varbinds = append(p.varbinds, varbind{oid: oid, value: pair[1]})
	}
	return p, nil
}
