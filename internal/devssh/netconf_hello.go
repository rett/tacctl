package devssh

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode"
)

// The prefixes of a capability URI. RFC 6241 names them
// 'urn:ietf:params:netconf:...', but a Junos device sends the XML
// namespace's prefix 'urn:ietf:params:xml:ns:netconf:...' for the same
// capabilities. The session records them in the RFC's form, so every
// comparison needs one only.
const (
	capNsPrefix  = "urn:ietf:params:xml:ns:netconf:"
	capRFCPrefix = "urn:ietf:params:netconf:"
)

// maxGot is how many bytes of what a device sent an error shows.
const maxGot = 120

// NetconfError is a NETCONF session that could not be opened, with the
// reason and what the device sent. It is its Kind (ErrProtocol, ErrClosed
// or ErrTimeout) for errors.Is; Why is its words without the Kind's.
type NetconfError struct {
	Kind   error
	Reason string
	// Detail is what the device sent or offered, cleaned of control
	// characters and cut to 120 bytes; empty when it sent nothing.
	Detail string
}

// Why is the reason and, when there is one, what the device sent: one
// line, for a caller that shows why a device gave no hello.
func (e *NetconfError) Why() string {
	if e.Detail == "" {
		return e.Reason
	}
	return e.Reason + "; " + e.Detail
}

func (e *NetconfError) Error() string { return e.Kind.Error() + ": " + e.Why() }
func (e *NetconfError) Unwrap() error { return e.Kind }

// NetconfWhy is the reason NETCONF gave no session, as one clean line: the
// reason and what the device sent for a NetconfError, the text of err
// otherwise.
func NetconfWhy(err error) string {
	var ne *NetconfError
	if errors.As(err, &ne) {
		return ne.Why()
	}
	return sanitize(err.Error())
}

// shown is the first 120 bytes of what a device sent, as one line.
func shown(raw []byte) string {
	cut := len(raw) > maxGot
	if cut {
		raw = raw[:maxGot]
	}
	var b strings.Builder
	for _, r := range string(raw) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' || r == unicode.ReplacementChar {
			r = '?'
		}
		b.WriteRune(r)
	}
	if cut {
		b.WriteString("...")
	}
	return b.String()
}

// sentDetail words what a device had sent (nothing: empty).
func sentDetail(raw []byte) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return ""
	}
	return `the device sent "` + shown(raw) + `"`
}

// helloStart is the start tag of a hello, in any prefix.
var helloStart = regexp.MustCompile(`<(?:[A-Za-z_][\w.-]*:)?hello[\s>/]`)

// helloIndex is where the first start tag of a hello is in raw outside a
// comment (a comment may name a '<hello>' without being one), or -1.
func helloIndex(raw []byte) int {
	for from := 0; from < len(raw); {
		loc := helloStart.FindIndex(raw[from:])
		if loc == nil {
			return -1
		}
		at := from + loc[0]
		// A comment that opens before the tag and ends after it holds it.
		open := bytes.LastIndex(raw[from:at], []byte("<!--"))
		if open < 0 {
			return at
		}
		open += from
		end := bytes.Index(raw[open+4:], []byte("-->"))
		if end < 0 || open+4+end+3 <= at {
			// An unterminated comment is text, not a comment; a closed one
			// ends before the tag.
			return at
		}
		from = open + 4 + end + 3
	}
	return -1
}

// decodeWhole is decodeXML for a document that is the one element v reads:
// only white space, comments and processing instructions may follow it.
func decodeWhole(raw []byte, v any) error {
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	if err := d.Decode(v); err != nil {
		return err
	}
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.Comment, xml.ProcInst:
		case xml.CharData:
			if len(bytes.TrimSpace(t)) > 0 {
				return errors.New("text after the element")
			}
		default:
			return errors.New("more than the element")
		}
	}
}

// parseHello reads a device's hello. RFC 6241 has the hello start the
// document, but a device may print comments (Junos names the user and its
// class), an XML declaration, a byte order mark, or text before it, and
// text with an '&' or a '<' is not XML; so a message that does not decode
// as a hello is read again from its first '<hello' outside a comment, and
// then the hello must be the whole rest of the message (a '<hello>' inside
// an <rpc-reply> is not the device's hello). The string is why it is none
// when it is none.
func parseHello(raw []byte) (helloDoc, string, error) {
	var h helloDoc
	if err := decodeXML(raw, &h); err == nil {
		return h, "", nil
	}
	if at := helloIndex(raw); at > 0 {
		h = helloDoc{}
		if err := decodeWhole(raw[at:], &h); err == nil {
			return h, "", nil
		}
	}
	h = helloDoc{}
	var root struct{ XMLName xml.Name }
	if decodeXML(raw, &root) == nil && root.XMLName.Local != "" && root.XMLName.Local != "hello" {
		return h, "the device's first message is <" + sanitize(root.XMLName.Local) + ">, not a hello", ErrProtocol
	}
	return h, "the device's hello is not a hello", ErrProtocol
}

// hello sends the client hello and reads the device's.
func (n *netconf) hello(ctx context.Context, f Framing) error {
	caps := []string{CapBase10}
	switch f {
	case FramingChunked:
		caps = []string{CapBase11}
	case FramingAuto:
		caps = append(caps, CapBase11)
	}
	var b strings.Builder
	b.WriteString(`<hello xmlns="` + nsBase + `"><capabilities>`)
	for _, c := range caps {
		b.WriteString("<capability>" + c + "</capability>")
	}
	b.WriteString("</capabilities></hello>")
	// A hello is sent without waiting for the device's: both sides send
	// first (RFC 6241 section 8.1). A channel the device has already ended
	// does not take it, but what the device sent before is still read.
	werr := n.c.write(ctx, n.ch, []byte(b.String()+eom))
	if werr != nil && !errors.Is(werr, ErrClosed) {
		return werr
	}
	raw, err := n.readFrame(ctx)
	if err != nil {
		switch {
		case errors.Is(err, ErrClosed):
			return &NetconfError{Kind: ErrClosed, Reason: "the channel closed after the subsystem was accepted", Detail: sentDetail(n.fr.buf)}
		case errors.Is(err, ErrTimeout):
			reason := "no hello from the device in time"
			if len(bytes.TrimSpace(n.fr.buf)) > 0 {
				reason += " (it sent text with no end-of-message delimiter)"
			}
			return &NetconfError{Kind: ErrTimeout, Reason: reason, Detail: sentDetail(n.fr.buf)}
		}
		return err
	}
	if werr != nil {
		n.broken.Store(true)
	}
	h, why, perr := parseHello(raw)
	if perr != nil {
		return &NetconfError{Kind: perr, Reason: why, Detail: sentDetail(raw)}
	}
	for _, c := range h.Capabilities {
		if c = strings.TrimSpace(c); c != "" {
			if rest, ok := strings.CutPrefix(c, capNsPrefix); ok {
				c = capRFCPrefix + rest
			}
			n.caps = append(n.caps, c)
		}
	}
	has := func(c string) bool {
		for _, x := range n.caps {
			if x == c {
				return true
			}
		}
		return false
	}
	offers := func() string {
		if len(n.caps) == 0 {
			return "it offers no capabilities"
		}
		return `it offers "` + shown([]byte(strings.Join(n.caps, " "))) + `"`
	}
	switch f {
	case FramingEOM:
		if !has(CapBase10) {
			return &NetconfError{Kind: ErrProtocol, Reason: "the device does not offer base:1.0 framing", Detail: offers()}
		}
	case FramingChunked:
		if !has(CapBase11) {
			return &NetconfError{Kind: ErrProtocol, Reason: "the device does not offer base:1.1 framing", Detail: offers()}
		}
		n.chunked = true
	default:
		n.chunked = has(CapBase11)
		if !n.chunked && !has(CapBase10) {
			return &NetconfError{Kind: ErrProtocol, Reason: "the device offers no known framing", Detail: offers()}
		}
	}
	n.fr.chunked = n.chunked
	return nil
}
