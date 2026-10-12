package devssh

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// Framing is how NETCONF messages are delimited on the channel (RFC 6242).
// A hello is always end-of-message framed; the framing in force afterwards
// is chosen by the capabilities both sides advertise.
type Framing int

// The framings. FramingEOM (base:1.0, the ']]>]]>' delimiter) is the
// default: the lab switch (Junos 25.4) speaks it, and the client advertises
// base:1.0 only. FramingChunked advertises base:1.1 and requires it of the
// device; FramingAuto advertises both and follows the device.
const (
	FramingEOM Framing = iota
	FramingChunked
	FramingAuto
)

// The capability URIs of the framings.
const (
	CapBase10 = "urn:ietf:params:netconf:base:1.0"
	CapBase11 = "urn:ietf:params:netconf:base:1.1"
)

// The RPC bodies the Junos readers use; the body of an RPC is the XML
// inside <rpc>.
const (
	// RPCGetConfigurationSet is get-configuration as 'display set' text
	// (the reply is a <configuration-set> element).
	RPCGetConfigurationSet = `<get-configuration format="set"/>`
	nsBase                 = "urn:ietf:params:xml:ns:netconf:base:1.0"
	eom                    = "]]>]]>"
)

// CommandRPC is the Junos <command> RPC for a CLI command (the reply is a
// <configuration-output> element for a configuration command).
func CommandRPC(cmd string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(cmd))
	return `<command format="text">` + b.String() + `</command>`
}

// NetconfOption changes how NETCONF opens a session.
type NetconfOption func(*netconfConfig)

type netconfConfig struct{ framing Framing }

// WithFraming selects the framing (FramingEOM when not given).
func WithFraming(f Framing) NetconfOption { return func(c *netconfConfig) { c.framing = f } }

// NetconfSession is a NETCONF session after the hello exchange. RPC may be
// called any number of times in sequence; calls are serialised.
type NetconfSession interface {
	// Capabilities are the capability URIs of the device's hello, in the
	// order it sent them.
	Capabilities() []string
	// RPC sends body inside an <rpc> element and returns the complete
	// <rpc-reply> document. The body must be well-formed XML and must not
	// hold the end-of-message delimiter; the reply must carry the message
	// id sent. A reply with an error-severity <rpc-error> is returned with
	// an RPCError (the session stays open). When ctx ends the session is
	// closed and the error is ErrTimeout or context.Canceled; if it ends
	// while a write is blocked on the device the whole client is closed
	// (a Client is one device's job and its context the job's deadline).
	RPC(ctx context.Context, body string) (string, error)
	// Close sends <close-session/> when no RPC is in flight (best effort)
	// and closes the channel; it never waits for an RPC.
	Close() error
}

// NETCONF opens the 'netconf' subsystem and exchanges hellos within the
// connect timeout. A device that refuses the subsystem is ErrNoSubsystem; a
// device that does not send a hello in time is ErrTimeout, one that ends
// the channel first is ErrClosed, a hello that is not one or offers no
// usable framing is ErrProtocol. As for every call of a Client, a timeout
// that fires while the channel is being opened closes the client.
func (c *Client) NETCONF(opts ...NetconfOption) (NetconfSession, error) {
	cfg := netconfConfig{framing: FramingEOM}
	for _, o := range opts {
		o(&cfg)
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()

	var ch ssh.Channel
	err := c.within(ctx, func() error {
		cc, reqs, err := c.conn.OpenChannel("session", nil)
		if err != nil {
			return closedError(err)
		}
		go ssh.DiscardRequests(reqs)
		ok, err := cc.SendRequest("subsystem", true, ssh.Marshal(struct{ Subsystem string }{"netconf"}))
		if err != nil {
			_ = cc.Close()
			return closedError(err)
		}
		if !ok {
			_ = cc.Close()
			return fmt.Errorf("%w: %s", ErrNoSubsystem, c.addr)
		}
		ch = cc
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := newSink()
	go func() { _, err := io.Copy(out, ch); out.close(err) }()
	go func() { _, _ = io.Copy(io.Discard, ch.Stderr()) }()

	n := &netconf{c: c, ch: ch, out: out, next: 1}
	unhook := context.AfterFunc(ctx, func() { _ = ch.Close() })
	err = n.hello(ctx, cfg.framing)
	unhook()
	if err != nil {
		_ = ch.Close()
		return nil, err
	}
	return n, nil
}

type netconf struct {
	c   *Client
	ch  ssh.Channel
	out *sink
	// caps is set by the hello, before the session is returned.
	caps []string

	mu      sync.Mutex // serialises RPC; guards the fields below
	fr      framer
	chunked bool
	next    int

	broken atomic.Bool
}

// helloDoc is a device hello.
type helloDoc struct {
	XMLName      xml.Name `xml:"hello"`
	Capabilities []string `xml:"capabilities>capability"`
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
	// first (RFC 6241 section 8.1).
	if err := n.c.write(ctx, n.ch, []byte(b.String()+eom)); err != nil {
		return err
	}
	raw, err := n.readFrame(ctx)
	if err != nil {
		return err
	}
	var h helloDoc
	if err := decodeXML(raw, &h); err != nil {
		return fmt.Errorf("%w: the device's hello is not a hello", ErrProtocol)
	}
	n.caps = h.Capabilities
	has := func(c string) bool {
		for _, x := range h.Capabilities {
			if x == c {
				return true
			}
		}
		return false
	}
	switch f {
	case FramingEOM:
		if !has(CapBase10) {
			return fmt.Errorf("%w: the device does not offer base:1.0 framing", ErrProtocol)
		}
	case FramingChunked:
		if !has(CapBase11) {
			return fmt.Errorf("%w: the device does not offer base:1.1 framing", ErrProtocol)
		}
		n.chunked = true
	default:
		n.chunked = has(CapBase11)
		if !n.chunked && !has(CapBase10) {
			return fmt.Errorf("%w: the device offers no known framing", ErrProtocol)
		}
	}
	n.fr.chunked = n.chunked
	return nil
}

func (n *netconf) Capabilities() []string { return append([]string(nil), n.caps...) }

// rpcDoc is the part of a reply RPC reads.
type rpcDoc struct {
	XMLName xml.Name
	ID      string `xml:"message-id,attr"`
	Errors  []struct {
		Severity string `xml:"error-severity"`
		Tag      string `xml:"error-tag"`
		Message  string `xml:"error-message"`
	} `xml:"rpc-error"`
}

// checkBody refuses an RPC body that would break the message out of its
// frame or its <rpc> element: the end-of-message delimiter, or anything
// that is not well-formed XML on its own.
func checkBody(body string) error {
	if strings.Contains(body, eom) {
		return errors.New("devssh: an rpc body must not hold the end-of-message delimiter")
	}
	d := xml.NewDecoder(strings.NewReader("<body>" + body + "</body>"))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	for {
		_, err := d.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("devssh: an rpc body must be well-formed XML")
		}
	}
}

func (n *netconf) RPC(ctx context.Context, body string) (string, error) {
	if err := checkBody(body); err != nil {
		return "", err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.broken.Load() {
		return "", fmt.Errorf("%w: %s", ErrClosed, n.c.addr)
	}
	if err := n.c.ctxErr(); err != nil {
		return "", err
	}
	if ctx.Err() != nil {
		return "", callError(ctx, n.c)
	}
	id := strconv.Itoa(n.next)
	n.next++
	msg := `<rpc xmlns="` + nsBase + `" message-id="` + id + `">` + body + `</rpc>`
	// The call's context closes the channel; an abandoned RPC leaves its
	// reply in the stream, so the session is not reused after it.
	unhook := context.AfterFunc(ctx, func() { _ = n.ch.Close() })
	defer unhook()
	fail := func(err error) (string, error) {
		_ = n.ch.Close()
		n.broken.Store(true)
		return "", err
	}
	if err := n.c.write(ctx, n.ch, n.frame(msg)); err != nil {
		return fail(err)
	}
	for {
		raw, err := n.readFrame(ctx)
		if err != nil {
			return fail(err)
		}
		var d rpcDoc
		if err := decodeXML(raw, &d); err != nil {
			return fail(fmt.Errorf("%w: the reply is not XML", ErrProtocol))
		}
		switch d.XMLName.Local {
		case "notification":
			continue
		case "rpc-reply":
		default:
			return fail(fmt.Errorf("%w: unexpected <%s> for an rpc", ErrProtocol, sanitize(d.XMLName.Local)))
		}
		if d.ID != id {
			return fail(fmt.Errorf("%w: the reply does not carry message id %s", ErrProtocol, id))
		}
		reply := string(raw)
		for _, e := range d.Errors {
			if e.Severity == "" || e.Severity == "error" {
				return reply, RPCError{Severity: "error", Tag: sanitize(e.Tag), Message: sanitize(strings.TrimSpace(e.Message))}
			}
		}
		return reply, nil
	}
}

// frame wraps a message in the framing in force.
func (n *netconf) frame(msg string) []byte {
	if n.chunked {
		return []byte("\n#" + strconv.Itoa(len(msg)) + "\n" + msg + "\n##\n")
	}
	return []byte(msg + eom)
}

// closeBound is how long Close waits for the best-effort close-session to
// be written before it closes the channel under it.
const closeBound = 250 * time.Millisecond

// Close never blocks behind the device: close-session is written from a
// goroutine and waited for at most closeBound (a device that does not read
// has a full window), and the channel is closed whatever came of it. An
// RPC in flight is ended by the close.
func (n *netconf) Close() error {
	if !n.broken.Load() && n.mu.TryLock() {
		msg := `<rpc xmlns="` + nsBase + `" message-id="` + strconv.Itoa(n.next) + `"><close-session/></rpc>`
		frame := n.frame(msg)
		done := make(chan struct{})
		go func() {
			_, _ = n.ch.Write(frame)
			n.mu.Unlock()
			close(done)
		}()
		t := time.NewTimer(closeBound)
		select {
		case <-done:
		case <-t.C:
		}
		t.Stop()
	}
	err := n.ch.Close()
	n.broken.Store(true)
	return err
}

// readFrame returns the next message from the framer, feeding it from the
// channel.
func (n *netconf) readFrame(ctx context.Context) ([]byte, error) {
	for {
		msg, ok, err := n.fr.next()
		if err != nil {
			return nil, err
		}
		if ok {
			return msg, nil
		}
		ch := n.out.take()
		if ch.overflow {
			return nil, ErrOutputTooLarge
		}
		if err := n.fr.push(ch.data); err != nil {
			return nil, err
		}
		if len(ch.data) > 0 {
			continue
		}
		if ch.closed {
			if err := n.c.ctxErr(); err != nil {
				return nil, err
			}
			if err := contextError(ctx, n.c.addr); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %s", ErrClosed, n.c.addr)
		}
		if err := n.out.wait(ctx); err != nil {
			return nil, callError(ctx, n.c)
		}
	}
}

// framer splits the byte stream into messages (RFC 6242), keeping its
// place between reads so a large message is parsed once, not once per
// chunk of it.
type framer struct {
	buf     []byte // received, not yet consumed
	chunked bool
	scan    int    // end-of-message framing: buf[:scan] holds no delimiter
	out     []byte // chunked framing: the chunks of the message so far
}

// push adds received bytes; a message that would pass MaxOutput is an
// error.
func (f *framer) push(p []byte) error {
	if len(f.buf)+len(f.out)+len(p) > MaxOutput {
		return ErrOutputTooLarge
	}
	f.buf = append(f.buf, p...)
	return nil
}

// next returns the next complete message, if the buffer holds one.
func (f *framer) next() (msg []byte, ok bool, err error) {
	if !f.chunked {
		i := bytes.Index(f.buf[f.scan:], []byte(eom))
		if i < 0 {
			// A delimiter may start in the last bytes.
			f.scan = max(f.scan, len(f.buf)-len(eom)+1)
			return nil, false, nil
		}
		i += f.scan
		msg = bytes.TrimSpace(f.buf[:i])
		f.buf = f.buf[i+len(eom):]
		f.scan = 0
		return msg, true, nil
	}
	for {
		b := f.buf
		if len(b) < 3 {
			return nil, false, nil
		}
		if b[0] != '\n' || b[1] != '#' {
			return nil, false, fmt.Errorf("%w: bad chunk header", ErrProtocol)
		}
		if b[2] == '#' {
			// '##\n' ends the message.
			if len(b) < 4 {
				return nil, false, nil
			}
			if b[3] != '\n' {
				return nil, false, fmt.Errorf("%w: bad end-of-chunks", ErrProtocol)
			}
			msg = f.out
			f.out, f.buf = nil, b[4:]
			return msg, true, nil
		}
		nl := bytes.IndexByte(b[2:], '\n')
		if nl < 0 {
			if len(b)-2 > 10 {
				return nil, false, fmt.Errorf("%w: bad chunk size", ErrProtocol)
			}
			return nil, false, nil
		}
		size, perr := strconv.ParseUint(string(b[2:2+nl]), 10, 32)
		if perr != nil || size == 0 || nl > 10 {
			return nil, false, fmt.Errorf("%w: bad chunk size", ErrProtocol)
		}
		if size > MaxOutput || uint64(len(f.out))+size > MaxOutput {
			return nil, false, ErrOutputTooLarge
		}
		start := 2 + nl + 1
		if uint64(len(b)-start) < size {
			return nil, false, nil
		}
		f.out = append(f.out, b[start:start+int(size)]...)
		f.buf = b[start+int(size):]
	}
}

// decodeXML unmarshals one document; any charset label is accepted (a
// device that says us-ascii sends ASCII, a subset of UTF-8).
func decodeXML(raw []byte, v any) error {
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	return d.Decode(v)
}

// ReplyText is the text of a configuration or command reply: the character
// data of its <configuration-output>, <configuration-set>,
// <configuration-text> or <output> elements wherever they sit in the reply
// (Junos wraps a command's <configuration-output> in a
// <configuration-information> element), concatenated (the XML escapes are
// undone). It is an error for a reply to hold none of them.
func ReplyText(reply string) (string, error) {
	d := xml.NewDecoder(strings.NewReader(reply))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var b strings.Builder
	found := false
	depth := 0 // nesting level inside a text element, 0 outside
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("%w: the reply is not XML", ErrProtocol)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case depth > 0:
				depth++
			case isReplyTextElement(t.Name.Local):
				depth, found = 1, true
			}
		case xml.EndElement:
			if depth > 0 {
				depth--
			}
		case xml.CharData:
			if depth > 0 {
				b.Write(t)
			}
		}
	}
	if !found {
		return "", fmt.Errorf("%w: the reply holds no text", ErrProtocol)
	}
	return b.String(), nil
}

func isReplyTextElement(name string) bool {
	switch name {
	case "configuration-output", "configuration-set", "configuration-text", "output":
		return true
	}
	return false
}
