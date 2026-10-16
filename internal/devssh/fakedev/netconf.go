package fakedev

import (
	"bytes"
	"encoding/xml"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	nsBase = "urn:ietf:params:xml:ns:netconf:base:1.0"
	eom    = "]]>]]>"
	base10 = "urn:ietf:params:netconf:base:1.0"
	base11 = "urn:ietf:params:netconf:base:1.1"
)

// hello is the device's hello document.
func (s *Server) hello(id int) string {
	if h, ok := s.t.read("netconf.hello"); ok {
		return strings.TrimSpace(h)
	}
	var caps []string
	if s.framing != FramingChunked {
		caps = append(caps, base10)
	}
	if s.framing != FramingEOM {
		caps = append(caps, base11)
	}
	caps = append(caps,
		"urn:ietf:params:netconf:capability:candidate:1.0",
		"urn:ietf:params:netconf:capability:confirmed-commit:1.0",
		"urn:ietf:params:netconf:capability:validate:1.0",
		"urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file",
	)
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="us-ascii"?><hello xmlns="` + nsBase + `"><capabilities>`)
	for _, c := range caps {
		b.WriteString("<capability>" + c + "</capability>")
	}
	b.WriteString("</capabilities><session-id>" + strconv.Itoa(id) + "</session-id></hello>")
	return b.String()
}

// frames reads NETCONF messages off a channel.
type frames struct {
	r       io.Reader
	buf     []byte
	chunked bool
}

// next returns the next message; io.EOF at the end of the channel.
func (f *frames) next() ([]byte, error) {
	for {
		if msg, used, ok := f.split(); ok {
			f.buf = f.buf[used:]
			return msg, nil
		}
		tmp := make([]byte, 4096)
		n, err := f.r.Read(tmp)
		f.buf = append(f.buf, tmp[:n]...)
		if err != nil && n == 0 {
			return nil, err
		}
	}
}

func (f *frames) split() (msg []byte, used int, ok bool) {
	if !f.chunked {
		i := bytes.Index(f.buf, []byte(eom))
		if i < 0 {
			return nil, 0, false
		}
		return bytes.TrimSpace(f.buf[:i]), i + len(eom), true
	}
	b, pos := f.buf, 0
	var out []byte
	for {
		if len(b)-pos < 3 || b[pos] != '\n' || b[pos+1] != '#' {
			return nil, 0, false
		}
		pos += 2
		if b[pos] == '#' {
			if len(b)-pos < 2 {
				return nil, 0, false
			}
			return out, pos + 2, true
		}
		nl := bytes.IndexByte(b[pos:], '\n')
		if nl < 0 {
			return nil, 0, false
		}
		n, err := strconv.Atoi(string(b[pos : pos+nl]))
		if err != nil || n <= 0 || len(b)-(pos+nl+1) < n {
			return nil, 0, false
		}
		pos += nl + 1
		out = append(out, b[pos:pos+n]...)
		pos += n
	}
}

// netconf is the subsystem: hello exchange, then one reply per RPC. user is
// the login the configure model's session belongs to and drop closes the
// connection (the knobs of the model).
func (s *Server) netconf(ch ssh.Channel, user string, drop func()) {
	s.mu.Lock()
	id := s.logins
	s.mu.Unlock()
	hello := s.hello(id)
	if _, err := io.WriteString(ch, hello+eom); err != nil {
		return
	}
	if s.noRead {
		<-s.quit
		return
	}
	fr := &frames{r: ch}
	raw, err := fr.next()
	if err != nil {
		return
	}
	var ch0 struct {
		Caps []string `xml:"capabilities>capability"`
	}
	_ = decode(raw, &ch0)
	clientChunks := false
	for _, c := range ch0.Caps {
		clientChunks = clientChunks || c == base11
	}
	chunked := clientChunks && strings.Contains(hello, base11)
	fr.chunked = chunked
	send := func(msg string) bool {
		var out string
		if chunked {
			out = "\n#" + strconv.Itoa(len(msg)) + "\n" + msg + "\n##\n"
		} else {
			out = msg + "\n" + eom
		}
		_, err := io.WriteString(ch, out)
		return err == nil
	}
	// The configure model's session (nil when the model is off). Whatever
	// ends this loop ends it: its lock and private candidate go; a confirmed
	// commit it made and did not confirm stays pending to the window's end.
	ns := s.newNetconfSession(user, drop)
	defer ns.end()
	for {
		raw, err := fr.next()
		if err != nil {
			return
		}
		reply, end, dr := s.rpcFor(ns, raw)
		if dr == dropSilent {
			ns.end()
			ns.drop()
			return
		}
		if !send(reply) || end {
			return
		}
		if dr == dropAfterOutput {
			ns.end()
			ns.drop()
			return
		}
	}
}

// decode reads one document, whatever charset it names.
func decode(raw []byte, v any) error {
	d := xml.NewDecoder(bytes.NewReader(raw))
	d.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	return d.Decode(v)
}

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// rpcFor answers one <rpc> for a session of the configure model (ns is nil
// when it is off); end is true after <close-session/> and drop says whether
// the connection closes (dropSilent: before the reply, dropAfterOutput:
// after it).
func (s *Server) rpcFor(ns *nsession, raw []byte) (reply string, end bool, drop int) {
	var d struct {
		ID    string  `xml:"message-id,attr"`
		Inner []xnode `xml:",any"`
	}
	wrap := func(id, body string) string {
		return `<?xml version="1.0" encoding="us-ascii"?>` +
			`<rpc-reply xmlns="` + nsBase + `" xmlns:junos="http://xml.juniper.net/junos/0.0R0/junos" message-id="` + esc(id) + `">` +
			body + `</rpc-reply>`
	}
	rpcErr := func(id, tag, msg string) string {
		return wrap(id, "<rpc-error><error-type>protocol</error-type><error-tag>"+tag+
			"</error-tag><error-severity>error</error-severity><error-message>"+esc(msg)+"</error-message></rpc-error>")
	}
	if err := decode(raw, &d); err != nil || len(d.Inner) == 0 {
		return rpcErr("", "malformed-message", "not an rpc"), false, dropNone
	}
	if s.wrongID {
		d.ID = "0"
	}
	op := d.Inner[0]
	s.log("netconf:" + op.XMLName.Local)
	format := ""
	for _, a := range op.Attrs {
		if a.Name.Local == "format" {
			format = a.Value
		}
	}
	text := func(cmd, element string) string {
		out, deny, known := s.t.command(cmd)
		if !known && ns != nil {
			// the configure model answers what the transcript has no file for
			out, known = ns.command(cmd)
		}
		switch {
		case deny != "":
			return rpcErr(d.ID, "access-denied", deny)
		case !known:
			return rpcErr(d.ID, "operation-failed", "syntax error, unknown command")
		}
		body := "<" + element + ">" + esc(out) + "</" + element + ">"
		if element == "configuration-output" {
			// A Junos device wraps a command's configuration text in
			// <configuration-information>.
			body = "<configuration-information>" + body + "</configuration-information>"
		}
		return wrap(d.ID, body)
	}
	switch op.XMLName.Local {
	case "close-session":
		return wrap(d.ID, "<ok/>"), true, dropNone
	case "command":
		cmd := strings.TrimSpace(op.Text)
		if s.t.hangs(cmd) {
			<-s.quit
			return "", true, dropNone
		}
		if ns != nil {
			if ns.d.dropsBefore(cmd) {
				return "", false, dropSilent
			}
			if !ns.d.delay(cmd) {
				return "", true, dropNone
			}
		}
		if strings.HasPrefix(cmd, "show configuration") {
			return text(cmd, "configuration-output"), false, dropNone
		}
		return text(cmd, "output"), false, dropNone
	case "get-configuration":
		if ns != nil {
			if _, canned := s.t.rpcReply("get-configuration", format); !canned {
				if body, ok := ns.getConfiguration(op, format, s.t); ok {
					return wrap(d.ID, body), false, dropNone
				}
			}
		}
		switch format {
		case "set":
			return text("show configuration | display set", "configuration-set"), false, dropNone
		case "text":
			return text("show configuration", "configuration-text"), false, dropNone
		}
	}
	if body, ok := s.t.rpcReply(op.XMLName.Local, format); ok {
		return wrap(d.ID, body), false, dropNone
	}
	if ns != nil {
		if body, dr, ok := ns.configRPC(op); ok {
			return wrap(d.ID, body), false, dr
		}
	}
	return rpcErr(d.ID, "operation-not-supported", "unsupported rpc "+op.XMLName.Local), false, dropNone
}
