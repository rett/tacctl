package devssh_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// ncScript is a device whose 'netconf' subsystem does what the script says:
// the hello of a Junos device as a hand-run subsystem request prints it, in
// the ways a real channel delivers it.
type ncScript struct {
	banner     string        // the pre-auth banner
	pieces     []string      // the writes of the device's hello
	pause      time.Duration // between two pieces
	delay      time.Duration // before the first piece
	afterHello bool          // wait for the client's hello before writing
	closeAfter bool          // close the channel after the last piece
	refuse     bool          // refuse the subsystem
	trailer    string        // written when the client's side of the channel ends
}

// helloText is the hello of the device, from its two comment lines to the
// delimiter, with the capability URIs in the form the device sends them
// (urn:ietf:params:xml:ns:netconf:..., form "ns") or in the RFC 6241 form
// (urn:ietf:params:netconf:..., form "rfc").
func helloText(form string) string {
	s := `<!-- No zombies were killed during the creation of this user interface -->
<!-- user alice, class j-example-class -->
<hello>
  <capabilities>
    <capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:confirmed-commit:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:validate:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:url:1.0?protocol=http,ftp,file</capability>
    <capability>http://xml.juniper.net/netconf/junos/1.0</capability>
    <capability>http://xml.juniper.net/dmi/system/1.0</capability>
  </capabilities>
  <session-id>29751</session-id>
</hello>
]]>]]>
`
	if form == "rfc" {
		s = strings.ReplaceAll(s, "urn:ietf:params:xml:ns:netconf:", "urn:ietf:params:netconf:")
	}
	return s
}

// chunks cuts s into pieces of n bytes.
func chunks(s string, n int) []string {
	var out []string
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	return append(out, s)
}

// start runs the device and returns a Target for it.
func (d *ncScript) start(t *testing.T) devssh.Target {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{}
	if d.banner != "" {
		cfg.BannerCallback = func(ssh.ConnMetadata) string { return d.banner }
	}
	cfg.PasswordCallback = func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if string(pw) == fakedev.DefaultPassword {
			return nil, nil
		}
		return nil, errors.New("denied")
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	quit := make(chan struct{})
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = nc.Close() }()
				go func() { <-quit; _ = nc.Close() }()
				d.serve(nc, cfg)
			}()
		}
	}()
	t.Cleanup(func() { close(quit); _ = ln.Close(); wg.Wait() })
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return devssh.Target{
		Host: host, Port: p, User: fakedev.DefaultUser,
		HostKeys: []string{fakedev.KeyText(signer.PublicKey())}, ConnectTimeout: 5 * time.Second,
		Password: func() (string, error) { return fakedev.DefaultPassword, nil },
	}
}

func (d *ncScript) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newc := range chans {
		ch, rq, err := newc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range rq {
				if r.Type != "subsystem" {
					_ = r.Reply(false, nil)
					continue
				}
				_ = r.Reply(!d.refuse, nil)
				if !d.refuse {
					go d.netconf(ch)
				}
			}
		}()
	}
}

func (d *ncScript) netconf(ch ssh.Channel) {
	var got []byte
	one := make([]byte, 1)
	if d.afterHello {
		for !strings.Contains(string(got), "]]>]]>") {
			if _, err := ch.Read(one); err != nil {
				return
			}
			got = append(got, one[0])
		}
	}
	time.Sleep(d.delay)
	for i, p := range d.pieces {
		if i > 0 {
			time.Sleep(d.pause)
		}
		_, _ = io.WriteString(ch, p)
	}
	if d.closeAfter {
		_ = ch.Close()
		return
	}
	// Whatever the client sends is read until its side of the channel ends;
	// then the device says goodbye, as a Junos device does.
	_, _ = io.Copy(io.Discard, ch)
	_, _ = io.WriteString(ch, d.trailer)
	_ = ch.Close()
}

// openHello dials the device and opens its NETCONF session.
func openHello(t *testing.T, tg devssh.Target) (devssh.NetconfSession, error) {
	t.Helper()
	cl, err := devssh.Dial(context.Background(), tg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl.NETCONF()
}

// The hello of a Junos device in every way its bytes can arrive: whichever
// of them the client reads, with the capability URIs in the device's form
// and in the RFC's, is a hello with the device's capabilities.
func TestNetconfJunosHelloVariants(t *testing.T) {
	t.Parallel()
	whole := func(s string) []string { return []string{s} }
	// A pause of 5 ms between pieces makes them separate reads of the
	// channel (a real timer, only to make the pieces arrive apart).
	const gap = 5 * time.Millisecond
	cases := []struct {
		name string
		mk   func(form string) *ncScript
	}{
		{"immediately", func(f string) *ncScript { return &ncScript{pieces: whole(helloText(f))} }},
		{"after the client hello", func(f string) *ncScript {
			return &ncScript{pieces: whole(helloText(f)), afterHello: true}
		}},
		{"small chunks", func(f string) *ncScript {
			return &ncScript{pieces: chunks(helloText(f), 7), pause: gap}
		}},
		{"split mid-comment, mid-tag and in the delimiter", func(f string) *ncScript {
			s := helloText(f)
			var ps []string
			for _, cut := range []string{"zombies were", "<capab", "ities>", "]]>"} {
				i := strings.Index(s, cut)
				ps = append(ps, s[:i+len(cut)/2])
				s = s[i+len(cut)/2:]
			}
			return &ncScript{pieces: append(ps, s), pause: gap}
		}},
		{"CRLF line endings", func(f string) *ncScript {
			return &ncScript{pieces: whole(strings.ReplaceAll(helloText(f), "\n", "\r\n"))}
		}},
		{"capabilities indented and wrapped", func(f string) *ncScript {
			s := strings.ReplaceAll(helloText(f), "<capability>", "<capability>\n        ")
			s = strings.ReplaceAll(s, "</capability>", "\n      </capability>")
			return &ncScript{pieces: whole(s)}
		}},
		{"a trailing comment after the delimiter", func(f string) *ncScript {
			return &ncScript{pieces: whole(helloText(f) + "<!-- session end at 2026-11-05 10:00:00 UTC -->\n")}
		}},
		{"the session-end comment when the client's side ends", func(f string) *ncScript {
			return &ncScript{pieces: whole(helloText(f)), trailer: "<!-- session end at 2026-11-05 10:00:00 UTC -->\n"}
		}},
		{"a long pre-auth banner", func(f string) *ncScript {
			return &ncScript{pieces: whole(helloText(f)),
				banner: strings.Repeat("*  This system is for authorised use only.            *\n", 25)}
		}},
		{"the channel closed right after the hello", func(f string) *ncScript {
			return &ncScript{pieces: whole(helloText(f)), closeAfter: true}
		}},
		{"an xml declaration", func(f string) *ncScript {
			return &ncScript{pieces: whole(`<?xml version="1.0" encoding="us-ascii"?>` + "\n" + helloText(f))}
		}},
		{"the namespace declared", func(f string) *ncScript {
			s := strings.Replace(helloText(f), "<hello>", `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">`, 1)
			return &ncScript{pieces: whole(s)}
		}},
		{"a prefixed namespace", func(f string) *ncScript {
			s := strings.Replace(helloText(f), "<hello>", `<nc:hello xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">`, 1)
			s = strings.Replace(s, "</hello>", "</nc:hello>", 1)
			return &ncScript{pieces: whole(s)}
		}},
		{"a banner line before the comments", func(f string) *ncScript {
			return &ncScript{pieces: whole("Welcome to example-sw1\n" + helloText(f))}
		}},
		{"a UTF-8 byte order mark", func(f string) *ncScript {
			return &ncScript{pieces: whole("\xef\xbb\xbf" + helloText(f))}
		}},
		{"a stray prompt and hash text", func(f string) *ncScript {
			return &ncScript{pieces: whole("# \nalice@example-sw1> \n" + helloText(f))}
		}},
		{"text with an ampersand and a bracket before the hello", func(f string) *ncScript {
			return &ncScript{pieces: whole("R&D <alice@example-sw1>\n" + helloText(f))}
		}},
		{"a comment that names a hello after text with an ampersand", func(f string) *ncScript {
			return &ncScript{pieces: whole("R&D <alice@sw1>\n<!-- <hello> is next -->\n" + helloText(f))}
		}},
		{"a comment that holds a whole hello before the real one", func(f string) *ncScript {
			return &ncScript{pieces: whole("R&D <alice@sw1>\n<!-- <hello><capabilities></capabilities></hello> -->\n" + helloText(f))}
		}},
	}
	for _, c := range cases {
		for _, form := range []string{"ns", "rfc"} {
			t.Run(c.name+"/"+form, func(t *testing.T) {
				t.Parallel()
				ns, err := openHello(t, c.mk(form).start(t))
				if err != nil {
					t.Fatalf("NETCONF: %v", err)
				}
				defer func() { _ = ns.Close() }()
				caps := ns.Capabilities()
				if len(caps) != 7 || caps[0] != devssh.CapBase10 ||
					caps[1] != "urn:ietf:params:netconf:capability:candidate:1.0" ||
					caps[2] != "urn:ietf:params:netconf:capability:confirmed-commit:1.0" ||
					caps[5] != "http://xml.juniper.net/netconf/junos/1.0" {
					t.Errorf("capabilities = %q", caps)
				}
			})
		}
	}
}

// A hello that is none, or that offers no framing the client speaks, is
// ErrProtocol, and says why and what the device sent.
func TestNetconfHelloRefusalsExplainThemselves(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("0123456789", 30)
	cases := []struct {
		name   string
		sent   string
		reason string // a part of the reason
		shown  string // a part of the reason: what the device sent
	}{
		{"an rpc-error", `<rpc-error><error-severity>error</error-severity><error-message>no service</error-message></rpc-error>]]>]]>`,
			"<rpc-error>", "no service"},
		{"plain text", "Permission denied\r\n]]>]]>", "not a hello", "Permission denied"},
		{"control characters and newlines", "bad\x1b[31m\nline\x00]]>]]>", "not a hello", "bad?[31m?line?"},
		{"long text is cut", long + "]]>]]>", "not a hello", long[:120]},
		{"no base:1.0", `<hello><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>]]>]]>`,
			"does not offer base:1.0", "base:1.1"},
		{"a hello nested in a reply", `<rpc-reply><rpc-error><error-message>no service</error-message></rpc-error><hello><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello></rpc-reply>]]>]]>`,
			"not a hello", "no service"},
		{"a hello nested in text and a reply", `R&D <rpc-reply><hello><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello></rpc-reply>]]>]]>`,
			"not a hello", "R&D"},
		{"a hello only in a comment", `R&D <!-- <hello><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello> -->]]>]]>`,
			"not a hello", "R&D"},
		{"no capabilities", `<hello><session-id>1</session-id></hello>]]>]]>`, "does not offer base:1.0", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := openHello(t, (&ncScript{pieces: []string{c.sent}}).start(t))
			if !errors.Is(err, devssh.ErrProtocol) {
				t.Fatalf("err = %v, want ErrProtocol", err)
			}
			why := devssh.NetconfWhy(err)
			if !strings.Contains(why, c.reason) || !strings.Contains(why, c.shown) {
				t.Errorf("why = %q, want %q and %q", why, c.reason, c.shown)
			}
			if strings.ContainsAny(why, "\r\n\x00\x1b") || len(why) > 260 {
				t.Errorf("why = %q: not one clean line, or too long", why)
			}
			if c.name == "long text is cut" && strings.Contains(why, long[:121]) {
				t.Errorf("why holds more than 120 bytes of the device's text: %q", why)
			}
		})
	}
}

// The channel that closes without a hello, the device that answers late and
// the hello without its delimiter say so.
func TestNetconfNoHelloExplainsItself(t *testing.T) {
	t.Parallel()
	t.Run("closed after the subsystem was accepted", func(t *testing.T) {
		t.Parallel()
		_, err := openHello(t, (&ncScript{closeAfter: true}).start(t))
		if !errors.Is(err, devssh.ErrClosed) {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
		if why := devssh.NetconfWhy(err); !strings.Contains(why, "channel closed after the subsystem was accepted") {
			t.Errorf("why = %q", why)
		}
	})
	t.Run("too late", func(t *testing.T) {
		t.Parallel()
		// A real timer: the hello comes 2 s after the subsystem, the client
		// waits 300 ms (the connect timeout).
		tg := (&ncScript{pieces: []string{helloText("ns")}, delay: 2 * time.Second}).start(t)
		tg.ConnectTimeout = 300 * time.Millisecond
		_, err := openHello(t, tg)
		if !errors.Is(err, devssh.ErrTimeout) {
			t.Fatalf("err = %v, want ErrTimeout", err)
		}
		if why := devssh.NetconfWhy(err); !strings.Contains(why, "no hello") {
			t.Errorf("why = %q", why)
		}
	})
	t.Run("late but in time", func(t *testing.T) {
		t.Parallel()
		// A real timer: a hello 1.2 s after the subsystem, inside a timeout
		// of 5 s.
		ns, err := openHello(t, (&ncScript{pieces: []string{helloText("ns")}, delay: 1200 * time.Millisecond}).start(t))
		if err != nil {
			t.Fatal(err)
		}
		_ = ns.Close()
	})
	t.Run("a hello without its delimiter, then the end", func(t *testing.T) {
		t.Parallel()
		_, err := openHello(t, (&ncScript{pieces: []string{"<hello><capabilities>"}, closeAfter: true}).start(t))
		if !errors.Is(err, devssh.ErrClosed) {
			t.Fatalf("err = %v, want ErrClosed", err)
		}
		if why := devssh.NetconfWhy(err); !strings.Contains(why, "<hello><capabilities>") {
			t.Errorf("why = %q: it does not show what the device sent", why)
		}
	})
	t.Run("a refused subsystem is not a hello problem", func(t *testing.T) {
		t.Parallel()
		if _, err := openHello(t, (&ncScript{refuse: true}).start(t)); !errors.Is(err, devssh.ErrNoSubsystem) {
			t.Fatalf("err = %v", err)
		}
	})
}
