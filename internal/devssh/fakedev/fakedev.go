// Package fakedev is a fake network device: an SSH server on loopback that
// answers CLI commands from a transcript directory and serves a NETCONF
// subsystem (docs/plans/0.2.4-plan.md D74). Go tests dial it in-process;
// the test-build verb 'tacctl _fake-device <dir>' runs it for bats and the
// diff corpus. The layout of the directory is in transcript.go.
//
// The server is test support, not a model of a device: it authenticates one
// fixed user and password (by 'password' and by 'keyboard-interactive'),
// has a fixed, public host key unless it is given another, and listens on
// the loopback interface only. Both are well known on purpose, so a fixture
// can pin the key and a test can log in. That makes it unfit for anything
// but tests: nothing in a release build may start it (the CLI wires
// '_fake-device' behind the test-build tag, as the other knobs).
package fakedev

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// The login a server accepts unless the transcript's 'login' file or
// WithCredentials say otherwise.
const (
	DefaultUser     = "gotest"
	DefaultPassword = "fakedev-password"
)

// AuthMethod is an ssh authentication method the server offers.
type AuthMethod int

// The methods; both are offered by default.
const (
	AuthPassword AuthMethod = iota
	AuthKeyboardInteractive
)

// Framing is what the server's NETCONF speaks.
type Framing int

// The framings: base:1.0 only, base:1.1 only, or both (chunked is used
// when the client offers 1.1 too).
const (
	FramingEOM Framing = iota
	FramingChunked
	FramingBoth
)

// Stage is where a server stops answering (WithHang).
type Stage int

// The stages: after the TCP accept (no ssh banner); a session channel
// that is never confirmed; a session channel whose requests (pty, shell,
// exec, subsystem) are never answered; and after the request is
// accepted (no output, no hello, no RPC reply).
const (
	HangAccept Stage = iota
	HangChannel
	HangRequests
	HangSession
)

// hostSeed is the seed of the default host key: a fixed, public test key,
// so a fixture can pin it.
var hostSeed = sha256.Sum256([]byte("tacctl fakedev default host key"))

func defaultSigner() ssh.Signer {
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(hostSeed[:]))
	if err != nil {
		panic("fakedev: " + err.Error())
	}
	return s
}

// KeyText is a public key as devices.yaml pins it: '<type> <base64>'.
func KeyText(k ssh.PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

// HostKey is the host key of a server that was not given another, as
// KeyText writes it.
func HostKey() string { return KeyText(defaultSigner().PublicKey()) }

// Option changes a Server.
type Option func(*Server)

// WithCredentials sets the accepted user and password (over the
// transcript's 'login' file and the defaults).
func WithCredentials(user, password string) Option {
	return func(s *Server) { s.user, s.password, s.credSet = user, password, true }
}

// WithAuth restricts the offered authentication methods.
func WithAuth(methods ...AuthMethod) Option {
	return func(s *Server) { s.methods = methods }
}

// WithHostKey sets the host key (WithRandomHostKey for one nobody pinned).
func WithHostKey(k ssh.Signer) Option { return func(s *Server) { s.hostKey = k } }

// WithExtraHostKeys adds host keys of other types to the server's own (a
// device that holds an ed25519, an ecdsa and an rsa key); a client is shown
// the one its negotiated host key algorithm names.
func WithExtraHostKeys(keys ...ssh.Signer) Option {
	return func(s *Server) { s.extraKeys = append(s.extraKeys, keys...) }
}

// WithRandomHostKey gives the server a new ed25519 host key.
func WithRandomHostKey() Option {
	return func(s *Server) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic("fakedev: " + err.Error())
		}
		sg, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			panic("fakedev: " + err.Error())
		}
		s.hostKey = sg
	}
}

var (
	legacyOnce   sync.Once
	legacySigner ssh.Signer
)

// WithKeyExchanges restricts the key exchanges the server accepts (the
// SHA-1 ones are what a client needs Target.Legacy for).
func WithKeyExchanges(kex ...string) Option { return func(s *Server) { s.kex = kex } }

// WithCiphers restricts the ciphers the server accepts (the CBC ones are
// what a client needs Target.Legacy for).
func WithCiphers(ciphers ...string) Option { return func(s *Server) { s.ciphers = ciphers } }

// WithLegacy makes the server an old device: an RSA host key signed with
// SHA-1 ('ssh-rsa'), the group1-sha1 key exchange and the CBC ciphers
// aes128-cbc and 3des-cbc only, which a client negotiates only with
// Target.Legacy.
func WithLegacy() Option {
	return func(s *Server) {
		WithSHA1RSAHostKey()(s)
		s.kex = []string{ssh.InsecureKeyExchangeDH1SHA1}
		s.ciphers = []string{ssh.InsecureCipherAES128CBC, ssh.InsecureCipherTripleDESCBC}
	}
}

// WithSHA1RSAHostKey gives the server an RSA host key that signs with SHA-1
// ('ssh-rsa') only, the host key algorithm a client offers only with
// Target.Legacy.
func WithSHA1RSAHostKey() Option {
	return func(s *Server) {
		legacyOnce.Do(func() {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic("fakedev: " + err.Error())
			}
			base, err := ssh.NewSignerFromKey(k)
			if err != nil {
				panic("fakedev: " + err.Error())
			}
			as, ok := base.(ssh.AlgorithmSigner)
			if !ok {
				panic("fakedev: rsa signer is not an AlgorithmSigner")
			}
			legacySigner, err = ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoRSA})
			if err != nil {
				panic("fakedev: " + err.Error())
			}
		})
		s.hostKey = legacySigner
	}
}

// WithNetconfFraming sets the framing the NETCONF subsystem speaks
// (FramingEOM when not given).
func WithNetconfFraming(f Framing) Option { return func(s *Server) { s.framing = f } }

// WithNetconfOff makes the server refuse the netconf subsystem (as
// 'netconf.off' in the transcript does).
func WithNetconfOff() Option { return func(s *Server) { s.netconfOff = true } }

// WithNoRead makes the NETCONF subsystem stop reading after it has sent its
// hello, as a device with a stuck process does: a client's writes fill the
// window and block.
func WithNoRead() Option { return func(s *Server) { s.noRead = true } }

// WithNoExitStatus makes exec channels end without an exit status.
func WithNoExitStatus() Option { return func(s *Server) { s.noStatus = true } }

// WithWrongMessageID makes NETCONF replies carry a message id nobody sent.
func WithWrongMessageID() Option { return func(s *Server) { s.wrongID = true } }

// WithEcho sets whether a shell session echoes what it is sent (true when
// not given, as a device with a terminal does).
func WithEcho(on bool) Option { return func(s *Server) { s.echo = on } }

// WithHang stops the server answering at stage, for the timeout tests; the
// connections are held until Stop.
func WithHang(st Stage) Option { return func(s *Server) { s.hang, s.hangSet = st, true } }

// Server is a running fake device.
type Server struct {
	t         transcript
	ln        net.Listener
	user      string
	password  string
	credSet   bool
	methods   []AuthMethod
	hostKey   ssh.Signer
	extraKeys []ssh.Signer
	kex       []string
	ciphers   []string
	framing   Framing
	echo      bool

	netconfOff bool
	noStatus   bool
	noRead     bool
	wrongID    bool
	hang       Stage
	hangSet    bool

	quit chan struct{}
	wg   sync.WaitGroup

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	attempts int
	logins   int
	commands []string
	stopped  bool
}

// Serve starts a server on a loopback port with the default credentials
// and host key, answering from dir. It returns the 'host:port' to dial and
// the function that stops it. Like httptest.NewServer it panics when the
// loopback interface cannot be listened on.
func Serve(dir string) (addr string, stop func()) {
	s := New(dir)
	return s.Addr(), s.Stop
}

// New starts a server answering from dir.
func New(dir string, opts ...Option) *Server {
	s := &Server{
		t: transcript{dir: dir}, user: DefaultUser, password: DefaultPassword,
		methods: []AuthMethod{AuthPassword, AuthKeyboardInteractive},
		hostKey: defaultSigner(), echo: true,
		quit: make(chan struct{}), conns: map[net.Conn]struct{}{},
	}
	for _, o := range opts {
		o(s)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("fakedev: " + err.Error())
	}
	s.ln = ln
	s.wg.Add(1)
	go s.accept()
	return s
}

// Addr is the 'host:port' the server listens on.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// HostKey is the server's host key, as KeyText writes it.
func (s *Server) HostKey() string { return KeyText(s.hostKey.PublicKey()) }

// Attempts is how many passwords (by either method) were presented.
func (s *Server) Attempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

// Logins is how many connections authenticated.
func (s *Server) Logins() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logins
}

// Commands are the CLI commands and NETCONF RPC elements served so far, in
// order of arrival ('netconf:<element>' for an RPC).
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

func (s *Server) log(cmd string) {
	s.mu.Lock()
	s.commands = append(s.commands, cmd)
	s.mu.Unlock()
}

// Stop closes the listener and every connection and waits for the
// handlers; it may be called more than once.
func (s *Server) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	close(s.quit)
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	_ = s.ln.Close()
	s.wg.Wait()
}

// credentials are the user and password in force: the options, else the
// transcript's login file, else the defaults.
func (s *Server) credentials() (string, string) {
	if s.credSet {
		return s.user, s.password
	}
	if u, p, ok := s.t.login(); ok {
		return u, p
	}
	return s.user, s.password
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.stopped {
			s.mu.Unlock()
			_ = c.Close()
			return
		}
		s.conns[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serve(c)
	}
}

func (s *Server) config() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{MaxAuthTries: 6}
	cfg.AddHostKey(s.hostKey)
	for _, k := range s.extraKeys {
		cfg.AddHostKey(k)
	}
	if s.kex != nil {
		cfg.KeyExchanges = s.kex
	}
	if s.ciphers != nil {
		cfg.Ciphers = s.ciphers
	}
	check := func(user, pw string) bool {
		u, p := s.credentials()
		s.mu.Lock()
		s.attempts++
		s.mu.Unlock()
		return user == u && pw == p
	}
	for _, m := range s.methods {
		switch m {
		case AuthPassword:
			cfg.PasswordCallback = func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
				if check(c.User(), string(pw)) {
					return nil, nil
				}
				return nil, errors.New("denied")
			}
		case AuthKeyboardInteractive:
			cfg.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				ans, err := ch(c.User(), "", []string{"Password: "}, []bool{false})
				if err != nil {
					return nil, err
				}
				if len(ans) == 1 && check(c.User(), ans[0]) {
					return nil, nil
				}
				return nil, errors.New("denied")
			}
		}
	}
	return cfg
}

// serve is one connection.
func (s *Server) serve(c net.Conn) {
	defer s.wg.Done()
	defer func() {
		_ = c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	if s.hangSet && s.hang == HangAccept {
		<-s.quit
		return
	}
	sc, chans, reqs, err := ssh.NewServerConn(c, s.config())
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	s.mu.Lock()
	s.logins++
	s.mu.Unlock()
	go ssh.DiscardRequests(reqs)
	var sessions sync.WaitGroup
	defer sessions.Wait()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "session channels only")
			continue
		}
		if s.hangSet && s.hang == HangChannel {
			// Never confirmed, never rejected.
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		sessions.Add(1)
		go func() {
			defer sessions.Done()
			s.session(ch, creqs)
		}()
	}
}

// session answers the requests of one session channel.
func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	var work sync.WaitGroup
	defer work.Wait()
	started := false
	for r := range reqs {
		if s.hangSet && s.hang == HangRequests {
			// Never answered.
			continue
		}
		ok := false
		switch r.Type {
		case "pty-req", "env", "window-change":
			ok = true
		case "shell", "exec", "subsystem":
			if started {
				break
			}
			var run func()
			switch r.Type {
			case "shell":
				run = func() { s.shell(ch) }
			case "exec":
				var p struct{ Command string }
				if ssh.Unmarshal(r.Payload, &p) != nil {
					break
				}
				run = func() { s.exec(ch, p.Command) }
			default:
				var p struct{ Name string }
				if ssh.Unmarshal(r.Payload, &p) != nil || p.Name != "netconf" {
					break
				}
				if s.netconfOff || s.t.exists("netconf.off") {
					break
				}
				run = func() { s.netconf(ch) }
			}
			if run == nil {
				break
			}
			ok, started = true, true
			work.Add(1)
			go func() {
				defer work.Done()
				defer func() { _ = ch.Close() }()
				if s.hangSet && s.hang == HangSession {
					<-s.quit
					return
				}
				run()
			}()
		}
		if r.WantReply {
			_ = r.Reply(ok, nil)
		}
	}
}

// crlf ends lines the way a device with a terminal does.
func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

// exec answers one command and ends the channel with its status.
func (s *Server) exec(ch ssh.Channel, cmd string) {
	s.log(cmd)
	if s.t.hangs(cmd) {
		<-s.quit
		return
	}
	out, deny, known := s.t.command(cmd)
	status := uint32(0)
	switch {
	case deny != "":
		out, status = deny+"\n", 1
	case !known:
		out, status = "error: unknown command: "+strings.TrimSpace(cmd)+"\n", 1
	}
	_, _ = io.WriteString(ch, out)
	if !s.noStatus {
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	}
}

// shell is an interactive session: banner, prompt, then one command per
// line, with the paging the transcript asks for.
func (s *Server) shell(ch ssh.Channel) {
	in := bufio.NewReader(ch)
	prompt := s.t.prompt()
	if b, ok := s.t.read("banner"); ok {
		_, _ = io.WriteString(ch, crlf(b))
	}
	pageLen, junos := s.t.paging()
	for {
		if _, err := io.WriteString(ch, prompt); err != nil {
			return
		}
		line, err := in.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		if s.echo {
			_, _ = io.WriteString(ch, cmd+"\r\n")
		}
		switch cmd {
		case "":
			continue
		case "exit", "quit", "logout":
			return
		case "terminal length 0", "terminal width 0", "set cli screen-length 0", "set cli screen-width 0":
			pageLen = 0
			continue
		}
		s.log(cmd)
		if s.t.hangs(cmd) {
			<-s.quit
			return
		}
		out, deny, known := s.t.command(cmd)
		switch {
		case deny != "":
			out = deny + "\n"
		case !known:
			out = "% Unknown command: " + cmd + "\n"
		}
		if !s.page(ch, in, crlf(out), pageLen, junos) {
			return
		}
	}
}

// page writes out, stopping after every pageLen lines for a key when
// pageLen is positive. It reports whether the session goes on.
func (s *Server) page(ch ssh.Channel, in *bufio.Reader, out string, pageLen int, junos bool) bool {
	if pageLen <= 0 {
		_, err := io.WriteString(ch, out)
		return err == nil
	}
	marker, erase := " --More-- ", strings.Repeat("\b", 8)+strings.Repeat(" ", 8)+strings.Repeat("\b", 8)
	if junos {
		marker, erase = "---(more)---", strings.Repeat("\b", 12)+strings.Repeat(" ", 12)+strings.Repeat("\b", 12)
	}
	lines := strings.SplitAfter(out, "\n")
	for i := 0; i < len(lines); i += pageLen {
		end := min(i+pageLen, len(lines))
		if _, err := io.WriteString(ch, strings.Join(lines[i:end], "")); err != nil {
			return false
		}
		if end >= len(lines) || (end == len(lines)-1 && lines[end] == "") {
			break
		}
		if _, err := io.WriteString(ch, marker); err != nil {
			return false
		}
		key, err := in.ReadByte()
		if err != nil {
			return false
		}
		if _, err := io.WriteString(ch, erase); err != nil {
			return false
		}
		if key == 'q' {
			_, err := io.WriteString(ch, "\r\n")
			return err == nil
		}
	}
	return true
}
