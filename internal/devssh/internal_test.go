package devssh

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsPasswordPrompt(t *testing.T) {
	for p, want := range map[string]bool{
		"Password: ":                            true,
		"password:":                             true,
		"alice@192.0.2.1's password: ":          true,
		"Password for alice: ":                  true,
		"Enter password:":                       true,
		"New password: ":                        false,
		"Retype new password: ":                 false,
		"Verification code: ":                   false,
		"Username: ":                            false,
		"Old password:":                         false,
		"Enter one-time password: ":             false,
		"Token password:":                       false,
		"Password (OTP):":                       false,
		"Enter your PIN password:":              false,
		"Passcode:":                             false,
		"Password verification code:":           false,
		"OneTimePassword:":                      false,
		"OTPPassword:":                          false,
		"Enter RSA SecurID password:":           false,
		"MFA password:":                         false,
		"2FA Password:":                         false,
		"Password (2FA):":                       false,
		"Second factor password:":               false,
		"Enter your token password:":            false,
		"(user@host) Password:":                 true,
		"alice@newyork.example.net's password:": true,
		"Password for olduser:":                 true,
		"":                                      false,
	} {
		if got := IsPasswordPrompt(p); got != want {
			t.Errorf("IsPasswordPrompt(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestPromptDetectors(t *testing.T) {
	cases := []struct {
		vendor, line string
		want         bool
	}{
		{VendorJuniper, "gotest@sw1> ", true},
		{VendorJuniper, "gotest@sw1# ", false},
		{VendorJuniper, "gotest@sw1>", false},
		{VendorJuniper, "set system host-name x", false},
		{VendorCisco, "rtr1#", true},
		{VendorCisco, "rtr1>", true},
		{VendorCisco, "rtr1(config)#", true},
		{VendorCisco, "rtr1# ", false},
		{VendorCisco, "ip access-list standard TACCTL-MGMT", false},
		{VendorCisco, " description uplink > core", false},
	}
	for _, c := range cases {
		if got := profiles[c.vendor].prompt.MatchString(c.line); got != c.want {
			t.Errorf("%s detector on %q = %v, want %v", c.vendor, c.line, got, c.want)
		}
	}
}

func TestPagerIsAnchored(t *testing.T) {
	for line, want := range map[string]bool{
		" --More-- ":                 true,
		"--More--":                   true,
		"---(more)---":               true,
		"---(more 12%)---":           true,
		"more of this":               false,
		"-- Moreover --":             false,
		"banner motd --More--":       false,
		"description x ---(more)---": false,
	} {
		if got := rePager.MatchString(line); got != want {
			t.Errorf("pager on %q = %v, want %v", line, got, want)
		}
	}
}

func TestSkipErase(t *testing.T) {
	for _, c := range []struct {
		in, rest string
		state    int
	}{
		{"\b\b\b   \b\b\bnext", "next", 0},
		{"next", "next", 0},
		{" indented", " indented", 0}, // no backspace: nothing was erased
		{"\b\b  ", "", 3},             // split across reads
		{"\b  \b\b x", " x", 0},
	} {
		got, st := skipErase([]byte(c.in), 1)
		if string(got) != c.rest || st != c.state {
			t.Errorf("skipErase(%q) = %q, %d; want %q, %d", c.in, got, st, c.rest, c.state)
		}
	}
	// Backspaces in the output itself are left alone.
	if got, _ := skipErase([]byte("a\bb"), 0); string(got) != "a\bb" {
		t.Errorf("state 0 changed the data: %q", got)
	}
}

func TestOutBufCountsPromptLines(t *testing.T) {
	o := outBuf{prev: -1, prompt: "rtr#"}
	o.add([]byte("show x\r\nrtr#\r\n{master:0}\r\nrtr#"))
	o.add([]byte("rtr#"))
	if len(o.hits) != 1 || o.hits[0].start != len("show x\r\n") {
		t.Fatalf("hits %+v", o.hits)
	}
	// One complete line, the tail twice over (an echo-less answer).
	if got := o.prompts(); got != 3 {
		t.Errorf("prompts() = %d, want 3", got)
	}
	if tl, ok := o.tail(); !ok || tl != "rtr#rtr#" {
		t.Errorf("tail %q %v", tl, ok)
	}
	long := outBuf{prev: -1, prompt: "rtr#"}
	long.add([]byte(strings.Repeat("x", maxPromptLine+1)))
	if _, ok := long.tail(); ok {
		t.Error("a line longer than a prompt must not be examined")
	}
}

func TestPromptUnitAndRepeats(t *testing.T) {
	det := profiles[VendorCisco].prompt
	for line, want := range map[string]string{
		"rtr1#":       "rtr1#",
		"rtr1#rtr1#":  "rtr1#",
		"rtr1>":       "rtr1>",
		"##########":  "##",
		"banner line": "",
		"":            "",
	} {
		if got := promptUnit(line, det); got != want {
			t.Errorf("promptUnit(%q) = %q, want %q", line, got, want)
		}
	}
	jdet := profiles[VendorJuniper].prompt
	if got := promptUnit("u@h> u@h> ", jdet); got != "u@h> " {
		t.Errorf("junos unit = %q", got)
	}
	if repeats("rtr#rtr#", "rtr#") != 2 || repeats("rtr#x", "rtr#") != 0 || repeats("", "rtr#") != 0 {
		t.Error("repeats")
	}
}

func TestStripEcho(t *testing.T) {
	for _, c := range []struct{ body, cmd, want string }{
		{"show version\nline1\nline2\n", "show version", "line1\nline2\n"},
		{"line1\nline2\n", "show version", "line1\nline2\n"},
		{"show version\n", "show version", ""},
		{"  show version \nx\n", "show version", "x\n"},
	} {
		if got := stripEcho(c.body, c.cmd); got != c.want {
			t.Errorf("stripEcho(%q, %q) = %q, want %q", c.body, c.cmd, got, c.want)
		}
	}
}

// feed pushes data in pieces of n bytes and returns the messages.
func feed(t *testing.T, f *framer, data string, n int) ([]string, error) {
	t.Helper()
	var out []string
	for len(data) > 0 {
		k := min(n, len(data))
		if err := f.push([]byte(data[:k])); err != nil {
			return out, err
		}
		data = data[k:]
		for {
			msg, ok, err := f.next()
			if err != nil {
				return out, err
			}
			if !ok {
				break
			}
			out = append(out, string(msg))
		}
	}
	return out, nil
}

func TestFramerEOM(t *testing.T) {
	for _, n := range []int{1, 3, 100} {
		var f framer
		got, err := feed(t, &f, "  <a/>\n]]>]]>\n<b/>]]>]]>", n)
		if err != nil || len(got) != 2 || got[0] != "<a/>" || got[1] != "<b/>" {
			t.Errorf("piece %d: %q %v", n, got, err)
		}
	}
}

func TestFramerChunked(t *testing.T) {
	const whole = "\n#4\n<a/>\n#5\n<b></\n#3\nb>\n\n##\n"
	for _, n := range []int{1, 2, 7, 100} {
		f := framer{chunked: true}
		got, err := feed(t, &f, whole+whole, n)
		if err != nil || len(got) != 2 || got[0] != "<a/><b></b>\n" || got[1] != got[0] {
			t.Errorf("piece %d: %q %v", n, got, err)
		}
	}
	for _, bad := range []string{"x#4\nabcd", "\n#0\n", "\n#zz\n", "\n#99999999999\n", "\n##x"} {
		f := framer{chunked: true}
		if _, err := feed(t, &f, bad, 100); !errors.Is(err, ErrProtocol) {
			t.Errorf("%q: err = %v, want ErrProtocol", bad, err)
		}
	}
	f := framer{chunked: true}
	if _, err := feed(t, &f, "\n#"+strconv.Itoa(MaxOutput+1)+"\n", 100); !errors.Is(err, ErrOutputTooLarge) {
		t.Errorf("a chunk past MaxOutput: %v", err)
	}
}

// A large message arriving in small pieces is parsed in linear time: the
// framer does not rescan or recopy what it has seen.
func TestFramerLinear(t *testing.T) {
	msg := strings.Repeat("x", 8<<20)
	for name, data := range map[string]string{
		"eom":     msg + eom,
		"chunked": "\n#" + strconv.Itoa(len(msg)) + "\n" + msg + "\n##\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := framer{chunked: name == "chunked"}
			start := time.Now()
			got, err := feed(t, &f, data, 512)
			if err != nil || len(got) != 1 || len(got[0]) != len(msg) {
				t.Fatalf("%d messages, err %v", len(got), err)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("took %v", d)
			}
		})
	}
}

func TestSinkOverflow(t *testing.T) {
	s := newSink()
	_, _ = s.Write(make([]byte, MaxOutput))
	if c := s.take(); c.overflow || len(c.data) != MaxOutput {
		t.Fatalf("a full buffer is not an overflow: %d %v", len(c.data), c.overflow)
	}
	_, _ = s.Write(make([]byte, MaxOutput))
	_, _ = s.Write([]byte("x"))
	if c := s.take(); !c.overflow {
		t.Fatal("more than MaxOutput must overflow")
	}
}

func TestSinkWait(t *testing.T) {
	s := newSink()
	go func() { _, _ = s.Write([]byte("x")) }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.wait(ctx); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := s.wait(ctx2); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func newMemo(src PasswordSource) *passwordMemo {
	return &passwordMemo{src: src, ctx: context.Background()}
}

func TestPasswordMemoOnce(t *testing.T) {
	var calls atomic.Int32
	m := newMemo(func() (string, error) { calls.Add(1); return "pw", nil })
	// A keyboard-interactive exchange: a password prompt, an unknown one.
	ans, err := m.challenge("", "", []string{"Password: ", "Code: "}, []bool{false, false})
	if err != nil || ans[0] != "pw" || ans[1] != "" {
		t.Fatalf("answers %q err %v", ans, err)
	}
	// A retry round gets nothing, and the password method is refused.
	ans, err = m.challenge("", "", []string{"Password: "}, []bool{false})
	if err != nil || ans[0] != "" {
		t.Fatalf("retry answers %q err %v", ans, err)
	}
	if _, err := m.plain(); !errors.Is(err, errPasswordUsed) {
		t.Fatalf("plain after challenge: %v", err)
	}
	if calls.Load() != 1 || m.sent() != 1 {
		t.Fatalf("source called %d times, password sent %d times", calls.Load(), m.sent())
	}
	// The memo keeps no copy once the password is sent.
	if m.value != "" || m.src != nil {
		t.Errorf("the memo still holds the password or the source: %q", m.value)
	}
	// A password prompt that echoes is never answered with the password.
	m2 := newMemo(func() (string, error) { return "pw", nil })
	if ans, _ := m2.challenge("", "", []string{"Password: "}, []bool{true}); ans[0] != "" || m2.sent() != 0 {
		t.Fatal("answered an echoing prompt")
	}
	// Neither is an OTP prompt.
	m3 := newMemo(func() (string, error) { return "pw", nil })
	if ans, _ := m3.challenge("", "", []string{"Enter one-time password: "}, []bool{false}); ans[0] != "" || m3.sent() != 0 {
		t.Fatal("answered a one-time password prompt")
	}
}

// A blocking source does not hold the memo's lock, and a wait for it ends
// with the context.
func TestPasswordMemoBlockingSource(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &passwordMemo{ctx: ctx, src: func() (string, error) { close(entered); <-release; return "pw", nil }}
	done := make(chan error, 1)
	go func() { _, err := m.use(); done <- err }()
	// The accessors answer while the source blocks: the source is known to
	// be in it, and the context is not ended yet.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the source was never called")
	}
	if m.sent() != 0 || m.srcErr() != nil {
		t.Fatal("state changed before the source answered")
	}
	select {
	case err := <-done:
		t.Fatalf("use returned before the context ended: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want the cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("use did not return when the context ended")
	}
	close(release)
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":             "plain text",
		"a\x1b[31mred\x1b[0m":    "a?[31mred?[0m",
		"line\nbreak\r":          "line?break?",
		"bidi \u202eevil":        "bidi ?evil",
		"c1 \u0085 \u009b":       "c1 ? ?",
		"nul\x00":                "nul?",
		"unicode \u00e9":         "unicode \u00e9",
		strings.Repeat("x", 500): strings.Repeat("x", maxErrText) + "...",
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckCommand(t *testing.T) {
	for _, bad := range []string{"a\nb", "a\rb", "a\tb", "a\x1bb", "a\x00b", "a\x7fb", "a\u0085b", "a\x03"} {
		if checkCommand(bad) == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	for _, ok := range []string{"show configuration | display set", "show interfaces ge-0/0/0 \u00e9"} {
		if err := checkCommand(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func TestCheckBody(t *testing.T) {
	for _, ok := range []string{"<get-configuration format=\"set\"/>", CommandRPC("show a | b < c"), "<a/><b/>", ""} {
		if err := checkBody(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"<a/>" + eom + "<rpc/>", "</rpc><rpc>", "<a>", "<a></b>", "<a b=c/>", "<?xml version='1.0'?><a/></x>",
	} {
		if checkBody(bad) == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

func TestErrHostKeyText(t *testing.T) {
	e := ErrHostKey{}
	if !e.Unpinned() || !strings.Contains(e.Error(), "no host key is pinned") {
		t.Errorf("unpinned: %q", e.Error())
	}
	e = ErrHostKey{Offered: "ssh-ed25519 AAAA", Fingerprint: "SHA256:abc", Pinned: []string{"ssh-ed25519 BBBB"}}
	if e.Unpinned() || !strings.Contains(e.Error(), "ssh-ed25519 SHA256:abc") {
		t.Errorf("mismatch: %q", e.Error())
	}
}
