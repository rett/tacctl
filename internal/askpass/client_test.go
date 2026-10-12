package askpass

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseEnv(t *testing.T) {
	tok := strings.Repeat("ab12", 16)
	for _, c := range []struct {
		in   string
		path string
		err  error
	}{
		{"", "", ErrNoAgent},
		{"/run/user/1000/tacctl/ap-1-x.sock:" + tok, "/run/user/1000/tacctl/ap-1-x.sock", nil},
		{"/a/b:c.sock:" + tok, "/a/b:c.sock", nil}, // the last colon splits
		{"/run/x.sock", "", ErrBadEnv},
		{"/run/x.sock:", "", ErrBadEnv},
		{"relative/x.sock:" + tok, "", ErrBadEnv},
		{"/run/../x.sock:" + tok, "", ErrBadEnv},
		{"/run//x.sock:" + tok, "", ErrBadEnv},
		{"/run/x.sock:" + strings.ToUpper(tok), "", ErrBadEnv},
		{"/run/x.sock:" + tok[:63], "", ErrBadEnv},
		{"/run/x.sock:" + tok + "0", "", ErrBadEnv},
		{"/run/x.sock:" + strings.Repeat("g", 64), "", ErrBadEnv},
		{"/" + strings.Repeat("d", 120) + ":" + tok, "", ErrBadEnv},
		{"/run/\x00x:" + tok, "", ErrBadEnv},
	} {
		path, token, err := ParseEnv(c.in)
		if !errors.Is(err, c.err) || path != c.path || (err == nil && token != tok) {
			t.Errorf("ParseEnv(%q) = %q, %q, %v", c.in, path, token, err)
		}
	}
}

func TestIsPasswordPrompt(t *testing.T) {
	yes := []string{
		"Password:", "Password: ", "password:", "PASSWORD:", "  Password:  ",
		"admin@192.0.2.1's password:", "alice@sw1.example.net's password: ",
		"(alice@sw1.example.net) Password:", "(alice@192.0.2.1) Password: ",
		"alice@[2001:db8::1]'s password:",
	}
	no := []string{
		"", ":", "Password", "Enter passphrase for key '/home/u/.ssh/id_ed25519':",
		"Enter passphrase for /home/u/.ssh/id_rsa:",
		"Are you sure you want to continue connecting (yes/no/[fingerprint])?",
		"The authenticity of host 'sw1 (192.0.2.1)' can't be established.\nED25519 key fingerprint is SHA256:xyz.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ",
		"Enter PIN for 'PIV_II':", "Verification code:", "One-time password:",
		"New password:", "Old password:", "Retype new password:", "Password for admin:",
		"Password:\nAre you sure", "Password: Password:", "(alice) Password again:",
		"alice's password:", "a b@host's password:", "(a b) Password:", "() Password:",
		"Please type 'yes', 'no' or the fingerprint:",
		"Password:" + strings.Repeat(" x", 200),
		"Permission denied, please try again.",
		"Confirm user presence for key ED25519-SK SHA256:abc",
	}
	for _, s := range yes {
		if !IsPasswordPrompt(s) {
			t.Errorf("rejected %q", s)
		}
	}
	for _, s := range no {
		if IsPasswordPrompt(s) {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestRunHelper(t *testing.T) {
	r := newRig(t, nil)
	env := r.a.Env()
	_ = r.a.Store([]byte("s3cret pw"))

	// Not in flight: nothing printed.
	var out bytes.Buffer
	if err := RunHelper(bg, env, "Password:", &out); !errors.Is(err, ErrNotInFlight) || out.Len() != 0 {
		t.Fatalf("outside a line: %v, %q", err, out.String())
	}
	r.a.setInFlight(true)
	out.Reset()
	if err := RunHelper(bg, env, "alice@192.0.2.1's password: ", &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "s3cret pw\n" {
		t.Fatalf("helper output %q", out.String())
	}
	// A host key question or a passphrase is never answered, and the
	// agent is not even asked: not one request reaches it.
	reqs := r.a.reqs.Load()
	if reqs == 0 {
		t.Fatal("the agent counted none of the requests so far")
	}
	for _, p := range []string{
		"Are you sure you want to continue connecting (yes/no/[fingerprint])?",
		"Enter passphrase for key '/home/u/.ssh/id':",
		"Enter PIN for 'PIV_II':",
	} {
		out.Reset()
		if err := RunHelper(bg, env, p, &out); !errors.Is(err, ErrNotPassword) || out.Len() != 0 {
			t.Fatalf("%q: %v, %q", p, err, out.String())
		}
	}
	// Nothing configured, or malformed: no connection either.
	if err := RunHelper(bg, "", "Password:", &out); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("no environment: %v", err)
	}
	if err := RunHelper(bg, "junk", "Password:", &out); !errors.Is(err, ErrBadEnv) {
		t.Fatalf("junk environment: %v", err)
	}
	if got := r.a.reqs.Load(); got != reqs {
		t.Fatalf("%d requests reached the agent for prompts that are no password prompt", got-reqs)
	}
	r.a.setInFlight(true) // a new line
	r.a.Forget(WhyCommand)
	if err := RunHelper(bg, env, "Password:", &out); !errors.Is(err, ErrEmpty) || out.Len() != 0 {
		t.Fatalf("empty cache: %v, %q", err, out.String())
	}
}

func TestSocketDir(t *testing.T) {
	uid := os.Geteuid()
	xdg, runUser, home := t.TempDir(), t.TempDir(), t.TempDir()
	save := runUserRoot
	t.Cleanup(func() { runUserRoot = save })
	runUserRoot = runUser
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if err := os.Mkdir(filepath.Join(runUser, strconv.Itoa(uid)), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := SocketDir(env(map[string]string{"XDG_RUNTIME_DIR": xdg, "HOME": home}), uid)
	if err != nil || got != filepath.Join(xdg, "tacctl") {
		t.Errorf("XDG_RUNTIME_DIR: %q, %v", got, err)
	}
	// Relative, missing and another user's XDG_RUNTIME_DIR do not count.
	for _, x := range []string{"run/user", filepath.Join(xdg, "missing"), "/"} {
		got, err = SocketDir(env(map[string]string{"XDG_RUNTIME_DIR": x, "HOME": home}), uid)
		want := filepath.Join(runUser, strconv.Itoa(uid), "tacctl")
		if x == "/" && uid == 0 {
			want = filepath.Join("/", "tacctl")
		}
		if err != nil || got != want {
			t.Errorf("XDG_RUNTIME_DIR=%q: %q, %v", x, got, err)
		}
	}
	// No runtime directory of the user's: the home fallback.
	runUserRoot = filepath.Join(runUser, "none")
	got, err = SocketDir(env(map[string]string{"HOME": home}), uid)
	if err != nil || got != filepath.Join(home, ".local", "state", "tacctl", "run") {
		t.Errorf("HOME fallback: %q, %v", got, err)
	}
	if _, err = SocketDir(env(map[string]string{"HOME": "relative"}), uid); !errors.Is(err, ErrNoDir) {
		t.Errorf("nothing usable: %v", err)
	}
	// A directory of another user is never chosen.
	if _, err = SocketDir(env(map[string]string{"XDG_RUNTIME_DIR": xdg, "HOME": home}), uid+1); !errors.Is(err, ErrNoDir) {
		t.Errorf("directories of another user: %v", err)
	}
}
