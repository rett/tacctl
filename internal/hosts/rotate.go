package hosts

// 'host provisioner <name> rotate': what the command line needs of this
// package. The steps themselves (validate, create the account, prove it,
// rewrite the registry, remove the old account) are ordered by the command
// (internal/cli/host_provisioner.go); here are the pieces that talk to the
// host or to the invoking user's files:
//
//   - the scripts run through RunScript (rotate_script.go) over the ssh
//     session the rotation began with (Env.KeepOpen);
//   - the proof: a fresh login to the new account in a NEW connection (no
//     shared connection, the new account's credentials only) that reaches
//     root through sudo, and reads the host's ssh keys for the pin check;
//   - the dry run's reads (the host's sshd setting);
//   - every access to the key file, which runs as the invoking user, never
//     as root: tacctl runs as root through sudo, and a path an unprivileged
//     user names must not be read, written or even stat'ed with root's
//     rights.
//
// A password never passes through this package: --password has the
// operator type it into the host's own passwd (create script) and, in the
// proof, into ssh's and sudo's prompts on the terminal tacctl hands them.

import (
	"bytes"
	"context"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// RunRotateScript copies body to target, runs it there as root (RunScript,
// over the session KeepOpen keeps) and removes the local copy. The exit
// status is the script's, and RotateStatus is what the create script said it
// did (empty for the remove script). The script gets a terminal on the host
// even when tacctl has none (Env.HangUp), so that a lost connection hangs it
// up and its own rollback runs.
func (e *Env) RunRotateScript(ctx context.Context, target, port, identity string, body []byte) (int, RotateStatus, error) {
	f, err := TempFile()
	if err != nil {
		return 1, RotateStatus{}, err
	}
	defer func() { _ = os.Remove(f) }()
	if err := os.WriteFile(f, body, 0o600); err != nil {
		return 1, RotateStatus{}, err
	}
	sw := &statusWriter{w: e.Out.Stdout}
	orig := e.Out.Stdout
	e.Out.Stdout, e.HangUp = sw, true
	defer func() { e.Out.Stdout, e.HangUp = orig, false }()
	code, err := e.RunScript(ctx, target, port, identity, f, nil)
	return code, sw.st, err
}

// statusWriter passes everything to w unchanged and as it comes, and reads
// the create script's status lines out of it.
type statusWriter struct {
	w    io.Writer
	line []byte
	st   RotateStatus
}

func (s *statusWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	for _, b := range p[:n] {
		if b != '\n' {
			if len(s.line) < 1024 {
				s.line = append(s.line, b)
			}
			continue
		}
		if m := reStatusLine.FindStringSubmatch(strings.TrimSuffix(string(s.line), "\r")); m != nil {
			switch m[1] {
			case "origin":
				s.st.Origin = m[2]
			case "sudoers-line":
				s.st.Sudoers = m[2]
			}
		}
		s.line = s.line[:0]
	}
	return n, err
}

// TempKnownHosts writes a known_hosts file of the pinned keys of one host
// (keys are 'type base64' strings), filed under alias, in a new directory of
// its own that the invoking user's ssh can read (public keys only), and
// returns its path and the function that removes it.
func TempKnownHosts(alias string, keys []string) (path string, cleanup func(), err error) {
	dir, err := TempDir()
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o755); err != nil {
		cleanup()
		return "", nil, err
	}
	var b strings.Builder
	for _, k := range keys {
		if strings.ContainsAny(k, "\r\n") || strings.ContainsAny(alias, " \r\n") {
			cleanup()
			return "", nil, ErrFailed
		}
		b.WriteString(alias + " " + k + "\n")
	}
	path = dir + "/known_hosts"
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// --- the proof ---------------------------------------------------------------

// proofMarker precedes the user id in the proof's output, so that a prompt,
// a banner or an echo before it cannot be taken for it.
const proofMarker = "tacctl-uid="

// ProofCommand is the remote command of the proof: the id sudo gives, then
// the host's public keys. With a key the login must reach root without a
// password (sudo -n); with a password sudo asks on the terminal. The probe's
// 'sudo-password' answer is not enough: it is also what a login that cannot
// sudo at all gives.
func ProofCommand(auth string) string {
	sudo := "sudo -n id -u"
	if auth == AuthPassword {
		sudo = "sudo -p '[sudo] password for %u on %H: ' id -u"
	}
	return "u=$(" + sudo + ") || exit 7; echo " + proofMarker + "$u; cat /etc/ssh/ssh_host_*_key.pub"
}

// Login is a fresh login to prove: the new account, and how it logs in.
type Login struct {
	// Target is user@host; Port and Identity as in the registry (Identity
	// for AuthKey only).
	Target, Port, Identity string
	// Auth is AuthKey or AuthPassword.
	Auth string
	// KnownHosts is a known_hosts file with the host's pinned keys filed
	// under HostKeyAlias (TempKnownHosts): the proof's ssh then trusts those
	// keys and no others, and refuses any other host. Empty for a host with
	// nothing pinned: ssh then goes by the invoking user's own known_hosts.
	KnownHosts, HostKeyAlias string
}

// Proof is what a fresh login found.
type Proof struct {
	// Connected: ssh logged in and the command ran to its end.
	Connected bool
	// UID is what 'id -u' printed through sudo ("" when it did not run).
	UID string
	// Keys is what the login read of the host's public keys (KeysErr when
	// nothing).
	Keys    []byte
	KeysErr error
}

// ProofOptions is the option vector of the proof's ssh: none of the shared
// connection of DefaultSSHOptions (a new connection, so the proof cannot
// ride on the old account's), and the credentials of the new account only.
// It is stricter than any later login ('host sync' offers the agent's keys
// and every method the host allows; the proof one key, or the password,
// only): a proof that holds is not undone by what the real login adds.
// With knownHosts the host must have exactly the keys in that file
// (alias is its HostKeyAlias), as 'tacctl ssh' checks a pinned device.
func ProofOptions(auth, knownHosts, alias string) []string {
	opts := []string{
		"-o", "ConnectTimeout=10",
		"-o", "ControlMaster=no", "-o", "ControlPath=none",
		"-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
		"-o", "GSSAPIAuthentication=no", "-o", "HostbasedAuthentication=no",
	}
	if knownHosts != "" {
		opts = append(opts,
			"-o", "UserKnownHostsFile="+knownHosts, "-o", "GlobalKnownHostsFile=/dev/null",
			"-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias="+alias, "-o", "UpdateHostKeys=no")
	}
	if auth == AuthPassword {
		return append(opts, "-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive")
	}
	return append(opts, "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no")
}

// ProveLogin logs in to the new account in a new connection and runs
// ProofCommand. A password login needs the terminal (it is typed into ssh
// and sudo themselves); the command's output is shown as it comes, but for
// the id and the keys.
func (e *Env) ProveLogin(ctx context.Context, l Login) Proof {
	var p Proof
	s := SSH{AsUser: e.AsUser, AuthSock: e.AuthSock, Options: ProofOptions(l.Auth, l.KnownHosts, l.HostKeyAlias), Batch: !e.tty(), Port: l.Port}
	if l.Auth == AuthKey {
		s.Identity = l.Identity
	}
	var out []byte
	if l.Auth == AuthPassword {
		w := &proofWriter{out: e.Out.Stdout}
		c := s.Cmd("-o", "LogLevel=ERROR", "-t", l.Target, ProofCommand(l.Auth))
		code, _, err := Attached(ctx, e.Runner, c, e.Stdin, ui.Output{Stdout: w, Stderr: e.Out.Stderr})
		if err != nil || code != 0 {
			return p
		}
		out = w.buf.Bytes()
	} else {
		c := s.Cmd("-T", l.Target, ProofCommand(l.Auth))
		c.Stderr = e.Out.Stderr
		res, err := e.Runner.Run(ctx, c)
		if err != nil || res.Code != 0 {
			return p
		}
		out = res.Stdout
	}
	p.Connected = true
	p.UID, p.Keys = parseProof(out)
	if len(bytes.TrimSpace(p.Keys)) == 0 {
		p.Keys, p.KeysErr = nil, ErrKeysUnread
	}
	return p
}

// parseProof reads the id and the keys out of the proof's output.
func parseProof(out []byte) (uid string, keys []byte) {
	text := strings.ReplaceAll(string(out), "\r", "")
	i := strings.LastIndex(text, proofMarker)
	if i < 0 {
		return "", nil
	}
	rest := text[i+len(proofMarker):]
	line, after, _ := strings.Cut(rest, "\n")
	return strings.TrimSpace(line), []byte(after)
}

// proofWriter passes the terminal everything up to the proof marker and
// keeps all of it: the host's keys after the marker are for the pin check,
// not for the screen.
type proofWriter struct {
	out  io.Writer
	buf  bytes.Buffer
	done bool
}

func (w *proofWriter) Write(p []byte) (int, error) {
	if w.done {
		w.buf.Write(p)
		return len(p), nil
	}
	w.buf.Write(p)
	if i := bytes.Index(w.buf.Bytes(), []byte(proofMarker)); i >= 0 {
		w.done = true
		// What came before the marker in earlier writes was shown as it
		// came; show the part of this one before it.
		shown := w.buf.Len() - len(p)
		if i > shown {
			_, _ = w.out.Write(p[:i-shown])
		}
		return len(p), nil
	}
	_, _ = w.out.Write(p)
	return len(p), nil
}

// --- reads for the dry run ---------------------------------------------------

// SSHDPasswordAuth is the host's 'sshd -T' value of passwordauthentication
// ("yes", "no"), read over the current login with root's rights; ok is
// false when it could not be read (sudo asks for a password, no sshd).
func (e *Env) SSHDPasswordAuth(ctx context.Context, target, port, identity string) (value string, ok bool) {
	if target == Local {
		return "", false
	}
	run := `"$(command -v sshd || echo /usr/sbin/sshd)" -T`
	c := e.ssh(port, identity).Cmd("-T", target, asRoot(run, false))
	c.Stderr = io.Discard
	res, err := e.Runner.Run(ctx, c)
	if err != nil || res.Code != 0 {
		return "", false
	}
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && strings.EqualFold(f[0], "passwordauthentication") {
			return strings.ToLower(f[1]), true
		}
	}
	return "", false
}

// ParseRotateState reads the account name and UID out of the create
// script's record (RotateStateDir/<account>).
func ParseRotateState(text string) (account, uid string) {
	for _, l := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		switch {
		case ok && k == "account":
			account = v
		case ok && k == "uid":
			uid = v
		}
	}
	return account, uid
}

// RotateState is the create script's record of account on the host, read
// over the current login with root's rights; ok is false when it could not
// be read (none, sudo asks for a password).
func (e *Env) RotateState(ctx context.Context, target, port, identity, account string) (acct, uid string, ok bool) {
	if target == Local || !ValidAccountName(account) {
		return "", "", false
	}
	c := e.ssh(port, identity).Cmd("-T", target, asRoot("cat "+RotateStateDir+"/"+account, false))
	c.Stderr = io.Discard
	res, err := e.Runner.Run(ctx, c)
	if err != nil || res.Code != 0 {
		return "", "", false
	}
	acct, uid = ParseRotateState(string(res.Stdout))
	return acct, uid, acct != ""
}

// --- the key file, as the invoking user --------------------------------------

// userCmd is the program run as the invoking user (as root when tacctl was
// not started through sudo), from a directory that user can enter.
func (e *Env) userCmd(name string, args ...string) execx.Cmd {
	c := execx.Cmd{Name: name, Args: args}
	if e.AsUser != "" {
		c.AsUser, c.Dir = e.AsUser, "/"
	}
	return c
}

// FileStat is what 'stat' says of a path, followed through links, as the
// invoking user sees it.
type FileStat struct {
	// Exists is false when the path cannot be stat'ed by that user.
	Exists  bool
	Regular bool
	Dir     bool
	// UID owns it; Mode is its permission bits (0o600).
	UID  int
	Mode int
}

// StatAsUser stats path as the invoking user.
func (e *Env) StatAsUser(ctx context.Context, path string) FileStat {
	c := e.userCmd("stat", "-L", "-c", "%u %a %F", "--", path)
	c.Stderr = io.Discard
	res, err := e.Runner.Run(ctx, c)
	if err != nil || res.Code != 0 {
		return FileStat{}
	}
	f := strings.Fields(strings.TrimSpace(string(res.Stdout)))
	if len(f) < 3 {
		return FileStat{}
	}
	uid, err1 := strconv.Atoi(f[0])
	mode, err2 := strconv.ParseInt(f[1], 8, 32)
	if err1 != nil || err2 != nil {
		return FileStat{}
	}
	kind := strings.Join(f[2:], " ")
	return FileStat{Exists: true, UID: uid, Mode: int(mode), Regular: strings.HasPrefix(kind, "regular"), Dir: kind == "directory"}
}

// PublicKeyOf is the public key of the private key file path, read as the
// invoking user: path.pub when it is there, else what ssh-keygen derives
// from the private key (it asks for the key's passphrase on the terminal).
func (e *Env) PublicKeyOf(ctx context.Context, path string) (string, error) {
	if st := e.StatAsUser(ctx, path+".pub"); st.Exists && st.Regular {
		c := e.userCmd("cat", "--", path+".pub")
		c.Stderr = io.Discard
		if res, err := e.Runner.Run(ctx, c); err == nil && res.Code == 0 {
			if line, ok := PublicKeyLine(string(res.Stdout)); ok {
				return line, nil
			}
		}
	}
	c := e.userCmd("ssh-keygen", "-y", "-f", path)
	c.Stderr = e.Out.Stderr
	res, err := e.Runner.Run(ctx, c)
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		return "", ErrFailed
	}
	if line, ok := PublicKeyLine(string(res.Stdout)); ok {
		return line, nil
	}
	return "", ErrFailed
}

// Fingerprint is ssh-keygen's fingerprint line of a public key line
// ("256 SHA256:... (ED25519)"), computed as the invoking user.
func (e *Env) Fingerprint(ctx context.Context, pub string) string {
	c := e.userCmd("ssh-keygen", "-l", "-f", "/dev/stdin")
	c.Stdin = strings.NewReader(pub + "\n")
	c.Stderr = io.Discard
	res, err := e.Runner.Run(ctx, c)
	if err != nil || res.Code != 0 {
		return ""
	}
	f := strings.Fields(strings.TrimSpace(string(res.Stdout)))
	if len(f) < 2 {
		return ""
	}
	out := f[0] + " " + f[1]
	if n := len(f); n > 2 && strings.HasPrefix(f[n-1], "(") {
		out += " " + f[n-1]
	}
	return out
}

// GenerateKey makes the key pair path with ssh-keygen -t ed25519, as the
// invoking user and on the terminal (ssh-keygen asks for the passphrase; an
// empty one is the operator's choice).
func (e *Env) GenerateKey(ctx context.Context, path string) error {
	c := e.userCmd("ssh-keygen", "-t", "ed25519", "-f", path, "-C", "tacctl-provisioner")
	code, intr, err := Attached(ctx, e.Runner, c, e.Stdin, ui.Output{Stdout: e.Out.Stderr, Stderr: e.Out.Stderr})
	switch {
	case intr:
		return ui.ErrInterrupted
	case err != nil:
		return err
	case code != 0:
		return ErrFailed
	}
	return nil
}
