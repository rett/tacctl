package console

// The server's pieces of the console (docs/plans/operator-console-wp-console.md
// 5.3): the /etc/shells line that lets the console be a login shell, and
// sshd's drop-in for the members of tac-console. The drop-in makes the
// console the only program such a login runs (ForceCommand: a remote
// command, scp, sftp and the internal-sftp subsystem all reach the console,
// which reads the client's command from SSH_ORIGINAL_COMMAND), closes every
// forwarding but X11 and TCP for the tiers of 'console forwarding tiers',
// and turns key logins off (they would bypass TACACS+). Every
// change of the drop-in is checked with 'sshd -t' and undone when sshd
// refuses it; sshd is reloaded only after a change it accepted.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

// Group is the local group whose members sshd's drop-in applies to: the
// accounts whose login shell is the console.
const Group = "tac-console"

// TierGroup is the local group of a tier ("" for none).
func TierGroup(t tier.Tier) string {
	switch t {
	case tier.Readonly:
		return tier.ReadonlyGroup
	case tier.Operator:
		return tier.OperatorGroup
	case tier.Engineer:
		return tier.EngineerGroup
	case tier.Superuser:
		return tier.SuperuserGroup
	}
	return ""
}

// DropIn is the text of sshd's drop-in for the console at command (the
// console's path). Agent forwarding stays possible only when agent is set
// (console agent-forwarding enable): DisableForwarding, which closes every
// kind at once, is then replaced by the single switches. The members of
// the tiers in forward (console forwarding tiers) may forward X11 and TCP
// ports: a block for each comes first, matching tac-console and the tier's
// group together, and sshd takes the first value it finds for each
// keyword; agent, stream-local and tunnel forwarding stay as for every
// console user. With gateway (console forwarding gateway-ports) the tier
// blocks set GatewayPorts clientspecified: their remote forwards listen on
// the address the client names (loopback when it names none); every other
// console login keeps GatewayPorts no.
func DropIn(command string, agent, gateway bool, forward []tier.Tier) string {
	var b strings.Builder
	b.WriteString("# Managed by tacctl (tacctl console install|remove, host sync of this server); do not edit.\n")
	b.WriteString("# The members of " + Group + " are tacctl users whose login shell is the console:\n")
	if len(forward) == 0 {
		b.WriteString("# the console is the only program their logins run, nothing is forwarded, and\n")
	} else {
		b.WriteString("# the console is the only program their logins run, nothing is forwarded but\n")
		b.WriteString("# what the tier blocks allow, and\n")
	}
	b.WriteString("# they log in with their TACACS+ password only.\n")
	for _, t := range Tiers {
		if g := TierGroup(t); g != "" && slices.Contains(forward, t) {
			b.WriteString("# Console users of the " + string(t) + " tier may forward X11 and TCP ports (console forwarding tiers).\n")
			if gateway {
				b.WriteString("# Their remote forwards may listen on any address they name (console forwarding gateway-ports).\n")
			}
			b.WriteString("Match Group " + Group + " Group " + g + "\n")
			b.WriteString("    DisableForwarding no\n")
			b.WriteString("    AllowTcpForwarding yes\n")
			b.WriteString("    X11Forwarding yes\n")
			if gateway {
				b.WriteString("    GatewayPorts clientspecified\n")
			}
		}
	}
	b.WriteString("Match Group " + Group + "\n")
	b.WriteString("    ForceCommand " + command + "\n")
	if !agent {
		b.WriteString("    DisableForwarding yes\n")
	}
	b.WriteString("    AllowTcpForwarding no\n")
	b.WriteString("    AllowStreamLocalForwarding no\n")
	b.WriteString("    X11Forwarding no\n")
	b.WriteString("    GatewayPorts no\n")
	b.WriteString("    AllowAgentForwarding " + map[bool]string{true: "yes", false: "no"}[agent] + "\n")
	b.WriteString("    PermitTunnel no\n")
	b.WriteString("    PermitTTY yes\n")
	b.WriteString("    PubkeyAuthentication no\n")
	b.WriteString("    ClientAliveInterval 300\n")
	b.WriteString("    ClientAliveCountMax 2\n")
	return b.String()
}

// ErrSSHD is a drop-in change sshd refused ('sshd -t'); the change was
// undone. The error's lines say what sshd printed.
var ErrSSHD = errors.New("console: sshd refused the configuration")

type sshdError struct{ lines []string }

func (e *sshdError) Error() string   { return strings.Join(e.lines, " ") }
func (e *sshdError) Lines() []string { return e.lines }
func (e *sshdError) Is(t error) bool { return t == ErrSSHD }

// Change is what a provisioning step did to one piece.
type Change int

const (
	Unchanged Change = iota
	Installed        // the piece was not there
	Updated          // it was there and differed
	Removed
)

// String is the change as the summaries word it.
func (c Change) String() string {
	return [...]string{"Unchanged", "Installed", "Updated", "Removed"}[c]
}

// EnsureShells adds the line shell to shellsFile (/etc/shells) when it is
// not listed; every other line is kept. The file is replaced by a rename
// (its mode kept, 0644 for a new one).
func EnsureShells(shellsFile, shell string) (Change, error) {
	listed, err := ShellListed(shellsFile, shell)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Unchanged, fail("Cannot read " + shellsFile + ": " + errText(err))
	}
	if listed {
		return Unchanged, nil
	}
	data, _ := os.ReadFile(shellsFile)
	text := string(data)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return Installed, writeKeepingMode(shellsFile, []byte(text+shell+"\n"), 0o644)
}

// RemoveShells takes every line that is exactly shell out of shellsFile;
// a missing file, or one without the line, is left as it is.
func RemoveShells(shellsFile, shell string) (Change, error) {
	data, err := os.ReadFile(shellsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return Unchanged, nil
	}
	if err != nil {
		return Unchanged, fail("Cannot read " + shellsFile + ": " + errText(err))
	}
	var keep []string
	found := false
	for _, l := range strings.SplitAfter(string(data), "\n") {
		if strings.TrimSpace(l) == shell {
			found = true
			continue
		}
		keep = append(keep, l)
	}
	if !found {
		return Unchanged, nil
	}
	return Removed, writeKeepingMode(shellsFile, []byte(strings.Join(keep, "")), 0o644)
}

// writeKeepingMode writes data to a new file next to path and renames it
// over path, with path's mode (mode for a new file).
func writeKeepingMode(path string, data []byte, mode os.FileMode) error {
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fail("Cannot create " + dir + ": " + errText(err))
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return fail("Cannot write " + path + ": " + errText(err))
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, mode)
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		_ = os.Remove(name)
		return fail("Cannot write " + path + ": " + errText(werr))
	}
	return nil
}

// DropInFile changes sshd's drop-in through the runner: 'sshd -t' after
// every change, 'systemctl reload' after an accepted one.
type DropInFile struct {
	Runner execx.Runner
	// Path is the drop-in (paths.SSHDDropIn).
	Path string
}

// Install makes the drop-in hold text. A drop-in that already does is
// Unchanged and nothing runs. Otherwise the file is written (0644, its
// directory made 0755), 'sshd -t' checks the whole configuration and, when
// sshd refuses it, the previous content comes back (a new file is removed)
// and the error is ErrSSHD with sshd's words; when sshd accepts it, sshd is
// reloaded (Reload).
func (s DropInFile) Install(ctx context.Context, text string) (Change, error) {
	old, err := os.ReadFile(s.Path)
	existed := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Unchanged, fail("Cannot read " + s.Path + ": " + errText(err))
	}
	if existed && string(old) == text {
		return Unchanged, nil
	}
	if err := writeKeepingMode(s.Path, []byte(text), 0o644); err != nil {
		return Unchanged, err
	}
	if err := s.test(ctx); err != nil {
		if existed {
			_ = writeKeepingMode(s.Path, old, 0o644)
		} else {
			_ = os.Remove(s.Path)
		}
		return Unchanged, err
	}
	ch := Installed
	if existed {
		ch = Updated
	}
	return ch, s.Reload(ctx)
}

// Remove deletes the drop-in, checks the configuration without it (the
// file comes back when sshd refuses) and reloads sshd. A missing drop-in
// is Unchanged.
func (s DropInFile) Remove(ctx context.Context) (Change, error) {
	old, err := os.ReadFile(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return Unchanged, nil
	}
	if err != nil {
		return Unchanged, fail("Cannot read " + s.Path + ": " + errText(err))
	}
	if err := os.Remove(s.Path); err != nil {
		return Unchanged, fail("Cannot remove " + s.Path + ": " + errText(err))
	}
	if err := s.test(ctx); err != nil {
		_ = writeKeepingMode(s.Path, old, 0o644)
		return Unchanged, err
	}
	return Removed, s.Reload(ctx)
}

// test is 'sshd -t'.
func (s DropInFile) test(ctx context.Context) error {
	res, err := s.Runner.Run(ctx, execx.Cmd{Name: "sshd", Args: []string{"-t"}})
	if err != nil {
		return &sshdError{lines: []string{"sshd -t could not be run: " + err.Error()}}
	}
	if res.Code != 0 {
		out := strings.TrimSpace(string(res.Stderr) + "\n" + string(res.Stdout))
		lines := []string{"sshd -t refused the configuration (exit status " + strconv.Itoa(res.Code) + ")" + map[bool]string{true: ".", false: ":"}[out == ""]}
		for _, l := range strings.Split(out, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, "  "+l)
			}
		}
		return &sshdError{lines: lines}
	}
	return nil
}

// SSHDUnits are the names sshd's unit has: ssh.service on Debian and
// Ubuntu, sshd.service on the RHEL family.
var SSHDUnits = []string{"ssh.service", "sshd.service"}

// Reload is 'systemctl reload <unit>' for the first of SSHDUnits systemctl
// accepts. sshd keeps its sessions over a reload; new logins see the new
// configuration.
func (s DropInFile) Reload(ctx context.Context) error {
	var last string
	for _, u := range SSHDUnits {
		res, err := s.Runner.Run(ctx, execx.Cmd{Name: "systemctl", Args: []string{"reload", u}})
		if err == nil && res.Code == 0 {
			return nil
		}
		if err != nil {
			last = err.Error()
		} else {
			last = strings.TrimSpace(firstLine(strings.TrimSpace(string(res.Stderr))))
			if last == "" {
				last = "exit status " + strconv.Itoa(res.Code)
			}
		}
	}
	return fail("sshd could not be reloaded (systemctl reload " + strings.Join(SSHDUnits, " or ") + ": " + last + "); new logins get the drop-in once sshd is restarted.")
}

// IncludesDropIns reports whether sshd_config (its text) includes the
// directory of drop-in files: an 'Include' line naming dir/*.conf, or
// <dir's name>/*.conf relative to /etc/ssh (as sshd reads a relative
// Include) or under /etc/ssh. Without it sshd never reads the drop-in.
func IncludesDropIns(sshdConfig, dir string) bool {
	base := filepath.Base(dir)
	for _, l := range strings.Split(sshdConfig, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.EqualFold(f[0], "Include") {
			continue
		}
		for _, w := range f[1:] {
			if w == dir+"/*.conf" || w == base+"/*.conf" || w == "/etc/ssh/"+base+"/*.conf" {
				return true
			}
		}
	}
	return false
}
