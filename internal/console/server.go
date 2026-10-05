package console

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
)

// Pieces is what is in place on this server for the console: the pieces
// 'console show' reports and 'console check' will test.
type Pieces struct {
	// Command is the console's symlink: Link is where it points ("" when
	// there is no symlink), Exists whether anything is at the path.
	Command string
	Link    string
	Exists  bool
	// Shells is whether /etc/shells lists the console; DropIn whether sshd's
	// drop-in file exists.
	Shells bool
	DropIn bool
}

// Inspect looks at the server's pieces; it reads and changes nothing else.
func Inspect(p paths.Paths) Pieces {
	pc := Pieces{Command: p.ConsoleCommand}
	if st, err := os.Lstat(p.ConsoleCommand); err == nil {
		pc.Exists = true
		if st.Mode()&os.ModeSymlink != 0 {
			pc.Link, _ = os.Readlink(p.ConsoleCommand)
		}
	}
	pc.Shells, _ = ShellListed(p.ShellsFile, p.ConsoleCommand)
	if st, err := os.Stat(p.SSHDDropIn); err == nil && st.Mode().IsRegular() {
		pc.DropIn = true
	}
	return pc
}

// SSHD is what sshd would apply to a user's connection: the effective
// values of the forwarding settings.
type SSHD struct {
	TCPForwarding   string // allowtcpforwarding: yes, all, local, remote or no
	AgentForwarding string // allowagentforwarding: yes or no
	// ForceCommand is forcecommand (none, or the console's drop-in's
	// command); PubkeyAuth is pubkeyauthentication. "" when sshd did not
	// print them.
	ForceCommand string
	PubkeyAuth   string
}

// SSHDCheck runs 'sshd -T -C user=<user>,host=localhost,addr=127.0.0.1'
// (the effective configuration for that user, Match blocks included)
// through the runner. An error is a check that could not be made (no sshd,
// no such user, a configuration sshd refuses); its text is for the person.
func SSHDCheck(ctx context.Context, r execx.Runner, user string) (SSHD, error) {
	res, err := r.Run(ctx, execx.Cmd{Name: "sshd", Args: []string{"-T", "-C", "user=" + user + ",host=localhost,addr=127.0.0.1"}})
	if err != nil {
		return SSHD{}, fail("sshd could not be run: " + err.Error())
	}
	if res.Code != 0 {
		l := strings.TrimSpace(firstLine(strings.TrimSpace(string(res.Stderr))))
		if l == "" {
			l = "exit status " + strconv.Itoa(res.Code)
		}
		return SSHD{}, fail("sshd -T failed: " + l)
	}
	var s SSHD
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
		switch k {
		case "allowtcpforwarding":
			s.TCPForwarding = v
		case "allowagentforwarding":
			s.AgentForwarding = v
		case "forcecommand":
			s.ForceCommand = v
		case "pubkeyauthentication":
			s.PubkeyAuth = v
		}
	}
	if s.TCPForwarding == "" || s.AgentForwarding == "" {
		return SSHD{}, fail("sshd -T printed no forwarding settings.")
	}
	return s, nil
}

// Problems are the ways the connection could still do more than the console
// intends: sshd does not force the console (command) on it, so a remote
// command or the sftp subsystem would run without it; TCP forwarding is
// anything but no for a user whose tier may not forward (console
// forwarding tiers: tcpAllowed); agent forwarding is on while the policy
// does not allow it; or a key login (which bypasses TACACS+) is allowed.
// Empty: as designed.
func (s SSHD) Problems(agentAllowed, tcpAllowed bool, command string) []string {
	var out []string
	if s.ForceCommand != command {
		v := s.ForceCommand
		if v == "" {
			v = "none"
		}
		out = append(out, "forcecommand is '"+v+"'")
	}
	if s.TCPForwarding != "no" && !tcpAllowed {
		out = append(out, "allowtcpforwarding is '"+s.TCPForwarding+"'")
	}
	if s.AgentForwarding != "no" && !agentAllowed {
		out = append(out, "allowagentforwarding is '"+s.AgentForwarding+"'")
	}
	if s.PubkeyAuth != "" && s.PubkeyAuth != "no" {
		out = append(out, "pubkeyauthentication is '"+s.PubkeyAuth+"'")
	}
	return out
}
