package cli

import (
	"os"
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/utmp"
)

// clientHostOK is what an audit line may carry as the client: an address or
// a host name, nothing that would break the key=value line.
var clientHostOK = regexp.MustCompile(`^[0-9A-Za-z.:_-]{1,253}$`)

// terminalLine is the name of the terminal this command runs on, as the login
// record names it ("pts/3"), or "" without one. It is read from the open
// standard streams, which sudo leaves on the caller's terminal.
var terminalLine = func() string {
	for _, fd := range []string{"0", "1", "2"} {
		target, err := os.Readlink("/proc/self/fd/" + fd)
		if err != nil {
			continue
		}
		if rest, ok := strings.CutPrefix(target, "/dev/"); ok && (strings.HasPrefix(rest, "pts/") || strings.HasPrefix(rest, "tty")) {
			return rest
		}
	}
	return ""
}

// clientAddr is where the person running this command logged in from: the
// first field of SSH_CONNECTION when the environment has it, else the host
// of the login record of the terminal (sudo removes SSH_CONNECTION, sshd
// records the client there), else "".
func (inv *invocation) clientAddr() string {
	if f := strings.Fields(inv.app.Env.Get("SSH_CONNECTION")); len(f) > 0 && clientHostOK.MatchString(f[0]) {
		return f[0]
	}
	if h := utmp.Remote(terminalLine()); clientHostOK.MatchString(h) {
		return h
	}
	return ""
}

// originFields are ' from=<client>' and ' console=<session>' for the audit
// lines of a command: where the caller logged in from, when it can be told,
// and the console session it runs in, if any.
func (inv *invocation) originFields() string {
	out := ""
	if c := inv.clientAddr(); c != "" {
		out += " from=" + c
	}
	return out + inv.sshConsoleField()
}
