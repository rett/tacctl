package cli

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// utmpFile is a utmp with one login of 'line' from 'host'.
func utmpFile(t *testing.T, line, host string) string {
	t.Helper()
	rec := make([]byte, 384)
	binary.LittleEndian.PutUint16(rec[0:], 7)
	copy(rec[8:40], line)
	copy(rec[76:332], host)
	p := filepath.Join(t.TempDir(), "utmp")
	if err := os.WriteFile(p, rec, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// sshAuditFrom runs 'ssh core-sw1' as alice with the given extra environment
// and reports whether the audit line ends with the wanted origin fields.
func (sb *sandbox) sshAuditFrom(extraEnv ...string) {
	sb.t.Helper()
	env := []string{"SSH_AUTH_SOCK=" + sshTestSock, "SUDO_USER=alice"}
	for uid, name := range testPasswd {
		if name == "alice" {
			env = append(env, "SUDO_UID="+uid)
		}
	}
	sb.cfgRun("", []string{"ssh", "core-sw1"}, nil, append(env, extraEnv...)...)
}

func TestSSHAuditNamesWhereTheCallerLoggedInFrom(t *testing.T) {

	// From the environment, as a caller without sudo's env_reset has it.
	sb, _, _ := sshSandbox(t)
	sb.sshAuditFrom("SSH_CONNECTION=198.51.100.7 50000 192.0.2.1 22")
	if !sb.runner.CalledRegexp(`ssh user=alice device=core-sw1 addr=10\.99\.0\.1 from=198\.51\.100\.7$`) {
		t.Errorf("env: %q", sb.runner.Argvs())
	}

	// From the login record of the terminal, which sudo leaves intact.
	sb, _, _ = sshSandbox(t)
	sb.hooks.terminalLine = func() string { return "pts/4" }
	sb.hooks.utmpFile = utmpFile(t, "pts/4", "203.0.113.20")
	sb.sshAuditFrom()
	if !sb.runner.CalledRegexp(`ssh user=alice device=core-sw1 addr=10\.99\.0\.1 from=203\.0\.113\.20$`) {
		t.Errorf("utmp: %q", sb.runner.Argvs())
	}

	// A host field that is not an address or a name is not logged.
	sb, _, _ = sshSandbox(t)
	sb.hooks.terminalLine = func() string { return "pts/4" }
	sb.hooks.utmpFile = utmpFile(t, "pts/4", "evil host=x")
	sb.sshAuditFrom()
	if !sb.runner.CalledRegexp(`ssh user=alice device=core-sw1 addr=10\.99\.0\.1$`) {
		t.Errorf("hostile: %q", sb.runner.Argvs())
	}
}
