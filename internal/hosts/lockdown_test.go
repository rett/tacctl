package hosts

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/assets"
	"github.com/rett/tacctl/internal/paths"
)

// Protocol 7 adds TAC_LOCKDOWN, the state of the scope's emergency lockdown on
// the host: written only while the scope is locked down (its absence removes
// sshd's drop-in), before TAC_PROTOCOL.
func TestHeaderLockdown(t *testing.T) {
	t.Parallel()
	if ScriptProtocol != "7" {
		t.Errorf("the protocol is %s: TAC_LOCKDOWN is a header field of protocol 7", ScriptProtocol)
	}
	if h := (Script{}).Header(); strings.Contains(h, "TAC_LOCKDOWN") {
		t.Errorf("a header of a scope with no lockdown has the field:\n%s", h)
	}
	for _, v := range []string{LockdownOn, LockdownOnEnd} {
		h := Script{Lockdown: v}.Header()
		if !strings.HasSuffix(h, "TAC_ENGINEER_SUDO=ALL\nTAC_LOCKDOWN="+v+"\nTAC_PROTOCOL=7\n") {
			t.Errorf("header for %s:\n%s", v, h)
		}
	}
	// With the server's own flag and the rollback field, in this order.
	h := Script{Local: true, RevokeEngineer: true, Lockdown: LockdownOn}.Header()
	if !strings.HasSuffix(h, "TAC_LOCAL=1\nTAC_ENGINEER_SUDO=ALL\nTAC_REVOKE_ENGINEER=1\nTAC_LOCKDOWN=on\nTAC_PROTOCOL=7\n") {
		t.Errorf("header:\n%s", h)
	}
}

// The body knows the values of the header's field and the drop-in's name is
// the one paths names, in the install and the remove script alike (the one
// the engineer's and the console's drop-ins sort after).
func TestScriptsKnowTheLockdownDropIn(t *testing.T) {
	t.Parallel()
	install, remove := string(assets.LinuxInstallScript), string(assets.LinuxRemoveScript)
	for _, w := range []string{
		`case "${TAC_LOCKDOWN:-off}" in`,
		`on-end) LOCKDOWN="on"; LOCKDOWN_END=1 ;;`,
		`Match Group ${G_USERS},!tac-superuser`,
		`    PubkeyAuthentication no`,
		`    AllowTcpForwarding no`,
		`    AllowStreamLocalForwarding no`,
		`    X11Forwarding no`,
		`    AllowAgentForwarding no`,
		"loginctl terminate-user",
		"restorecon",
		"sshd -t",
		"sshd -T -C",
		"systemctl reload",
		`kill -HUP "$pid"`,
		`SSHD_PIDFILE="${TACCTL_CLIENT_SSHD_PIDFILE:-/run/sshd.pid}"`,
	} {
		if !strings.Contains(install, w) {
			t.Errorf("client-install.sh lacks %q", w)
		}
	}
	def := "/etc/ssh/sshd_config.d/" + paths.SSHDLockdownDropInName
	for name, body := range map[string]string{"client-install.sh": install, "client-remove.sh": remove} {
		if !strings.Contains(body, `LOCKDOWN_DROPIN="${TACCTL_CLIENT_LOCKDOWN_DROPIN:-`+def+`}"`) {
			t.Errorf("%s does not default the lockdown drop-in to %s", name, def)
		}
	}
	if !strings.Contains(remove, `kill -HUP "$pid"`) {
		t.Error("client-remove.sh does not reload sshd without systemd")
	}
	// a restart would end the sessions of everyone: the scripts reload only
	for name, body := range map[string]string{"client-install.sh": install, "client-remove.sh": remove} {
		if strings.Contains(body, "systemctl restart") {
			t.Errorf("%s restarts a service", name)
		}
	}
}
