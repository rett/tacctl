package hosts

import (
	"strings"
	"testing"
)

// TAC_REVOKE_ENGINEER=1 (tacctl rollback --hosts, D50) is in the header only
// when asked for, after TAC_ENGINEER_SUDO and before the protocol; the
// protocol stays 6, so the body of the script and its header still agree.
func TestHeaderRevokeEngineer(t *testing.T) {
	plain := Script{}.Header()
	if strings.Contains(plain, "TAC_REVOKE_ENGINEER") {
		t.Errorf("an ordinary header has the field:\n%s", plain)
	}
	revoke := Script{RevokeEngineer: true}.Header()
	want := "TAC_ENGINEER_SUDO=ALL\nTAC_REVOKE_ENGINEER=1\nTAC_PROTOCOL=" + ScriptProtocol + "\n"
	if !strings.HasSuffix(revoke, want) {
		t.Errorf("header does not end with %q:\n%s", want, revoke)
	}
	if ScriptProtocol != "6" {
		t.Errorf("the protocol is %s: the rollback field is a header field of protocol 6", ScriptProtocol)
	}
	// With the server's own flags and a sudo list.
	both := Script{Local: true, EngineerSudo: "/usr/bin/id", RevokeEngineer: true}.Header()
	if !strings.HasSuffix(both, "TAC_LOCAL=1\nTAC_ENGINEER_SUDO=/usr/bin/id\nTAC_REVOKE_ENGINEER=1\nTAC_PROTOCOL=6\n") {
		t.Errorf("header:\n%s", both)
	}
}
