package plan

import "testing"

// A source interface typed inside the server group is named as the older
// per-group form, not as an unexplained statement of the group (backlog 3g).
func TestPlainIOSNamesThePerGroupSourceInterface(t *testing.T) {
	got := plainIOS("aaa group server tacacs+ LAB" + pathSep + "ip tacacs source-interface Loopback0")
	want := "the server group LAB has its own TACACS+ source interface, Loopback0 (an older per-group form; the standard sets one for the device)"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	// The group's other leaves keep their label.
	if got := plainIOS("aaa group server tacacs+ LAB" + pathSep + "server name TACACS"); got != "the server group LAB: server name TACACS" {
		t.Errorf("server entry: %q", got)
	}
	if got := plainIOS("ip tacacs source-interface Loopback0"); got != "the TACACS+ source interface is Loopback0" {
		t.Errorf("device-level: %q", got)
	}
}
