package blocks

import (
	"strings"
	"testing"
)

// A block with only what 0.2.18 knew is not listed; one with a statement of
// the closed tables, an announcement, an absent line or an IOS motd banner
// is, with a count and no text.
func TestFindSince0219(t *testing.T) {
	st := NewStore(t.TempDir())
	put := func(l Level, vendor, text string) {
		t.Helper()
		if err := st.Write(l, vendor, BlockSystem, []byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	put(ScopeLevel("lab"), VendorJuniper, "set system time-zone UTC\nset system name-server 192.0.2.53\n")
	put(ScopeLevel("dc1"), VendorJuniper, "set system time-zone UTC\nset system syslog host 192.0.2.50 any notice\nset system login announcement <<'EOF'\nA notice.\nEOF\nabsent system services telnet\ndelete system syslog host 198.51.100.7 any\n")
	put(DeviceLevel("rtr1.example.net"), VendorCisco, "ip domain name example.net\nbanner motd <<'EOF'\nA notice.\nEOF\nlogging host 192.0.2.50\nno logging host 198.51.100.7\n")
	put(ScopeLevel("lab"), VendorCisco, "ip domain name example.net\n")
	got := st.FindSince0219()
	var lines []string
	for _, u := range got {
		lines = append(lines, u.String())
	}
	want := []string{
		"scope dc1, juniper system block: 4 statements",
		"device rtr1.example.net, cisco system block: 3 statements",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}
