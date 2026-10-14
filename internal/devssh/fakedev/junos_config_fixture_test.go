package fakedev

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const rolloutFixture = "../../../tests/fixtures/devconf/fake/junos-rollout"

// copyDir copies the files of a fixture directory.
func copyDir(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	ents, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return to
}

func TestJunosRolloutFixture(t *testing.T) {
	dir := copyDir(t, rolloutFixture)
	clk := NewFakeClock(time.Date(2026, 10, 12, 2, 0, 0, 0, time.UTC))
	srv := New(dir, WithClock(clk))
	defer srv.Stop()
	c, first := shell(t, srv, "local-admin", "local-fakedev-pw")
	if first != "\n{master:0}\nlocal-admin@example-sw1> " {
		t.Errorf("first prompt %q", first)
	}
	got := c.send("show version")
	mustContain(t, "show version", got, "Hostname: example-sw1", "Junos: 25.4R1-S2.3")
	if got := c.send("show chassis hardware"); !strings.Contains(got, "FXYZ00000001") {
		t.Errorf("hardware: %q", got)
	}
	c.send("configure exclusive")
	c.send("set system login idle-timeout 30")
	c.send("set snmp community example-ro clients 198.51.100.0/24 restrict")
	got = c.send("show | compare")
	mustContain(t, "compare", got, "[edit system login]\n+   idle-timeout 30;\n",
		"[edit snmp community example-ro clients]\n+   198.51.100.0/24 restrict;")
	if got := c.send("commit"); got != "commit complete" {
		t.Errorf("commit: %q", got)
	}
	b, err := os.ReadFile(filepath.Join(dir, "committed.set"))
	if err != nil || !strings.Contains(string(b), "set system login idle-timeout 30\n") ||
		!strings.Contains(string(b), "set snmp community example-ro clients 198.51.100.0/24 restrict\n") {
		t.Errorf("committed.set: %v\n%s", err, b)
	}
	if _, err := os.Stat(filepath.Join(rolloutFixture, "committed.set")); err == nil {
		t.Error("the fixture directory was written to")
	}
}
