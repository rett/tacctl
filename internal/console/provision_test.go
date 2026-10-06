package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/tier"
)

const testConsole = "/usr/local/bin/tacctl-console"

func TestDropInText(t *testing.T) {
	off := DropIn(testConsole, false, false, nil)
	for _, l := range []string{
		"Match Group tac-console\n", "    ForceCommand " + testConsole + "\n", "    DisableForwarding yes\n",
		"    AllowTcpForwarding no\n", "    AllowStreamLocalForwarding no\n", "    X11Forwarding no\n",
		"    AllowAgentForwarding no\n", "    PermitTunnel no\n", "    PermitTTY yes\n", "    PubkeyAuthentication no\n",
		"    ClientAliveInterval 300\n", "    ClientAliveCountMax 2\n",
	} {
		if !strings.Contains(off, l) {
			t.Errorf("drop-in lacks %q:\n%s", l, off)
		}
	}
	if !strings.HasPrefix(off, "# Managed by tacctl") {
		t.Errorf("no header:\n%s", off)
	}
	// Agent forwarding on: DisableForwarding would close it too.
	on := DropIn(testConsole, true, false, nil)
	if strings.Contains(on, "DisableForwarding") || !strings.Contains(on, "    AllowAgentForwarding yes\n") ||
		!strings.Contains(on, "    AllowTcpForwarding no\n") {
		t.Errorf("agent on:\n%s", on)
	}
	if strings.Contains(off, "Group tac-superuser") || strings.Contains(off, "but\n") {
		t.Errorf("no forwarding tier, yet a tier block:\n%s", off)
	}
	// Forwarding tiers: a block per tier before the console's, matching both
	// groups (sshd takes the first value of each keyword), in tier order.
	fwd := DropIn(testConsole, false, false, []tier.Tier{tier.Superuser, tier.Operator})
	op := strings.Index(fwd, "Match Group tac-console Group tac-operator\n    DisableForwarding no\n    AllowTcpForwarding yes\n    X11Forwarding yes\n")
	su := strings.Index(fwd, "Match Group tac-console Group tac-superuser\n    DisableForwarding no\n    AllowTcpForwarding yes\n    X11Forwarding yes\n")
	all := strings.Index(fwd, "Match Group tac-console\n")
	if op < 0 || su < 0 || all < 0 || op >= su || su >= all || strings.Contains(fwd, "tac-readonly") {
		t.Errorf("forwarding tiers:\n%s", fwd)
	}
	if !strings.Contains(fwd, "    DisableForwarding yes\n") || !strings.Contains(fwd, "    AllowAgentForwarding no\n") {
		t.Errorf("the console's own block changed:\n%s", fwd)
	}
	// Gateway ports: clientspecified in each tier block only; every other
	// console login keeps no.
	if strings.Contains(fwd, "clientspecified") || !strings.Contains(fwd[all:], "    GatewayPorts no\n") {
		t.Errorf("gateway ports off:\n%s", fwd)
	}
	gw := DropIn(testConsole, false, true, []tier.Tier{tier.Superuser})
	su = strings.Index(gw, "Match Group tac-console Group tac-superuser\n    DisableForwarding no\n    AllowTcpForwarding yes\n    X11Forwarding yes\n    GatewayPorts clientspecified\n")
	all = strings.Index(gw, "Match Group tac-console\n")
	if su < 0 || su >= all || strings.Count(gw, "clientspecified") != 1 || !strings.Contains(gw[all:], "    GatewayPorts no\n") {
		t.Errorf("gateway ports on:\n%s", gw)
	}
	if DropIn(testConsole, false, true, nil) != DropIn(testConsole, false, false, nil) {
		t.Errorf("gateway ports without a forwarding tier changed the drop-in")
	}
}

func TestShellsLine(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "shells")
	// A missing file is made with the line.
	if ch, err := EnsureShells(f, testConsole); ch != Installed || err != nil {
		t.Fatalf("new: %v %v", ch, err)
	}
	if b, _ := os.ReadFile(f); string(b) != testConsole+"\n" {
		t.Errorf("new file %q", b)
	}
	// Every other line is kept; the mode too; no trailing newline mended.
	_ = os.Remove(f)
	if err := os.WriteFile(f, []byte("# /etc/shells\n/bin/sh\n/bin/bash"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ch, err := EnsureShells(f, testConsole); ch != Installed || err != nil {
		t.Fatalf("add: %v %v", ch, err)
	}
	want := "# /etc/shells\n/bin/sh\n/bin/bash\n" + testConsole + "\n"
	if b, _ := os.ReadFile(f); string(b) != want {
		t.Errorf("added %q", b)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if ch, err := EnsureShells(f, testConsole); ch != Unchanged || err != nil {
		t.Errorf("again: %v %v", ch, err)
	}
	if ch, err := RemoveShells(f, testConsole); ch != Removed || err != nil {
		t.Fatalf("remove: %v %v", ch, err)
	}
	if b, _ := os.ReadFile(f); string(b) != "# /etc/shells\n/bin/sh\n/bin/bash\n" {
		t.Errorf("removed %q", b)
	}
	if ch, err := RemoveShells(f, testConsole); ch != Unchanged || err != nil {
		t.Errorf("remove again: %v %v", ch, err)
	}
	if ch, err := RemoveShells(filepath.Join(dir, "none"), testConsole); ch != Unchanged || err != nil {
		t.Errorf("remove from a missing file: %v %v", ch, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left behind %v", entries)
	}
}

func TestDropInInstallRemove(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config.d", "tacctl-console.conf")
	r := &fake.Runner{Strict: true}
	r.On([]string{"sshd", "-t"}, execx.Result{})
	r.On([]string{"systemctl", "reload"}, execx.Result{})
	d := DropInFile{Runner: r, Path: path}
	text := DropIn(testConsole, false, false, nil)

	if ch, err := d.Install(ctx, text); ch != Installed || err != nil {
		t.Fatalf("install: %v %v", ch, err)
	}
	if got := r.Argvs(); !slices.Equal(got, []string{"sshd -t", "systemctl reload ssh.service"}) {
		t.Errorf("calls %q", got)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", st.Mode())
	}
	if st, _ := os.Stat(filepath.Dir(path)); st.Mode().Perm() != 0o755 {
		t.Errorf("dir mode %v", st.Mode())
	}
	r.Reset()
	if ch, err := d.Install(ctx, text); ch != Unchanged || err != nil || len(r.Calls()) != 0 {
		t.Errorf("same text: %v %v %q", ch, err, r.Argvs())
	}

	// sshd refuses a change: the old text comes back, no reload.
	r.Fail([]string{"sshd", "-t"}, 255, "/etc/ssh/sshd_config.d/tacctl-console.conf line 7: Bad configuration option: DisableForwarding")
	r.Reset()
	ch, err := d.Install(ctx, DropIn(testConsole, true, false, nil))
	if ch != Unchanged || !errors.Is(err, ErrSSHD) || !strings.Contains(err.Error(), "Bad configuration option: DisableForwarding") {
		t.Fatalf("refused: %v %v", ch, err)
	}
	if b, _ := os.ReadFile(path); string(b) != text {
		t.Errorf("not restored: %q", b)
	}
	if r.Called("systemctl") {
		t.Error("reloaded after a refusal")
	}
	// ... and a new file refused is removed.
	other := DropInFile{Runner: r, Path: filepath.Join(dir, "other.conf")}
	if _, err := other.Install(ctx, text); !errors.Is(err, ErrSSHD) {
		t.Fatalf("new refused: %v", err)
	}
	if _, err := os.Stat(other.Path); !os.IsNotExist(err) {
		t.Error("a refused new drop-in was left")
	}

	// The reload falls back to sshd.service (the RHEL family).
	r = &fake.Runner{Strict: true}
	r.On([]string{"sshd", "-t"}, execx.Result{})
	r.Fail([]string{"systemctl", "reload", "ssh.service"}, 5, "Failed to reload ssh.service: Unit ssh.service not found.")
	r.On([]string{"systemctl", "reload", "sshd.service"}, execx.Result{})
	d.Runner = r
	if ch, err := d.Install(ctx, DropIn(testConsole, true, false, nil)); ch != Updated || err != nil {
		t.Fatalf("update: %v %v", ch, err)
	}
	if got := r.Argvs(); !slices.Equal(got, []string{"sshd -t", "systemctl reload ssh.service", "systemctl reload sshd.service"}) {
		t.Errorf("calls %q", got)
	}
	// Neither unit: reported, the drop-in stays (sshd accepted it).
	r.Fail([]string{"systemctl", "reload", "sshd.service"}, 5, "Unit sshd.service not found.")
	if _, err := d.Install(ctx, text); err == nil || !strings.Contains(err.Error(), "sshd could not be reloaded") {
		t.Errorf("no unit: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != text {
		t.Error("an accepted drop-in was undone after a failed reload")
	}

	// Remove: refused by sshd puts it back; accepted removes and reloads.
	r = &fake.Runner{Strict: true}
	r.Fail([]string{"sshd", "-t"}, 1, "")
	d.Runner = r
	if ch, err := d.Remove(ctx); ch != Unchanged || !errors.Is(err, ErrSSHD) {
		t.Fatalf("remove refused: %v %v", ch, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("not restored after a refused removal")
	}
	r = &fake.Runner{Strict: true}
	r.On([]string{"sshd", "-t"}, execx.Result{})
	r.On([]string{"systemctl", "reload"}, execx.Result{})
	d.Runner = r
	if ch, err := d.Remove(ctx); ch != Removed || err != nil {
		t.Fatalf("remove: %v %v", ch, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("still there")
	}
	r.Reset()
	if ch, err := d.Remove(ctx); ch != Unchanged || err != nil || len(r.Calls()) != 0 {
		t.Errorf("remove again: %v %v %q", ch, err, r.Argvs())
	}
}

func TestIncludesDropIns(t *testing.T) {
	const dir = "/etc/ssh/sshd_config.d"
	for text, want := range map[string]bool{
		"Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n": true,
		"include sshd_config.d/*.conf\n":                   true,
		"Include /etc/ssh/other.conf sshd_config.d/*.conf": true,
		"#Include /etc/ssh/sshd_config.d/*.conf\n":         false,
		"Port 22\n": false,
		"Include /etc/ssh/sshd_config.d/tacctl.conf\n": false,
	} {
		if got := IncludesDropIns(text, dir); got != want {
			t.Errorf("IncludesDropIns(%q) = %t", text, got)
		}
	}
}

// Forwarding: the policy per tier, the _console-policy field, the display
// the console hands on, and the scrub that keeps it.
func TestForwardingPolicyAndDisplay(t *testing.T) {
	p := &Policy{File: Defaults()}
	for _, c := range []struct {
		t    tier.Tier
		want bool
	}{{tier.Superuser, true}, {tier.Operator, false}, {tier.Readonly, false}, {tier.Unrestricted, true}, {tier.None, false}} {
		if got := p.Forwarding(c.t); got != c.want {
			t.Errorf("%s: %v", c.t, got)
		}
	}
	if r, ok := ParseRemote("shell=console forward=yes tier=superuser"); !ok || !r.Forward {
		t.Errorf("forward=yes: %+v", r)
	}
	if r, _ := ParseRemote("shell=console forward=maybe"); r.Forward {
		t.Errorf("forward=maybe: %+v", r)
	}
	for v, want := range map[string]bool{"localhost:10.0": true, ":0": true, "unix/:0": true, "": false,
		"localhost:10.0 ;id": false, "a\nb": false, strings.Repeat("a", 256): false} {
		if ValidDisplay(v) != want {
			t.Errorf("ValidDisplay(%q) != %v", v, want)
		}
	}
	env := Scrub([]string{"DISPLAY=localhost:10.0", "XAUTHORITY=/tmp/x", "TERM=xterm"}, "/bin/bash", false)
	if !slices.Contains(env, "DISPLAY=localhost:10.0") || slices.Contains(env, "XAUTHORITY=/tmp/x") {
		t.Errorf("scrub: %q", env)
	}
}
