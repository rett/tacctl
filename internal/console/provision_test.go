package console

import (
	"context"
	"errors"
	"fmt"
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
	off := DropIn(testConsole, false, false, nil, nil)
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
	on := DropIn(testConsole, true, false, nil, nil)
	if strings.Contains(on, "DisableForwarding") || !strings.Contains(on, "    AllowAgentForwarding yes\n") ||
		!strings.Contains(on, "    AllowTcpForwarding no\n") {
		t.Errorf("agent on:\n%s", on)
	}
	if strings.Contains(off, "Group tac-superuser") || strings.Contains(off, "but\n") {
		t.Errorf("no forwarding tier, yet a tier block:\n%s", off)
	}
	// Forwarding tiers: a block per tier before the console's, matching both
	// groups (sshd takes the first value of each keyword), in tier order.
	fwd := DropIn(testConsole, false, false, []tier.Tier{tier.Superuser, tier.Operator}, nil)
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
	gw := DropIn(testConsole, false, true, []tier.Tier{tier.Superuser}, nil)
	su = strings.Index(gw, "Match Group tac-console Group tac-superuser\n    DisableForwarding no\n    AllowTcpForwarding yes\n    X11Forwarding yes\n    GatewayPorts clientspecified\n")
	all = strings.Index(gw, "Match Group tac-console\n")
	if su < 0 || su >= all || strings.Count(gw, "clientspecified") != 1 || !strings.Contains(gw[all:], "    GatewayPorts no\n") {
		t.Errorf("gateway ports on:\n%s", gw)
	}
	if DropIn(testConsole, false, true, nil, nil) != DropIn(testConsole, false, false, nil, nil) {
		t.Errorf("gateway ports without a forwarding tier changed the drop-in")
	}
}

// The users held to a password change (pwchange.Pending) get a block of their
// own before every other: a forwarding opens no session, so the console that
// holds them never sees it, and a tier that may forward would let it through.
func TestDropInHeld(t *testing.T) {
	const hold = "    DisableForwarding yes\n    AllowTcpForwarding no\n    AllowStreamLocalForwarding no\n" +
		"    X11Forwarding no\n    AllowAgentForwarding no\n    PermitTunnel no\n    GatewayPorts no\n"
	// No held user, no block: the text is what it was before the block existed.
	for _, held := range [][]string{nil, {}, {"root", "*", "a,b", "Alice", "!bob", "", "a b", "a.b"}} {
		if got := DropIn(testConsole, false, false, []tier.Tier{tier.Superuser}, held); strings.Contains(got, "Match User") ||
			got != DropIn(testConsole, false, false, []tier.Tier{tier.Superuser}, nil) {
			t.Errorf("held %q: a block for no user:\n%s", held, got)
		}
	}
	// One user, a user of the default tier (no forwarding tier but the superuser's).
	one := DropIn(testConsole, false, false, []tier.Tier{tier.Superuser}, []string{"alice"})
	if !strings.Contains(one, "Match User alice\n"+hold) || strings.Count(one, "Match User") != 1 {
		t.Errorf("one held user:\n%s", one)
	}
	// Several: sorted, once each, only names a Linux account can have.
	many := DropIn(testConsole, false, false, nil, []string{"dave", "bob", "alice", "bob", "carol", "*", "root"})
	if !strings.Contains(many, "Match User alice,bob,carol,dave\n"+hold) || strings.Count(many, "Match User") != 1 {
		t.Errorf("several held users:\n%s", many)
	}
	// A user of a forwarding tier: the block comes before the tier blocks and
	// the console's own, in each case of the agent switch and gateway ports.
	for _, agent := range []bool{false, true} {
		for _, gateway := range []bool{false, true} {
			d := DropIn(testConsole, agent, gateway, []tier.Tier{tier.Superuser, tier.Operator}, []string{"bob", "alice"})
			h := strings.Index(d, "Match User alice,bob\n"+hold)
			op := strings.Index(d, "Match Group tac-console Group tac-operator\n")
			su := strings.Index(d, "Match Group tac-console Group tac-superuser\n")
			all := strings.Index(d, "Match Group tac-console\n")
			if h < 0 || h >= op || op >= su || su >= all {
				t.Errorf("agent=%v gateway=%v: order of the blocks:\n%s", agent, gateway, d)
			}
			// the held block closes agent forwarding too, whatever the console says
			if strings.Count(d[h:op], "DisableForwarding yes") != 1 || strings.Contains(d[h:op], "ForceCommand") {
				t.Errorf("agent=%v gateway=%v: held block:\n%s", agent, gateway, d[h:op])
			}
		}
	}
	// What a drop-in lists is what it was written for.
	if got := HeldInDropIn(many); !slices.Equal(got, []string{"alice", "bob", "carol", "dave"}) {
		t.Errorf("HeldInDropIn = %q", got)
	}
	if got := HeldInDropIn(DropIn(testConsole, false, false, nil, nil)); got != nil {
		t.Errorf("HeldInDropIn of a drop-in without the block = %q", got)
	}
	if got := HeldNames([]string{"carol", "alice", "carol", "root", "x y"}); !slices.Equal(got, []string{"alice", "carol"}) {
		t.Errorf("HeldNames = %q", got)
	}
}

// Many held users are written in several 'Match User' blocks of at most
// HeldPerBlock names, all before the tier blocks, and read back as one list.
func TestDropInHeldSplitsLongLists(t *testing.T) {
	var held []string
	for i := 1; i <= 301; i++ {
		held = append(held, fmt.Sprintf("u%03d", i))
	}
	slices.Reverse(held)
	d := DropIn(testConsole, false, false, []tier.Tier{tier.Superuser, tier.Operator}, held)
	var lines []string
	for _, l := range strings.Split(d, "\n") {
		if strings.HasPrefix(l, "Match User ") {
			lines = append(lines, strings.TrimPrefix(l, "Match User "))
		}
	}
	if len(lines) != 7 {
		t.Fatalf("%d Match User blocks for 301 names, want 7", len(lines))
	}
	for i, l := range lines {
		names := strings.Split(l, ",")
		if want := min(HeldPerBlock, 301-i*HeldPerBlock); len(names) != want {
			t.Errorf("block %d lists %d names, want %d", i, len(names), want)
		}
		// sorted across the blocks
		if want := fmt.Sprintf("u%03d", i*HeldPerBlock+1); names[0] != want {
			t.Errorf("block %d starts at %s, want %s", i, names[0], want)
		}
	}
	// every block comes before the first tier block, and each closes the same
	if op, last := strings.Index(d, "Match Group tac-console Group tac-operator\n"), strings.LastIndex(d, "Match User "); last < 0 || last >= op {
		t.Errorf("a held block is after the tier blocks:\n%s", d)
	}
	if n := strings.Count(d, "    DisableForwarding yes\n    AllowTcpForwarding no\n    AllowStreamLocalForwarding no\n    X11Forwarding no\n    AllowAgentForwarding no\n    PermitTunnel no\n    GatewayPorts no\n"); n != 7 {
		t.Errorf("%d blocks close every forwarding in the held block's order, want the 7 held ones", n)
	}
	// the list read back is the whole list, sorted
	want := slices.Clone(held)
	slices.Sort(want)
	if got := HeldInDropIn(d); !slices.Equal(got, want) {
		t.Errorf("HeldInDropIn lists %d names, want 301", len(got))
	}
	// exactly one block per HeldPerBlock names: 50 names, one block
	if strings.Count(DropIn(testConsole, false, false, nil, held[:HeldPerBlock]), "Match User ") != 1 {
		t.Error("50 names are not one block")
	}
	if strings.Count(DropIn(testConsole, false, false, nil, held[:HeldPerBlock+1]), "Match User ") != 2 {
		t.Error("51 names are not two blocks")
	}
}

// The engineer tier has the console or no login: its drop-in is a file of
// its own that closes every forwarding and tunnel whatever shell the account
// has and does not depend on the console's settings but the agent switch,
// which the engineers' own ssh to the hosts they sync needs. The console's
// drop-in holds no block of it.
func TestEngineerDropIn(t *testing.T) {
	off := EngineerDropIn(false)
	block := "Match Group tac-engineer\n    DisableForwarding yes\n    AllowTcpForwarding no\n    AllowStreamLocalForwarding no\n" +
		"    X11Forwarding no\n    AllowAgentForwarding no\n    PermitTunnel no\n    GatewayPorts no\n"
	if !strings.HasSuffix(off, block) || strings.Contains(off, "ForceCommand\n") {
		t.Errorf("engineer drop-in:\n%s", off)
	}
	on := EngineerDropIn(true)
	eng := on[strings.Index(on, "Match Group tac-engineer\n"):]
	if strings.Contains(eng, "DisableForwarding") || !strings.Contains(eng, "    AllowAgentForwarding yes\n") ||
		!strings.Contains(eng, "    AllowTcpForwarding no\n") || !strings.Contains(eng, "    PermitTunnel no\n") {
		t.Errorf("engineer drop-in with agent forwarding:\n%s", eng)
	}
	for _, d := range []string{DropIn(testConsole, false, false, nil, nil), DropIn(testConsole, true, true, []tier.Tier{tier.Superuser, tier.Operator}, nil)} {
		if strings.Contains(d, "tac-engineer") {
			t.Errorf("the console's drop-in holds an engineer block:\n%s", d)
		}
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
	text := DropIn(testConsole, false, false, nil, nil)

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
	ch, err := d.Install(ctx, DropIn(testConsole, true, false, nil, nil))
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
	if ch, err := d.Install(ctx, DropIn(testConsole, true, false, nil, nil)); ch != Updated || err != nil {
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
