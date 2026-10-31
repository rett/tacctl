package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'device check --sources' and 'device scan --sources' (D315), end to end: a
// device is pulled from the fake device, its AAA source addresses are read
// from the pull, and the host-key read (ssh-keyscan, scripted) of each
// address but the registered one is compared with the pin. Warnings only:
// nothing is pinned, recorded or stored.

// srcKeys scripts ssh-keyscan by address: the keys an address offers, an
// address not listed does not resolve (no answer).
func srcKeys(keys map[string][]devreg.HostKey) func(*fake.Runner) {
	return func(r *fake.Runner) {
		route(r)
		r.On([]string{"journalctl"}, execx.Result{})
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh-keyscan" }, func(c execx.Cmd) (execx.Result, error) {
			addr := c.Args[len(c.Args)-1]
			ks, ok := keys[addr]
			if !ok {
				return execx.Result{Stderr: []byte(unresolvable(addr))}, nil
			}
			return execx.Result{Stdout: keyscanOut(addr, ks...), Stderr: []byte("# " + addr + ":22 SSH-2.0-OpenSSH_9.6\n")}, nil
		})
	}
}

// junosSources is a Junos device whose server states each of the source
// addresses, with the interface addresses it holds.
func junosSources(t *testing.T, srcs ...string) (*pullBox, string) {
	t.Helper()
	return aaaBox(t, "juniper", false, func(text string) string {
		a := wordAfter(t, text, "set system tacplus-server ")
		var stmts []string
		for i, s := range srcs {
			stmts = append(stmts, "set interfaces ge-0/0/"+strconv.Itoa(i)+" unit 0 family inet address "+s+"/32",
				"set system tacplus-server "+a+" source-address "+s)
		}
		return appendStmts(text, stmts...)
	})
}

func (b *pullBox) check(extra func(*fake.Runner), args ...string) string {
	b.t.Helper()
	return plain(b.sb.cfgRun("", append([]string{"device"}, args...), extra, "SUDO_USER=alice"))
}

// keyscansOf are the addresses ssh-keyscan was asked about, in order.
func keyscansOf(sb *sandbox) []string {
	var out []string
	for _, c := range sb.runner.Calls() {
		if c.Name == "ssh-keyscan" {
			out = append(out, c.Args[len(c.Args)-1])
		}
	}
	return out
}

func srcCount(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}

func TestDeviceCheckSourcesWarnsAndChangesNothing(t *testing.T) {
	b, name := junosSources(t, "192.0.2.250", "198.51.100.9", "203.0.113.5", "192.168.1.20")
	ed, other := hkKey(t, "ed25519"), otherEd25519(t)
	own, err := devreg.ParseHostKey(b.srv.HostKey())
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string][]devreg.HostKey{
		"192.168.1.20": {own},
		"192.0.2.250":  {own, ed}, // the device's key among others
		"198.51.100.9": {other},   // another device's
	}

	// without --sources nothing but the device's own address is read
	out := b.check(srcKeys(keys), "check", name)
	if got := keyscansOf(b.sb); srcCount(got, "192.0.2.250")+srcCount(got, "198.51.100.9")+srcCount(got, "203.0.113.5") != 0 || strings.Contains(out, "source address") {
		t.Errorf("a check without --sources tested sources: %v\n%s", got, out)
	}

	files := snapshotTree(t, b.sb.path("var-lib"), b.sb.path("state"))
	out = b.check(srcKeys(keys), "check", name, "--sources")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{
		"[WARN] source-address 198.51.100.9 presents another SSH host key (" + other.Fingerprint() + "), the device's is " +
			own.Fingerprint() + ": the address may belong to another device",
		"[WARN] source-address 203.0.113.5 is unreachable from this server; it may be unreachable by design",
		"[INFO] 3 source addresses tested: 1 presents the device's key, 1 unreachable, 1 presents another key",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "source-address 192.0.2.250 ") || strings.Contains(out, "source-address 192.168.1.20 ") {
		t.Errorf("an address that is fine, or the registered one, is named:\n%s", out)
	}
	// the registered address is read by the host-key scan of the check only
	// (once); each source once
	got := keyscansOf(b.sb)
	for addr, n := range map[string]int{"192.168.1.20": 1, "192.0.2.250": 1, "198.51.100.9": 1, "203.0.113.5": 1} {
		if srcCount(got, addr) != n {
			t.Errorf("ssh-keyscan of %s: %d, want %d (%v)", addr, srcCount(got, addr), n, got)
		}
	}
	audit := auditLines(b.sb.runner)
	// nothing is pinned, recorded or stored, the device keeps its state
	if after := snapshotTree(t, b.sb.path("var-lib"), b.sb.path("state")); !sameTree(files, after, "devices-seen.json") {
		t.Errorf("--sources changed files:\n%s", diffTree(files, after))
	}
	seen, _ := os.ReadFile(b.sb.path("var-lib", "devices-seen.json"))
	for _, a := range []string{"198.51.100.9", "203.0.113.5"} {
		if strings.Contains(string(seen), a) {
			t.Errorf("the seen cache holds the source address %s", a)
		}
	}
	if cfg := b.run("device", "config", "list", "--differs"); strings.Contains(cfg, name) {
		t.Errorf("the device differs after a source test:\n%s", cfg)
	}
	// the audit line carries counts, no address
	var line string
	for _, l := range audit {
		if strings.HasPrefix(l, "sources ") {
			line = l
		}
		for _, a := range []string{"198.51.100.9", "203.0.113.5", "192.0.2.250"} {
			if strings.Contains(l, a) {
				t.Errorf("audit line names an address: %s", l)
			}
		}
	}
	if !strings.HasPrefix(line, "sources tested=3 unreachable=1 mismatched=1 by=") {
		t.Errorf("audit line %q in\n%s", line, strings.Join(audit, "\n"))
	}

	// JSON
	out = b.check(srcKeys(keys), "check", name, "--sources", "--json")
	var js []struct {
		Name    string
		Sources *[]sourceResult
	}
	if err := json.Unmarshal([]byte(out), &js); err != nil || len(js) != 1 || js[0].Sources == nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	byAddr := map[string]sourceResult{}
	for _, x := range *js[0].Sources {
		byAddr[x.Address] = x
	}
	if len(byAddr) != 3 || byAddr["192.0.2.250"].Result != "ok" || byAddr["203.0.113.5"].Result != "unreachable" ||
		byAddr["198.51.100.9"].Result != "mismatch" || byAddr["198.51.100.9"].Fingerprint != other.Fingerprint() ||
		byAddr["198.51.100.9"].Pinned != own.Fingerprint() {
		t.Errorf("sources %+v", byAddr)
	}
	out = b.check(srcKeys(keys), "check", name, "--json")
	if strings.Contains(out, `"sources"`) {
		t.Errorf("a check without --sources has a sources key:\n%s", out)
	}
}

func TestDeviceCheckSourcesAllPresentTheKey(t *testing.T) {
	b, name := junosSources(t, "192.0.2.250", "198.51.100.9")
	own, _ := devreg.ParseHostKey(b.srv.HostKey())
	keys := map[string][]devreg.HostKey{"192.168.1.20": {own}, "192.0.2.250": {own}, "198.51.100.9": {own}}
	out := b.check(srcKeys(keys), "check", name, "--sources")
	if !strings.Contains(out, "[INFO] 2 source addresses tested, all present the device's key") || strings.Contains(out, "[WARN]") {
		t.Errorf("%s", out)
	}
}

func TestDeviceCheckSourcesNothingToTest(t *testing.T) {
	// the registered address is the only source
	b, name := junosSources(t, "192.168.1.20")
	own, _ := devreg.ParseHostKey(b.srv.HostKey())
	keys := map[string][]devreg.HostKey{"192.168.1.20": {own}}
	out := b.check(srcKeys(keys), "check", name, "--sources")
	if !strings.Contains(out, "no source address to test other than the registered address") {
		t.Errorf("registered only:\n%s", out)
	}
	// a pull of the device without a source
	b2, name := aaaBox(t, "juniper", false, func(s string) string { return s })
	out = b2.check(srcKeys(nil), "check", name, "--sources")
	if !strings.Contains(out, "[INFO] no source address was tested: the device states no source address of its AAA client") {
		t.Errorf("no source:\n%s", out)
	}
	// no pin: not compared, nothing connected to
	b3, name := junosSources(t, "198.51.100.9")
	reg := b3.sb.devices()
	b3.sb.write("state/devices.yaml", strings.ReplaceAll(reg, "    host_keys:\n    - "+b3.srv.HostKey()+"\n", ""), 0o600)
	out = b3.check(srcKeys(nil), "check", name, "--sources")
	if !strings.Contains(out, "not compared: no host key is pinned for "+name) || srcCount(keyscansOf(b3.sb), "198.51.100.9") != 0 {
		t.Errorf("unpinned: %v\n%s", keyscansOf(b3.sb), out)
	}
	// never pulled
	b4 := newPullBox(t)
	b4.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	out = b4.check(srcKeys(nil), "check", "lab-j", "--sources")
	if !strings.Contains(out, "its configuration was never read: tacctl device config pull lab-j") {
		t.Errorf("never pulled:\n%s", out)
	}
}

// A device that cannot be tested is named, with the reason, in a scan, and
// the closing line counts them instead of saying that no device has a source.
func TestDeviceScanSourcesSaysWhyADeviceIsNotTested(t *testing.T) {
	b, name := junosSources(t, "198.51.100.9")
	own, _ := devreg.ParseHostKey(b.srv.HostKey())
	keys := map[string][]devreg.HostKey{"192.168.1.20": {own}, "198.51.100.9": {own}}
	reg := b.sb.devices()
	never := "  lab-n:\n    address: 192.168.1.21\n    vendor: juniper\n    host_keys:\n    - " + b.srv.HostKey() + "\n"
	b.sb.write("state/devices.yaml", reg+never, 0o600)

	// a mixed fleet: one device tested, one never pulled
	out := b.check(srcKeys(keys), "scan", "--sources")
	for _, want := range []string{
		"[INFO] " + name + ": 1 source address tested, all present the device's key",
		"[INFO] lab-n: no source address was tested: its configuration was never read: tacctl device config pull lab-n",
		"[INFO] 1 device not tested (see the lines above)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mixed fleet lacks %q:\n%s", want, out)
		}
	}
	// the pin removed: the device states a source and is not compared
	b.sb.write("state/devices.yaml", strings.ReplaceAll(reg, "    host_keys:\n    - "+b.srv.HostKey()+"\n", "")+never, 0o600)
	out = b.check(srcKeys(keys), "scan", "--sources")
	for _, want := range []string{
		"[INFO] " + name + ": no source address was tested: not compared: no host key is pinned for " + name,
		"[INFO] lab-n: no source address was tested: its configuration was never read",
		"[INFO] 2 devices not tested (see the lines above)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unpinned lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "No device states a source address") {
		t.Errorf("a device that states a source is said to state none:\n%s", out)
	}
}

// What the warnings say: an error that is not "no answer" is not called
// unreachable by design, a mismatch names the registered device that holds the
// address, and a key type that is not pinned is not a wrong key.
func TestDeviceCheckSourcesWarningsInDetail(t *testing.T) {
	b, name := junosSources(t, "198.51.100.9", "198.51.100.10", "203.0.113.5")
	own, _ := devreg.ParseHostKey(b.srv.HostKey())
	other, rsa := otherEd25519(t), hkKey(t, "rsa")
	b.sb.write("state/devices.yaml", b.sb.devices()+"  lab-other:\n    address: 198.51.100.9\n    vendor: cisco\n", 0o600)
	script := func(r *fake.Runner) {
		route(r)
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh-keyscan" }, func(c execx.Cmd) (execx.Result, error) {
			addr := c.Args[len(c.Args)-1]
			switch addr {
			case "192.168.1.20":
				return execx.Result{Stdout: keyscanOut(addr, own), Stderr: []byte("# " + addr + ":22 SSH-2.0-OpenSSH_9.6\n")}, nil
			case "198.51.100.9":
				return execx.Result{Stdout: keyscanOut(addr, other), Stderr: []byte("# " + addr + ":22 SSH-2.0-OpenSSH_9.6\n")}, nil
			case "198.51.100.10":
				return execx.Result{Stdout: keyscanOut(addr, rsa), Stderr: []byte("# " + addr + ":22 SSH-2.0-OpenSSH_9.6\n")}, nil
			}
			return execx.Result{}, errors.New("ssh-keyscan: permission denied")
		})
	}
	out := b.check(script, "check", name, "--sources")
	for _, want := range []string{
		"the address may belong to another device (lab-other)",
		"[INFO] source-address 198.51.100.10 not compared: presented only rsa, pinned ed25519",
		"[WARN] source-address 203.0.113.5 could not be tested: ssh-keyscan could not be run (ssh-keyscan: permission denied)",
		"[INFO] 2 source addresses tested: 0 present the device's key, 1 unreachable, 1 presents another key",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "203.0.113.5 is unreachable") {
		t.Errorf("an error that is not no-answer reads as unreachable by design:\n%s", out)
	}
}

// A run on a terminal says which device it is at, apart from the report.
func TestDeviceCheckSourcesProgress(t *testing.T) {
	b, name := junosSources(t, "198.51.100.9")
	own, _ := devreg.ParseHostKey(b.srv.HostKey())
	keys := map[string][]devreg.HostKey{"192.168.1.20": {own}, "198.51.100.9": {own}}
	b.check(srcKeys(keys), "check", name, "--sources")
	if strings.Contains(b.sb.stderr(), "testing source addresses") {
		t.Errorf("progress without a terminal: %q", b.sb.stderr())
	}
	b.sb.hooks.isTerminalWriter = func(io.Writer) bool { return true }
	b.check(srcKeys(keys), "check", name, "--sources")
	if !strings.Contains(b.sb.stderr(), "testing source addresses of "+name+" ...") {
		t.Errorf("no progress on a terminal: %q", b.sb.stderr())
	}
}

func TestDeviceCheckSourcesIOSInterfaces(t *testing.T) {
	b, name := aaaBox(t, "cisco", false, func(text string) string {
		text = inBlock(t, text, "aaa group server tacacs+ ", "ip tacacs source-interface Loopback0")
		return appendStmts(text,
			"interface Loopback0", " ip address 192.0.2.250 255.255.255.255", " ip address 192.0.2.251 255.255.255.255 secondary", "!",
			"interface GigabitEthernet0/2", " ip address dhcp", "!",
			"ip radius source-interface GigabitEthernet0/2")
	})
	own, _ := devreg.ParseHostKey(b.srv.HostKey())
	other := otherEd25519(t)
	keys := map[string][]devreg.HostKey{"192.168.1.30": {own}, "192.0.2.250": {own}, "192.0.2.251": {other}}
	out := b.check(srcKeys(keys), "check", name, "--sources")
	for _, want := range []string{
		"[WARN] source-interface loopback0 (192.0.2.251) presents another SSH host key",
		"[INFO] source-interface gigabitethernet0/2 skipped: the address is learned dynamically",
		"[INFO] 2 source addresses tested: 1 presents the device's key, 1 presents another key",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	// a record made before the addresses were kept
	b.editRecord(name, func(r *devconf.Record) { r.Interfaces = nil })
	out = b.check(srcKeys(keys), "check", name, "--sources")
	if !strings.Contains(out, "[INFO] source-interface loopback0 skipped: addresses are not recorded: pull the device again") ||
		!strings.Contains(out, "[INFO] no source address was tested") {
		t.Errorf("not recorded:\n%s", out)
	}
	if got := keyscansOf(b.sb); srcCount(got, "192.0.2.250")+srcCount(got, "192.0.2.251") != 0 {
		t.Errorf("connected without a recorded address: %v", got)
	}
}

func TestDeviceCheckSourcesLimit(t *testing.T) {
	srcs := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8", "192.0.2.9", "192.0.2.10"}
	b, name := junosSources(t, srcs...)
	own, _ := devreg.ParseHostKey(b.srv.HostKey())
	keys := map[string][]devreg.HostKey{"192.168.1.20": {own}}
	for _, s := range srcs {
		keys[s] = []devreg.HostKey{own}
	}
	out := b.check(srcKeys(keys), "check", name, "--sources")
	if !strings.Contains(out, "[INFO] 8 source addresses tested, all present the device's key") ||
		!strings.Contains(out, "[INFO] 2 more source addresses not tested (at most 8 per device)") {
		t.Errorf("%s", out)
	}
	if got := keyscansOf(b.sb); len(got) != 9 {
		t.Errorf("%d reads, want 8 sources and the device's own: %v", len(got), got)
	}
}

// A source is read as the device's own address is: the built-in client
// follows a silent ssh-keyscan, and both use the timing of the device's scale.
func TestDeviceCheckSourcesFallbackAndScale(t *testing.T) {
	b, name := junosSources(t, "198.51.100.9")
	own, _ := devreg.ParseHostKey(b.srv.HostKey())
	var mu sync.Mutex
	var timings []devssh.ScanTiming
	var addrs []string
	b.sb.hooks.keyFallback = func(*invocation) devreg.KeyFallback {
		return func(_ context.Context, address string, _ int, _ bool, tm devssh.ScanTiming) ([]devreg.HostKey, error) {
			mu.Lock()
			defer mu.Unlock()
			timings, addrs = append(timings, tm), append(addrs, address)
			return []devreg.HostKey{own}, nil
		}
	}
	script := func(r *fake.Runner) {
		route(r)
		r.Func(func(c execx.Cmd) bool { return c.Name == "ssh-keyscan" }, func(c execx.Cmd) (execx.Result, error) {
			addr := c.Args[len(c.Args)-1]
			if addr == "192.168.1.20" {
				return execx.Result{Stdout: keyscanOut(addr, own), Stderr: []byte("# " + addr + ":22 SSH-2.0-OpenSSH_9.6\n")}, nil
			}
			return execx.Result{Stderr: []byte("# " + addr + ":22 SSH-2.0-OpenSSH_7.5\n")}, nil
		})
	}
	b.sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "3"}, nil)
	b.sb.cfgRun("", []string{"device", "timeout-scale", name, "4"}, nil)
	out := b.check(script, "check", name, "--sources")
	if !strings.Contains(out, "[INFO] 1 source address tested, all present the device's key") {
		t.Errorf("%s", out)
	}
	want := devssh.ScanTiming{}.Scaled(4)
	if len(addrs) != 1 || addrs[0] != "198.51.100.9" || timings[0] != want || want.Handshake != 4*devssh.DefaultScanTiming().Handshake {
		t.Errorf("fallback: %v %+v, want the device's scale %+v", addrs, timings, want)
	}
	// the combined ssh-keyscan of the source is the first of its calls: -T 5
	// at scale 1
	var first []string
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "ssh-keyscan" && c.Args[len(c.Args)-1] == "198.51.100.9" {
			for i, a := range c.Args {
				if a == "-T" && len(first) == 0 {
					first = append(first, c.Args[i+1])
				}
			}
		}
	}
	if len(first) != 1 || first[0] != "20" {
		t.Errorf("ssh-keyscan -T of the source %v, want the scaled 20", first)
	}
}

func TestDeviceScanSources(t *testing.T) {
	b, name := junosSources(t, "198.51.100.9", "203.0.113.5")
	own, _ := devreg.ParseHostKey(b.srv.HostKey())
	other := otherEd25519(t)
	keys := map[string][]devreg.HostKey{"192.168.1.20": {own}, "198.51.100.9": {other}}
	out := b.check(srcKeys(keys), "scan")
	if strings.Contains(out, "Source addresses") || srcCount(keyscansOf(b.sb), "198.51.100.9") != 0 {
		t.Errorf("a scan without --sources:\n%s", out)
	}
	out = b.check(srcKeys(keys), "scan", "--sources")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %s", b.sb.code, b.sb.stderr())
	}
	for _, want := range []string{
		"Source addresses",
		"[WARN] " + name + ": source-address 198.51.100.9 presents another SSH host key",
		"[WARN] " + name + ": source-address 203.0.113.5 is unreachable from this server; it may be unreachable by design",
		"[INFO] " + name + ": 2 source addresses tested: 0 present the device's key, 1 unreachable, 1 presents another key",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("scan lacks %q:\n%s", want, out)
		}
	}
	if l := auditLine(b.sb.runner, "sources tested=2 unreachable=1 mismatched=1 by="); l == "" {
		t.Errorf("audit lines: %v", auditLines(b.sb.runner))
	}
	// the background form and a quiet run take no --sources; discover has none
	for _, a := range [][]string{{"scan", "--sources", "--if-stale"}, {"scan", "--sources", "--quiet"}} {
		b.check(srcKeys(keys), a...)
		b.sb.expect(1, "", "--sources is not part of the background form")
	}
	b.check(srcKeys(keys), "discover", "--sources")
	b.sb.expect(1, "", "--sources")
}

func TestDeviceSourcesNeedTheOperatorTier(t *testing.T) {
	sb := newSandbox(t, true)
	for _, args := range [][]string{{"device", "check", "x", "--sources"}, {"device", "scan", "--sources"}} {
		sb.cfgRun("", args, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
		}, "SUDO_USER=carol")
		if sb.code == 0 {
			t.Errorf("%v: a read-only caller ran it", args)
		}
	}
}

// snapshotTree reads every file under dirs (path to content), for the
// comparison of a run that must change nothing.
func snapshotTree(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			out[p] = string(data)
			return nil
		})
	}
	return out
}

func sameTree(a, b map[string]string, ignore ...string) bool { return diffTree(a, b, ignore...) == "" }

func diffTree(a, b map[string]string, ignore ...string) string {
	var out []string
	skip := func(p string) bool {
		for _, i := range ignore {
			if strings.HasSuffix(p, "/"+i) {
				return true
			}
		}
		return false
	}
	for p, v := range a {
		if w, ok := b[p]; !skip(p) && (!ok || w != v) {
			out = append(out, p)
		}
	}
	for p := range b {
		if _, ok := a[p]; !skip(p) && !ok {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n")
}
