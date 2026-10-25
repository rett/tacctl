package cli

// The scope's system configuration block in what the verbs render (0.2.7):
// the walkthroughs and the managed sections of the batch verbs carry it as a
// section of its own, a block with an error is never rendered in part and
// the refusal says how to see what is wrong without a word of the message or
// the key, IOS devices are not touched, and an engineer's read of a block
// with a key is logged.

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
)

const cliSystemBlockFile = "set system login message <<'EOF'\nAuthorized use only.\n  *** jsw1.lab.example.net ***\nEOF\n" +
	"set system domain-name lab.example.net\n" +
	"set system name-server 192.0.2.53\n" +
	"set system ntp server 192.0.2.123 prefer\n" +
	"set system ntp authentication-key 1 type md5 value ntp-key-0123456789\n"

// putBlockSet writes the files of a scope's Junos blocks and the manifest that
// puts them in force; head is what the file keeps before them (an engineer
// sandbox's tier setting).
func (sb *sandbox) putBlockSet(head, scope string, files map[string]string) {
	sb.t.Helper()
	// a manifest written before is replaced
	head, _, _ = strings.Cut(head, "blocks:\n")
	for _, d := range []string{"state/blocks", "state/blocks/" + scope, "state/blocks/" + scope + "/juniper"} {
		if err := os.MkdirAll(sb.path(d), 0o700); err != nil {
			sb.t.Fatal(err)
		}
	}
	manifest := "blocks:\n  " + scope + ":\n    juniper:\n"
	for _, name := range []string{"snmp", "system"} {
		if text, ok := files[name]; ok {
			sb.write("state/blocks/"+scope+"/juniper/"+name, text, 0o600)
			manifest += "    - " + name + "\n"
		}
	}
	sb.write("state/tacctl.yaml", head+manifest, 0o640)
}

func TestWalkthroughCarriesTheSystemBlock(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw-c", "192.168.1.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	without := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	ciscoWithout := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "sw-c"}, route))
	sb.putBlockSet(sb.overrides(), "lab", map[string]string{"system": cliSystemBlockFile})

	out := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	sb.expect(0, "Juniper Junos Configuration", "")
	for _, want := range []string{
		"# The system block of scope 'lab' (tacctl scope block lab juniper show system): the login message, domain, time zone, name servers and NTP.\n" +
			`set system login message "Authorized use only.\n  *** jsw1.lab.example.net ***"` + "\n" +
			"set system domain-name lab.example.net\nset system name-server 192.0.2.53\nset system ntp server 192.0.2.123 prefer\n" +
			"set system ntp authentication-key 1 type md5 value ntp-key-0123456789\n",
		"show configuration system ntp",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the walkthrough lacks %q:\n%s", want, out)
		}
	}
	if out == without {
		t.Error("the block changed nothing")
	}
	// 'device config show' is the same code
	got := plain(sb.cfgRun("", []string{"device", "config", "show", "sw-j"}, route))
	if !strings.HasSuffix(got, out) {
		t.Errorf("device config show does not end in the walkthrough:\n%s", got)
	}
	// IOS: blocks are the release after
	if got := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "sw-c"}, route)); got != ciscoWithout {
		t.Errorf("the IOS walkthrough changed:\n%s", got)
	}

	// A block with an error is not rendered in part: the refusal names the
	// scope and the verb, and nothing of the message or the key.
	sb.putBlockSet(sb.overrides(), "lab", map[string]string{"system": cliSystemBlockFile + "set system time-zone\nset system ntp trusted-key 0\n"})
	got = plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j"}, route))
	if sb.code != 1 || got != "" {
		t.Fatalf("a block with errors: %d %q", sb.code, got)
	}
	for _, want := range []string{"The system block of scope 'lab' has errors", "tacctl scope block lab juniper check system"} {
		if !strings.Contains(sb.stderr(), want) {
			t.Errorf("the refusal lacks %q:\n%s", want, sb.stderr())
		}
	}
	for _, bad := range []string{"Authorized", "jsw1.lab", "ntp-key-0123456789"} {
		if strings.Contains(sb.stderr(), bad) {
			t.Errorf("the refusal holds %q:\n%s", bad, sb.stderr())
		}
	}
}

func TestBatchRenderCarriesTheSystemBlock(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j1", "192.168.1.20", "juniper"}, [3]string{"prod-j", "10.99.0.20", "juniper"})
	b.sb.putBlockSet(b.sb.overrides(), "lab", map[string]string{"system": cliSystemBlockFile})
	inv := b.invoke()
	_, res, err := inv.deviceLoad()
	if err != nil {
		t.Fatal(err)
	}
	var entries []devreg.Entry
	for _, n := range []string{"lab-j1", "prod-j"} {
		e, ok := res.Lookup(n, devreg.ScopeFilter{})
		if !ok {
			t.Fatalf("no %s", n)
		}
		entries = append(entries, e)
	}
	r := inv.newManagedRender(managedOptions{}, false)
	r.prepare(entries)
	sections := func(e devreg.Entry) map[string]devices.Section {
		t.Helper()
		secs, err := r.Expected(e)
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		out := map[string]devices.Section{}
		for _, s := range secs {
			out[s.Name] = s
		}
		return out
	}
	lab := sections(entries[0])
	sys, ok := lab["system"]
	if !ok {
		t.Fatalf("no system section: %v", lab)
	}
	want := []string{
		`set system login message "Authorized use only.\n  *** jsw1.lab.example.net ***"`,
		"set system domain-name lab.example.net",
		"set system name-server 192.0.2.53",
		"set system ntp server 192.0.2.123 prefer",
		"set system ntp authentication-key 1 type md5 value ntp-key-0123456789",
	}
	if strings.Join(sys.Lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("the system section:\n%s", strings.Join(sys.Lines, "\n"))
	}
	for i := range sys.Lines {
		if !sys.Block[i] || sys.Secret[i] != strings.Contains(sys.Lines[i], "authentication-key") {
			t.Errorf("%q: block %v secret %v", sys.Lines[i], sys.Block[i], sys.Secret[i])
		}
	}
	// another scope carries none
	for _, e := range entries[1:] {
		if _, ok := sections(e)["system"]; ok {
			t.Errorf("%s has a system section", e.Name)
		}
	}
	// An error in the block is the scope's Junos devices' problem and nobody
	// else's.
	b.sb.putBlockSet(b.sb.overrides(), "lab", map[string]string{"system": "set system time-zone\n"})
	r = b.invoke().newManagedRender(managedOptions{}, false)
	r.prepare(entries)
	_, err = r.Expected(entries[0])
	if err == nil {
		t.Fatal("a block with errors was rendered")
	}
	for _, w := range []string{"scope 'lab'", "tacctl scope block lab juniper check system"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the problem lacks %q: %v", w, err)
		}
	}
	for _, other := range entries[1:] {
		if _, err := r.Expected(other); err != nil {
			t.Errorf("%s: %v", other.Name, err)
		}
	}
}

// An engineer's walkthrough prints the block's key as it prints the scope's
// secret: a read of its own, logged without the value, and only where the
// block holds a key.
func TestEngineerWalkthroughLogsTheSystemBlockRead(t *testing.T) {
	sb := engineerSandbox(t)
	sb.dev("", "add", "lab-j", "192.168.1.7", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	head := "tier:\n  operator: engineer\n"
	logged := func() int {
		return auditCount(sb.runner, "auth.info", "secret-read kind=block name=lab/juniper/system by=bob")
	}

	sb.putBlockSet(head, "lab", map[string]string{"system": "set system domain-name lab.example.net\nset system name-server 192.0.2.53\n"})
	out := sb.asEngineer("", "config", "juniper", "--scope", "lab")
	if sb.code != 0 || !strings.Contains(out, "set system domain-name lab.example.net") {
		t.Fatalf("no key: %d %q %q", sb.code, out, sb.stderr())
	}
	if n := logged(); n != 0 {
		t.Errorf("a block with no key was logged %d times", n)
	}

	sb.putBlockSet(head, "lab", map[string]string{"system": cliSystemBlockFile})
	out = sb.asEngineer("", "config", "juniper", "--scope", "lab")
	if sb.code != 0 || !strings.Contains(out, "ntp-key-0123456789") {
		t.Fatalf("a key: %d %q %q", sb.code, out, sb.stderr())
	}
	if n := logged(); n != 1 {
		t.Errorf("logged %d times: %q", n, sb.runner.Argvs())
	}
	for _, c := range sb.runner.Records() {
		if c.Cmd.Name == "logger" && strings.Contains(strings.Join(c.Cmd.Args, " "), "ntp-key-0123456789") {
			t.Errorf("the key is in a log line: %q", c.Cmd.Args)
		}
	}
	// a superuser's reveal is logged as well (D253)
	sb.cfgRun("", []string{"config", "juniper", "--scope", "lab"}, nil)
	if !hasAudit(sb.runner, "auth.info", "secret-read kind=block name=lab/juniper/system by=root") {
		t.Errorf("the superuser's read was not logged: %q", auditLines(sb.runner))
	}
}
