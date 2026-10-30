package cli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
)

// 'device sync' (D137): the registry's empty hostname, location and
// description from the last pull record; no login; the preview first; one
// registry write under the lock; what a device reports is checked.

// syncSeed registers a Junos device and gives it a pull record whose
// sections say what the device reports of itself.
func (b *pullBox) syncSeed(name, addr, hostname string, snmp ...string) {
	b.t.Helper()
	b.devices([3]string{name, addr, "juniper"})
	st := b.invoke().configStore()
	sec := devices.Section{Name: "snmp", Lines: snmp, Secret: make([]bool, len(snmp))}
	if err := st.SaveSections(name, "juniper", map[string]devices.Section{"snmp": sec}); err != nil {
		b.t.Fatal(err)
	}
	b.putRecord(name, devconf.Record{Address: addr, Vendor: "juniper", Pulled: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC), By: "alice",
		Result: devconf.ResultOK, Release: "25.4R1-S2.3", Model: "EX4300-48MP", Serial: "FXYZ00000001", Hostname: hostname, UserPulled: true})
}

// resolves is the DNS of the test: a name the table lacks does not resolve.
func (b *pullBox) resolves(table map[string][]string) {
	b.sb.resolve = func(_ context.Context, name string) ([]string, error) {
		if a, ok := table[name]; ok {
			return a, nil
		}
		return nil, errors.New("no such host")
	}
}

// sync runs 'device sync' as alice on a terminal with the lines of typed
// typed ahead ("-": none).
func (b *pullBox) sync(typed string, args ...string) string {
	b.t.Helper()
	b.sb.script = route
	defer func() { b.sb.script, b.sb.tty = nil, nil }()
	b.sb.tty = nil
	if typed != "-" {
		holdTTY(b.t, b.sb, typed)
	}
	return plain(b.sb.run("", append([]string{"device", "sync"}, args...), "SUDO_USER=alice"))
}

// entry is the registry's entry of a device.
func (b *pullBox) entry(name string) devreg.Entry {
	b.t.Helper()
	_, res, err := b.invoke().deviceLoad()
	if err != nil {
		b.t.Fatal(err)
	}
	e, ok := res.Lookup(name, devreg.ScopeFilter{})
	if !ok {
		b.t.Fatalf("no device %s", name)
	}
	return e
}

func TestSyncPreviewApplyOverwrite(t *testing.T) {
	b := newCollectBox(t)
	b.syncSeed("sw-a", "192.168.1.31", "sw-a.lab.example.net",
		`set snmp location "Lab rack 2"`, `set snmp description "Lab switch five"`)
	b.resolves(map[string][]string{"sw-a.lab.example.net": {"192.168.1.31"}})

	// the preview changes nothing and logs in to nothing
	out := b.sync("-", "sw-a")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"hostname", "sw-a.lab.example.net", "location", "Lab rack 2", "description", "Lab switch five", "fill",
		"EX4300-48MP", "25.4R1-S2.3", "FXYZ00000001", "would be written. Write them with --apply."} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if e := b.entry("sw-a"); e.Hostname != "" || e.Location != "" || e.Description != "" {
		t.Errorf("the preview wrote: %+v", e)
	}
	if b.srv.Attempts() != 0 {
		t.Errorf("sync logged in (%d attempts)", b.srv.Attempts())
	}
	// --apply without a terminal needs --yes
	b.sync("-", "sw-a", "--apply")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "without one needs --yes") {
		t.Errorf("no terminal: %d %q", b.sb.code, b.sb.stderr())
	}
	// declined at the terminal: nothing written
	out = b.sync("n\n", "sw-a", "--apply")
	if !strings.Contains(out, "Write 3 field(s) on 1 device(s) of the registry? [y/N]") && !strings.Contains(b.sb.stderr(), "Write 3 field(s) on 1 device(s) of the registry? [y/N]") {
		t.Errorf("the question: %q\n%s", b.sb.stderr(), out)
	}
	if e := b.entry("sw-a"); e.Hostname != "" {
		t.Errorf("declined, written: %+v", e)
	}
	// applied
	out = b.sync("-", "sw-a", "--apply", "--yes")
	if b.sb.code != 0 || !strings.Contains(out, "Wrote 3 field(s) on 1 device(s).") {
		t.Fatalf("apply: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	e := b.entry("sw-a")
	if e.Hostname != "sw-a.lab.example.net" || e.Location != "Lab rack 2" || e.Description != "Lab switch five" || e.Address != "192.168.1.31" ||
		e.Vendor != "juniper" || e.Name != "sw-a" {
		t.Errorf("entry %+v", e)
	}
	al := b.auditLines("device sync")
	if len(al) != 1 || !strings.Contains(al[0], "device sync user=alice devices=1 fields=3") {
		t.Errorf("audit %q", al)
	}
	// again: nothing to fill
	out = b.sync("-", "sw-a", "--apply", "--yes")
	if !strings.Contains(out, "Nothing to fill") {
		t.Errorf("again:\n%s", out)
	}

	// a set value is kept; --overwrite shows the old one and replaces it
	b.syncSeed("sw-a", "192.168.1.31", "sw-a.lab.example.net",
		`set snmp location "Lab rack 9"`, `set snmp description "Lab switch five"`)
	if _, err := b.invoke().deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		f.Find("sw-a").Location = "Old rack"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out = b.sync("-", "sw-a", "--apply", "--yes")
	if !strings.Contains(out, "keep") || !strings.Contains(out, "Old rack") || b.entry("sw-a").Location != "Old rack" {
		t.Errorf("keep:\n%s\n%+v", out, b.entry("sw-a"))
	}
	out = b.sync("-", "sw-a", "--overwrite")
	if !strings.Contains(out, "replace") || !strings.Contains(out, "Old rack") || !strings.Contains(out, "Lab rack 9") {
		t.Errorf("overwrite preview:\n%s", out)
	}
	if b.entry("sw-a").Location != "Old rack" {
		t.Error("the preview wrote")
	}
	out = b.sync("-", "sw-a", "--overwrite", "--apply", "--yes")
	if b.sb.code != 0 || b.entry("sw-a").Location != "Lab rack 9" || !strings.Contains(out, "Wrote 1 field(s)") {
		t.Errorf("overwrite:\n%s\n%+v", out, b.entry("sw-a"))
	}
}

// What a device reports is checked: control characters, a value the
// registry would not accept, a bare host name are listed refused and never
// written; the fields beside them are.
func TestSyncRefusesHostileText(t *testing.T) {
	b := newCollectBox(t)
	b.syncSeed("sw-a", "192.168.1.31", "sw-a", // a bare name: not a DNS name
		"set snmp location \"rack\x1b]0;x\x07\"", `set snmp description "`+strings.Repeat("d", 130)+`"`)
	out := b.sync("-", "sw-a", "--apply", "--yes")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Errorf("a terminal escape reached the output: %q", out)
	}
	if got := strings.Count(out, "refused:"); got != 3 {
		t.Errorf("refused rows: %d\n%s", got, out)
	}
	if e := b.entry("sw-a"); e.Hostname != "" || e.Location != "" || e.Description != "" {
		t.Errorf("a refused value was written: %+v", e)
	}
	if !strings.Contains(out, "Nothing to fill") {
		t.Errorf("output:\n%s", out)
	}
	if got := unsafeText("a\nb"); got == "" {
		t.Error("a newline is safe")
	}
	if got := unsafeText("a\x1b[2Jb"); got == "" {
		t.Error("an escape is safe")
	}
	if got := unsafeText("a\u009bb"); got == "" {
		t.Error("a C1 control is safe")
	}
	if got := unsafeText("Lab rack 2"); got != "" {
		t.Errorf("plain text: %q", got)
	}
}

// A device without a record, a device of another vendor and a host are
// said; --json is one object; the selectors.
func TestSyncSelectionAndJSON(t *testing.T) {
	b := newCollectBox(t)
	b.syncSeed("sw-a", "192.168.1.31", "sw-a.lab.example.net", `set snmp location "Lab rack 2"`)
	b.resolves(map[string][]string{"sw-a.lab.example.net": {"192.168.1.31"}})
	b.devices([3]string{"sw-a", "192.168.1.31", "juniper"}, [3]string{"sw-b", "192.168.1.32", "juniper"}, [3]string{"fw-c", "192.168.1.33", "cisco"})
	out := b.sync("-", "--all", "--json")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	var got struct {
		Devices []syncDevice
		Apply   bool
		Fields  int
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	by := map[string]syncDevice{}
	for _, d := range got.Devices {
		by[d.Name] = d
	}
	if got.Apply || got.Fields != 2 || len(by) != 3 || !strings.Contains(by["sw-b"].Skipped, "no pull record") ||
		!strings.Contains(by["fw-c"].Skipped, "only a Junos device's record") || len(by["sw-a"].Fields) != 3 {
		t.Errorf("%+v", got)
	}
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 2, "Name the devices to sync"},
		{[]string{"sw-a", "--all"}, 2, "not both"},
		{[]string{"--vendor", "other"}, 2, "--vendor takes cisco, juniper or wti"},
		{[]string{"nope"}, 1, "not found"},
	} {
		b.sync("-", c.args...)
		if b.sb.code != c.code || !strings.Contains(b.sb.stderr(), c.want) {
			t.Errorf("%v: %d %q", c.args, b.sb.code, b.sb.stderr())
		}
	}
	b.sync("-", "--scope", "prod")
	if b.sb.code != 0 {
		t.Errorf("--scope: %d %q", b.sb.code, b.sb.stderr())
	}
}

// The registry write checks each field again under the lock: a value set
// since the preview is left as it is.
func TestSyncWriteSkipsWhatChanged(t *testing.T) {
	b := newCollectBox(t)
	b.syncSeed("sw-a", "192.168.1.31", "sw-a.lab.example.net", `set snmp location "Lab rack 2"`)
	b.resolves(map[string][]string{"sw-a.lab.example.net": {"192.168.1.31"}})
	inv := b.invoke()
	inv.app.Resolve = b.sb.resolve
	s := &deviceSyncRun{inv: inv, user: "alice", apply: true}
	if err := s.collect(selection{names: []string{"sw-a"}}); err != nil {
		t.Fatal(err)
	}
	// somebody sets the location between the preview and the write
	if _, err := b.invoke().deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		f.Find("sw-a").Location = "Set by hand"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.write(); err != nil {
		t.Fatal(err)
	}
	e := b.entry("sw-a")
	if e.Location != "Set by hand" || e.Hostname != "sw-a.lab.example.net" || s.applied != 1 || s.concurrent != 1 {
		t.Errorf("entry %+v applied %d concurrent %d", e, s.applied, s.concurrent)
	}
}

// A reported host name becomes the registry's hostname (the ssh target)
// only when the resolver answers it with the device's address and no other.
func TestSyncHostnameMustResolveToAddress(t *testing.T) {
	const addr = "192.168.1.31"
	for _, c := range []struct {
		name  string
		table map[string][]string
		fill  bool
	}{
		{"exact", map[string][]string{"sw-a.lab.example.net": {addr}}, true},
		{"the address twice", map[string][]string{"sw-a.lab.example.net": {addr, addr}}, true},
		{"another address", map[string][]string{"sw-a.lab.example.net": {"192.168.1.99"}}, false},
		{"the address and another", map[string][]string{"sw-a.lab.example.net": {addr, "192.168.1.99"}}, false},
		{"the address and an ipv6 one", map[string][]string{"sw-a.lab.example.net": {addr, "2001:db8::1"}}, false},
		{"an empty answer", map[string][]string{"sw-a.lab.example.net": {}}, false},
		{"a lookup failure", map[string][]string{}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newCollectBox(t)
			b.syncSeed("sw-a", addr, "sw-a.lab.example.net", `set snmp location "Lab rack 2"`)
			b.resolves(c.table)
			out := b.sync("-", "sw-a", "--apply", "--yes")
			if b.sb.code != 0 {
				t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
			}
			e := b.entry("sw-a")
			switch {
			case c.fill && (e.Hostname != "sw-a.lab.example.net" || !strings.Contains(out, "resolves to the address")):
				t.Errorf("not filled: %+v\n%s", e, out)
			case !c.fill && (e.Hostname != "" || !strings.Contains(out, "does not resolve: not filled")):
				t.Errorf("filled or unexplained: %+v\n%s", e, out)
			}
			// the location does not depend on the lookup
			if e.Location != "Lab rack 2" {
				t.Errorf("location %q", e.Location)
			}
		})
	}
}

// --overwrite follows the same rule: a set hostname is never replaced with
// one that does not resolve to the address, and the preview says so.
func TestSyncOverwriteHostnameMustResolve(t *testing.T) {
	b := newCollectBox(t)
	b.syncSeed("sw-a", "192.168.1.31", "sw-a.lab.example.net")
	if _, err := b.invoke().deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		f.Find("sw-a").Hostname = "old.lab.example.net"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.resolves(map[string][]string{"sw-a.lab.example.net": {"192.168.1.31", "10.9.9.9"}})
	out := b.sync("-", "sw-a", "--overwrite", "--apply", "--yes")
	if !strings.Contains(out, "does not resolve: not filled") || b.entry("sw-a").Hostname != "old.lab.example.net" {
		t.Errorf("unresolved name replaced a hostname:\n%s\n%+v", out, b.entry("sw-a"))
	}
	b.resolves(map[string][]string{"sw-a.lab.example.net": {"192.168.1.31"}})
	out = b.sync("-", "sw-a", "--overwrite")
	if !strings.Contains(out, "replace: resolves to the address") || !strings.Contains(out, "old.lab.example.net") {
		t.Errorf("preview:\n%s", out)
	}
	b.sync("-", "sw-a", "--overwrite", "--apply", "--yes")
	if b.entry("sw-a").Hostname != "sw-a.lab.example.net" {
		t.Errorf("resolved name not written: %+v", b.entry("sw-a"))
	}
	// without --overwrite a set hostname is kept and nothing is looked up
	b.sb.resolve = func(context.Context, string) ([]string, error) {
		t.Error("a lookup for a field that is not written")
		return nil, errors.New("no")
	}
	if _, err := b.invoke().deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		f.Find("sw-a").Hostname = "other.lab.example.net"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if out = b.sync("-", "sw-a"); !strings.Contains(out, "keep") {
		t.Errorf("keep:\n%s", out)
	}
}

func TestResolvesToOnly(t *testing.T) {
	res := func(a ...string) func(context.Context, string) ([]string, error) {
		return func(context.Context, string) ([]string, error) { return a, nil }
	}
	for _, c := range []struct {
		resolve func(context.Context, string) ([]string, error)
		addr    string
		want    bool
	}{
		{res("10.0.0.1"), "10.0.0.1", true},
		{res("10.0.0.1", "10.0.0.1"), "10.0.0.1", true},
		{res("2001:db8::1"), "2001:DB8:0::1", true},
		{res("10.0.0.2"), "10.0.0.1", false},
		{res("10.0.0.1", "10.0.0.2"), "10.0.0.1", false},
		{res("garbage"), "10.0.0.1", false},
		{res(), "10.0.0.1", false},
		{res("10.0.0.1"), "not-an-address", false},
		{func(context.Context, string) ([]string, error) { return []string{"10.0.0.1"}, errors.New("x") }, "10.0.0.1", false},
	} {
		if got := resolvesToOnly(context.Background(), c.resolve, "h.example.net", c.addr); got != c.want {
			t.Errorf("addr %q: %v", c.addr, got)
		}
	}
}

func TestSectionValue(t *testing.T) {
	for in, want := range map[string]string{
		`set snmp location "Lab rack 2"`:      "Lab rack 2",
		`set snmp location "a \"b\" c"`:       `a "b" c`,
		`set snmp location "back\\slash"`:     `back\slash`,
		`set snmp location bare`:              "bare",
		`set snmp contact "x"`:                "",
		`set snmp location "unterminated`:     "unterminated",
		`set snmp locationx "no"` + "\n" + "": "",
	} {
		if got := sectionValue([]string{in}, "snmp location"); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
