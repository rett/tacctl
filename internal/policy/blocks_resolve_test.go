package policy

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
)

// ResolveSNMPBlock: nothing for a scope with no block in force or no file, the
// block when it is whole, and a refusal that names the scope and the verb and
// holds no string when it is not.
func TestResolveSNMPBlock(t *testing.T) {
	c, _ := newConf(t, "")
	store := blocks.NewStore(t.TempDir())
	lab := blocks.ScopeLevel("lab")
	good := "set snmp community nms-ro authorization read-only\nset snmp community nms-ro clients 192.0.2.50/32\n" +
		"set snmp trap-group nms-traps targets 198.51.100.7\n"

	// no manifest entry: a file alone is ignored
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSNMP, []byte(good)); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveSNMPBlock(store, c, "lab", ""); b != nil || err != nil {
		t.Fatalf("not in force: %v %v", b, err)
	}
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	b, _, err := ResolveSNMPBlock(store, c, "lab", "")
	if err != nil || b == nil || len(b.Communities) != 1 || len(b.TrapGroups) != 1 {
		t.Fatalf("in force: %v %v", b, err)
	}
	// other scopes and vendors have none; so does a nil store
	for _, scope := range []string{"dmz", "devices", "no/such"} {
		if b, _, err := ResolveSNMPBlock(store, c, scope, ""); b != nil || err != nil {
			t.Errorf("%s: %v %v", scope, b, err)
		}
	}
	if b, _, err := ResolveSNMPBlock(nil, c, "lab", ""); b != nil || err != nil {
		t.Errorf("no store: %v %v", b, err)
	}
	// a name in force with no file renders nothing ('check' says so)
	if err := SetBlockInForce(c, "dmz", blocks.VendorJuniper, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveSNMPBlock(store, c, "dmz", ""); b != nil || err != nil {
		t.Errorf("no file: %v %v", b, err)
	}
	// only a note (a community open to every client): rendered
	open := "set snmp community nms-ro authorization read-only\nset snmp community nms-ro clients 0.0.0.0/0 restrict\n"
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSNMP, []byte(open)); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveSNMPBlock(store, c, "lab", ""); b == nil || err != nil {
		t.Errorf("a block with notes only: %v %v", b, err)
	}

	// errors: never half a block, no string in the refusal
	bad := good + "set snmp community secretive-two authorization read-only\nset snmp trap-group TACCTL-SNMP targets 198.51.100.7\n"
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSNMP, []byte(bad)); err != nil {
		t.Fatal(err)
	}
	b, _, err = ResolveSNMPBlock(store, c, "lab", "")
	if b != nil || err == nil {
		t.Fatalf("a block with errors: %v %v", b, err)
	}
	for _, want := range []string{"scope 'lab'", "tacctl scope block lab juniper check snmp", "line 5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q:\n%s", want, err)
		}
	}
	for _, s := range []string{"nms-ro", "nms-traps", "secretive-two"} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("the refusal holds %q:\n%s", s, err)
		}
	}
	// the first line is the whole story (a batch keeps only that)
	first, _, _ := strings.Cut(err.Error(), "\n")
	if !strings.Contains(first, "scope 'lab'") || !strings.Contains(first, "tacctl scope block lab juniper check snmp") {
		t.Errorf("the first line: %q", first)
	}
}

// ResolveSystemBlock: the same rules for the system block, and a refusal that
// holds no word of the message and no key.
func TestResolveSystemBlock(t *testing.T) {
	c, _ := newConf(t, "")
	store := blocks.NewStore(t.TempDir())
	lab := blocks.ScopeLevel("lab")
	good := "set system login message <<'EOF'\nAuthorized use only.\nEOF\nset system domain-name lab.example.net\n" +
		"set system name-server 192.0.2.53\nset system ntp server 192.0.2.123 prefer\n" +
		"set system ntp authentication-key 1 type md5 value ntp-key-0123456789\n"

	// no manifest entry: a file alone is ignored
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSystem, []byte(good)); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveSystemBlock(store, c, "lab", ""); b != nil || err != nil {
		t.Fatalf("not in force: %v %v", b, err)
	}
	// the snmp block's entry is not the system block's
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveSystemBlock(store, c, "lab", ""); b != nil || err != nil {
		t.Fatalf("the snmp entry: %v %v", b, err)
	}
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSystem, true); err != nil {
		t.Fatal(err)
	}
	b, _, err := ResolveSystemBlock(store, c, "lab", "")
	if err != nil || b == nil || b.Message == nil || b.DomainName == nil || len(b.NameServers) != 1 || len(b.NTPServers) != 1 || len(b.NTPKeys) != 1 {
		t.Fatalf("in force: %v %v", b, err)
	}
	// other scopes have none; so does a nil store
	for _, scope := range []string{"dmz", "devices", "no/such"} {
		if b, _, err := ResolveSystemBlock(store, c, scope, ""); b != nil || err != nil {
			t.Errorf("%s: %v %v", scope, b, err)
		}
	}
	if b, _, err := ResolveSystemBlock(nil, c, "lab", ""); b != nil || err != nil {
		t.Errorf("no store: %v %v", b, err)
	}
	// a name in force with no file renders nothing ('check' says so)
	if err := SetBlockInForce(c, "dmz", blocks.VendorJuniper, blocks.BlockSystem, true); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveSystemBlock(store, c, "dmz", ""); b != nil || err != nil {
		t.Errorf("no file: %v %v", b, err)
	}
	// a block of delete lines renders nothing
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSystem, []byte("delete system ntp\n")); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveSystemBlock(store, c, "lab", ""); b != nil || err != nil {
		t.Errorf("delete lines only: %v %v", b, err)
	}

	// errors: never half a block, no message and no key in the refusal
	bad := good + "set system login message <<'EOF'\nSecond banner.\nEOF\nset system time-zone not/valid\x01\n"
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSystem, []byte(bad)); err != nil {
		t.Fatal(err)
	}
	b, _, err = ResolveSystemBlock(store, c, "lab", "")
	if b != nil || err == nil {
		t.Fatalf("a block with errors: %v %v", b, err)
	}
	for _, want := range []string{"The system block of scope 'lab'", "tacctl scope block lab juniper check system", "line "} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q:\n%s", want, err)
		}
	}
	for _, s := range []string{"Authorized", "Second banner", "ntp-key-0123456789"} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("the refusal holds %q:\n%s", s, err)
		}
	}
	first, _, _ := strings.Cut(err.Error(), "\n")
	if !strings.Contains(first, "scope 'lab'") || !strings.Contains(first, "tacctl scope block lab juniper check system") {
		t.Errorf("the first line: %q", first)
	}
}

// The device's own block is laid over the scope's, per object: a community
// the device states replaces the scope's of the same string whole, the scope's
// others stay, and the layers say where the result came from.
func TestResolveWithTheDevicesOwnBlock(t *testing.T) {
	c, _ := newConf(t, "")
	store := blocks.NewStore(t.TempDir())
	scope, dev := blocks.ScopeLevel("lab"), blocks.DeviceLevel("JSW1.lab.example.net")
	scopeText := "set snmp community nms-ro authorization read-only\nset snmp community nms-ro clients 192.0.2.50/32\n" +
		"set snmp community poller-two authorization read-only\nset snmp community poller-two clients 192.0.2.60/32\n"
	devText := "set snmp community nms-ro authorization read-write\nset snmp community nms-ro clients 198.51.100.0/24\n" +
		"set snmp community dev-extra authorization read-only\nset snmp community dev-extra clients 203.0.113.9/32\n"
	for _, w := range []struct {
		l    blocks.Level
		text string
	}{{scope, scopeText}, {dev, devText}} {
		if err := store.Write(w.l, blocks.VendorJuniper, blocks.BlockSNMP, []byte(w.text)); err != nil {
			t.Fatal(err)
		}
	}
	// nothing is in force: no layer
	if b, l, err := ResolveSNMPBlock(store, c, "lab", "jsw1.lab.example.net"); b != nil || l != (BlockLayers{}) || err != nil {
		t.Fatalf("nothing in force: %v %v %v", b, l, err)
	}
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	// the scope's alone, for a device with none of its own and for the scope
	for _, device := range []string{"", "jsw1.lab.example.net"} {
		b, l, err := ResolveSNMPBlock(store, c, "lab", device)
		if err != nil || b == nil || l != (BlockLayers{Scope: true}) || len(b.Communities) != 2 || b.Communities[0].Authorization != "read-only" {
			t.Fatalf("scope only (%q): %v %v %v", device, b, l, err)
		}
	}
	if err := SetDeviceBlockInForce(c, "JSW1.lab.example.net", blocks.VendorJuniper, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	b, l, err := ResolveSNMPBlock(store, c, "lab", "JSW1.lab.example.net")
	if err != nil || b == nil || l != (BlockLayers{Scope: true, Device: true}) {
		t.Fatalf("both: %v %v %v", b, l, err)
	}
	var got []string
	for _, cm := range b.Communities {
		got = append(got, cm.String+":"+cm.Authorization)
	}
	if want := "nms-ro:read-write poller-two:read-only dev-extra:read-only"; strings.Join(got, " ") != want {
		t.Errorf("communities %q, want %q", strings.Join(got, " "), want)
	}
	if st := blocks.Statements(b); strings.Contains(strings.Join(st, "\n"), "192.0.2.50") {
		t.Errorf("the scope's client of the replaced community stayed:\n%s", strings.Join(st, "\n"))
	}
	// the scope alone is what the scope's own render sees
	if _, l, _ := ResolveSNMPBlock(store, c, "lab", ""); l != (BlockLayers{Scope: true}) {
		t.Errorf("scope layers: %v", l)
	}
	// the device's alone: the scope has none in force
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSNMP, false); err != nil {
		t.Fatal(err)
	}
	b, l, err = ResolveSNMPBlock(store, c, "lab", "jsw1.lab.example.net")
	if err != nil || b == nil || l != (BlockLayers{Device: true}) || len(b.Communities) != 2 {
		t.Errorf("device only: %v %v %v", b, l, err)
	}
	// a device's block with an error refuses that device, naming it and its verb
	if err := store.Write(dev, blocks.VendorJuniper, blocks.BlockSNMP, []byte(devText+"set snmp community short authorization read-only\n")); err != nil {
		t.Fatal(err)
	}
	b, _, err = ResolveSNMPBlock(store, c, "lab", "jsw1.lab.example.net")
	if b != nil || err == nil {
		t.Fatalf("a device block with errors: %v %v", b, err)
	}
	first, _, _ := strings.Cut(err.Error(), "\n")
	for _, want := range []string{"The snmp block of device 'jsw1.lab.example.net' has errors", "tacctl device block jsw1.lab.example.net check snmp"} {
		if !strings.Contains(first, want) {
			t.Errorf("the first line lacks %q: %q", want, first)
		}
	}
	for _, s := range []string{"nms-ro", "dev-extra", "short"} {
		if strings.Contains(err.Error(), s) {
			t.Errorf("the refusal holds %q:\n%s", s, err)
		}
	}
	// the same device without the device argument is untouched by it
	if _, _, err := ResolveSNMPBlock(store, c, "lab", ""); err != nil {
		t.Errorf("the scope's render: %v", err)
	}
}

func TestResolveSystemBlockWithTheDevicesOwn(t *testing.T) {
	c, _ := newConf(t, "")
	store := blocks.NewStore(t.TempDir())
	scope, dev := blocks.ScopeLevel("lab"), blocks.DeviceLevel("sw1")
	scopeText := "set system domain-name lab.example.net\nset system time-zone UTC\nset system name-server 192.0.2.53\n"
	devText := "set system domain-name sw1.lab.example.net\nset system name-server 192.0.2.54\ndelete system time-zone\n"
	if err := store.Write(scope, blocks.VendorJuniper, blocks.BlockSystem, []byte(scopeText)); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(dev, blocks.VendorJuniper, blocks.BlockSystem, []byte(devText)); err != nil {
		t.Fatal(err)
	}
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSystem, true); err != nil {
		t.Fatal(err)
	}
	if err := SetDeviceBlockInForce(c, "sw1", blocks.VendorJuniper, blocks.BlockSystem, true); err != nil {
		t.Fatal(err)
	}
	b, l, err := ResolveSystemBlock(store, c, "lab", "sw1")
	if err != nil || b == nil || l != (BlockLayers{Scope: true, Device: true}) {
		t.Fatalf("%v %v %v", b, l, err)
	}
	want := "set system domain-name sw1.lab.example.net\nset system name-server 192.0.2.53\nset system name-server 192.0.2.54"
	if got := strings.Join(blocks.SystemStatements(b), "\n"); got != want {
		t.Errorf("statements:\n%s\nwant\n%s", got, want)
	}
	// a device block of delete lines alone renders what the scope has
	if err := store.Write(dev, blocks.VendorJuniper, blocks.BlockSystem, []byte("delete system domain-name\n")); err != nil {
		t.Fatal(err)
	}
	b, _, err = ResolveSystemBlock(store, c, "lab", "sw1")
	if err != nil || b == nil || strings.Contains(strings.Join(blocks.SystemStatements(b), "\n"), "domain-name") {
		t.Errorf("delete: %v %v", b, err)
	}
	// errors name the device and the verb, and no word of a message
	if err := store.Write(dev, blocks.VendorJuniper, blocks.BlockSystem, []byte("set system login message <<'EOF'\nSecret banner text\nEOF\nset system time-zone\n")); err != nil {
		t.Fatal(err)
	}
	_, _, err = ResolveSystemBlock(store, c, "lab", "sw1")
	if err == nil || !strings.Contains(err.Error(), "The system block of device 'sw1' has errors") ||
		!strings.Contains(err.Error(), "tacctl device block sw1 check system") || strings.Contains(err.Error(), "Secret banner") {
		t.Errorf("errors: %v", err)
	}
}

// The IOS snmp block: the cisco manifest and files, the device's block over
// the scope's, and a refusal that names the verb and holds no string.
func TestResolveIOSSNMPBlock(t *testing.T) {
	c, _ := newConf(t, "")
	store := blocks.NewStore(t.TempDir())
	lab := blocks.ScopeLevel("lab")
	good := "ip access-list standard POLLERS\n permit host 192.0.2.50\nsnmp-server community nms-ro RO POLLERS\nsnmp-server enable traps config\n"
	if err := store.Write(lab, blocks.VendorCisco, blocks.BlockSNMP, []byte(good)); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveIOSSNMPBlock(store, c, "lab", ""); b != nil || err != nil {
		t.Fatalf("not in force: %v %v", b, err)
	}
	// a Junos block of the same scope is another vendor's
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveIOSSNMPBlock(store, c, "lab", ""); b != nil || err != nil {
		t.Fatalf("the Junos entry: %v %v", b, err)
	}
	if err := SetBlockInForce(c, "lab", blocks.VendorCisco, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	b, layers, err := ResolveIOSSNMPBlock(store, c, "lab", "")
	if err != nil || b == nil || len(b.Communities) != 1 || len(b.ACLs) != 1 || len(b.Traps) != 1 || !layers.Scope || layers.Device {
		t.Fatalf("in force: %v %+v %v", b, layers, err)
	}
	// the device's own over it, by object
	dev := blocks.DeviceLevel("rt1")
	if err := store.Write(dev, blocks.VendorCisco, blocks.BlockSNMP, []byte("no snmp-server community nms-ro\nsnmp-server enable traps tty\n")); err != nil {
		t.Fatal(err)
	}
	if err := SetDeviceBlockInForce(c, "rt1", blocks.VendorCisco, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	b, layers, err = ResolveIOSSNMPBlock(store, c, "lab", "rt1")
	if err != nil || b == nil || len(b.Communities) != 0 || len(b.Traps) != 2 || !layers.Scope || !layers.Device {
		t.Fatalf("with the device's: %v %+v %v", b, layers, err)
	}
	// errors: never half a block, no string
	if err := store.Write(lab, blocks.VendorCisco, blocks.BlockSNMP, []byte(good+"snmp-server community secretive-rw RW\n")); err != nil {
		t.Fatal(err)
	}
	b, _, err = ResolveIOSSNMPBlock(store, c, "lab", "")
	if b != nil || err == nil {
		t.Fatalf("a block with errors: %v %v", b, err)
	}
	for _, want := range []string{"scope 'lab'", "tacctl scope block lab cisco check snmp", "the scope's IOS devices", "line 5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), "secretive-rw") || strings.Contains(err.Error(), "nms-ro") {
		t.Errorf("the refusal holds a string:\n%s", err)
	}
	// texts in hand
	if b, _, err := ResolveIOSSNMPTexts("lab", "", nil, nil); b != nil || err != nil {
		t.Errorf("no text: %v %v", b, err)
	}
	if b, _, err := ResolveIOSSNMPTexts("lab", "", []byte("# nothing\n"), nil); b != nil || err != nil {
		t.Errorf("comments only: %v %v", b, err)
	}
}

// The IOS system block: the cisco manifest and files, the device's block over
// the scope's, and a refusal that names the verb and holds neither the
// banner nor a key.
func TestResolveIOSSystemBlock(t *testing.T) {
	c, _ := newConf(t, "")
	store := blocks.NewStore(t.TempDir())
	lab := blocks.ScopeLevel("lab")
	good := "banner login <<'EOF'\nSecret banner Qx7\nEOF\nip domain name lab.example.net\nip name-server 192.0.2.53\nntp authentication-key 5 md5 sekret-ntp-key\nntp trusted-key 5\n"
	if err := store.Write(lab, blocks.VendorCisco, blocks.BlockSystem, []byte(good)); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveIOSSystemBlock(store, c, "lab", ""); b != nil || err != nil {
		t.Fatalf("not in force: %v %v", b, err)
	}
	// the Junos entry is another vendor's
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSystem, true); err != nil {
		t.Fatal(err)
	}
	if b, _, err := ResolveIOSSystemBlock(store, c, "lab", ""); b != nil || err != nil {
		t.Fatalf("the Junos entry: %v %v", b, err)
	}
	if err := SetBlockInForce(c, "lab", blocks.VendorCisco, blocks.BlockSystem, true); err != nil {
		t.Fatal(err)
	}
	b, layers, err := ResolveIOSSystemBlock(store, c, "lab", "")
	if err != nil || b == nil || b.Banner == nil || b.DomainName == nil || len(b.NameServers) != 1 || len(b.NTPKeys) != 1 || !layers.Scope || layers.Device {
		t.Fatalf("in force: %v %+v %v", b, layers, err)
	}
	// the device's own over it, by object
	dev := blocks.DeviceLevel("rt1")
	if err := store.Write(dev, blocks.VendorCisco, blocks.BlockSystem, []byte("no banner login\nno ip name-server\nip name-server 192.0.2.99\nntp server 192.0.2.1\n")); err != nil {
		t.Fatal(err)
	}
	if err := SetDeviceBlockInForce(c, "rt1", blocks.VendorCisco, blocks.BlockSystem, true); err != nil {
		t.Fatal(err)
	}
	b, layers, err = ResolveIOSSystemBlock(store, c, "lab", "rt1")
	if err != nil || b == nil || b.Banner != nil || len(b.NameServers) != 1 || b.NameServers[0].Text != "192.0.2.99" || len(b.NTPServers) != 1 || !layers.Scope || !layers.Device {
		t.Fatalf("with the device's: %+v %+v %v", b, layers, err)
	}
	// errors: never half a block, no banner and no key in the refusal
	if err := store.Write(lab, blocks.VendorCisco, blocks.BlockSystem, []byte(good+"ntp authentication-key 6 sha1 sekret-ntp-key2\n")); err != nil {
		t.Fatal(err)
	}
	b, _, err = ResolveIOSSystemBlock(store, c, "lab", "")
	if b != nil || err == nil {
		t.Fatalf("a block with errors: %v %v", b, err)
	}
	for _, want := range []string{"scope 'lab'", "tacctl scope block lab cisco check system", "the scope's IOS devices", "line 8"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q:\n%s", want, err)
		}
	}
	for _, bad := range []string{"Secret banner", "sekret-ntp-key"} {
		if strings.Contains(err.Error(), bad) {
			t.Errorf("the refusal holds %q:\n%s", bad, err)
		}
	}
	// a block of no statement renders nothing; texts in hand
	if b, _, err := ResolveIOSSystemTexts("lab", "", []byte("no ntp\n"), nil); b != nil || err != nil {
		t.Errorf("no lines only: %v %v", b, err)
	}
	if b, _, err := ResolveIOSSystemTexts("lab", "", nil, nil); b != nil || err != nil {
		t.Errorf("no text: %v %v", b, err)
	}
	if b, _, err := ResolveIOSSystemTexts("lab", "", []byte("! nothing\n"), nil); b != nil || err != nil {
		t.Errorf("comments only: %v %v", b, err)
	}
}
