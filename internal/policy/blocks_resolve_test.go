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
	if b, err := ResolveSNMPBlock(store, c, "lab"); b != nil || err != nil {
		t.Fatalf("not in force: %v %v", b, err)
	}
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	b, err := ResolveSNMPBlock(store, c, "lab")
	if err != nil || b == nil || len(b.Communities) != 1 || len(b.TrapGroups) != 1 {
		t.Fatalf("in force: %v %v", b, err)
	}
	// other scopes and vendors have none; so does a nil store
	for _, scope := range []string{"dmz", "devices", "no/such"} {
		if b, err := ResolveSNMPBlock(store, c, scope); b != nil || err != nil {
			t.Errorf("%s: %v %v", scope, b, err)
		}
	}
	if b, err := ResolveSNMPBlock(nil, c, "lab"); b != nil || err != nil {
		t.Errorf("no store: %v %v", b, err)
	}
	// a name in force with no file renders nothing ('check' says so)
	if err := SetBlockInForce(c, "dmz", blocks.VendorJuniper, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	if b, err := ResolveSNMPBlock(store, c, "dmz"); b != nil || err != nil {
		t.Errorf("no file: %v %v", b, err)
	}
	// only a note (a community open to every client): rendered
	open := "set snmp community nms-ro authorization read-only\nset snmp community nms-ro clients 0.0.0.0/0 restrict\n"
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSNMP, []byte(open)); err != nil {
		t.Fatal(err)
	}
	if b, err := ResolveSNMPBlock(store, c, "lab"); b == nil || err != nil {
		t.Errorf("a block with notes only: %v %v", b, err)
	}

	// errors: never half a block, no string in the refusal
	bad := good + "set snmp community secretive-two authorization read-only\nset snmp trap-group TACCTL-SNMP targets 198.51.100.7\n"
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSNMP, []byte(bad)); err != nil {
		t.Fatal(err)
	}
	b, err = ResolveSNMPBlock(store, c, "lab")
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
	if b, err := ResolveSystemBlock(store, c, "lab"); b != nil || err != nil {
		t.Fatalf("not in force: %v %v", b, err)
	}
	// the snmp block's entry is not the system block's
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSNMP, true); err != nil {
		t.Fatal(err)
	}
	if b, err := ResolveSystemBlock(store, c, "lab"); b != nil || err != nil {
		t.Fatalf("the snmp entry: %v %v", b, err)
	}
	if err := SetBlockInForce(c, "lab", blocks.VendorJuniper, blocks.BlockSystem, true); err != nil {
		t.Fatal(err)
	}
	b, err := ResolveSystemBlock(store, c, "lab")
	if err != nil || b == nil || b.Message == nil || b.DomainName == nil || len(b.NameServers) != 1 || len(b.NTPServers) != 1 || len(b.NTPKeys) != 1 {
		t.Fatalf("in force: %v %v", b, err)
	}
	// other scopes have none; so does a nil store
	for _, scope := range []string{"dmz", "devices", "no/such"} {
		if b, err := ResolveSystemBlock(store, c, scope); b != nil || err != nil {
			t.Errorf("%s: %v %v", scope, b, err)
		}
	}
	if b, err := ResolveSystemBlock(nil, c, "lab"); b != nil || err != nil {
		t.Errorf("no store: %v %v", b, err)
	}
	// a name in force with no file renders nothing ('check' says so)
	if err := SetBlockInForce(c, "dmz", blocks.VendorJuniper, blocks.BlockSystem, true); err != nil {
		t.Fatal(err)
	}
	if b, err := ResolveSystemBlock(store, c, "dmz"); b != nil || err != nil {
		t.Errorf("no file: %v %v", b, err)
	}
	// a block of delete lines renders nothing
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSystem, []byte("delete system ntp\n")); err != nil {
		t.Fatal(err)
	}
	if b, err := ResolveSystemBlock(store, c, "lab"); b != nil || err != nil {
		t.Errorf("delete lines only: %v %v", b, err)
	}

	// errors: never half a block, no message and no key in the refusal
	bad := good + "set system login message <<'EOF'\nSecond banner.\nEOF\nset system time-zone not/valid\x01\n"
	if err := store.Write(lab, blocks.VendorJuniper, blocks.BlockSystem, []byte(bad)); err != nil {
		t.Fatal(err)
	}
	b, err = ResolveSystemBlock(store, c, "lab")
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
