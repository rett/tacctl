package devreg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RenameHost moves the record of the host whole: keys, address, history,
// acknowledgements; a leftover of the new name is replaced.
func TestRenameHost(t *testing.T) {
	ed, ec := testKey(t, "ed25519"), testKey(t, "ecdsa")
	f := Empty()
	f.SetHostKeys("web1", []string{ed.String()})
	f.SetHostAddress("web1", "192.0.2.50", "2026-10-04 12:00")
	f.SetHostAddress("web1", "192.0.2.51", "2026-10-04 14:00")
	f.Host("web1").Ack = []string{NoticeAddressChanged}
	f.SetHostKeys("web2", []string{ec.String()})
	f.SetHostAddress("web9", "192.0.2.99", "2026-10-04 12:00") // a leftover

	if !f.RenameHost("web1", "web9") {
		t.Fatal("not moved")
	}
	if f.Host("web1") != nil || len(f.Hosts) != 2 {
		t.Fatalf("hosts %+v", f.Hosts)
	}
	h := f.Host("web9")
	if h == nil || h.Name != "web9" || h.Address != "192.0.2.51" || h.PrevAddress != "192.0.2.50" || h.Changed != "2026-10-04 14:00" ||
		len(h.Keys) != 1 || len(h.Ack) != 1 {
		t.Fatalf("moved record %+v", h)
	}
	if f.Hosts[0].Name != "web2" || f.Hosts[1].Name != "web9" {
		t.Errorf("not sorted: %+v", f.Hosts)
	}
	if text, err := f.Text(); err != nil || !strings.Contains(string(text), "web9:") {
		t.Errorf("%v\n%s", err, text)
	}

	// A host with no record moves nothing; a leftover of the new name still
	// goes (nothing may stay under it).
	if f.RenameHost("ghost", "web2") {
		t.Error("moved a record that is not there")
	}
	if f.Host("web2") != nil {
		t.Error("the leftover of the new name stayed")
	}

	// A change of spelling renames the one record.
	g := Empty()
	g.SetHostKeys("web1", []string{ed.String()})
	if !g.RenameHost("web1", "Web1") || len(g.Hosts) != 1 || g.Hosts[0].Name != "Web1" || len(g.Hosts[0].Keys) != 1 {
		t.Errorf("spelling: %+v", g.Hosts)
	}
}

// Mutate with a rename leaves known_hosts listing the keys under the new name.
func TestRenameHostRegeneratesKnownHosts(t *testing.T) {
	dir := t.TempDir()
	path, kh := filepath.Join(dir, "devices.yaml"), filepath.Join(dir, "known_hosts")
	ed := testKey(t, "ed25519")
	if _, err := Mutate(path, kh, nil, func(f *File) error {
		f.SetHostKeys("web1", []string{ed.String()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Mutate(path, kh, nil, func(f *File) error { f.RenameHost("web1", "web9"); return nil }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(kh)
	if err != nil || !strings.Contains(string(data), "web9") || strings.Contains(string(data), "web1") {
		t.Errorf("known_hosts %q %v", data, err)
	}
}

func TestSeenRenameKeyScan(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s := NewSeen()
	s.RecordKeyScan("Web1", "192.0.2.5", 22, nil, t0)
	s.RecordKeyScan("web9", "192.0.2.9", 22, nil, t0)
	if !s.HasKeyScanFor("web1") || s.HasKeyScanFor("nobody") {
		t.Error("HasKeyScanFor")
	}
	if s.RenameKeyScan("web1", "WEB1") {
		t.Error("a change of spelling moved a key")
	}
	if !s.RenameKeyScan("WEB1", "web9") {
		t.Fatal("not renamed")
	}
	if k, ok := s.KeyScanOf("web9"); !ok || k.Address != "192.0.2.5" {
		t.Errorf("moved %+v %v", k, ok)
	}
	if _, ok := s.KeyScanOf("web1"); ok {
		t.Error("the old key stayed")
	}
	// No result for the old name: the new name's is a stranger's and goes.
	if !s.RenameKeyScan("ghost", "web9") || s.HasKeyScanFor("web9") {
		t.Error("a leftover stayed")
	}
	if s.RenameKeyScan("ghost", "web9") {
		t.Error("changed nothing but said it did")
	}
}

func TestCheckRenameHostName(t *testing.T) {
	reg := hostRegistry(t, "web1|root@w||lab|1.1.1.1|\nDB2|root@d||lab|1.1.1.1|\nweb3|root@e||lab|1.1.1.1|\n")
	f := Empty()
	f.Devices = []*Device{{Name: "core-sw1", Address: "192.0.2.77", Vendor: "cisco"}}
	for _, c := range []struct{ old, new, want string }{
		{"web1", "web9", ""},
		{"web1", "Web1", ""}, // the host is exempt from its own name
		{"DB2", "db2", ""},
		{"web1", "all", "'all' is a tacctl word and cannot name a host. Nothing was changed."},
		{"web1", "Scope", "tacctl word"},
		{"web1", "web3", "A host named 'web3' is already enrolled"},
		{"web1", "WEB3", "'web3' is enrolled; names are not case-sensitive. Nothing was changed."},
		{"web1", "db2", "'DB2' is enrolled; names are not case-sensitive"},
		{"web1", "Core-SW1", "'core-sw1' is already registered as a device (192.0.2.77)"},
		{"web1", "switch", "generic name"},
	} {
		err := CheckRenameHostName(reg, f, c.old, c.new)
		if (c.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s -> %s: %v, want %q", c.old, c.new, err, c.want)
		}
	}
	// An old host that carries a generic name may change its spelling.
	old := hostRegistry(t, "switch|root@w||lab|1.1.1.1|\n")
	if err := CheckRenameHostName(old, f, "switch", "Switch"); err != nil {
		t.Errorf("spelling of a generic name: %v", err)
	}
}

func TestSeenForgetKeyScan(t *testing.T) {
	s := NewSeen()
	s.RecordKeyScan("Web1", "192.0.2.5", 22, nil, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	if s.ForgetKeyScan("nobody") {
		t.Error("reported a change for a name it does not keep")
	}
	if !s.ForgetKeyScan("WEB1") || s.HasKeyScanFor("web1") {
		t.Error("the result stayed")
	}
	if s.ForgetKeyScan("web1") {
		t.Error("reported a change twice")
	}
	var none *Seen
	if none.ForgetKeyScan("web1") {
		t.Error("a nil cache changed")
	}
}
