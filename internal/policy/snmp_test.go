package policy

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

func TestSNMPClientsAddRemoveOrder(t *testing.T) {
	c, path := newConf(t, "")
	if got := SNMPClients(c, "lab"); len(got) != 0 {
		t.Fatalf("empty: %q", got)
	}
	added, skipped, err := AddSNMPClients(c, "lab", []string{"198.51.100.0/24", "10.0.0.0/8", "192.0.2.7/32"})
	if err != nil || len(added) != 3 || len(skipped) != 0 {
		t.Fatalf("add: %q %q %v", added, skipped, err)
	}
	// The order given is kept, and what is there is not added again.
	added, skipped, err = AddSNMPClients(c, "lab", []string{"10.0.0.0/8", "172.16.0.0/12"})
	if err != nil || !reflect.DeepEqual(added, []string{"172.16.0.0/12"}) || !reflect.DeepEqual(skipped, []string{"10.0.0.0/8"}) {
		t.Fatalf("add again: %q %q %v", added, skipped, err)
	}
	want := []string{"198.51.100.0/24", "10.0.0.0/8", "192.0.2.7/32", "172.16.0.0/12"}
	if got := SNMPClients(c, "lab"); !reflect.DeepEqual(got, want) {
		t.Errorf("list: %q", got)
	}
	if got := SNMPClients(c, "prod"); len(got) != 0 {
		t.Errorf("another scope: %q", got)
	}
	// Nothing new: nothing written.
	before, _ := os.ReadFile(path)
	if a, _, err := AddSNMPClients(c, "lab", []string{"10.0.0.0/8"}); err != nil || a != nil {
		t.Errorf("no-op add: %q %v", a, err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("a no-op add rewrote the file")
	}
	removed, missing, err := RemoveSNMPClients(c, "lab", []string{"10.0.0.0/8", "203.0.113.0/24"})
	if err != nil || !reflect.DeepEqual(removed, []string{"10.0.0.0/8"}) || !reflect.DeepEqual(missing, []string{"203.0.113.0/24"}) {
		t.Fatalf("remove: %q %q %v", removed, missing, err)
	}
	if got := SNMPClients(c, "lab"); !reflect.DeepEqual(got, []string{"198.51.100.0/24", "192.0.2.7/32", "172.16.0.0/12"}) {
		t.Errorf("after remove: %q", got)
	}
	// Removing the last ones removes the key, and the file with it.
	if _, _, err := RemoveSNMPClients(c, "lab", SNMPClients(c, "lab")); err != nil {
		t.Fatal(err)
	}
	if c.HasOverride("snmp_scope.lab.clients") || c.HasOverride("snmp_scope") {
		t.Error("an empty list left a key")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("tacctl.yaml kept: %v", err)
	}
}

// What the schema refuses is never stored.
func TestSNMPClientsValidation(t *testing.T) {
	c, path := newConf(t, "")
	for _, bad := range [][]string{
		{"0.0.0.0/0"}, {"192.0.2.0/24", "0.0.0.0/0"}, {"2001:db8::/32"}, {"192.0.2.7"}, {"192.0.2.5/24"}, {"junk"},
		{"192.0.2.0/24", "192.0.2.0/24"},
	} {
		if err := SetSNMPClients(c, "lab", bad); err == nil {
			t.Errorf("%q stored", bad)
		}
	}
	var many []string
	for i := 0; i < 33; i++ {
		many = append(many, "10.0."+strconv.Itoa(i)+".0/24")
	}
	if err := SetSNMPClients(c, "lab", many[:32]); err != nil {
		t.Errorf("32 entries: %v", err)
	}
	err := SetSNMPClients(c, "lab", many)
	if err == nil || !strings.Contains(err.Error(), "at most 32") {
		t.Errorf("33 entries: %v", err)
	}
	// Not a key of the scope: refused.
	if err := c.Set("snmp_scope.lab.nosuch", "x"); err == nil {
		t.Error("an unknown setting stored")
	}
	if err := c.Set("snmp_scope.lab.v3.nosuch", "x"); err == nil {
		t.Error("an unknown v3 setting stored")
	}
	_ = path
}

func TestSNMPContactAndSettings(t *testing.T) {
	c, path := newConf(t, "")
	if SNMPContact(c, "lab") != "" || SNMPSet(c, "lab") {
		t.Error("something is set")
	}
	if err := SetSNMPContact(c, "lab", "NOC <noc@example.net>"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "  ", "a\nb", "what?", strings.Repeat("x", 121), "tab\there"} {
		if err := SetSNMPContact(c, "lab", bad); err == nil {
			t.Errorf("contact %q stored", bad)
		}
	}
	if err := SetSNMPContact(c, "lab", strings.Repeat("é", 120)); err != nil {
		t.Errorf("120 characters: %v", err)
	}
	if err := SetSNMPContact(c, "lab", "NOC <noc@example.net>"); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"version": "v3", "port": "1161", "timeout": "5", "v3.auth": "sha256", "v3.priv": "aes128"} {
		if err := c.Set(conf.SNMPPath("lab", k), v); err != nil {
			t.Fatalf("%s: %v", k, err)
		}
	}
	got := SNMPSettings(c, "lab")
	want := SNMPScope{Version: "v3", Port: 1161, Timeout: 5, Auth: "sha256", Priv: "aes128", Contact: "NOC <noc@example.net>"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("settings: %+v", got)
	}
	if !SNMPSet(c, "lab") || SNMPSet(c, "prod") {
		t.Error("SNMPSet")
	}
	for k, bad := range map[string]string{"version": "v1", "port": "0", "timeout": "11", "v3.auth": "md5", "v3.priv": "des"} {
		if err := c.Set(conf.SNMPPath("lab", k), bad); err == nil {
			t.Errorf("%s=%s stored", k, bad)
		}
	}
	// Move follows a rename; nothing of the old name is left.
	lost, err := MoveSNMPScope(c, "lab", "lab2")
	if err != nil || len(lost) != 0 {
		t.Fatalf("move: %q %v", lost, err)
	}
	if got := SNMPSettings(c, "lab2"); !reflect.DeepEqual(got, want) {
		t.Errorf("moved: %+v", got)
	}
	if SNMPSet(c, "lab") {
		t.Error("old name keeps settings")
	}
	// Dropping a scope takes its keys, and the file when nothing is left.
	if _, err := MoveSNMPScope(c, "lab2", ""); err != nil {
		t.Fatal(err)
	}
	if SNMPSet(c, "lab2") {
		t.Error("dropped scope keeps settings")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("tacctl.yaml kept: %v", err)
	}
}

// A tacctl.yaml that never had a scope's SNMP setting is not rewritten by a
// read, and the keys are written only when set.
func TestSNMPKeysOnlyWhenSet(t *testing.T) {
	c, path := newConf(t, "scope:\n  default: lab\n")
	before, _ := os.ReadFile(path)
	_ = SNMPSettings(c, "lab")
	_ = SNMPClients(c, "lab")
	_ = SNMPContact(c, "lab")
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("reading rewrote tacctl.yaml")
	}
	if err := SetSNMPContact(c, "lab", "x"); err != nil {
		t.Fatal(err)
	}
	if err := ClearSNMPKey(c, "lab", conf.SNMPKeyContact); err != nil {
		t.Fatal(err)
	}
	if got := file(t, path); strings.Contains(got, "snmp_scope") {
		t.Errorf("a cleared key stays:\n%s", got)
	}
}
