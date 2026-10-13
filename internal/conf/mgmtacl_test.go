package conf

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The management ACL lists take a CIDR, or a CIDR with its services
// (0.2.7): the schema names the element and the problem.
func TestMgmtACLListsValidateServices(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for _, path := range []string{"mgmt_acl.permits", "scope_mgmt_acl.permits.lab"} {
		for _, c := range []struct {
			list []any
			want string
		}{
			{[]any{"10.0.0.0/8"}, ""},
			{[]any{"10.0.0.0/8:tcp/22", "172.16.100.0/23:tcp/22,udp/161,udp/162", "2001:db8::/32:icmp", "192.0.2.0/24:*"}, ""},
			{[]any{"10.0.0.0/8", "garbage"}, "element 1: 'garbage' is not a valid CIDR"},
			{[]any{"10.0.0.0/8:tcp/0"}, "element 0: '10.0.0.0/8:tcp/0': 'tcp/0': '0' is not a port"},
			{[]any{"10.0.0.0/8:icmp/8"}, "element 0: '10.0.0.0/8:icmp/8': 'icmp/8': icmp takes no port"},
			{[]any{"10.0.0.0/8:ssh"}, "'ssh' is not a service"},
			{[]any{"10.0.0.0/8", 5}, "element 1: must be a string"},
		} {
			got := s.Validate(path, c.list, true)
			if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
				t.Errorf("%s %v: %q, want %q", path, c.list, got, c.want)
			}
		}
	}
}

// A hand-edited file with a bad service is reported by 'config validate'
// with its path, and a good one is clean.
func TestMgmtACLValidateFile(t *testing.T) {
	s := NewSchema(DefaultBackends)
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	write := func(text string) {
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("mgmt_acl:\n  permits:\n  - 10.0.0.0/8\n  - 172.16.100.0/23:tcp/22,udp/161,udp/162\nscope_mgmt_acl:\n  permits:\n    lab:\n    - 192.0.2.0/24:icmp\n")
	if lines := s.ValidateFile(p); len(lines) != 0 {
		t.Errorf("a valid file: %q", lines)
	}
	write("scope_mgmt_acl:\n  permits:\n    lab:\n    - 192.0.2.0/24:udp/70000\n")
	lines := s.ValidateFile(p)
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "scope_mgmt_acl.permits.lab: element 0: '192.0.2.0/24:udp/70000'") {
		t.Errorf("a bad port: %q", lines)
	}
}

// The elements with services are what a rollback refuses.
func TestMgmtACLServiceEntries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	c := Load(p, DefaultBackends)
	if got := c.MgmtACLServiceEntries(); len(got) != 0 {
		t.Fatalf("an empty file: %v", got)
	}
	if err := c.SetList("mgmt_acl.permits", []string{"10.0.0.0/8", "172.16.100.0/23:tcp/22,udp/161,udp/162"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetList("scope_mgmt_acl.permits.lab", []string{"192.0.2.0/24:icmp", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetList("scope_mgmt_acl.permits.dmz", []string{"203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	want := []ACLServiceEntry{
		{"mgmt_acl.permits", "172.16.100.0/23:tcp/22,udp/161,udp/162"},
		{"scope_mgmt_acl.permits.lab", "192.0.2.0/24:icmp"},
	}
	if got := Load(p, DefaultBackends).MgmtACLServiceEntries(); !reflect.DeepEqual(got, want) {
		t.Errorf("entries %v, want %v", got, want)
	}
	// the written file holds the entry as one plain scalar
	text, _ := os.ReadFile(p)
	if !strings.Contains(string(text), "\n  - 172.16.100.0/23:tcp/22,udp/161,udp/162\n") {
		t.Errorf("file:\n%s", text)
	}
}
