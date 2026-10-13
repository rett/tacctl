package lifecycle

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// A management ACL entry with services (0.2.7) stops the rollback, in the
// dry run and the apply alike: the older release reads the lists as plain
// CIDRs, and a rewrite to the CIDR would permit every protocol and port.
// Nothing is changed, and each entry is named with its remove command.
func TestPlanRollbackRefusesWhileAManagementACLEntryHasServices(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+`mgmt_acl:
  permits:
  - 10.0.0.0/8
  - 172.16.100.0/23:tcp/22,udp/161,udp/162
scope_mgmt_acl:
  permits:
    lab:
    - 192.0.2.0/24:icmp
    - 198.51.100.0/24
    other:
    - 203.0.113.0/24
`, 0o640)
	s.reload()
	before := s.snapshotOf()
	p, err := PlanRollback(s.in)
	var ref *RollbackRefusal
	if p != nil || !errors.As(err, &ref) {
		t.Fatalf("the plan was made: %v %v", p, err)
	}
	text := strings.Join(ref.Lines, "\n")
	for _, want := range []string{
		"The management ACL has 2 entries with services",
		"mgmt_acl.permits: 172.16.100.0/23:tcp/22,udp/161,udp/162   (tacctl config mgmt-acl remove 172.16.100.0/23:tcp/22,udp/161,udp/162)",
		"scope_mgmt_acl.permits.lab: 192.0.2.0/24:icmp   (tacctl scope mgmt-acl lab remove 192.0.2.0/24:icmp)",
		"would permit every protocol and port",
		"Nothing was changed.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the refusal lacks %q:\n%s", want, text)
		}
	}
	for _, not := range []string{"10.0.0.0/8\n", "198.51.100.0/24", "203.0.113.0/24"} {
		if strings.Contains(text, not) {
			t.Errorf("the refusal names a plain entry %q:\n%s", not, text)
		}
	}
	if !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Error("the refusal changed a file")
	}

	// Plain lists plan as they did.
	s.write(s.p.Overrides, rbConf+`mgmt_acl:
  permits:
  - 10.0.0.0/8
scope_mgmt_acl:
  permits:
    lab:
    - 198.51.100.0/24
`, 0o640)
	s.reload()
	if _, err := PlanRollback(s.in); err != nil {
		t.Errorf("plain lists: %v", err)
	}
}

// One entry is "1 entry".
func TestACLServicesRefusalSingular(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+"mgmt_acl:\n  permits:\n  - 2001:db8::/32:tcp/22\n", 0o640)
	s.reload()
	_, err := PlanRollback(s.in)
	var ref *RollbackRefusal
	if !errors.As(err, &ref) || !strings.Contains(ref.Lines[0], "has 1 entry with services") {
		t.Fatalf("%v", err)
	}
}
