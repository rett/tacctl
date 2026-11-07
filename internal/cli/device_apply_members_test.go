package cli

import "testing"

import "github.com/rett/tacctl/internal/devconf"

// A read of 'device config apply' replaces the pull record's release but
// keeps the model, the serial number and the chassis members of the last
// pull: the apply reads no chassis.
func TestApplyRefreshKeepsTheFactsOfThePull(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.putRecord("example-sw1", devconf.Record{Address: "192.168.1.20", Vendor: "juniper", Result: devconf.ResultOK,
		Model: "EX4300-48T", Serial: "SN000001",
		Members: []devconf.Member{{ID: "0", Role: "master", Model: "EX4300-48T", Serial: "SN000001", Priority: 129},
			{ID: "1", Role: "backup", Model: "EX4300-48T", Serial: "SN000002", Priority: 129}}})
	if code, out, errs := b.apply("example-sw1", "--check"); code != 0 {
		t.Fatalf("check: %d\n%s\n%s", code, out, errs)
	}
	rec, ok := b.records().Of("example-sw1")
	if !ok || rec.Model != "EX4300-48T" || rec.Serial != "SN000001" || len(rec.Members) != 2 || rec.Members[1].Serial != "SN000002" {
		t.Errorf("the record after the read: %+v", rec)
	}
}
