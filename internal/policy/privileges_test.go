package policy

import (
	"reflect"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

// Ports of tests/unit/privilege.bats (0.1.18) that TestPrivileges does not
// cover.

func TestDefaultPrivilegesSuperuserIsEmpty(t *testing.T) {
	// default_privileges_for_group superuser: priv 15 ceiling, no mapping.
	if got := DefaultPrivileges("superuser"); len(got) != 0 {
		t.Errorf("superuser defaults: %q", got)
	}
}

func TestDefaultPrivilegesUnknownGroupIsEmpty(t *testing.T) {
	if got := DefaultPrivileges("custom-group"); len(got) != 0 {
		t.Errorf("custom-group defaults: %q", got)
	}
}

func TestReadGroupPrivilegesFiltersToOneGroup(t *testing.T) {
	c, _ := newConf(t, "")
	if err := WritePrivileges(c, "operator", []string{"show running-config\nshow startup-config"}); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivileges(c, "readonly", []string{"show version"}); err != nil {
		t.Fatal(err)
	}
	if got, want := Privileges(c, "operator"), []string{"show running-config", "show startup-config"}; !reflect.DeepEqual(got, want) {
		t.Errorf("operator: %q, want %q", got, want)
	}
	if got, want := Privileges(c, "readonly"), []string{"show version"}; !reflect.DeepEqual(got, want) {
		t.Errorf("readonly: %q, want %q", got, want)
	}
	if got := Privileges(c, "superuser"); len(got) != 0 {
		t.Errorf("superuser: %q", got)
	}
}

func TestWriteGroupPrivilegesReplacesOnlyTheTargetGroup(t *testing.T) {
	c, path := newConf(t, "")
	if err := WritePrivileges(c, "operator", []string{"show running-config", "show startup-config"}); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivileges(c, "readonly", []string{"show version"}); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivileges(c, "operator", []string{"show ip interface brief"}); err != nil {
		t.Fatal(err)
	}
	if got, want := Privileges(c, "operator"), []string{"show ip interface brief"}; !reflect.DeepEqual(got, want) {
		t.Errorf("operator: %q, want %q", got, want)
	}
	if got, want := Privileges(c, "readonly"), []string{"show version"}; !reflect.DeepEqual(got, want) {
		t.Errorf("readonly: %q, want %q", got, want)
	}
	// The same holds for a fresh read of the file.
	re := conf.Load(path, conf.DefaultBackends)
	if got, want := Privileges(re, "operator"), []string{"show ip interface brief"}; !reflect.DeepEqual(got, want) {
		t.Errorf("reloaded operator: %q, want %q", got, want)
	}
	if got, want := Privileges(re, "readonly"), []string{"show version"}; !reflect.DeepEqual(got, want) {
		t.Errorf("reloaded readonly: %q, want %q", got, want)
	}
}
