package radius_test

import (
	"reflect"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/render/radius"
)

func noteLines(notes []radius.Note) []string {
	var out []string
	for _, n := range notes {
		out = append(out, n.String())
	}
	return out
}

func notesOf(t *testing.T, m *model.Model) []string {
	t.Helper()
	return noteLines(radius.Notes(m, cfg(t).Merged()))
}

func TestNotesOfTheFixture(t *testing.T) {
	// bob (operator) is served and the operator group's rules restrict
	// something; readonly has only carol (disabled) and the sink. The
	// secrets of lab and prod-inner are beyond the advice. Four of the five
	// scopes are served; none enables a vendor attribute.
	want := []string{
		"commands|operator",
		"secret|lab, prod-inner",
		"filters|4 allow, 2 deny",
		"vendors|0|4|0",
	}
	if got := notesOf(t, radiusModel(t)); !reflect.DeepEqual(got, want) {
		t.Errorf("notes:\n%q\nwant\n%q", got, want)
	}
}

func TestNotesCommandsOnlyForRestrictingGroupsWithServedUsers(t *testing.T) {
	m := radiusModel(t)
	const deny = `[{"name": "show", "action": "deny"}, {"name": "*", "action": "permit"}]`
	commands := func(rules map[string]string) string {
		c := cfg(t)
		for group, json := range rules {
			if err := c.SetJSON("commands."+group, json); err != nil {
				t.Fatal(err)
			}
		}
		for _, n := range radius.Notes(m, c.Merged()) {
			if n.Kind == "commands" {
				return n.Detail
			}
		}
		return ""
	}
	// A permit-everything rule set is not named.
	if got := commands(map[string]string{"operator": `[{"name": "*", "action": "permit"}]`}); got != "" {
		t.Errorf("a permit-everything group is named: %q", got)
	}
	// readonly has only carol (disabled) and the sink, which have no entry:
	// its rules are nobody's business here.
	if got := commands(map[string]string{"operator": `[{"name": "*", "action": "permit"}]`, "readonly": deny}); got != "" {
		t.Errorf("a group without served users is named: %q", got)
	}
	// netops has erin (wifi, prod-inner), superuser has alice: named, sorted.
	rules := map[string]string{"operator": deny, "netops": deny, "superuser": deny}
	if got := commands(rules); got != "netops, operator, superuser" {
		t.Errorf("commands note %q", got)
	}
}

func TestNotesNameSecretsByScopeNeverByValue(t *testing.T) {
	m := radiusModel(t)
	for _, n := range radius.Notes(m, cfg(t).Merged()) {
		if n.Kind == "secret" && n.Detail != "lab, prod-inner" {
			t.Errorf("secret note %q", n.Detail)
		}
	}
	// 63 printable characters are within the advice, 64 or a space are not;
	// a scope RADIUS does not serve is not looked at.
	scope(t, m, "prod").Secret = "0123456789012345678901234567890123456789012345678901234567890123"
	scope(t, m, "wifi").Secret = "012345678901234567890123456789012345678901234567890123456789012"
	scope(t, m, "legacy").Secret = "has a space"
	var got string
	for _, n := range radius.Notes(m, cfg(t).Merged()) {
		if n.Kind == "secret" {
			got = n.Detail
		}
	}
	if got != "lab, prod, prod-inner" {
		t.Errorf("secret note %q", got)
	}
}

func TestNotesVendorCounts(t *testing.T) {
	m := radiusModel(t)
	scope(t, m, "lab").VendorAttrs = []string{"cisco"}
	scope(t, m, "prod").Devices = []model.Device{{CIDR: "10.1.2.3/32", Vendor: "wti"}, {CIDR: "10.2.0.0/16", Vendor: "juniper"}}
	// A tagged address of a scope RADIUS does not serve is not counted.
	scope(t, m, "legacy").Devices = []model.Device{{CIDR: "198.51.100.7/32", Vendor: "cisco"}}
	scope(t, m, "legacy").VendorAttrs = []string{"cisco"}
	var got string
	for _, n := range notesOf(t, m) {
		if len(n) > 8 && n[:8] == "vendors|" {
			got = n
		}
	}
	if got != "vendors|1|4|2" {
		t.Errorf("vendors note %q", got)
	}
}

func TestNotesWithoutFilters(t *testing.T) {
	m := radiusModel(t)
	m.Filters.Allow, m.Filters.Deny = nil, nil
	for _, n := range notesOf(t, m) {
		if len(n) > 8 && n[:8] == "filters|" {
			t.Errorf("filters note without filters: %s", n)
		}
	}
	m.Filters.Deny = []string{"10.0.0.1/32"}
	found := false
	for _, n := range notesOf(t, m) {
		if n == "filters|0 allow, 1 deny" {
			found = true
		}
	}
	if !found {
		t.Error("no filters note for a deny-only list")
	}
}
