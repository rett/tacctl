package policy

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

// The scope's NETCONF service setting (D145 of docs/plans/0.2.10-plan.md):
// netconf_scope.<scope>.state, .connection_limit and .rate_limit.

func TestNetconfSettings(t *testing.T) {
	c, _ := newConf(t, "")
	if got := NetconfSettings(c, "lab"); got != (NetconfScope{}) || NetconfSet(c, "lab") {
		t.Fatalf("a scope with none: %+v", got)
	}
	if err := SetNetconfState(c, "lab", conf.NetconfEnable); err != nil {
		t.Fatal(err)
	}
	if err := SetNetconfLimit(c, "lab", conf.NetconfKeyConnectionLimit, 5); err != nil {
		t.Fatal(err)
	}
	if err := SetNetconfLimit(c, "lab", conf.NetconfKeyRateLimit, 10); err != nil {
		t.Fatal(err)
	}
	want := NetconfScope{State: conf.NetconfEnable, ConnectionLimit: 5, RateLimit: 10}
	if got := NetconfSettings(c, "lab"); got != want || !NetconfSet(c, "lab") {
		t.Errorf("settings: %+v", got)
	}
	if NetconfSet(c, "other") {
		t.Error("another scope has settings")
	}
	// 0 removes a limit
	if err := SetNetconfLimit(c, "lab", conf.NetconfKeyRateLimit, 0); err != nil {
		t.Fatal(err)
	}
	if got := NetconfSettings(c, "lab"); got.RateLimit != 0 || got.ConnectionLimit != 5 {
		t.Errorf("after clearing a limit: %+v", got)
	}
}

// The schema refuses what is not a state a scope stores or a limit in range.
func TestNetconfSettingsAreValidated(t *testing.T) {
	c, path := newConf(t, "")
	for _, state := range []string{"leave", "on", "", "Enable"} {
		if err := SetNetconfState(c, "lab", state); err == nil {
			t.Errorf("state %q accepted", state)
		}
	}
	for _, n := range []int{-1, 251, 1000} {
		if err := SetNetconfLimit(c, "lab", conf.NetconfKeyConnectionLimit, n); err == nil {
			t.Errorf("limit %d accepted", n)
		}
	}
	if err := SetNetconfLimit(c, "lab", "bogus", 5); err == nil {
		t.Error("a key of no setting accepted")
	}
	if got := file(t, path); strings.Contains(got, "netconf_scope") {
		t.Errorf("a refused value was written:\n%s", got)
	}
}

func TestMoveNetconfScope(t *testing.T) {
	c, path := newConf(t, "")
	for _, f := range []func() error{
		func() error { return SetNetconfState(c, "lab", conf.NetconfDisable) },
		func() error { return SetNetconfLimit(c, "lab", conf.NetconfKeyConnectionLimit, 7) },
		func() error { return SetNetconfState(c, "other", conf.NetconfEnable) },
	} {
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
	lost, err := MoveNetconfScope(c, "lab", "lab2")
	if err != nil || len(lost) != 0 {
		t.Fatalf("move: %v %v", lost, err)
	}
	if NetconfSet(c, "lab") {
		t.Error("the old scope keeps its settings")
	}
	if got := NetconfSettings(c, "lab2"); got != (NetconfScope{State: conf.NetconfDisable, ConnectionLimit: 7}) {
		t.Errorf("moved: %+v", got)
	}
	if got := NetconfSettings(c, "other"); got.State != conf.NetconfEnable {
		t.Errorf("another scope changed: %+v", got)
	}
	// removal drops them
	if _, err := MoveNetconfScope(c, "lab2", ""); err != nil {
		t.Fatal(err)
	}
	if NetconfSet(c, "lab2") {
		t.Error("a removed scope keeps its settings")
	}
	// a scope with none does not rewrite the file
	before, _ := os.ReadFile(path)
	if _, err := MoveNetconfScope(c, "nothing", "something"); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(path); string(before) != string(after) {
		t.Error("moving a scope with no settings rewrote tacctl.yaml")
	}
}
