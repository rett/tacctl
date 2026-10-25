package plan

import (
	"testing"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// iosSystemSectionOf is the system section an IOS block's text renders.
func iosSystemSectionOf(t testing.TB, text string) devices.Section {
	t.Helper()
	b, fs := blocks.LintIOSSystem(text, blocks.LayerDevice)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	st := blocks.IOSSystemStatements(blocks.ResolveIOSSystem(nil, b, nil))
	sec := devices.Section{Name: "system", Lines: st, Secret: make([]bool, len(st)), Block: make([]bool, len(st))}
	for i, l := range st {
		sec.Secret[i] = blocks.IsIOSSecretStatement(l)
		sec.Block[i] = true
	}
	return sec
}

// The cases of the owned rows of the IOS system block's closed table
// (0.2.19): logging, timestamps, login and password policy, ssh and summer
// time. Each plans a device that holds another value of the same statement
// against a block that states one: the value is typed (in place for a
// single-valued one), nothing is removed, and what the block does not state is
// kept.
func iosRuleCase(block, device, want, kept string) func(t *testing.T) {
	return func(t *testing.T) {
		f := fixtureNamed(t, "cisco.synthetic-system")
		exp := withSystem(expectedSections(t, f.expected), iosSystemSectionOf(t, block))
		c := ParseIOS(capture(t, f.raw))
		c.typeGlobal(device)
		text := c.Text()
		cur, err := devconf.Extract(f.vendor, text, exp...)
		if err != nil {
			t.Fatal(err)
		}
		d, err := Plan(f.vendor, exp, cur, cur, Options{Scope: "lab", Class: f.class, Syntax: f.syntax()})
		if err != nil {
			t.Fatal(err)
		}
		wantLine(t, d, "system", want)
		noLine(t, d, "system", "no ")
		if kept != "" {
			wantKept(t, d, "system", kept)
		}
		// pasted, the section reads ok: the model replaces a single-valued
		// statement as the device does
		c = ParseIOS(text)
		if err := c.Apply(d.Lines); err != nil {
			t.Fatal(err)
		}
		cur, err = devconf.Extract(f.vendor, c.Text(), exp...)
		if err != nil {
			t.Fatal(err)
		}
		rs, err := devconf.CompareAll(exp, cur)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			if r.Name == devconf.SectionSystem && r.State != devconf.StateOK {
				t.Errorf("system reads %s after the plan:\n%v", r.State, r.Lines)
			}
		}
	}
}

func init() {
	for id, c := range map[string]func(*testing.T){
		"ios.system.logging-host": iosRuleCase(
			"logging host 192.0.2.50\n", "logging host 198.51.100.7",
			"logging host 192.0.2.50", "logging host 198.51.100.7"),
		"ios.system.logging-trap": iosRuleCase(
			"logging trap warnings\n", "logging trap debugging", "logging trap warnings", ""),
		"ios.system.logging-buffered": iosRuleCase(
			"logging buffered 16384 warnings\n", "logging buffered 8192", "logging buffered 16384 warnings", ""),
		"ios.system.logging-origin-id": iosRuleCase(
			"logging origin-id hostname\n", "logging origin-id string other", "logging origin-id hostname", ""),
		"ios.system.timestamps": iosRuleCase(
			"service timestamps debug datetime msec localtime\n", "service timestamps debug uptime",
			"service timestamps debug datetime msec localtime", ""),
		"ios.system.login-on-failure": iosRuleCase(
			"login on-failure log every 3\n", "login on-failure log", "login on-failure log every 3", ""),
		"ios.system.login-on-success": iosRuleCase(
			"login on-success log\n", "login on-success log every 5", "login on-success log", ""),
		"ios.system.login-delay": iosRuleCase(
			"login delay 3\n", "login delay 5", "login delay 3", ""),
		"ios.system.passwords-min-length": iosRuleCase(
			"security passwords min-length 12\n", "security passwords min-length 6", "security passwords min-length 12", ""),
		"ios.system.auth-failure-rate": iosRuleCase(
			"security authentication failure rate 5 log\n", "security authentication failure rate 10 log",
			"security authentication failure rate 5 log", ""),
		"ios.system.ssh-version": iosRuleCase(
			"ip ssh version 2\n", "ip ssh version 1", "ip ssh version 2", ""),
		"ios.system.ssh-timeout": iosRuleCase(
			"ip ssh time-out 60\n", "ip ssh time-out 120", "ip ssh time-out 60", ""),
		"ios.system.ssh-retries": iosRuleCase(
			"ip ssh authentication-retries 3\n", "ip ssh authentication-retries 5", "ip ssh authentication-retries 3", ""),
		"ios.system.summer-time": iosRuleCase(
			"clock summer-time EDT recurring\n", "clock summer-time PDT recurring", "clock summer-time EDT recurring", ""),
	} {
		iosRowCases[id] = c
	}
}

// Only the three ssh settings of a scope's system block are emitted; every
// other 'ip ssh' statement, and these anywhere else, stay on the never list.
func TestNeverListKeepsOtherSSH(t *testing.T) {
	for _, c := range []struct {
		l     Line
		never bool
	}{
		{Line{Op: OpLine, Section: "system", Text: "ip ssh version 2"}, false},
		{Line{Op: OpLine, Section: "system", Text: "ip ssh time-out 60"}, false},
		{Line{Op: OpNo, Section: "system", Text: "ip ssh authentication-retries"}, false},
		{Line{Op: OpLine, Section: "system", Text: "ip ssh source-interface Loopback0"}, true},
		{Line{Op: OpLine, Section: "system", Text: "ip ssh server algorithm mac hmac-sha2-256"}, true},
		{Line{Op: OpLine, Section: "aaa", Text: "ip ssh version 2"}, true},
	} {
		if _, got := neverMatch("ios", c.l); got != c.never {
			t.Errorf("%+v: never = %v", c.l, got)
		}
	}
}
