package devconf

import (
	"context"
	"errors"
	"slices"
	"testing"
)

func TestReadFactsMembersJunos(t *testing.T) {
	ctx := context.Background()
	hw := capture(t, "members/synthetic-ex4300-hardware-vc.txt")
	ver := capture(t, "members/synthetic-ex4300-version-vc.txt")
	vc := capture(t, "members/synthetic-ex4300-vc-3-labelled-master.txt")
	t.Run("a virtual chassis: the members are set, no command runs twice", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{JunosChassisCommand: hw, JunosVersionCommand: ver, JunosVirtualChassisCommand: vc}}
		got := ReadFacts(ctx, f, "juniper", Facts{})
		if got.Release != "25.4R1-S2.3" || got.Model != "Virtual Chassis" || got.Serial != "SN000001" {
			t.Errorf("%+v", got)
		}
		if len(got.Members) != 3 || got.Members[2].Release != "24.4R2.9" || got.Members[1].Serial != "SN000002" || got.Members[0].Role != "master" {
			t.Errorf("%+v", got.Members)
		}
		if !slices.Equal(f.ran, []string{JunosChassisCommand, JunosVersionCommand, JunosVirtualChassisCommand}) {
			t.Errorf("%v", f.ran)
		}
	})
	t.Run("a refused command leaves the members out and the rest read", func(t *testing.T) {
		for name, f := range map[string]*fakeRunner{
			"an error text": {out: map[string]string{JunosChassisCommand: hw, JunosVersionCommand: ver,
				JunosVirtualChassisCommand: capture(t, "members/real-vmx-virtual-chassis-refusal.txt")}},
			"a failed command": {out: map[string]string{JunosChassisCommand: hw, JunosVersionCommand: ver},
				errs: map[string]error{JunosVirtualChassisCommand: errors.New("denied")}},
			"one member": {out: map[string]string{JunosChassisCommand: hw, JunosVersionCommand: ver,
				JunosVirtualChassisCommand: capture(t, "members/synthetic-ex4300-vc-1.txt")}},
		} {
			got := ReadFacts(ctx, f, "juniper", Facts{})
			if got.Members != nil || got.Release != "25.4R1-S2.3" || got.Model != "Virtual Chassis" || got.Serial != "SN000001" {
				t.Errorf("%s: %+v", name, got)
			}
		}
	})
	t.Run("a cancelled context after the version leaves them out", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		f := &cancelRunner{fakeRunner: fakeRunner{out: map[string]string{JunosChassisCommand: hw, JunosVersionCommand: ver, JunosVirtualChassisCommand: vc}}, cancelAfter: JunosVersionCommand, cancel: cancel}
		got := ReadFacts(cctx, f, "juniper", Facts{})
		if got.Members != nil || got.Release != "25.4R1-S2.3" || slices.Contains(f.ran, JunosVirtualChassisCommand) {
			t.Errorf("%+v %v", got, f.ran)
		}
	})
}

func TestReadFactsMembersIOS(t *testing.T) {
	ctx := context.Background()
	sw := capture(t, "members/synthetic-ios-show-switch-3.txt")
	inv := capture(t, "members/synthetic-ios-inventory-stack-3.txt")
	ver := capture(t, "members/synthetic-ios-show-version-stack-3.txt")
	t.Run("a stack", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{IOSInventoryCommand: inv, IOSSwitchCommand: sw, IOSVersionCommand: ver}}
		got := ReadFacts(ctx, f, "cisco", Facts{Release: "12.2(55)SE12"})
		if got.Model != "WS-C3750G-24PS-S" || got.Serial != "SN000004" || got.Release != "12.2(55)SE12" {
			t.Errorf("%+v", got)
		}
		if len(got.Members) != 3 || got.Members[2].Release != "12.2(53)SE2" || got.Members[1].Serial != "SN000005" || got.Members[2].Role != "backup" {
			t.Errorf("%+v", got.Members)
		}
		if !slices.Equal(f.ran, []string{IOSInventoryCommand, IOSSwitchCommand, IOSVersionCommand}) {
			t.Errorf("%v", f.ran)
		}
	})
	t.Run("a stack whose show version is refused keeps the members", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{IOSInventoryCommand: inv, IOSSwitchCommand: sw}, errs: map[string]error{IOSVersionCommand: errors.New("closed")}}
		got := ReadFacts(ctx, f, "ios-xe", Facts{})
		if len(got.Members) != 3 || got.Members[0].Release != "" || got.Members[0].Serial != "SN000004" {
			t.Errorf("%+v", got)
		}
	})
	t.Run("a refused show switch leaves them out, the inventory read, and show version is not run", func(t *testing.T) {
		for name, f := range map[string]*fakeRunner{
			"a refusal":  {out: map[string]string{IOSInventoryCommand: inv, IOSSwitchCommand: capture(t, "members/real-ios-show-switch-refusal.txt"), IOSVersionCommand: ver}},
			"an error":   {out: map[string]string{IOSInventoryCommand: inv, IOSVersionCommand: ver}, errs: map[string]error{IOSSwitchCommand: errors.New("closed")}},
			"one switch": {out: map[string]string{IOSInventoryCommand: inv, IOSSwitchCommand: "*1       Master 0000.5e00.5301     15     V01     Ready\n", IOSVersionCommand: ver}},
		} {
			got := ReadFacts(ctx, f, "cisco", Facts{Release: "15.6(2)T"})
			if got.Members != nil || got.Model != "WS-C3750G-24PS-S" || got.Serial != "SN000004" || got.Release != "15.6(2)T" || slices.Contains(f.ran, IOSVersionCommand) {
				t.Errorf("%s: %+v %v", name, got, f.ran)
			}
		}
	})
}

// cancelRunner cancels its context after the command cancelAfter ran.
type cancelRunner struct {
	fakeRunner
	cancelAfter string
	cancel      context.CancelFunc
}

func (c *cancelRunner) Run(ctx context.Context, cmd string) (string, error) {
	out, err := c.fakeRunner.Run(ctx, cmd)
	if cmd == c.cancelAfter {
		c.cancel()
	}
	return out, err
}
