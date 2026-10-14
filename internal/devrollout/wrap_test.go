package devrollout

import (
	"context"
	"net"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

type netIP = net.IP

// deltaOf is a Junos delta of the lines, their sections planned.
func deltaOf(ls ...plan.Line) plan.Delta {
	d := plan.Delta{Vendor: devconf.FamilyJunos, Lines: ls}
	for _, s := range plan.PlanOrder(devconf.FamilyJunos) {
		st := plan.StateNoChange
		for _, l := range ls {
			if l.Section == s {
				st = plan.StatePlanned
			}
		}
		d.Sections = append(d.Sections, plan.SectionPlan{Name: s, State: st})
	}
	return d
}

// runShell types commands as another login (a person at the device) and
// closes the session without 'exit'.
func runShell(t *testing.T, d *device, cmds ...string) {
	t.Helper()
	c, err := devssh.Dial(context.Background(), d.target(fakedev.DefaultUser, fakedev.DefaultPassword))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	s, err := c.CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeShell))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for _, cmd := range cmds {
		if _, err := s.Run(context.Background(), cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
	}
}

// vendorT is a transport of another vendor.
type vendorT struct{ Transport }

func (vendorT) Vendor() string { return "cisco" }

// extraT is a device that stages one statement more than it was given.
type extraT struct {
	*JunosCLI
	done bool
}

func (e *extraT) Load(ctx context.Context, l plan.Line) (Loaded, error) {
	r, err := e.JunosCLI.Load(ctx, l)
	if err == nil && !e.done {
		e.done = true
		e.mu.Lock()
		held := e.held
		e.mu.Unlock()
		_, _ = held.Run(ctx, "set snmp contact stranger")
	}
	return r, err
}

// landedT reports a landed compare with one statement more.
type landedT struct{ Reader }

func (l landedT) LandedCompare(ctx context.Context, d plan.Delta) (plan.CompareText, error) {
	c, err := l.Reader.LandedCompare(ctx, d)
	c.Stmts = append(c.Stmts, plan.CompareStmt{Op: '+', Path: []string{"snmp", "contact", "x"}})
	return c, err
}

// cancelT cancels the job's context after n statements (the second
// interrupt in the middle of the load).
type cancelT struct {
	*JunosCLI
	afterLoads int
	n          int
	cancel     func()
}

func (c *cancelT) Load(ctx context.Context, l plan.Line) (Loaded, error) {
	r, err := c.JunosCLI.Load(ctx, l)
	c.n++
	if c.n == c.afterLoads {
		c.cancel()
	}
	return r, err
}
