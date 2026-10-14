package devapply

// A change of one element of a bracket list (live acceptance 2026-10-14,
// defect C): the device prints the whole list removed and added; the check
// and the apply see only the net change, and an element someone else adds
// or removes beside it still fails the check.

import (
	"context"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

func listLines() []plan.Line {
	return []plan.Line{
		{Section: "aaa", Op: plan.OpDelete, Text: "delete system accounting events interactive-commands"},
		{Section: "system", Op: plan.OpSet, Text: "set system domain-search example.org"},
	}
}

// listDevice is the fixture with a three-event accounting list and one
// search domain committed.
func listDevice(t *testing.T) *device {
	t.Helper()
	d := newDevice(t, nil)
	runShell(t, d, "configure",
		"set system accounting events login",
		"set system accounting events change-log",
		"set system accounting events interactive-commands",
		"set system domain-search example.net",
		"commit", "exit")
	return d
}

func listInput(d *device, p *planner) Input {
	in := d.input(p)
	in.Allow = plan.Allow{Login: fakedev.DefaultUser, Expected: []devices.Section{
		{Name: "aaa", Lines: []string{"set system accounting events login", "set system accounting events change-log"}, Secret: []bool{false, false}},
		{Name: "system", Lines: []string{"set system domain-search example.net", "set system domain-search example.org"}, Secret: []bool{false, false}},
	}}
	return in
}

func TestListElementCompare(t *testing.T) {
	d := listDevice(t)
	// the fake prints the lists as the device does: the whole leaf removed,
	// then added
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
	var txt string
	for _, cmd := range []string{"configure", "delete system accounting events interactive-commands",
		"set system domain-search example.org", plan.ApplyCompare, "rollback 0", "exit"} {
		out, err := s.Run(context.Background(), cmd)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		if cmd == plan.ApplyCompare {
			txt = out
		}
	}
	for _, w := range []string{
		"-   events [ login change-log interactive-commands ];",
		"+   events [ login change-log ];",
		"-   domain-search example.net;",
		"+   domain-search [ example.net example.org ];",
	} {
		if !strings.Contains(txt, w) {
			t.Fatalf("the fake's compare lacks %q:\n%s", w, txt)
		}
	}
}

func TestListElementCheckAndApply(t *testing.T) {
	d := listDevice(t)
	p := &planner{desired: listLines()}
	before := d.srv.Committed()
	o := Driver{}.Check(context.Background(), listInput(d, p))
	assertLog(t, o, listLines())
	wantExit(t, o, ExitChecked, ResultChecked)
	if !strings.Contains(o.Line(), "1 set, 1 delete") || d.srv.Committed() != before {
		t.Errorf("line %q", o.Line())
	}

	rev := d.reviewed(p)
	o = Driver{}.Apply(context.Background(), listInput(d, p), rev)
	assertLog(t, o, rev.Lines)
	wantExit(t, o, ExitApplied, ResultApplied)
	after := d.srv.Committed()
	for _, w := range []string{"set system accounting events login", "set system accounting events change-log", "set system domain-search example.net", "set system domain-search example.org"} {
		if !strings.Contains(after, w) {
			t.Errorf("committed lacks %q:\n%s", w, after)
		}
	}
	if strings.Contains(after, "interactive-commands") {
		t.Errorf("the deleted event stayed:\n%s", after)
	}
}

// listStrangerT stages someone else's statement in the held session after the
// first line is loaded.
type listStrangerT struct {
	*JunosCLI
	line string
	done bool
}

func (e *listStrangerT) Load(ctx context.Context, l plan.Line) (Loaded, error) {
	r, err := e.JunosCLI.Load(ctx, l)
	if err == nil && !e.done {
		e.done = true
		e.mu.Lock()
		held := e.held
		e.mu.Unlock()
		_, _ = held.Run(ctx, e.line)
	}
	return r, err
}

// Someone else's element staged beside the planned one, or a second element
// of the list removed, is a change outside the delta: the check fails
// closed.
func TestListElementStrangerFails(t *testing.T) {
	for line, want := range map[string]string{
		"set system domain-search stranger.example":  "+ system domain-search stranger.example",
		"delete system accounting events change-log": "- system accounting events change-log",
	} {
		d := listDevice(t)
		before := d.srv.Committed()
		in := listInput(d, &planner{desired: listLines()})
		in.Transport = &listStrangerT{JunosCLI: in.Transport.(*JunosCLI), line: line}
		o := Driver{}.Check(context.Background(), in)
		wantExit(t, o, ExitFailedLoad, ResultFailed)
		if !strings.Contains(o.Reason, "a change outside the delta: "+want) || !o.Discarded {
			t.Errorf("%s: %q %v", line, o.Reason, o.Discarded)
		}
		if d.srv.Committed() != before || d.srv.Candidate() != before {
			t.Errorf("%s: changed", line)
		}
	}
}
