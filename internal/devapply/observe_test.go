package devapply

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/plan"
)

// Observe files the lines of a shape a check saw without confirming it, and
// leaves a shape that is confirmed as it is.
func TestShapesObserve(t *testing.T) {
	s := OpenShapes(t.TempDir())
	d := plan.Delta{Vendor: devconf.FamilyJunos, Lines: []plan.Line{{Section: "aaa", Op: plan.OpSet, Text: "set system accounting events login"}}}
	hash, lines := plan.Shape(d)
	if err := s.Observe(hash, lines); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Confirmed(hash); err != nil || ok {
		t.Fatalf("an observed shape is confirmed: %v %v", ok, err)
	}
	m, _ := s.Load()
	if e := m[hash]; len(e.Lines) != len(lines) || len(e.Confirmed) != 0 {
		t.Errorf("entry %+v", e)
	}
	if err := s.Confirm(hash, lines, Confirmation{Device: "sw", At: time.Now(), By: "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Observe(hash, lines); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Confirmed(hash); !ok {
		t.Error("Observe dropped a confirmation")
	}
	if err := s.Observe("000000000000", lines); err == nil {
		t.Error("a shape under another name was filed")
	}
}

// ReadPlain reads the plain view through the transport's exec channel, the
// one command beside the pull's read that the guard lets through.
func TestReadPlain(t *testing.T) {
	d := newDevice(t, nil)
	j := d.dial()
	defer func() { _ = j.Close() }()
	got := j.ReadPlain(context.Background())
	if !strings.Contains(got, "set system host-name example-sw1") {
		t.Errorf("plain view: %q", got)
	}
	logged := false
	for _, l := range j.Log() {
		if l == devconf.PlainCommand("juniper") {
			logged = true
		}
	}
	if !logged {
		t.Errorf("the command is not in the log: %q", j.Log())
	}
}
