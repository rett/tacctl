package lifecycle

// The timing scale (0.2.22) in a rollback. It is a setting every older
// release lacks, in two files: tacctl.yaml (device.timeout_scale, the
// default of the whole server, and timeout_scale_scope.<scope>), which
// conf.Added0222 lists so that every target's key list removes them, and
// devices.yaml (timeout_scale of a device), whose parser refuses a key it
// does not know ("unknown key 'timeout_scale'") in every release before
// this one. So every target takes the devices' own scales out of
// devices.yaml (devreg.RollbackTimeoutScale), after the snapshot --apply
// takes first, and says so: the older release connects to every device with
// its fixed timings again, which a slow or distant device may not meet. It
// is a note, not a warning: nothing stops the rollback and nothing needs an
// answer; the values stay in the snapshot.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
)

// devTimeoutScale is a device with a timing scale of its own.
type devTimeoutScale struct {
	name string
	n    int
}

// planTimeoutScale reads the devices that have a timing scale of their own.
// A registry that cannot be read is an error, as for the other targets that
// read it: a rollback must not leave a key the older parser refuses unseen.
func (p *RollbackPlan) planTimeoutScale() error {
	set, err := devreg.TimeoutScaleSet(p.in.Paths.DevicesFile)
	if err != nil {
		return err
	}
	for _, d := range set {
		p.timeoutDev = append(p.timeoutDev, devTimeoutScale{d.Name, d.TimeoutScale})
	}
	return nil
}

// addTimeoutScale adds the step of devices.yaml and the note to the plan of
// any target, before the step that lists what is left untouched (and takes
// devices.yaml out of its list).
func (p *RollbackPlan) addTimeoutScale() {
	target, df := p.target(), p.in.Paths.DevicesFile
	if len(p.timeoutDev) > 0 {
		s := RollbackStep{Title: df + ": remove the timeout scale of the devices", Todo: true}
		for _, d := range p.timeoutDev {
			s.Lines = append(s.Lines, "remove the timeout_scale key of "+d.name+" ("+strconv.Itoa(d.n)+")")
		}
		s.Lines = append(s.Lines, "("+target+"'s parser refuses a device with a key it does not know: \"unknown key 'timeout_scale'\")")
		at := len(p.Steps)
		for i := range p.Steps {
			if p.Steps[i].Title == "leave every other file untouched" {
				at = i
				if len(p.Steps[i].Lines) > 0 {
					p.Steps[i].Lines[0] = strings.Replace(p.Steps[i].Lines[0], df+", ", "", 1)
				}
				break
			}
		}
		p.Steps = slices.Insert(p.Steps, at, s)
	}
	n := len(p.timeoutDev)
	for _, k := range p.keys {
		if conf.Added0222Key(k) && k != conf.ServerNameKey {
			n++
		}
	}
	if n > 0 {
		p.Notes = append(p.Notes, "The timing scale (tacctl device timeout-scale, scope timeout-scale and config devices timeout-scale) is removed: "+target+
			" connects to every device with its fixed timings again, which a slow or distant device may not meet. The values stay in the snapshot --apply takes first (tacctl backup list).")
	}
}
