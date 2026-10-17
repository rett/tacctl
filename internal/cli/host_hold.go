package cli

// A break-glass hold on an enrolled Linux host (docs/plans/0.2.14-plan.md
// D176 and D179-D181) as the 'host' commands see it: the record is the same
// as a device's (breakglass.go); what a held host loses is every command that
// logs in to it over ssh, which is refused up front, naming the hold and the
// command that releases it, so that nothing is attempted on a host whose
// local administrator is being used without this server.

import (
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
)

// hostDevices is the device registry the address of a held host is read
// from; err is a failure to read it (the address would then be guessed from
// the ssh target, which a recorded address may differ from).
func (inv *invocation) hostDevices() (*devreg.File, error) {
	return devreg.Load(inv.app.Paths.DevicesFile)
}

// hostHoldIn is the record that holds the enrolled host e: the one under its
// name whose address is the address a hold on the host carves
// (hostHoldAddress), f being the device registry (nil when it was not
// read). This server's own host is never held.
func (inv *invocation) hostHoldIn(f *devreg.File, e hosts.Entry) (conf.Hold, bool) {
	if e.Target == hosts.Local {
		return conf.Hold{}, false
	}
	addr := hostHoldAddress(f, e)
	if addr == "" {
		return conf.Hold{}, false
	}
	return inv.holdOf(e.Name, addr)
}

// hostHoldShown is hostHoldIn for what only displays a hold ('host list',
// 'host show', 'tacctl ssh'): a registry that cannot be read is not a
// failure there, and the address is the ssh target's.
func (inv *invocation) hostHoldShown(e hosts.Entry) (conf.Hold, bool) {
	f, _ := inv.hostDevices()
	return inv.hostHoldIn(f, e)
}

// hostHoldUnreadable refuses what cannot be checked: the registry of the
// devices holds the address of a hold on a host. It is exit status 1.
func (inv *invocation) hostHoldUnreadable(e hosts.Entry, err error) error {
	return inv.hostRefuse(err.Error(),
		"The device registry cannot be read, so the break-glass hold on "+e.Name+" cannot be checked; nothing was attempted.")
}

// hostHold is the record that holds the host e, for what acts on it: err is
// a refusal, already printed, when the registry cannot be read.
func (inv *invocation) hostHold(e hosts.Entry) (h conf.Hold, held bool, err error) {
	if e.Target == hosts.Local {
		return conf.Hold{}, false, nil
	}
	f, lerr := inv.hostDevices()
	if lerr != nil {
		return conf.Hold{}, false, inv.hostHoldUnreadable(e, lerr)
	}
	h, held = inv.hostHoldIn(f, e)
	return h, held, nil
}

// hostHoldLine is the one line that names the hold on a host: where it
// stands, since when, by whom and why.
func (inv *invocation) hostHoldLine(e hosts.Entry, h conf.Hold) string {
	return "Break-glass is held on host '" + e.Name + "' (" + h.Address + ") " + inv.holdSummary(h) + ": " + h.Reason + "."
}

// hostRefuse prints lines as errors (the reason of a hold is free text: no
// escape in it is read) and is exit status 1.
func (inv *invocation) hostRefuse(lines ...string) error {
	for _, l := range lines {
		inv.app.Out.Error(l)
	}
	return exit(1)
}

// hostHeldErr refuses what (the command, as typed) for a held host: nil when
// the host is not held. The refusal is printed here and is exit status 1.
func (inv *invocation) hostHeldErr(e hosts.Entry, what string) error {
	h, ok, err := inv.hostHold(e)
	if err != nil || !ok {
		return err
	}
	return inv.hostRefuse(inv.hostHoldLine(e, h),
		"'"+what+"' is refused for a held host: nothing was attempted over ssh and nothing was changed. Release it first: tacctl breakglass release "+e.Name)
}

// hostHoldJSON is the hold on the host as JSON (nil when none).
func (inv *invocation) hostHoldJSON(e hosts.Entry) *deviceHoldJSON {
	h, ok := inv.hostHoldShown(e)
	if !ok {
		return nil
	}
	return &deviceHoldJSON{Held: true, Address: h.Address, Since: h.Since, By: h.By, Reason: h.Reason}
}

// hostSkipHeld drops the held hosts from names for an operation on every
// host ('host sync --all'): each is said, with the hold, and is not tried.
// err is a refusal, already printed, when the registry cannot be read.
func (inv *invocation) hostSkipHeld(reg *hosts.Registry, names []string, what string) ([]string, error) {
	f, lerr := inv.hostDevices()
	var out []string
	for _, n := range names {
		e, ok := reg.Find(n)
		if !ok {
			out = append(out, n)
			continue
		}
		if lerr != nil && e.Target != hosts.Local {
			return nil, inv.hostHoldUnreadable(e, lerr)
		}
		h, held := inv.hostHoldIn(f, e)
		if !held {
			out = append(out, n)
			continue
		}
		inv.app.Out.Warn(n + ": skipped by " + what + ": break-glass is held on it " + inv.holdSummary(h) + ": " + h.Reason + " (tacctl breakglass release " + n + ")")
	}
	return out, nil
}
