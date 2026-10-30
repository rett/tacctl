package cli

// What the timing scale is applied to (timeout_scale.go has the scale and how
// it resolves): the scale in force for a registry entry or for the device at
// an address, and the timings the host-key scans, the sessions and the
// batches take from it.

import (
	"context"
	"strconv"
	"time"

	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/snmp"
)

// scaleOfEntry is the scale in force for a registry entry.
func (inv *invocation) scaleOfEntry(e devreg.Entry) int {
	return inv.timeoutScaleOf(e.Scope, e.TimeoutScale).N
}

// scaleAt is the scale in force for the device at addr (a registered device's
// own value, else the scope that answers the address, else the server's),
// whether the address is registered or not.
func (inv *invocation) scaleAt(addr string) int {
	own := 0
	if d := inv.deviceAt(addr); d != nil {
		own = d.TimeoutScale
	}
	return inv.timeoutScaleOf(inv.scopeOfAddress(addr), own).N
}

// scanTimingAt is the timing of the host-key reads of the device at addr.
func (inv *invocation) scanTimingAt(addr string) devssh.ScanTiming {
	return devssh.ScanTiming{}.Scaled(inv.scaleAt(addr))
}

// deviceTimeoutAt is the per-device timeout of a run that has none typed: the
// setting (device.config.timeout) scaled for the device at addr.
func (inv *invocation) deviceTimeoutAt(addr string) time.Duration {
	return scaledDeviceTimeout(inv.deviceConfigSettings().timeout, inv.scaleAt(addr))
}

// deviceTimeoutOf is deviceTimeoutAt for a registry entry.
func (inv *invocation) deviceTimeoutOf(e devreg.Entry) time.Duration {
	return scaledDeviceTimeout(inv.deviceConfigSettings().timeout, inv.scaleOfEntry(e))
}

// scaleJobTimeouts is the budget of a batch run and its jobs when the
// per-device timeout is the setting's and not one typed on the command line:
// every device has the setting scaled for it. The run's budget is one number
// (batch.Options.Timeout), so it is the largest of them, and a job whose own
// is shorter is held to it inside (a failure at that deadline is a timeout,
// as the run's own would make it). When no device is scaled the run is
// untouched: the same budget, the same jobs.
func (inv *invocation) scaleJobTimeouts(entries []devreg.Entry, jobs []batch.Job, base time.Duration, typed bool) (time.Duration, []batch.Job) {
	if typed || len(entries) != len(jobs) {
		return base, jobs
	}
	per := make([]time.Duration, len(entries))
	longest := time.Duration(0)
	for i, e := range entries {
		per[i] = scaledDeviceTimeout(base, inv.scaleOfEntry(e))
		longest = max(longest, per[i])
	}
	if longest == base {
		return base, jobs
	}
	out := make([]batch.Job, len(jobs))
	for i, j := range jobs {
		out[i] = j
		if per[i] < longest {
			out[i] = holdToTimeout(j, per[i])
		}
	}
	return longest, out
}

// snmpScaleNote is the line under the timeout of an SNMP show when a timing
// scale above 1 is in force: the wait on the wire is the timeout times the
// scale, never above the most SNMP takes. "" at scale 1.
func snmpScaleNote(timeout, scale int) string {
	if scale <= devssh.MinTimeoutScale {
		return ""
	}
	return "              x " + strconv.Itoa(scale) + " (timing scale) = " + strconv.Itoa(scaledSNMPTimeout(timeout, scale)) +
		" s on the wire, never above " + strconv.Itoa(snmp.MaxTimeout) + " s"
}

// holdToTimeout is j held to its own time inside the run's: a failure at that
// deadline, while the run's own has not passed, is a timeout, as the run's
// would make it.
func holdToTimeout(j batch.Job, own time.Duration) batch.Job {
	do := j.Do
	j.Do = func(ctx context.Context) batch.Result {
		jctx, cancel := context.WithTimeout(ctx, own)
		defer cancel()
		r := do(jctx)
		if r.Status == batch.StatusFailed && ctx.Err() == nil && jctx.Err() != nil {
			r.Status = batch.StatusTimeout
			if r.Reason == "" {
				r.Reason = "timeout after " + own.String()
			}
		}
		return r
	}
	return j
}
