package cli

import (
	"context"
	"fmt"

	"github.com/rett/tacctl/internal/devapply"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
)

// serviceVerifier is the verification of a change to the NETCONF service
// itself (D148), the driver's Input.VerifyService. It is made over the
// command line (the delta's transport is chosen so) and runs on a fresh
// login, between the fresh login's checks and the confirming commit:
//
//	enable   a NETCONF hello as the user must now be answered;
//	disable  the hello must no longer be answered (port closed or no hello).
//
// A probe that cannot tell is an error, never a pass. The record's probe is
// written only when the change is applied (keep), from st.probe; a failure
// says what the record's probe stays.
func (r *applyRun) serviceVerifier(e devreg.Entry, target devssh.Target, st *applyState) func(context.Context, plan.Delta) (string, error) {
	return func(ctx context.Context, d plan.Delta) (string, error) {
		want := plan.NetconfService(d)
		if want == "" {
			return "", nil
		}
		was := r.probeOf(e.Name)
		if was == "" {
			was = netconfNotProbed
		}
		got, err := devapply.ProbeNetconf(ctx, target)
		if err != nil {
			return "", fmt.Errorf("%s (the record's NETCONF probe stays '%s')", shortReason(err), was)
		}
		switch {
		case want == "enable" && got != devapply.ProbeHelloOK:
			return "", fmt.Errorf("the device does not answer NETCONF after the change (%s; the record's NETCONF probe stays '%s')", got, was)
		case want == "disable" && got == devapply.ProbeHelloOK:
			return "", fmt.Errorf("the device still answers NETCONF after the change (the record's NETCONF probe stays '%s')", was)
		}
		st.probe = got
		if got == devapply.ProbeHelloOK {
			return "NETCONF verified: hello ok", nil
		}
		return "NETCONF verified: not answering", nil
	}
}
