package devapply

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// The proof of a change to the NETCONF service (D148), once per transport.

func TestBothVerifyServiceProofIsKept(t *testing.T) {
	both(t, nil, func(t *testing.T, d *device) {
		var seen int
		o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
			in.VerifyService = func(ctx context.Context, p plan.Delta) (string, error) {
				seen = len(p.Lines)
				return "NETCONF verified: hello ok", nil
			}
		})
		wantExit(t, o, ExitApplied, ResultApplied)
		if o.ServiceProof != "NETCONF verified: hello ok" || seen == 0 {
			t.Errorf("proof %q over %d lines", o.ServiceProof, seen)
		}
	})
}

func TestBothVerifyServiceRefusedRollsBack(t *testing.T) {
	both(t, nil, func(t *testing.T, d *device) {
		before := d.srv.Committed()
		o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
			in.VerifyService = func(context.Context, plan.Delta) (string, error) {
				return "", errors.New("the device still answers NETCONF after the change")
			}
		})
		wantExit(t, o, ExitRolledBack, ResultRolledBack)
		if !strings.Contains(o.Reason, "verification failed (the NETCONF service: the device still answers NETCONF") ||
			d.srv.Committed() != before || o.ServiceProof != "" {
			t.Errorf("%q (proof %q)", o.Reason, o.ServiceProof)
		}
	})
}

// A NETCONF fresh login names the state it read in its own words: it has no
// prompt to show a banner. The command line keeps its 0.2.9 words.
func TestNetconfNoPendingWord(t *testing.T) {
	w := (&JunosNetconf{}).NoPendingWord()
	if !strings.Contains(w, "commit history") || strings.Contains(w, "prompt") {
		t.Errorf("%q", w)
	}
	var cli Reader = &JunosCLI{}
	if _, ok := cli.(interface{ NoPendingWord() string }); ok {
		t.Error("the command line says its own words")
	}
}
