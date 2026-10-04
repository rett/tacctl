package cli

// Native commands: what runs before every command.
//
// Every command of the tree has a RunE made with inv.native, which does
// what the 0.1.x entrypoint did before its dispatch, in the same order:
//
//  1. the test knobs must have been readable (a malformed TACCTL_TEST_* is
//     reported; only a -tags testknobs binary reads them);
//  2. the tacctl.yaml warning that sourcing lib/conf.sh prints once
//     (App.WarnConf);
//  3. the tier gate, enforce_tier "$COMMAND" "${1:-}" (internal/tier), on
//     the first two words of the command line as typed;
//  4. preflight, for the families bin/tacctl.sh runs it for (App.Preflight);
//  5. the command, which returns an error that exit.go maps to the exit
//     status (printing what has not been printed).
//
// A new family gives its node and its verbs RunEs made with inv.native
// (withPreflight when the command needs the store or tacquito.yaml).
// Nothing else changes: the App's services (Conf, Prompter, Snapshots,
// Backends, LoadModel) are made on first use.

import (
	"io"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// nativeOpts are what bin/tacctl.sh does before a family's dispatch.
type nativeOpts struct {
	// Preflight: the family is dispatched with 'preflight'.
	Preflight bool
}

// withPreflight and noPreflight are the two kinds of family.
var (
	withPreflight = nativeOpts{Preflight: true}
	noPreflight   = nativeOpts{}
)

// native makes the RunE of a command implemented in Go: steps 1-4 above,
// then run with the arguments after the command's words.
func (inv *invocation) native(o nativeOpts, run func(args []string) error) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, args []string) error {
		if err := inv.prelude(o); err != nil {
			return err
		}
		return run(args)
	}
}

// prelude is steps 1-4.
func (inv *invocation) prelude(o nativeOpts) error {
	a := inv.app
	if a.KnobsErr != nil {
		return a.KnobsErr
	}
	a.WarnConf()
	if err := inv.gate(); err != nil {
		return err
	}
	if o.Preflight {
		return a.Preflight()
	}
	return nil
}

// gate is enforce_tier "$COMMAND" "${1:-}".
func (inv *invocation) gate() error {
	a := inv.app
	var cmd, sub string
	if len(a.Args) > 0 {
		cmd = a.Args[0]
	}
	if len(a.Args) > 1 {
		sub = a.Args[1]
	}
	g := tier.Gate{
		Runner:   a.Runner,
		Out:      a.Out,
		SudoUser: a.Env.Get("SUDO_USER"),
		PrivLvl: func(user string) string {
			m, err := inv.model()
			if err != nil {
				return ""
			}
			return m.UserPrivLvl(user)
		},
	}
	return g.Enforce(inv.ctx, cmd, sub)
}

// model is the model as this invocation first read it (model_load's
// per-process cache): every read of a command comes before its one write.
// The load error is returned on every call, unprinted.
func (inv *invocation) model() (*model.Model, error) {
	if !inv.loaded {
		inv.loaded = true
		inv.m, inv.mErr = inv.app.LoadModel()
	}
	return inv.m, inv.mErr
}

// storeApply is 'store_apply <writer>': fn changes the store (one
// store.Mutate, under the snapshot StoreApply took) and every enabled
// backend renders and restarts as it needs. The error is StoreApply's
// (printed: exit 1 or 3) or fn's (unprinted: exit.go reports it).
func (inv *invocation) storeApply(fn func(*store.Store) error) error {
	a := inv.app
	_, err := a.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		_, err := store.Mutate(a.Paths.StoreFile, a.MutateOptions(), fn)
		return err
	})
	return err
}

// echo is bash's 'echo "<s>"' on stdout; echoE is 'echo -e "<s>"' (the
// backslash escapes of s interpreted, as every coloured line of 0.1.16 is
// printed).
func (inv *invocation) echo(s string) { _, _ = io.WriteString(inv.app.Out.Stdout, s+"\n") }

func (inv *invocation) echoE(s string) { _, _ = io.WriteString(inv.app.Out.Stdout, ui.Echo(s)) }

// stderrLine is 'echo "<s>" >&2'.
func (inv *invocation) stderrLine(s string) { _, _ = io.WriteString(inv.app.Out.Stderr, s+"\n") }
