package firewall

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
)

// Tool is the program that loads the rules, looked up in PATH (execx).
const Tool = "nft"

// InstallCommand is what a report tells the operator to run when nft is
// missing.
const InstallCommand = "sudo apt-get install nftables"

// Engine applies the table. It is made over the invocation's runner, paths
// and tacctl.yaml; nothing in it reads the host's ruleset but the table of
// tacctl.
type Engine struct {
	Runner execx.Runner
	Paths  paths.Paths
	Conf   *conf.Config
}

// States of an Apply.
const (
	// Applied: the table was loaded with the holds and the setting.
	Applied = "applied"
	// Removed: the setting is off and the table is gone.
	Removed = "removed"
	// Idle: nothing was to be enforced and nft is not there, so nothing was
	// loaded; the rules file is written all the same, for the day it is.
	Idle = "idle"
	// Failed: the table could not be loaded, written or removed; the hold
	// stands, the server completes the TCP handshake of the address.
	Failed = "failed"
)

// Result is what an Apply did.
type Result struct {
	// State is Applied, Removed, Idle or Failed.
	State string
	// Mode is the setting that was applied.
	Mode string
	// Addrs are the held addresses of the table, as text.
	Addrs []string
	// Ports are the tacquito TCP ports the rules match.
	Ports []int
	// Why is what went wrong when State is Failed ("" otherwise).
	Why string
	// NftMissing is whether the reason is that nft is not installed.
	NftMissing bool
}

// OK reports whether the table is as the holds and the setting ask for.
func (r Result) OK() bool { return r.State != Failed }

// Refused is the line of the report that says what the table does: 'refused
// on tcp/49 (reject)' for the held addresses. "" when the state is not
// Applied.
func (r Result) Refused() string {
	if r.State != Applied || len(r.Addrs) == 0 {
		return ""
	}
	return strings.Join(r.Addrs, ", ") + " refused on " + PortList(r.Ports) + " (" + r.Mode + ")"
}

// Apply writes the rules file for the holds and the setting now in
// tacctl.yaml and loads it with 'nft -f': the table is replaced in one
// transaction, so applying twice, or after a crash, ends in the same table.
// With the setting off the file removes the table. It never reads the rest of
// the ruleset.
//
// Without nft there is nothing to load: that is a failure when an address is
// held (the server still completes the handshake) or a rules file was
// written before (a table may still be in the kernel), and nothing to say
// otherwise (Idle).
func (e *Engine) Apply(ctx context.Context) Result {
	spec := SpecOf(e.Conf)
	res := Result{State: Applied, Mode: spec.Mode, Addrs: spec.Strings(), Ports: spec.Ports}
	_, had := statFile(e.Paths.FirewallRules)
	if err := writeAtomic(e.Paths.FirewallRules, []byte(spec.Render()), 0o600); err != nil {
		res.State, res.Why = Failed, "cannot write "+e.Paths.FirewallRules+": "+errText(err)
		return res
	}
	if _, err := e.Runner.LookPath(Tool); err != nil {
		res.NftMissing = true
		switch {
		case spec.Mode != Off && len(spec.Held) > 0, had:
			res.State, res.Why = Failed, "nft is not installed"
		default:
			res.State = Idle
		}
		return res
	}
	if why := e.load(ctx); why != "" {
		res.State, res.Why = Failed, why
		return res
	}
	if spec.Mode == Off {
		res.State = Removed
		return res
	}
	// The boot unit: written when it is missing, which a hand-removed unit or
	// a failed upgrade leaves; its failure is the unit's own to report.
	_, _ = e.InstallUnit(ctx)
	return res
}

// load runs 'nft -f <rules file>' and says why it failed ("" when it did not).
func (e *Engine) load(ctx context.Context) string {
	r, err := e.Runner.Run(ctx, execx.Cmd{Name: Tool, Args: []string{"-f", e.Paths.FirewallRules}, Stdout: io.Discard})
	switch {
	case err != nil && r.Code == 0:
		return "nft could not be run: " + errText(err)
	case r.Code != 0:
		why := firstLine(string(r.Stderr))
		if why == "" {
			why = "no message"
		}
		return "nft -f " + e.Paths.FirewallRules + " failed (exit " + strconv.Itoa(r.Code) + "): " + why
	}
	return ""
}

// Remove takes tacctl's table, its rules file and its boot unit away (a
// rollback, an uninstall). The table goes by loading the rules file of the
// setting off ('table' declares it, 'delete table' removes it, so it is
// legal whether or not the table exists); without nft nothing is loaded.
// What was not there is not an error. The nftables package stays. removed
// lists what went, one line each.
func (e *Engine) Remove(ctx context.Context) (removed []string, err error) {
	var errs []error
	_, hadFile := statFile(e.Paths.FirewallRules)
	if _, lerr := e.Runner.LookPath(Tool); lerr == nil {
		if werr := writeAtomic(e.Paths.FirewallRules, []byte(Spec{Mode: Off}.Render()), 0o600); werr != nil {
			errs = append(errs, werr)
		} else if why := e.load(ctx); why != "" {
			errs = append(errs, errors.New(why))
		} else {
			removed = append(removed, "the nftables table inet tacctl")
		}
	}
	if _, ok := statFile(e.Paths.FirewallRules); ok {
		if rerr := os.Remove(e.Paths.FirewallRules); rerr != nil {
			errs = append(errs, rerr)
		} else if hadFile {
			removed = append(removed, e.Paths.FirewallRules)
		}
	}
	if line, uerr := e.RemoveUnit(ctx); uerr != nil {
		errs = append(errs, uerr)
	} else if line != "" {
		removed = append(removed, line)
	}
	return removed, errors.Join(errs...)
}

func statFile(path string) (os.FileInfo, bool) {
	st, err := os.Lstat(path)
	return st, err == nil
}

// writeAtomic writes data to path through a temporary file in the same
// directory and a rename, creating the directory when it is missing. A file
// that already says the same is not rewritten.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if have, err := os.ReadFile(path); err == nil && string(have) == string(data) {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr, os.Chmod(tmp, mode)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// errText is err without the path prefix noise of an *os.PathError.
func errText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
