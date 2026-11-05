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
	// Idle: nothing was to be enforced and nft is not there (and no table of
	// tacctl was ever loaded), so nothing was loaded and nothing is wrong.
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
	// UnitErr is why the boot unit could not be written or enabled (or, with
	// the setting off, removed) after the table was loaded ("" otherwise).
	UnitErr string
}

// OK reports whether the table is as the holds and the setting ask for.
func (r Result) OK() bool { return r.State != Failed }

// Enforces reports whether the table asked for refuses anything (Spec.Enforces
// of the result): a mode that is not off, an address held and a port.
func (r Result) Enforces() bool { return r.Mode != Off && len(r.Addrs) > 0 && len(r.Ports) > 0 }

// UnitLine is the warning for a table that is loaded but whose boot unit
// could not be installed ("" when it could): the table is gone after a
// reboot until the setting command is run again. With the setting off the
// unit that could not be removed only loads a file that removes the table.
func (r Result) UnitLine() string {
	if r.UnitErr == "" {
		return ""
	}
	if r.State == Removed {
		return "the boot unit " + UnitName + " could not be removed (" + r.UnitErr + "); it loads a file that removes the table, so it does no harm."
	}
	return "the boot unit " + UnitName + " could not be installed (" + r.UnitErr + "), so the table is lost at the next reboot: " + FixCommand(r.Mode) + " tries again."
}

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
// Without nft nothing can be loaded, and there are three outcomes:
//
//   - Failed when the table is to refuse something (Spec.Enforces: a mode
//     that is not off, an address held and a port): the server still
//     completes the handshake.
//   - Failed when the boot unit is there. Only a successful 'nft -f' installs
//     it, so a table may still be in the kernel after nftables was removed,
//     and it keeps refusing addresses that were released since. (The rules
//     file is no such sign: it is written before the load.)
//   - Idle otherwise: the setting is off, nothing is held or no listener
//     binds a TCP port, and no table of tacctl was ever loaded. Nothing is
//     said, and the rules file is not created (a file that exists is kept
//     current only while the unit is there, for the boot after nft is back).
//
// A caller treats Idle as success and says nothing of it, Failed as a failure
// and names the fix (Result.NftMissing says to install nft first).
func (e *Engine) Apply(ctx context.Context) Result {
	spec := SpecOf(e.Conf)
	res := Result{State: Applied, Mode: spec.Mode, Addrs: spec.Strings(), Ports: spec.Ports}
	if _, err := e.Runner.LookPath(Tool); err != nil {
		res.NftMissing = true
		_, unit := statFile(e.Paths.FirewallUnit)
		switch {
		case spec.Enforces():
			res.State, res.Why = Failed, "nft is not installed"
		case unit:
			// best effort: the unit loads this file once nft is back
			_ = writeAtomic(e.Paths.FirewallRules, []byte(spec.Render()), 0o600)
			res.State, res.Why = Failed, "nft is not installed, and a table loaded earlier may still be in the kernel"
		default:
			res.State = Idle
		}
		return res
	}
	if err := writeAtomic(e.Paths.FirewallRules, []byte(spec.Render()), 0o600); err != nil {
		res.State, res.Why = Failed, "cannot write "+e.Paths.FirewallRules+": "+errText(err)
		return res
	}
	if why := e.load(ctx); why != "" {
		res.State, res.Why = Failed, why
		return res
	}
	if spec.Mode == Off {
		// No table is live now, so the boot unit goes too: its being there is
		// what says that a table may be live (above).
		res.State = Removed
		if _, err := e.RemoveUnit(ctx); err != nil {
			res.UnitErr = err.Error()
		}
		return res
	}
	// The boot unit: written when it is missing, which a hand-removed unit or
	// a failed upgrade leaves. A failure of its own does not fail the table,
	// which is loaded: it is the UnitErr of the result, for the report to
	// say that the table will be gone after a reboot.
	if _, err := e.InstallUnit(ctx); err != nil {
		res.UnitErr = err.Error()
	}
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
