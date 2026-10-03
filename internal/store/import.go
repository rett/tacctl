package store

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/ui"
	"github.com/rett/tacctl/internal/yamlpy"
)

// 'tacctl store import': the one-time import of a legacy tacquito.yaml into
// the store (lib/store.sh store_import / _store_import_run and
// lib/model.sh _carry_over / import_load at 0.1.16).

// carryOver is _carry_over: re-importing over an existing store keeps what
// a tacquito.yaml cannot carry (scope protocols, vendor attributes and
// tagged addresses, password dates, the saved hash of a disabled user).
func carryOver(s *Store, existing string, rep *LegacyReport) {
	old, err := Load(existing)
	if err != nil {
		rep.note("existing store could not be read (%s); nothing carried over", err.Error())
		return
	}
	var keptProtocols, keptDates, keptHashes, keptVendor int
	oldScopes, oldUsers := old.section("scopes"), old.section("users")
	scopes := s.section("scopes")
	for name, sv := range scopes.All() {
		sc := sv.(*yamlpy.Map)
		prev, ok := mapOf(get(oldScopes, name))
		if !ok {
			continue
		}
		if p := get(prev, "protocols"); truthy(p) {
			sc.Set("protocols", p)
			keptProtocols++
		}
		if truthy(get(prev, "vendor_attrs")) || truthy(get(prev, "devices")) {
			if va := get(prev, "vendor_attrs"); truthy(va) {
				sc.Set("vendor_attrs", pyList(va))
			}
			if dm, ok := mapOf(get(prev, "devices")); ok && dm.Len() > 0 {
				sc.Set("devices", cloneMap(dm))
			}
			keptVendor++
		}
	}
	// A tagged address whose prefix the imported file no longer has (or has
	// given to another scope) cannot be kept: the store refuses it.
	for _, p := range DeviceProblems(deviceScopes(scopes)) {
		sc := get(scopes, p.Scope).(*yamlpy.Map)
		get(sc, "devices").(*yamlpy.Map).Delete(p.CIDR)
		rep.drop("scope '%s': the vendor tag of %s (no prefix of the scope in this file contains it any more)", p.Scope, p.CIDR)
	}
	for name, uv := range s.section("users").All() {
		u := uv.(*yamlpy.Map)
		prev, ok := mapOf(get(oldUsers, name))
		if !ok {
			continue
		}
		if get(u, "password_changed") == nil && truthy(get(prev, "password_changed")) {
			u.Set("password_changed", get(prev, "password_changed"))
			keptDates++
		}
		if truthy(get(u, "disabled")) && get(u, "hash") == nil && !truthy(get(u, "accounting_sink")) &&
			BcryptHexOK(get(prev, "hash")) {
			u.Set("hash", get(prev, "hash"))
			keptHashes++
		}
	}
	if keptProtocols > 0 {
		rep.note("kept the protocols filter of %d scope(s) from the existing store", keptProtocols)
	}
	if keptVendor > 0 {
		rep.note("kept the RADIUS vendor attributes and tagged addresses of %d scope(s) from the existing store", keptVendor)
	}
	if keptDates > 0 {
		rep.note("kept the password date of %d user(s) from the existing store", keptDates)
	}
	if keptHashes > 0 {
		rep.note("kept the saved password of %d disabled user(s) from the existing store", keptHashes)
	}
}

// pyList is list(v) for the values a store holds: a copy of a list, the
// characters of a string, the keys of a mapping.
func pyList(v any) any {
	switch x := v.(type) {
	case []any:
		return append([]any{}, x...)
	case string:
		out := []any{}
		for _, r := range x {
			out = append(out, string(r))
		}
		return out
	case *yamlpy.Map:
		out := []any{}
		for _, k := range x.Keys() {
			out = append(out, k)
		}
		return out
	}
	return v
}

// ImportLoadOptions are the inputs of ImportLoad.
type ImportLoadOptions struct {
	Src         string // the tacquito.yaml to import
	DatesDir    string // password-date sidecars ('<user>.date'); "" for none
	DisabledDir string // saved hashes of disabled users ('<user>.hash'); "" for none
	Existing    string // the existing store to carry fields over from; "" for none
	Force       bool   // drop what the store cannot represent
}

// ImportLoad is import_load ('import-load'): load src with the legacy
// loader, carry fields over from an existing store, canonicalise,
// validate, and print the report to stdout (and the verdict line to
// stderr when the import cannot go ahead). It returns the store to write,
// and ok=false when the import must not be written. An error (the file
// cannot be read or parsed; printed by Report as 'tacctl store: ...') means
// nothing was printed.
func ImportLoad(stdout, stderr io.Writer, opts ImportLoadOptions) (s *Store, ok bool, err error) {
	s, rep, err := LegacyRaw(opts.Src, opts.DatesDir, opts.DisabledDir)
	if err != nil {
		return nil, false, err
	}
	if opts.Existing != "" {
		carryOver(s, opts.Existing, rep)
	}
	s.Canonicalize()
	// Validation problems are fatal, but only worth listing once the loader
	// itself has nothing fatal to say (its errors usually cause them).
	var verrs []string
	if len(rep.Errors) == 0 {
		verrs = Validate(s.doc)
	}

	users := s.section("users")
	disabled, sinks := 0, 0
	for _, uv := range users.All() {
		u, _ := mapOf(uv)
		sink := truthy(get(u, "accounting_sink"))
		if sink {
			sinks++
		} else if truthy(get(u, "disabled")) {
			disabled++
		}
	}
	filters := s.section("filters")
	var b strings.Builder
	fmt.Fprintf(&b, "  Source:   %s\n", opts.Src)
	fmt.Fprintf(&b, "  Groups:   %d\n", s.section("groups").Len())
	detail := fmt.Sprintf("%d disabled", disabled)
	if sinks > 0 {
		detail += fmt.Sprintf(", %d accounting sink", sinks)
	}
	fmt.Fprintf(&b, "  Users:    %d (%s)\n", users.Len(), detail)
	fmt.Fprintf(&b, "  Scopes:   %d\n", s.section("scopes").Len())
	fmt.Fprintf(&b, "  Filters:  allow %d, deny %d\n", pyLen(get(filters, "allow")), pyLen(get(filters, "deny")))
	list := func(heading string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n  %s:\n", heading)
		for _, it := range items {
			fmt.Fprintf(&b, "    - %s\n", it)
		}
	}
	list("Notes", rep.Notes)
	if opts.Force {
		list("Dropped (--force)", rep.Dropped)
	} else {
		list("Cannot be represented in the store", rep.Dropped)
	}
	errs := append(append([]string{}, rep.Errors...), verrs...)
	list("Errors", errs)
	_, _ = io.WriteString(stdout, b.String())

	if len(errs) > 0 {
		tail := "."
		if opts.Force {
			tail = " (--force does not override these)."
		}
		_, _ = fmt.Fprintf(stderr, "\ntacctl store: %d error(s) must be fixed in %s before it can be imported%s\n",
			len(errs), opts.Src, tail)
		return s, false, nil
	}
	if len(rep.Dropped) > 0 && !opts.Force {
		_, _ = fmt.Fprintf(stderr, "\ntacctl store: %d item(s) cannot be represented in the store. "+
			"Fix them, or re-run with --force to drop them.\n", len(rep.Dropped))
		return s, false, nil
	}
	return s, true, nil
}

// pyLen is len() of a list (0 for anything else).
func pyLen(v any) int {
	l, _ := v.([]any)
	return len(l)
}

// ErrNoRenderer is what ImportOptions.Render returns when no renderer is
// available (store_render_hook's status 2): the check is then not proven.
var ErrNoRenderer = errors.New("no renderer available")

// ErrSmokeSkipped is what ImportOptions.Smoke returns when the daemon
// load-smoke cannot run (no daemon binary; store_smoke_hook's status 2).
var ErrSmokeSkipped = errors.New("daemon load-smoke skipped")

// EquivFunc is the equivalence check of two tacquito.yaml files (model.
// EquivCheck): it writes its notes, the diff and the verdict to w and
// reports whether the files are equivalent. An error (a file cannot be
// read or parsed) is printed with Report.
type EquivFunc func(live, rendered string, w io.Writer) (bool, error)

// ImportOptions are the inputs of Import: the parsed command line of
// 'tacctl store import', the paths and the hooks. An error from a hook is
// printed by Import (a *Error or file-system error as Report words it,
// anything else as an [ERROR] line) before the line that reports the
// failure, so a hook returns its problem rather than printing it.
type ImportOptions struct {
	Src     string // the file to import; "" for ConfigPath
	Check   bool   // --check: write nothing; report and prove equivalence
	Force   bool   // --force: drop what the store cannot represent
	Replace bool   // --replace: overwrite an existing store

	StorePath   string // STORE_FILE
	ConfigPath  string // CONFIG, the live tacquito.yaml
	DatesDir    string // PASSWORD_DATES_DIR
	DisabledDir string // ${BACKUP_DIR}/disabled
	LegacyDir   string // ${BACKUP_DIR}/legacy (pre-store copies)

	// Snapshot is store_snapshot_hook, called before an existing store is
	// replaced; an error stops the import.
	Snapshot func() error
	// Render renders the imported store as a tacquito.yaml for --check
	// (store_render_hook). nil, or ErrNoRenderer, means no renderer.
	Render func(s *Store) ([]byte, error)
	// Equiv compares the source with the render (store_equiv_check).
	// Required when Render is set.
	Equiv EquivFunc
	// Smoke loads the rendered file in the daemon (store_smoke_hook); nil,
	// or ErrSmokeSkipped, means skipped.
	Smoke func(rendered string) error
	// Now is the clock of the pre-store copy's name (nil: time.Now).
	Now func() time.Time
	// TempDir is where --check renders ("" for os.TempDir); the directory
	// it creates there is removed before Import returns.
	TempDir string
}

// ImportStatus is the exit status of a 'store import' that did not succeed
// (every message has been printed): 1 failed, 3 (--check only) the import
// is clean but equivalence was not proven.
type ImportStatus struct{ Code int }

func (e *ImportStatus) Error() string { return fmt.Sprintf("store import: exit status %d", e.Code) }

// ImportFailed and ImportNotProven are the two ImportStatus values.
var (
	ImportFailed    = &ImportStatus{Code: 1}
	ImportNotProven = &ImportStatus{Code: 3}
)

// Import is store_import after its argument parsing (which, with its
// usage errors and exit status 2, is the CLI's): the import, or with Check
// the report and the equivalence proof. Messages go to out as 0.1.16
// prints them. It returns nil (exit 0) or ImportFailed / ImportNotProven.
func Import(out ui.Output, opts ImportOptions) error {
	src := opts.Src
	if src == "" {
		src = opts.ConfigPath
	}
	if !isRegular(src) {
		out.Error("Cannot import: " + src + " not found.")
		return ImportFailed
	}
	if !opts.Check && isRegular(opts.StorePath) && !opts.Replace {
		out.Error("A store already exists at " + opts.StorePath + "; importing would overwrite it.")
		out.Error("Use 'tacctl store import --check' to compare, or add --replace to overwrite.")
		return ImportFailed
	}
	existing := ""
	if isRegular(opts.StorePath) {
		existing = opts.StorePath
	}
	say := func(line string) { _, _ = io.WriteString(out.Stdout, line+"\n") }
	report := func(err error) { _, _ = io.WriteString(out.Stderr, Report(err)+"\n") }

	say("")
	s, ok, err := ImportLoad(out.Stdout, out.Stderr, ImportLoadOptions{
		Src: src, DatesDir: opts.DatesDir, DisabledDir: opts.DisabledDir,
		Existing: existing, Force: opts.Force,
	})
	if err != nil {
		report(err)
	}
	if err != nil || !ok {
		say("")
		out.Error("Import failed. Nothing was written.")
		return ImportFailed
	}
	say("")

	if !opts.Check {
		pre := ""
		switch {
		case existing != "":
			if opts.Snapshot != nil {
				if err := opts.Snapshot(); err != nil {
					printErr(out, err)
					return ImportFailed
				}
			}
		case sameFile(src, opts.ConfigPath):
			// The flip: the live config is about to stop being the source
			// of truth. Keep it, so 'tacctl store rollback' can go back.
			now := time.Now
			if opts.Now != nil {
				now = opts.Now
			}
			if pre, err = KeepPreStore(src, opts.LegacyDir, now()); err != nil {
				printErr(out, err)
				out.Error("Import failed: could not keep a copy of " + src + " under " +
					strings.TrimSuffix(opts.LegacyDir, "/") + "/. Nothing was written.")
				return ImportFailed
			}
		}
		if _, err := Write(opts.StorePath, s); err != nil {
			report(err)
			out.Error("Import failed. Nothing was written.")
			return ImportFailed
		}
		out.Info("Store written to " + opts.StorePath + ".")
		if pre != "" {
			out.Info("Pre-store " + src + " kept as " + pre + " ('tacctl store rollback' returns to it).")
		}
		return nil
	}
	return importCheck(out, opts, src, s)
}

// importCheck is the --check half of _store_import_run: steps 2-4 of the
// equivalence proof. Nothing persistent.
func importCheck(out ui.Output, opts ImportOptions, src string, s *Store) error {
	say := func(line string) { _, _ = io.WriteString(out.Stdout, line+"\n") }
	say("  import + validate:   OK")
	var text []byte
	err := ErrNoRenderer
	if opts.Render != nil {
		text, err = opts.Render(s)
	}
	proven := true
	switch {
	case errors.Is(err, ErrNoRenderer):
		say("  render:              SKIPPED (no renderer available)")
		say("  equivalence:         SKIPPED")
		say("  daemon load-smoke:   SKIPPED")
		proven = false
	case err != nil:
		printErr(out, err)
		say("  render:              FAILED")
		return ImportFailed
	default:
		say("  render:              OK")
		say("  equivalence:")
		dir, err := os.MkdirTemp(opts.TempDir, "tacctl-import.")
		if err != nil {
			_, _ = io.WriteString(out.Stderr, Report(&osError{err})+"\n")
			return ImportFailed
		}
		defer func() { _ = os.RemoveAll(dir) }()
		rendered := filepath.Join(dir, "tacquito.yaml")
		if err := os.WriteFile(rendered, text, 0o600); err != nil {
			_, _ = io.WriteString(out.Stderr, Report(&osError{err})+"\n")
			return ImportFailed
		}
		var diff bytes.Buffer
		equivalent := false
		if opts.Equiv == nil {
			err = &Error{Msg: "internal: no equivalence check"}
		} else {
			equivalent, err = opts.Equiv(src, rendered, &diff)
		}
		if err != nil {
			_, _ = io.WriteString(out.Stderr, Report(err)+"\n")
		}
		// printf '%s\n' "$(...)" | sed 's/^/    /'
		for _, line := range strings.Split(strings.TrimRight(diff.String(), "\n"), "\n") {
			say("    " + line)
		}
		if err != nil || !equivalent {
			say("")
			out.Error("Rendered config is not equivalent to " + src + ".")
			return ImportFailed
		}
		err = ErrSmokeSkipped
		if opts.Smoke != nil {
			err = opts.Smoke(rendered)
		}
		switch {
		case errors.Is(err, ErrSmokeSkipped):
			say("  daemon load-smoke:   SKIPPED")
		case err != nil:
			printErr(out, err)
			say("  daemon load-smoke:   FAILED")
			return ImportFailed
		default:
			say("  daemon load-smoke:   OK")
		}
	}
	say("")
	if !proven {
		out.Warn("Import is clean, but equivalence with " + src + " was not proven.")
		return ImportNotProven
	}
	out.Info("Check passed. Nothing was written.")
	return nil
}

// printErr prints a hook's error: a store or file-system error as Report
// words it ('tacctl store: ...'), anything else as an [ERROR] line.
func printErr(out ui.Output, err error) {
	var se *Error
	var oe *osError
	if errors.As(err, &se) || errors.As(err, &oe) {
		_, _ = io.WriteString(out.Stderr, Report(err)+"\n")
		return
	}
	out.Error(err.Error())
}

// sameFile is bash's 'a -ef b': both exist and are the same file.
func sameFile(a, b string) bool {
	sa, err := os.Stat(a)
	if err != nil {
		return false
	}
	sb, err := os.Stat(b)
	return err == nil && os.SameFile(sa, sb)
}
