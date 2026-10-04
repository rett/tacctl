package cli

// The 'store' family (lib/store.sh cmd_store at 0.1.16). Native since
// WP2.4d: show and import; rollback since WP3.3a (store_rollback.go,
// registered with registerFamilyVerb). bin/tacctl.sh runs no preflight for
// 'store': 'store import <file>' and 'store show' work without the live
// config.

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/tacacs"
	"github.com/rett/tacctl/internal/model"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// storeSpecs are the arguments of each verb, for completion (args.go).
var storeSpecs = map[string]Spec{
	"show": {MaxArgs: 1, Flags: []Flag{{Names: []string{"--json"}}}},
	"import": {MaxArgs: 1, Args: []string{KindFile}, Flags: []Flag{
		{Names: []string{"--check"}}, {Names: []string{"--force"}}, {Names: []string{"--replace"}}}},
	"rollback": {},
}

const (
	storeShowUsage   = "Usage: tacctl store show [--json]"
	storeImportUsage = "Usage: tacctl store import [--check|--force] [--replace] [<file>]"
)

func storeCmd(inv *invocation) *cobra.Command {
	n := func(run func([]string) error) func(*cobra.Command, []string) error {
		return inv.native(noPreflight, run)
	}
	c := verb("store <subcommand>", "The canonical store: show, import, rollback",
		withRun(verb("show [--json]", "Print the model (YAML by default)"), n(inv.storeShow)),
		withRun(verb("import [--check|--force] [--replace] [<file>]",
			"Import a legacy tacquito.yaml (default: the live one)"), n(inv.storeImport)),
		// Replaced by store_rollback.go's (registerFamilyVerb).
		verb("rollback", "Undo the import: restore the pre-store tacquito.yaml"),
	)
	replaceRegistered(inv, c, storeVerbs)
	// No sub-command, help, -h, --help: the usage, exit 0; anything else:
	// an error, the usage, exit 1.
	c.RunE = n(func(args []string) error {
		switch sub := arg(args, 0); sub {
		case "", "help", "-h", "--help":
			inv.write(storeUsage())
			return nil
		default:
			inv.app.Out.ErrorE("Unknown store subcommand '" + sub + "'.")
			inv.write(storeUsage())
			return exit(1)
		}
	})
	return c
}

// storeVerbs are 'store' verbs other files register (registerFamilyVerb).
var storeVerbs = map[string]func(inv *invocation) *cobra.Command{}

// registerFamilyVerb makes '<family> <name>' native with the command mk
// builds, in place of the declared word of that name, for the verbs that
// live in a file of their own (store rollback, backend enable|disable). Call it from an
// init function; the family's spec table (storeSpecs, backendSpecs) already
// lists the verb's arguments.
func registerFamilyVerb(family, name string, mk func(inv *invocation) *cobra.Command) {
	switch family {
	case "store":
		storeVerbs[name] = mk
	case "backend":
		backendVerbs[name] = mk
	default:
		panic("registerFamilyVerb: no family " + family)
	}
}

// replaceRegistered puts the registered verbs of a family in place of its
// declared words.
func replaceRegistered(inv *invocation, c *cobra.Command, verbs map[string]func(inv *invocation) *cobra.Command) {
	names := make([]string, 0, len(verbs))
	for name := range verbs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if old := child(c, name); old != nil {
			c.RemoveCommand(old)
		}
		c.AddCommand(verbs[name](inv))
	}
}

// storeUsage is cmd_store_usage.
func storeUsage() string { return Usage("store", nil) }

// storeShow is cmd_store_show: the model as YAML (or JSON); the first
// argument must be nothing or --json (exit 2), the rest are ignored.
func (inv *invocation) storeShow(args []string) error {
	asJSON := false
	switch arg(args, 0) {
	case "":
	case "--json":
		asJSON = true
	default:
		inv.app.Out.Error(storeShowUsage)
		return exit(2)
	}
	return model.Show(inv.app.Out, inv.app.ModelPaths(), asJSON)
}

// importArgs is store_import's argument loop: --check, --force, --replace;
// any other dash-word is an unknown option (exit 2), a second file too.
type importArgs struct {
	check, force, replace bool
	src                   string
}

func (inv *invocation) parseImportArgs(args []string) (importArgs, error) {
	var p importArgs
	for _, a := range args {
		switch {
		case a == "--check":
			p.check = true
		case a == "--force":
			p.force = true
		case a == "--replace":
			p.replace = true
		case strings.HasPrefix(a, "-"):
			inv.app.Out.ErrorE("Unknown option '" + a + "'. " + storeImportUsage)
			return p, exit(2)
		default:
			if p.src != "" {
				inv.app.Out.Error("Only one file may be given.")
				return p, exit(2)
			}
			p.src = a
		}
	}
	return p, nil
}

// storeImport is store_import: the parsed command line, then store.Import
// with the hooks of this invocation (the snapshot, the TACACS+ render, the
// equivalence check and the daemon load-smoke).
func (inv *invocation) storeImport(args []string) error {
	p, err := inv.parseImportArgs(args)
	if err != nil {
		return err
	}
	return store.Import(inv.app.Out, inv.importOptions(p))
}

// importOptions are store.Import's inputs for this invocation.
func (inv *invocation) importOptions(p importArgs) store.ImportOptions {
	a := inv.app
	return store.ImportOptions{
		Src:         p.src,
		Check:       p.check,
		Force:       p.force,
		Replace:     p.replace,
		StorePath:   a.Paths.StoreFile,
		ConfigPath:  a.Paths.Config,
		DatesDir:    a.Paths.PWDatesDir,
		DisabledDir: filepath.Join(a.Paths.BackupDir, "disabled"),
		LegacyDir:   filepath.Join(a.Paths.BackupDir, "legacy"),
		Snapshot:    a.Snapshots().Hook,
		Render:      inv.importRender,
		Equiv:       model.EquivCheckRand(a.Knobs.Rand()),
		Smoke:       func(rendered string) error { return inv.importSmoke(inv.ctx, rendered) },
		Now:         a.Knobs.Now,
	}
}

// importRender is store_render_hook (render_tacacs_config): the imported
// store rendered as tacquito.yaml with the live tacctl.yaml's command
// rules, read back through the importer before it counts. A failure is
// printed here as the render program words it ('tacctl render: ...') and
// returned as ui.ErrReported, which store.Import does not print again.
func (inv *invocation) importRender(s *store.Store) ([]byte, error) {
	cfg := inv.app.Conf()
	fail := func(err error) ([]byte, error) {
		inv.stderrLine(rendered.Report(err))
		return nil, ui.ErrReported
	}
	if err := rtacacs.CheckOverrides(cfg.Path); err != nil {
		return fail(err)
	}
	dir, err := os.MkdirTemp("", "tacctl-render.")
	if err != nil {
		return fail(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	text, err := rtacacs.RenderToFile(s, cfg.Merged(), filepath.Join(dir, "tacquito.yaml"), rtacacs.DefaultLoader, nil)
	if err != nil {
		return fail(err)
	}
	return text, nil
}

// smoker is the TACACS+ module's daemon load-smoke.
type smoker interface {
	LoadSmoke(ctx context.Context, rendered string) tacacs.SmokeResult
}

// importSmoke is store_smoke_hook: nil passed, store.ErrSmokeSkipped (no
// daemon binary), ui.ErrReported failed (the module said why).
func (inv *invocation) importSmoke(ctx context.Context, rendered string) error {
	b, err := inv.app.Backends().Get(backend.TACACS)
	if err != nil {
		return store.ErrSmokeSkipped
	}
	s, ok := b.(smoker)
	if !ok {
		return store.ErrSmokeSkipped
	}
	switch s.LoadSmoke(ctx, rendered) {
	case tacacs.SmokePassed:
		return nil
	case tacacs.SmokeSkipped:
		return store.ErrSmokeSkipped
	}
	return ui.ErrReported
}
