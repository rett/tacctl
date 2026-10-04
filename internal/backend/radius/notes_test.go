package radius_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/store"
)

func notes(r *renv) string {
	r.reset()
	r.m.RenderNotes(context.Background())
	return strip(r.stdout.String())
}

// "validate: a scope served over RADIUS that sends no vendor attribute is
// warned about, unless it is a Linux-host scope": the warning of
// render_notes names the scopes model_vendor_gaps finds, which reads the
// host registry for the scopes of enrolled Linux hosts.
func TestRenderNotesVendorGapsAndLinuxHostScopes(t *testing.T) {
	r := newEnv(t)
	r.up()
	line := func(scopes string) string {
		return "[WARN] Over RADIUS no vendor attribute is sent to the devices of scope(s) " + scopes +
			": an Access-Accept carries Service-Type only. Enable what they need: tacctl scope vendor-attrs <scope> enable cisco|juniper|wti\n"
	}
	contains(t, notes(r), line("lab, prod, prod-inner, wifi"))
	apply := func(name string, fields ...string) {
		t.Helper()
		if _, err := r.apply(r.mutate(scopeSet(name, fields...))); err != nil {
			t.Fatalf("scope %s %v: %v\n%s", name, fields, err, r.stderr)
		}
	}
	apply("lab", "vendor_attrs=cisco")
	apply("prod", "devices=10.9.9.9/32=juniper")
	// wifi: the scope of two enrolled hosts, and one /32 of theirs.
	apply("wifi", "prefixes=10.30.0.5/32")
	writeFile(t, r.p.LinuxHosts, "h1|root@10.30.0.5||wifi|10.0.0.42||radius\nh2|root@h2||wifi|10.0.0.42||radius\n\n|x||\n")
	contains(t, notes(r), line("prod-inner"))
	// A host scope with a wider prefix is not told apart: warned about.
	apply("wifi", "prefixes=10.30.0.5/32,10.31.0.0/24")
	contains(t, notes(r), line("prod-inner, wifi"))
}

// With nothing to warn about the notes are silent.
func TestRenderNotesSilent(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.minimal.yaml")
	r.enableList("radius")
	contains(t, notes(r), "devices of scope(s) lab: an Access-Accept carries Service-Type only.")
	if _, err := store.Mutate(r.p.StoreFile, store.MutateOptions{}, func(s *store.Store) error {
		return s.ScopeSet("lab", "vendor_attrs=cisco")
	}); err != nil {
		t.Fatal(err)
	}
	if got := notes(r); got != "" {
		t.Errorf("notes: %q", got)
	}
	// No store: no notes, no failure.
	if err := os.Remove(r.p.StoreFile); err != nil {
		t.Fatal(err)
	}
	if got := notes(r); got != "" {
		t.Errorf("notes without a store: %q", got)
	}
	if got := status(t, r, backend.StatusConfig); strings.Contains(got, "Vendor attributes") {
		t.Errorf("status config without a store: %q", got)
	}
}

// A store that does not read, or a tacctl.yaml that does not parse, makes
// the notes empty and the reports shorter, never an error.
func TestNotesTolerateUnreadableInput(t *testing.T) {
	r := newEnv(t)
	r.up()
	writeFile(t, r.p.Overrides, "listeners: [\n")
	r.env.Conf.Reload()
	if got := status(t, r, backend.StatusConfig); strings.Contains(got, "Connection filters") || !strings.Contains(got, "Config:") {
		t.Errorf("config with a bad tacctl.yaml: %q", got)
	}
	writeFile(t, r.p.Overrides, "backends:\n  enabled: [tacacs, radius]\n")
	r.env.Conf.Reload()
	writeFile(t, r.p.StoreFile, "version: [\n")
	if got := notes(r); got != "" {
		t.Errorf("notes: %q", got)
	}
}

// A commit that cannot write beside the live file fails without installing
// anything of that file, and leaves no .tacctl-new behind.
func TestCommitFailsWhenTheDirectoryIsReadOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	ctx := context.Background()
	dir := t.TempDir()
	if err := r.m.RenderStage(ctx, dir, false); err != nil {
		t.Fatal(err)
	}
	// The dictionary's directory does not exist yet, and raddb cannot be written.
	if err := os.Chmod(r.m.L.Dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(r.m.L.Dir, 0o755) }()
	changed, err := r.m.RenderCommit(ctx, dir)
	wantCode(t, err, 1)
	if changed {
		t.Error("changed")
	}
	contains(t, strip(r.stderr.String()), "[ERROR] Cannot create "+r.m.L.DictDir)
	// A stage directory without its status is no stage.
	if err := os.Remove(filepath.Join(dir, "status")); err != nil {
		t.Fatal(err)
	}
	r.reset()
	_, err = r.m.RenderCommit(ctx, dir)
	wantCode(t, err, 1)
	contains(t, r.stderr.String(), "Cannot read "+filepath.Join(dir, "status"))
	writeFile(t, filepath.Join(dir, "status"), "current current\n")
	r.reset()
	_, err = r.m.RenderCommit(ctx, dir)
	wantCode(t, err, 1)
}

// A stage of a store that does not render says why on stderr, as the render
// program did, and the gate does not care.
func TestStageOfAnUnrenderableStore(t *testing.T) {
	r := newEnv(t)
	r.useStore("store.radius.yaml")
	r.enableList("radius")
	ctx := context.Background()
	// A user whose name FreeRADIUS reads as a default for everyone.
	w := r.mutate(func(s *store.Store) error {
		return s.UserSet("DEFAULTx", "group=operator", "scopes=lab", "hash=24326224313224616c6963652e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e")
	})
	if err := w(); err != nil {
		t.Fatal(err)
	}
	err := r.m.RenderStage(ctx, t.TempDir(), false)
	wantCode(t, err, 1)
	contains(t, r.stderr.String(), "tacctl render: user 'DEFAULTx' cannot be served over RADIUS")
	// An unreadable tacctl.yaml is refused with 0.1.16's text.
	r.reset()
	writeFile(t, r.p.Overrides, "backends: [\n")
	r.env.Conf.Reload()
	err = r.m.RenderStage(ctx, t.TempDir(), false)
	wantCode(t, err, 1)
	contains(t, r.stderr.String(), "tacctl render: "+r.p.Overrides+": ")
	contains(t, r.stderr.String(), " -- fix it before rendering")
	// No store at all.
	r.reset()
	if err := os.Remove(r.p.StoreFile); err != nil {
		t.Fatal(err)
	}
	err = r.m.RenderStage(ctx, t.TempDir(), false)
	wantCode(t, err, 1)
	contains(t, r.stderr.String(), "tacctl render: "+r.p.StoreFile+": No such file or directory")
}
