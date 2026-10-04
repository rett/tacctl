package tacacs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// render_tacacs.bats: "render: a rendered file imports back to the same
// model and re-renders byte-identically".
func TestARenderedFileImportsBackAndReRendersByteIdentically(t *testing.T) {
	for _, name := range []string{"minimal", "multiscope"} {
		t.Run(name, func(t *testing.T) {
			w := t.TempDir()
			golden := readFile(t, filepath.Join(goldenDir, "tacquito."+name+".rendered.yaml"))
			cfg, st := filepath.Join(w, "etc", "tacquito.yaml"), filepath.Join(w, "state", "store.yaml")
			writeFile(t, cfg, string(golden))
			for _, d := range []string{"state/backups/password-dates", "state/backups/disabled", "state/backups/legacy"} {
				if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			var out, errOut bytes.Buffer
			err := store.Import(ui.Output{Stdout: &out, Stderr: &errOut}, store.ImportOptions{
				StorePath: st, ConfigPath: cfg,
				DatesDir:    filepath.Join(w, "state/backups/password-dates"),
				DisabledDir: filepath.Join(w, "state/backups/disabled"),
				LegacyDir:   filepath.Join(w, "state/backups/legacy"),
			})
			if err != nil {
				t.Fatalf("import: %v\n%s%s", err, out.String(), errOut.String())
			}
			if bytes.Contains(out.Bytes(), []byte("Cannot be represented")) {
				t.Fatalf("import dropped content:\n%s", out.String())
			}
			diffText(t, readFile(t, st), readFile(t, filepath.Join(fixDir, "store."+name+".yaml")), "imported store")
			s, err := store.Load(st)
			if err != nil {
				t.Fatal(err)
			}
			text, err := RenderToFile(s, defaultView(t), filepath.Join(w, "out.yaml"), DefaultLoader, nil)
			if err != nil {
				t.Fatal(rendered.Report(err))
			}
			diffText(t, text, golden, "re-render")
			diffText(t, readFile(t, filepath.Join(w, "out.yaml")), golden, "re-rendered file")
		})
	}
}

// Each golden says what its store says, for the render gate's adoption;
// the other store's golden does not.
func TestGoldensMatchTheirStores(t *testing.T) {
	for _, name := range []string{"minimal", "multiscope"} {
		path := filepath.Join(goldenDir, "tacquito."+name+".rendered.yaml")
		m := model.FromStore(loadStore(t, "store."+name+".yaml"))
		if !MatchesModel(path, m, DefaultLoader) {
			probs, err := ReadbackProblems(path, m, DefaultLoader)
			t.Fatalf("%s: %v %v", name, probs, err)
		}
		if err := Readback(path, m, defaultView(t), DefaultLoader); err != nil {
			t.Fatalf("%s: %s", name, rendered.Report(err))
		}
	}
	if MatchesModel(filepath.Join(goldenDir, "tacquito.minimal.rendered.yaml"),
		model.FromStore(loadStore(t, "store.multiscope.yaml")), DefaultLoader) {
		t.Fatal("minimal matches multiscope")
	}
}

// The real importer's reports and refusals reach the read-back.
func TestDefaultLoaderReportsAndRefusals(t *testing.T) {
	// A pre-store tacquito.yaml with content the store cannot hold.
	r, err := DefaultLoader(filepath.Join(fixDir, "legacy.unrepresentable.yaml"))
	if err != nil || len(r.Errors)+len(r.Dropped) == 0 {
		t.Fatalf("%v %v", r, err)
	}
	p := filepath.Join(t.TempDir(), "t.yaml")
	writeFile(t, p, "- a\n")
	if _, err := DefaultLoader(p); err == nil || rendered.Report(err) != "tacctl render: "+p+": top level is not a YAML mapping" {
		t.Fatalf("got %v", err)
	}
	m := model.FromStore(loadStore(t, "store.multiscope.yaml"))
	if MatchesModel(p, m, DefaultLoader) {
		t.Fatal("matches")
	}
}
