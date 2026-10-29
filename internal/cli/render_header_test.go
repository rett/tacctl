package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/rendered"
)

// A drop-in that differs from a fresh render only in its comment (an older
// release's header, which named config listen and config metrics) is not
// drift: it is the recorded text, so it reads ok. The render writes it again,
// the backend counts as changed (RenderCommit) and RestartChanged restarts
// tacquito once, after a daemon-reload. That is the cost of the first render
// after the upgrade of 0.2.22, which rewords the header (CHANGELOG 18); a
// render of an unchanged tree restarts nothing.
func TestADropInThatDiffersOnlyInItsCommentIsRewrittenAndRestartsTheDaemon(t *testing.T) {
	hs := newHostSandbox(t)
	hs.installTacquito()
	var live, records string
	_ = filepath.Walk(hs.dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			switch {
			case filepath.Base(p) == "tacctl.conf" && strings.Contains(p, "tacquito.service.d"):
				live = p
			case filepath.Base(p) == "rendered.json":
				records = p
			}
		}
		return nil
	})
	if live == "" || records == "" {
		t.Fatalf("no live drop-in (%q) or records (%q) under %s", live, records, hs.dir)
	}
	// nothing changed: a render restarts nothing
	r := hs.runner()
	hs.run(r, "config", "render")
	if hs.code != 0 || r.Called("systemctl", "restart") {
		t.Fatalf("a render of nothing: exit %d, restart %v\n%s", hs.code, r.Called("systemctl", "restart"), hs.err.String())
	}
	// the drop-in as an older release rendered it: another comment, recorded
	text, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	old := strings.Replace(string(text), "'tacctl server listen'", "'tacctl config listen'", 1)
	old = strings.Replace(old, "'tacctl server metrics'", "'tacctl config metrics'", 1)
	if old == string(text) || !strings.Contains(old, "tacctl config listen") {
		t.Fatalf("the header changed:\n%s", text)
	}
	if err := os.WriteFile(live, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rendered.Record(records, live); err != nil {
		t.Fatal(err)
	}
	r = hs.runner()
	hs.run(r, "config", "render")
	got, _ := os.ReadFile(live)
	if hs.code != 0 || string(got) != string(text) {
		t.Fatalf("exit %d; the drop-in was not rewritten:\n%s", hs.code, got)
	}
	if !r.Called("systemctl", "daemon-reload") || !r.Called("systemctl", "restart") {
		t.Errorf("a comment-only difference: daemon-reload %v, restart %v (%v)", r.Called("systemctl", "daemon-reload"), r.Called("systemctl", "restart"), r.Argvs())
	}
}
