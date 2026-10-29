package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/rendered"
)

// Why the comment of the generated drop-in (rtacacs.DropInHeader) is not
// reworded: a drop-in that differs from a fresh render only in its comment is
// not drift (it is the recorded text, so it reads ok), but the render writes
// it again, the backend counts as changed, and RestartChanged restarts
// tacquito. An upgrade would then restart the daemon for a comment, which
// operators must not be exposed to. The text of the header and of the unit
// templates stays until a release restarts the daemon anyway.
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
	old := strings.Replace(string(text), "# unit settings of your own", "# (an older comment) unit settings of your own", 1)
	if old == string(text) {
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
