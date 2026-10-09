package lifecycle

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// noticeFor is what presetNotice prints for a tacctl.yaml holding text.
func noticeFor(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tacctl.yaml")
	if text != "" {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	c := conf.Load(path, conf.DefaultBackends)
	h := &Host{Env: &Env{Env: &backend.Env{Conf: c, Out: ui.Output{Stdout: &out, Stderr: &out}}}}
	h.presetNotice()
	return out.String()
}

// An install that ran 0.2.2's role preset gets the red notice after the
// upgrade; a clean one, and one whose engineer holds other values, do not.
func TestPresetNotice(t *testing.T) {
	if got := noticeFor(t, ""); got != "" {
		t.Errorf("a clean install: %q", got)
	}
	// Build tacctl.yaml with the 0.2.2 engineer rules through the setters.
	path := filepath.Join(t.TempDir(), "tacctl.yaml")
	c := conf.Load(path, conf.DefaultBackends)
	if err := policy.Write(c, "engineer", policy.Engineer022Commands()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := noticeFor(t, string(data))
	if !strings.Contains(got, ui.Red) || !strings.Contains(got, "commands.engineer") ||
		!strings.Contains(got, "tacctl group reset engineer --dry-run") || !strings.Contains(got, "tacctl group reset engineer"+ui.NC) ||
		strings.Contains(got, "preset roles") || !strings.Contains(got, "did not hold") {
		t.Errorf("notice: %q", got)
	}
	// The same rules with one more rule are the operator's own.
	if err := policy.InsertRule(c, "engineer", "ping", "deny", ""); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if got := noticeFor(t, string(data)); got != "" {
		t.Errorf("customised engineer: %q", got)
	}
}
