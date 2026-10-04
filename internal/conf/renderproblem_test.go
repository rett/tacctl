package conf

import (
	"os"
	"path/filepath"
	"testing"
)

// RenderProblem: the words of radius_conf_view at 0.1.16. The syntax and
// mapping cases are pinned against the bash program in
// internal/render/radius (TestConfViewRefusals); here the rest.
func TestRenderProblem(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		path   string
		msg    string
		fixIt  bool
		wantOK string
	}{
		{"", "", false, "no path"},
		{filepath.Join(dir, "missing"), "", false, "missing file"},
		{write("empty", ""), "", false, "empty file"},
		{write("ok", "cost: 12\n"), "", false, "a mapping"},
	} {
		if msg, fixIt := RenderProblem(c.path); msg != c.msg || fixIt != c.fixIt {
			t.Errorf("%s: %q, %v", c.wantOK, msg, fixIt)
		}
	}
	bad := write("bad", "a: [\n")
	if msg, fixIt := RenderProblem(bad); msg != bad+": expected the node content, but found '<stream end>' (line 2, column 1)" || !fixIt {
		t.Errorf("syntax error: %q, %v", msg, fixIt)
	}
	// A file that cannot be read: strerror alone, no "fix it" advice.
	if msg, fixIt := RenderProblem(dir); msg != dir+": Is a directory" || fixIt {
		t.Errorf("directory: %q, %v", msg, fixIt)
	}
	// What 0.1.16 died on with a traceback gets the usual reason.
	val := write("val", "a: !!int abc\n")
	if msg, fixIt := RenderProblem(val); msg == "" || !fixIt {
		t.Errorf("value error: %q, %v", msg, fixIt)
	}
}
