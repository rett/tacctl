package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

func TestNew(t *testing.T) {
	var out, errb bytes.Buffer
	args := []string{"user", "list"}
	r := &fake.Runner{}
	a := New(args, paths.NewEnv([]string{"TACCTL_STATE_DIR=/t/state", "TACCTL_TREE=/t/tree"}), "/x/dist/tacctl", 1000,
		Stdio{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}, r)
	args[0] = "changed"
	if a.Args[0] != "user" || len(a.Args) != 2 {
		t.Errorf("Args = %q (must be a copy)", a.Args)
	}
	if a.Paths.StoreFile != "/t/state/store.yaml" || a.Paths.Tree != "/t/tree" {
		t.Errorf("Paths not resolved from env: %+v", a.Paths)
	}
	if a.Exe != "/x/dist/tacctl" || a.EUID != 1000 || a.Runner != r || a.Stdin == nil {
		t.Errorf("App = %+v", a)
	}
	a.Out.Info("x")
	a.Out.Error("y")
	if !strings.Contains(out.String(), "[INFO]") || !strings.Contains(errb.String(), "[ERROR]") {
		t.Errorf("Out not wired: %q %q", out.String(), errb.String())
	}
}
