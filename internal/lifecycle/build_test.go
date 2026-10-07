package lifecycle_test

// The installed command is obtained through the deploy clone's bootstrap
// shim (WP6.8): '<deploy>/bin/tacctl.sh --install-binary <command>', which
// installs the verified release binary of a release tag or builds the
// clone, and prints which. A clone whose shim predates that mode (0.2.0) is
// built with its '--build <command>' and the Go side prints the 'Building'
// line itself (orchestrate_test.go and matrix_test.go run that path).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// modernShim makes the deploy clone's shim one with '--install-binary' (the
// shim of this tree) and the recipe a stand-in that prints the shim's line
// for path (download or build) and writes the binary; fail: exit 1 after
// leaving <dst>.new behind.
func (o *ohost) modernShim(line string, fail bool) {
	o.t.Helper()
	shim := readFile(o.t, filepath.Join("..", "..", "bin", "tacctl.sh"))
	if !strings.Contains(shim, "--install-binary)") {
		o.t.Fatal("bin/tacctl.sh has no --install-binary mode")
	}
	o.write(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), shim)
	o.run.Func(func(c execx.Cmd) bool { return strings.HasSuffix(c.Name, "/bin/tacctl.sh") }, func(c execx.Cmd) (execx.Result, error) {
		if len(c.Args) != 2 || c.Args[0] != "--install-binary" {
			return execx.Result{Code: 1}, nil
		}
		_, _ = c.Stdout.Write([]byte("[INFO] " + line + "\n"))
		if fail {
			o.write(c.Args[1]+".new", "half")
			return execx.Result{Code: 1}, nil
		}
		o.write(c.Args[1], "release binary\n")
		_ = os.Chmod(c.Args[1], 0o755)
		return execx.Result{}, nil
	})
}

// install over a clone whose shim has '--install-binary': the command is
// obtained with it, its output passes through, and the Go side prints no
// 'Building' line of its own.
func TestInstallObtainsTheCommandWithInstallBinary(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.commit = "something-else"
	o.modernShim("Installing the 0.2.1 release binary (linux/amd64, verified)", false)
	if code := install(o, "-y"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	recipe := filepath.Join(o.p.Deploy, "bin", "tacctl.sh")
	if !o.run.Called(recipe, "--install-binary", o.p.Command) || o.run.Called(recipe, "--build") {
		t.Errorf("calls %v", o.run.Argvs())
	}
	inOrder(t, o.text(), "Management repo already cloned", "[INFO] Installing the 0.2.1 release binary (linux/amd64, verified)",
		"Installation Complete")
	if strings.Contains(o.text(), "Building "+o.p.Command) {
		t.Errorf("a Building line besides the shim's:\n%s", o.text())
	}
	if readFile(t, o.p.Command) != "release binary\n" {
		t.Error("the installed command is not the shim's")
	}
}

// The self-update of upgrade obtains the new command with
// '--install-binary' too, then re-executes it.
func TestSelfUpdateObtainsTheCommandWithInstallBinary(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.commit = "old"
	o.modernShim("Building "+o.p.Command+" from "+o.p.Deploy+"...", false)
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	recipe := filepath.Join(o.p.Deploy, "bin", "tacctl.sh")
	if !o.run.Called(recipe, "--install-binary", o.p.Command) || o.run.Called(recipe, "--build") {
		t.Errorf("calls %v", o.run.Argvs())
	}
	if n := strings.Count(o.text(), "Building "+o.p.Command); n != 1 {
		t.Errorf("%d Building lines:\n%s", n, o.text())
	}
	inOrder(t, o.text(), "Building "+o.p.Command, "[INFO] tacctl updated — restarting upgrade with new version...")
	if ex := o.run.Execs(); len(ex) != 1 || ex[0].Path != o.p.Command {
		t.Errorf("execs %+v", ex)
	}
}

// A failure of '--install-binary' is Decision 20's text with the way back,
// <command>.new is gone, the installed command is as it was, nothing is
// exec'd.
func TestSelfUpdateInstallBinaryFailure(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.commit = "old"
	o.modernShim("Building "+o.p.Command+" from "+o.p.Deploy+"...", true)
	if code := upgrade(o); code == 0 {
		t.Fatal("a failed --install-binary succeeded")
	}
	if _, err := os.Stat(o.p.Command + ".new"); !os.IsNotExist(err) {
		t.Errorf("%s.new left: %v", o.p.Command, err)
	}
	if readFile(t, o.p.Command) != "binary\n" || len(o.run.Execs()) != 0 {
		t.Errorf("command replaced or exec'd: %v", o.run.Execs())
	}
	if !strings.Contains(o.stderr.String(), "tacctl could not be built (see above). The installed command is unchanged.") {
		t.Errorf("stderr:\n%s", o.stderr)
	}
}

// A clone whose shim has no '--install-binary' (a 0.2.0 tree reached with
// 'config branch'): '--build', and the Building line from the Go side.
func TestBuildWithAnOlderShimUsesBuild(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.commit = "old"
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	recipe := filepath.Join(o.p.Deploy, "bin", "tacctl.sh")
	if !o.run.Called(recipe, "--build", o.p.Command) || o.run.Called(recipe, "--install-binary") {
		t.Errorf("calls %v", o.run.Argvs())
	}
	inOrder(t, o.text(), "[INFO] Building "+o.p.Command+" from "+o.p.Deploy+"...", "restarting upgrade")
}
