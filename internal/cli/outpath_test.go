package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

// outInv is an invocation whose home is the sandbox's; env is added to the
// sandbox's environment.
func outInv(t *testing.T, env ...string) (*invocation, *sandbox) {
	t.Helper()
	sb := newSandbox(t, false)
	a := app.New(nil, paths.NewEnv(append(append([]string(nil), sb.env...), env...)), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}, &fake.Runner{})
	return &invocation{ctx: sb.runCtx(), app: a, hooks: sb.hooks}, sb
}

func TestOutPathRefusals(t *testing.T) {
	inv, sb := outInv(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, sb.homePath("escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "gone"), sb.homePath("dangling")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sb.homePath("."), sb.homePath("self")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, path, want string }{
		{"empty", "", "takes a path"},
		{"nul", sb.homePath("x\x00y"), "NUL"},
		{"tilde", "~/x", "starts with '~'"},
		{"tilde alone", "~", "starts with '~'"},
		{"tilde user", "~alice/x", "starts with '~'"},
		{"dollar", sb.homePath("$HOME/x"), "'$'"},
		{"dollar braces", sb.homePath("a${X}"), "'$'"},
		{"backtick", sb.homePath("`id`"), "backtick"},
		{"outside", filepath.Join(outside, "x"), "not inside your home"},
		{"root", "/", "not inside your home"},
		{"the home itself", sb.home, "not inside your home"},
		{"the home with a dot", sb.home + "/.", "not inside your home"},
		{"dotdot out", sb.homePath("a/../../x"), "not inside your home"},
		{"dotdot to parent", sb.homePath(".."), "not inside your home"},
		{"link out", sb.homePath("escape/x"), "not inside your home"},
		{"link out, deep", sb.homePath("escape/a/b/c"), "not inside your home"},
		{"link itself out", sb.homePath("escape"), "not inside your home"},
		{"dangling link", sb.homePath("dangling"), "cannot be resolved"},
		{"sibling with the home's name as prefix", sb.home + "-other/x", "not inside your home"},
	} {
		got, err := inv.outPath("--out", c.path)
		if err == nil || !strings.Contains(err.Error(), c.want) || got != "" {
			t.Errorf("%s (%q): %q, %v; want an error with %q", c.name, c.path, got, err, c.want)
			continue
		}
		if !strings.HasPrefix(err.Error(), "--out ") || !strings.Contains(err.Error(), "tacctl does not expand ~ or variables; name a path inside your home, relative to the current directory.") {
			t.Errorf("%s: the error does not say what to do: %v", c.name, err)
		}
	}
}

func TestOutPathAccepts(t *testing.T) {
	inv, sb := outInv(t)
	if err := os.MkdirAll(sb.homePath("d/e"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sb.homePath("d"), sb.homePath("inner")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sb.homePath("d/file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sb.homePath("d/file"), sb.homePath("filelink")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, path, want string }{
		{"new file", sb.homePath("x.txt"), sb.homePath("x.txt")},
		{"new deep file", sb.homePath("a/b/c.txt"), sb.homePath("a/b/c.txt")},
		{"existing directory", sb.homePath("d"), sb.homePath("d")},
		{"dotdot inside", sb.homePath("d/e/../x"), sb.homePath("d/x")},
		{"a name with a tilde inside", sb.homePath("a~b"), sb.homePath("a~b")},
		{"a dot-slash tilde", "./~x", ""},
		{"link inside", sb.homePath("inner/x"), sb.homePath("d/x")},
		{"a link to a file is kept as named", sb.homePath("filelink"), sb.homePath("filelink")},
	} {
		if c.path == "./~x" {
			continue // relative: below
		}
		got, err := inv.outPath("--out", c.path)
		if err != nil || got != c.want {
			t.Errorf("%s (%q): %q, %v; want %q", c.name, c.path, got, err, c.want)
		}
	}
}

// A relative path is taken from the current directory; a '~' that is not the
// first component's first character is a name like any other.
func TestOutPathRelative(t *testing.T) {
	serial(t)
	inv, sb := outInv(t)
	t.Chdir(sb.home)
	for path, want := range map[string]string{
		"x":      sb.homePath("x"),
		"a/b":    sb.homePath("a/b"),
		"./~x":   sb.homePath("~x"),
		"a/~/b":  sb.homePath("a/~/b"),
		"a/../b": sb.homePath("b"),
	} {
		if got, err := inv.outPath("--out-dir", path); err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", path, got, err, want)
		}
	}
	for _, path := range []string{"..", "../x", ".", "a/../.."} {
		if got, err := inv.outPath("--out-dir", path); err == nil || !strings.HasPrefix(err.Error(), "--out-dir ") {
			t.Errorf("%q: %q, %v; want a refusal", path, got, err)
		}
	}
	t.Chdir(t.TempDir())
	if _, err := inv.outPath("--out", "x"); err == nil || !strings.Contains(err.Error(), "not inside your home") {
		t.Errorf("a relative path from outside the home: %v", err)
	}
}

// The home is the account database's, for the person who ran sudo when the
// process is root, else for the process's own user; never $HOME.
func TestOutPathHomeIsTheAccountsNotTheEnvironment(t *testing.T) {
	inv, sb := outInv(t, "SUDO_UID=1234", "SUDO_GID=1234", "HOME=/etc")
	var asked []int
	inv.hooks.homeOfUID = func(uid int) (string, error) { asked = append(asked, uid); return sb.home, nil }
	inv.hooks.editEuid = func() int { return 0 }
	if got, err := inv.outPath("--out", sb.homePath("x")); err != nil || got != sb.homePath("x") {
		t.Fatalf("%q, %v", got, err)
	}
	if len(asked) != 1 || asked[0] != 1234 {
		t.Errorf("home of %v; want the sudo caller 1234", asked)
	}
	// not root: the process's own user, whatever SUDO_UID says
	asked = nil
	inv.hooks.editEuid = func() int { return 1000 }
	if _, err := inv.outPath("--out", sb.homePath("x")); err != nil || len(asked) != 1 || asked[0] != 1000 {
		t.Errorf("home of %v, %v; want the process's 1000", asked, err)
	}
	// $HOME names nothing
	if _, err := inv.outPath("--out", "/etc/x"); err == nil {
		t.Error("$HOME=/etc made /etc a home")
	}
	// no account, no home: a refusal that says so
	inv.hooks.homeOfUID = func(int) (string, error) { return "", os.ErrNotExist }
	if _, err := inv.outPath("--out", sb.homePath("x")); err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Errorf("no account: %v", err)
	}
	inv.hooks.homeOfUID = func(int) (string, error) { return "home/relative", nil }
	if _, err := inv.outPath("--out", sb.homePath("x")); err == nil {
		t.Error("a relative home was accepted")
	}
}
