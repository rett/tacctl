package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// dirNames lists the entries of dir, sorted.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// The temporary directory of an invocation is the TMPDIR of its environment
// (paths.Paths.TempDir), never the process's: with the process TMPDIR on a
// directory that holds a sentinel, commands that stage in the temporary
// directory leave it untouched, leave the sandbox's own empty, and a sandbox
// TMPDIR that cannot be used is the one the error names.
//
// This test sets the process environment, so it is serial.
func TestTempDirIsTheInvocationsNotTheProcess(t *testing.T) {
	sentinel := t.TempDir()
	if err := os.WriteFile(filepath.Join(sentinel, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", sentinel)
	before := dirNames(t, sentinel)

	// store import (render, smoke), config render, a dry run, store rollback.
	sb, _ := flippedSandbox(t)
	sb.run("", []string{"config", "render", "--dry-run", "--out", sb.path("preview")})
	sb.expect(0, "Dry run: rendered into", "")
	sb.run("y\n", []string{"store", "rollback"})
	sb.expect(0, "Rolled back", "")
	sb.run("", []string{"store", "import", "--check"})
	// A sudoers drop-in is checked in a temporary file.
	env := []string{"TACCTL_SUDOERS_FILE=" + sb.path("sudoers.d", "tacctl"), "TACCTL_TIER_SUDOERS_FILE=" + sb.path("sudoers.d", "tacctl-tiers")}
	sb.cfgRun("", []string{"config", "sudoers", "tiers", "install"}, nil, env...)

	if got := dirNames(t, sentinel); !reflect.DeepEqual(got, before) {
		t.Errorf("the process TMPDIR was used: %v, was %v", got, before)
	}
	if left := dirNames(t, sb.path("tmp")); len(left) != 0 {
		t.Errorf("the sandbox TMPDIR holds %v", left)
	}

	// Positive proof: with the sandbox's directory gone, the invocation's
	// own TMPDIR is the one that cannot be used, and the message names it.
	if err := os.RemoveAll(sb.path("tmp")); err != nil {
		t.Fatal(err)
	}
	sb.cfgRun("", []string{"config", "sudoers", "tiers", "install"}, nil, env...)
	want := "mktemp: failed to create file via template '" + filepath.Join(sb.path("tmp"), "tmp.XXXXXXXXXX") + "': "
	if sb.code != 1 || !strings.Contains(sb.err.String(), want) {
		t.Errorf("exit %d, stderr %q, want it to hold %q", sb.code, sb.err.String(), want)
	}
	if got := dirNames(t, sentinel); !reflect.DeepEqual(got, before) {
		t.Errorf("the process TMPDIR was used after the sandbox's was removed: %v, was %v", got, before)
	}
}
