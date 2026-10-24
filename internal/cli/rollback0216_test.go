package cli

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// 'tacctl rollback 0.2.16' (docs/plans/0.2.17-plan.md D257) on the host
// sandbox: a 0.2.17 state is the 0.2.16 one with audit.strict. The plan's own
// cases are internal/lifecycle's.

func rollback0216State(t *testing.T, strict string) *hostSandbox {
	t.Helper()
	hs := rollbackState(t)
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"audit:\n  strict: "+strict+"\n", 0o640)
	return hs
}

func TestRollback0216DryRunListsTheKeyAndWritesNothing(t *testing.T) {
	hs := rollback0216State(t, "true")
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, args := range [][]string{{"rollback", "0.2.16"}, {"rollback", "v0.2.16"}, {"rollback", "0.2.16", "--hosts"}} {
		r := hs.runner()
		hs.run(r, args...)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		if !reflectEqual(before, tree(t, hs.dir)) || hs.snapshots() != snaps || r.Called("visudo") || r.Called("ssh") {
			t.Errorf("%v changed %q", args, changedFiles(before, tree(t, hs.dir)))
		}
	}
	hs.run(nil, "rollback", "0.2.16")
	out := hs.all()
	for _, want := range []string{
		"Roll back to 0.2.16 (dry run)",
		"1. " + hs.path("state") + "/tacctl.yaml: remove the keys 0.2.16 does not know   [does]",
		"remove audit.strict",
		"2. leave every other file untouched   [leaves]",
		"audit.strict is set and is dropped",
		"To convert the state: tacctl rollback 0.2.16 --apply --yes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"console.yaml: write it", "per-device SNMP", "NETCONF service setting", "device.config.max_concurrency"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run names %q:\n%s", not, out)
		}
	}
}

func TestRollback0216ApplyRoundTrip(t *testing.T) {
	hs := rollback0216State(t, "true")
	hs.run(nil, "rollback", "0.2.16", "--apply")
	hs.expect(1, "", "The warnings above need your decision")
	if !strings.Contains(hs.overrides(), "strict: true") {
		t.Fatal("a refused apply changed tacctl.yaml")
	}
	snaps := hs.snapshots()
	hs.run(nil, "rollback", "0.2.16", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	out := hs.all()
	for _, want := range []string{"removed 1 key", "Next steps", "tacctl upgrade --branch 0.2.16",
		"do not add the 'audit' setting (audit.strict)", "holds the 0.2.17 state"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply output lacks %q:\n%s", want, out)
		}
	}
	if ov := hs.overrides(); strings.Contains(ov, "audit") || !strings.Contains(ov, "max_concurrency: 16") {
		t.Errorf("tacctl.yaml after:\n%s", ov)
	}
	if hs.snapshots() == snaps {
		t.Error("no snapshot was taken first")
	}
	// The audit line of the rollback names the target and the key count.
	hs.run(nil, "rollback", "0.2.16", "--apply")
	hs.expect(0, "Nothing to convert", "")
}

// A state without the key has nothing to convert, and a strict=false state
// needs no --yes.
func TestRollback0216WithoutTheKeyOrWithItFalse(t *testing.T) {
	hs := rollbackState(t)
	hs.run(nil, "rollback", "0.2.16", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.16 can read.", "")
	hf := rollback0216State(t, "false")
	hf.run(nil, "rollback", "0.2.16", "--apply")
	hf.expect(0, "removed 1 key", "")
	if strings.Contains(hf.overrides(), "audit") {
		t.Errorf("tacctl.yaml: %q", hf.overrides())
	}
}

// 0.2.10 to 0.2.15 are not targets: the refusal names the targets and no route.
func TestRollback0216RefusesTheReleasesBetween(t *testing.T) {
	hs := rollback0216State(t, "true")
	before := tree(t, hs.dir)
	hs.run(nil, "rollback", "0.2.15")
	hs.expect(1, "", "is not a release to roll back to")
	if !reflectEqual(before, tree(t, hs.dir)) {
		t.Errorf("a refusal changed %q", changedFiles(before, tree(t, hs.dir)))
	}
}

// The check against the real release: where the 0.2.16 tag is here and go is
// there, build that release (testknobs) and run its config validate against
// the state, before and after the rollback. Before, it refuses audit.strict
// as an unknown key (so the removal is needed); after, it accepts the state.
func TestRollbackRealOldBinary0216(t *testing.T) {
	bin := oldBinaryOf(t, "0.2.16", old0216Flag)
	hs := rollback0216State(t, "true")
	stubs := t.TempDir()
	for _, name := range []string{"systemctl", "logger", "chown"} {
		if err := os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, int) {
		res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: bin, Args: args,
			Env: append(append([]string(nil), hs.env...), "PATH="+stubs+":/usr/bin:/bin", "HOME="+t.TempDir(), "LANG=C.UTF-8")})
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return plain(string(res.Stdout) + string(res.Stderr)), res.Code
	}
	out, code := run("config", "validate")
	if code != 1 || !strings.Contains(out, "audit.strict: unknown config key") {
		t.Errorf("0.2.16 config validate before: %d\n%s", code, out)
	}
	hs.run(hs.runner(), "rollback", "0.2.16", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	out, code = run("config", "validate")
	if code != 0 || strings.Contains(out, "unknown config key") || !strings.Contains(out, "Configuration is valid.") {
		t.Errorf("0.2.16 config validate after: %d\n%s", code, out)
	}
}

// old0216Flag names a 0.2.16 binary built with -tags testknobs, to skip the
// build: go test ./internal/cli -run RealOldBinary0216 -args -old-bin-0216=<path>.
var old0216Flag = flag.String("old-bin-0216", "", "a tacctl 0.2.16 binary built with -tags testknobs (TestRollbackRealOldBinary0216)")
