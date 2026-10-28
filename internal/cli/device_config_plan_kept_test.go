package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
)

// The rules of the kept back-out and of the files beside a plan (WP13.2,
// second review): what a narrower plan, a plan with nothing to type and a
// plan for another address do to it, what --backout prints when the plan
// cannot be made, and the files of an earlier run that sit beside a new one.

// planDropPrivilege removes the first 'privilege exec' line of a Cisco text:
// a second section (roles) for the plan to change.
func planDropPrivilege(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "privilege exec ") {
			return strings.Join(append(lines[:i:i], lines[i+1:]...), "\n")
		}
	}
	return text
}

// A Cisco box whose device lacks its server block and one privilege line: a
// plan of aaa and roles.
func planCiscoTwoSections(t *testing.T) *pullBox {
	t.Helper()
	b := planCiscoBox(t, "", ciscoVersionModern)
	b.serve("cisco", planDropServer(planDropPrivilege(b.expected("lab-c"))))
	b.version(ciscoVersionModern)
	b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %s", b.sb.code, b.sb.stderr())
	}
	return b
}

func readKept(t *testing.T, b *pullBox, name string) string {
	t.Helper()
	data, err := os.ReadFile(b.sb.path("var-lib", "device-config", name+".backout"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// S3: a narrower plan from the same pull does not replace the kept back-out
// (it covers what was pasted), and --backout names the sections it undoes.
// S5: a plan from another pull says it replaces the kept one of the earlier
// pull.
func TestPlanKeptBackoutCoversWhatWasPasted(t *testing.T) {
	b := planCiscoTwoSections(t)
	out := b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "PASTE FROM HERE: lab-c") {
		t.Fatalf("plan: %d\n%s", b.sb.code, out)
	}
	kept := readKept(t, b, "lab-c")
	if !strings.Contains(kept, "\nsections: aaa,roles\n") || !strings.Contains(kept, "\naddress: 192.168.1.30\n") ||
		!strings.Contains(kept, "\nvendor: cisco\n") {
		t.Fatalf("the stamp:\n%s", kept)
	}
	// the narrower plan of the same pull keeps it, and says so
	b.run("device", "config", "plan", "lab-c", "--section", "roles")
	if again := readKept(t, b, "lab-c"); again != kept {
		t.Errorf("a narrower plan replaced the kept back-out:\n%s", again)
	}
	if !strings.Contains(b.sb.stderr(), "lab-c: the back-out kept from this pull covers aaa, roles and is kept: this plan covers roles only") {
		t.Errorf("stderr: %q", b.sb.stderr())
	}
	// --backout names what it undoes, and holds the server's removal
	bo := b.run("device", "config", "plan", "lab-c", "--backout", "--section", "roles")
	first := strings.SplitN(bo, "\n", 2)[0]
	if !strings.HasPrefix(first, "! This back-out undoes the plan of aaa, roles made from the pull of ") ||
		!strings.Contains(bo, "\nno tacacs server TACACS\n") {
		t.Errorf("--backout:\n%s", bo)
	}
	// a plan that covers the same sections replaces it (the same pull)
	b.run("device", "config", "plan", "lab-c")
	if replaced := readKept(t, b, "lab-c"); !strings.Contains(replaced, "\nsections: aaa,roles\n") {
		t.Errorf("replaced:\n%s", replaced)
	}
	// a later pull, a plan with changes: the report says it replaces the one
	// kept for the earlier pull
	b.run("device", "config", "pull", "lab-c")
	out = b.run("device", "config", "plan", "lab-c")
	if !strings.Contains(unwrapPlan(out), "WARNING: this plan replaces the kept back-out of the plan from the pull of ") ||
		!strings.Contains(unwrapPlan(out), "(UTC); print it first with 'tacctl device config plan lab-c --backout'") {
		t.Errorf("no word of the replaced back-out:\n%s", out)
	}
	if !strings.Contains(unwrapPlan(out), "says which pull it undoes, until the next plan with changes") {
		t.Errorf("the after-steps do not say how long it is kept:\n%s", out)
	}
	js := b.run("device", "config", "plan", "lab-c", "--json")
	if strings.Contains(js, "replaces the kept back-out") {
		t.Errorf("a plan from the same pull says it replaces the kept back-out:\n%s", js)
	}
}

// S5: the kept back-out is the device's: a name that moved to another address
// is another device.
func TestPlanKeptBackoutIsOfOneAddress(t *testing.T) {
	b := planCiscoBox(t, "", ciscoVersionModern)
	b.run("device", "config", "plan", "lab-c")
	b.sb.write("state/devices.yaml", "version: 1\nsettings:\n  stale_days: 30\ndevices:\n  lab-c:\n    address: 192.168.1.31\n    vendor: cisco\n    host_keys:\n    - "+
		b.srv.HostKey()+"\n", 0o600)
	out := b.run("device", "config", "plan", "lab-c", "--backout")
	if b.sb.code != 0 || strings.Contains(out, "BACK-OUT FROM HERE") ||
		!strings.Contains(out, "! lab-c: nothing to back out: the kept back-out is for another device address") {
		t.Errorf("another address: %d\n%s", b.sb.code, out)
	}
}

// S4: a later plan that has changes and no line tacctl can type to undo them
// removes the kept back-out (a later --backout would print the earlier plan's
// for it), and says so.
func TestPlanWithNothingToTypeRemovesTheKeptBackout(t *testing.T) {
	b := planBoxJunos(t)
	b.run("device", "config", "pull", "lab-j")
	out := b.run("device", "config", "plan", "lab-j")
	if b.sb.code != 0 || !strings.Contains(out, "PASTE FROM HERE: lab-j") {
		t.Fatalf("plan: %d\n%s", b.sb.code, out)
	}
	kept := b.sb.path("var-lib", "device-config", "lab-j.backout")
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("no kept back-out: %v", err)
	}
	// the paste is made: the device runs the rendering; its secrets are to be
	// pushed again: changes, and nothing tacctl could type to undo them
	text := b.expected("lab-j")
	b.serve("juniper", text)
	b.servePlain(text)
	b.run("device", "config", "pull", "lab-j")
	out = b.run("device", "config", "plan", "lab-j", "--secrets")
	if b.sb.code != 0 || !strings.Contains(out, "PASTE FROM HERE: lab-j") {
		t.Fatalf("--secrets plan: %d\n%s", b.sb.code, out)
	}
	if _, err := os.Stat(kept); err == nil {
		t.Errorf("the plan with nothing to type left the earlier plan's back-out")
	}
	if !strings.Contains(unwrapPlan(out), "WARNING: this plan has no lines tacctl can type to undo it and removes the kept back-out of the plan from the pull of ") {
		t.Errorf("no word of the removed back-out:\n%s", out)
	}
	out = b.run("device", "config", "plan", "lab-j", "--backout")
	if !strings.Contains(out, "nothing to back out") && !strings.Contains(out, "BACK-OUT FROM HERE") {
		t.Errorf("--backout:\n%s", out)
	}
	if strings.Contains(out, "This back-out undoes the plan") {
		t.Errorf("the earlier plan's back-out was printed:\n%s", out)
	}
}

// --backout needs none of the plan's prerequisites: a stale record or a
// rendering that fails does not take what was kept away.
func TestPlanBackoutPrintsTheKeptOneWhenThePlanCannotBeMade(t *testing.T) {
	b := planCiscoBox(t, "", ciscoVersionModern)
	b.run("device", "config", "plan", "lab-c")
	b.editRecord("lab-c", func(r *devconf.Record) { r.Pulled = r.Pulled.Add(-100 * 24 * time.Hour) })
	out := b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 1 || !strings.Contains(out, "CANNOT BE PLANNED") {
		t.Fatalf("a stale record: %d\n%s", b.sb.code, out)
	}
	out = b.run("device", "config", "plan", "lab-c", "--backout")
	if b.sb.code != 0 || !strings.Contains(out, "!!!!! BACK-OUT FROM HERE: lab-c !!!!!") ||
		!strings.HasPrefix(out, "! This back-out undoes the plan of aaa made from the pull of ") {
		t.Errorf("--backout of a stale record: %d\n%s", b.sb.code, out)
	}
	if !strings.Contains(b.sb.stderr(), "the plan itself cannot be made") || !strings.Contains(b.sb.stderr(), "stale pull") {
		t.Errorf("stderr: %q", b.sb.stderr())
	}
	// a device that was never pulled and has nothing kept: the plan's own
	// refusal stands
	b2 := newPullBox(t)
	b2.devices([3]string{"new-j", "192.168.1.21", "juniper"})
	out = b2.run("device", "config", "plan", "new-j", "--backout")
	if b2.sb.code != 1 || !strings.Contains(out, "CANNOT BE PLANNED") {
		t.Errorf("nothing kept: %d\n%s", b2.sb.code, out)
	}
}

// S1: the files of an earlier run beside a new main file. A plain plan after
// the verifying pull wrote the file and the cleanup file; the device changed;
// a run with --force writes the new statements and takes the old cleanup away
// (B1 through files). The back-out of a text plan goes the same way.
func TestPlanForceRemovesTheFilesOfAnEarlierPlan(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	stray := `set system tacplus-server 192.0.2.99 secret "` + strayKey + `"` + "\n"
	settled := b.expected("lab-j") + "\n" + stray
	b.serve("juniper", settled)
	b.servePlain(settled)
	b.run("device", "config", "pull", "lab-j")
	dir := filepath.Join(t.TempDir(), "sets")
	plain := []string{"device", "config", "plan", "lab-j", "--plain", "--converge", "--out-dir", dir}
	b.run(plain...)
	if b.sb.code != 0 {
		t.Fatalf("run 1: %d %s", b.sb.code, b.sb.stderr())
	}
	for _, f := range []string{"lab-j.set", "lab-j.cleanup.set"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("run 1 wrote no %s: %v", f, err)
		}
	}
	// the device changes: the paste has something to type again
	changed := strings.Replace(settled, "set system authentication-order tacplus\n", "", 1)
	if changed == settled {
		t.Fatal("the fixture has no authentication-order tacplus line to take away")
	}
	b.serve("juniper", changed)
	b.servePlain(changed)
	b.run("device", "config", "pull", "lab-j")
	b.run(append(plain, "--force")...)
	if b.sb.code != 0 {
		t.Fatalf("run 2: %d %s", b.sb.code, b.sb.stderr())
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "lab-j.set")); !strings.Contains(string(data), "authentication-order") {
		t.Errorf("run 2 wrote no statements:\n%s", data)
	}
	if _, err := os.Stat(filepath.Join(dir, "lab-j.cleanup.set")); err == nil {
		t.Errorf("the cleanup file of the earlier plan stayed beside the new statements")
	}
	if !strings.Contains(b.sb.stderr(), "Removed "+filepath.Join(dir, "lab-j.cleanup.set")) {
		t.Errorf("stderr: %q", b.sb.stderr())
	}
	// and the one line that says why there is no cleanup file now
	if !strings.Contains(b.sb.stderr(), "lab-j: no cleanup file: cleanup comes after this region is pasted and verified") {
		t.Errorf("no word of the missing cleanup file: %q", b.sb.stderr())
	}

	// --out: the file beside it
	f := filepath.Join(t.TempDir(), "x.set")
	b.serve("juniper", settled)
	b.servePlain(settled)
	b.run("device", "config", "pull", "lab-j")
	b.run("device", "config", "plan", "lab-j", "--plain", "--converge", "--out", f)
	cf := filepath.Join(filepath.Dir(f), "x.cleanup.set")
	if _, err := os.Stat(cf); err != nil {
		t.Fatalf("no cleanup file: %v", err)
	}
	b.serve("juniper", changed)
	b.servePlain(changed)
	b.run("device", "config", "pull", "lab-j")
	b.run("device", "config", "plan", "lab-j", "--plain", "--converge", "--out", f, "--force")
	if _, err := os.Stat(cf); err == nil {
		t.Errorf("--out left the cleanup file of the earlier plan")
	}

	// a text plan: the back-out of the earlier plan goes when this one has none
	txt := filepath.Join(t.TempDir(), "txt")
	b.serve("juniper", changed)
	b.servePlain(changed)
	b.run("device", "config", "pull", "lab-j")
	b.run("device", "config", "plan", "lab-j", "--out-dir", txt)
	if _, err := os.Stat(filepath.Join(txt, "lab-j.backout.txt")); err != nil {
		t.Fatalf("no back-out file: %v", err)
	}
	b.serve("juniper", settled)
	b.servePlain(settled)
	b.run("device", "config", "pull", "lab-j")
	b.run("device", "config", "plan", "lab-j", "--out-dir", txt, "--force")
	if b.sb.code != 0 {
		t.Fatalf("text run 2: %d %s", b.sb.code, b.sb.stderr())
	}
	if _, err := os.Stat(filepath.Join(txt, "lab-j.backout.txt")); err == nil {
		t.Errorf("the back-out of the earlier plan stayed beside a plan that has none")
	}
	if _, err := os.Stat(filepath.Join(txt, "lab-j.txt")); err != nil {
		t.Errorf("the plan file: %v", err)
	}
}

// --plain --converge says why a device has no cleanup file: the cleanup is
// deferred, refused or there is nothing to remove.
func TestPlanPlainConvergeSaysWhyThereIsNoCleanupFile(t *testing.T) {
	b := planBoxJunos(t)
	b.run("device", "config", "pull", "lab-j")
	f := filepath.Join(t.TempDir(), "p.set")
	b.run("device", "config", "plan", "lab-j", "--plain", "--converge", "--out", f)
	if b.sb.code != 0 || !strings.Contains(b.sb.stderr(), "lab-j: no cleanup file: cleanup comes after this region is pasted and verified") {
		t.Errorf("deferred: %d %q", b.sb.code, b.sb.stderr())
	}
	// a consistent device: nothing to remove
	text := b.expected("lab-j")
	b.serve("juniper", text)
	b.servePlain(text)
	b.run("device", "config", "pull", "lab-j")
	b.run("device", "config", "plan", "lab-j", "--plain", "--converge", "--out", f, "--force")
	if !strings.Contains(b.sb.stderr(), "lab-j: no cleanup file: nothing to remove") {
		t.Errorf("nothing to remove: %q", b.sb.stderr())
	}
}
