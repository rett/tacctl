package cli

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
)

// 'device config plan' end to end, in-process, against the fake device and
// the sandbox's registry, store and records (the pull boxes of
// device_config_pull_test.go). The planner's own output is pinned by the
// goldens of internal/devconf/plan; these tests pin the verb: what it takes
// from the record, what it refuses, the formats, the files, the tiers and
// the audit line. testdata/plan holds the verb's output for the fake
// devices (go test -update-plan rewrites it).

var updatePlan = flag.Bool("update-plan", false, "rewrite internal/cli/testdata/plan")

const (
	strayKey      = "$9$STRAYKEY-SECRET-VALUE"
	junosPlainCmd = "show configuration | display set"
)

// planBoxJunos is a box with one Junos device whose pull differs from the
// rendering: the first authentication-order statement is missing and a
// stray second server (with its own secret) is there. The device also
// answers the plain view (the same statements: no group).
func planBoxJunos(t *testing.T) *pullBox {
	t.Helper()
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	var kept []string
	dropped := false
	for _, l := range strings.Split(strings.TrimSpace(b.expected("lab-j")), "\n") {
		if !dropped && strings.HasPrefix(l, "set system authentication-order") {
			dropped = true
			continue
		}
		kept = append(kept, l)
	}
	kept = append(kept, `set system tacplus-server 192.0.2.99 secret "`+strayKey+`"`)
	text := strings.Join(kept, "\n") + "\n"
	b.serve("juniper", text)
	b.servePlain(text)
	return b
}

// servePlain makes the fake Junos device answer the plain view with text.
func (b *pullBox) servePlain(text string) {
	b.t.Helper()
	if err := os.WriteFile(filepath.Join(b.dir, junosPlainCmd+".out"), []byte(text), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

// editRecord changes a device's record in place.
func (b *pullBox) editRecord(name string, fn func(*devconf.Record)) {
	b.t.Helper()
	s := devconf.Store{Records: b.sb.path("var-lib", "devices-config.json"), Dir: b.sb.path("var-lib", "device-config")}
	unlock, err := s.Lock()
	if err != nil {
		b.t.Fatal(err)
	}
	defer unlock()
	r, err := s.Load()
	if err != nil {
		b.t.Fatal(err)
	}
	rec, ok := r.Of(name)
	if !ok {
		b.t.Fatalf("no record of %s", name)
	}
	c := *rec
	fn(&c)
	r.Put(name, c)
	if err := s.Save(r); err != nil {
		b.t.Fatal(err)
	}
}

// auditLines are the audit lines the run logged for the verb.
func (b *pullBox) auditLines(verb string) []string {
	b.t.Helper()
	var out []string
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "logger" {
			if l := strings.Join(c.Args, " "); strings.Contains(l, verb) {
				out = append(out, l)
			}
		}
	}
	return out
}

// planNorm makes a plan's output independent of the clock.
var planNorm = regexp.MustCompile(`\d{4}-\d\d-\d\d[ T]\d\d:\d\dZ?`)

func normPlan(s string) string { return planNorm.ReplaceAllString(s, "<time>") }

// planWrap joins the continuation lines of a wrapped comment, so a sentence
// is looked for whole.
var planWrap = regexp.MustCompile(`\n[#!] +`)

func unwrapPlan(s string) string { return planWrap.ReplaceAllString(s, " ") }

// planGolden compares text with testdata/plan/<name>.
func planGolden(t *testing.T, name, text string) {
	t.Helper()
	p := filepath.Join("testdata", "plan", name)
	text = normPlan(text)
	if *updatePlan {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (go test ./internal/cli -run %s -update-plan writes it)", err, t.Name())
	}
	if text != string(want) {
		t.Errorf("%s differs from its golden:\n--- got\n%s\n--- want\n%s", name, text, want)
	}
}

func TestPlanJunosFromTheLastPull(t *testing.T) {
	b := planBoxJunos(t)
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 {
		t.Fatalf("pull: %d %s %s", b.sb.code, out, b.sb.stderr())
	}
	logins := b.srv.Logins()
	out := b.run("device", "config", "plan", "lab-j")
	if b.sb.code != 0 {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	// the plan reads no device
	if b.srv.Logins() != logins {
		t.Errorf("plan logged in to the device (%d, was %d)", b.srv.Logins(), logins)
	}
	lines := strings.Split(out, "\n")
	// the box is the first line, both banners carry the name
	if !strings.HasPrefix(lines[0], "##### lab-j  192.168.1.20  scope lab  juniper (TACACS+) #####") {
		t.Errorf("first line %q", lines[0])
	}
	for _, want := range []string{"##### PASTE FROM HERE: lab-j #####\nconfigure private\n", "\nshow | compare | no-more\ncommit check\ncommit confirmed 5 comment \"tacctl plan lab-j ",
		"##### PASTE TO HERE: lab-j #####\n", "set system authentication-order tacplus\n", "Left alone. To remove it later: delete system"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	// the stray server is reported and its secret printed nowhere
	noSecrets(t, "the plan", out, strayKey, testPassword)
	noSecrets(t, "stderr", b.sb.stderr(), strayKey, testPassword)
	if strings.Contains(out, "no plain view") {
		t.Error("the plain view was read, and the report says it was not")
	}
	if strings.Contains(out, "CLEANUP") {
		t.Error("a cleanup without --converge")
	}
	// the one audit line: user, device, status, sections, converge, secrets, out
	al := b.auditLines("device config plan")
	if len(al) != 1 || !strings.Contains(al[0], "auth.info") ||
		!strings.Contains(al[0], "device config plan user=alice device=lab-j status=needs-change sections=aaa converge=no secrets=none out=-") {
		t.Errorf("audit %q", al)
	}
	noSecrets(t, "audit", strings.Join(al, "\n"), strayKey, testPassword)
	planGolden(t, "junos.out", out)
}

// No plan without a pull, none from a pull the device failed since, none
// from one older than stale-days, none for a WTI unit; each is exit 1 and a
// reason that names what to do.
func TestPlanCannotPlanWhatIsNotCurrent(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"new-j", "192.168.1.21", "juniper"}, [3]string{"old-j", "192.168.1.22", "juniper"},
		[3]string{"bad-j", "192.168.1.23", "juniper"}, [3]string{"rack-w", "192.168.1.24", "wti"})
	b.serve("juniper", b.expected("old-j"))
	b.run("device", "config", "pull", "old-j", "bad-j")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %s", b.sb.code, b.sb.stderr())
	}
	b.editRecord("old-j", func(r *devconf.Record) { r.Pulled = time.Now().Add(-45 * 24 * time.Hour) })
	b.editRecord("bad-j", func(r *devconf.Record) { r.Result = devconf.ResultUnreachable })

	for _, c := range []struct{ dev, want string }{
		{"new-j", "not pulled: tacctl device config pull new-j (or --pull)"},
		{"old-j", "stale pull (45 days old, stale-days is 30): tacctl device config pull old-j (or --pull)"},
		{"bad-j", "the last pull failed (unreachable)"},
		{"rack-w", "device config plan does not cover WTI units; the walkthrough is: tacctl config wti"},
	} {
		out := b.run("device", "config", "plan", c.dev)
		if b.sb.code != 1 {
			t.Errorf("%s: exit %d", c.dev, b.sb.code)
		}
		if !strings.Contains(b.sb.stderr(), c.dev+" cannot be planned: "+c.want) || !strings.Contains(out, "CANNOT BE PLANNED: "+c.want) {
			t.Errorf("%s: stdout %q stderr %q", c.dev, out, b.sb.stderr())
		}
		if strings.Contains(out, "configure private") || strings.Contains(out, "PASTE FROM HERE") {
			t.Errorf("%s: a region for a device that cannot be planned:\n%s", c.dev, out)
		}
		if al := b.auditLines("device config plan"); len(al) != 1 || !strings.Contains(al[0], "device="+c.dev+" status=cannot-plan sections=-") {
			t.Errorf("%s: audit %q", c.dev, al)
		}
	}
	// the same in --json: an object with the status and the reason
	js := b.run("device", "config", "plan", "new-j", "--json")
	var docs []map[string]any
	if err := json.Unmarshal([]byte(js), &docs); err != nil || len(docs) != 1 || docs[0]["status"] != "cannot-plan" ||
		!strings.Contains(docs[0]["reason"].(string), "not pulled") || b.sb.code != 1 {
		t.Errorf("json: %v %d\n%s", err, b.sb.code, js)
	}
	// several: the cover says it for each, the exit status is 1
	b.run("device", "config", "plan", "old-j,new-j", "--all")
	if b.sb.code != 2 {
		t.Errorf("names with --all: %d", b.sb.code)
	}
	out := b.run("device", "config", "plan", "--all")
	if b.sb.code != 1 || !strings.Contains(out, "# tacctl device config plan: 3 devices") ||
		!strings.Contains(out, "new-j  cannot be planned: not pulled") || !strings.Contains(out, "old-j  cannot be planned: stale pull") ||
		!strings.Contains(out, "bad-j  cannot be planned: the last pull failed") {
		t.Errorf("cover: %d\n%s", b.sb.code, out)
	}
	if strings.Contains(out, "rack-w") || !strings.Contains(b.sb.stderr(), "skipped 1 (rack-w): device config plan does not cover WTI units; the walkthrough is: tacctl config wti") {
		t.Errorf("a selection took the WTI unit, or did not say it left it out:\n%s\n%s", out, b.sb.stderr())
	}
}

func TestPlanFormatsAndFiles(t *testing.T) {
	b := planBoxJunos(t)
	b.run("device", "config", "pull", "lab-j")
	bad := func(want string, args ...string) {
		t.Helper()
		out := b.run(append([]string{"device", "config", "plan", "lab-j"}, args...)...)
		if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), want) || strings.Contains(out, "configure private") {
			t.Errorf("%v: exit %d stdout %q stderr %q", args, b.sb.code, out, b.sb.stderr())
		}
	}
	bad("--secrets and --no-secrets exclude each other", "--secrets", "--no-secrets")
	bad("--plain with --no-secrets", "--plain", "--no-secrets")
	bad("--plain and --json are two formats", "--plain", "--json")
	bad("--backout prints the back-out region", "--backout", "--json")
	bad("--backout is the undo of the plan", "--backout", "--converge")
	bad("--out is one file for one device and --out-dir one file per device", "--out", "x", "--out-dir", "y")
	bad("--force replaces files", "--force")
	bad("never planned", "--section", "netconf")
	bad("never planned", "--section", "breakglass")
	bad("--section takes sections of aaa, roles, mgmt-acl, snmp, system: 'nope'", "--section", "nope")
	bad("--transport is for --pull", "--transport", "ssh")
	bad("--from takes the address you are logged in", "--from", "10.0.0.0/8")
	bad("--plain --converge makes two files", "--plain", "--converge")

	// --plain: the statements alone, no wrapper line, no comment, no banner
	out := b.run("device", "config", "plan", "lab-j", "--plain")
	if b.sb.code != 0 || out != "set system authentication-order tacplus\n" {
		t.Errorf("plain: %d %q", b.sb.code, out)
	}
	// --section: the others are not planned
	out = b.run("device", "config", "plan", "lab-j", "--section", "roles")
	if b.sb.code != 0 || strings.Contains(out, "configure private") || !strings.Contains(out, "Not selected (--section): aaa") {
		t.Errorf("section: %d\n%s", b.sb.code, out)
	}
	out = b.run("device", "config", "plan", "lab-j", "--section", "aaa,roles")
	if b.sb.code != 0 || !strings.Contains(out, "configure private") || !strings.Contains(out, "Not selected (--section): snmp, mgmt-acl") {
		t.Errorf("sections: %d\n%s", b.sb.code, out)
	}
	// --json: values elided, the region and the back-out in lists
	js := b.run("device", "config", "plan", "lab-j", "--json")
	noSecrets(t, "json", js, strayKey, testPassword)
	var docs []struct {
		Name    string   `json:"name"`
		Status  string   `json:"status"`
		Region  []string `json:"region"`
		Backout []string `json:"backout"`
		Extras  []struct {
			Text   string   `json:"text"`
			Remove []string `json:"remove"`
		} `json:"extras"`
	}
	if err := json.Unmarshal([]byte(js), &docs); err != nil || len(docs) != 1 || docs[0].Name != "lab-j" || docs[0].Status != "needs-change" ||
		docs[0].Region[0] != "configure private" || len(docs[0].Backout) == 0 || len(docs[0].Extras) == 0 {
		t.Errorf("json: %v\n%s", err, js)
	}
	// --backout: its own region, with its own banners, and no plan region
	out = b.run("device", "config", "plan", "lab-j", "--backout")
	if b.sb.code != 0 || !strings.Contains(out, "##### BACK-OUT FROM HERE: lab-j #####") || strings.Contains(out, "PASTE FROM HERE") ||
		!strings.Contains(out, "delete system authentication-order") {
		t.Errorf("backout: %d\n%s", b.sb.code, out)
	}

	// --out: one file, 0600, refused when it exists
	dir := t.TempDir()
	f := filepath.Join(dir, "lab-j.txt")
	b.run("device", "config", "plan", "lab-j", "--out", f)
	if b.sb.code != 0 || !strings.Contains(b.sb.out.String(), "Wrote "+f) {
		t.Fatalf("out: %d %q %q", b.sb.code, b.sb.out.String(), b.sb.stderr())
	}
	st, err := os.Stat(f)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("file %v %v", st, err)
	}
	data, _ := os.ReadFile(f)
	if !strings.Contains(string(data), "PASTE FROM HERE: lab-j") || strings.Contains(string(data), strayKey) {
		t.Errorf("file:\n%s", data)
	}
	b.run("device", "config", "plan", "lab-j", "--out", f)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "exist") || !strings.Contains(b.sb.stderr(), "--force") {
		t.Errorf("existing: %d %q", b.sb.code, b.sb.stderr())
	}
	if again, _ := os.ReadFile(f); string(again) != string(data) {
		t.Error("the refused run changed the file")
	}
	b.run("device", "config", "plan", "lab-j", "--out", f, "--force", "--plain")
	if again, _ := os.ReadFile(f); b.sb.code != 0 || string(again) != "set system authentication-order tacplus\n" {
		t.Errorf("force: %d %q", b.sb.code, again)
	}
	if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
		t.Errorf("replaced file %v", st.Mode())
	}
	// no temporary file is left in the directory
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("files left: %v", ents)
	}
}

func TestPlanSeveralDevicesCoverAndOutDir(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"lab-j2", "192.168.1.25", "juniper"})
	// lab-j2 agrees with the rendering, lab-j does not
	text := b.expected("lab-j")
	b.serve("juniper", text)
	b.run("device", "config", "pull", "lab-j2")
	var kept []string
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		if !strings.HasPrefix(l, "set system authentication-order") {
			kept = append(kept, l)
		}
	}
	b.serve("juniper", strings.Join(kept, "\n")+"\n")
	b.run("device", "config", "pull", "lab-j")

	// a --plain stream of two devices is refused
	b.run("device", "config", "plan", "--all", "--plain")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--plain is the statements of one device") {
		t.Errorf("plain of two: %d %q", b.sb.code, b.sb.stderr())
	}
	b.run("device", "config", "plan", "--all", "--out", filepath.Join(t.TempDir(), "x"))
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--out is one file for one device") {
		t.Errorf("out of two: %d %q", b.sb.code, b.sb.stderr())
	}

	out := b.run("device", "config", "plan", "--all")
	if b.sb.code != 0 {
		t.Fatalf("exit %d %s", b.sb.code, b.sb.stderr())
	}
	for _, want := range []string{"# tacctl device config plan: 2 devices", "lab-j2  consistent", "lab-j   needs change: 1 irregularity fixed by the paste",
		"# 1 consistent, 1 need a change, 0 not consistent with nothing to paste, 0 cannot be planned"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.Index(out, "tacctl device config plan: 2 devices") > strings.Index(out, "##### lab-j  ") {
		t.Error("the cover is not first")
	}
	planGolden(t, "junos-cover.out", out)
	// --exit-code: a change is needed
	b.run("device", "config", "plan", "--all", "--exit-code")
	if b.sb.code != 2 {
		t.Errorf("--exit-code: %d", b.sb.code)
	}

	// --out-dir: a file per device, COVER.txt, the back-out beside the plan
	dir := filepath.Join(t.TempDir(), "plans")
	out = b.run("device", "config", "plan", "--all", "--out-dir", dir)
	if b.sb.code != 0 {
		t.Fatalf("out-dir: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	st, err := os.Stat(dir)
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("directory %v %v", st, err)
	}
	for _, n := range []string{"lab-j.txt", "lab-j2.txt", "lab-j.backout.txt", "COVER.txt"} {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", n, st, err)
		}
	}
	cover, _ := os.ReadFile(filepath.Join(dir, "COVER.txt"))
	if !strings.Contains(string(cover), "lab-j2  consistent") || !strings.Contains(out, "Wrote "+filepath.Join(dir, "lab-j.txt")) ||
		!strings.Contains(out, "# tacctl device config plan: 2 devices") {
		t.Errorf("cover file %q\nstdout %q", cover, out)
	}
	one, _ := os.ReadFile(filepath.Join(dir, "lab-j.txt"))
	if strings.Contains(string(one), "BACK-OUT FROM HERE") {
		t.Error("the back-out is in the plan's file")
	}
	bo, _ := os.ReadFile(filepath.Join(dir, "lab-j.backout.txt"))
	if !strings.Contains(string(bo), "BACK-OUT FROM HERE: lab-j") {
		t.Errorf("back-out file:\n%s", bo)
	}
	// the files exist: refused, nothing written; --force replaces
	b.run("device", "config", "plan", "--all", "--out-dir", dir)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "--force") {
		t.Errorf("existing: %d %q", b.sb.code, b.sb.stderr())
	}
	b.run("device", "config", "plan", "--all", "--out-dir", dir, "--force")
	if b.sb.code != 0 {
		t.Errorf("force: %d %q", b.sb.code, b.sb.stderr())
	}
	// --plain with --out-dir: one .set file each
	pdir := filepath.Join(t.TempDir(), "sets")
	b.run("device", "config", "plan", "--all", "--plain", "--out-dir", pdir)
	if set, err := os.ReadFile(filepath.Join(pdir, "lab-j.set")); err != nil || string(set) != "set system authentication-order tacplus\n" {
		t.Errorf("set file: %q %v", set, err)
	}
	if set, err := os.ReadFile(filepath.Join(pdir, "lab-j2.set")); err != nil || len(set) != 0 {
		t.Errorf("an empty plan's set file: %q %v", set, err)
	}
	if _, err := os.Stat(filepath.Join(pdir, "lab-j.backout.txt")); err == nil {
		t.Error("a back-out file beside a plain plan")
	}
	// a directory that is open to others is refused: the files hold secrets
	open := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	b.run("device", "config", "plan", "--all", "--out-dir", open)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "is open to other users") {
		t.Errorf("open directory: %d %q", b.sb.code, b.sb.stderr())
	}
	// --json of several: one array
	js := b.run("device", "config", "plan", "--all", "--json")
	var docs []map[string]any
	if err := json.Unmarshal([]byte(js), &docs); err != nil || len(docs) != 2 {
		t.Errorf("json: %v\n%s", err, js)
	}
	// the name of a file: --out-dir with --json
	jdir := filepath.Join(t.TempDir(), "json")
	b.run("device", "config", "plan", "--all", "--json", "--out-dir", jdir)
	if _, err := os.Stat(filepath.Join(jdir, "lab-j.json")); err != nil {
		t.Error(err)
	}
}

// --converge (D111, amended): a device with a first region gets that region
// and one sentence, never a cleanup beside it; the plan made after the paste
// and the verifying pull has the cleanup region alone, with banners of its
// own.
func TestPlanConvergeCleanupAndFrom(t *testing.T) {
	b := planBoxJunos(t)
	b.run("device", "config", "pull", "lab-j")
	out := b.run("device", "config", "plan", "lab-j", "--converge")
	if b.sb.code != 0 {
		t.Fatalf("exit %d %s", b.sb.code, b.sb.stderr())
	}
	// as pulled: the first region, the sentence, no cleanup
	if strings.Contains(out, "CLEANUP FROM HERE") || strings.Contains(out, "CLEANUP TO HERE") || strings.Contains(out, "tacctl cleanup lab-j") ||
		!strings.Contains(out, "##### PASTE FROM HERE: lab-j #####\nconfigure private\n") {
		t.Errorf("the cleanup beside the first region:\n%s", out)
	}
	if !strings.Contains(unwrapPlan(out), "Cleanup (--converge): cleanup comes after this region is pasted and verified: pull the device, then plan --converge again.") {
		t.Errorf("the sentence is not in the report:\n%s", out)
	}
	if strings.Count(out, "commit confirmed") != 1 {
		t.Errorf("more than one confirmed commit in the output:\n%s", out)
	}
	noSecrets(t, "the plan", out, strayKey)
	if al := b.auditLines("device config plan"); len(al) != 1 || !strings.Contains(al[0], "converge=yes") {
		t.Errorf("audit %q", al)
	}
	planGolden(t, "junos-converge.out", out)
	// --plain --converge with a first region: its file, and no cleanup file
	dir := t.TempDir()
	f := filepath.Join(dir, "lab-j.set")
	b.run("device", "config", "plan", "lab-j", "--plain", "--converge", "--out", f)
	if b.sb.code != 0 {
		t.Fatalf("plain converge: %d %s", b.sb.code, b.sb.stderr())
	}
	first, _ := os.ReadFile(f)
	if string(first) != "set system authentication-order tacplus\n" {
		t.Errorf("plain first file %q", first)
	}
	if _, err := os.Stat(filepath.Join(dir, "lab-j.cleanup.set")); err == nil {
		t.Error("a cleanup file for a device with a first region")
	}
	// the confirm timeout setting is the N of the commit
	b.run("config", "devices", "confirm-timeout", "12")
	if b.sb.code != 0 {
		t.Fatalf("setting: %d %s", b.sb.code, b.sb.stderr())
	}
	out = b.run("device", "config", "plan", "lab-j")
	if !strings.Contains(out, "commit confirmed 12 comment") || !strings.Contains(out, "undoes this by itself in 12 minutes") {
		t.Errorf("confirm timeout:\n%s", out)
	}
	b.run("config", "devices", "confirm-timeout", "5")

	// the paste is made (the stray server stays), the verifying pull reads it
	text := b.expected("lab-j") + "\n" + `set system tacplus-server 192.0.2.99 secret "` + strayKey + `"` + "\n"
	b.serve("juniper", text)
	b.servePlain(text)
	b.run("device", "config", "pull", "lab-j")
	out = b.run("device", "config", "plan", "lab-j", "--converge")
	if b.sb.code != 0 {
		t.Fatalf("exit %d %s", b.sb.code, b.sb.stderr())
	}
	for _, want := range []string{"##### CLEANUP FROM HERE: lab-j #####\nconfigure private\n",
		"delete system tacplus-server 192.0.2.99\nshow | compare | no-more\ncommit check\ncommit confirmed 5 comment \"tacctl cleanup lab-j ",
		"##### CLEANUP TO HERE: lab-j #####\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "PASTE FROM HERE") || strings.Contains(out, "PASTE TO HERE") {
		t.Errorf("a first-region banner for a device with no first region:\n%s", out)
	}
	if !strings.Contains(unwrapPlan(out), "Removed by the cleanup region, line 3") {
		t.Errorf("the item does not say where its removal is:\n%s", out)
	}
	noSecrets(t, "the cleanup", out, strayKey)
	planGolden(t, "junos-converge-after.out", out)
	// --from the stray server's own address: it is never removed
	out = b.run("device", "config", "plan", "lab-j", "--converge", "--from", "192.0.2.99")
	if strings.Contains(out, "CLEANUP FROM HERE") || !strings.Contains(out, "Cleanup (--converge): nothing to remove.") {
		t.Errorf("--from:\n%s", out)
	}
	// --plain --converge: the cleanup's own file; the first has nothing
	f = filepath.Join(dir, "after.set")
	b.run("device", "config", "plan", "lab-j", "--plain", "--converge", "--out", f)
	if b.sb.code != 0 {
		t.Fatalf("plain converge: %d %s", b.sb.code, b.sb.stderr())
	}
	first, _ = os.ReadFile(f)
	second, err := os.ReadFile(filepath.Join(dir, "after.cleanup.set"))
	if len(first) != 0 || err != nil || string(second) != "delete system tacplus-server 192.0.2.99\n" {
		t.Errorf("files: %q %q %v", first, second, err)
	}
}

// A statement a group supplies is read from the plain view: the section is
// refused, nothing is pasted, and the exit status says it.
func TestPlanRefusesWhatAGroupOwns(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	text := b.expected("lab-j")
	var kept, plainView []string
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		if strings.HasPrefix(l, "set system authentication-order") {
			// the device has another order, and it comes from a group: the
			// inheritance view has it, the plain view does not
			kept = append(kept, "set system authentication-order password")
			continue
		}
		kept = append(kept, l)
		plainView = append(plainView, l)
	}
	b.serve("juniper", strings.Join(kept, "\n")+"\n")
	b.servePlain(strings.Join(plainView, "\n") + "\n")
	b.run("device", "config", "pull", "lab-j")
	out := b.run("device", "config", "plan", "lab-j")
	if b.sb.code != 1 || strings.Contains(out, "configure private") ||
		!strings.Contains(unwrapPlan(out), "CANNOT BE PLANNED") && !strings.Contains(unwrapPlan(out), "refused") {
		t.Errorf("a statement of a group: %d\n%s", b.sb.code, out)
	}
	if !strings.Contains(b.sb.stderr(), "lab-j cannot be planned: refused: aaa:") {
		t.Errorf("stderr %q", b.sb.stderr())
	}
	// the status is the cover's and the JSON's too
	js := b.run("device", "config", "plan", "lab-j", "--json")
	var docs []map[string]any
	if err := json.Unmarshal([]byte(js), &docs); err != nil || docs[0]["status"] != "cannot-plan" || b.sb.code != 1 {
		t.Errorf("json %v %d\n%s", err, b.sb.code, js)
	}
	if al := b.auditLines("device config plan"); len(al) != 1 || !strings.Contains(al[0], "status=cannot-plan") {
		t.Errorf("audit %q", al)
	}
	// without the plain view nothing says it comes from a group: planned, and
	// the report says the check was not made
	b.servePlain("")
	if err := os.Remove(filepath.Join(b.dir, junosPlainCmd+".out")); err != nil {
		t.Fatal(err)
	}
	b.run("device", "config", "pull", "lab-j")
	out = b.run("device", "config", "plan", "lab-j")
	if b.sb.code != 0 || !strings.Contains(out, "configure private") || !strings.Contains(unwrapPlan(out), "not checked (pull the device again to read it)") {
		t.Errorf("without a plain view: %d\n%s", b.sb.code, out)
	}
}

// A file of a plan is made whole or not at all: new, 0600, never through a
// link, never over an existing name unless forced (and then the name is
// replaced, not what a link points at).
func TestWritePrivateIsExclusiveAndNeverFollowsALink(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "plan.txt")
	if err := writePrivate(p, []byte("one\n"), false); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	if err := writePrivate(p, []byte("two\n"), false); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Errorf("an existing file: %v", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "one\n" {
		t.Errorf("the refused write changed the file: %q", got)
	}
	// a link where the file goes: refused, and forced it is the link that is
	// replaced; its target stays as it was
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := filepath.Join(dir, "link")
	if err := os.Symlink(target, l); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(l, []byte("x\n"), false); err == nil {
		t.Error("a write through a link")
	}
	if err := writePrivate(l, []byte("x\n"), true); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != "keep\n" {
		t.Errorf("the target of the link was written: %q", got)
	}
	if st, err := os.Lstat(l); err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0o600 {
		t.Errorf("the link was not replaced: %v %v", st, err)
	}
	// no temporary file is left behind, a failed write or not
	_ = writePrivate(p, []byte("three\n"), false)
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("left %s", e.Name())
		}
	}
	// the second file of a plain --converge
	for in, want := range map[string]string{"/x/lab-j.set": "/x/lab-j.cleanup.set", "plan": "plan.cleanup", "a.b.txt": "a.b.cleanup.txt"} {
		if got := cleanupName(in); got != want {
			t.Errorf("cleanupName(%q) = %q, want %q", in, got, want)
		}
	}
}

// The plain view is stored with the sections and goes with the device.
func TestPullKeepsThePlainViewAndForgetsIt(t *testing.T) {
	b := planBoxJunos(t)
	b.run("device", "config", "pull", "lab-j")
	p := b.sb.path("var-lib", "device-config", "lab-j.plain")
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("plain file %v %v", st, err)
	}
	data, _ := os.ReadFile(p)
	noSecrets(t, "the plain file", string(data), strayKey)
	// a device that answers no plain view leaves none behind
	if err := os.Remove(filepath.Join(b.dir, junosPlainCmd+".out")); err != nil {
		t.Fatal(err)
	}
	b.run("device", "config", "pull", "lab-j")
	if _, err := os.Stat(p); err == nil {
		t.Error("the plain view of the last pull is kept")
	}
	out := b.run("device", "config", "plan", "lab-j")
	if !strings.Contains(out, "The pull has no plain view of the configuration") {
		t.Errorf("no plain view and no word of it:\n%s", out)
	}
	b.servePlain("set system authentication-order tacplus\n")
	b.run("device", "config", "pull", "lab-j")
	b.run("device", "config", "forget", "lab-j")
	if _, err := os.Stat(p); err == nil {
		t.Error("forget left the plain view")
	}
}
