package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 'device config plan --restore-point' (0.2.7): the verb's side of the
// restore point of an IOS plan. The block's text is pinned by the goldens of
// internal/devconf/plan; these tests pin what the verb takes from the pull
// (the archive path), what it refuses, the stored back-out's stamp and the
// JSON.

// restoreArchiveTail is what a device with an archive path prints after its
// other statements.
const restoreArchiveTail = "\narchive\n log config\n  hidekeys\n path flash:tacctl-\n maximum 5\n!\n"

// restoreBox is planCiscoBox with a tail on the device's last pull: the
// statements the plan does not manage but the pull reads the archive path from.
func restoreBox(t *testing.T, tail string) *pullBox {
	t.Helper()
	b := newPullBox(t)
	b.ciscoDevice("")
	b.serve("cisco", b.expected("lab-c"))
	b.version(ciscoVersionModern)
	b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %s", b.sb.code, b.sb.stderr())
	}
	b.serve("cisco", planDropServer(b.expected("lab-c"))+tail)
	b.version(ciscoVersionModern)
	b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("second pull: %d %s", b.sb.code, b.sb.stderr())
	}
	return b
}

var reRestoreFile = regexp.MustCompile(`copy running-config ([a-z0-9]+:tacctl-lab-c-[0-9]{8}-[0-9]{4}\.cfg)\n\n`)

func TestPlanRestorePointNamedCopyAndItsBackout(t *testing.T) {
	b := restoreBox(t, restoreArchiveTail)
	// the archive path of the pull is on the record, as the file system only
	if rec, ok := b.records().Of("lab-c"); !ok || rec.ArchiveFS != "flash:" {
		t.Fatalf("the record's archive file system: %+v", rec)
	}
	out := b.run("device", "config", "plan", "lab-c", "--restore-point=disk0:")
	if b.sb.code != 0 {
		t.Fatalf("plan: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	m := reRestoreFile.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no named copy in\n%s", out)
	}
	file := m[1]
	if !strings.HasPrefix(file, "disk0:") {
		t.Errorf("the file system named is not the file's: %s", file)
	}
	from, to, paste := strings.Index(out, "!!!!! RESTORE POINT FROM HERE: lab-c !!!!!\n"), strings.Index(out, "\n!!!!! RESTORE POINT TO HERE: lab-c !!!!!\n"),
		strings.Index(out, "!!!!! PASTE FROM HERE: lab-c !!!!!\n")
	if from < 0 || to < from || paste < to {
		t.Fatalf("the restore block is not one pair before the region (%d %d %d):\n%s", from, to, paste, out)
	}
	// the one empty line is between the command and the closing banner, and
	// nothing else is typed before the region
	if !strings.Contains(out, file+"\n\n!!!!! RESTORE POINT TO HERE: lab-c !!!!!\n") {
		t.Errorf("the restore block:\n%s", out[from:to+60])
	}
	for _, l := range strings.Split(out[:paste], "\n") {
		if l != "" && !strings.HasPrefix(l, "!") && !strings.HasPrefix(l, "copy running-config "+file) {
			t.Errorf("a line to type before the region: %q", l)
		}
	}
	for _, want := range []string{"dir disk0:", "protect the file and delete it when you are done", "not a rollback timer"} {
		if !strings.Contains(unwrapPlan(out), want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}

	// the back-out kept from the plan names the same file, and its stamp too
	bo := b.run("device", "config", "plan", "lab-c", "--backout")
	if b.sb.code != 0 {
		t.Fatalf("backout: %d\n%s\n%s", b.sb.code, bo, b.sb.stderr())
	}
	for _, want := range []string{"configure replace " + file + " force", "its restore point is " + file} {
		if !strings.Contains(unwrapPlan(bo), want) {
			t.Errorf("no %q in the back-out\n%s", want, bo)
		}
	}
	if strings.Contains(bo, "RESTORE POINT FROM HERE") {
		t.Errorf("the back-out holds the restore block:\n%s", bo)
	}
	kept, _ := filepath.Glob(filepath.Join(b.sb.dir, "var-lib", "device-config", "*.backout*"))
	if len(kept) != 1 {
		t.Fatalf("the kept back-outs: %v", kept)
	}
	data, err := os.ReadFile(kept[0])
	if err != nil || !strings.Contains(string(data), "\nrestore: "+file+"\n") {
		t.Errorf("the kept back-out's stamp: %v\n%s", err, data)
	}

	// --json: the same file, the command, the file system and the note
	js := b.run("device", "config", "plan", "lab-c", "--restore-point=disk0:", "--json")
	var objs []struct {
		Restore *struct {
			Mode       string `json:"mode"`
			File       string `json:"file"`
			Command    string `json:"command"`
			FileSystem string `json:"file_system"`
			Note       string `json:"note"`
		} `json:"restore_point"`
		Region []string `json:"region"`
	}
	if err := json.Unmarshal([]byte(js), &objs); err != nil || len(objs) != 1 || objs[0].Restore == nil {
		t.Fatalf("json: %v\n%s", err, js)
	}
	r := objs[0].Restore
	if r.Mode != "copy" || r.File == "" || r.Command != "copy running-config "+r.File || r.FileSystem != "disk0:" ||
		r.Note != "" {
		t.Errorf("restore_point: %+v", r)
	}
	for _, l := range objs[0].Region {
		if strings.HasPrefix(l, "copy ") || strings.Contains(l, "RESTORE") {
			t.Errorf("the region of the JSON holds the restore block: %q", l)
		}
	}
	// the audit lines never carry the file or a value
	for _, l := range b.auditLines("device config plan") {
		if strings.Contains(l, "tacctl-lab-c") {
			t.Errorf("the audit line names the file: %s", l)
		}
	}
}

func TestPlanRestorePointBareTakesTheArchivePath(t *testing.T) {
	b := restoreBox(t, restoreArchiveTail)
	out := b.run("device", "config", "plan", "lab-c", "--restore-point")
	if b.sb.code != 0 {
		t.Fatalf("plan: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if !strings.Contains(out, "!!!!! RESTORE POINT FROM HERE: lab-c !!!!!\narchive config\n!!!!! RESTORE POINT TO HERE: lab-c !!!!!\n") {
		t.Errorf("no 'archive config' block in\n%s", out)
	}
	if strings.Contains(out, "copy running-config") {
		t.Errorf("a named copy beside the archive:\n%s", out)
	}
	// a device name after the bare flag is a device, not its value
	b.run("device", "config", "plan", "--restore-point", "lab-c")
	if b.sb.code != 0 {
		t.Errorf("bare flag before the device: %d %s", b.sb.code, b.sb.stderr())
	}
	bo := b.run("device", "config", "plan", "lab-c", "--backout")
	for _, want := range []string{"its restore point was taken with 'archive config'", "configure replace <that file> force"} {
		if !strings.Contains(unwrapPlan(bo), want) {
			t.Errorf("no %q in the back-out\n%s", want, bo)
		}
	}
	js := b.run("device", "config", "plan", "lab-c", "--restore-point", "--json")
	if !strings.Contains(js, `"mode": "archive"`) || !strings.Contains(js, `"command": "archive config"`) ||
		!strings.Contains(js, `"file_system": "flash:"`) || strings.Contains(js, `"file":`) {
		t.Errorf("json:\n%s", js)
	}
	// a named file system wins over the archive path
	out = b.run("device", "config", "plan", "lab-c", "--restore-point=bootflash:")
	if !strings.Contains(out, "copy running-config bootflash:tacctl-lab-c-") || strings.Contains(out, "archive config\n") {
		t.Errorf("named over archive:\n%s", out)
	}
}

func TestPlanRestorePointBareNeedsAFileSystem(t *testing.T) {
	// the device prints no archive path (an 'archive' with a log only)
	b := restoreBox(t, "\narchive\n log config\n  hidekeys\n!\n")
	out := b.run("device", "config", "plan", "lab-c", "--restore-point")
	if b.sb.code != 2 || strings.Contains(out, "PASTE FROM HERE") ||
		!strings.Contains(b.sb.stderr(), "--restore-point with no file system: the last pull of lab-c read no 'archive' with a 'path'") ||
		!strings.Contains(b.sb.stderr(), "--restore-point=flash:") || !strings.Contains(b.sb.stderr(), "Usage: tacctl device config plan") {
		t.Errorf("bare, no archive path: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	// naming one is the way out
	out = b.run("device", "config", "plan", "lab-c", "--restore-point=flash:")
	if b.sb.code != 0 || !strings.Contains(out, "copy running-config flash:tacctl-lab-c-") {
		t.Errorf("named: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	// without the flag nothing of it is in the output
	out = b.run("device", "config", "plan", "lab-c")
	if b.sb.code != 0 || strings.Contains(out, "RESTORE POINT") || strings.Contains(out, "configure replace") {
		t.Errorf("no flag: %d\n%s", b.sb.code, out)
	}
}

func TestPlanRestorePointRefusals(t *testing.T) {
	b := restoreBox(t, restoreArchiveTail)
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"plain", []string{"--restore-point=flash:", "--plain"}, "--restore-point with --plain"},
		{"backout", []string{"--restore-point=flash:", "--backout"}, "--restore-point with --backout"},
		{"no colon", []string{"--restore-point=flash"}, "'flash' is not a file system"},
		{"remote", []string{"--restore-point=tftp:"}, "'tftp:' is not a local file system"},
		{"path", []string{"--restore-point=flash:cfg/"}, "is not a file system"},
	} {
		out := b.run(append([]string{"device", "config", "plan", "lab-c"}, c.args...)...)
		if b.sb.code != 2 || out != "" || !strings.Contains(b.sb.stderr(), c.want) {
			t.Errorf("%s: %d\n%s\n%s", c.name, b.sb.code, out, b.sb.stderr())
		}
	}
	// a value needs the equals sign: '--restore-point flash:' leaves 'flash:'
	// as a device name, which is no device
	b.run("device", "config", "plan", "lab-c", "--restore-point", "flash:")
	if b.sb.code == 0 {
		t.Errorf("'--restore-point flash:' took flash: as its value")
	}
}

func TestPlanRestorePointIsRefusedForJunos(t *testing.T) {
	b := planBoxJunos(t)
	b.run("device", "config", "pull", "lab-j")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %s", b.sb.code, b.sb.stderr())
	}
	for _, flag := range []string{"--restore-point", "--restore-point=flash:"} {
		out := b.run("device", "config", "plan", "lab-j", flag)
		if b.sb.code != 2 || out != "" ||
			!strings.Contains(b.sb.stderr(), "--restore-point is for IOS and IOS-XE devices") || !strings.Contains(b.sb.stderr(), "lab-j (juniper)") {
			t.Errorf("%s: %d\n%s\n%s", flag, b.sb.code, out, b.sb.stderr())
		}
	}
	// without it the plan is as before
	out := b.run("device", "config", "plan", "lab-j")
	if b.sb.code != 0 || strings.Contains(out, "RESTORE POINT") {
		t.Errorf("no flag: %d\n%s", b.sb.code, out)
	}
}

func TestPlanRestorePointOutDirKeepsTheBlockAndTheBackout(t *testing.T) {
	b := restoreBox(t, restoreArchiveTail)
	dir := filepath.Join(b.sb.dir, "plans")
	b.run("device", "config", "plan", "lab-c", "--restore-point=flash:", "--out-dir", dir)
	if b.sb.code != 0 {
		t.Fatalf("out-dir: %d %s", b.sb.code, b.sb.stderr())
	}
	txt, err1 := os.ReadFile(filepath.Join(dir, "lab-c.txt"))
	bo, err2 := os.ReadFile(filepath.Join(dir, "lab-c.backout.txt"))
	if err1 != nil || err2 != nil {
		t.Fatalf("files: %v %v", err1, err2)
	}
	m := reRestoreFile.FindStringSubmatch(string(txt))
	if m == nil || !strings.Contains(unwrapPlan(string(bo)), "configure replace "+m[1]+" force") {
		t.Errorf("the file of the plan and of its back-out differ:\n%s\n%s", txt, bo)
	}
}
