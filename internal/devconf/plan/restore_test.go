package plan

// The restore point of an IOS plan (0.2.7, restore.go): the shapes the block
// may have, what refuses it, that nothing else can be typed outside the
// region, and that the back-out names the file the block makes.

import (
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
)

// restoreOptions are the restore points the tests plan with.
var restoreOptions = []struct {
	name string
	rp   *RestorePoint
}{
	{"copy flash", &RestorePoint{FS: "flash:"}},
	{"copy disk0", &RestorePoint{FS: "disk0:"}},
	{"archive", &RestorePoint{ArchiveFS: "bootflash:"}},
	{"named beside an archive path", &RestorePoint{FS: "usbflash0:", ArchiveFS: "flash:"}},
}

// Off by default: with no restore point no output, JSON or back-out of an
// IOS device mentions one (the existing goldens say the same, byte for byte).
func TestRestorePointIsOffByDefault(t *testing.T) {
	n := 0
	for _, gc := range goldenCases(t) {
		if gc.opt.RestorePoint != nil || gc.d.Vendor != devconf.FamilyIOS {
			continue
		}
		out := Block(gc.d, gc.h, gc.w)
		bo, _ := Backout(gc.d, gc.h, gc.w)
		js, err := JSON(gc.d, gc.h, gc.w)
		if err != nil {
			t.Fatal(err)
		}
		for what, text := range map[string]string{"output": out, "back-out": bo, "json": string(js)} {
			for _, w := range []string{"RESTORE POINT", "restore_point", "Restore point:", "archive config", "tacctl-"} {
				if strings.Contains(text, w) {
					t.Errorf("%s %s holds %q", gc.name, what, w)
				}
			}
		}
		if RestoreRegion(gc.d, gc.h) != "" || RestoreLines(gc.d, gc.h) != nil || RestoreName(gc.d, gc.h) != "" {
			t.Errorf("%s: a restore block with none asked for", gc.name)
		}
		n++
	}
	if n < 10 {
		t.Errorf("only %d IOS goldens looked at", n)
	}
}

// The property: for every IOS fixture and every form of the restore point,
// the lines of the output that a terminal would run are the restore block's
// (before the region), the region's and nothing else; the back-out output
// has only its region; no other exec command can appear; and the block, the
// back-out and the JSON name one file.
func TestRestorePointIsTheOnlyExecCommandOutsideTheRegion(t *testing.T) {
	checked := 0
	for _, f := range fixtures(t) {
		if f.vendor != "cisco" {
			continue
		}
		exp, cur, plain := f.load(t)
		for _, c := range restoreOptions {
			opt := f.options()
			opt.RestorePoint = c.rp
			d, err := Plan(f.vendor, exp, cur, plain, opt)
			if err != nil {
				t.Fatalf("%s %s: %v", f.name, c.name, err)
			}
			h, w := f.header(), Wrapper{ConfirmMinutes: 5}
			label := f.name + " " + c.name
			if d.Empty() {
				if RestoreRegion(d, h) != "" || strings.Contains(Block(d, h, w), "RESTORE") {
					t.Errorf("%s: a restore block for a plan with nothing to paste", label)
				}
				js, _ := JSON(d, h, w)
				if strings.Contains(string(js), "restore_point") {
					t.Errorf("%s: restore_point in the JSON of an empty plan", label)
				}
				continue
			}
			checkWholePaste(t, label, d, h, w)
			out := Block(d, h, w)
			bc := bannerChar(d.Vendor)
			var run []string
			for _, l := range strings.Split(out, "\n") {
				if l != "" && !strings.HasPrefix(l, "!") {
					run = append(run, l)
				}
			}
			// the restore command is the first thing a whole copy runs
			cmd := d.Restore.Command(h)
			if len(run) == 0 || run[0] != cmd {
				t.Errorf("%s: the first line run is %q, not %q", label, run[0], cmd)
			}
			if i := slices.Index(run, "configure terminal"); i != 1 {
				t.Errorf("%s: 'configure terminal' follows the restore command at %d: %q", label, i, run[:min(len(run), 4)])
			}
			for i, l := range run {
				if i == 0 {
					continue
				}
				if strings.HasPrefix(l, "copy ") || strings.HasPrefix(l, "archive ") || strings.HasPrefix(l, "configure replace") ||
					l == "write memory" || l == "reload" || strings.HasPrefix(l, "delete ") {
					t.Errorf("%s: a second exec command %q", label, l)
				}
			}
			// the region's own allowlist still refuses the command
			region := []string{"configure terminal", cmd, "end"}
			if err := CheckRegion(d.Vendor, region); err == nil {
				t.Errorf("%s: the region's allowlist takes %q", label, cmd)
			}
			// the back-out output: its own region and comments
			if bo, err := Backout(d, h, w); err == nil {
				if strings.Contains(bo, "RESTORE POINT FROM") {
					t.Errorf("%s: the back-out holds the restore block", label)
				}
				for _, l := range strings.Split(bo[strings.Index(bo, bc+" BACK-OUT FROM HERE"):strings.Index(bo, bc+" BACK-OUT TO HERE")], "\n") {
					if strings.HasPrefix(l, "copy ") || strings.HasPrefix(l, "archive ") || strings.HasPrefix(l, "configure replace") {
						t.Errorf("%s: the back-out region types %q", label, l)
					}
				}
				after := bo[strings.Index(bo, bc+" BACK-OUT TO HERE"):]
				alt := "configure replace " + d.Restore.File(h) + " force"
				if d.Restore.Mode() == RestoreArchive {
					alt = "configure replace <that file> force"
				}
				if !strings.Contains(after, "!   "+alt+"\n") {
					t.Errorf("%s: the back-out does not name %q as a comment:\n%s", label, alt, after)
				}
				for _, l := range strings.Split(after, "\n") {
					if l != "" && !strings.HasPrefix(l, "!") {
						t.Errorf("%s: a line to type after the back-out region: %q", label, l)
					}
				}
			}
			js, err := JSON(d, h, w)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(js), `"restore_point"`) || !strings.Contains(string(js), `"command": "`+cmd+`"`) {
				t.Errorf("%s: the JSON does not carry the command %q", label, cmd)
			}
			if got := RestoreName(d, h); got != d.Restore.Name(h) || got == "" {
				t.Errorf("%s: the name for the kept back-out is %q", label, got)
			}
			checked++
		}
	}
	if checked < 20 {
		t.Errorf("only %d plans checked", checked)
	}
}

// The restore block's allowlist: exactly the two shapes.
func TestCheckRestorePoint(t *testing.T) {
	good := [][]string{
		{"archive config"},
		{"copy running-config flash:tacctl-sw-lab-1-20261012-1430.cfg", ""},
		{"copy running-config disk0:tacctl-r1-20261012-0905.cfg", ""},
	}
	for _, g := range good {
		if err := CheckRestorePoint(g); err != nil {
			t.Errorf("%q refused: %v", g, err)
		}
	}
	bad := map[string][]string{
		"empty":               nil,
		"copy to startup":     {"copy running-config startup-config", ""},
		"no empty line":       {"copy running-config flash:tacctl-sw-20261012-1430.cfg"},
		"two empty lines":     {"copy running-config flash:tacctl-sw-20261012-1430.cfg", "", ""},
		"empty line first":    {"", "copy running-config flash:tacctl-sw-20261012-1430.cfg"},
		"a second command":    {"copy running-config flash:tacctl-sw-20261012-1430.cfg", "", "write memory"},
		"remote":              {"copy running-config tftp:tacctl-sw-20261012-1430.cfg", ""},
		"tftp url":            {"copy running-config tftp://192.0.2.1/tacctl-sw-20261012-1430.cfg", ""},
		"another prefix":      {"copy running-config flash:config-20261012-1430.cfg", ""},
		"a path":              {"copy running-config flash:/x/tacctl-sw-20261012-1430.cfg", ""},
		"a space in the name": {"copy running-config flash:tacctl-s w-20261012-1430.cfg", ""},
		"copy to running":     {"copy flash:tacctl-sw-20261012-1430.cfg running-config", ""},
		"archive with args":   {"archive config force"},
		"archive and copy":    {"archive config", "copy running-config flash:tacctl-sw-20261012-1430.cfg", ""},
		"reload":              {"reload"},
		"delete":              {"delete flash:tacctl-sw-20261012-1430.cfg", ""},
		"non-ASCII":           {"copy running-config flash:tacctl-swé-20261012-1430.cfg", ""},
		"comment":             {"! hello"},
	}
	for name, lines := range bad {
		if err := CheckRestorePoint(lines); err == nil {
			t.Errorf("%s: %q accepted", name, lines)
		}
	}
}

// The file name: the device's first label, safe characters, short, and the
// plan's time in UTC.
func TestRestoreFileName(t *testing.T) {
	r := &RestorePoint{FS: "flash:"}
	for device, want := range map[string]string{
		"rtr-lab-1":                          "flash:tacctl-rtr-lab-1-20261010-1420.cfg",
		"rtr1.lab.example.net":               "flash:tacctl-rtr1-20261010-1420.cfg",
		"Core_SW.2":                          "flash:tacctl-Core_SW-20261010-1420.cfg",
		"odd name!":                          "flash:tacctl-odd-name--20261010-1420.cfg",
		strings.Repeat("a", 50) + ".example": "flash:tacctl-" + strings.Repeat("a", 32) + "-20261010-1420.cfg",
		".hidden":                            "flash:tacctl-device-20261010-1420.cfg",
	} {
		h := Header{Device: device, Now: tNow}
		got := r.File(h)
		if got != want {
			t.Errorf("%q: %s, want %s", device, got, want)
		}
		if err := CheckRestorePoint([]string{"copy running-config " + got, ""}); err != nil {
			t.Errorf("%q: the file name is not one the allowlist takes: %v", device, err)
		}
		if len(got)-len("flash:") > 63 {
			t.Errorf("%q: %d characters", device, len(got))
		}
	}
	// the time is the plan's, UTC whatever zone it carries
	zone := tNow.In(time.FixedZone("UTC+9", 9*3600))
	if got := r.File(Header{Device: "r", Now: zone}); !strings.HasSuffix(got, "-20261010-1420.cfg") {
		t.Errorf("a time in another zone: %s", got)
	}
}

// What refuses a restore point: another vendor, a file system that is not
// one, and none known.
func TestRestorePointRefusals(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	exp, cur, plain := f.load(t)
	opt := f.options()
	opt.RestorePoint = &RestorePoint{FS: "flash:"}
	if _, err := Plan(f.vendor, exp, cur, plain, opt); !errors.Is(err, ErrUsage) {
		t.Errorf("junos: %v", err)
	}
	fi := fixtureNamed(t, "cisco.reference-bare")
	exp, cur, plain = fi.load(t)
	for name, rp := range map[string]*RestorePoint{
		"no file system":  {},
		"no colon":        {FS: "flash"},
		"upper case":      {FS: "Flash:"},
		"a path":          {FS: "flash:cfg/"},
		"tftp":            {FS: "tftp:"},
		"https":           {FS: "https:"},
		"a bare archive?": {ArchiveFS: ""},
	} {
		o := fi.options()
		o.RestorePoint = rp
		if _, err := Plan(fi.vendor, exp, cur, plain, o); !errors.Is(err, ErrUsage) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if why := ValidRestoreFS("flash:"); why != "" {
		t.Errorf("flash: refused: %s", why)
	}
	for _, fs := range []string{"bootflash:", "disk0:", "usbflash0:", "harddisk:", "slot0:"} {
		if why := ValidRestoreFS(fs); why != "" {
			t.Errorf("%s refused: %s", fs, why)
		}
	}
}

// The block stands before a cleanup that is the output's only region, and the
// cleanup's after-steps name the file.
func TestRestorePointBeforeACleanupAlone(t *testing.T) {
	f, d := oldServerForms(t)
	if !d.Empty() || d.Cleanup.Empty() {
		t.Fatalf("the settled device has a first region (%d lines) or no cleanup", len(d.Lines))
	}
	d.Restore = &RestorePoint{FS: "bootflash:"}
	h, w := f.header(), Wrapper{}
	out := Block(d, h, w)
	bc := bannerChar(d.Vendor)
	rt := strings.Index(out, bc+" RESTORE POINT TO HERE: ")
	cf := strings.Index(out, bc+" CLEANUP FROM HERE: ")
	if rt < 0 || cf < rt || strings.Contains(out, "PASTE FROM HERE") {
		t.Fatalf("the restore block is not before the cleanup region:\n%s", out)
	}
	file := d.Restore.File(h)
	for _, want := range []string{"copy running-config " + file + "\n\n", "Restore point: " + file, "!   configure replace " + file + " force\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	checkCleanupWhole(t, f.name, d, h, w)
	js, err := JSON(d, h, w)
	if err != nil || !strings.Contains(string(js), `"file": "`+file+`"`) {
		t.Errorf("json: %v\n%s", err, js)
	}
}

// The report says it was not lab-tested, once, in the text and the JSON.
func TestRestorePointIsNotLabTested(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-bare")
	exp, cur, plain := f.load(t)
	opt := f.options()
	opt.RestorePoint = &RestorePoint{FS: "flash:"}
	d, err := Plan(f.vendor, exp, cur, plain, opt)
	if err != nil {
		t.Fatal(err)
	}
	out := unwrapComments(Block(d, f.header(), Wrapper{}))
	if n := strings.Count(out, "not lab-tested): read them before you use them"); n != 1 {
		t.Errorf("the note is said %d times:\n%s", n, out)
	}
	js, _ := JSON(d, f.header(), Wrapper{})
	if !strings.Contains(string(js), "not lab-tested") {
		t.Errorf("the JSON does not say it:\n%s", js)
	}
}

var reCommentWrap = regexp.MustCompile(`\n! +`)

func unwrapComments(s string) string { return reCommentWrap.ReplaceAllString(s, " ") }

// A plan with lines and nothing tacctl can type to undo them has no back-out
// output: its after-steps carry the way back with the file themselves.
func TestRestorePointOfAPlanWithNoBackoutLines(t *testing.T) {
	d := Delta{Vendor: devconf.FamilyIOS, Lines: []Line{{Section: "snmp", Op: OpSet, Text: "snmp-server location Rack 4"}},
		Restore: &RestorePoint{FS: "flash:"}}
	h := Header{Device: "r1", Now: tNow}
	if HasBackout(d) {
		t.Fatal("the delta has a back-out")
	}
	after := After(d, h, Wrapper{})
	file := d.Restore.File(h)
	for _, want := range []string{"Restore point: " + file, "!   configure replace " + file + " force\n"} {
		if !strings.Contains(after, want) {
			t.Errorf("no %q in\n%s", want, after)
		}
	}
	for _, l := range strings.Split(after, "\n") {
		if l != "" && !strings.HasPrefix(l, "!") {
			t.Errorf("a line to type after the region: %q", l)
		}
	}
	if !strings.Contains(RestoreRegion(d, h), "copy running-config "+file+"\n\n") {
		t.Errorf("the restore block:\n%s", RestoreRegion(d, h))
	}
}
