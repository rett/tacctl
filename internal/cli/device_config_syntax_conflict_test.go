package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// A setting that contradicts the image the pull read is not silent (D113,
// review M6): 'pull' (text and --json), 'device show', 'device config list'
// and the walkthrough say so. The setting still wins; nothing is refused.

// A device registered 'modern' whose pull read IOS 12.4 is compared as set,
// and every surface says the image is the other syntax.
func TestSettingContradictingThePullIsShown(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", true)
	b.sb.dev("", "ios-syntax", "lab-c", "modern")
	b.serve("cisco", b.expectedSyntax("lab-c", false))
	b.version(ciscoVersion12)

	// pull, text: ok, compared as set, and the warning on the device's row.
	out := b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "lab-c  ok via ssh") ||
		!strings.Contains(out, "warning: ios-syntax is modern but the device says IOS 12.4(15)T14 (ios12 syntax)") {
		t.Fatalf("pull: %d\n%s", b.sb.code, out)
	}
	// pull, --json: the field and the line.
	js := b.run("device", "config", "pull", "lab-c", "--json")
	var line pullJSON
	if err := json.Unmarshal([]byte(strings.Split(strings.TrimSpace(js), "\n")[0]), &line); err != nil ||
		!line.SyntaxConflict || line.Syntax != devconf.SyntaxModern || line.ImageSyntax != devconf.SyntaxIOS12 || line.OS != ciscoVersion12 {
		t.Errorf("pull --json: %+v %v\n%s", line, err, js)
	}
	// device show, text and JSON.
	show := b.run("device", "show", "lab-c")
	if !strings.Contains(show, "Config syntax: modern (the pull of ") ||
		!strings.Contains(show, "read IOS 12.4(15)T14, which is ios12 syntax, not modern: check the setting)") {
		t.Errorf("show:\n%s", show)
	}
	var sj struct {
		ConfigSyntax   string `json:"config_syntax"`
		Syntax         string `json:"syntax"`
		SyntaxConflict bool   `json:"syntax_conflict"`
		ImageSyntax    string `json:"image_syntax"`
		OS             string `json:"os"`
	}
	if err := json.Unmarshal([]byte(b.run("device", "show", "lab-c", "--json")), &sj); err != nil ||
		sj.ConfigSyntax != "modern" || sj.Syntax != "modern" || !sj.SyntaxConflict || sj.ImageSyntax != "ios12" || sj.OS != ciscoVersion12 {
		t.Errorf("show --json: %+v %v", sj, err)
	}
	// The verb with no word says it too.
	if got := b.run("device", "ios-syntax", "lab-c"); !strings.Contains(got, "modern (the pull of ") || !strings.Contains(got, "check the setting") {
		t.Errorf("ios-syntax: %q", got)
	}
	// device config list: the DETAIL column and --json.
	list := b.run("device", "config", "list")
	if !strings.Contains(list, "ios-syntax modern, the pull read ios12") {
		t.Errorf("list:\n%s", list)
	}
	var lj []listJSON
	if err := json.Unmarshal([]byte(b.run("device", "config", "list", "--json")), &lj); err != nil || len(lj) != 1 ||
		!lj[0].SyntaxConflict || lj[0].ImageSyntax != "ios12" || lj[0].State != "ok" {
		t.Errorf("list --json: %+v %v", lj, err)
	}
	// The walkthrough follows the setting and warns in one line.
	wt := b.run("device", "config", "show", "lab-c")
	if !strings.Contains(wt, "tacacs server TACACS") || strings.Contains(wt, "tacacs-server host") ||
		strings.Count(wt, "# warning:") != 1 || !strings.Contains(wt, "# warning: ios-syntax of lab-c is modern but the pull of ") ||
		!strings.Contains(wt, "read IOS 12.4(15)T14, which is ios12 syntax, not modern") {
		t.Errorf("device config show:\n%s", wt)
	}
	plainOut := plain(b.sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "lab-c"}, route, "SUDO_USER=alice"))
	if !strings.Contains(plainOut, "tacacs server TACACS") || !strings.Contains(b.sb.stderr(), "# warning: ios-syntax of lab-c is modern but") {
		t.Errorf("config cisco --name:\n%s\nstderr: %s", plainOut, b.sb.stderr())
	}

	// Setting it to what the image says clears every message.
	b.sb.dev("", "ios-syntax", "lab-c", "ios12")
	b.serve("cisco", b.expectedSyntax("lab-c", true))
	b.version(ciscoVersion12)
	out = b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "lab-c  ok via ssh") || strings.Contains(out, "warning") {
		t.Fatalf("agreeing pull: %d\n%s", b.sb.code, out)
	}
	for what, text := range map[string]string{
		"show": b.run("device", "show", "lab-c"), "list": b.run("device", "config", "list"),
		"walkthrough": b.run("device", "config", "show", "lab-c"),
	} {
		if strings.Contains(text, "check the setting") || strings.Contains(text, "the pull read") || strings.Contains(text, "# warning") {
			t.Errorf("%s still warns:\n%s", what, text)
		}
	}
	if js := b.run("device", "config", "pull", "lab-c", "--json"); strings.Contains(js, "syntax_conflict") {
		t.Errorf("--json carries a conflict:\n%s", js)
	}
}

// The verb says at once when the new setting contradicts the pulled image.
func TestConfigSyntaxVerbWarnsOnConflict(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", false)
	b.putRecord("lab-c", devconf.Record{Vendor: "cisco", Result: devconf.ResultOK, OS: ciscoVersion12, Syntax: devconf.SyntaxIOS12,
		Sections: map[string]devconf.SectionRecord{"aaa": {State: "ok"}}})
	out := b.sb.dev("", "ios-syntax", "lab-c", "modern")
	if b.sb.code != 0 || !strings.Contains(out, "The setting contradicts the image: ") ||
		!strings.Contains(out, "IOS 12.4(15)T14, which is ios12 syntax, not modern") {
		t.Errorf("modern: %d\n%s", b.sb.code, out)
	}
	out = b.sb.dev("", "ios-syntax", "lab-c", "ios12")
	if b.sb.code != 0 || strings.Contains(out, "contradicts") {
		t.Errorf("ios12: %d\n%s", b.sb.code, out)
	}
}

// A line the table does not map is refused without a setting (never read as
// modern): IOS 11.x, an ASA registered as cisco, IOS XR, IOS 15.0 and 15.1,
// and a boot-ROM line alone. Nothing is recorded; a setting compares it.
func TestPullRefusesAnUnmappedImage(t *testing.T) {
	for _, tc := range []struct{ name, line, reason string }{
		{"IOS 11.3", "IOS (tm) 4500 Software (C4500-J-M), Version 11.3(11b)T1, RELEASE SOFTWARE (fc1)", "is not an image tacctl maps"},
		{"IOS 15.1", "Cisco IOS Software, 1900 Software (C1900-UNIVERSALK9-M), Version 15.1(4)M, RELEASE SOFTWARE", "is not an image tacctl maps"},
		{"IOS 15.0", "Cisco IOS Software, 1900 Software (C1900-UNIVERSALK9-M), Version 15.0(1)M, RELEASE SOFTWARE", "is not an image tacctl maps"},
		{"an ASA registered as cisco", "Cisco Adaptive Security Appliance Software Version 9.8(4)", "is not an image tacctl maps"},
		{"IOS XR", "Cisco IOS XR Software, Version 6.1.3[Default]", "is not an image tacctl maps"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newPullBox(t)
			b.cisco("lab-c", false)
			b.serve("cisco", b.expectedSyntax("lab-c", false))
			b.version(tc.line)
			out := b.run("device", "config", "pull", "lab-c")
			if b.sb.code != 1 || !strings.Contains(out, tc.reason) || !strings.Contains(out, "tacctl device ios-syntax lab-c ios12|modern") {
				t.Fatalf("pull: %d\n%s", b.sb.code, out)
			}
			if rec, _ := b.records().Of("lab-c"); rec != nil && rec.Result != "" {
				t.Errorf("a refused pull was recorded: %+v", rec)
			}
			js := b.run("device", "config", "pull", "lab-c", "--json")
			var line pullJSON
			if err := json.Unmarshal([]byte(strings.Split(strings.TrimSpace(js), "\n")[0]), &line); err != nil || line.Syntax != "" || !strings.Contains(line.Reason, "unknown") {
				t.Errorf("--json: %+v %v\n%s", line, err, js)
			}
			// The setting is how the device is read.
			b.sb.dev("", "ios-syntax", "lab-c", "modern")
			if out := b.run("device", "config", "pull", "lab-c"); b.sb.code != 0 || !strings.Contains(out, "lab-c  ok via ssh") {
				t.Errorf("modern: %d\n%s", b.sb.code, out)
			}
		})
	}
}

// A boot-ROM line is not an image line: a device that answers only ROM and
// BOOTLDR lines gives the pull no version, so it is refused as unread.
func TestPullIgnoresBootLoaderLines(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", false)
	b.serve("cisco", b.expectedSyntax("lab-c", true))
	b.version("ROM: System Bootstrap, Version 12.4(13r)T, RELEASE SOFTWARE (fc1)\nBOOTLDR: 7200 Software, Version 12.2(44)SE")
	out := b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 1 || !strings.Contains(out, "the device's IOS version was not read") ||
		strings.Contains(out, "ok via ssh") {
		t.Errorf("boot loader lines: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-c"); rec != nil && (rec.OS != "" || rec.Syntax != "") {
		t.Errorf("the loader's line was recorded: %+v", rec)
	}
	// With the image line after them, the image decides.
	b.version("ROM: System Bootstrap, Version 12.4(13r)T\n" + ciscoVersionModern)
	b.serve("cisco", b.expectedSyntax("lab-c", false))
	if out := b.run("device", "config", "pull", "lab-c"); b.sb.code != 0 || !strings.Contains(out, "ok via ssh") {
		t.Errorf("image line after ROM: %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("lab-c"); rec == nil || rec.OS != ciscoVersionModern || rec.Syntax != devconf.SyntaxModern {
		t.Errorf("record %+v", rec)
	}
}

// 'device config show' of a device that WAS pulled by a build that kept no
// image line does not say 'no pull yet'; one that was never pulled does.
func TestWalkthroughNoteForAPulledDeviceWithoutImage(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", false)
	out := b.run("device", "config", "show", "lab-c")
	if !strings.Contains(out, "# syntax: modern (no pull yet;") {
		t.Errorf("never pulled:\n%s", out)
	}
	b.putRecord("lab-c", devconf.Record{Vendor: "cisco", Result: devconf.ResultOK,
		Sections: map[string]devconf.SectionRecord{"aaa": {State: "ok"}}})
	out = b.run("device", "config", "show", "lab-c")
	if strings.Contains(out, "no pull yet") || strings.Count(out, "# syntax:") != 1 ||
		!strings.Contains(out, "the last pull holds no image line: run device config pull lab-c") {
		t.Errorf("pulled without an image line:\n%s", out)
	}
	// config cisco --name says the same on stderr.
	b.sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "lab-c"}, route, "SUDO_USER=alice")
	if strings.Contains(b.sb.stderr(), "no pull yet") || !strings.Contains(b.sb.stderr(), "the last pull holds no image line") {
		t.Errorf("config cisco --name stderr: %s", b.sb.stderr())
	}
}

// 'config cisco --name X' of a device on auto whose record holds an IOS 12.x
// image renders the 12.x syntax and says nothing about it.
func TestConfigCiscoNameAutoWithIOS12Record(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", true)
	b.putRecord("lab-c", devconf.Record{Vendor: "cisco", Result: devconf.ResultOK, OS: ciscoVersion12, Syntax: devconf.SyntaxIOS12,
		Sections: map[string]devconf.SectionRecord{"aaa": {State: "ok"}}})
	plainOut := plain(b.sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "lab-c"}, route, "SUDO_USER=alice"))
	if b.sb.code != 0 || !strings.Contains(plainOut, "tacacs-server host") || strings.Contains(plainOut, "tacacs server TACACS") {
		t.Errorf("config cisco --name:\n%s", plainOut)
	}
	if strings.Contains(plainOut, "# syntax:") || strings.Contains(plainOut, "# warning") ||
		strings.Contains(b.sb.stderr(), "# syntax:") || strings.Contains(b.sb.stderr(), "# warning") {
		t.Errorf("a note for a device the pull settles:\n%s\nstderr: %s", plainOut, b.sb.stderr())
	}
}

// The setting goes with the vendor: a device that stops being Cisco does not
// keep it, and the message says which setting went.
func TestDeviceVendorChangeDropsTheSyntax(t *testing.T) {
	b := newPullBox(t)
	b.cisco("lab-c", false)
	b.sb.dev("", "ios-syntax", "lab-c", "ios12")
	if !strings.Contains(b.sb.devices(), "config_syntax: ios12") {
		t.Fatalf("not set:\n%s", b.sb.devices())
	}
	out := b.sb.dev("", "vendor", "lab-c", "juniper")
	if b.sb.code != 0 || strings.Contains(b.sb.devices(), "config_syntax") ||
		!strings.Contains(out, "The configuration syntax setting (ios12) was removed: it is a Cisco setting.") {
		t.Errorf("vendor juniper: %d\n%s\n%s", b.sb.code, b.sb.devices(), out)
	}
	// The registry is still readable, and going back to Cisco starts at auto.
	b.sb.dev("", "vendor", "lab-c", "cisco")
	if b.sb.code != 0 || strings.Contains(b.sb.devices(), "config_syntax") {
		t.Errorf("vendor cisco: %d\n%s", b.sb.code, b.sb.devices())
	}
	// A device with no setting says nothing.
	out = b.sb.dev("", "vendor", "lab-c", "juniper")
	if b.sb.code != 0 || strings.Contains(out, "configuration syntax") {
		t.Errorf("no setting: %d\n%s", b.sb.code, out)
	}
	// 'vendor clear' is the other way a Cisco device stops being one.
	b.sb.dev("", "vendor", "lab-c", "cisco")
	b.sb.dev("", "ios-syntax", "lab-c", "modern")
	b.sb.dev("", "vendor", "lab-c", "clear")
	if b.sb.code != 0 || strings.Contains(b.sb.devices(), "config_syntax") {
		t.Errorf("vendor clear: %d\n%s", b.sb.code, b.sb.devices())
	}
}
