package plan

// The goldens (tests/fixtures/golden/plan.*): per fixture the whole output,
// the plain form and the JSON; per secrets option one more set. 'go test
// -update' rewrites them. Every golden runs through the whole-paste
// invariant (plan D109).

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// goldenCase is one planned device and the golden files it produces.
type goldenCase struct {
	name  string
	opt   Options
	d     Delta
	h     Header
	w     Wrapper
	files []goldenFile
	plain string
	// plainErr is the error of Plain (ErrNoSecretsPlain for --no-secrets).
	plainErr error
}

type goldenFile struct{ name, content string }

// goldenVariants are the secrets variants of the fixtures that have one.
func goldenVariants(f fixture) []struct {
	name string
	opt  Options
} {
	type variant = struct {
		name string
		opt  Options
	}
	vs := []variant{{"", f.options()}}
	if f.name == "juniper.lab-superuser" || f.name == "cisco.reference-bare" {
		o := f.options()
		o.NoSecrets = true
		s := f.options()
		s.Secrets = true
		vs = append(vs, variant{"nosecrets.", o}, variant{"secrets.", s})
	}
	return vs
}

// goldenCases plans every fixture in every variant and lists the files
// each one produces: the whole output, the statements only, the JSON, and
// the back-out when there is one.
func goldenCases(t *testing.T) []goldenCase {
	t.Helper()
	var out []goldenCase
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		for _, v := range goldenVariants(f) {
			d, err := Plan(f.vendor, exp, cur, plain, v.opt)
			if err != nil {
				t.Fatalf("%s: %v", f.name, err)
			}
			h := f.header()
			w := Wrapper{ConfirmMinutes: 5}
			gc := goldenCase{name: f.name + "." + v.name, opt: v.opt, d: d, h: h, w: w}
			gc.files = append(gc.files, goldenFile{gc.name + "output.txt", Block(d, h, w)})
			gc.plain, gc.plainErr = Plain(d, h, w)
			if gc.plainErr == nil {
				gc.files = append(gc.files, goldenFile{gc.name + "plain.txt", gc.plain})
			}
			js, err := JSON(d, h, w)
			if err != nil {
				t.Fatal(err)
			}
			gc.files = append(gc.files, goldenFile{gc.name + "json", string(js) + "\n"})
			if bo, err := Backout(d, h, w); err == nil {
				gc.files = append(gc.files, goldenFile{gc.name + "backout.txt", bo})
			}
			out = append(out, gc)
		}
	}
	return out
}

// coverFiles is the cover page of every fixture's default plan, with a
// device that could not be planned.
func coverFiles(t *testing.T) []goldenFile {
	t.Helper()
	var sts []DeviceStatus
	for _, gc := range goldenCases(t) {
		if gc.opt.Secrets || gc.opt.NoSecrets {
			continue
		}
		sts = append(sts, StatusFor(gc.d, gc.h))
	}
	sts = append(sts, CannotPlan(Header{Device: "dev-not-pulled", Scope: "lab", Vendor: "juniper"}, "not pulled"))
	js, err := json.MarshalIndent(sts, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return []goldenFile{{"cover.txt", Cover(sts)}, {"cover.json", string(js) + "\n"}}
}

func TestGoldens(t *testing.T) {
	for _, gc := range goldenCases(t) {
		for _, f := range gc.files {
			golden(t, f.name, f.content)
		}
		if gc.opt.NoSecrets && !errors.Is(gc.plainErr, ErrNoSecretsPlain) && gc.d.Counts.Placeholders > 0 {
			t.Errorf("%s: a --no-secrets plain form: %v", gc.name, gc.plainErr)
		}
		checkWholePaste(t, gc.name, gc.d, gc.h, gc.w)
	}
	for _, f := range coverFiles(t) {
		golden(t, f.name, f.content)
	}
}

// Every plan.* golden is produced by a variant of the golden test, and the
// test fails on a file nothing produces (M2: a stale golden shows a form
// the planner no longer makes).
func TestGoldenFilesAreProduced(t *testing.T) {
	want := map[string]bool{}
	for _, gc := range goldenCases(t) {
		for _, f := range gc.files {
			want["plan."+f.name] = true
		}
	}
	for _, f := range coverFiles(t) {
		want["plan."+f.name] = true
	}
	ents, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "plan.") {
			have[e.Name()] = true
		}
	}
	for n := range have {
		if !want[n] {
			t.Errorf("%s is produced by no variant of the golden test: delete it", n)
		}
	}
	for n := range want {
		if !have[n] {
			t.Errorf("%s is missing (go test -update writes it)", n)
		}
	}
	if len(want) < 30 {
		t.Errorf("only %d golden files are expected: the variants shrank", len(want))
	}
}

// onlyComments reports the lines of text that are neither blank nor a
// comment.
func onlyComments(text, leader string) []string {
	var typed []string
	for _, l := range strings.Split(text, "\n") {
		if l != "" && !strings.HasPrefix(l, leader) {
			typed = append(typed, l)
		}
	}
	return typed
}

// checkWholePaste is the invariant of plan D109 on one device's output: the
// region is safe pasted whole, the plain form is statements only, and
// after the region nothing is a plain line: the follow-up (commit, write
// memory) and the back-out are comments (review H1, H2).
func checkWholePaste(t *testing.T, name string, d Delta, h Header, w Wrapper) {
	t.Helper()
	if d.Empty() {
		if Region(d, h, w) != "" {
			t.Errorf("%s: a region for an empty plan", name)
		}
		if _, err := Backout(d, h, w); !errors.Is(err, ErrNoBackout) {
			t.Errorf("%s: a back-out of an empty plan: %v", name, err)
		}
		return
	}
	var lines []string
	for _, l := range RegionLines(d, h, w) {
		lines = append(lines, l.Text)
	}
	if err := CheckRegion(d.Vendor, lines); err != nil {
		t.Errorf("%s: the region is not safe to paste whole: %v\n%s", name, err, strings.Join(lines, "\n"))
	}
	// the comment lines are the labels and the placeholders, one label per
	// run of a section
	leader := commentLeader(d.Vendor)
	for _, l := range lines {
		if strings.HasPrefix(l, leader) && !strings.HasPrefix(l, leader+" "+secretLinePrefix) {
			if !strings.Contains(l, ": ") {
				t.Errorf("%s: a comment that is no label inside the region: %q", name, l)
			}
		}
	}
	// the banners are in the output once each, and the region sits between them
	full := Block(d, h, w)
	bc := bannerChar(d.Vendor)
	from := bc + " PASTE FROM HERE: " + h.Device + " " + bc
	to := bc + " PASTE TO HERE: " + h.Device + " " + bc
	if strings.Count(full, from) != 1 || strings.Count(full, to) != 1 || strings.Index(full, from) > strings.Index(full, to) {
		t.Errorf("%s: the banners are not one pair around the region", name)
	}
	between := full[strings.Index(full, from)+len(from)+1 : strings.Index(full, to)]
	if strings.TrimSuffix(between, "\n") != strings.Join(lines, "\n") {
		t.Errorf("%s: the text between the banners is not the region", name)
	}
	// H1: nothing after the region is a plain line, so copying from the
	// region's start to the end of the output cannot confirm or save
	after := full[strings.Index(full, to)+len(to)+1:]
	if typed := onlyComments(after, leader); len(typed) != 0 {
		t.Errorf("%s: plain lines after the region: %q", name, typed)
	}
	// the follow-up is still said, as a comment
	want := "write memory"
	if d.Vendor == devconf.FamilyJunos {
		want = "commit"
	}
	if !strings.Contains(after, "yourself:  "+want) {
		t.Errorf("%s: the follow-up %q is not said after the region", name, want)
	}
	// nothing before the region is a plain line either
	before := full[:strings.Index(full, from)]
	if typed := onlyComments(before, leader); len(typed) != 0 {
		t.Errorf("%s: plain lines before the region: %q", name, typed)
	}
	// the plain form: the statements, no wrapper line, no comment
	if p, err := Plain(d, h, w); err == nil {
		checkPlain(t, name, d.Vendor, p)
	}
	// the back-out is its own region, with the same invariant
	if bo, err := Backout(d, h, w); err == nil {
		checkBackoutWhole(t, name, d, h, w, bo)
	}
}

// checkPlain: every plain line is a statement of an owned shape and none is
// a wrapper line or a comment.
func checkPlain(t *testing.T, name, vendor, p string) {
	t.Helper()
	for _, l := range strings.Split(strings.TrimSuffix(p, "\n"), "\n") {
		switch {
		case l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "!"):
			t.Errorf("%s: plain holds %q", name, l)
		case vendor == devconf.FamilyJunos:
			if l == "configure private" || l == "commit check" || strings.HasPrefix(l, "commit ") || strings.HasPrefix(l, "show ") {
				t.Errorf("%s: plain holds the wrapper line %q", name, l)
			}
			if err := junosStatementOK(l); err != nil {
				t.Errorf("%s: plain line %q: %v", name, l, err)
			}
		default:
			if l == "configure terminal" || l == "end" {
				t.Errorf("%s: plain holds the wrapper line %q", name, l)
			}
		}
	}
	// the statements are the region's own: wrapped again they are safe
	if vendor == devconf.FamilyJunos && p != "" {
		lines := []string{"configure private"}
		lines = append(lines, strings.Split(strings.TrimSuffix(p, "\n"), "\n")...)
		lines = append(lines, "show | compare | no-more", "commit check", "commit confirmed 5")
		if err := CheckRegion(vendor, lines); err != nil {
			t.Errorf("%s: plain wrapped is not a safe region: %v", name, err)
		}
	}
	if vendor == devconf.FamilyIOS && p != "" {
		lines := []string{"configure terminal"}
		lines = append(lines, strings.Split(strings.TrimSuffix(p, "\n"), "\n")...)
		lines = append(lines, "end")
		if err := CheckRegion(vendor, lines); err != nil {
			t.Errorf("%s: plain wrapped is not a safe region: %v", name, err)
		}
	}
}

// checkBackoutWhole: the back-out output has exactly one region between its
// own banners, the region passes CheckRegion, and every line outside it is a
// comment.
func checkBackoutWhole(t *testing.T, name string, d Delta, h Header, w Wrapper, bo string) {
	t.Helper()
	leader := commentLeader(d.Vendor)
	bc := bannerChar(d.Vendor)
	from := bc + " BACK-OUT FROM HERE: " + h.Device + " " + bc
	to := bc + " BACK-OUT TO HERE: " + h.Device + " " + bc
	if strings.Count(bo, from) != 1 || strings.Count(bo, to) != 1 || strings.Index(bo, from) > strings.Index(bo, to) {
		t.Errorf("%s: the back-out banners are not one pair around the region", name)
		return
	}
	var lines []string
	for _, l := range BackoutLines(d, h, w) {
		lines = append(lines, l.Text)
	}
	if err := CheckRegion(d.Vendor, lines); err != nil {
		t.Errorf("%s: the back-out region is not safe to paste whole: %v\n%s", name, err, strings.Join(lines, "\n"))
	}
	between := bo[strings.Index(bo, from)+len(from)+1 : strings.Index(bo, to)]
	if strings.TrimSuffix(between, "\n") != strings.Join(lines, "\n") {
		t.Errorf("%s: the text between the back-out banners is not the region", name)
	}
	if typed := onlyComments(bo[strings.Index(bo, to)+len(to)+1:], leader); len(typed) != 0 {
		t.Errorf("%s: plain lines after the back-out region: %q", name, typed)
	}
	if typed := onlyComments(bo[:strings.Index(bo, from)], leader); len(typed) != 0 {
		t.Errorf("%s: plain lines before the back-out region: %q", name, typed)
	}
	// no confirm or save inside but the wrapper's own; the main output
	// never holds the back-out region
	if strings.Contains(Block(d, h, w), "BACK-OUT") {
		t.Errorf("%s: the main output holds the back-out", name)
	}
}

// secretValues are every secret value of the inputs of the fixtures: the
// rendering's (expected.txt) and the devices' own.
var secretValues = []string{
	"lab-secret-0123456789abcdef", "lab-ro-community", "auth-pass-0123", "priv-pass-4567",
	"EXAMPLEEXAMPLE", "example-community", "other-example", "EXAMPLEKEY", "0822455D0A16",
	"STRAYSTRAY", "notarealsecret", "example-trap-community", "EXAMPLEHASH", "EXAMPLEAUTH1", "EXAMPLEPRIV1", "$9$",
	"AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEY",
}

// The leak test: Display, the whole output under --no-secrets and the JSON
// always hold no secret value of the inputs. (Without --no-secrets the
// region holds the values it pastes, and Display and the JSON still do not.)
func TestNoSecretValueLeaks(t *testing.T) {
	scan := func(label, text string) {
		t.Helper()
		for _, v := range secretValues {
			if strings.Contains(text, v) {
				t.Errorf("%s holds the secret value %q:\n%s", label, v, text)
				return
			}
		}
	}
	checked := 0
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		for _, mode := range []string{"default", "secrets", "nosecrets"} {
			opt := f.options()
			opt.Secrets = mode == "secrets"
			opt.NoSecrets = mode == "nosecrets"
			d, err := Plan(f.vendor, exp, cur, plain, opt)
			if err != nil {
				t.Fatal(err)
			}
			label := f.name + " " + mode
			h := f.header()
			js, err := JSON(d, h, Wrapper{})
			if err != nil {
				t.Fatal(err)
			}
			scan(label+" JSON", string(js))
			scan(label+" Display", d.Display())
			// marshalling the lines or the whole delta elides too
			raw, _ := json.Marshal(d.Lines)
			scan(label+" json.Marshal(Lines)", string(raw))
			var kept strings.Builder
			for _, k := range d.Kept {
				kept.WriteString(k.Text + "\n")
			}
			scan(label+" Kept", kept.String())
			for _, w := range d.Warnings {
				scan(label+" warning", w)
			}
			for _, it := range d.Items {
				scan(label+" item", it.Words+" "+it.Statement+" "+it.Action)
			}
			for _, e := range d.Extras {
				scan(label+" extra", e.Text)
				for _, r := range e.Remove {
					scan(label+" extra removal", r.Shown())
				}
			}
			if mode == "nosecrets" {
				scan(label+" output", Block(d, h, Wrapper{}))
				if _, err := Plain(d, h, Wrapper{}); d.Counts.Placeholders > 0 && !errors.Is(err, ErrNoSecretsPlain) {
					t.Errorf("%s: plain of a --no-secrets plan: %v", label, err)
				}
				if d.HoldsSecret() {
					t.Errorf("%s: the delta holds a value", label)
				}
			}
			for _, l := range d.Lines {
				if l.HasValue && !l.Secret {
					t.Errorf("%s: a line with a value is not flagged: %q", label, l.Shown())
				}
			}
			checked++
		}
	}
	t.Logf("leak test: %d plans scanned", checked)
}

// The whole-paste invariant over every fixture and both secrets options
// (the golden test above runs it per golden; this one covers every plan
// the fixtures make, with the confirmation clamp).
func TestWholePasteInvariantOverEveryFixture(t *testing.T) {
	n := 0
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		for _, secrets := range []bool{false, true} {
			opt := f.options()
			opt.Secrets = secrets
			d, err := Plan(f.vendor, exp, cur, plain, opt)
			if err != nil {
				t.Fatal(err)
			}
			checkWholePaste(t, f.name, d, f.header(), Wrapper{ConfirmMinutes: 7})
			n++
		}
	}
	t.Logf("whole-paste invariant: %d outputs", n)
}
