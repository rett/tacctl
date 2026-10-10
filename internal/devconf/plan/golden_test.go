package plan

// The goldens (tests/fixtures/golden/plan.*): per fixture the whole output,
// the plain form and the JSON; per secrets option one more set. 'go test
// -update' rewrites them. Every golden runs through the whole-paste
// invariant (plan D109).

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

func TestGoldens(t *testing.T) {
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		type variant struct {
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
		for _, v := range vs {
			d, err := Plan(f.vendor, exp, cur, plain, v.opt)
			if err != nil {
				t.Fatalf("%s: %v", f.name, err)
			}
			h := f.header()
			w := Wrapper{ConfirmMinutes: 5}
			golden(t, f.name+"."+v.name+"output.txt", Block(d, h, w))
			p, err := Plain(d, h, w)
			switch {
			case v.opt.NoSecrets && !errors.Is(err, ErrNoSecretsPlain) && d.Counts.Placeholders > 0:
				t.Errorf("%s: a --no-secrets plain form: %v", f.name, err)
			case err == nil:
				golden(t, f.name+"."+v.name+"plain.txt", p)
			}
			js, err := JSON(d, h, w)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, f.name+"."+v.name+"json", string(js)+"\n")
			checkWholePaste(t, f.name, d, h, w)
		}
	}
}

// checkWholePaste is the invariant of plan D109 on one device's output: the
// region is safe pasted whole, the plain form has no comment, and the lines
// that confirm or save are outside the region and are comment-free single
// lines.
func checkWholePaste(t *testing.T, name string, d Delta, h Header, w Wrapper) {
	t.Helper()
	if d.Empty() {
		if Region(d, h, w) != "" {
			t.Errorf("%s: a region for an empty plan", name)
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
	// nothing that confirms or saves is typed before the region ends: the
	// lines after it that are not comments are one line
	after := full[strings.Index(full, to)+len(to)+1:]
	var typed []string
	for _, l := range strings.Split(after, "\n") {
		if l != "" && !strings.HasPrefix(l, leader) {
			typed = append(typed, l)
		}
	}
	want := "write memory"
	if d.Vendor == devconf.FamilyJunos {
		want = "commit"
	}
	if !slices.Equal(typed, []string{want}) {
		t.Errorf("%s: the lines to type after the region are %q, want just %q", name, typed, want)
	}
	// the plain form: the region without comments
	if p, err := Plain(d, h, w); err == nil {
		for _, l := range strings.Split(strings.TrimSuffix(p, "\n"), "\n") {
			if strings.HasPrefix(l, "#") || strings.HasPrefix(l, "!") || l == "" {
				t.Errorf("%s: plain holds %q", name, l)
			}
		}
		if d.Vendor == devconf.FamilyJunos && !strings.HasPrefix(p, "configure private\n") {
			t.Errorf("%s: plain does not start with the wrapper", name)
		}
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
