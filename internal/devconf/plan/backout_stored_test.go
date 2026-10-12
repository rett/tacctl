package plan

// The back-out tacctl keeps beside a device's record (D111, point 3) is the
// back-out the plan printed and nothing more: for every fixture and every
// secrets option the stored text is the printed one, and no secret's value
// is in it.

import (
	"errors"
	"strings"
	"testing"
)

func TestStoredBackoutIsThePrintedBackout(t *testing.T) {
	stored, sawValue := 0, 0
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		for _, v := range []struct{ secrets, noSecrets bool }{{false, false}, {true, false}, {false, true}} {
			o := f.options()
			o.Secrets, o.NoSecrets = v.secrets, v.noSecrets
			d, err := Plan(f.vendor, exp, cur, plain, o)
			if err != nil {
				t.Fatal(err)
			}
			h, w := f.header(), Wrapper{ConfirmMinutes: 5}
			printed, perr := Backout(d, h, w)
			kept, kerr := StoredBackout(d, h, w)
			if (perr == nil) != (kerr == nil) || errors.Is(perr, ErrNoBackout) != errors.Is(kerr, ErrNoBackout) {
				t.Errorf("%s %+v: printed err %v, kept err %v", f.name, v, perr, kerr)
				continue
			}
			if perr != nil {
				continue
			}
			stored++
			// the lines of the back-out that hold a value
			var values []string
			for _, l := range d.Backout {
				if l.Secret && l.HasValue {
					values = append(values, l.Text)
				}
			}
			for _, l := range d.Lines {
				for _, u := range l.Undo {
					if u.Secret && u.HasValue {
						values = append(values, u.Text)
					}
				}
			}
			if len(values) == 0 {
				if kept != printed {
					t.Errorf("%s %+v: the kept back-out is not the printed one:\n--- printed\n%s\n--- kept\n%s", f.name, v, printed, kept)
				}
				continue
			}
			sawValue++
			for _, val := range values {
				if strings.Contains(kept, val) {
					t.Errorf("%s %+v: a value is in the kept back-out: %q", f.name, v, val)
				}
			}
			if !strings.Contains(kept, "type yourself, with its own value: ") {
				t.Errorf("%s %+v: a value was dropped with no note:\n%s", f.name, v, kept)
			}
			// a kept back-out is as safe to paste whole as the printed one
			if kerr := checkKeptRegion(d, h, w); kerr != nil {
				t.Errorf("%s %+v: %v", f.name, v, kerr)
			}
		}
	}
	if stored == 0 || sawValue == 0 {
		t.Errorf("%d back-outs, %d with a value: the test proves nothing", stored, sawValue)
	}
}

// checkKeptRegion runs the whole-paste allowlist over the lines of the kept
// back-out's region.
func checkKeptRegion(d Delta, h Header, w Wrapper) error {
	var lines []string
	for _, l := range BackoutLines(d.kept(), h, w) {
		lines = append(lines, l.Text)
	}
	return CheckRegion(d.Vendor, lines)
}
