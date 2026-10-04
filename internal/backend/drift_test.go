package backend_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/ui"
)

// backends_check_drift's selections and print_drift_lines' text (bash:
// lib/backend.sh at 0.1.16), over the TACACS+ test module (import_cmd set),
// the stand-in (none), an artifact no backend claims and rendered.json.

const hintPad = "                        "

func driftLine(path, what string) string {
	return "  " + ui.Red + "DRIFT:" + ui.NC + "                " + path + " — " + what + "\n"
}

func lines(entries []rendered.Entry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Line() + "\n")
	}
	return b.String()
}

func TestDriftNothingRenderedOrNothingChangedIsSilent(t *testing.T) {
	e := newTenv(t)
	if got := e.set.CheckDrift(backend.DriftAll); got != nil {
		t.Fatal(got)
	}
	e.withStore("tacacs, fake")
	if _, err := e.set.RenderAll(ctx, backend.RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := e.set.DriftLines(backend.DriftAll); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestDriftSelectionsAndHints(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if _, err := e.set.RenderAll(ctx, backend.RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	// An artifact no backend claims, recorded by hand.
	other := filepath.Join(e.w, "etc", "other.conf")
	if err := os.WriteFile(other, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rendered.Record(e.p.Rendered, other); err != nil {
		t.Fatal(err)
	}
	appendFile(t, e.p.Config, "# edit\n")
	appendFile(t, e.dropIn(), "# edit\n")
	appendFile(t, e.fakeConf, "intruder\n")
	_ = os.Remove(other)

	all := lines(e.set.CheckDrift(backend.DriftAll))
	want := "drift\t" + e.fakeConf + "\nmissing\t" + other + "\ndrift\t" + e.dropIn() + "\ndrift\t" + e.p.Config + "\n"
	if !sameLines(all, want) {
		t.Fatalf("all:\n%s", all)
	}
	if got := lines(e.set.CheckDrift(backend.DriftOf("fake"))); got != "drift\t"+e.fakeConf+"\n" {
		t.Fatalf("fake: %q", got)
	}
	if got := lines(e.set.CheckDrift(backend.DriftUnowned)); got != "missing\t"+other+"\n" {
		t.Fatalf("unowned: %q", got)
	}
	// The artifacts of a disabled backend are not reported by DriftAll.
	e.enable("tacacs")
	if got := lines(e.set.CheckDrift(backend.DriftAll)); strings.Contains(got, e.fakeConf) || !strings.Contains(got, other) {
		t.Fatalf("all with fake disabled: %q", got)
	}
	if got := lines(e.set.CheckDrift(backend.DriftOf("fake"))); got != "drift\t"+e.fakeConf+"\n" {
		t.Fatalf("fake disabled, by owner: %q", got)
	}

	e.enable("tacacs, fake")
	text := strings.Join(e.set.DriftLines(backend.DriftAll), "")
	for _, w := range []string{
		driftLine(e.p.Config, "edited since tacctl rendered it") +
			hintPad + "keep the edits: 'tacctl store import --replace' then 'tacctl config render --force'; discard them: 'tacctl config render --force'\n",
		driftLine(e.dropIn(), "edited since tacctl rendered it") +
			hintPad + "'tacctl config render' rewrites it from tacctl.yaml (a copy is kept); unit settings of your own belong in another .conf file of that directory\n",
		driftLine(e.fakeConf, "edited since tacctl rendered it") +
			hintPad + "discard the edits: 'tacctl config render --force' (a copy is kept); there is no way to adopt them into the store\n",
		driftLine(other, "rendered by tacctl but no longer there") +
			hintPad + "keep the edits: 'tacctl store import --replace' then 'tacctl config render --force'; discard them: 'tacctl config render --force'\n",
	} {
		if !strings.Contains(text, w) {
			t.Errorf("missing:\n%q\nin\n%q", w, text)
		}
	}
	if n := len(e.set.DriftLines(backend.DriftOf("tacacs"))); n != 4 {
		t.Fatalf("%d lines for tacacs", n)
	}
}

func TestDriftUnreadableRecords(t *testing.T) {
	e := newTenv(t)
	e.withStore("tacacs, fake")
	if err := os.WriteFile(e.p.Rendered, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := e.set.CheckDrift(backend.DriftAll)
	if len(got) != 1 || got[0].Status != rendered.Unreadable || got[0].Path != e.p.Rendered {
		t.Fatalf("%v", got)
	}
	// rendered.json is nobody's: it is reported as unowned, not per backend.
	if len(e.set.CheckDrift(backend.DriftUnowned)) != 1 || len(e.set.CheckDrift(backend.DriftOf("tacacs"))) != 0 {
		t.Fatal("selection of the unreadable records")
	}
	want := driftLine(e.p.Rendered, "render records cannot be read") +
		hintPad + "keep the edits: 'tacctl store import --replace' then 'tacctl config render --force'; discard them: 'tacctl config render --force'\n"
	if text := strings.Join(e.set.DriftLines(backend.DriftAll), ""); text != want {
		t.Fatalf("%q", text)
	}
	// An enabled list that cannot be read: every registered backend counts.
	e.enable("tacacs, gone")
	if len(e.set.CheckDrift(backend.DriftAll)) != 1 {
		t.Fatal("unreadable enabled list")
	}
}

func sameLines(a, b string) bool {
	as, bs := strings.Split(a, "\n"), strings.Split(b, "\n")
	if len(as) != len(bs) {
		return false
	}
	seen := map[string]int{}
	for _, l := range as {
		seen[l]++
	}
	for _, l := range bs {
		seen[l]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
