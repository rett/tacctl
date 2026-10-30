package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/batch"
)

// '--timing' of the device configuration verbs: where the time of each
// device went. The phases are marked by the code that passes them (devssh,
// devapply, the pull) and stamped by the batch's clock, which these tests
// replace (hooks.batchClock), so every duration is exact. testdata/timing
// holds the text of the verbs with the option (go test -update-timing
// rewrites it).

var updateTiming = flag.Bool("update-timing", false, "rewrite internal/cli/testdata/timing")

// growingClock is a clock whose k-th reading is k*100ms after the one
// before, so every phase of a run has a duration of its own. The batch reads
// it from one goroutine only.
func growingClock() func() time.Time {
	t := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	k := 0
	return func() time.Time {
		k++
		t = t.Add(time.Duration(k) * 100 * time.Millisecond)
		return t
	}
}

func timingGolden(t *testing.T, name, text string) {
	t.Helper()
	p := filepath.Join("testdata", "timing", name)
	if *updateTiming {
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
		t.Fatalf("%v (go test ./internal/cli -run %s -update-timing writes it)", err, t.Name())
	}
	if text != string(want) {
		t.Errorf("%s differs from its golden:\n--- got\n%s\n--- want\n%s", name, text, want)
	}
}

// applyID is the id of an apply, which holds the time and a random part.
var applyID = regexp.MustCompile(`\[tacctl-[0-9]{8}T[0-9]{6}Z-[0-9a-f]+\]`)

// timingLine is the line of the timing block that starts with the device.
func timingLine(out, name string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "    "+name+"  ") {
			return l
		}
	}
	return ""
}

// jsonLines decodes the lines of a --json run.
func jsonLines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(l, "{") {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

// stepsOf are the phases of a "timings" object, in order, as "name=ms".
func stepsOf(t *testing.T, m any) []string {
	t.Helper()
	obj, ok := m.(map[string]any)
	if !ok {
		t.Fatalf("no timings object: %v", m)
	}
	var out []string
	for _, s := range obj["steps"].([]any) {
		st := s.(map[string]any)
		out = append(out, st["step"].(string)+"="+jsonInt(st["ms"]))
	}
	return out
}

func jsonInt(v any) string {
	f, _ := v.(float64)
	return strconv.FormatInt(int64(f), 10) + "ms"
}

// --- the text -----------------------------------------------------------------

func TestTimingText(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "0ms", 40 * time.Millisecond: "40ms", 999 * time.Millisecond: "999ms",
		time.Second: "1.0s", 4120 * time.Millisecond: "4.1s", 75 * time.Second: "75.0s",
	} {
		if got := timingText(d); got != want {
			t.Errorf("timingText(%v) = %q, want %q", d, got, want)
		}
	}
}

// The lines list the devices in the order they ran, each with its phases in
// the order they happened and a total, a phase that was not reached absent,
// and end with the slowest device.
func TestTimingLines(t *testing.T) {
	ts := []batch.Timing{
		{Name: "sw1", Total: 7 * time.Second, Steps: []batch.StepTime{{Step: "connect", Duration: 4 * time.Second},
			{Step: "login", Duration: 900 * time.Millisecond}, {Step: "read", Duration: 2100 * time.Millisecond}}},
		{Name: "core1", Total: 5 * time.Second, Steps: []batch.StepTime{{Step: "connect", Duration: 4 * time.Second},
			{Step: "auth-failed", Duration: time.Second}}},
	}
	got := strings.Join(timingLines(ts), "\n")
	want := `  timing:
    sw1    connect 4.0s  login 900ms  read 2.1s  total 7.0s
    core1  connect 4.0s  auth-failed 1.0s  total 5.0s
  slowest: sw1 (7.0s)`
	if got != want {
		t.Errorf("lines:\n%s\nwant:\n%s", got, want)
	}
	if timingLines(nil) != nil {
		t.Error("no device ran, no lines")
	}
}

func TestTimingsByNameMarksTheSlowest(t *testing.T) {
	m := timingsByName([]batch.Timing{{Name: "a", Total: time.Second}, {Name: "b", Total: 2 * time.Second}})
	if m["a"].Slowest || !m["b"].Slowest || m["b"].TotalMS != 2000 {
		t.Errorf("%+v %+v", m["a"], m["b"])
	}
}

// --- pull ---------------------------------------------------------------------

// timingBox is a pull box with two devices, a Junos one read over NETCONF
// and a Cisco one over ssh, and the growing clock.
func timingBox(t *testing.T) *pullBox {
	t.Helper()
	b := newPullBox(t)
	b.sb.hooks.batchClock = growingClock()
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"lab-c", "192.168.1.30", "cisco"})
	b.serve("juniper", b.expected("lab-j"))
	b.serve("cisco", b.expected("lab-c"))
	return b
}

func TestPullTimingText(t *testing.T) {
	b := timingBox(t)
	out := b.run("device", "config", "pull", "--all", "--concurrency", "1", "--timing")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	timingGolden(t, "pull.out", out)
}

func TestPullTimingJSON(t *testing.T) {
	b := timingBox(t)
	out := b.run("device", "config", "pull", "--all", "--concurrency", "1", "--timing", "--json")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	ls := jsonLines(t, out)
	if len(ls) != 3 {
		t.Fatalf("lines:\n%s", out)
	}
	// the clock's k-th reading is k*100ms after the one before: the start of
	// the first device is reading 1, its phases readings 2 to 7
	if got := strings.Join(stepsOf(t, ls[0]["timings"]), " "); got != "connect=200ms login=300ms session=400ms read=500ms compare=600ms record=700ms" {
		t.Errorf("lab-j steps: %s", got)
	}
	if ls[0]["name"] != "lab-j" || ls[0]["timings"].(map[string]any)["total_ms"].(float64) != 3500 {
		t.Errorf("lab-j: %v", ls[0])
	}
	sum := ls[2]["summary"].(map[string]any)
	tm := sum["timings"].(map[string]any)
	if tm["slowest"] != "lab-c" || tm["slowest_ms"].(float64) <= 3500 {
		t.Errorf("summary timings: %v", tm)
	}
}

// A device that failed shows the phases it reached and the one it failed in;
// the summary names the slowest all the same.
func TestPullTimingOfAFailedDevice(t *testing.T) {
	b := timingBox(t)
	b.pw.pw = "not-the-password"
	out := b.run("device", "config", "pull", "lab-j", "--timing")
	if b.sb.code != 1 {
		t.Fatalf("exit %d: %q", b.sb.code, out)
	}
	if !strings.Contains(out, "lab-j  connect ") || !strings.Contains(out, "  auth-failed ") || strings.Contains(out, "login ") ||
		!strings.Contains(out, "  slowest: lab-j (") {
		t.Errorf("output:\n%s", out)
	}
	timingGolden(t, "pull-failed.out", out)
}

// Without the option nothing changes: the text and the JSON are the same
// whatever the clock, and say nothing of timing.
func TestPullWithoutTimingIsUnchanged(t *testing.T) {
	run := func(clock func() time.Time, args ...string) string {
		b := timingBox(t)
		b.sb.hooks.batchClock = clock
		out := b.run(append([]string{"device", "config", "pull", "--all", "--concurrency", "1"}, args...)...)
		if b.sb.code != 0 {
			t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
		}
		return out
	}
	for _, args := range [][]string{nil, {"--json"}} {
		a, c := run(growingClock(), args...), run(nil, args...)
		if strings.Contains(a, "timing") || strings.Contains(a, "slowest") || strings.Contains(c, "timing") {
			t.Errorf("%v: the output speaks of timing:\n%s", args, a)
		}
		if len(args) == 0 && a != c {
			t.Errorf("the text differs with the clock:\n%s\n%s", a, c)
		}
	}
	// the default text, pinned
	timingGolden(t, "pull-default.out", run(growingClock()))
}

// --- diff and plan with --pull ----------------------------------------------------

func TestDiffAndPlanTiming(t *testing.T) {
	b := timingBox(t)
	out := b.run("device", "config", "diff", "--all", "--pull", "--concurrency", "1", "--timing")
	if b.sb.code != 0 || !strings.Contains(out, "  timing:\n    lab-j  connect 200ms  login 300ms  session 400ms  read 500ms  compare 600ms  record 700ms  total 3.5s\n") ||
		!strings.Contains(out, "  slowest: lab-c (") {
		t.Fatalf("diff: exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}

	b = timingBox(t)
	out = b.run("device", "config", "diff", "--all", "--pull", "--concurrency", "1", "--timing", "--json")
	var devs []map[string]any
	if err := json.Unmarshal([]byte(out), &devs); err != nil || len(devs) != 2 {
		t.Fatalf("diff json: %v\n%s", err, out)
	}
	j, c := devs[0]["timings"].(map[string]any), devs[1]["timings"].(map[string]any)
	if j["slowest"] != nil || c["slowest"] != true || len(j["steps"].([]any)) != 6 {
		t.Errorf("diff json timings: %v %v", j, c)
	}

	// the plan: standard output is the plan alone
	b = timingBox(t)
	out = b.run("device", "config", "plan", "--all", "--pull", "--concurrency", "1", "--timing")
	errs := b.sb.stderr()
	if strings.Contains(out, "timing") || !strings.Contains(errs, "  timing:\n    lab-j  connect 200ms") || !strings.Contains(errs, "  slowest: lab-c (") {
		t.Errorf("plan: stdout\n%s\nstderr\n%s", out, errs)
	}
	b = timingBox(t)
	out = b.run("device", "config", "plan", "--all", "--pull", "--concurrency", "1", "--timing", "--json")
	errs = b.sb.stderr()
	var tl map[string]map[string]any
	for _, l := range strings.Split(errs, "\n") {
		if strings.HasPrefix(l, `{"timings"`) {
			if err := json.Unmarshal([]byte(l), &tl); err != nil {
				t.Fatal(err)
			}
		}
	}
	if tl == nil || tl["timings"]["slowest"] != "lab-c" || len(tl["timings"]["devices"].([]any)) != 2 || strings.Contains(out, "timings") {
		t.Errorf("plan json: stdout\n%s\nstderr\n%s", out, errs)
	}
}

// --timing is for the verbs that read a device.
func TestTimingNeedsAPullForDiffAndPlan(t *testing.T) {
	b := timingBox(t)
	for _, verb := range []string{"diff", "plan"} {
		b.run("device", "config", verb, "lab-j", "--timing")
		if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "--timing is for --pull") {
			t.Errorf("%s: exit %d %q", verb, b.sb.code, b.sb.stderr())
		}
	}
	for _, args := range [][]string{{"list", "--timing"}, {"show", "lab-j", "--timing"}} {
		b.run(append([]string{"device", "config"}, args...)...)
		if b.sb.code == 0 {
			t.Errorf("%v took --timing", args)
		}
	}
}

// --- apply --------------------------------------------------------------------

// A check marks the phases up to the commit check, a device's apply all of
// them; the timing is the whole run's, the check and the apply of a device
// added up.
func TestApplyTimingCheckAndApply(t *testing.T) {
	b := newApplyBox(t)
	b.sb.hooks.batchClock = growingClock()
	b.register("example-sw1")
	code, out, errs := b.apply("example-sw1", "--check", "--timing")
	if code != 0 {
		t.Fatalf("check: %d\n%s\n%s", code, out, errs)
	}
	timingGolden(t, "apply-check.out", out)
	if line := timingLine(out, "example-sw1"); strings.Contains(line, " commit ") || strings.Contains(line, " confirm ") || strings.Contains(line, " verify ") {
		t.Errorf("a check committed:\n%s", out)
	}

	code, out, errs = b.apply("example-sw1", "--check", "--json")
	if code != 0 || strings.Contains(out, "timing") {
		t.Errorf("without --timing: %d\n%s\n%s", code, out, errs)
	}
	code, out, errs = b.apply("example-sw1", "--check", "--timing", "--json")
	ls := jsonLines(t, out)
	if code != 0 || len(ls) != 2 {
		t.Fatalf("check json: %d\n%s\n%s", code, out, errs)
	}
	var names []string
	for _, st := range stepsOf(t, ls[0]["timings"]) {
		names = append(names, strings.Split(st, "=")[0])
	}
	if got := strings.Join(names, " "); got != "connect login session preflight read load check" {
		t.Errorf("check steps: %s", got)
	}
	if ls[1]["summary"].(map[string]any)["timings"].(map[string]any)["slowest"] != "example-sw1" {
		t.Errorf("summary: %v", ls[1])
	}

	// the apply: both phases, and the phases of the second that the first
	// never reached
	b.seed("example-sw1")
	b.sb.hooks.batchClock = growingClock()
	code, out, errs = b.apply("example-sw1", "--confirmed", "--yes", "--timing")
	if code != 0 || !strings.Contains(out, "example-sw1  applied") {
		t.Fatalf("apply: %d\n%s\n%s", code, out, errs)
	}
	timingGolden(t, "apply-apply.out", applyID.ReplaceAllString(out, "[<id>]"))
	for _, step := range []string{" commit ", " verify ", " confirm "} {
		if !strings.Contains(out, step) {
			t.Errorf("no %q in\n%s", step, out)
		}
	}
}

// With --pull the pull's phases are the run's too.
func TestApplyTimingWithPull(t *testing.T) {
	b := newApplyBox(t)
	b.sb.hooks.batchClock = growingClock()
	b.register("example-sw1")
	code, out, errs := b.apply("example-sw1", "--check", "--pull", "--timing")
	if code != 0 || !strings.Contains(out, "    example-sw1  connect ") || !strings.Contains(out, " compare ") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
}

// A device whose check failed shows the phases it reached.
func TestApplyTimingOfAFailedDevice(t *testing.T) {
	b := newApplyBox(t)
	b.sb.hooks.batchClock = growingClock()
	b.register("example-sw1")
	b.pw.pw = "not-the-password"
	code, out, _ := b.apply("example-sw1", "--check", "--timing")
	if code != 1 || !strings.Contains(out, "example-sw1  connect ") || !strings.Contains(out, "auth-failed ") || strings.Contains(out, " login ") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// The default output of an apply does not change with the marks.
func TestApplyWithoutTimingIsUnchanged(t *testing.T) {
	run := func(clock func() time.Time) string {
		b := newApplyBox(t)
		b.sb.hooks.batchClock = clock
		b.register("example-sw1")
		code, out, errs := b.apply("example-sw1", "--check")
		if code != 0 {
			t.Fatalf("exit %d\n%s\n%s", code, out, errs)
		}
		return out
	}
	a, c := run(growingClock()), run(nil)
	if a != c || strings.Contains(a, "timing") || strings.Contains(a, "slowest") {
		t.Errorf("the output differs or speaks of timing:\n%s\n%s", a, c)
	}
	timingGolden(t, "apply-check-default.out", a)
}
