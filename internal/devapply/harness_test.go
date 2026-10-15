package devapply

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// The secrets of the test deltas: no text the package returns, logs or
// stores may hold one.
const (
	secretKey  = "zzTopSecretKey9"
	secretComm = "zz-comm-secret"
)

var allSecrets = []string{secretKey, secretComm}

var testStart = time.Date(2026, 10, 13, 14, 0, 0, 0, time.UTC)

// fixtureDir is the fake's Junos configure model fixture.
const fixtureDir = "../../tests/fixtures/devconf/fake/junos-apply"

// device is one fake device with its clock.
type device struct {
	t     *testing.T
	srv   *fakedev.Server
	clk   *fakedev.FakeClock
	dir   string
	state string
	// netconf makes the held transport and the fresh login NETCONF ones
	// (mode is the held transport's edit-session mode).
	netconf bool
	mode    NetconfMode
}

// newDevice copies the fixture, adds the knob files and serves it.
func newDevice(t *testing.T, knobs map[string]string) *device {
	t.Helper()
	dir := t.TempDir()
	ents, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(fixtureDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The fake echoes an empty line as ' ' (the trailing space it adds to
	// every command), which puts a blank after the prompt on its line, and
	// devssh's shell then never learns the prompt: 'echo.plain' echoes
	// as typed. (A finding for the fake, reported with WP14.4.)
	if _, ok := knobs["echo.plain"]; !ok {
		if err := os.WriteFile(filepath.Join(dir, "echo.plain"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for n, c := range knobs {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	clk := fakedev.NewFakeClock(testStart)
	srv := fakedev.New(dir, fakedev.WithClock(clk))
	t.Cleanup(srv.Stop)
	return &device{t: t, srv: srv, clk: clk, dir: dir, state: t.TempDir()}
}

// unknob removes a knob file.
func (d *device) unknob(name string) { _ = os.Remove(filepath.Join(d.dir, name)) }

func (d *device) target(user, pw string) devssh.Target {
	host, port, _ := net.SplitHostPort(d.srv.Addr())
	p, _ := strconv.Atoi(port)
	return devssh.Target{
		Host: host, Port: p, User: user, HostKeys: []string{fakedev.HostKey()},
		Password:       func() (string, error) { return pw, nil },
		Quiet:          25 * time.Millisecond,
		ConnectTimeout: 3 * time.Second,
	}
}

// dial is the held login (the default user).
func (d *device) dial() *JunosCLI {
	d.t.Helper()
	j, err := DialJunos(context.Background(), d.target(fakedev.DefaultUser, fakedev.DefaultPassword))
	if err != nil {
		d.t.Fatalf("dial: %v", err)
	}
	return j
}

// dialNetconf is the held login over NETCONF.
func (d *device) dialNetconf(mode NetconfMode) *JunosNetconf {
	d.t.Helper()
	j, err := DialJunosNetconf(context.Background(), d.target(fakedev.DefaultUser, fakedev.DefaultPassword), mode)
	if err != nil {
		d.t.Fatalf("dial netconf: %v", err)
	}
	return j
}

// transport is the held transport of the device's kind.
func (d *device) transport() Transport {
	if d.netconf {
		return d.dialNetconf(d.mode)
	}
	return d.dial()
}

// verify is the fresh login of the verification.
func (d *device) verify(ctx context.Context) (Reader, error) {
	if d.netconf {
		return DialJunosNetconf(ctx, d.target(fakedev.DefaultUser, fakedev.DefaultPassword), ModePrivate)
	}
	return DialJunos(ctx, d.target(fakedev.DefaultUser, fakedev.DefaultPassword))
}

// The test's desired statements: an snmp community (its name is the
// secret), a tacplus secret, an accounting event, the removal of a client of
// the fixture's community.
func desiredLines() []plan.Line {
	return []plan.Line{
		{Section: "aaa", Op: plan.OpSet, Text: `set system tacplus-server 192.0.2.11 secret "` + secretKey + `"`,
			Secret: true, HasValue: true, Elided: "set system tacplus-server 192.0.2.11 secret <secret>"},
		{Section: "aaa", Op: plan.OpSet, Text: "set system accounting events login"},
		{Section: "snmp", Op: plan.OpSet, Text: "set snmp community " + secretComm + " authorization read-only",
			Secret: true, HasValue: true, Elided: "set snmp community <secret> authorization read-only"},
		{Section: "snmp", Op: plan.OpDelete, Text: "delete snmp community example-ro clients 192.0.2.0/24",
			Secret: true, HasValue: true, Elided: "delete snmp community <secret> clients 192.0.2.0/24"},
	}
}

// expected is the rendering the test deltas come from: it names the
// tacplus server and both communities.
func expected() []devices.Section {
	return []devices.Section{
		{Name: "aaa", Lines: []string{
			`set system tacplus-server 192.0.2.11 secret "` + secretKey + `"`,
			"set system accounting events login",
		}, Secret: []bool{true, false}},
		{Name: "snmp", Lines: []string{
			"set snmp community " + secretComm + " authorization read-only",
			"set snmp community example-ro authorization read-only",
		}, Secret: []bool{true, true}},
	}
}

// planner is a stand-in for the caller's planner: each desired set the
// read lacks, each desired delete whose statement the read has.
type planner struct {
	mu      sync.Mutex
	desired []plan.Line
	calls   int
	// after, when set, replaces the result of the calls after the first
	// (the convergence read).
	after func(d plan.Delta) plan.Delta
	// onRead runs at each call.
	onRead func(n int)
}

func (p *planner) plan(_ context.Context, raw string, from net.IP) (plan.Delta, error) {
	p.mu.Lock()
	p.calls++
	n := p.calls
	p.mu.Unlock()
	if from == nil {
		return plan.Delta{}, fmt.Errorf("no local address")
	}
	if p.onRead != nil {
		p.onRead(n)
	}
	have := map[string]bool{}
	var all []string
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		have[l] = true
		all = append(all, l)
	}
	d := plan.Delta{Vendor: devconf.FamilyJunos}
	for _, l := range p.desired {
		stmt := strings.TrimPrefix(strings.TrimPrefix(l.Text, "set "), "delete ")
		present := have["set "+stmt]
		for _, a := range all {
			if strings.HasPrefix(a, "set "+stmt+" ") {
				present = true
			}
		}
		if l.Secret && l.Op == plan.OpSet && strings.Contains(stmt, " secret ") {
			pre, _, _ := strings.Cut(stmt, " secret ")
			for _, a := range all {
				if strings.HasPrefix(a, "set "+pre+" secret ") {
					present = true
				}
			}
		}
		if (l.Op == plan.OpSet && !present) || (l.Op == plan.OpDelete && present) {
			d.Lines = append(d.Lines, l)
		}
	}
	for _, s := range plan.PlanOrder(devconf.FamilyJunos) {
		st := plan.StateNoChange
		for _, l := range d.Lines {
			if l.Section == s {
				st = plan.StatePlanned
			}
		}
		d.Sections = append(d.Sections, plan.SectionPlan{Name: s, State: st})
	}
	if n > 1 && p.after != nil {
		d = p.after(d)
	}
	return d, nil
}

// input is a complete Input for the device.
func (d *device) input(p *planner) Input {
	return Input{
		Device: "example-sw1", Names: []string{"example-sw1", "example-sw1.lab.example.net"},
		User:           "alice",
		Transport:      d.transport(),
		Verify:         d.verify,
		Plan:           p.plan,
		Allow:          plan.Allow{Login: fakedev.DefaultUser, Expected: expected()},
		ConfirmMinutes: 10,
		Clock:          d.clk.Now,
		Rand:           bytes.NewReader(bytes.Repeat([]byte{0x3f, 0x2a}, 64)),
		StateDir:       d.state,
	}
}

// reviewed is the delta the first plan makes of the device (Phase A).
func (d *device) reviewed(p *planner) plan.Delta {
	d.t.Helper()
	j := d.dial()
	defer func() { _ = j.Close() }()
	raw, err := j.Read(context.Background())
	if err != nil {
		d.t.Fatal(err)
	}
	q := &planner{desired: p.desired}
	dl, err := q.plan(context.Background(), raw, net.IPv4(127, 0, 0, 1))
	if err != nil {
		d.t.Fatal(err)
	}
	return dl
}

// assertLog holds the command logs to the rule of the brief: nothing but
// the delta's statements (as shown) and the apply's words.
func assertLog(t *testing.T, o Outcome, delta []plan.Line) {
	t.Helper()
	_, read, _ := devconf.Commands("juniper")
	shown := map[string]bool{}
	for _, l := range delta {
		shown[l.Shown()] = true
	}
	for _, logs := range [][]string{o.Log, o.VerifyLog} {
		for _, l := range logs {
			if plan.IsApplyWord(l) || l == read || shown[l] || strings.HasPrefix(l, "netconf: ") {
				continue
			}
			t.Errorf("the log holds %q, which is neither a delta statement nor an apply word", l)
		}
	}
}

// assertNoSecret scans everything the outcome and the state directory hold.
func assertNoSecret(t *testing.T, o Outcome, state string) {
	t.Helper()
	b, _ := json.Marshal(o)
	texts := []string{fmt.Sprintf("%+v", o), string(b), o.Line(), strings.Join(o.Log, "\n"), strings.Join(o.VerifyLog, "\n")}
	if state != "" {
		_ = filepath.Walk(state, func(p string, fi os.FileInfo, err error) error {
			if err == nil && !fi.IsDir() {
				c, _ := os.ReadFile(p)
				texts = append(texts, string(c))
			}
			return nil
		})
	}
	for _, s := range allSecrets {
		for _, tx := range texts {
			if strings.Contains(tx, s) {
				t.Fatalf("a secret %q is in the outcome or the state:\n%s", s, tx)
			}
		}
	}
}

// indexOf is the position of the first log line equal to s (-1 none).
func indexOf(log []string, s string) int {
	for i, l := range log {
		if l == s {
			return i
		}
	}
	return -1
}

// lastIs reports whether the log ends with the lines.
func endsWith(log []string, tail ...string) bool {
	if len(log) < len(tail) {
		return false
	}
	for i, s := range tail {
		if log[len(log)-len(tail)+i] != s {
			return false
		}
	}
	return true
}
