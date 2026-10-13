package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// The device configuration verbs against a fake WTI unit
// (tests/fixtures/devconf/wti/fake, internal/devssh/fakedev menu mode): the
// pages are walked over a terminal session in a first connection and the
// user directory in a second, as the reader of internal/devconf does.

const (
	wtiFixtures = "../../tests/fixtures/devconf/wti"
	// the communities the unit shows in clear: a read must keep none of them
	wtiROSecret   = "SENTINELro-7f3a91"
	wtiRWSecret   = "SENTINELrw-7f3a91"
	wtiTrapSecret = "SENTINELtrap-7f3a91"
)

var wtiSentinels = []string{wtiROSecret, wtiRWSecret, wtiTrapSecret, testPassword}

// wtiUnitDir writes the manifest of a fake unit at command menu version
// version and the login's level, with other sessions open and the IP tables
// list filled, serving the captured screens with the SNMP communities
// replaced by sentinels.
func wtiUnitDir(t *testing.T, level, version string, sessions int) string {
	t.Helper()
	fx, err := filepath.Abs(wtiFixtures)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var m strings.Builder
	fmt.Fprintf(&m, "screens %s\nversion %s\nlevel %s\nsessions %d\niptables filled\n", fx, version, level, sessions)
	for _, p := range []struct{ key, file string }{{"/N > 25", "network-25.txt"}, {"/N > 25 > 9", "network-25-9.txt"}, {"/N > 26", "network-26.txt"}} {
		b, err := os.ReadFile(filepath.Join(fx, "pages", p.file))
		if err != nil {
			t.Fatal(err)
		}
		s := strings.ReplaceAll(string(b), "rw-community", wtiRWSecret)
		if strings.HasSuffix(p.file, "26.txt") {
			s = strings.ReplaceAll(s, "ro-community", wtiTrapSecret)
		} else {
			s = strings.ReplaceAll(s, "ro-community", wtiROSecret)
		}
		if err := os.WriteFile(filepath.Join(dir, p.file), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&m, "page %s = %s\n", p.key, p.file)
	}
	if err := os.WriteFile(filepath.Join(dir, "menu"), []byte(m.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newWTIBox is a pull box whose fake device is a WTI unit.
func newWTIBox(t *testing.T, level string, sessions int) *pullBox {
	t.Helper()
	return newPullBoxIn(t, wtiUnitDir(t, level, "8.10", sessions))
}

// events counts the fake unit's events that begin with prefix.
func eventsOf(b *pullBox, prefix string) []string {
	var out []string
	for _, e := range b.srv.Events() {
		if strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}

// storeText is every file of the records and the sections files, and every
// line of the audit log: what the pull kept.
func (b *pullBox) storeText() string {
	b.t.Helper()
	var sb strings.Builder
	root := filepath.Join(b.sb.dir, "var-lib")
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := os.ReadFile(p)
			sb.WriteString(p + "\n" + string(data) + "\n")
		}
		return nil
	})
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "logger" {
			sb.WriteString(strings.Join(c.Args, " ") + "\n")
		}
	}
	return sb.String()
}

func TestPullWTIUnitThenListShowDiff(t *testing.T) {
	b := newWTIBox(t, "administrator", 1)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})

	out := b.run("device", "config", "pull", "pdu1")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"pdu1", "via ssh; 1 other session on the unit"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "1 ok") && !strings.Contains(out, "1 differ") {
		t.Errorf("no summary in:\n%s", out)
	}
	rec, ok := b.records().Of("pdu1")
	if !ok || rec.Result != "ok" || rec.Transport != "ssh" || rec.OS != "8.10" || rec.By != "alice" || rec.Netconf != "" ||
		rec.Address != "192.168.1.40" || rec.Vendor != "wti" || rec.Pulled.IsZero() || rec.Syntax != "" {
		t.Fatalf("record %+v", rec)
	}
	if u := rec.Unit; u == nil || u.OtherSessions != 1 || !u.UsersRead || u.SiteID == "" {
		t.Errorf("unit facts %+v", rec.Unit)
	}
	// A WTI unit's fact is its release, the command menu's version; the menu
	// prints no model and no serial number.
	if rec.Release != "8.10" || rec.Model != "" || rec.Serial != "" {
		t.Errorf("facts %q %q %q", rec.Release, rec.Model, rec.Serial)
	}
	// The sections of a unit: the four it has, no n/a noise for the others.
	var names []string
	for n := range rec.Sections {
		names = append(names, n)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"aaa", "breakglass", "mgmt-acl", "snmp"}) {
		t.Errorf("sections %q", names)
	}
	// Nothing was written on the unit: no top-level menu was left with ESC
	// (that saves the whole configuration), and both sessions went away on a
	// page.
	if got := b.srv.Saved(); len(got) != 0 {
		t.Errorf("the unit saved its configuration: %q (events %q)", got, b.srv.Events())
	}
	if got := eventsOf(b, "save"); len(got) != 0 {
		t.Errorf("save events %q", got)
	}
	if got := eventsOf(b, "close"); len(got) != 2 {
		t.Errorf("close events %q, want one per session", got)
	}
	for _, e := range []string{"entry", "refused", "unmodelled", "no-page"} {
		if got := eventsOf(b, e); len(got) != 0 {
			t.Errorf("%s events %q", e, got)
		}
	}
	if b.srv.Logins() != 2 {
		t.Errorf("logins %d, want the pages' session and the user directory's", b.srv.Logins())
	}
	if b.pw.asked != 1 || b.pw.accepted != 1 || b.pw.rejected != 0 {
		t.Errorf("password source: asked %d accepted %d rejected %d", b.pw.asked, b.pw.accepted, b.pw.rejected)
	}
	// The audit line names the transport and the result.
	var audit string
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "logger" && strings.Contains(strings.Join(c.Args, " "), "device config pull") {
			audit = strings.Join(c.Args, " ")
		}
	}
	if !strings.Contains(audit, "user=alice device=pdu1 transport=ssh result=ok duration=") {
		t.Errorf("audit line %q", audit)
	}

	// device list, show, config list.
	for _, l := range strings.Split(b.run("device", "list"), "\n") {
		f := strings.Fields(l)
		if len(f) > 3 && f[0] == "pdu1" && !slices.ContainsFunc(f, func(w string) bool { return w == "ok" || w == "differs" }) {
			t.Errorf("pdu1's row has no state: %q", l)
		}
	}
	show := b.run("device", "show", "pdu1")
	if !strings.Contains(show, "Configuration: pulled ") || !strings.Contains(show, " by alice over ssh, ok; sections: aaa ") ||
		!strings.Contains(show, "command menu 8.10") || !strings.Contains(show, "1 other session on the unit") {
		t.Errorf("show:\n%s", show)
	}
	if strings.Contains(show, "not read") {
		t.Errorf("show says the unit is not read:\n%s", show)
	}
	cfgList := b.run("device", "config", "list")
	if !strings.Contains(cfgList, "pdu1") || !strings.Contains(cfgList, "ssh") || strings.Contains(cfgList, "not read") {
		t.Errorf("config list:\n%s", cfgList)
	}
	if got := b.run("device", "config", "list", "--transport", "ssh"); !strings.Contains(got, "pdu1") ||
		!strings.Contains(got, "1 other session on the unit") {
		t.Errorf("--transport ssh:\n%s", got)
	}
	var lj []listJSON
	if err := json.Unmarshal([]byte(b.run("device", "config", "list", "--json")), &lj); err != nil || len(lj) != 1 ||
		lj[0].Unit == nil || lj[0].Unit.Version != "8.10" || lj[0].Unit.OtherSessions != 1 || !lj[0].Unit.UsersRead || lj[0].Unit.SiteID == "" {
		t.Errorf("list json %v %+v", err, lj)
	}
	if got := b.run("device", "config", "list", "--transport", "none"); strings.Contains(got, "pdu1") {
		t.Errorf("--transport none lists a pulled unit:\n%s", got)
	}
	if got := b.run("device", "config", "list", "--vendor", "wti"); !strings.Contains(got, "pdu1") {
		t.Errorf("--vendor wti:\n%s", got)
	}

	// diff: the sections of a unit, nothing of the ones it has not.
	diff := b.run("device", "config", "diff", "pdu1")
	if !strings.Contains(diff, "Device pdu1 (lab, wti): pulled ") || !strings.Contains(diff, " over ssh") {
		t.Errorf("diff header:\n%s", diff)
	}
	for _, sec := range []string{"aaa", "mgmt-acl", "snmp", "breakglass"} {
		if !strings.Contains(diff, "\n  "+padRight(sec, 11)+" ") {
			t.Errorf("diff has no %s section:\n%s", sec, diff)
		}
	}
	for _, sec := range []string{"roles", "netconf", "system"} {
		if strings.Contains(diff, "\n  "+padRight(sec, 11)+" ") {
			t.Errorf("diff has a %s section:\n%s", sec, diff)
		}
	}
	// the stored sections are what the diff compares: no read of the unit
	if b.srv.Logins() != 2 {
		t.Errorf("a diff of the stored pull logged in: %d logins", b.srv.Logins())
	}

	// JSON.
	js := b.run("device", "config", "pull", "pdu1", "--json")
	lines := strings.Split(strings.TrimSpace(js), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d json lines:\n%s", len(lines), js)
	}
	var pj pullJSON
	if err := json.Unmarshal([]byte(lines[0]), &pj); err != nil {
		t.Fatal(err)
	}
	if pj.Name != "pdu1" || pj.Vendor != "wti" || pj.Status != "ok" || pj.Result != "ok" || pj.Transport != "ssh" || pj.OS != "8.10" ||
		pj.Unit == nil || pj.Unit.Version != "8.10" || pj.Unit.Level != "administrator" || pj.Unit.OtherSessions != 1 || !pj.Unit.UsersRead ||
		pj.Unit.SiteID == "" || pj.Warning != "" {
		t.Errorf("json %+v unit %+v", pj, pj.Unit)
	}
	var secNames []string
	for _, s := range pj.Sections {
		secNames = append(secNames, s.Name)
	}
	if !slices.Equal(secNames, []string{"aaa", "mgmt-acl", "snmp", "breakglass"}) {
		t.Errorf("json sections %q", secNames)
	}

	// No secret anywhere: not in the output, the records, the sections files
	// or the log; and the raw pages are not kept.
	withDiff := b.run("device", "config", "pull", "pdu1", "--diff")
	for what, text := range map[string]string{"pull": out, "show": show, "list": cfgList, "diff": diff, "json": js,
		"pull --diff": withDiff, "stderr": b.sb.stderr(), "store": b.storeText()} {
		noSecrets(t, what, text, wtiSentinels...)
	}
	if strings.Contains(b.storeText(), "# page:") || strings.Contains(b.storeText(), "SNMP ACCESS") {
		t.Errorf("the raw pages were kept:\n%s", b.storeText())
	}
	if b.sb.runner.ArgvContains(testPassword) {
		t.Error("the password reached an argv")
	}
}

// An engineer's login (SuperUser level) can configure the unit, and a batch
// selects units like any device: --all, --scope and --vendor.
func TestPullWTISuperUserAndSelectors(t *testing.T) {
	b := newWTIBox(t, "superuser", 0)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"}, [3]string{"pdu2", "192.168.1.41", "wti"})
	for _, args := range [][]string{{"--all"}, {"--scope", "lab"}, {"--vendor", "wti"}, {"--stale"}} {
		out := b.run(append([]string{"device", "config", "pull"}, args...)...)
		summary := strings.Contains(out, "2 ok") || strings.Contains(out, "2 differ")
		if b.sb.code != 0 || !strings.Contains(out, "pdu1") || !strings.Contains(out, "pdu2") || !summary ||
			strings.Contains(out, "skipped") || strings.Contains(out, "other session") {
			t.Errorf("%v: %d\n%s", args, b.sb.code, out)
		}
	}
	if got := eventsOf(b, "save"); len(got) != 0 {
		t.Errorf("save events %q", got)
	}
	for _, n := range []string{"pdu1", "pdu2"} {
		if rec, ok := b.records().Of(n); !ok || rec.Result != "ok" || rec.OS != "8.10" || rec.Unit == nil || rec.Unit.OtherSessions != 0 {
			t.Errorf("%s: %+v", n, rec)
		}
	}
	// The password was asked once per run (the last may have selected none).
	if b.pw.asked < 3 || b.pw.asked > 4 {
		t.Errorf("asked %d times for 4 runs", b.pw.asked)
	}
	// --transport netconf does not exist for a unit: refused before any login.
	logins := b.srv.Logins()
	b.run("device", "config", "pull", "pdu1", "--transport", "netconf")
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "NETCONF is not read for WTI units") || b.srv.Logins() != logins {
		t.Errorf("netconf: %d %q (logins %d, was %d)", b.sb.code, b.sb.stderr(), b.srv.Logins(), logins)
	}
}

// A login whose level cannot configure the unit is 'denied': a failed line
// with the level and the hint, exit 1, and the next unit is still read.
func TestPullWTIDeniedByLevel(t *testing.T) {
	for _, level := range []string{"user", "viewonly"} {
		t.Run(level, func(t *testing.T) {
			b := newWTIBox(t, level, 0)
			b.devices([3]string{"pdu1", "192.168.1.40", "wti"}, [3]string{"pdu2", "192.168.1.41", "wti"})
			label := map[string]string{"user": "User", "viewonly": "ViewOnly"}[level]
			out := b.run("device", "config", "pull", "--all")
			if b.sb.code != 1 {
				t.Errorf("exit %d", b.sb.code)
			}
			for _, want := range []string{
				"failed: the login's WTI level is " + label + "; SuperUser or Administrator is needed",
				"2 failed", "tacctl group edit",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("no %q in:\n%s", want, out)
				}
			}
			// The password is fine, so the pool did not stop and no password
			// was forgotten.
			if b.pw.rejected != 0 || b.pw.accepted != 1 || strings.Contains(out, "not started") {
				t.Errorf("password source: accepted %d rejected %d\n%s", b.pw.accepted, b.pw.rejected, out)
			}
			rec, ok := b.records().Of("pdu1")
			if !ok || rec.Result != "denied" || !rec.Pulled.IsZero() {
				t.Errorf("record %+v", rec)
			}
			if got := b.srv.Saved(); len(got) != 0 {
				t.Errorf("saved %q", got)
			}
			// Nothing but the gate was typed: no page was opened.
			for _, c := range b.srv.Commands() {
				if strings.HasPrefix(c, "/N") || strings.HasPrefix(c, "/F") {
					t.Errorf("a denied login typed %q (commands %q)", c, b.srv.Commands())
				}
			}
			// list: failed, --failed has it, the detail says the result; JSON.
			if got := b.run("device", "config", "list", "--failed"); !strings.Contains(got, "pdu1") || !strings.Contains(got, "denied") ||
				!strings.Contains(got, "failed") {
				t.Errorf("list --failed:\n%s", got)
			}
			if got := b.run("device", "config", "list", "--stale"); !strings.Contains(got, "pdu2") {
				t.Errorf("list --stale:\n%s", got)
			}
			var l []listJSON
			if err := json.Unmarshal([]byte(b.run("device", "config", "list", "--json", "--failed")), &l); err != nil || len(l) != 2 ||
				l[0].State != "failed" || l[0].Result != "denied" {
				t.Errorf("list json %v %+v", err, l)
			}
			if b.run("device", "config", "list", "--never"); b.sb.code != 0 {
				t.Errorf("exit %d", b.sb.code)
			}
			show := b.run("device", "show", "pdu1")
			if !strings.Contains(show, "never pulled, denied (the last attempt)") {
				t.Errorf("show:\n%s", show)
			}
			// the CONFIG column of device list
			found := false
			for _, l := range strings.Split(b.run("device", "list"), "\n") {
				if f := strings.Fields(l); len(f) > 3 && f[0] == "pdu1" {
					found = slices.Contains(f, "failed")
				}
			}
			if !found {
				t.Error("device list does not say failed for pdu1")
			}
			// --json of the pull says the result word and the level.
			js := b.run("device", "config", "pull", "pdu1", "--json")
			var pj pullJSON
			if err := json.Unmarshal([]byte(strings.Split(strings.TrimSpace(js), "\n")[0]), &pj); err != nil || pj.Result != "denied" ||
				pj.Status != "failed" || !strings.Contains(pj.Reason, "WTI level is "+label) {
				t.Errorf("json %v %+v", err, pj)
			}
			// diff names the failed pull
			diff := b.run("device", "config", "diff", "pdu1")
			if b.sb.code != 1 || !strings.Contains(diff, "no configuration has been pulled") {
				t.Errorf("diff: %d\n%s", b.sb.code, diff)
			}
		})
	}
}

// A unit at another command menu version is unsupported, the walk stops
// before any page, and the reason says the version.
func TestPullWTIOtherVersionIsUnsupported(t *testing.T) {
	b := newPullBoxIn(t, filepath.Join(wtiFixtures, "fake", "lab-old"))
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
	out := b.run("device", "config", "pull", "pdu1")
	if b.sb.code != 1 || !strings.Contains(out, "failed: command menu version 7.4; tables are verified for 8.10") {
		t.Errorf("exit %d\n%s", b.sb.code, out)
	}
	if rec, ok := b.records().Of("pdu1"); !ok || rec.Result != "unsupported" {
		t.Errorf("record %+v", rec)
	}
	for _, c := range b.srv.Commands() {
		if strings.HasPrefix(c, "/N") || strings.HasPrefix(c, "/SN") {
			t.Errorf("typed %q at an unsupported unit", c)
		}
	}
	if got := b.run("device", "config", "list", "--failed"); !strings.Contains(got, "pdu1") || !strings.Contains(got, "unsupported") {
		t.Errorf("list --failed:\n%s", got)
	}
}

// A user directory that cannot be read is a warning: the pull is ok, the
// breakglass section is n/a with its note, and nothing else changes.
func TestPullWTIUserDirectoryNotRead(t *testing.T) {
	b := newWTIBox(t, "administrator", 0)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
	// the scope renders an account, so the section is compared when the
	// directory is read
	b.sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	// the second connection of the read (the user directory's) is refused
	var dials atomic.Int32
	inner := deviceDialOverride
	deviceDialOverride = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if dials.Add(1) > 1 {
			return nil, errors.New("connection refused")
		}
		return inner(ctx, network, addr)
	}
	out := b.run("device", "config", "pull", "pdu1")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q %q", b.sb.code, out, b.sb.stderr())
	}
	if !strings.Contains(out, "warning: the user directory was not read, so the breakglass section is not compared") {
		t.Errorf("pull:\n%s", out)
	}
	rec, _ := b.records().Of("pdu1")
	if rec == nil || rec.Result != "ok" || rec.Unit == nil || rec.Unit.UsersRead {
		t.Fatalf("record %+v", rec)
	}
	if s := rec.Sections["breakglass"]; s.State != "n/a" {
		t.Errorf("breakglass %+v", s)
	}
	diff := b.run("device", "config", "diff", "pdu1")
	if !strings.Contains(diff, devconf.NoteWTIUsersNotRead) {
		t.Errorf("diff lacks the note:\n%s", diff)
	}
	if got := eventsOf(b, "save"); len(got) != 0 {
		t.Errorf("save events %q", got)
	}
	dials.Store(0)
	js := b.run("device", "config", "pull", "pdu1", "--json")
	if !strings.Contains(js, `"warning":"the user directory was not read`) || !strings.Contains(js, `"users_read":false`) {
		t.Errorf("json:\n%s", js)
	}
	noSecrets(t, "output", out+diff+js+b.storeText(), wtiSentinels...)
}

// A page the tables do not know is parse-failed, naming the page and its
// title only.
func TestPullWTIUnknownPageIsParseFailed(t *testing.T) {
	dir := wtiUnitDir(t, "administrator", "8.10", 0)
	if err := os.WriteFile(filepath.Join(dir, "odd.txt"), []byte("# ---\n28\n\nSOMETHING ELSE ENTIRELY\n\n1. A: "+wtiRWSecret+"\n\n"+
		"Enter: #<CR> to change,\n       <ESC> to return to previous menu ...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "menu"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("page /N > 28 = odd.txt\n")
	_ = f.Close()
	b := newPullBoxIn(t, dir)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
	out := b.run("device", "config", "pull", "pdu1")
	if b.sb.code != 1 || !strings.Contains(out, "failed: WTI unit, page /N > 28") || !strings.Contains(out, `SOMETHING ELSE ENTIRELY`) {
		t.Errorf("exit %d\n%s", b.sb.code, out)
	}
	if rec, _ := b.records().Of("pdu1"); rec == nil || rec.Result != "parse-failed" {
		t.Errorf("record %+v", rec)
	}
	noSecrets(t, "output", out+b.sb.stderr()+b.storeText(), wtiSentinels...)
	if got := b.srv.Saved(); len(got) != 0 {
		t.Errorf("saved %q after an aborted read", got)
	}
}

// A hold refuses a unit like any device, a read-only user is stopped by the
// gate as before, and a wrong password is auth-failed (not denied).
func TestPullWTIHoldGateAndPassword(t *testing.T) {
	b := newWTIBox(t, "administrator", 0)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"}, [3]string{"pdu2", "192.168.1.41", "wti"})
	if out := b.sb.hold(t, "pdu1", "console recovery", "pdu1"); b.sb.code != 0 {
		t.Fatalf("hold: %q %q", out, b.sb.stderr())
	}
	want := "break-glass is held on pdu1: the device does not authenticate your login until it is released (tacctl breakglass release pdu1)"
	b.run("device", "config", "pull", "pdu1")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), want) {
		t.Errorf("named pull of a held unit: %d %q", b.sb.code, b.sb.stderr())
	}
	out := b.run("device", "config", "pull", "--all")
	if !strings.Contains(out, "skipped pdu1: "+want) || !strings.Contains(out, "pdu2") || strings.Contains(out, "pdu1  ") {
		t.Errorf("batch:\n%s", out)
	}
	if got := b.run("device", "config", "pull", "--all", "--json"); !strings.Contains(got, `"break_glass_held":["pdu1"]`) {
		t.Errorf("json summary:\n%s", got)
	}
	// a read-only user is stopped by the gate
	b.sb.asUser("carol", "tac-readonly", "device", "config", "pull", "pdu2")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'tacctl device config' is not permitted for the readonly tier.") {
		t.Errorf("readonly: %d %q", b.sb.code, b.sb.stderr())
	}
	// a wrong password: rejected, not denied
	b.pw.pw = "not-the-password"
	b.pw.rejected, b.pw.accepted = 0, 0
	out = b.run("device", "config", "pull", "pdu2")
	if b.sb.code != 1 || !strings.Contains(out, "failed: authentication failed") || b.pw.rejected != 1 {
		t.Errorf("wrong password: %d rejected %d\n%s", b.sb.code, b.pw.rejected, out)
	}
	if rec, _ := b.records().Of("pdu2"); rec == nil || rec.Result != "auth-failed" {
		t.Errorf("record %+v", rec)
	}
}

// A unit's pull is a pull: after a good one, a denied one keeps the good
// sections (the diff still compares them) and says so.
func TestPullWTIFailedKeepsTheLastGoodPull(t *testing.T) {
	b := newWTIBox(t, "administrator", 0)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
	b.run("device", "config", "pull", "pdu1")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q", b.sb.code, b.sb.stderr())
	}
	good, _ := b.records().Of("pdu1")
	// the same unit now answers as a User: a new fake on the same address
	b.srv.Stop()
	srv := fakedev.New(wtiUnitDir(t, "user", "8.10", 0), fakedev.WithCredentials("alice", testPassword))
	t.Cleanup(srv.Stop)
	addr := srv.Addr()
	deviceDialOverride = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	b.srv = srv
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
	out := b.run("device", "config", "pull", "pdu1")
	if b.sb.code != 1 || !strings.Contains(out, "WTI level is User") {
		t.Fatalf("exit %d\n%s", b.sb.code, out)
	}
	rec, _ := b.records().Of("pdu1")
	if rec == nil || rec.Result != "denied" || !rec.Pulled.Equal(good.Pulled) || len(rec.Sections) != len(good.Sections) || rec.OS != "8.10" || rec.Release != "8.10" {
		t.Errorf("record after the denied pull %+v (good %+v)", rec, good)
	}
	diff := b.run("device", "config", "diff", "pdu1")
	if !strings.Contains(diff, "this is the last good pull") && !strings.Contains(diff, "the last pull ended denied") {
		t.Errorf("diff:\n%s", diff)
	}
	if !strings.Contains(diff, "  aaa") {
		t.Errorf("the last good pull is not compared:\n%s", diff)
	}
}

// A unit of a RADIUS scope is compared with the RADIUS page's rendering: the
// Data the render builds for a RADIUS scope (the backend's listener) is the
// same for a WTI unit as for the other vendors.
func TestPullWTIRadiusScope(t *testing.T) {
	b := newWTIBox(t, "administrator", 0)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
	b.sb.run("", []string{"scope", "vendor-attrs", "lab", "enable", "cisco,juniper,wti"})
	b.sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\nlisteners:\n  radius:\n    auth: {network: udp, address: \"10.0.0.77:1645\", role: auth}\n", 0o600)
	b.sb.run("", []string{"scope", "auth-method", "lab", "radius"})
	if b.sb.code != 0 {
		t.Fatalf("auth-method: %d %s", b.sb.code, b.sb.stderr())
	}
	out := b.run("device", "config", "pull", "pdu1", "--diff")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"- radius enable on", "- radius primary 10.0.0.77", "- radius port 1645"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "- tacacs") {
		t.Errorf("the TACACS+ page is rendered for a RADIUS scope:\n%s", out)
	}
	noSecrets(t, "output", out+b.storeText(), wtiSentinels...)
}

// The managed render prepares a unit as any device (one base per vendor and
// scope) and renders the sections the scope has statements for.
func TestManagedRenderOfAWTIUnit(t *testing.T) {
	b := newWTIBox(t, "administrator", 0)
	b.devices([3]string{"pdu1", "192.168.1.40", "wti"}, [3]string{"pdu2", "192.168.1.41", "wti"})
	inv := b.invoke()
	_, res, err := inv.deviceLoad()
	if err != nil {
		t.Fatal(err)
	}
	var entries []devreg.Entry
	for _, n := range []string{"pdu1", "pdu2"} {
		e, ok := res.Lookup(n, devreg.ScopeFilter{})
		if !ok {
			t.Fatalf("no %s", n)
		}
		entries = append(entries, e)
	}
	r := inv.newManagedRender(managedOptions{}, false)
	r.prepare(entries)
	if len(r.base) != 1 {
		t.Errorf("%d bases for one vendor and scope", len(r.base))
	}
	secs, err := r.Expected(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range secs {
		names = append(names, s.Name)
	}
	// a section the scope states nothing for is left out (here the scope
	// has no permit list, no SNMP settings and no break-glass account)
	if !slices.Equal(names, []string{"aaa"}) {
		t.Errorf("sections %q", names)
	}
	if !strings.Contains(flat(secs), "tacacs enable on") {
		t.Errorf("no TACACS+ page:\n%s", flat(secs))
	}
}
