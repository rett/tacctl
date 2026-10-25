package cli

// The progress view of a batch pull (D67): one line per device, rewritten
// in place on a terminal and appended otherwise, or one JSON object per
// device with --json. The batch runner calls it from one goroutine only; the
// workers never write anywhere.

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/ui"
)

// realTerminalWriter reports whether w is a terminal (hooks.isTerminalWriter
// replaces it in tests); a stream with its colour taken out (app.New) is the
// terminal it wraps.
func realTerminalWriter(w io.Writer) bool {
	f, ok := ui.File(w)
	return ok && term.IsTerminal(int(f.Fd()))
}

// terminalHeight is the rows of the terminal w is (0 when unknown).
var terminalHeight = func(w io.Writer) int {
	f, ok := ui.File(w)
	if !ok {
		return 0
	}
	_, h, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return 0
	}
	return h
}

// pullView is the batch.View of a pull.
type pullView struct {
	batch.Board
	inv   *invocation
	out   io.Writer
	user  string
	json  bool
	quiet bool
	// tty: the rows are rewritten in place.
	tty     bool
	names   []string
	scopes  []string
	vendors []string
	width   int
	drawn   int
	// audit logs the audit line of each device (false for 'diff --pull',
	// which is a pull all the same: it logs).
	audit bool
	// jsonMode lines.
	enc *json.Encoder
	// phase is the "phase" of each JSON object ("" none): "pull" for the
	// pull that 'device config apply --pull' makes first (0.2.17 D268).
	phase string
}

// newPullView is the view of a pull of entries. quiet leaves the progress
// out (a diff that pulls first prints its own result); the audit lines are
// still written.
func (inv *invocation) newPullView(entries []devreg.Entry, asJSON bool, user string, quiet bool) *pullView {
	v := &pullView{inv: inv, out: inv.app.Out.Stdout, user: user, json: asJSON, quiet: quiet, audit: true}
	for _, e := range entries {
		v.names = append(v.names, e.Name)
		v.scopes = append(v.scopes, e.Scope)
		v.vendors = append(v.vendors, e.Vendor)
		v.width = max(v.width, len(e.Name))
	}
	v.tty = !asJSON && !quiet && inv.hooks.terminalWriter(v.out)
	if v.tty {
		// More rows than the terminal has cannot be repainted: append.
		if h := terminalHeight(v.out); h > 0 && len(entries)+4 > h {
			v.tty = false
		}
	}
	v.enc = json.NewEncoder(v.out)
	return v
}

// rowText is the line of one device: the runner's words, with the
// transport a successful pull used and why NETCONF was not.
func (v *pullView) rowText(i int) string {
	r := v.Row(i)
	text := r.Text
	if o, ok := r.Result.Value.(*pullOutcome); ok && r.Settled && o != nil {
		switch {
		case r.Result.Status == batch.StatusOK && o.Transport != "":
			text += " via " + o.Transport
			if o.Fallback != "" {
				text += " (" + o.Fallback + ")"
			}
		case r.Result.Status != batch.StatusOK && o.Fallback != "" && o.Reason == "":
			text += " (" + o.Fallback + ")"
		}
		// A WTI unit: who else is logged in (a count; no name is kept) and a
		// pull that did less than asked.
		if o.Unit != nil && r.Result.Status == batch.StatusOK {
			if n := o.Unit.OtherSessions; n > 0 {
				text += "; " + sessionsText(n)
			}
			if o.Warning != "" {
				text += "; warning: " + o.Warning
			}
		}
		// A setting the device's own version line contradicts (D113: the
		// setting wins; modern on a 12.x image is the lock-out direction).
		if o.ImageSyntax != "" && r.Result.Status == batch.StatusOK {
			text += "; warning: ios-syntax is " + o.Syntax + " but the device says " + imageText(o.OS) +
				" (" + o.ImageSyntax + " syntax)"
		}
	}
	return cleanLine(text)
}

// sessionsText is the count of the other sessions on a WTI unit in words.
func sessionsText(n int) string {
	if n == 1 {
		return "1 other session on the unit"
	}
	return strconv.Itoa(n) + " other sessions on the unit"
}

// cleanLine makes device-controlled text safe for a terminal: control
// characters become '?'.
func cleanLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}

func (v *pullView) line(i int) string {
	return fmt.Sprintf("  %-*s  %s", v.width, v.names[i], v.rowText(i))
}

// Begin queues every device.
func (v *pullView) Begin(names []string) {
	v.Board.Begin(names)
	if v.json || v.quiet {
		return
	}
	if v.tty {
		_, _ = fmt.Fprintln(v.out)
		v.paint()
	}
}

// paint draws every row, over the rows drawn before.
func (v *pullView) paint() {
	if v.drawn > 0 {
		_, _ = fmt.Fprintf(v.out, "\x1b[%dA", v.drawn)
	}
	for i := range v.names {
		_, _ = fmt.Fprintf(v.out, "\r\x1b[2K%s\n", v.line(i))
	}
	v.drawn = len(v.names)
}

// Update applies one event, logs the audit line of a finished device and
// shows it.
func (v *pullView) Update(e batch.Event) {
	v.Board.Update(e)
	if e.Phase == batch.PhaseRunning {
		if v.tty {
			v.paint()
		}
		return
	}
	if o, ok := e.Result.Value.(*pullOutcome); ok && o != nil && v.audit && e.Phase == batch.PhaseDone {
		v.inv.app.Audit().Raw("auth.info", pullAuditLine(v.user, o, e.Result))
	}
	switch {
	case v.quiet:
	case v.json:
		_ = v.enc.Encode(v.deviceJSON(e.Index, false))
	case v.tty:
		v.paint()
	default:
		_, _ = fmt.Fprintln(v.out, v.line(e.Index))
	}
}

// End leaves the rows as they are; the verb prints the summary.
func (v *pullView) End(s batch.Summary) { v.Board.End(s) }

// pullSectionJSON is one section of a device's pull in --json. Unmanaged
// counts the device's own statements among the extras: a section that is ok
// with them stays "ok".
type pullSectionJSON struct {
	Name      string         `json:"name"`
	State     string         `json:"state"`
	Unmanaged int            `json:"unmanaged,omitempty"`
	Lines     []diffLineJSON `json:"lines,omitempty"`
	Notes     []string       `json:"notes,omitempty"`
}

// diffLineJSON is a statement of a comparison (never a secret's value).
type diffLineJSON struct {
	Op     string `json:"op"`
	Text   string `json:"text"`
	Secret bool   `json:"secret,omitempty"`
}

func diffLinesJSON(ls []devconf.DiffLine) []diffLineJSON {
	var out []diffLineJSON
	for _, l := range ls {
		out = append(out, diffLineJSON{Op: string(l.Op), Text: l.Text, Secret: l.Secret})
	}
	return out
}

// pullJSON is one device of a pull in --json: a line per device.
type pullJSON struct {
	Name   string `json:"name"`
	Scope  string `json:"scope"`
	Vendor string `json:"vendor"`
	// Phase is "pull" in the output of 'device config apply --pull'.
	Phase     string `json:"phase,omitempty"`
	Status    string `json:"status"`
	Result    string `json:"result,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Transport string `json:"transport,omitempty"`
	Netconf   string `json:"netconf,omitempty"`
	Fallback  string `json:"fallback,omitempty"`
	// Syntax is the Cisco configuration syntax the device was compared in
	// (D113) and OS the version line it answered. SyntaxConflict is set when
	// the explicit setting is not the syntax that line derives to (the
	// setting wins), ImageSyntax then being what the line says.
	Syntax         string `json:"syntax,omitempty"`
	OS             string `json:"os,omitempty"`
	SyntaxConflict bool   `json:"syntax_conflict,omitempty"`
	ImageSyntax    string `json:"image_syntax,omitempty"`
	// Unit is what a WTI unit's read saw beside its pages; Warning a pull
	// that is ok but did less than asked.
	Unit       *pullUnitJSON     `json:"unit,omitempty"`
	Warning    string            `json:"warning,omitempty"`
	DurationMS int64             `json:"duration_ms"`
	DiffersIn  []string          `json:"differs_in,omitempty"`
	Secrets    *bool             `json:"secrets_visible,omitempty"`
	Sections   []pullSectionJSON `json:"sections,omitempty"`
}

// pullUnitJSON is the facts of a WTI unit's read in --json: the command
// menu's version and the login's access level, the unit's Site ID, how many
// other sessions it had (no name), and whether its user directory was read.
type pullUnitJSON struct {
	Version       string `json:"version"`
	Level         string `json:"level,omitempty"`
	SiteID        string `json:"site_id,omitempty"`
	OtherSessions int    `json:"other_sessions"`
	UsersRead     bool   `json:"users_read"`
}

func (v *pullView) deviceJSON(i int, withLines bool) pullJSON {
	r := v.Row(i)
	j := pullJSON{Name: v.names[i], Scope: v.scopes[i], Vendor: v.vendors[i], Phase: v.phase, Status: r.Result.Status.String()}
	if r.Result.Status == batch.StatusNotStarted {
		j.Reason = r.Result.Reason
	}
	o, ok := r.Result.Value.(*pullOutcome)
	if !ok || o == nil {
		return j
	}
	j.Result, j.Transport, j.Fallback = o.Result, o.Transport, o.Fallback
	if o.Netconf != netconfNotProbed {
		j.Netconf = o.Netconf
	}
	j.DurationMS = o.Duration.Milliseconds()
	j.Reason = cleanLine(o.Reason)
	j.Syntax, j.OS = o.Syntax, cleanLine(o.OS)
	j.SyntaxConflict, j.ImageSyntax = o.ImageSyntax != "", o.ImageSyntax
	if r.Result.Status == batch.StatusOK {
		if u := o.Unit; u != nil {
			j.Unit = &pullUnitJSON{Version: cleanLine(u.Version), Level: u.Level, SiteID: cleanLine(u.SiteID),
				OtherSessions: u.OtherSessions, UsersRead: u.UsersRead}
			j.Warning = cleanLine(o.Warning)
		}
		j.DiffersIn = r.Result.Differs
		sv := o.SecretsVisible
		j.Secrets = &sv
		for _, s := range o.Sections {
			sj := pullSectionJSON{Name: s.Name, State: string(s.State), Unmanaged: s.Unmanaged}
			if withLines || s.State == devconf.StateDiffers || s.State == devconf.StateMissing {
				sj.Lines, sj.Notes = diffLinesJSON(s.Lines), s.Notes
			}
			j.Sections = append(j.Sections, sj)
		}
	}
	return j
}

// printSummaryJSON is the last line of a --json pull.
func (v *pullView) printSummaryJSON(s batch.Summary, c *chosenDevices, code int) {
	stop := ""
	switch {
	case s.Interrupted:
		stop = "interrupted"
	case s.Stop == batch.StopMaxFailures:
		stop = "max-failures"
	case s.Stop == batch.StopAuthFailure:
		stop = "auth-failed"
	}
	sum := map[string]any{"ok": s.OK - s.Differ, "differ": s.Differ, "failed": s.Failed, "not_started": s.NotStarted,
		"pool": s.Pool, "exit": code}
	if stop != "" {
		sum["stop"] = stop
	}
	if c != nil && c.skipped.any() {
		sum["skipped"] = c.skipped.jsonMap()
	}
	_ = v.enc.Encode(map[string]any{"summary": sum})
}
