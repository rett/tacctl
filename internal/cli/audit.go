package cli

// The central audit lines (docs/plans/0.2.17-plan.md D249-D251): every
// state-changing command writes
//
//	cmd start v=1 user=.. uid=.. origin=.. tier=.. tty=.. console=.. cmd=".." args=".."
//	cmd end   v=1 user=.. cmd=".." result=.. status=.. duration=.. snapshot=..
//
// (the writer appends sid=), and a refusal inside a verb writes
//
//	cmd DENY  v=1 user=.. uid=.. tier=.. cmd=".." args=".." reason=..
//
// A table (auditTable) classifies every command by the words the tier gate
// sees. A "read" command writes no line. An "action" command writes its start
// line in the dispatcher (prelude), after the gate and preflight. A "mixed"
// command is a read or a write by its later arguments: its start line is
// written by the first write choke point it reaches (Audit.Touch, called by
// the snapshot, the apply lock, deviceWrite, consoleWrite, the SNMP, staging
// and host-key writers ...), so a "mixed" command that only read writes
// nothing. The end line is written where the exit status is decided (runWith),
// for every command that wrote a start line.

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// auditClass says what a command does to the state.
type auditClass string

const (
	// classRead: no central line. The command lists, shows, checks, scans or
	// prints, or is the shell, which runs each line as its own sudo process.
	classRead auditClass = "read"
	// classAction: the command changes state or logs in somewhere every time
	// it runs.
	classAction auditClass = "action"
	// classMixed: a read or a write by its later arguments.
	classMixed auditClass = "mixed"
)

// auditEntry is one row of the class table.
type auditEntry struct {
	Class auditClass
	// Notice: the lines are written at auth.notice, the weight of the weighty
	// verbs (whole-state replacements, install, upgrade, uninstall, the tier
	// of a group, sudoers, the console's reach). NoticeWhen narrows it to some
	// arguments (the words after the command's own); NoticeNote says which, for
	// the manual page.
	Notice     bool
	NoticeWhen func(rest []string) bool
	NoticeNote string
	// Secret names the words after the command's own that are a secret on the
	// command line, by index into them (redacted in args=).
	Secret func(rest []string) []int
}

func read() auditEntry   { return auditEntry{Class: classRead} }
func action() auditEntry { return auditEntry{Class: classAction} }
func mixed() auditEntry  { return auditEntry{Class: classMixed} }

func (e auditEntry) weighty() auditEntry { e.Notice = true; return e }

// when is e with its notice weight limited to the command lines that
// satisfy pred; note says in words which.
func (e auditEntry) when(note string, pred func(rest []string) bool) auditEntry {
	e.Notice, e.NoticeWhen, e.NoticeNote = true, pred, note
	return e
}

// isNotice reports whether the lines of this command line are written at
// auth.notice.
func (e auditEntry) isNotice(rest []string) bool {
	if !e.Notice {
		return false
	}
	return e.NoticeWhen == nil || e.NoticeWhen(rest)
}

// secretAfterSet marks the words that follow a "set" at the second place
// ('scope secret <scope> set <value>').
func secretAfterSet(rest []string) []int {
	var out []int
	if len(rest) >= 3 && rest[1] == "set" {
		for i := 2; i < len(rest); i++ {
			out = append(out, i)
		}
	}
	return out
}

// secretAll marks every word ('hash <password>').
func secretAll(rest []string) []int {
	out := make([]int, len(rest))
	for i := range rest {
		out[i] = i
	}
	return out
}

// auditTable is the class table: the words the tier gate sees ("cmd sub", or
// "cmd" for the commands that are leaves of their own) and what each does.
// A command of the tree with no entry is treated as an action (the safe side)
// and audit_class_test.go fails until the row is added.
var auditTable = map[string]auditEntry{
	// Leaves of their own.
	"install":           action().weighty(),
	"upgrade":           action().weighty(),
	"uninstall":         action().weighty(),
	"rollback":          mixed().weighty(),
	"passwd":            action(),
	"status":            read(),
	"version":           read(),
	"hash":              withSecret(read(), secretAll),
	"shell":             read(),
	"ssh":               action(),
	"completion":        read(),
	"_askpass":          read(),
	"_completion-names": read(),
	"_console-policy":   read(),
	"_phase":            action(),

	"user list":    read(),
	"user show":    read(),
	"user add":     action(),
	"user remove":  action(),
	"user passwd":  action(),
	"user disable": action(),
	"user enable":  action(),
	"user rename":  action(),
	"user move":    action(),
	"user verify":  read(),
	"user scope":   mixed(),

	"group list":   read(),
	"group show":   read(),
	"group add":    action(),
	"group remove": action(),
	"group edit": action().when("the field is tier or priv-lvl", func(rest []string) bool {
		return len(rest) >= 2 && (rest[1] == "tier" || rest[1] == "priv-lvl")
	}),
	"group reset":        mixed(),
	"group preset":       mixed(),
	"group junos":        mixed(),
	"group commands":     mixed(),
	"group privilege":    mixed(),
	"scope list":         read(),
	"scope routing":      read(),
	"scope show":         read(),
	"scope add":          action(),
	"scope remove":       action(),
	"scope rename":       action(),
	"scope default":      mixed(),
	"scope lookup":       read(),
	"scope prefixes":     mixed(),
	"scope staging":      mixed(),
	"scope secret":       withSecret(mixed(), secretAfterSet),
	"scope protocols":    mixed(),
	"scope devices":      mixed(),
	"scope aaa-order":    mixed(),
	"scope exec-timeout": mixed(),
	"scope tacacs-group": mixed(),
	"scope radius-group": mixed(),
	"scope auth-method":  mixed(),
	"scope vendor-attrs": mixed(),
	"scope mgmt-acl":     mixed(),
	"scope breakglass":   mixed(),
	"scope block":        mixed(),
	"scope netconf":      mixed(),
	"scope snmp":         mixed(),

	"host list":           read(),
	"host show":           read(),
	"host check":          read(),
	"host enroll":         action(),
	"host sync":           action(),
	"host move":           action(),
	"host target":         mixed(),
	"host provisioner":    mixed(),
	"host rename":         action(),
	"host forget":         action(),
	"host unenroll":       action(),
	"host default-method": mixed(),

	"device list":          read(),
	"device show":          read(),
	"device notices":       read(),
	"device export":        read(),
	"device ssh-config":    read(),
	"device scan":          read(),
	"device discover":      read(),
	"device check":         read(),
	"device add":           action(),
	"device remove":        action(),
	"device rename":        action(),
	"device notice":        action(),
	"device ssh":           action(),
	"device onboard":       mixed(),
	"device collect":       mixed(),
	"device sync":          mixed(),
	"device address":       mixed(),
	"device hostname":      mixed(),
	"device vendor":        mixed(),
	"device port":          mixed(),
	"device description":   mixed(),
	"device location":      mixed(),
	"device legacy-ssh":    mixed(),
	"device config-syntax": mixed(),
	"device netconf":       mixed(),
	"device stale-days":    mixed(),
	"device import":        mixed(),
	"device hostkey":       mixed(),
	"device snmp":          mixed(),
	"device block":         mixed(),
	"device config":        mixed(),

	"config show":                read(),
	"config dump":                read(),
	"config defaults":            read(),
	"config get":                 read(),
	"config get-list":            read(),
	"config diff":                read(),
	"config juniper":             mixed(),
	"config wti":                 mixed(),
	"config allow":               mixed(),
	"config deny":                mixed(),
	"config mgmt-acl":            mixed(),
	"config bcrypt-cost":         mixed(),
	"config branch":              mixed(),
	"config cisco":               mixed(),
	"config devices":             mixed(),
	"config linux":               mixed(),
	"config listen":              mixed(),
	"config loglevel":            mixed(),
	"config metrics":             mixed(),
	"config password-age":        mixed(),
	"config password-min-length": mixed(),
	"config secret-min-length":   mixed(),
	"config render":              mixed(),
	"config restore":             action().weighty(),
	"config snmp":                mixed(),
	"config sudoers":             mixed().weighty(),
	"config validate":            mixed(),

	"console show":             read(),
	"console check":            read(),
	"console forget":           read(),
	"console install":          action(),
	"console remove":           action(),
	"console agent-forwarding": mixed(),
	"console forwarding":       mixed(),
	"console idle-timeout":     mixed(),
	"console password-cache":   mixed(),
	"console space-completion": mixed(),
	"console ssh-escape":       mixed(),
	"console system-shell":     mixed().weighty(),
	"console tiers":            mixed().weighty(),
	"console user":             mixed().weighty(),

	"log tail":       read(),
	"log search":     read(),
	"log failures":   read(),
	"log accounting": read(),
	"log clear":      action().weighty(),

	"backup list":    read(),
	"backup diff":    read(),
	"backup restore": action().weighty(),

	"store show":     read(),
	"store import":   mixed().weighty(),
	"store rollback": action().weighty(),

	"backend list":    read(),
	"backend status":  read(),
	"backend enable":  action(),
	"backend disable": action(),

	"breakglass list":    read(),
	"breakglass hold":    action(),
	"breakglass release": action(),
}

// withSecret is e with the words that are a secret on the command line.
func withSecret(e auditEntry, f func(rest []string) []int) auditEntry {
	e.Secret = f
	return e
}

// auditLookup finds the table row for the command at path (the words of the
// resolved command after 'tacctl'): the row of the first word when it is a
// leaf of its own, else of the first two. n is how many of the typed words
// the row's key spans.
func auditLookup(path []string) (key string, n int, e auditEntry, ok bool) {
	if len(path) == 0 {
		return "", 0, auditEntry{}, false
	}
	if e, ok := auditTable[path[0]]; ok {
		return path[0], 1, e, true
	}
	if len(path) >= 2 {
		k := path[0] + " " + path[1]
		if e, ok := auditTable[k]; ok {
			return k, 2, e, true
		}
	}
	return "", 0, auditEntry{}, false
}

// commandKeys are the keys the command tree needs a row for: for each
// command, the first word when it has no sub-commands (a leaf of its own), or
// its first two words. It is what audit_class_test.go walks.
func commandKeys(root *cobra.Command) []string {
	var keys []string
	seen := map[string]bool{}
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	var walk func(c *cobra.Command, path []string)
	walk = func(c *cobra.Command, path []string) {
		for _, sub := range c.Commands() {
			p := append(slices.Clone(path), sub.Name())
			switch {
			case len(p) == 1 && len(sub.Commands()) == 0:
				add(p[0])
			case len(p) == 1:
				// A family: a row for each of its words.
			case len(p) == 2:
				add(p[0] + " " + p[1])
			}
			walk(sub, p)
		}
	}
	walk(root, nil)
	return keys
}

// auditRun is what one invocation knows of its own central lines.
type auditRun struct {
	// key and words are the table row and the typed words it spans ('user
	// add'); rest are the arguments after them.
	key   string
	words []string
	rest  []string
	// path is the resolved command, for the flags' Secret marks.
	path  []string
	entry auditEntry
	class auditClass
	// known is false for a command with no row (an action, the safe side).
	known bool
	begin time.Time
	// denied: the DENY line was written. ended: an end line was written (at
	// most one is: the first stays).
	denied, ended bool
}

// callerTierName is the tier the gate held the caller to.
func (inv *invocation) callerTierName() string {
	if inv.callerTier == "" {
		return string(tier.None)
	}
	return string(inv.callerTier)
}

// auditPanics makes a command classified read that reaches a write choke
// point panic instead of only writing class=unexpected. The Go tests and a
// -tags testknobs binary set it.
var auditPanics = false

// auditBegin classifies the command and registers the writer's start line
// (prelude, after the gate and preflight). An action writes it now.
func (inv *invocation) auditBegin() {
	if inv.ar != nil {
		return
	}
	a := inv.app
	w := a.Audit()
	path := inv.commandPath()
	ar := &auditRun{path: path}
	inv.ar = ar
	key, _, entry, ok := auditLookup(path)
	switch {
	case ok:
		ar.key, ar.entry, ar.known = key, entry, true
		ar.class = entry.Class
	case inv.isFamilyOrRoot(path):
		// A family word with no sub-command, or a word that is no command:
		// the usage, which changes nothing.
		ar.class = classRead
		ar.key = strings.Join(path[:min(len(path), 2)], " ")
	default:
		// A command with no row is an action (the safe side).
		ar.class = classAction
		ar.key = strings.Join(path[:min(len(path), 2)], " ")
	}
	ar.words = strings.Fields(ar.key)
	if n := len(ar.words); n <= len(a.Args) {
		ar.rest = a.Args[n:]
	}
	tty, marker := inv.hooks.line(), ""
	if m := a.Env.Get(console.EnvMarker); m != "" {
		// The variable comes through sudo from the caller: only a session id
		// as the console makes them is written.
		if marker = console.MarkerValue(m); marker == "?" {
			marker = "invalid"
		}
	}
	w.SetTerminal(tty, marker)
	w.SetStart(inv.auditStart)
	if ar.class == classAction {
		w.Touch()
	}
}

// commandPath is the words of the command a.Args resolve to in the tree.
func (inv *invocation) commandPath() []string {
	root := inv.root
	if root == nil {
		root = newRoot(inv)
	}
	cmd, _ := resolve(root, inv.app.Args)
	return strings.Fields(strings.TrimPrefix(cmd.CommandPath(), root.Name()))
}

// isFamilyOrRoot: the path is empty (no word is a command) or ends at a word
// that has sub-commands (no sub-command typed): the usage.
func (inv *invocation) isFamilyOrRoot(path []string) bool {
	if len(path) == 0 {
		return true
	}
	root := inv.root
	if root == nil {
		root = newRoot(inv)
	}
	cmd, _ := resolve(root, inv.app.Args)
	return len(cmd.Commands()) > 0
}

// auditNotice reports whether the running command's lines are written at
// auth.notice.
func (inv *invocation) auditNotice() bool {
	return inv.ar != nil && inv.ar.entry.isNotice(inv.ar.rest)
}

func (inv *invocation) auditPriority() string {
	if inv.auditNotice() {
		return audit.Notice
	}
	return audit.Info
}

// auditStart writes the start line (the writer calls it once, from Touch).
func (inv *invocation) auditStart() {
	ar := inv.ar
	if ar == nil {
		return
	}
	a := inv.app
	w := a.Audit()
	ar.begin = a.Knobs.Now()
	act := w.Actor()
	kv := []audit.KV{
		audit.Pair("v", "1"),
		audit.Pair("user", act.User), audit.Pair("uid", act.UID), audit.Pair("origin", act.Origin),
		audit.Pair("tier", inv.callerTierName()),
		audit.Pair("tty", act.TTY), audit.Pair("console", act.Console),
		audit.Pair("cmd", strings.Join(ar.words, " ")),
		audit.Wide("args", inv.auditArgs()),
	}
	prio := inv.auditPriority()
	if ar.class == classRead {
		// A read command reached a write: a classification bug. The line is
		// written all the same; the tests find it.
		kv = append(kv, audit.Pair("class", "unexpected"))
		prio = audit.Warning
	}
	w.Line(prio, "cmd start", kv...)
	if ar.class == classRead && auditPanics {
		panic("audit: '" + ar.key + "' is classified read and reached a write (internal/cli/audit.go)")
	}
}

// redacted is what a secret is written as.
const redacted = "<redacted>"

// auditArgs is the command line after the words of cmd=: each word as the
// writer quotes and caps it, the secrets replaced by <redacted>.
func (inv *invocation) auditArgs() string {
	ar := inv.ar
	rest := ar.rest
	hide := map[int]bool{}
	if ar.entry.Secret != nil {
		for _, i := range ar.entry.Secret(rest) {
			hide[i] = true
		}
	}
	flags := secretFlags(ar.path)
	var out []string
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		switch {
		case hide[i]:
			out = append(out, redacted)
		case flags[w]:
			out = append(out, audit.Value(w))
			if i+1 < len(rest) {
				i++
				out = append(out, redacted)
			}
		default:
			if name, _, ok := strings.Cut(w, "="); ok && flags[name] {
				out = append(out, audit.Value(name)+"="+redacted)
				continue
			}
			out = append(out, audit.Value(w))
		}
	}
	return strings.Join(out, " ")
}

// secretFlags are the spellings of the flags of the command at path whose
// value is a secret (Flag.Secret).
func secretFlags(path []string) map[string]bool {
	if len(path) == 0 {
		return nil
	}
	spec, ok := specFor(path)
	if !ok {
		return nil
	}
	m := map[string]bool{}
	for _, f := range spec.Flags {
		if f.Secret {
			for _, n := range f.Names {
				m[n] = true
			}
		}
	}
	return m
}

// Reasons of a denial inside a verb (deniedError.Reason).
const (
	// reasonSuperuser: the verb is the superuser's.
	reasonSuperuser = "superuser"
	// reasonScope: the caller named something outside their own scopes.
	reasonScope = "scope"
)

// deniedError is a refusal inside a verb: the caller's tier passed the gate,
// but the verb is not theirs (or the thing named is not in their scopes).
// It unwraps to what the site returned before, so every message and exit
// status is as it was; the dispatcher writes the cmd DENY line for it.
type deniedError struct {
	Reason string
	Err    error
}

func (e *deniedError) Error() string { return e.Err.Error() }
func (e *deniedError) Unwrap() error { return e.Err }

// denied marks err, a refusal the site has printed and is about to return,
// as the typed denial with reason. The DENY line names the command from the
// dispatcher's own record of it.
func (inv *invocation) denied(reason string, err error) error {
	return &deniedError{Reason: reason, Err: err}
}

// deniedUsage prints msgs as usageErr does and returns the exit as a denial.
func (inv *invocation) deniedUsage(reason string, msgs ...string) error {
	return inv.denied(reason, inv.usageErr(msgs...))
}

// auditEnd writes the DENY line for a typed denial and the end line for a
// command that wrote its start line. err is the command's error; aborted
// says the command panicked.
func (inv *invocation) auditEnd(err error, aborted bool) {
	ar := inv.ar
	if ar == nil {
		return
	}
	a := inv.app
	w := a.Audit()
	status := exitStatus(err)
	var de *deniedError
	isDenied := errors.As(err, &de)
	if isDenied && !ar.denied && !aborted {
		ar.denied = true
		act := w.Actor()
		w.Line(audit.Warning, "cmd DENY",
			audit.Pair("v", "1"), audit.Pair("user", act.User), audit.Pair("uid", act.UID),
			audit.Pair("tier", inv.callerTierName()),
			audit.Pair("cmd", strings.Join(ar.words, " ")), audit.Wide("args", inv.auditArgs()),
			audit.Pair("reason", de.Reason))
	}
	if !w.Touched() || ar.ended {
		return
	}
	ar.ended = true
	result := "ok"
	switch {
	case aborted:
		result, status = "aborted", 2
	case isDenied || errors.Is(err, tier.ErrDenied):
		result = "denied"
	case status == 130:
		result = "interrupted"
	case status != 0:
		result = "failed"
	}
	prio := audit.Warning
	if result == "ok" {
		prio = inv.auditPriority()
	}
	snap := strings.Join(w.Snapshots(), ",")
	w.Line(prio, "cmd end",
		audit.Pair("v", "1"), audit.Pair("user", w.Actor().User),
		audit.Pair("cmd", strings.Join(ar.words, " ")),
		audit.Pair("result", result), audit.Pair("status", strconv.Itoa(status)),
		audit.Pair("duration", auditDuration(a.Knobs.Now().Sub(ar.begin))),
		audit.Pair("snapshot", snap))
}

// auditDuration is d in seconds with millisecond precision ('0.312s').
func auditDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return fmt.Sprintf("%d.%03ds", int(d/time.Second), int(d%time.Second/time.Millisecond))
}

// exitStatus is the exit status exitCode would give err, with nothing
// printed.
func exitStatus(err error) int {
	return exitCode(err, ui.Output{Stdout: discard{}, Stderr: discard{}})
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// auditFinish is runWith's deferred end of the command: the end line, also
// when the command panicked (status 2, result=aborted; the panic goes on).
func (inv *invocation) auditFinish(errp *error) {
	if r := recover(); r != nil {
		inv.auditEnd(nil, true)
		panic(r)
	}
	inv.auditEnd(*errp, false)
}
