package fakedev

// The NETCONF side of the configure model (docs/plans/0.2.10-plan.md D151).
// A NETCONF session is a jsession of the same device as the command line's:
// one committed configuration, one shared candidate, one history, one
// exclusive lock and one pending confirmed commit. What differs is the way
// in (the RPCs below) and one rule of the device: a confirmed commit that
// the session which made it closes without confirming is rolled back at
// once (0.2.4 spike (d)); the window's timer is only the backstop for a
// host that vanished.
//
// The RPCs, each over the model only when the transcript has no canned
// 'rpc.<element>.xml' for it:
//
//	open-configuration      <private/> | nothing (shared); an <exclusive/>
//	                        child is a syntax error as on the device; success
//	                        is an EMPTY reply [C: plan N1]
//	lock-configuration      the exclusive analogue: the candidate's lock,
//	unlock-configuration    an empty reply on success [C: plan N1]
//	close-configuration     leaves the mode; a private candidate is dropped
//	load-configuration      action="set" with <configuration-set> (text):
//	                        statement by statement, not atomic
//	get-configuration       database="committed|candidate", format="set|
//	                        text", compare="rollback" rollback="N", and a
//	                        <configuration> filter of one path
//	commit-configuration    <check/>, <confirmed/>, <confirm-timeout> (in
//	                        seconds, as the lab switch reads it), <log>
//	                        (also named <commit>)
//	discard-changes         the candidate goes back to the committed
//	lock, unlock            <target><candidate/></target>
//	get-commit-information  the history, newest first
//	command                 an operational command of the CLI model, when the
//	                        transcript has no file for it
//
// The knobs of junos_config.go act on this channel as on the command line
// (load.errors, version-gate, check.errors, exclusive.held-by, verify.fail,
// commit.drop, drop, slow, timer.minute); one more is NETCONF's own:
//
//	netconf.private.confirm   a confirmed commit in a private session is
//	                          refused, as the lab switch does [C: plan N1:
//	                          '"commit confirmed" is not supported for
//	                          private configuration'], unless the knob says
//	                          'accept' (a device that allows it: a transport
//	                          tests both)
//
// 'persist' and 'persist-id' are not modelled: the RPC is refused as not
// supported.

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// xnode is an element of a request, whatever it holds.
type xnode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Text    string     `xml:",chardata"`
	Kids    []xnode    `xml:",any"`
}

func (n xnode) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n xnode) kid(name string) (xnode, bool) {
	for _, k := range n.Kids {
		if k.XMLName.Local == name {
			return k, true
		}
	}
	return xnode{}, false
}

func (n xnode) has(name string) bool { _, ok := n.kid(name); return ok }

// nsession is one NETCONF session of the model.
type nsession struct {
	d    *junosDevice
	sess *jsession
	// drop closes the connection (the 'commit.drop' and 'drop' knobs).
	drop func()
}

// newNetconfSession is the model's session for a NETCONF login, or nil when
// the model is off.
func (s *Server) newNetconfSession(user string, drop func()) *nsession {
	d := s.junos()
	if d == nil {
		return nil
	}
	return &nsession{d: d, sess: d.newSession(user), drop: drop}
}

// end is the session's end, clean or not: a confirmed commit it made and did
// not confirm is rolled back at once, the exclusive lock goes, and a private
// candidate with it. It is safe to call twice and on nil.
func (ns *nsession) end() {
	if ns == nil {
		return
	}
	d := ns.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if p := d.pending; p != nil && p.owner == ns.sess {
		p.timer.Stop()
		d.pending = nil
		d.committed = p.before.clone()
		d.record(jtExpiryUser, jtExpiryVia, "", 0)
	}
	d.leave(ns.sess)
	delete(d.sessions, ns.sess)
}

// --- the replies' pieces -------------------------------------------------------------------------

// nsError is one <rpc-error>.
func nsError(sev, tag, msg, path, bad string) string {
	var b strings.Builder
	b.WriteString("<rpc-error><error-type>protocol</error-type><error-tag>" + tag + "</error-tag>" +
		"<error-severity>" + sev + "</error-severity>")
	if path != "" {
		b.WriteString("<error-path>" + esc(path) + "</error-path>")
	}
	b.WriteString("<error-message>" + esc(msg) + "</error-message>")
	if bad != "" {
		b.WriteString("<error-info><bad-element>" + esc(bad) + "</bad-element></error-info>")
	}
	b.WriteString("</rpc-error>")
	return b.String()
}

// plainMsg is the one-line message of a CLI text: the caret line and a
// trailing full stop dropped.
func plainMsg(text string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l == strings.TrimSpace(jtCaret) {
			continue
		}
		l = strings.TrimPrefix(l, "error: ")
		l = strings.TrimPrefix(l, "warning: ")
		out = append(out, strings.TrimSuffix(l, "."))
	}
	return strings.Join(out, " ")
}

// lockDenied is the refusal while another session holds the lock.
func (d *junosDevice) lockDenied(holder string) string {
	return nsError("error", "lock-denied", "configuration database locked by: "+holder, "", "")
}

// --- the RPCs --------------------------------------------------------------------------------

// configRPC answers one of the configuration RPCs; ok is false for an
// element that is not one. drop is a dropNone, dropSilent or dropAfterOutput
// for the connection.
func (ns *nsession) configRPC(op xnode) (body string, drop int, ok bool) {
	switch op.XMLName.Local {
	case "open-configuration":
		return ns.open(op), dropNone, true
	case "close-configuration":
		return ns.closeConfig(), dropNone, true
	case "load-configuration":
		return ns.load(op), dropNone, true
	case "commit-configuration", "commit":
		body, drop = ns.commit(op)
		return body, drop, true
	case "discard-changes":
		return ns.discard(), dropNone, true
	case "lock":
		return ns.lock(op), dropNone, true
	case "unlock":
		return ns.unlock(), dropNone, true
	case "lock-configuration":
		return emptyOK(ns.lockConfiguration()), dropNone, true
	case "unlock-configuration":
		return emptyOK(ns.unlock()), dropNone, true
	case "get-commit-information":
		return ns.commitInformation(), dropNone, true
	}
	return "", dropNone, false
}

func (ns *nsession) open(op xnode) string {
	d, sess := ns.d, ns.sess
	mode := ""
	for _, k := range op.Kids {
		switch k.XMLName.Local {
		case "private":
			mode = k.XMLName.Local
		case "exclusive":
			return nsError("error", "operation-failed", jtNetconfNoExclusive, "", "exclusive")
		default:
			return nsError("error", "operation-not-supported", "open-configuration <"+k.XMLName.Local+"> is not supported", "", "")
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !mayConfigure(sess.class) {
		return nsError("error", "access-denied", "permission denied", "", "")
	}
	if sess.configure {
		return nsError("error", "operation-failed", "configuration database already open", "", "")
	}
	switch st, h := d.enterMode(sess, mode); st {
	case enterLocked:
		return d.lockDenied(h)
	case enterModified:
		return nsError("error", "operation-failed", plainMsg(jtModified), "", "")
	case enterPrivateHeld:
		return nsError("warning", "operation-failed", plainMsg(jtPrivateUnderExcl), "", "")
	}
	// the device answers an open with an empty reply [C: plan N1]
	return ""
}

func (ns *nsession) closeConfig() string {
	d := ns.d
	d.mu.Lock()
	defer d.mu.Unlock()
	d.leave(ns.sess)
	return "<ok/>"
}

// implicit puts a session that never opened the configuration to the shared
// candidate, as a device does for a load.
func (ns *nsession) implicit() {
	ns.sess.configure = true
}

func (ns *nsession) load(op xnode) string {
	d, sess := ns.d, ns.sess
	if a := op.attr("action"); a != "set" {
		return nsError("error", "operation-not-supported", "load-configuration action '"+a+"' is not supported", "", "")
	}
	set, ok := op.kid("configuration-set")
	if !ok {
		return nsError("error", "operation-not-supported", "load-configuration takes <configuration-set>", "", "")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !mayConfigure(sess.class) {
		return nsError("error", "access-denied", "permission denied", "", "")
	}
	if t := d.blocked(sess, true); t != "" {
		return d.lockDenied(d.holder())
	}
	if !sess.configure {
		ns.implicit()
	}
	var errs strings.Builder
	for _, line := range strings.Split(set.Text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words := jsplit(line)
		verb, rest := words[0], words[1:]
		if (verb != "set" && verb != "delete" && verb != "insert") || len(rest) == 0 {
			errs.WriteString(nsError("error", "operation-failed", "syntax error", "[edit]", words[len(words)-1]))
			continue
		}
		kind, msg := d.editStatement(sess, verb, rest)
		switch kind {
		case editRefused:
			errs.WriteString(nsError("error", "operation-failed", plainMsg(msg), "[edit]", rest[len(rest)-1]))
		case editNotFound:
			errs.WriteString(nsError("warning", "operation-failed", plainMsg(jtStatementNotFound), "[edit]", ""))
		case editBad:
			errs.WriteString(nsError("error", "operation-failed", msg, "[edit]", rest[len(rest)-1]))
		}
	}
	return "<load-configuration-results>" + errs.String() + "<ok/></load-configuration-results>"
}

func (ns *nsession) commit(op xnode) (string, int) {
	d, sess := ns.d, ns.sess
	check, confirmed, seconds, comment := false, false, 600, ""
	for _, k := range op.Kids {
		switch k.XMLName.Local {
		case "check":
			check = true
		case "confirmed":
			confirmed = true
		case "confirm-timeout":
			n, err := strconv.Atoi(strings.TrimSpace(k.Text))
			if err != nil || n < 1 || n > 65535*60 {
				return nsError("error", "invalid-value", plainMsg(jtBadConfirmed), "", "confirm-timeout"), dropNone
			}
			// seconds, as the lab switch reads it (180 is 'rollback in
			// 3mins'; its reference says minutes)
			seconds = n
		case "log":
			comment = strings.TrimSpace(k.Text)
		case "synchronize", "force", "full":
		default:
			return nsError("error", "operation-not-supported", "commit <"+k.XMLName.Local+"> is not supported", "", k.XMLName.Local), dropNone
		}
	}
	if confirmed && check {
		return nsError("error", "operation-failed", "commit <check/> and <confirmed/> do not go together", "", ""), dropNone
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !mayConfigure(sess.class) {
		return nsError("error", "access-denied", "permission denied", "", ""), dropNone
	}
	if t := d.blocked(sess, false); t != "" {
		return d.lockDenied(d.holder()), dropNone
	}
	if confirmed && sess.private {
		if w, _ := d.knobWord("netconf.private.confirm"); w != "accept" {
			return nsError("error", "operation-failed", jtNetconfNoConfirmedPrivate, "", ""), dropNone
		}
	}
	o := d.commitApply(sess, check, confirmed, time.Duration(seconds)*d.minute()/60, seconds/60, comment, jtNetconfVia, sess)
	if len(o.fails) > 0 {
		var b strings.Builder
		for _, f := range o.fails {
			b.WriteString(nsError("error", "operation-failed", plainMsg(f), "[edit]", ""))
		}
		return b.String(), dropNone
	}
	if op.XMLName.Local == "commit" {
		return "<ok/>", d.commitDrop(confirmed && !check)
	}
	mark := "<commit-success/>"
	if check {
		mark = "<commit-check-success/>"
	}
	return "<commit-results><routing-engine><name>re0</name>" + mark + "</routing-engine></commit-results>",
		d.commitDrop(confirmed && !check)
}

func (ns *nsession) discard() string {
	d := ns.d
	d.mu.Lock()
	defer d.mu.Unlock()
	if t := d.blocked(ns.sess, true); t != "" {
		return d.lockDenied(d.holder())
	}
	d.cfgRollback(ns.sess, nil)
	return "<ok/>"
}

// emptyOK is the device's answer to a control RPC that succeeded: an empty
// reply, where the model's own helpers say <ok/> [C: plan N1].
func emptyOK(body string) string {
	if body == "<ok/>" {
		return ""
	}
	return body
}

func (ns *nsession) lock(op xnode) string {
	if t, ok := op.kid("target"); !ok || !t.has("candidate") {
		return nsError("error", "operation-not-supported", "lock takes <target><candidate/></target>", "", "")
	}
	return ns.lockConfiguration()
}

// lockConfiguration is the candidate's lock, whichever RPC asked for it.
func (ns *nsession) lockConfiguration() string {
	d, sess := ns.d, ns.sess
	d.mu.Lock()
	defer d.mu.Unlock()
	if h := d.holder(); h != "" && d.excl != sess {
		return d.lockDenied(h)
	}
	if d.excl != sess {
		if d.modified() {
			return nsError("error", "operation-failed", plainMsg(jtModified), "", "")
		}
		d.shared = nil
		d.excl = sess
		sess.exclusive = true
	}
	return "<ok/>"
}

func (ns *nsession) unlock() string {
	d, sess := ns.d, ns.sess
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.excl != sess {
		return nsError("error", "operation-failed", "the lock is not held by this session", "", "")
	}
	d.excl = nil
	sess.exclusive = false
	return "<ok/>"
}

// commitInformation is get-commit-information: the history, newest first.
func (ns *nsession) commitInformation() string {
	d := ns.d
	d.mu.Lock()
	defer d.mu.Unlock()
	var b strings.Builder
	b.WriteString("<commit-information>")
	for i, h := range d.history {
		fmt.Fprintf(&b, "<commit-history><sequence-number>%d</sequence-number><user>%s</user><client>%s</client>"+
			"<date-time junos:seconds=\"%d\">%s</date-time>", i, esc(h.User), esc(h.Via), h.Time.Unix(), esc(formatTime(h.Time)))
		if h.Comment != "" {
			b.WriteString("<log>" + esc(h.Comment) + "</log>")
		}
		if h.Confirmed || h.RollbackIn > 0 {
			fmt.Fprintf(&b, "<rollback-in>%d</rollback-in>", h.RollbackIn)
		}
		b.WriteString("</commit-history>")
	}
	b.WriteString("</commit-information>")
	return b.String()
}

// command is an operational command of the CLI model, for a command the
// transcript has no file for. ok is false for one the device does not know.
func (ns *nsession) command(cmd string) (out string, ok bool) {
	d := ns.d
	d.mu.Lock()
	defer d.mu.Unlock()
	inner := *ns.sess
	inner.configure = false
	r := d.runOp(&inner, cmd, true)
	if r.unknown {
		return "", false
	}
	return r.out, true
}

// getConfiguration answers a get-configuration the model owns; ok is false
// when the request is for the transcript's file (a plain committed read in
// set or text format that has one) or in a format the model does not
// produce.
func (ns *nsession) getConfiguration(op xnode, format string, t transcript) (body string, ok bool) {
	d, sess := ns.d, ns.sess
	database := op.attr("database")
	if database == "" {
		database = "committed"
	}
	if database != "committed" && database != "candidate" {
		return nsError("error", "invalid-value", "unknown database "+database, "", ""), true
	}
	compare := op.attr("compare")
	var path []string
	if f, has := op.kid("configuration"); has {
		path = filterPath(f)
	}
	cmdFor := map[string]string{"set": "show configuration | display set", "text": "show configuration"}
	plain := compare == "" && database == "committed" && len(path) == 0
	if plain {
		if c, known := cmdFor[format]; !known {
			return "", false
		} else if _, _, has := t.command(c); has {
			return "", false
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	// a compare is the candidate's, whatever database says
	cand := d.committed
	if database == "candidate" || compare != "" {
		cand = d.candidate(sess)
	}
	if compare != "" {
		if compare != "rollback" {
			return nsError("error", "invalid-value", "unknown compare "+compare, "", ""), true
		}
		n := 0
		if r := op.attr("rollback"); r != "" {
			v, err := strconv.Atoi(r)
			if err != nil || v < 0 {
				return nsError("error", "invalid-value", plainMsg(jtBadRollback), "", ""), true
			}
			n = v
		}
		if n >= len(d.versions) {
			return nsError("error", "invalid-value", plainMsg(jtNoRollback), "", ""), true
		}
		old := d.versions[n]
		if n == 0 && sess.private {
			old = sess.base
		}
		return "<configuration-information><configuration-output>" + esc(d.compare(old, cand)) +
			"</configuration-output></configuration-information>", true
	}
	switch format {
	case "set":
		return "<configuration-set>" + esc(cand.under(path).setText()) + "</configuration-set>", true
	case "text":
		return "<configuration-text>" + esc(cand.braceAt(path)) + "</configuration-text>", true
	}
	return "", false
}

// filterPath is the statement path a <configuration> filter names: the chain
// of its first children, a <name> child being the key of its list element.
func filterPath(n xnode) []string {
	var path []string
	for cur := n; len(cur.Kids) > 0; {
		var next *xnode
		for i := range cur.Kids {
			k := cur.Kids[i]
			if k.XMLName.Local == "name" {
				if v := strings.TrimSpace(k.Text); v != "" {
					path = append(path, v)
				}
				continue
			}
			if next == nil {
				next = &cur.Kids[i]
			}
		}
		if next == nil {
			break
		}
		path = append(path, next.XMLName.Local)
		cur = *next
	}
	return path
}
