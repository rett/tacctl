package fakedev

// The command line of the configure model: what each command of the
// operational and configuration modes does to the state of junos_config.go
// and prints. The session loop (the prompts, the echo, paging, the csh of a
// root login) is junos_config_shell.go.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// jresult is the answer to one command.
type jresult struct {
	out     string // the text, with '\n' line ends and no prompt
	quit    bool   // the CLI ends
	drop    int    // 0 none, 1 the connection closes unanswered, 2 after the answer
	noMore  bool   // paging is off for this answer
	unknown bool   // a command the device does not know (an exec's status 1)
}

const (
	dropNone = iota
	dropSilent
	dropAfterOutput
)

func (d *junosDevice) newSession(user string) *jsession {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nextID++
	pageLen, junos := d.s.t.paging()
	sess := &jsession{id: d.nextID, user: user, class: d.classOf(user), since: d.s.clock.Now(), pageLen: pageLen, junosPage: junos}
	d.sessions[sess] = struct{}{}
	return sess
}

// endSession ends a session as the device does when its terminal closes:
// the exclusive lock goes and the candidate it staged with it.
func (d *junosDevice) endSession(sess *jsession) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.leave(sess)
	delete(d.sessions, sess)
}

// leave takes a session out of configuration mode.
func (d *junosDevice) leave(sess *jsession) {
	if sess.exclusive && d.excl == sess {
		d.excl = nil
		d.shared = nil
	}
	sess.configure, sess.exclusive, sess.private = false, false, false
	sess.base, sess.cand, sess.edit = nil, nil, nil
}

// run executes one command of the session. oneShot is an exec channel's
// command: no mode change.
func (d *junosDevice) run(sess *jsession, cmd string, oneShot bool) jresult {
	d.mu.Lock()
	defer d.mu.Unlock()
	if sess.configure {
		return d.runConfig(sess, cmd)
	}
	return d.runOp(sess, cmd, oneShot)
}

func unknownText() string { return jtCaret + "\n" + jtUnknownCommand + "\n" }
func syntaxText() string  { return jtCaret + "\n" + jtSyntaxError + "\n" }

// pipes splits 'a b | c d' into its words per segment.
func pipes(cmd string) [][]string {
	var out [][]string
	for _, seg := range strings.Split(cmd, "|") {
		out = append(out, strings.Fields(seg))
	}
	return out
}

// --- operational mode ---------------------------------------------------------------------

func (d *junosDevice) runOp(sess *jsession, cmd string, oneShot bool) jresult {
	segs := pipes(cmd)
	noMore := false
	for len(segs) > 1 && slices.Equal(segs[len(segs)-1], []string{"no-more"}) {
		segs = segs[:len(segs)-1]
		noMore = true
	}
	res := jresult{noMore: noMore}
	if len(segs) == 0 || len(segs[0]) == 0 {
		return res
	}
	w := segs[0]
	switch {
	case w[0] == "configure" && !oneShot:
		res.out = d.enter(sess, w[1:])
	case (w[0] == "exit" || w[0] == "quit") && !oneShot:
		res.quit = true
	case w[0] == "set" && len(w) >= 2 && w[1] == "cli":
		res.out = d.setCLI(sess, w[2:])
	case slices.Equal(w, []string{"show", "system", "commit"}) && len(segs) == 1:
		res.out = d.historyText()
	case slices.Equal(w, []string{"show", "cli", "authorization"}) && len(segs) == 1:
		res.out = d.authorizationText(sess.user)
	case slices.Equal(w, []string{"show", "configuration"}) && len(segs) == 2 && len(segs[1]) == 3 && segs[1][0] == "compare" && segs[1][1] == "rollback":
		// 'show configuration | compare rollback N': the committed
		// configuration against rollback N (lab L3)
		n, err := strconv.Atoi(segs[1][2])
		switch {
		case err != nil || n < 0:
			res.out = jtBadRollback + "\n"
		case n >= len(d.versions):
			res.out = jtNoRollback + "\n"
		default:
			res.out = d.compare(d.versions[n], d.committed)
		}
	case len(w) >= 2 && w[0] == "show" && w[1] == "configuration":
		set := false
		for _, s := range segs[1:] {
			if slices.Equal(s, []string{"display", "set"}) {
				set = true
			}
		}
		res.out = d.showConfiguration(w[2:], set)
	default:
		out, deny, known := d.s.t.command(cmd)
		switch {
		case deny != "":
			res.out, res.unknown = deny+"\n", true
		case known:
			res.out = out
		case slices.Equal(w, []string{"show", "version"}):
			res.out = d.versionText()
		default:
			res.out, res.unknown = unknownText(), true
		}
	}
	return res
}

func (d *junosDevice) setCLI(sess *jsession, w []string) string {
	if len(w) == 2 && (w[0] == "screen-length" || w[0] == "screen-width") {
		n, err := strconv.Atoi(w[1])
		if err != nil || n < 0 {
			return syntaxText()
		}
		if w[0] == "screen-length" {
			sess.pageLen = n
			return fmt.Sprintf(jtScreenLength, n) + "\n"
		}
		return fmt.Sprintf(jtScreenWidth, n) + "\n"
	}
	return ""
}

// lockedText is the refusal while another session holds the exclusive lock.
func (d *junosDevice) lockedText(user string) string {
	since := d.born
	pid := 20000
	if d.excl != nil {
		since, pid = d.excl.since, 30000+d.excl.id
	}
	return jtLocked + "\n" + fmt.Sprintf(jtEditingLine, user, 0, pid, formatTime(since)) + "\n" + fmt.Sprintf(jtEditingExcl, d.switchLine()) + "\n"
}

// editors is the users block of 'configure' when others are editing.
func (d *junosDevice) editors(self *jsession) string {
	var b strings.Builder
	ids := make([]*jsession, 0, len(d.sessions))
	for s := range d.sessions {
		if s != self && s.configure {
			ids = append(ids, s)
		}
	}
	slices.SortFunc(ids, func(a, b *jsession) int { return a.id - b.id })
	for _, s := range ids {
		b.WriteString(fmt.Sprintf(jtEditingLine, s.user, s.id, 30000+s.id, formatTime(s.since)) + "\n")
		switch {
		case s.exclusive:
			b.WriteString(fmt.Sprintf(jtEditingExcl, d.switchLine()) + "\n")
		case s.private:
			b.WriteString(fmt.Sprintf(jtEditingPriv, d.switchLine()) + "\n")
		default:
			b.WriteString(fmt.Sprintf(jtEditingShared, d.switchLine()) + "\n")
		}
	}
	if h := d.holder(); h != "" && d.excl == nil {
		// the 'exclusive.held-by' knob's holder: a session of no connection
		b.WriteString(fmt.Sprintf(jtEditingLine, h, 2, 20419, formatTime(d.born)) + "\n" + fmt.Sprintf(jtEditingExcl, d.switchLine()) + "\n")
	}
	if d.stranger != "" && d.modified() && !(self.exclusive) {
		b.WriteString(fmt.Sprintf(jtEditingLine, d.stranger, 1, 20418, formatTime(d.born)) + "\n" + fmt.Sprintf(jtEditingShared, d.switchLine()) + "\n")
	}
	if b.Len() == 0 {
		return ""
	}
	return jtUsersEditing + "\n" + b.String()
}

// What enterMode did.
const (
	enterShared      = iota // a shared session
	enterExclusive          // the exclusive lock is now the session's
	enterPrivate            // a private session
	enterPrivateHeld        // a private session, entered under another's lock
	enterLocked             // refused: another session holds the lock
	enterModified           // refused: the shared candidate holds a staged change
)

// enterMode puts a session into configuration mode: mode is "", "exclusive"
// or "private". Under another session's exclusive lock only 'configure
// exclusive' is refused: a shared session enters and lists the holder among
// the editors, a private one enters with a warning (lab L1); neither can
// change or commit (blocked). The second result is the lock's holder for
// enterLocked. The caller holds d.mu and has checked the class.
func (d *junosDevice) enterMode(sess *jsession, mode string) (int, string) {
	h := d.holder()
	held := h != "" && d.excl != sess
	st := enterShared
	switch mode {
	case "exclusive":
		if held {
			return enterLocked, h
		}
		if d.modified() {
			return enterModified, ""
		}
		d.shared = nil
		d.excl = sess
		sess.exclusive = true
		st = enterExclusive
	case "private":
		st = enterPrivate
		if held {
			st = enterPrivateHeld
		}
		sess.private = true
		sess.base = d.committed.clone()
		sess.cand = d.committed.clone()
	}
	sess.configure = true
	sess.edit = nil
	return st, ""
}

// enter is 'configure [exclusive|private]'.
func (d *junosDevice) enter(sess *jsession, args []string) string {
	mode := ""
	switch {
	case len(args) == 0:
	case len(args) == 1 && (args[0] == "exclusive" || args[0] == "private"):
		mode = args[0]
	default:
		return syntaxText()
	}
	if !mayConfigure(sess.class) {
		return unknownText()
	}
	out := ""
	switch st, h := d.enterMode(sess, mode); st {
	case enterLocked:
		return d.lockedText(h)
	case enterModified:
		return jtModified + "\n"
	case enterExclusive:
		out = jtExclusiveWarning + "\n"
	case enterPrivateHeld:
		out = jtPrivateUnderExcl + "\n"
	}
	out += jtEnterConfig + "\n"
	if e := d.editors(sess); e != "" {
		out += e
	}
	return out
}

// --- configuration mode ----------------------------------------------------------------------

// blocked is the refusal text when another session's exclusive lock stops
// this one from changing the shared candidate (or committing), or "".
func (d *junosDevice) blocked(sess *jsession, writes bool) string {
	h := d.holder()
	if h == "" || d.excl == sess {
		return ""
	}
	if sess.private && writes {
		return ""
	}
	return d.lockedText(h)
}

func (d *junosDevice) candidate(sess *jsession) *jcfg {
	if sess.private {
		return sess.cand
	}
	return d.sharedOrCommitted()
}

func (d *junosDevice) writable(sess *jsession) *jcfg {
	if sess.private {
		return sess.cand
	}
	if d.shared == nil {
		d.shared = d.committed.clone()
	}
	return d.shared
}

func (d *junosDevice) runConfig(sess *jsession, cmd string) jresult {
	w := strings.Fields(cmd)
	if len(w) == 0 {
		return jresult{}
	}
	res := jresult{}
	switch w[0] {
	case "set", "delete", "insert":
		res.out = d.cfgEdit(sess, cmd)
	case "show":
		res.out, res.noMore = d.cfgShow(sess, cmd)
	case "commit":
		return d.cfgCommit(sess, w[1:])
	case "rollback":
		res.out = d.cfgRollback(sess, w[1:])
	case "exit", "quit":
		switch {
		case w[0] == "exit" && len(w) == 1 && len(sess.edit) > 0:
			sess.edit = sess.edit[:len(sess.edit)-1]
		case len(w) == 1 || len(w) == 2 && w[1] == "configuration-mode":
			if !sess.exclusive && !sess.private && d.modified() {
				res.out = jtNotCommitted + "\n"
			}
			d.leave(sess)
			res.out += jtExitConfig + "\n"
		default:
			res.out = syntaxText()
		}
	case "edit":
		res.out = d.cfgEditPath(sess, w[1:])
	case "up":
		if len(sess.edit) > 0 {
			sess.edit = sess.edit[:len(sess.edit)-1]
		}
	case "top":
		sess.edit = nil
	case "run":
		if len(w) < 2 {
			return jresult{out: syntaxText()}
		}
		inner := *sess
		inner.configure = false
		r := d.runOp(&inner, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(cmd), "run")), true)
		sess.pageLen = inner.pageLen
		r.quit = false
		return r
	default:
		res.out = syntaxText()
	}
	return res
}

func (d *junosDevice) cfgEditPath(sess *jsession, w []string) string {
	if len(w) == 0 {
		return syntaxText()
	}
	sess.edit = append(sess.edit, w...)
	return ""
}

// loadRefusal is the statement-level refusal of the knob files.
func (d *junosDevice) loadRefusal(text string) (string, bool) {
	for _, l := range d.rules("load.errors") {
		if prefix, msg, ok := splitRule(l); ok && hasPrefixWords(text, prefix) {
			return msg + "\n", true
		}
	}
	for _, l := range d.rules("version-gate") {
		if prefix, mode, ok := splitRule(l); !ok || mode != "check" {
			if hasPrefixWords(text, prefix) {
				return syntaxText(), true
			}
		}
	}
	return "", false
}

func (d *junosDevice) cfgEdit(sess *jsession, cmd string) string {
	if t := d.blocked(sess, true); t != "" {
		return t
	}
	words := jsplit(cmd)
	verb, rest := words[0], words[1:]
	if len(rest) == 0 {
		return syntaxText()
	}
	switch kind, msg := d.editStatement(sess, verb, slices.Concat(sess.edit, rest)); kind {
	case editRefused:
		return msg
	case editNotFound:
		return jtStatementNotFound + "\n"
	case editBad:
		return "error: " + msg + "\n"
	}
	return ""
}

// What editStatement did.
const (
	editApplied  = iota
	editRefused  // the text the device printed is the message
	editNotFound // a delete of a node that is not there
	editBad      // the message is the error
)

// editStatement applies one set, delete or insert statement (abs is its
// absolute path) to the session's candidate. The caller holds d.mu and has
// checked blocked.
func (d *junosDevice) editStatement(sess *jsession, verb string, abs []string) (int, string) {
	if msg, ok := d.loadRefusal(verb + " " + strings.Join(abs, " ")); ok {
		return editRefused, msg
	}
	cand := d.writable(sess)
	switch verb {
	case "set":
		for _, p := range expandBrackets(abs) {
			cand.set(p)
		}
	case "delete":
		found := false
		for _, p := range expandBrackets(abs) {
			if cand.delete(p) {
				found = true
			}
		}
		if !found {
			return editNotFound, ""
		}
	case "insert":
		if err := cand.insert(abs); err != nil {
			return editBad, err.Error()
		}
	}
	return editApplied, ""
}

// compare is what a compare prints: compareText, with the context lines of
// a device when the 'compare.context' knob is on.
func (d *junosDevice) compare(old, cur *jcfg) string {
	return compareText(old, cur, d.s.t.exists("compare.context"))
}

// cfgShow is 'show [path] [| compare [rollback N]] [| display set]'.
func (d *junosDevice) cfgShow(sess *jsession, cmd string) (out string, noMore bool) {
	segs := pipes(cmd)
	path := slices.Concat(sess.edit, segs[0][1:])
	compare, set := false, false
	var old *jcfg
	for _, s := range segs[1:] {
		switch {
		case len(s) >= 1 && s[0] == "compare":
			compare = true
			switch {
			case len(s) == 1:
			case len(s) == 3 && s[1] == "rollback":
				n, err := strconv.Atoi(s[2])
				if err != nil || n < 0 {
					return jtBadRollback + "\n", noMore
				}
				if n >= len(d.versions) {
					return jtNoRollback + "\n", noMore
				}
				old = d.versions[n]
			default:
				return syntaxText(), noMore
			}
		case len(s) == 2 && s[0] == "display" && s[1] == "set":
			set = true
		case len(s) == 1 && s[0] == "no-more":
			noMore = true
		case len(s) >= 1 && (s[0] == "display" || s[0] == "except" || s[0] == "match" || s[0] == "count"):
		default:
			return syntaxText(), noMore
		}
	}
	cand := d.candidate(sess)
	switch {
	case compare:
		if old == nil {
			old = d.committed
			if sess.private {
				old = sess.base
			}
		}
		return d.compare(old, cand), noMore
	case set:
		return cand.under(path).setText(), noMore
	}
	return cand.braceAt(path), noMore
}

func (d *junosDevice) cfgRollback(sess *jsession, w []string) string {
	if t := d.blocked(sess, true); t != "" {
		return t
	}
	n := 0
	if len(w) == 1 {
		v, err := strconv.Atoi(w[0])
		if err != nil || v < 0 {
			return jtBadRollback + "\n"
		}
		n = v
	} else if len(w) > 1 {
		return syntaxText()
	}
	if n >= len(d.versions) {
		return jtNoRollback + "\n"
	}
	switch {
	case sess.private:
		sess.cand = d.versions[n].clone()
	case n == 0:
		d.shared = nil
	default:
		d.shared = d.versions[n].clone()
	}
	return jtLoadComplete + "\n"
}

// checkFailures are the messages the candidate fails 'commit check' with.
func (d *junosDevice) checkFailures(cand *jcfg) []string {
	var out []string
	added := func(prefix string) bool {
		for _, s := range cand.stmts {
			if hasPrefixWords("set "+strings.Join(s, " "), prefix) && !slices.ContainsFunc(d.committed.stmts, func(o []string) bool { return slices.Equal(o, s) }) {
				return true
			}
		}
		return false
	}
	for _, l := range d.rules("check.errors") {
		if prefix, msg, ok := splitRule(l); ok {
			if added(prefix) {
				out = append(out, msg)
			}
		} else {
			out = append(out, l)
		}
	}
	for _, l := range d.rules("version-gate") {
		if prefix, mode, ok := splitRule(l); ok && mode == "check" && added(prefix) {
			out = append(out, strings.TrimRight(syntaxText(), "\n"))
		}
	}
	return out
}

// cfgCommit is 'commit [check|confirmed [N]] [comment "text"]'.
func (d *junosDevice) cfgCommit(sess *jsession, args []string) jresult {
	if t := d.blocked(sess, false); t != "" {
		return jresult{out: t}
	}
	check, confirmed, minutes, comment := false, false, 10, ""
	line := strings.Join(args, " ")
	words := jsplit(line)
	for i := 0; i < len(words); i++ {
		switch words[i] {
		case "check":
			check = true
		case "confirmed":
			confirmed = true
			if i+1 < len(words) {
				if n, err := strconv.Atoi(words[i+1]); err == nil {
					if n < 1 || n > 65535 {
						return jresult{out: jtBadConfirmed + "\n"}
					}
					minutes = n
					i++
				}
			}
		case "comment":
			if i+1 >= len(words) {
				return jresult{out: syntaxText()}
			}
			comment = words[i+1]
			i++
		case "and-quit", "synchronize", "force":
		default:
			return jresult{out: syntaxText()}
		}
	}
	if confirmed && check {
		return jresult{out: syntaxText()}
	}
	if confirmed && sess.private {
		// a private session refuses a confirmed commit (lab L5)
		return jresult{out: jtNoConfirmedPrivate + "\n"}
	}
	o := d.commitApply(sess, check, confirmed, minutes, comment, jtCommitVia, nil)
	if len(o.fails) > 0 {
		return jresult{out: strings.Join(o.fails, "\n") + "\n" + jtCheckFailed + "\n"}
	}
	if check {
		return jresult{out: jtCheckOK + "\n"}
	}
	out := jtCheckOK + "\n" + jtCommitComplete + "\n"
	if confirmed {
		out = jtCheckOK + "\n" + fmt.Sprintf(jtConfirmedFmt, minutes) + "\n" + jtCommitComplete + "\n"
	}
	return jresult{out: out, drop: d.commitDrop(confirmed)}
}

// commitDrop is the 'commit.drop' knob's drop mode for a commit.
func (d *junosDevice) commitDrop(confirmed bool) int {
	if !confirmed || !d.s.t.exists("commit.drop") {
		return dropNone
	}
	if w, _ := d.knobWord("commit.drop"); w == "after-output" {
		return dropAfterOutput
	}
	return dropSilent
}

// commitOutcome is what commitApply did.
type commitOutcome struct {
	// fails are the messages of a refused check; nothing else happened.
	fails []string
}

// commitApply is the commit of either channel, after the arguments are
// checked: the candidate's check, then for a check alone the confirmation of
// a pending commit (a 'commit check' from any session confirms it and leaves
// no history entry, lab L2), else the commit, the confirmed commit's window
// and the history entry. via is the history entry's way and owner the
// session whose close rolls an unconfirmed commit back at once (nil for the
// command line, which only the window's end does). The caller holds d.mu and
// has checked blocked.
func (d *junosDevice) commitApply(sess *jsession, check, confirmed bool, minutes int, comment, via string, owner *jsession) commitOutcome {
	cand := d.candidate(sess)
	if fails := d.checkFailures(cand); len(fails) > 0 {
		return commitOutcome{fails: fails}
	}
	if check {
		if d.pending != nil {
			d.pending.timer.Stop()
			d.pending = nil
		}
		return commitOutcome{}
	}
	next := d.committed.clone()
	if sess.private {
		for _, s := range sess.base.stmts {
			if !slices.ContainsFunc(sess.cand.stmts, func(o []string) bool { return slices.Equal(o, s) }) {
				next.delete(s)
			}
		}
		for _, s := range sess.cand.stmts {
			if !slices.ContainsFunc(sess.base.stmts, func(o []string) bool { return slices.Equal(o, s) }) {
				next.set(s)
			}
		}
	} else {
		next = cand.clone()
	}
	next.uidsAssign()
	before := d.committed
	if d.pending != nil {
		d.pending.timer.Stop()
		if confirmed {
			before = d.pending.before
		}
		d.pending = nil
	}
	d.committed = next
	if sess.private {
		sess.base, sess.cand = d.committed.clone(), d.committed.clone()
	} else {
		d.shared = nil
	}
	rollbackIn := 0
	if confirmed {
		rollbackIn = minutes
		p := &junosPending{before: before.clone(), owner: owner}
		p.until = d.s.clock.Now().Add(time.Duration(minutes) * d.minute())
		p.timer = d.s.clock.AfterFunc(time.Duration(minutes)*d.minute(), func() { d.expire(p) })
		d.pending = p
	}
	d.record(sess.user, via, comment, rollbackIn)
	return commitOutcome{}
}
