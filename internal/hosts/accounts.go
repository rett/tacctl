package hosts

// The removed users of a host and the question about their home
// directories. The client script deletes the accounts tacctl created whose
// user is no longer in the host's scope; whether a home directory goes with
// its account is the operator's answer, asked here before the script is
// written, because the script runs on the host over ssh. The list is worked
// out from the host's 'getent passwd', read over the same ssh connection
// before anything is copied there (read-only, no sudo), and the answers go
// into the script's header as TAC_REMOVE_HOMES. The script stays the
// authority on what it deletes (its 'created' state, the UID range); a home
// that was not named there is kept and reported.

import (
	"context"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// AccountsCommand is the read-only command that lists a host's accounts.
const AccountsCommand = "getent passwd"

// Account is one line of 'getent passwd'.
type Account struct {
	Name, UID, GECOS, Home string
}

// ParsePasswd reads passwd lines (name:x:uid:gid:gecos:home:shell); lines
// that are not one are skipped.
func ParsePasswd(text string) []Account {
	var out []Account
	for _, l := range strings.Split(text, "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		out = append(out, Account{Name: f[0], UID: f[2], GECOS: f[4], Home: f[5]})
	}
	return out
}

// Accounts lists the accounts of target: 'getent passwd' over the ssh
// connection the script run then shares, or here for a --local host.
func (e *Env) Accounts(ctx context.Context, target, port, identity string) ([]Account, error) {
	c := execx.Cmd{Name: "getent", Args: []string{"passwd"}}
	if target != Local {
		c = e.ssh(port, identity).Cmd("-T", target, AccountsCommand)
	}
	c.Stderr = io.Discard
	res, err := e.Runner.Run(ctx, c)
	if interrupted(ctx) {
		return nil, ui.ErrInterrupted
	}
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, ErrFailed
	}
	return ParsePasswd(string(res.Stdout)), nil
}

// tacctlGECOS reports whether gecos is a full name the client script gives
// the accounts it creates ('<name> (TACACS+)', '<name> (RADIUS)', or the
// generic name of releases before 0.1.16).
func tacctlGECOS(name, gecos string) bool {
	switch gecos {
	case name + " (TACACS+)", name + " (RADIUS)", "TACACS+ user (tacctl)":
		return true
	}
	return false
}

// reHomeDir is a home directory the script may delete: one directory
// directly under /home.
var reHomeDir = regexp.MustCompile(`^/home/[^/]+$`)

// Removed are the accounts of a host that the script will delete, as far
// as tacctl can tell from here: a name tacctl gave a UID (uids), a UID of
// the range on the host (or of a range the UID file was numbered for
// before: the script renumbers such an account before it deletes it), a
// full name the script writes, and a user that is not current (current: the
// scope's users, active or not). Only those whose home is a directory
// directly under /home are returned: any other home is kept by the script
// whatever the answer.
func Removed(accts []Account, uids UIDs, current map[string]bool) ([]Account, error) {
	_, prev, err := uids.Recorded()
	if err != nil {
		return nil, err
	}
	ours := func(uid string) bool {
		for _, r := range append([]Range{uids.rng()}, prev...) {
			if r.Contains(uid) {
				return true
			}
		}
		return false
	}
	var out []Account
	for _, a := range accts {
		if current[a.Name] || !ours(a.UID) || !tacctlGECOS(a.Name, a.GECOS) || !reHomeDir.MatchString(a.Home) {
			continue
		}
		uid, err := uids.Lookup(a.Name)
		if err != nil {
			return nil, err
		}
		if uid != "" {
			out = append(out, a)
		}
	}
	return out, nil
}

// HomePrompt is the question for one removed user.
func HomePrompt(a Account) string {
	return "Delete " + a.Home + " of removed user '" + a.Name + "'? [y/N] "
}

// yes is an answer of y or yes, in any case.
func yes(answer string) bool {
	a := strings.ToLower(strings.TrimSpace(answer))
	return a == "y" || a == "yes"
}

// HomesToDelete asks, for each removed user of the host name (reached at
// target), whether its home directory goes with the account, and returns
// the names answered yes. ask is the operator's terminal (nil when there
// is none: nothing is read from the host, nothing asked, and every home is
// kept). A host whose accounts cannot be listed is reported and its homes
// are kept.
func (e *Env) HomesToDelete(ctx context.Context, name, target, port, identity string, current map[string]bool, ask func(prompt string) string) ([]string, error) {
	if ask == nil {
		return nil, nil
	}
	accts, err := e.Accounts(ctx, target, port, identity)
	if err != nil {
		if errors.Is(err, ui.ErrInterrupted) {
			return nil, err
		}
		e.Out.WarnE(name + ": could not list the host's accounts; the home directories of removed users are kept.")
		return nil, nil
	}
	removed, err := Removed(accts, e.UIDs(), current)
	if err != nil || len(removed) == 0 {
		return nil, err
	}
	names := make([]string, len(removed))
	for i, a := range removed {
		names[i] = a.Name
	}
	e.Out.InfoE(name + ": removed users with an account there (deleted by this run): " + strings.Join(names, ", "))
	var del []string
	for _, a := range removed {
		if yes(ask(HomePrompt(a))) {
			del = append(del, a.Name)
		}
	}
	return del, nil
}

// AccountSummary is what the client script reports at the end of its
// account sync ("[INFO] Accounts: <n> managed by tacctl here[; <k>
// renumbered][; refused: <names>]."): the users of the list that have an
// account tacctl manages on the host, how many of the accounts it created
// were renumbered from the legacy range by this run, and the users it
// refused there (a local account of that name tacctl did not create, a UID
// outside the range, no free number, an account it could not renumber).
type AccountSummary struct {
	Managed    int
	Renumbered int
	Refused    []string
}

// Counts is the summary in words: "<n> users", plus "; <k> renumbered"
// and "; <k> refused: <names>" when there are any.
func (s AccountSummary) Counts() string {
	out := UsersText(s.Managed)
	if s.Renumbered > 0 {
		out += "; " + strconv.Itoa(s.Renumbered) + " renumbered"
	}
	if len(s.Refused) > 0 {
		out += "; " + strconv.Itoa(len(s.Refused)) + " refused: " + strings.Join(s.Refused, ", ")
	}
	return out
}

// UsersText is n users ('1 user', '2 users').
func UsersText(n int) string {
	if n == 1 {
		return "1 user"
	}
	return strconv.Itoa(n) + " users"
}

var reAccountSummary = regexp.MustCompile(`^\[INFO\] Accounts: ([0-9]+) managed by tacctl here(?:; ([0-9]+) renumbered)?(?:; refused: (.*))?\.\r?$`)

// ParseAccountSummary reads the summary line; ok is false for any other.
func ParseAccountSummary(line string) (AccountSummary, bool) {
	m := reAccountSummary.FindStringSubmatch(line)
	if m == nil {
		return AccountSummary{}, false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return AccountSummary{}, false
	}
	s := AccountSummary{Managed: n}
	if m[2] != "" {
		s.Renumbered, _ = strconv.Atoi(m[2])
	}
	if m[3] != "" {
		s.Refused = strings.Split(m[3], ", ")
	}
	return s, true
}

// summaryWriter passes everything to w unchanged and as it comes, and
// keeps the last summary line seen.
type summaryWriter struct {
	w    io.Writer
	line []byte
	sum  *AccountSummary
}

func (s *summaryWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	for _, b := range p[:n] {
		if b != '\n' {
			if len(s.line) < 4096 {
				s.line = append(s.line, b)
			}
			continue
		}
		if sum, ok := ParseAccountSummary(string(s.line)); ok {
			s.sum = &sum
		}
		s.line = s.line[:0]
	}
	return n, err
}
