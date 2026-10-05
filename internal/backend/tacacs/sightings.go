package tacacs

// Sightings (backend.Sighter): which devices talked to tacquito, read from
// its journal (docs/plans/operator-console.md 3.3). The scanner recognises
// three shapes of line, whatever tacquito's log prefix around them:
//
//   - patched (patches/0003): 'accepting user [u] from [A] using a bcrypt
//     password' and 'failed to validate the user [u] from [A] using a bcrypt
//     password', at the default level: address, user and outcome;
//   - error, at any level: 'bad secret detected for ip [A:port]' (wrong
//     shared secret) and 'no matching prefix secret provider found' (no
//     scope covers the address). Whether the latter names the address
//     depends on the line that wraps it; when it carries 'for ip [..]' or
//     'remote [..]' the address is taken, otherwise the sighting has no
//     address and is only counted (to be confirmed on a live server, WP6.11);
//   - debug (level 30 only): 'prefix secret provider matches remote [A]
//     against prefix [P]': the address, no user.
//
// An unpatched 'accepting user [u] using a bcrypt password' names no device
// and is ignored.

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
)

var _ backend.Sighter = (*Backend)(nil)

var (
	reSightAccept   = regexp.MustCompile(`accepting user \[(.*?)\] from \[([^\]]*)\] using a bcrypt password`)
	reSightReject   = regexp.MustCompile(`failed to validate the user \[(.*?)\] from \[([^\]]*)\] using a bcrypt password`)
	reSightBad      = regexp.MustCompile(`bad secret detected for ip \[(\[[0-9A-Fa-f:.%a-z]+\]:\d+|[^\]\s]+)\]`)
	reSightNoScope  = regexp.MustCompile(`no matching prefix secret provider found`)
	reSightForIP    = regexp.MustCompile(`(?:for ip|remote) \[(\[[0-9A-Fa-f:.%a-z]+\]:\d+|[^\]\s]+)\]`)
	reSightDebug    = regexp.MustCompile(`prefix secret provider matches remote \[([^\]]+)\] against prefix \[[^\]]*\]`)
	journalTimeForm = "2006-01-02 15:04:05"
)

// ParseSightingLine is the sighting a tacquito journal message records, if
// it is one of the shapes above.
func ParseSightingLine(msg string, at time.Time) (backend.Sighting, bool) {
	s := backend.Sighting{Time: at}
	switch {
	case reSightAccept.MatchString(msg):
		m := reSightAccept.FindStringSubmatch(msg)
		s.User, s.Address, s.Outcome = m[1], backend.CanonAddr(m[2]), backend.SightAccept
	case reSightReject.MatchString(msg):
		m := reSightReject.FindStringSubmatch(msg)
		s.User, s.Address, s.Outcome = m[1], backend.CanonAddr(m[2]), backend.SightReject
	case reSightBad.MatchString(msg):
		s.Address, s.Outcome = backend.CanonHostPort(reSightBad.FindStringSubmatch(msg)[1]), backend.SightBadSecret
	case reSightNoScope.MatchString(msg):
		s.Outcome = backend.SightNoScope
		if m := reSightForIP.FindStringSubmatch(msg); m != nil {
			s.Address = backend.CanonHostPort(m[1])
		}
	case reSightDebug.MatchString(msg):
		s.Address, s.Outcome = backend.CanonAddr(reSightDebug.FindStringSubmatch(msg)[1]), backend.SightSeen
	default:
		return s, false
	}
	return s, true
}

// journalEntry is the part of a 'journalctl -o json' record the scanner
// reads. MESSAGE is a string, or an array of bytes when it is not UTF-8.
type journalEntry struct {
	Cursor   string          `json:"__CURSOR"`
	Realtime string          `json:"__REALTIME_TIMESTAMP"`
	Message  json.RawMessage `json:"MESSAGE"`
}

func (e journalEntry) message() string {
	var s string
	if json.Unmarshal(e.Message, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(e.Message, &ints) == nil {
		for _, n := range ints {
			b = append(b, byte(n))
		}
	}
	return string(b)
}

// ParseJournal reads 'journalctl -o json' output: the sightings in order,
// the cursor of the last record, the time of the first and last record and
// how many records were read. A line that is not a JSON record is skipped.
func ParseJournal(out []byte) (ss []backend.Sighting, cursor string, first, last time.Time, n int) {
	for _, line := range bytes.Split(out, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var e journalEntry
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		us, err := strconv.ParseInt(e.Realtime, 10, 64)
		if err != nil {
			continue
		}
		at := time.UnixMicro(us)
		n++
		if first.IsZero() {
			first = at
		}
		last = at
		if e.Cursor != "" {
			cursor = e.Cursor
		}
		if s, ok := ParseSightingLine(e.message(), at); ok {
			ss = append(ss, s)
		}
	}
	return ss, cursor, first, last, n
}

// Sightings implements backend.Sighter over the journal of every
// listener's unit: 'journalctl <units> -o json --no-pager' after the
// cursor resume, or since since (everything when since is zero). A cursor
// journald no longer knows falls back to since.
func (b *Backend) Sightings(ctx context.Context, since time.Time, resume string) ([]backend.Sighting, string, string, error) {
	run := func(extra ...string) (execx.Result, error) {
		args := append(b.journalUnits(), "-o", "json", "--no-pager")
		return b.env.Runner.Run(ctx, execx.Cmd{Name: "journalctl", Args: append(args, extra...)})
	}
	var res execx.Result
	var err error
	if resume != "" {
		res, err = run("--after-cursor", resume)
		if err == nil && res.Code != 0 {
			resume = ""
		}
	}
	if resume == "" {
		var extra []string
		if !since.IsZero() {
			extra = []string{"--since", since.Format(journalTimeForm)}
		}
		res, err = run(extra...)
	}
	if err != nil {
		return nil, resume, "", err
	}
	if res.Code != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = "journalctl exited " + strconv.Itoa(res.Code)
		}
		return nil, resume, "", &journalError{msg: msg}
	}
	ss, cursor, first, last, n := ParseJournal(res.Stdout)
	if cursor == "" {
		cursor = resume
	}
	return ss, cursor, backend.TimeWindow("journal", first, last, n), nil
}

type journalError struct{ msg string }

func (e *journalError) Error() string { return "cannot read the tacquito journal: " + e.msg }
