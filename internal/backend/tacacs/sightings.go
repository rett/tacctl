package tacacs

// Sightings (backend.Sighter): which devices talked to tacquito, read from
// its journal (docs/plans/operator-console.md 3.3). The scanner recognises
// three shapes of line, whatever tacquito's log prefix around them:
//
//   - patched (patches/0003): 'accepting user [u] from [A] using a bcrypt
//     password' and 'failed to validate the user [u] from [A] using a bcrypt
//     password', at the default level: address, user and outcome;
//   - error, at any level: 'bad secret detected for ip [A:port]' (wrong
//     shared secret) and 'ignoring request: remote [A:port] has no secret
//     providers' (no scope covers the address: tacquito's loader tried
//     every secret provider). The loader's debug line 'remote [A:port], no
//     matching prefix secret provider found' is not a sighting: it is
//     logged for each provider that does not match, also when a later one
//     does (every connection on a server with several scopes);
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
	reSightNoScope  = regexp.MustCompile(`remote \[(\[[0-9A-Fa-f:.%a-z]+\]:\d+|[^\]\s]+)\] has no secret providers`)
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
		s.Address, s.Outcome = backend.CanonHostPort(reSightNoScope.FindStringSubmatch(msg)[1]), backend.SightNoScope
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
	var p journalParser
	_, _ = p.Write(out)
	p.flush()
	return p.ss, p.cursor, p.first, p.last, p.n
}

// journalParser is ParseJournal as an io.Writer: the journal is parsed as
// journalctl writes it, so only the sightings are held in memory, never the
// whole output (hundreds of megabytes at log level 30).
type journalParser struct {
	partial     []byte
	ss          []backend.Sighting
	cursor      string
	first, last time.Time
	n           int
}

func (p *journalParser) Write(b []byte) (int, error) {
	data := b
	if len(p.partial) > 0 {
		data = append(p.partial, b...)
		p.partial = nil
	}
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		p.line(data[:i])
		data = data[i+1:]
	}
	p.partial = append(p.partial, data...)
	return len(b), nil
}

// flush parses an unterminated last line.
func (p *journalParser) flush() {
	if len(p.partial) > 0 {
		p.line(p.partial)
		p.partial = nil
	}
}

func (p *journalParser) line(line []byte) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return
	}
	var e journalEntry
	if json.Unmarshal(line, &e) != nil {
		return
	}
	us, err := strconv.ParseInt(e.Realtime, 10, 64)
	if err != nil {
		return
	}
	at := time.UnixMicro(us)
	p.n++
	if p.first.IsZero() {
		p.first = at
	}
	p.last = at
	if e.Cursor != "" {
		p.cursor = e.Cursor
	}
	if s, ok := ParseSightingLine(e.message(), at); ok {
		p.ss = append(p.ss, s)
	}
}

// Sightings implements backend.Sighter over the journal of every
// listener's unit: 'journalctl <units> -o json --output-fields=MESSAGE
// --no-pager' (MESSAGE alone: the journal of a server at log level 30 is
// large, and the other fields more than double it) after the cursor
// resume, or since since (everything when since is zero), parsed as it is
// read. A cursor journald no longer knows falls back to since.
func (b *Backend) Sightings(ctx context.Context, since time.Time, resume string) ([]backend.Sighting, string, string, error) {
	var p *journalParser
	run := func(extra ...string) (execx.Result, error) {
		p = &journalParser{}
		args := append(b.journalUnits(), "-o", "json", "--output-fields=MESSAGE", "--no-pager")
		return b.env.Runner.Run(ctx, execx.Cmd{Name: "journalctl", Args: append(args, extra...), Stdout: p})
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
	_, _ = p.Write(res.Stdout) // a runner that did not stream
	p.flush()
	cursor := p.cursor
	if cursor == "" {
		cursor = resume
	}
	return p.ss, cursor, backend.TimeWindow("journal", p.first, p.last, p.n), nil
}

type journalError struct{ msg string }

func (e *journalError) Error() string { return "cannot read the tacquito journal: " + e.msg }
