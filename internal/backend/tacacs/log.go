package tacacs

import (
	"bytes"
	"context"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

const rule = "--------------------------------------------"

// FollowArgv is backend.Follower: the journal of every listener's unit,
// new entries only.
func (b *Backend) FollowArgv() [][]string {
	return [][]string{append(append([]string{"journalctl"}, b.journalUnits()...), "--no-pager", "-f", "-n", "0")}
}

// Log is backend_tacacs_log: 'tacctl log tail [n]', 'search <term>',
// 'failures' and 'clear [-y|--yes|--force]' over the journal of every
// listener's unit (just 'tacquito' with only the default listener), written
// to w; ErrUnsupported for another sub-command.
func (b *Backend) Log(ctx context.Context, sub string, args []string, w io.Writer) error {
	arg := ""
	if len(args) > 0 {
		arg = args[0]
	}
	switch sub {
	case "tail":
		count := or(arg, "20")
		echoLine(w, "\n"+ui.Bold+"Recent TACACS+ Log Entries"+ui.NC)
		writeString(w, rule+"\n")
		res, err := b.env.Runner.Run(ctx, execx.Cmd{Name: "journalctl",
			Args: append(b.journalUnits(), "--no-pager", "-n", count), Stdout: w, Stderr: io.Discard})
		if err != nil || res.Code != 0 {
			writeString(w, "  No log entries found.\n")
		}
		writeString(w, "\n")
	case "search":
		if arg == "" {
			b.out().Error("Usage: tacctl log search <username>")
			return backend.ErrFailed
		}
		echoLine(w, "\n"+ui.Bold+"Log entries matching '"+arg+"'"+ui.NC)
		writeString(w, rule+"\n")
		lines := b.journal(ctx, "7 days ago")
		re, err := grepRegexp(arg)
		var hits []string
		if err == nil {
			for _, l := range lines {
				if re.MatchString(l) {
					hits = append(hits, l)
				}
			}
		}
		if len(hits) == 0 {
			writeString(w, "  No matches found.\n")
		} else {
			writeString(w, strings.Join(hits, "\n")+"\n")
		}
		writeString(w, "\n")
	case "failures":
		echoLine(w, "\n"+ui.Bold+"Authentication Failures (last 24 hours)"+ui.NC)
		writeString(w, rule+"\n")
		var hits []string
		for _, l := range b.journal(ctx, "24 hours ago") {
			if failureRE.MatchString(l) {
				hits = append(hits, l)
			}
		}
		if text := strings.TrimRight(strings.Join(hits, "\n"), "\n"); text != "" {
			writeString(w, text+"\n")
		} else {
			echoLine(w, "  "+ui.Green+"No failures in the last 24 hours"+ui.NC)
		}
		writeString(w, "\n")
	case "clear":
		b.logClear(ctx, arg, w)
	default:
		return backend.ErrUnsupported
	}
	return nil
}

// failureRE is grep -i "ERROR\|fail\|bad secret".
var failureRE = regexp.MustCompile(`(?i)ERROR|fail|bad secret`)

// journal is the lines of 'journalctl <units> --no-pager --since <since>
// 2>/dev/null'.
func (b *Backend) journal(ctx context.Context, since string) []string {
	res, _ := b.env.Runner.Run(ctx, execx.Cmd{Name: "journalctl",
		Args: append(b.journalUnits(), "--no-pager", "--since", since)})
	return records(string(res.Stdout))
}

// logClear is cmd_log_clear: purge the tacquito journal and truncate every
// accounting log, after a confirmation that -y, --yes and --force skip.
func (b *Backend) logClear(ctx context.Context, flag string, w io.Writer) {
	out := ui.Output{Stdout: w, Stderr: b.env.Out.Stderr}
	force := flag == "-y" || flag == "--force" || flag == "--yes"
	acct := b.env.Paths.AcctLog
	others := b.acctLogs(false)

	writeString(w, "\n")
	echoLine(w, ui.Bold+"Clear tacquito logs"+ui.NC)
	writeString(w, rule+"\n")
	out.Warn("This permanently deletes tacquito journal entries and truncates " + acct + ".")
	for _, log := range others {
		if isRegular(log) {
			out.Warn("Also truncated: " + log)
		}
	}
	out.Warn("Historical authentication and accounting records will be lost.")
	if !force && !b.prompt().Confirm("  Continue? [y/N]: ") {
		out.Info("Cancelled.")
		return
	}

	// Rotate closes the active journal file so the vacuum step can evict
	// it; --vacuum-time=1s then drops everything older than one second.
	_, _ = b.env.Runner.Run(ctx, execx.Cmd{Name: "journalctl", Args: []string{"--rotate"}, Stdout: w, Stderr: io.Discard})
	if res, err := b.env.Runner.Run(ctx, execx.Cmd{Name: "journalctl",
		Args: []string{"--vacuum-time=1s", "-u", Service}}); err != nil || res.Code != 0 {
		out.Warn("journalctl vacuum failed — run manually: sudo journalctl --vacuum-time=1s -u tacquito")
	}

	// Truncate in place so logrotate's ownership and permissions stay.
	for _, log := range append([]string{acct}, others...) {
		if !isRegular(log) {
			continue
		}
		if err := os.Truncate(log, 0); err != nil {
			out.Warn("Could not truncate " + log + " (check permissions).")
		}
	}
	out.Info("Logs cleared (journal + accounting).")
	writeString(w, "\n")
}

// Accounting is backend_tacacs_accounting: 'tacctl log accounting [n]'
// (sub "tail"), the last lines of every listener's accounting log;
// ErrUnsupported for another sub-command.
func (b *Backend) Accounting(_ context.Context, sub string, args []string, w io.Writer) error {
	if sub != "tail" {
		return backend.ErrUnsupported
	}
	count := "20"
	if len(args) > 0 && args[0] != "" {
		count = args[0]
	}
	writeString(w, "\n")
	echoLine(w, ui.Bold+"Recent Accounting Entries"+ui.NC)
	writeString(w, rule+"\n")
	if acct := b.env.Paths.AcctLog; isRegular(acct) {
		b.tail(w, acct, count)
	} else {
		writeString(w, "  No accounting log found at "+acct+"\n")
	}
	// The other listeners' logs, each under its name.
	for _, log := range b.acctLogs(false) {
		if !isRegular(log) {
			continue
		}
		writeString(w, "\n")
		echoLine(w, ui.Bold+log+ui.NC)
		b.tail(w, log, count)
	}
	writeString(w, "\n")
	return nil
}

// tail is 'tail -n <count> <file>': the last count lines ('+K': from line
// K on), the bytes as they are. A count tail cannot read is its complaint
// on stderr and nothing on w.
func (b *Backend) tail(w io.Writer, path, count string) {
	from := false
	c := count
	switch {
	case strings.HasPrefix(c, "+"):
		from, c = true, c[1:]
	case strings.HasPrefix(c, "-"):
		c = c[1:]
	}
	n, err := strconv.ParseUint(c, 10, 63)
	if err != nil {
		writeString(b.env.Out.Stderr, "tail: invalid number of lines: '"+count+"'\n")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeString(b.env.Out.Stderr, "tail: cannot open '"+path+"' for reading: "+err.Error()+"\n")
		return
	}
	// Line starts: a line ends at a newline or at the end of the data.
	var starts []int
	for i := 0; i < len(data); {
		starts = append(starts, i)
		j := bytes.IndexByte(data[i:], '\n')
		if j < 0 {
			break
		}
		i += j + 1
	}
	var at int
	switch {
	case from:
		k := max(int(min(n, uint64(len(starts)+1))), 1)
		if k > len(starts) {
			return
		}
		at = starts[k-1]
	case n == 0:
		return
	case int(min(n, uint64(len(starts)))) == len(starts):
		at = 0
	default:
		at = starts[len(starts)-int(n)]
	}
	_, _ = w.Write(data[at:])
}

// grepRegexp is the matcher of 'grep -i -e <pattern>': a POSIX basic
// regular expression (GNU flavour: \| \+ \? \{ \} \( \) are operators,
// \< \> \b \B \w \W \s \S as GNU grep has them), case-insensitive; a
// pattern holding newlines is one pattern per line. A back-reference is
// not supported (an error, as for a pattern grep refuses).
func grepRegexp(pattern string) (*regexp.Regexp, error) {
	var alts []string
	for _, p := range strings.Split(pattern, "\n") {
		re, err := breToRE2(p)
		if err != nil {
			return nil, err
		}
		alts = append(alts, re)
	}
	return regexp.Compile("(?i)(?:" + strings.Join(alts, ")|(?:") + ")")
}

type breError string

func (e breError) Error() string { return "grep: " + string(e) }

// breToRE2 translates one GNU basic regular expression into RE2 syntax.
func breToRE2(p string) (string, error) {
	var out strings.Builder
	// atStart: where '*' is literal and '^' an anchor (the start, after
	// \( and after \|).
	atStart := true
	depth := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		start := atStart
		atStart = false
		switch c {
		case '\\':
			if i+1 >= len(p) {
				return "", breError("Trailing backslash")
			}
			i++
			e := p[i]
			switch {
			case e == '(':
				depth++
				out.WriteString("(")
				atStart = true
			case e == ')':
				if depth == 0 {
					return "", breError("Unmatched ) or \\)")
				}
				depth--
				out.WriteString(")")
			case e == '|':
				out.WriteString("|")
				atStart = true
			case e == '{' || e == '}' || e == '+' || e == '?':
				out.WriteByte(e)
			case e == '<' || e == '>':
				out.WriteString(`\b`)
			case strings.IndexByte("bBwWsS", e) >= 0:
				out.WriteByte('\\')
				out.WriteByte(e)
			case e >= '1' && e <= '9':
				return "", breError("back-references are not supported")
			default:
				out.WriteString(regexp.QuoteMeta(string(e)))
			}
		case '*':
			if start {
				out.WriteString(`\*`)
			} else {
				out.WriteByte('*')
			}
		case '^':
			if start {
				out.WriteByte('^')
				atStart = true
			} else {
				out.WriteString(`\^`)
			}
		case '$':
			rest := p[i+1:]
			if rest == "" || strings.HasPrefix(rest, `\)`) || strings.HasPrefix(rest, `\|`) {
				out.WriteByte('$')
			} else {
				out.WriteString(`\$`)
			}
		case '.':
			out.WriteByte('.')
		case '[':
			j, class, err := bracket(p, i)
			if err != nil {
				return "", err
			}
			out.WriteString(class)
			i = j
		default:
			out.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if depth != 0 {
		return "", breError("Unmatched ( or \\(")
	}
	return out.String(), nil
}

// bracket reads the bracket expression that starts at p[i] ('['): the
// index of its closing ']' and the expression in RE2 syntax (a backslash
// is an ordinary character in it).
func bracket(p string, i int) (int, string, error) {
	var out strings.Builder
	out.WriteByte('[')
	j := i + 1
	if j < len(p) && p[j] == '^' {
		out.WriteByte('^')
		j++
	}
	first := true
	for ; j < len(p); j++ {
		c := p[j]
		switch {
		case c == ']' && !first:
			out.WriteByte(']')
			return j, out.String(), nil
		case c == '[' && j+1 < len(p) && (p[j+1] == ':' || p[j+1] == '.' || p[j+1] == '='):
			end := strings.Index(p[j+2:], string(p[j+1])+"]")
			if end < 0 {
				return 0, "", breError("Unmatched [, [^, [:, [., or [=")
			}
			out.WriteString(p[j : j+2+end+2])
			j += 2 + end + 1
		case c == '\\' || c == ']' || c == '[':
			out.WriteByte('\\')
			out.WriteByte(c)
		default:
			out.WriteByte(c)
		}
		first = false
	}
	return 0, "", breError("Unmatched [, [^, [:, [., or [=")
}
