package radius

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/ui"
)

const rule = "--------------------------------------------"

// Log is backend_radius_log: 'tacctl log <sub>' for this daemon, written to
// w. tail shows the auth log and the daemon log, search greps both, failures
// are the last 24 hours' rejects, clear truncates the three logs after a
// yes. Any other sub-command is ErrUnsupported and writes nothing.
func (m *Module) Log(_ context.Context, sub string, args []string, w io.Writer) error {
	out := ui.Output{Stdout: w, Stderr: m.env.Out.Stderr}
	switch sub {
	case "tail":
		return m.logTail(w, arg(args, 0, "20"))
	case "search":
		return m.logSearch(w, arg(args, 0, ""))
	case "failures":
		echo(w, "")
		echo(w, ui.Bold+"RADIUS Authentication Failures (last 24 hours)"+ui.NC)
		echo(w, rule)
		var failures []string
		for _, l := range m.authRecent() {
			if strings.Contains(l, " Access-Reject ") {
				failures = append(failures, l)
			}
		}
		if len(failures) > 0 {
			_, _ = io.WriteString(w, strings.Join(failures, "\n")+"\n")
		} else {
			echo(w, "  "+ui.Green+"No failures in the last 24 hours"+ui.NC)
		}
		echo(w, "")
		return nil
	case "clear":
		m.logClear(out, arg(args, 0, ""))
		return nil
	}
	return backend.ErrUnsupported
}

// arg is "${n:-def}": the argument, or def when it is absent or empty.
func arg(args []string, i int, def string) string {
	if i < len(args) && args[i] != "" {
		return args[i]
	}
	return def
}

// logTail is the 'tail' of backend_radius_log.
func (m *Module) logTail(w io.Writer, count string) error {
	echo(w, "")
	echo(w, ui.Bold+"Recent RADIUS Authentications"+ui.NC+" ("+m.L.AuthLog+")")
	echo(w, rule)
	if nonEmpty(m.L.AuthLog) {
		if err := m.tail(w, m.L.AuthLog, count); err != nil {
			return err
		}
	} else {
		echo(w, "  No log entries found.")
	}
	if nonEmpty(m.L.DaemonLog) {
		echo(w, "")
		echo(w, ui.Bold+"FreeRADIUS Daemon Log"+ui.NC+" ("+m.L.DaemonLog+")")
		echo(w, rule)
		if err := m.tail(w, m.L.DaemonLog, count); err != nil {
			return err
		}
	}
	echo(w, "")
	return nil
}

// nonEmpty is bash's -s.
func nonEmpty(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Size() > 0
}

// logSearch is the 'search' of backend_radius_log: a case-insensitive
// grep (a basic regular expression, as 'grep -i -e') over the auth log and
// the daemon log.
func (m *Module) logSearch(w io.Writer, term string) error {
	if term == "" {
		m.env.Out.Error("Usage: tacctl log search <username>")
		return backend.ErrFailed
	}
	echo(w, "")
	echo(w, ui.Bold+"RADIUS log entries matching '"+term+"'"+ui.NC)
	echo(w, rule)
	re, err := compileBRE(term)
	if err != nil {
		_, _ = fmt.Fprintln(m.env.Out.Stderr, "grep: "+err.Error())
	}
	found := false
	for _, f := range []string{m.L.AuthLog, m.L.DaemonLog} {
		if err != nil {
			break
		}
		if grepFile(w, f, re) {
			found = true
		}
	}
	if !found {
		echo(w, "  No matches found.")
	}
	echo(w, "")
	return nil
}

// grepFile writes the lines of the file that match, and reports whether any
// did. A file that cannot be read has none.
func grepFile(w io.Writer, path string, re *regexp.Regexp) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	found := false
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			line = strings.TrimSuffix(line, "\n")
			if re.MatchString(line) {
				found = true
				_, _ = io.WriteString(w, line+"\n")
			}
		}
		if err != nil {
			return found
		}
	}
}

// logClear is _radius_log_clear: truncate the three logs in place (the
// daemon keeps writing to the same files), after a yes unless forced.
func (m *Module) logClear(out ui.Output, flag string) {
	force := flag == "-y" || flag == "--force" || flag == "--yes"
	w := out.Stdout
	echo(w, "")
	echo(w, ui.Bold+"Clear RADIUS logs"+ui.NC)
	echo(w, rule)
	out.Warn("This truncates " + m.L.AuthLog + ", " + m.L.AcctLog + " and " + m.L.DaemonLog + ".")
	out.Warn("Historical authentication and accounting records will be lost.")
	if !force {
		var in io.Reader = strings.NewReader("")
		if m.env.Stdin != nil {
			in = m.env.Stdin
		}
		if !ui.NewPrompter(in, m.env.Out).Confirm("  Continue? [y/N]: ") {
			out.Info("Cancelled.")
			return
		}
	}
	for _, f := range []string{m.L.AuthLog, m.L.AcctLog, m.L.DaemonLog} {
		if !isFile(f) {
			continue
		}
		fh, err := os.OpenFile(f, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			out.Warn("Could not truncate " + f + " (check permissions).")
			continue
		}
		_ = fh.Close()
	}
	out.Info("RADIUS logs cleared.")
	echo(w, "")
}

// Accounting is backend_radius_accounting: the last <n> records of the
// detail file (a record is a paragraph). Only the sub-command tail exists.
func (m *Module) Accounting(_ context.Context, sub string, args []string, w io.Writer) error {
	if sub != "tail" {
		return backend.ErrUnsupported
	}
	count := arg(args, 0, "20")
	echo(w, "")
	echo(w, ui.Bold+"Recent RADIUS Accounting Records"+ui.NC)
	echo(w, rule)
	if isFile(m.L.AcctLog) {
		data, err := os.ReadFile(m.L.AcctLog)
		if err == nil {
			_, _ = io.WriteString(w, lastParagraphs(string(data), count))
		}
	} else {
		echo(w, "  No accounting log found at "+m.L.AcctLog)
	}
	echo(w, "")
	return nil
}

var reBlankRuns = regexp.MustCompile(`\n\n+`)

// lastParagraphs is the awk program of backend_radius_accounting: records
// are separated by blank lines (leading and trailing newlines are not part
// of any), and the last n are printed, each followed by an empty line. n is
// awk's: a number (the start is then NR-n+1, a fractional start finds no
// record and prints an empty one), or a string, which compares above every
// record number so that all records print.
func lastParagraphs(text, count string) string {
	text = strings.Trim(text, "\n")
	if text == "" {
		return ""
	}
	recs := reBlankRuns.Split(text, -1)
	nr := float64(len(recs))
	n, numeric := awkStrnum(count)
	start := 1.0
	if numeric && nr > n {
		start = nr - n + 1
	}
	var b strings.Builder
	for i := start; i <= nr; i++ {
		if i == float64(int64(i)) && i >= 1 {
			b.WriteString(recs[int(i)-1])
		}
		b.WriteString("\n\n")
	}
	return b.String()
}

// awkStrnum reports whether an awk -v value looks like a number (a "strnum"),
// and which.
func awkStrnum(s string) (float64, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// LastLogin is _radius_last_login: 'YYYY-MM-DD HH:MM:SS' of the user's last
// Access-Accept, or "never". An accepted line ends in ' user=<name>', and
// only a request whose User-Name is exactly a user of the store is ever
// accepted.
func (m *Module) LastLogin(_ context.Context, username string) (string, error) {
	f, err := os.Open(m.L.AuthLog)
	if err != nil {
		return "never", nil
	}
	defer func() { _ = f.Close() }()
	want := "user=" + username
	last := ""
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			line = strings.TrimSuffix(line, "\n")
			if strings.Contains(line, " Access-Accept ") && strings.Contains(line, " "+want) {
				if fl := awkFields(line); len(fl) > 0 && fl[len(fl)-1] == want {
					last = line
				}
			}
		}
		if err != nil {
			break
		}
	}
	if last == "" {
		return "never", nil
	}
	if utf8.RuneCountInString(last) > 19 {
		last = string([]rune(last)[:19])
	}
	return last, nil
}

// --- tail ---------------------------------------------------------------------

// tail is 'tail -n <count> <path>': count is the argument as given, N (the
// last N lines), +N (from line N on) or -N (the last N). Anything else is
// refused as GNU tail does, and the command fails.
func (m *Module) tail(w io.Writer, path, count string) error {
	plus := strings.HasPrefix(count, "+")
	digits := strings.TrimLeft(count, "+-")
	n, err := strconv.ParseUint(digits, 10, 63)
	if err != nil || digits == "" || len(count)-len(digits) > 1 {
		_, _ = fmt.Fprintln(m.env.Out.Stderr, "tail: invalid number of lines: '"+count+"'")
		return backend.ErrFailed
	}
	f, err := os.Open(path)
	if err != nil {
		_, _ = fmt.Fprintln(m.env.Out.Stderr, "tail: cannot open '"+path+"' for reading: "+errText(err))
		return backend.ErrFailed
	}
	defer func() { _ = f.Close() }()
	if plus {
		return tailFrom(w, f, n)
	}
	return tailLast(w, f, n)
}

// errText is the C library's wording of a file error ("No such file or
// directory").
func errText(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		err = pe.Err
	}
	s := err.Error()
	if s != "" {
		return strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// tailFrom writes the file from line n on (n is 1-based; 0 is 1).
func tailFrom(w io.Writer, f *os.File, n uint64) error {
	r := bufio.NewReader(f)
	var line uint64
	for {
		text, err := r.ReadString('\n')
		if text != "" {
			line++
			if line >= max(n, 1) {
				if _, werr := io.WriteString(w, text); werr != nil {
					return werr
				}
			}
		}
		if err != nil {
			return nil
		}
	}
}

// tailLast writes the last n lines of the file, found by reading backwards.
func tailLast(w io.Writer, f *os.File, n uint64) error {
	if n == 0 {
		return nil
	}
	st, err := f.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	if size == 0 {
		return nil
	}
	const block = 64 * 1024
	buf := make([]byte, block)
	// The last byte's newline ends the last line; it does not start another.
	var one [1]byte
	if _, err := f.ReadAt(one[:], size-1); err != nil {
		return err
	}
	pos := size
	if one[0] == '\n' {
		pos--
	}
	start := int64(0)
	var seen uint64
scan:
	for pos > 0 {
		chunk := min(int64(block), pos)
		pos -= chunk
		if _, err := f.ReadAt(buf[:chunk], pos); err != nil && err != io.EOF {
			return err
		}
		for i := chunk - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				seen++
				if seen == n {
					start = pos + i + 1
					break scan
				}
			}
		}
	}
	_, err = io.Copy(w, io.NewSectionReader(f, start, size-start))
	return err
}
