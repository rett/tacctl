package shell

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// HistoryMax is how many lines the history keeps, in memory and on disk.
const HistoryMax = 1000

// RedactedMark replaces what redaction removed from a line. A line that
// carries it is refused (Shell.run): recalling a redacted line and pressing
// Enter must not set a secret to the mark.
const RedactedMark = "…(redacted)"

// History is the shell's line history: term.History for the line editor
// (Up, Down, Ctrl-R), kept in memory and, when it has a file, appended to
// that file (0600, the newest HistoryMax lines). Every line is stored
// redacted (Redact) and escaped (one line per entry), in memory as on
// disk: a secret typed at the prompt is never recalled or written.
type History struct {
	path  string
	lines []string // oldest first
	// skip, when set, is asked before a line is added: the editor skips a
	// line ended by Ctrl-C.
	skip func() bool
	// warn receives one message when the file cannot be written.
	warn   io.Writer
	warned bool
}

// NewHistory is a history kept in path ("" keeps it in memory only), with
// the newest HistoryMax lines of an existing file loaded. A file that
// cannot be read is an empty history.
func NewHistory(path string, warn io.Writer) *History {
	h := &History{path: path, warn: warn}
	if path == "" {
		return h
	}
	f, err := os.Open(path)
	if err != nil {
		return h
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if l := sc.Text(); l != "" {
			h.lines = append(h.lines, l)
		}
	}
	if n := len(h.lines); n > HistoryMax {
		h.lines = h.lines[n-HistoryMax:]
	}
	return h
}

// Add records line: term.History's Add, called for every line the editor
// returns. Blank lines, lines ended by Ctrl-C and a repeat of the newest
// entry are not recorded.
func (h *History) Add(line string) {
	if strings.TrimSpace(line) == "" || (h.skip != nil && h.skip()) {
		return
	}
	entry := escapeEntry(Redact(line))
	if n := len(h.lines); n > 0 && h.lines[n-1] == entry {
		return
	}
	h.lines = append(h.lines, entry)
	trimmed := false
	if n := len(h.lines); n > HistoryMax {
		h.lines = h.lines[n-HistoryMax:]
		trimmed = true
	}
	if h.path != "" {
		h.report(h.save(entry, trimmed))
	}
}

// Len is term.History's Len.
func (h *History) Len() int { return len(h.lines) }

// At is term.History's At: 0 is the newest entry.
func (h *History) At(i int) string { return h.lines[len(h.lines)-1-i] }

// Entries are the entries, oldest first.
func (h *History) Entries() []string { return append([]string(nil), h.lines...) }

// save appends entry to the file, or rewrites the file with the kept lines
// when the oldest had to go. The directory is made 0700 and the file 0600
// (an existing file is set to 0600).
func (h *History) save(entry string, rewrite bool) error {
	if err := os.MkdirAll(filepath.Dir(h.path), 0o700); err != nil {
		return err
	}
	if !rewrite {
		f, err := os.OpenFile(h.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		_ = f.Chmod(0o600)
		_, err = io.WriteString(f, entry+"\n")
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(h.path), ".history.*")
	if err != nil {
		return err
	}
	_, err = io.WriteString(tmp, strings.Join(h.lines, "\n")+"\n")
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), h.path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}

func (h *History) report(err error) {
	if err == nil || h.warned || h.warn == nil {
		return
	}
	h.warned = true
	_, _ = fmt.Fprintf(h.warn, "tacctl shell: history not saved: %v\n", err)
}

// escapeEntry makes line one printable line: a newline is '\n', a carriage
// return '\r', a tab '\t', any other control character '\xNN'.
func escapeEntry(line string) string {
	var b strings.Builder
	for _, r := range line {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Redact is the line as the history stores it. Everything from the first
// value that may be a secret on is replaced by RedactedMark:
//
//   - after '--secret', '--hash' or '--password' ('--secret=<v>' keeps the
//     name);
//   - after 'set' in 'secret … set …' ('scope secret lab set x' is stored as
//     'scope secret lab set …(redacted)');
//   - after 'import' when a value follows it;
//   - after the first word of a 'passwd' line that has more words, and
//     'passwd' itself is stored as 'passwd …(redacted)'.
//
// The kept words are written so that Tokenize reads them back unchanged. A
// line that does not tokenize is judged by its blank-separated fields.
func Redact(line string) string {
	toks, err := Tokenize(line)
	if err != nil {
		toks = strings.Fields(line)
	}
	if len(toks) == 0 {
		return line
	}
	keep := redactAt(toks)
	if keep < 0 {
		return line
	}
	kept := make([]string, 0, keep+2)
	for _, t := range toks[:keep] {
		kept = append(kept, Quote(t))
	}
	out := strings.Join(kept, " ")
	if strings.HasSuffix(out, "=") {
		return out + RedactedMark
	}
	return out + " " + RedactedMark
}

// redactAt is how many leading words a line keeps before RedactedMark, or
// -1 when it is kept whole.
func redactAt(toks []string) int {
	if toks[0] == "passwd" {
		return 1
	}
	for i, t := range toks {
		name, _, hasVal := strings.Cut(t, "=")
		switch {
		case name == "--secret" || name == "--hash" || name == "--password":
			if hasVal {
				toks[i] = name + "="
			}
			return i + 1
		case t == "secret":
			for j := i + 1; j < len(toks); j++ {
				if toks[j] == "set" {
					return j + 1
				}
			}
		case t == "import" && i+1 < len(toks):
			return i + 1
		}
	}
	return -1
}
