package reports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The report formats.
const (
	FormatText = "text"
	FormatCSV  = "csv"
	FormatJSON = "json"
)

// Formats lists the report formats, the default first.
func Formats() []string { return []string{FormatText, FormatCSV, FormatJSON} }

// Ext is the file extension of a format, with the dot, or "" for an unknown
// format.
func Ext(format string) string {
	switch format {
	case FormatText:
		return ".txt"
	case FormatCSV:
		return ".csv"
	case FormatJSON:
		return ".json"
	}
	return ""
}

func errFormat(format string) error {
	return fmt.Errorf("unknown report format %q (valid formats: %s)", format, strings.Join(Formats(), ", "))
}

// Render writes the report in a format: text, csv or json.
func Render(w io.Writer, r Report, format string) error {
	var b []byte
	var err error
	switch format {
	case FormatText:
		b = renderText(r)
	case FormatCSV:
		b, err = renderCSV(r)
	case FormatJSON:
		b, err = renderJSON(r)
	default:
		return errFormat(format)
	}
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// --- text ---------------------------------------------------------------------

const gutter = "  "

func renderText(r Report) []byte {
	var b strings.Builder
	b.WriteString("Device " + cleanText(r.Type) + " report\n")
	b.WriteString("Generated: " + r.Generated.UTC().Format(DateFormat) + " UTC\n")
	if r.OldestData.IsZero() {
		b.WriteString("Oldest data: none (no device was pulled)\n")
	} else {
		b.WriteString("Oldest data: " + r.OldestData.UTC().Format(DateFormat) + " UTC\n")
	}
	fmt.Fprintf(&b, "Devices: %d\n\n", r.Devices)

	cells := make([][]string, 0, len(r.Rows)+1)
	head := make([]string, len(r.Columns))
	for i, c := range r.Columns {
		head[i] = cleanText(c)
	}
	cells = append(cells, head)
	for _, row := range r.Rows {
		out := make([]string, len(row))
		for i, c := range row {
			out[i] = cleanText(c)
			if out[i] == "" {
				out[i] = "-"
			}
		}
		cells = append(cells, out)
	}
	w := make([]int, len(r.Columns))
	for _, row := range cells {
		for i, c := range row {
			if n := utf8.RuneCountInString(c); i < len(w) && n > w[i] {
				w[i] = n
			}
		}
	}
	total := len(gutter) * max(len(w)-1, 0)
	for _, n := range w {
		total += n
	}
	for i, row := range cells {
		writeTextRow(&b, row, w)
		if i == 0 {
			b.WriteString(strings.Repeat("-", total) + "\n")
		}
	}
	return []byte(b.String())
}

// writeTextRow pads every cell but the last, so a line has no trailing blanks.
func writeTextRow(b *strings.Builder, row []string, w []int) {
	for i, c := range row {
		b.WriteString(c)
		if i < len(row)-1 {
			b.WriteString(strings.Repeat(" ", w[i]-utf8.RuneCountInString(c)))
			b.WriteString(gutter)
		}
	}
	b.WriteString("\n")
}

// cleanText replaces what could move a terminal (control, C1, bidirectional
// and invalid bytes) with '?'. The text of a report is otherwise shown as the
// record keeps it.
func cleanText(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return r == utf8.RuneError || risky(r) }) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || risky(r) {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func risky(r rune) bool {
	if unicode.IsControl(r) { // C0, DEL, C1
		return true
	}
	switch {
	case r == 0x061C, r == 0x200E, r == 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	case r == 0x2028, r == 0x2029:
		return true
	}
	return false
}

// --- csv ----------------------------------------------------------------------

// guardCell keeps a spreadsheet from running a cell: one that starts with =,
// +, - or @, or with a tab or a carriage return, gets a leading single quote.
func guardCell(s string) string {
	if s != "" && strings.IndexByte("=+-@\t\r", s[0]) >= 0 {
		return "'" + s
	}
	return s
}

func renderCSV(r Report) ([]byte, error) {
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	if err := cw.Write(guardAll(r.Columns)); err != nil {
		return nil, err
	}
	for _, row := range r.Rows {
		if err := cw.Write(guardAll(row)); err != nil {
			return nil, err
		}
	}
	cw.Flush()
	return buf.Bytes(), cw.Error()
}

func guardAll(row []string) []string {
	out := make([]string, len(row))
	for i, c := range row {
		out[i] = guardCell(c)
	}
	return out
}

// --- json ---------------------------------------------------------------------

// marshal is json.Marshal without the escaping of <, > and &.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func renderJSON(r Report) ([]byte, error) {
	var c bytes.Buffer
	field := func(key string, v any, first bool) error {
		if !first {
			c.WriteByte(',')
		}
		k, err := marshal(key)
		if err != nil {
			return err
		}
		val, err := marshal(v)
		if err != nil {
			return err
		}
		c.Write(k)
		c.WriteByte(':')
		c.Write(val)
		return nil
	}
	var oldest any
	if !r.OldestData.IsZero() {
		oldest = r.OldestData.UTC().Format(time.RFC3339)
	}
	cols := r.Columns
	if cols == nil {
		cols = []string{}
	}
	c.WriteByte('{')
	for i, f := range []struct {
		k string
		v any
	}{
		{"schema", r.Schema},
		{"type", r.Type},
		{"generated", r.Generated.UTC().Format(time.RFC3339)},
		{"oldest_data", oldest},
		{"columns", cols},
	} {
		if err := field(f.k, f.v, i == 0); err != nil {
			return nil, err
		}
	}
	c.WriteString(`,"rows":[`)
	for i, obj := range r.Objects {
		if i > 0 {
			c.WriteByte(',')
		}
		c.WriteByte('{')
		for j, k := range r.Keys {
			if err := field(k, obj[k], j == 0); err != nil {
				return nil, err
			}
		}
		c.WriteByte('}')
	}
	c.WriteString("]}")
	var out bytes.Buffer
	if err := json.Indent(&out, c.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
