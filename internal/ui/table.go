package ui

import "strings"

// Column is one column of a Table, a printf field of the bash listings:
// '%-20s' is Width 20 left-aligned, '%5s' is Width 5 right-aligned, a plain
// '%s' is Width 0.
type Column struct {
	// Width is the minimum field width in bytes (printf pads by bytes, not
	// characters; names are ASCII). 0 means no padding.
	Width int
	// Right aligns the text to the right edge of the field.
	Right bool
	// Gap is the number of spaces printed before the column; ignored for
	// the first column.
	Gap int
}

// L is a left-aligned column of the given width, one space after the
// previous column ('%-Ns' after ' ').
func L(width int) Column { return Column{Width: width, Gap: 1} }

// R is a right-aligned column ('%Ns' after ' ').
func R(width int) Column { return Column{Width: width, Right: true, Gap: 1} }

// WithGap returns the column with n spaces before it (the listings use two
// before some columns).
func (c Column) WithGap(n int) Column { c.Gap = n; return c }

// Cell is one value of a Row with a colour: the escape sequence wraps the
// padded field, as in 'printf "%s${color}%-8s${NC}"'.
type Cell struct {
	Text  string
	Style string // one of Red, Green, Yellow, Cyan, Bold; "" for none
}

// Styled is a Cell of text in style.
func Styled(style, text string) Cell { return Cell{Text: text, Style: style} }

// Table formats the printf-width listings of the bash code (user list,
// group list, scope list, backend list, ...): an indented bold header line,
// then rows of padded columns. Header and Row return the finished line
// including the newline, byte-identical to the printf the bash used.
type Table struct {
	// Indent is printed at the start of every line; NewTable sets the two
	// spaces every listing uses.
	Indent string
	Cols   []Column
}

// NewTable is a Table with the usual two-space indent.
func NewTable(cols ...Column) Table { return Table{Indent: "  ", Cols: cols} }

// Header is the title line: 'printf "  ${BOLD}%-20s %-15s${NC}\n" ...'. The
// whole row, padding included, is bold.
func (t Table) Header(titles ...string) string {
	cells := make([]any, len(titles))
	for i, s := range titles {
		cells[i] = s
	}
	var b strings.Builder
	b.WriteString(t.Indent)
	b.WriteString(Bold)
	b.WriteString(t.fields(cells))
	b.WriteString(NC)
	b.WriteByte('\n')
	return b.String()
}

// Row is one data line. Each cell is a string or a Cell; cells beyond the
// columns are an error of the caller and are ignored, missing cells end the
// line early.
func (t Table) Row(cells ...any) string {
	return t.Indent + t.fields(cells) + "\n"
}

func (t Table) fields(cells []any) string {
	var b strings.Builder
	for i, c := range cells {
		if i >= len(t.Cols) {
			break
		}
		col := t.Cols[i]
		if i > 0 {
			b.WriteString(strings.Repeat(" ", col.Gap))
		}
		var cell Cell
		switch v := c.(type) {
		case Cell:
			cell = v
		case string:
			cell = Cell{Text: v}
		}
		field := pad(cell.Text, col.Width, col.Right)
		if cell.Style != "" {
			b.WriteString(cell.Style + field + NC)
		} else {
			b.WriteString(field)
		}
	}
	return b.String()
}

// pad is printf's %-Ns / %Ns: the text, padded with spaces to width bytes.
func pad(s string, width int, right bool) string {
	n := width - len(s)
	if n <= 0 {
		return s
	}
	if right {
		return strings.Repeat(" ", n) + s
	}
	return s + strings.Repeat(" ", n)
}

// Pad is printf '%-Ns' of s: padded on the right to width bytes, never
// truncated.
func Pad(s string, width int) string { return pad(s, width, false) }

// PadLeft is printf '%Ns' of s: padded on the left to width bytes.
func PadLeft(s string, width int) string { return pad(s, width, true) }
