package ui

import (
	"strings"
	"unicode/utf8"
)

// Indent is the left margin of every table line below the title.
const Indent = "  "

// gap separates two columns.
const gap = "  "

// DetailRuleWidth is the least width of the rule under the title of a
// detail view (a block of "Key: value" lines).
const DetailRuleWidth = 44

// Col is one column of a Table: its header text and its alignment.
type Col struct {
	Head  string
	Right bool
}

// Left is a left-aligned column headed head.
func Left(head string) Col { return Col{Head: head} }

// Right is a right-aligned column headed head.
func Right(head string) Col { return Col{Head: head, Right: true} }

// Cell is one value of a row with a colour. The escape sequence wraps the
// text only; the padding that aligns the column stays outside it.
type Cell struct {
	Text  string
	Style string // one of Red, Green, Yellow, Cyan, Bold; "" for none
}

// Styled is a Cell of text in style.
func Styled(style, text string) Cell { return Cell{Text: text, Style: style} }

// Table is the one renderer of every list in tacctl:
//
//	Title (hint)
//	----------------------------   as wide as the indent and the table
//	  HEAD   HEAD   HEAD
//	  --------------------------   as wide as the table
//	  cell   cell   cell
//
// Column widths come from the header and the cells (colour codes do not
// count), columns are two spaces apart, and no line ends in a space.
type Table struct {
	Title string
	// Hint follows the title on its line (already coloured by the caller).
	Hint string
	Cols []Col
	rows [][]Cell
}

// NewTable is a table titled title with the given columns.
func NewTable(title string, cols ...Col) *Table {
	return &Table{Title: title, Cols: cols}
}

// Add appends a row. Each cell is a string or a Cell; a short row is
// padded with empty cells, extra cells are ignored.
func (t *Table) Add(cells ...any) {
	row := make([]Cell, len(t.Cols))
	for i := range row {
		if i >= len(cells) {
			break
		}
		switch v := cells[i].(type) {
		case Cell:
			row[i] = v
		case string:
			row[i] = Cell{Text: v}
		}
	}
	t.rows = append(t.rows, row)
}

// Len is the number of rows added.
func (t *Table) Len() int { return len(t.rows) }

// widths are the column widths: the widest of the header and the cells.
func (t *Table) widths() []int {
	w := make([]int, len(t.Cols))
	for i, c := range t.Cols {
		w[i] = Width(c.Head)
	}
	for _, r := range t.rows {
		for i, c := range r {
			w[i] = max(w[i], Width(c.Text))
		}
	}
	return w
}

// Width is the number of columns the text takes on a terminal: its
// characters, the colour escape sequences excluded.
func Width(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] == ';' || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			if j < len(s) && s[j] == 'm' {
				i = j + 1
				continue
			}
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		n++
		i += size
	}
	return n
}

// line is one row of cells laid out in widths w. The last non-empty cell
// ends the line: nothing after it is padded.
func (t *Table) line(cells []Cell, w []int, bold bool) string {
	last := -1
	for i, c := range cells {
		if c.Text != "" {
			last = i
		}
	}
	var b strings.Builder
	b.WriteString(Indent)
	for i := 0; i <= last; i++ {
		c := cells[i]
		text := c.Text
		if bold {
			text = Bold + text + NC
		} else if c.Style != "" {
			text = c.Style + text + NC
		}
		padn := w[i] - Width(c.Text)
		if t.Cols[i].Right {
			b.WriteString(strings.Repeat(" ", padn))
		}
		b.WriteString(text)
		if i < last {
			if !t.Cols[i].Right {
				b.WriteString(strings.Repeat(" ", padn))
			}
			b.WriteString(gap)
		}
	}
	return b.String() + "\n"
}

// String renders the table: title, rule, header, rule, rows. A table with
// no rows is the title and the header.
func (t *Table) String() string {
	w := t.widths()
	tw := len(gap) * max(len(w)-1, 0)
	for _, n := range w {
		tw += n
	}
	var b strings.Builder
	b.WriteString(Bold + t.Title + NC)
	if t.Hint != "" {
		b.WriteString(" " + t.Hint)
	}
	b.WriteString("\n" + strings.Repeat("-", len(Indent)+tw) + "\n")
	head := make([]Cell, len(t.Cols))
	for i, c := range t.Cols {
		head[i] = Cell{Text: c.Head}
	}
	b.WriteString(t.line(head, w, true))
	b.WriteString(Indent + strings.Repeat("-", tw) + "\n")
	for _, r := range t.rows {
		b.WriteString(t.line(r, w, false))
	}
	return b.String()
}

// Rule is the underline of a detail view titled title: DetailRuleWidth
// dashes, or as many as the title when that is longer.
func Rule(title string) string {
	return strings.Repeat("-", max(DetailRuleWidth, Width(title)))
}
