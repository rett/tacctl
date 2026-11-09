package reports

import (
	"html"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FormatPDF is the report as a PDF document. The PDF is made by an external
// tool from the HTML of RenderHTML; this package only builds the HTML, so it
// still imports nothing but the standard library.
const FormatPDF = "pdf"

// monoColumns are the columns whose cells are numbers, dates, addresses and
// identifiers: they are set in the monospaced face.
var monoColumns = map[string]bool{
	"address": true, "serial": true, "release": true, "members": true, "member": true,
	"priority": true, "pulled": true, "applied": true,
}

// pdfCSS is the whole style of the document. It refers to nothing outside
// itself: no @import, no url(), no font file, only the faces the system has.
const pdfCSS = `@page { size: letter landscape; margin: 14mm; @bottom-center { content: counter(page) " / " counter(pages); font: 8pt "DejaVu Sans", sans-serif; color: #555555 } }
html { font: 8pt "DejaVu Sans", sans-serif; color: #111111 }
body { margin: 0 }
h1 { font-size: 14pt; margin: 0 0 4pt 0 }
.facts { margin: 0 0 10pt 0 }
.k { display: inline-block; width: 64pt; font-weight: bold }
table { border-collapse: collapse; width: 100% }
thead { display: table-header-group }
th { text-align: left; background: #dde3ea; border-bottom: 1pt solid #666666; padding: 2pt 4pt }
td { padding: 2pt 4pt; vertical-align: top; word-break: break-word }
tr { page-break-inside: avoid }
tbody tr:nth-child(even) td { background: #f3f5f7 }
.mono { font-family: "DejaVu Sans Mono", monospace; white-space: nowrap }
`

// Long words. The tool does not break a word that is wider than its column
// (word-break: break-word is not enough for it, and overflow-wrap: anywhere
// makes it narrow every column and about four times slower), so a word longer
// than wordMax characters gets a zero-width space after every wordMax
// characters, where it may break; a value in the monospaced face that is
// longer than monoMax is set in the plain face, so that it can wrap too (the
// others do not wrap, which keeps an address or a date in one piece).
const (
	wordMax = 24
	monoMax = 40
	// zwsp is the zero-width space as the document writes it.
	zwsp = "&#8203;"
)

// plainHTMLText is s with the characters a PDF has no use for dropped (control, C1,
// bidirectional and line-separator characters) and an invalid byte shown as a
// '?'; it is not escaped yet.
func plainHTMLText(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteByte('?')
		case risky(r):
			// dropped
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// htmlText is s as the HTML document carries it: cleaned and escaped.
func htmlText(s string) string { return html.EscapeString(plainHTMLText(s)) }

// softHTMLText is htmlText with a break opportunity after every wordMax
// characters of a word that holds no space.
func softHTMLText(s string) string {
	var b strings.Builder
	run := 0
	for _, r := range plainHTMLText(s) {
		if unicode.IsSpace(r) {
			run = 0
		} else if run++; run > wordMax {
			b.WriteString(zwsp)
			run = 1
		}
		b.WriteString(html.EscapeString(string(r)))
	}
	return b.String()
}

// filtersText is the filters of the command in key order, "none" for none.
func filtersText(f map[string]string) string {
	var parts []string
	for _, k := range []string{"scope", "vendor"} {
		if v, ok := f[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// RenderHTML is the report as one self-contained HTML document, the input of
// the PDF tool: a title block (the type, when it was made, the filters, the
// date of the oldest datum and the counts), then a table with the columns of
// the report that repeats its header on each page. Every cell is escaped, and
// the document has no link, image, script, style sheet or font reference: the
// tool has nothing to fetch.
func RenderHTML(r Report) []byte {
	var b strings.Builder
	title := "Device " + htmlText(r.Type) + " report"
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>" + title + "</title>\n<style>\n")
	b.WriteString(pdfCSS)
	b.WriteString("</style>\n</head>\n<body>\n<h1>" + title + "</h1>\n<div class=\"facts\">\n")
	row := func(k, v string) { b.WriteString("<div><span class=\"k\">" + k + "</span>" + htmlText(v) + "</div>\n") }
	row("Generated", r.Generated.UTC().Format(DateFormat)+" UTC")
	row("Filters", filtersText(r.Filters))
	if r.OldestData.IsZero() {
		row("Oldest data", "none (no device was pulled)")
	} else {
		row("Oldest data", r.OldestData.UTC().Format(DateFormat)+" UTC")
	}
	row("Devices", strconv.Itoa(r.Devices))
	row("Rows", strconv.Itoa(len(r.Rows)))
	b.WriteString("</div>\n<table>\n<thead>\n<tr>")
	for _, c := range r.Columns {
		b.WriteString("<th>" + htmlText(c) + "</th>")
	}
	b.WriteString("</tr>\n</thead>\n<tbody>\n")
	for _, cells := range r.Rows {
		b.WriteString("<tr>")
		for i, c := range cells {
			clean := plainHTMLText(c)
			if clean == "" {
				clean = "-"
			}
			if i < len(r.Columns) && monoColumns[r.Columns[i]] && utf8.RuneCountInString(clean) <= monoMax {
				b.WriteString("<td class=\"mono\">" + html.EscapeString(clean) + "</td>")
			} else {
				b.WriteString("<td>" + softHTMLText(clean) + "</td>")
			}
		}
		b.WriteString("</tr>\n")
	}
	b.WriteString("</tbody>\n</table>\n</body>\n</html>\n")
	return []byte(b.String())
}
