package reports

import (
	"regexp"
	"strings"
	"testing"
)

// hostile is a fleet whose text tries every way into the document: markup, a
// style, a script, an include, a control character, a direction override and
// an invalid byte.
func hostile() []Device {
	return []Device{
		{Name: "sw1", Address: "192.0.2.11", Vendor: "cisco", Scope: "site-a",
			Model: "<script>alert(1)</script>", Serial: "SN000001", Release: "16.12.4",
			Location:    "\"><img src=http://example.net/x.png>",
			Description: "@import 'x.css'; <link rel=stylesheet href=//example.net/a.css>",
			Pulled:      at(6, 7, 45), ConfigState: "ok"},
		{Name: "jsw1", Address: "192.0.2.10", Vendor: "juniper", Scope: "site-a",
			Model: "a&b\x1b[31m\x07\u202e", Serial: "SN\xff000002", Release: "21.4R3-S5.4",
			Location: "<style>*{background:url(http://example.net/b.png)}</style>", Pulled: at(6, 7, 30), ConfigState: "ok"},
	}
}

func hostileReport(t *testing.T, typ string) Report {
	t.Helper()
	r, err := Build(typ, hostile(), now)
	if err != nil {
		t.Fatal(err)
	}
	r.Filters = map[string]string{"scope": "site-a\"><b>", "vendor": "cisco"}
	return r
}

// The document is escaped everywhere and holds no reference to anything
// outside it: the tool that renders it has nothing to fetch.
func TestRenderHTMLHasNoExternalReference(t *testing.T) {
	tags := regexp.MustCompile(`<([a-zA-Z0-9!]+)`)
	for _, typ := range Types() {
		doc := string(RenderHTML(hostileReport(t, typ)))
		low := strings.ToLower(doc)
		// the reference words of markup and of a style: a tag or an
		// attribute would hold them bare; in a cell they are escaped
		for _, bad := range []string{"<link", "<img", "<script", "<iframe", "<object", "<embed", "<base", "<form", "<a ", "<svg", "<video", "<audio", "<source", "<input", "<meta http", "<meta content", "@import", "@font-face", "url(", " src=", " href=", "http://", "https://", "xlink:"} {
			if strings.Contains(low, bad) && !onlyInCells(doc, bad) {
				t.Errorf("%s: the document holds %q outside the text of a cell:\n%s", typ, bad, doc)
			}
		}
		// no element but the document's own
		for _, m := range tags.FindAllStringSubmatch(doc, -1) {
			switch m[1] {
			case "!DOCTYPE", "html", "head", "meta", "title", "style", "body", "h1", "div", "span", "table", "thead", "tbody", "tr", "th", "td":
			default:
				t.Errorf("%s: unexpected element <%s>", typ, m[1])
			}
		}
		// the style block is the document's own text and holds none of them
		style := doc[strings.Index(doc, "<style>") : strings.Index(doc, "</style>")+len("</style>")]
		for _, bad := range []string{"@import", "url(", "src:", "@font-face", "http"} {
			if strings.Contains(strings.ToLower(style), bad) {
				t.Errorf("%s: the style holds %q", typ, bad)
			}
		}
	}
}

// onlyInCells says whether every occurrence of word in the document lies in
// text that came from the hostile fleet, that is outside the document's own
// markup: with the cells' text escaped, the markup characters of a tag cannot
// be there, so a "<"-word is never in a cell, and a word of a style or an
// attribute is, at most, plain text.
func onlyInCells(doc, word string) bool {
	if strings.HasPrefix(word, "<") {
		return false // a bare '<' is always markup
	}
	// outside the style, every occurrence must be one of the text: the
	// text is what is left when the tags are taken out
	rest := regexp.MustCompile(`(?s)<style>.*?</style>`).ReplaceAllString(doc, "")
	text := regexp.MustCompile(`<[^>]*>`).ReplaceAllString(rest, "")
	return strings.Count(strings.ToLower(rest), word) == strings.Count(strings.ToLower(text), word)
}

func TestRenderHTMLEscapesCells(t *testing.T) {
	// the break opportunities of a long word are not part of the escaping
	doc := strings.ReplaceAll(string(RenderHTML(hostileReport(t, TypeInventory))), zwsp, "")
	for _, want := range []string{
		"&lt;script&gt;alert(1)&lt;/script&gt;",
		"a&amp;b",
		"&#34;&gt;&lt;img src=http://example.net/x.png&gt;",
		"SN?000002", // the invalid byte is a '?'
		"<span class=\"k\">Filters</span>scope=site-a&#34;&gt;&lt;b&gt;, vendor=cisco</div>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("no %q in:\n%s", want, doc)
		}
	}
	for _, ch := range []string{"\x1b", "\x07", "\u202e", "\xff"} {
		if strings.Contains(doc, ch) {
			t.Errorf("the document holds %q", ch)
		}
	}
	for _, tag := range []string{"<script", "<img", "<link"} {
		if strings.Contains(doc, tag) {
			t.Errorf("a %s tag came through:\n%s", tag, doc)
		}
	}
}

func TestRenderHTMLStyle(t *testing.T) {
	for _, want := range []string{
		"size: letter landscape; margin: 14mm;",
		"@bottom-center { content: counter(page) \" / \" counter(pages)",
		"thead { display: table-header-group }",
		"tr { page-break-inside: avoid }",
		"word-break: break-word",
		"8pt \"DejaVu Sans\"",
		"\"DejaVu Sans Mono\"",
		"nth-child(even)",
	} {
		if !strings.Contains(pdfCSS, want) {
			t.Errorf("the style lacks %q", want)
		}
	}
}

// The title block, the columns and the rows are the report's own.
func TestRenderHTMLCarriesTheReport(t *testing.T) {
	r := mustBuild(t, TypeMembers)
	r.Filters = map[string]string{"scope": "site-a", "vendor": "juniper"}
	doc := string(RenderHTML(r))
	for _, want := range []string{
		"<title>Device members report</title>",
		"<h1>Device members report</h1>",
		"<div><span class=\"k\">Generated</span>2026-11-06 09:30 UTC</div>",
		"<div><span class=\"k\">Filters</span>scope=site-a, vendor=juniper</div>",
		"<div><span class=\"k\">Oldest data</span>2026-11-03 22:10 UTC</div>",
		"<th>device</th><th>member</th><th>role</th><th>model</th><th>serial</th><th>release</th><th>status</th><th>priority</th><th>pulled</th>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("no %q in:\n%s", want, doc)
		}
	}
	// one <tr> for the header, one for each row
	if got := strings.Count(doc, "<tr>") - 1; got != len(r.Rows) {
		t.Errorf("%d body rows, want %d", got, len(r.Rows))
	}
	if !strings.Contains(doc, "<td class=\"mono\">SN000001</td>") || !strings.Contains(doc, "<td>jsw1</td>") {
		t.Errorf("mono and plain cells:\n%s", doc)
	}
	// no filter and no rows
	e, err := Build(TypeInventory, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	empty := string(RenderHTML(e))
	for _, want := range []string{"<span class=\"k\">Filters</span>none</div>", "<span class=\"k\">Oldest data</span>none (no device was pulled)</div>", "<span class=\"k\">Rows</span>0</div>", "<tbody>\n</tbody>"} {
		if !strings.Contains(empty, want) {
			t.Errorf("no %q in:\n%s", want, empty)
		}
	}
}

func TestRenderHTMLEmptyCellIsADash(t *testing.T) {
	if doc := string(RenderHTML(mustBuild(t, TypeInventory))); !strings.Contains(doc, "<td>-</td>") {
		t.Errorf("no dash for an empty cell:\n%s", doc)
	}
}

// A word wider than a column does not break by itself in the tool, so a long
// word gets a break opportunity after every 24 characters, never inside an
// escape; a short word, and a word with spaces, are left as they are, and a
// long value of the monospaced face is set in the plain face so that it can
// wrap.
func TestRenderHTMLBreaksLongWords(t *testing.T) {
	devs := []Device{{Name: "sw1", Address: "192.0.2.11", Vendor: "cisco", Scope: "site-a", Serial: "SN000001", Release: "16.12.4",
		Location: strings.Repeat("&", 30), Description: strings.Repeat("x", 50) + " short words " + strings.Repeat("y", 24),
		Model: "WS-C3850-24T"}}
	r, err := Build(TypeInventory, devs, now)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(RenderHTML(r))
	for _, want := range []string{
		"<td>" + strings.Repeat("x", 24) + zwsp + strings.Repeat("x", 24) + zwsp + "xx short words " + strings.Repeat("y", 24) + "</td>",
		"<td>" + strings.Repeat("&amp;", 24) + zwsp + strings.Repeat("&amp;", 6) + "</td>",
		"<td>WS-C3850-24T</td>",
		"<td class=\"mono\">192.0.2.11</td>",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("no %q in:\n%s", want, doc)
		}
	}
	// a long identifier is not held in one piece: it is in the plain face and breaks
	devs[0].Release = strings.Repeat("r", 60)
	r, _ = Build(TypeInventory, devs, now)
	doc = string(RenderHTML(r))
	if !strings.Contains(doc, "<td>"+strings.Repeat("r", 24)+zwsp+strings.Repeat("r", 24)+zwsp+strings.Repeat("r", 12)+"</td>") {
		t.Errorf("a long release:\n%s", doc)
	}
	if strings.Contains(doc, "class=\"mono\">"+strings.Repeat("r", 10)) {
		t.Error("a long release in the monospaced face")
	}
}
