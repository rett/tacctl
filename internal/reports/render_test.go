package reports

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

var update = flag.Bool("update", false, "rewrite internal/reports/testdata")

func render(t *testing.T, r Report, format string) string {
	t.Helper()
	var b bytes.Buffer
	if err := Render(&b, r, format); err != nil {
		t.Fatalf("Render %s %s: %v", r.Type, format, err)
	}
	return b.String()
}

func mustBuild(t *testing.T, typ string) Report {
	t.Helper()
	r, err := Build(typ, fixture(), now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGoldens(t *testing.T) {
	for _, typ := range Types() {
		r := mustBuild(t, typ)
		for _, f := range Formats() {
			t.Run(typ+Ext(f), func(t *testing.T) {
				got := render(t, r, f)
				p := filepath.Join("testdata", typ+Ext(f))
				if *update {
					if err := os.MkdirAll("testdata", 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
					return
				}
				want, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("%v (go test ./internal/reports -run %s -update writes it)", err, t.Name())
				}
				if got != string(want) {
					t.Errorf("%s differs from its golden:\n--- got\n%s\n--- want\n%s", p, got, want)
				}
			})
		}
	}
}

func TestRenderUnknownFormat(t *testing.T) {
	r := mustBuild(t, TypeInventory)
	var b bytes.Buffer
	err := Render(&b, r, "pdf")
	if err == nil {
		t.Fatal("unknown format accepted")
	}
	for _, w := range []string{`"pdf"`, "text", "csv", "json"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not mention %s", err, w)
		}
	}
	if b.Len() != 0 {
		t.Error("something was written")
	}
}

func TestExt(t *testing.T) {
	if Ext("text") != ".txt" || Ext("csv") != ".csv" || Ext("json") != ".json" || Ext("pdf") != "" {
		t.Error("Ext")
	}
}

func TestTextLayout(t *testing.T) {
	r := mustBuild(t, TypeConfig)
	lines := strings.Split(render(t, r, "text"), "\n")
	want := []string{
		"Device config report",
		"Generated: 2026-11-06 09:30 UTC",
		"Oldest data: 2026-11-03 22:10 UTC",
		"Devices: 7",
		"",
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("line %d = %q, want %q", i, lines[i], w)
		}
	}
	head, rule := lines[5], lines[6]
	if strings.Trim(rule, "-") != "" || len(rule) == 0 {
		t.Errorf("rule = %q", rule)
	}
	// Columns line up: every line starts its second column where the header does.
	col := len([]rune(head[:strings.Index(head, "scope")]))
	for _, line := range lines[7 : len(lines)-1] {
		l := []rune(line)
		if len(l) <= col || l[col-1] != ' ' || l[col-2] != ' ' {
			t.Errorf("column 2 of %q is not at %d", l, col)
		}
		if line != strings.TrimRight(line, " ") {
			t.Errorf("trailing blank in %q", line)
		}
	}
	if lines[len(lines)-1] != "" {
		t.Error("no final newline")
	}
}

// An empty cell is shown as "-" in the text format only.
func TestEmptyCell(t *testing.T) {
	r := mustBuild(t, TypeSoftware)
	if out := render(t, r, "text"); !strings.Contains(out, "rtr1   junos   MX204         22.2R1.9     -      2026-11-03 22:10\n") {
		t.Errorf("text lost the placeholder:\n%s", out)
	}
	if out := render(t, r, "csv"); !strings.Contains(out, "rtr1,junos,MX204,22.2R1.9,,2026-11-03 22:10\n") {
		t.Errorf("csv lost the empty cell:\n%s", out)
	}
	if out := render(t, r, "json"); !strings.Contains(out, `"gate": ""`) {
		t.Errorf("json lost the empty cell:\n%s", out)
	}
}

func TestTextNoPulls(t *testing.T) {
	r, _ := Build(TypeInventory, []Device{{Name: "sw1"}}, now)
	out := render(t, r, "text")
	if !strings.Contains(out, "Oldest data: none (no device was pulled)\n") {
		t.Errorf("header:\n%s", out)
	}
	r, _ = Build(TypeMembers, nil, now)
	out = render(t, r, "text")
	if !strings.Contains(out, "Devices: 0\n\ndevice") || !strings.HasSuffix(out, "-\n") {
		t.Errorf("empty report:\n%s", out)
	}
}

func TestCSVGuard(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"plain":    "plain",
		"=1+1":     "'=1+1",
		"+1":       "'+1",
		"-1":       "'-1",
		"-":        "-",
		"--":       "'--",
		"@SUM(A1)": "'@SUM(A1)",
		"\tx":      "'\tx",
		"\rx":      "'\rx",
		" =1":      " =1",
		"a=b":      "a=b",
		"'=1":      "'=1",
	}
	for in, want := range cases {
		if got := guardCell(in); got != want {
			t.Errorf("guardCell(%q) = %q, want %q", in, got, want)
		}
	}
	devs := []Device{{Name: "=a", Vendor: "+b", Model: "-c", Serial: "@d", Location: "\te", Description: "\rf"}}
	r, _ := Build(TypeInventory, devs, now)
	recs, err := csv.NewReader(strings.NewReader(render(t, r, "csv"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	row := recs[1]
	for i, w := range map[int]string{0: "'=a", 2: "'+b", 4: "'-c", 5: "'@d", 8: "'\te", 9: "'\rf", 7: "-"} {
		if row[i] != w {
			t.Errorf("cell %d = %q, want %q", i, row[i], w)
		}
	}
	// JSON and text need no guard.
	if strings.Contains(render(t, r, "json"), `"'=a"`) || strings.Contains(render(t, r, "text"), "'=a") {
		t.Error("guard in json or text")
	}
}

func TestCSVShape(t *testing.T) {
	out := render(t, mustBuild(t, TypeInventory), "csv")
	if strings.Contains(strings.ReplaceAll(out, "'\r", ""), "\r") {
		t.Error("CRLF line ends")
	}
	if !strings.HasSuffix(out, "\n") || !utf8.ValidString(out) {
		t.Error("final newline or UTF-8")
	}
	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 8 || strings.Join(recs[0], ",") != strings.Join(Columns(TypeInventory), ",") {
		t.Errorf("records: %d, header %v", len(recs), recs[0])
	}
	// A comma and a quote survive the round trip.
	r, _ := Build(TypeInventory, []Device{{Name: "a", Location: `Rack 4, "DC1"`}}, now)
	recs, _ = csv.NewReader(strings.NewReader(render(t, r, "csv"))).ReadAll()
	if recs[1][8] != `Rack 4, "DC1"` {
		t.Errorf("location = %q", recs[1][8])
	}
}

func TestJSONDecodes(t *testing.T) {
	for _, typ := range Types() {
		r := mustBuild(t, typ)
		out := render(t, r, "json")
		if !strings.HasSuffix(out, "\n") || !strings.Contains(out, "\n  \"rows\": [\n    {\n      \"") {
			t.Errorf("%s: not pretty printed:\n%s", typ, out)
		}
		var doc struct {
			Schema     int              `json:"schema"`
			Type       string           `json:"type"`
			Generated  string           `json:"generated"`
			OldestData *string          `json:"oldest_data"`
			Columns    []string         `json:"columns"`
			Rows       []map[string]any `json:"rows"`
		}
		dec := json.NewDecoder(strings.NewReader(out))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("%s: %v\n%s", typ, err, out)
		}
		if doc.Schema != 1 || doc.Type != typ || doc.Generated != "2026-11-06T09:30:15Z" ||
			doc.OldestData == nil || *doc.OldestData != "2026-11-03T22:10:00Z" {
			t.Errorf("%s: header %+v", typ, doc)
		}
		if len(doc.Rows) != len(r.Rows) || strings.Join(doc.Columns, ",") != strings.Join(r.Columns, ",") {
			t.Errorf("%s: %d rows, columns %v", typ, len(doc.Rows), doc.Columns)
		}
	}
	// The key order is the documented one, not alphabetical.
	out := render(t, mustBuild(t, TypeMembers), "json")
	i, j, k := strings.Index(out, `"device"`), strings.Index(out, `"id"`), strings.Index(out, `"components"`)
	if !(i < j && j < k) || !strings.Contains(out, `"components": []`) || !strings.Contains(out, `"priority": 129,`) {
		t.Errorf("members json:\n%s", out)
	}
	// No pull at all: oldest_data is null.
	r, _ := Build(TypeInventory, nil, now)
	out = render(t, r, "json")
	if !strings.Contains(out, `"oldest_data": null`) || !strings.Contains(out, `"rows": []`) {
		t.Errorf("empty json:\n%s", out)
	}
	// No HTML escaping: a model keeps its <, > and &.
	r, _ = Build(TypeSoftware, []Device{{Name: "a", Model: "A&B <1>"}}, now)
	if !strings.Contains(render(t, r, "json"), `"A&B <1>"`) {
		t.Error("html escaping")
	}
}

// TestNoControlBytes: the text format never carries a byte below 0x20 other
// than the newline, nor DEL, nor a C1 control, whatever the records hold.
func TestNoControlBytes(t *testing.T) {
	nasty := "a\x1b[2Jb\x00c\td\re\x7ff\u0085g‮h⁦i\xff\xfej k"
	devs := []Device{{
		Name: nasty, Address: nasty, Vendor: nasty, Scope: nasty, Model: nasty, Serial: nasty,
		Release: nasty, Location: nasty, Description: nasty, ConfigState: nasty, GateState: nasty,
		Members: []Member{{ID: nasty, Role: nasty, Model: nasty, Serial: nasty, Release: nasty, Status: nasty}},
	}}
	for _, typ := range Types() {
		r, _ := Build(typ, devs, now)
		out := render(t, r, "text")
		for i := 0; i < len(out); i++ {
			if out[i] == '\n' {
				continue
			}
			if out[i] < 0x20 || out[i] == 0x7f {
				t.Fatalf("%s: byte %#x at %d in %q", typ, out[i], i, out)
			}
		}
		if !utf8.ValidString(out) {
			t.Errorf("%s: not UTF-8", typ)
		}
		for _, bad := range []string{"\u0085", "‮", "⁦", " "} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: %q survived", typ, bad)
			}
		}
		if typ == TypeSoftware && !strings.Contains(out, "a?[2Jb?c?d?e?f?g?h?i??j?k") {
			t.Errorf("%s: not replaced by ?:\n%s", typ, out)
		}
		// The rows themselves are not touched.
		if !strings.Contains(strings.Join(r.Rows[0], "|"), "\x1b") {
			t.Errorf("%s: Rows were cleaned", typ)
		}
	}
	// JSON escapes it.
	r, _ := Build(TypeSoftware, devs, now)
	if strings.ContainsAny(render(t, r, "json"), "\x1b\x00\t\r") {
		t.Error("raw control byte in json")
	}
}
