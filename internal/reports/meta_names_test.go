package reports

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMetaRoundTrip(t *testing.T) {
	m := Meta{
		Schema: 1, Name: "inventory-20261106", Type: TypeInventory, Format: FormatCSV, User: "alice",
		Command: "tacctl device report generate inventory --format csv --scope site-a",
		Filters: map[string]string{"scope": "site-a"}, Generated: now, OldestData: at(3, 22, 10),
		Size: 1234, Count: 7,
	}
	b, err := MarshalMeta(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b), "\n") || !strings.Contains(string(b), "\n  \"schema\": 1,") {
		t.Errorf("not pretty printed:\n%s", b)
	}
	got, err := ParseMeta(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, m)
	}
}

func TestMetaDefaults(t *testing.T) {
	m := Meta{Name: "a", Type: TypeConfig, Format: FormatText, User: "bob", Generated: now.In(time.FixedZone("CET", 3600))}
	b, err := MarshalMeta(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`"schema": 1`, `"oldest_data": null`, `"filters": {}`, `"generated": "2026-11-06T09:30:15Z"`} {
		if !strings.Contains(string(b), w) {
			t.Errorf("no %s in:\n%s", w, b)
		}
	}
	got, err := ParseMeta(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Schema != 1 || !got.OldestData.IsZero() || got.Filters == nil || len(got.Filters) != 0 || !got.Generated.Equal(now) {
		t.Errorf("parsed %+v", got)
	}
}

func TestMetaRefusals(t *testing.T) {
	good := `{"schema":1,"name":"a","type":"config","format":"text","user":"bob","command":"c","filters":{},` +
		`"generated":"2026-11-06T09:30:15Z","oldest_data":null,"size":1,"count":1}`
	if _, err := ParseMeta([]byte(good)); err != nil {
		t.Fatalf("good metadata refused: %v", err)
	}
	cases := []struct{ name, in, want string }{
		{"newer schema", strings.Replace(good, `"schema":1`, `"schema":2`, 1), "schema 2, newer than the 1"},
		{"newer schema with new keys", `{"schema":7,"extra":true}`, "schema 7, newer"},
		{"no schema", `{"name":"a"}`, "no valid schema"},
		{"schema 0", strings.Replace(good, `"schema":1`, `"schema":0`, 1), "no valid schema"},
		{"unknown key", strings.Replace(good, `"count":1`, `"count":1,"colour":"red"`, 1), "colour"},
		{"not json", `inventory`, "report metadata"},
		{"wrong type", strings.Replace(good, `"size":1`, `"size":"big"`, 1), "report metadata"},
		{"trailing data", good + `{}`, "invalid character"},
		{"empty", ``, "report metadata"},
	}
	for _, c := range cases {
		_, err := ParseMeta([]byte(c.in))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", c.name, err, c.want)
		}
	}
	if _, err := MarshalMeta(Meta{Schema: 2}); err == nil {
		t.Error("MarshalMeta wrote schema 2")
	}
}

func TestValidName(t *testing.T) {
	ok := []string{"a", "inventory-20261106", "inventory-20261106-2", "My_Report.v2", "x.y", "a..", "0", strings.Repeat("a", 64)}
	for _, s := range ok {
		if err := ValidName(s); err != nil {
			t.Errorf("ValidName(%q) = %v", s, err)
		}
	}
	bad := map[string]string{
		"":                      "empty",
		".":                     "dot",
		"..":                    "dot",
		".hidden":               "dot",
		strings.Repeat("a", 65): "at most 64",
		"a b":                   "only letters",
		"a/b":                   "only letters",
		"../x":                  "dot",
		"a\x00b":                "only letters",
		"a\nb":                  "only letters",
		"ünï":                   "only letters",
		"a:b":                   "only letters",
		"a*":                    "only letters",
		"a~":                    "only letters",
	}
	for s, w := range bad {
		err := ValidName(s)
		if err == nil || !strings.Contains(err.Error(), w) {
			t.Errorf("ValidName(%q) = %v, want an error with %q", s, err, w)
		}
	}
}

func TestDefaultName(t *testing.T) {
	// 23:30 UTC on 5 November is the 5th, whatever the zone of now.
	late := time.Date(2026, 11, 5, 23, 30, 0, 0, time.UTC)
	if got := DefaultName(TypeInventory, late, nil); got != "inventory-20261105" {
		t.Errorf("name = %s", got)
	}
	cet := late.In(time.FixedZone("CET", 3600))
	if got := DefaultName(TypeMembers, cet, func(string) bool { return false }); got != "members-20261105" {
		t.Errorf("name in CET = %s", got)
	}
	taken := map[string]bool{}
	var asked []string
	fn := func(s string) bool { asked = append(asked, s); return taken[s] }
	for _, want := range []string{"config-20261106", "config-20261106-2", "config-20261106-3", "config-20261106-4"} {
		got := DefaultName(TypeConfig, now, fn)
		if got != want {
			t.Fatalf("name = %s, want %s", got, want)
		}
		taken[got] = true
	}
	// A gap is filled: -2 is free again.
	delete(taken, "config-20261106-2")
	if got := DefaultName(TypeConfig, now, fn); got != "config-20261106-2" {
		t.Errorf("gap: %s", got)
	}
	// Every name it returns is a valid one.
	for _, n := range asked {
		if err := ValidName(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	if got := strings.Join(asked[:1], ","); got != "config-20261106" {
		t.Errorf("first candidate = %s", got)
	}
}

func TestFileName(t *testing.T) {
	cases := []struct{ name, format, want string }{
		{"inventory-20261106", "text", "inventory-20261106.txt"},
		{"inventory-20261106", "csv", "inventory-20261106.csv"},
		{"a.b", "json", "a.b.json"},
	}
	for _, c := range cases {
		got, err := FileName(c.name, c.format)
		if err != nil || got != c.want {
			t.Errorf("FileName(%q, %q) = %q, %v", c.name, c.format, got, err)
		}
	}
	if _, err := FileName("a", "pdf"); err == nil || !strings.Contains(err.Error(), "valid formats: text, csv, json") {
		t.Errorf("unknown format: %v", err)
	}
	if _, err := FileName("../a", "csv"); err == nil {
		t.Error("bad name accepted")
	}
	if _, err := FileName("", "csv"); err == nil {
		t.Error("empty name accepted")
	}
}

func TestCheckLimits(t *testing.T) {
	if DefaultMaxSize != 10<<20 || DefaultMaxCount != 100 {
		t.Errorf("defaults %d %d", DefaultMaxSize, DefaultMaxCount)
	}
	cases := []struct {
		name     string
		size     int64
		count    int
		maxSize  int64
		maxCount int
		limit    string
	}{
		{"within", 100, 5, 1000, 10, ""},
		{"size at the cap", 1000, 5, 1000, 10, ""},
		{"size over", 1001, 5, 1000, 10, "size"},
		{"count at the cap", 100, 10, 1000, 10, ""},
		{"count over", 100, 11, 1000, 10, "count"},
		{"no size cap", 1 << 40, 5, 0, 10, ""},
		{"no count cap", 100, 1 << 20, 1000, 0, ""},
		{"no caps", 1 << 40, 1 << 20, 0, 0, ""},
		{"both over names the size", 2000, 50, 1000, 10, "size"},
		{"defaults ok", 10 << 20, 100, DefaultMaxSize, DefaultMaxCount, ""},
		{"defaults size over", 10<<20 + 1, 1, DefaultMaxSize, DefaultMaxCount, "size"},
		{"defaults count over", 1, 101, DefaultMaxSize, DefaultMaxCount, "count"},
	}
	for _, c := range cases {
		err := CheckLimits(c.size, c.count, c.maxSize, c.maxCount)
		if c.limit == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		var le *LimitError
		if !errors.As(err, &le) || le.Limit != c.limit {
			t.Errorf("%s: err = %v, want the %s limit", c.name, err, c.limit)
			continue
		}
		if !strings.Contains(err.Error(), c.limit) {
			t.Errorf("%s: %q does not name the limit", c.name, err)
		}
	}
	err := CheckLimits(5000, 1, 1000, 10)
	if got := err.Error(); got != "the report is 5000 bytes, over the size limit of 1000 bytes" {
		t.Errorf("size message = %q", got)
	}
	err = CheckLimits(1, 12, 1000, 10)
	if got := err.Error(); got != "that would be 12 reports, over the count limit of 10 reports" {
		t.Errorf("count message = %q", got)
	}
}
