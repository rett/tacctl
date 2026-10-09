package devreg

import (
	"strings"
	"testing"
)

func TestValidateLocation(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Rack 4, DC1", ""},
		{"Building 2 / room 17 (north)", ""},
		{strings.Repeat("é", 120), ""},
		{"", "may not be empty"},
		{"   ", "may not be empty"},
		{strings.Repeat("x", 121), "limited to 120"},
		{"a\nb", "control characters"},
		{"a\x1bb", "control characters"},
		{"a\x7fb", "control characters"},
		{"where?", "'?'"},
		{"bad \xff utf8", "limited to 120"},
	} {
		err := ValidateLocation(c.in)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%q refused: %v", c.in, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%q: %v, want %q", c.in, err, c.want)
		}
	}
}

// location is written only when set: a registry without one is the bytes it
// was, and one with it reads back.
func TestLocationOnlyWhenSet(t *testing.T) {
	f, err := devicesFromText(t, []byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	text, err := f.Text()
	if err != nil || string(text) != sample || strings.Contains(string(text), "location") {
		t.Fatalf("without location: %v\n%s", err, text)
	}
	f.Find("core-sw1").Location = "Rack 4, DC1"
	text, err = f.Text()
	if err != nil || !strings.Contains(string(text), "location: 'Rack 4, DC1'") && !strings.Contains(string(text), "location: Rack 4, DC1") {
		t.Fatalf("with location: %v\n%s", err, text)
	}
	back, err := devicesFromText(t, text)
	if err != nil || back.Find("core-sw1").Location != "Rack 4, DC1" || back.Find("lab-rtr2").Location != "" {
		t.Fatalf("read back: %v %+v", err, back.Find("core-sw1"))
	}
	// Cleared, it leaves the file as it was.
	back.Find("core-sw1").Location = ""
	again, err := back.Text()
	if err != nil || string(again) != sample {
		t.Errorf("cleared:\n%s", again)
	}
	// A location that breaks the rules is refused when the file is read.
	bad := strings.Replace(sample, "vendor: wti}", "vendor: wti, location: \"a?b\"}", 1)
	if _, err := devicesFromText(t, []byte(bad)); err == nil {
		t.Error("a location with '?' was read")
	}
}

// A CSV import keeps the location of a device it updates; the JSON shows it
// only when set.
func TestLocationInImportAndJSON(t *testing.T) {
	f, err := devicesFromText(t, []byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	f.Find("core-sw1").Location = "Rack 4"
	rows, err := ParseImport([]byte("name,address,vendor,port,description\ncore-sw1,10.99.0.1,cisco,,DC1 core renamed\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Import(rows, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if d := f.Find("core-sw1"); d.Location != "Rack 4" || d.Description != "DC1 core renamed" {
		t.Errorf("after import: %+v", d)
	}
	out, err := JSON([]Device{*f.Find("core-sw1"), *f.Find("lab-rtr2")})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(out), `"location"`) != 1 || !strings.Contains(string(out), `"location": "Rack 4"`) {
		t.Errorf("json:\n%s", out)
	}
	if strings.Contains(string(CSV([]Device{*f.Find("core-sw1")})), "Rack 4") {
		t.Error("the CSV columns carry the location")
	}
}
