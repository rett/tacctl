package shellquote

import "testing"

func TestXargsEcho(t *testing.T) {
	for in, want := range map[string]string{
		"":        "",
		"  lab ":  "lab",
		"a  b\tc": "a b c",
		"'la b'":  "la b",
		`"x"y`:    "xy",
		`a\ b`:    "a b",
		`trail\`:  "trail",
		"it's'":   "its",
	} {
		got, err := XargsEcho(in)
		if err != nil || got != want {
			t.Errorf("XargsEcho(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	_, err := XargsEcho("it's")
	if err == nil || err.Error() != "unmatched single quote; by default quotes are special to xargs unless you use the -0 option" {
		t.Errorf("single: %v", err)
	}
	_, err = XargsEcho(`a"b`)
	if err == nil || err.Error() != "unmatched double quote; by default quotes are special to xargs unless you use the -0 option" {
		t.Errorf("double: %v", err)
	}
}
