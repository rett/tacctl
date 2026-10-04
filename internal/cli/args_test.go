package cli

import (
	"errors"
	"reflect"
	"testing"
)

var userAddSpec = Spec{
	Flags: []Flag{
		{Names: []string{"--hash"}, Value: true},
		{Names: []string{"--scopes"}, Value: true},
		{Names: []string{"--yes", "-y"}},
		{Names: []string{"--match"}, Value: true, Repeat: true},
	},
	MinArgs: 2, MaxArgs: 2,
}

func TestParse(t *testing.T) {
	p, err := Parse(userAddSpec, []string{"alice", "--hash", "abc", "ops", "--scopes=lab,prod", "-y", "--match", "a", "--match=b"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Args, []string{"alice", "ops"}) {
		t.Errorf("Args = %q", p.Args)
	}
	if p.Value("--hash") != "abc" || p.Value("--scopes") != "lab,prod" {
		t.Errorf("values: %q %q", p.Value("--hash"), p.Value("--scopes"))
	}
	if !p.Has("--yes") || p.Has("--nope") || p.Value("--nope") != "" {
		t.Error("Has/Value of switches wrong")
	}
	if got := p.Values("--match"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("Values = %q", got)
	}
	// Values returns a copy.
	p.Values("--match")[0] = "x"
	if p.Value("--match") != "b" || p.Values("--match")[0] != "a" {
		t.Error("Values leaked the internal slice")
	}

	// "--" ends the flags; a lone "-" and an empty string are positionals.
	p, err = Parse(Spec{MaxArgs: -1}, []string{"-", "", "--", "--hash", "-y"})
	if err != nil || !reflect.DeepEqual(p.Args, []string{"-", "", "--hash", "-y"}) {
		t.Errorf("-- handling: %q %v", p.Args, err)
	}
	// A value that looks like a flag is taken as the value.
	p, err = Parse(userAddSpec, []string{"a", "b", "--hash", "--scopes"})
	if err != nil || p.Value("--hash") != "--scopes" {
		t.Errorf("flag-like value: %v %v", p.Value("--hash"), err)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		argv    []string
		target  any
		message string
	}{
		{[]string{"a", "b", "--bogus"}, new(*UnknownFlagError), "Unknown flag: '--bogus'"},
		{[]string{"a", "b", "--bogus=1"}, new(*UnknownFlagError), "Unknown flag: '--bogus=1'"},
		{[]string{"a", "b", "--hash"}, new(*MissingValueError), "--hash requires a value"},
		{[]string{"a", "b", "--yes=1"}, new(*UnexpectedValueError), "--yes takes no value"},
		{[]string{"a", "b", "-y", "--yes"}, new(*RepeatedFlagError), "--yes given more than once"},
		{[]string{"a"}, new(*ArgCountError), "expected at least 2 argument(s), got 1"},
		{[]string{"a", "b", "c", "d"}, new(*ArgCountError), "Unknown argument: 'c'"},
	}
	for _, c := range cases {
		_, err := Parse(userAddSpec, c.argv)
		if err == nil {
			t.Errorf("%q: no error", c.argv)
			continue
		}
		if !errors.As(err, c.target) {
			t.Errorf("%q: error %T, want %T", c.argv, err, c.target)
		}
		if err.Error() != c.message {
			t.Errorf("%q: message %q, want %q", c.argv, err.Error(), c.message)
		}
	}
	var ac *ArgCountError
	_, err := Parse(userAddSpec, []string{"a", "b", "c"})
	if !errors.As(err, &ac) || ac.Got != 3 || ac.Extra != "c" || ac.Max != 2 {
		t.Errorf("ArgCountError = %+v", ac)
	}
}
