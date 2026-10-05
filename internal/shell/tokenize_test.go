package shell

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestTokenize(t *testing.T) {
	cases := []struct {
		line string
		want []string
		err  error
	}{
		{"", nil, nil},
		{"   \t ", nil, nil},
		{"user list", []string{"user", "list"}, nil},
		{"  user\t list  ", []string{"user", "list"}, nil},
		{"user add 'a b' ops", []string{"user", "add", "a b", "ops"}, nil},
		{`user add "a b" ops`, []string{"user", "add", "a b", "ops"}, nil},
		{`a\ b`, []string{"a b"}, nil},
		{`'a\b'`, []string{`a\b`}, nil},
		{`"a\"b"`, []string{`a"b`}, nil},
		{`"a\\b"`, []string{`a\b`}, nil},
		{`"a\nb"`, []string{`a\nb`}, nil},
		{`'it'\''s'`, []string{"it's"}, nil},
		{`''`, []string{""}, nil},
		{`x "" y`, []string{"x", "", "y"}, nil},
		{`a'b'"c"d`, []string{"abcd"}, nil},
		{`\'`, []string{"'"}, nil},
		{"'abc", nil, ErrUnterminatedQuote},
		{`"abc`, nil, ErrUnterminatedQuote},
		{`"abc\`, nil, ErrUnterminatedQuote},
		{`abc\`, nil, ErrTrailingBackslash},
	}
	for _, c := range cases {
		got, err := Tokenize(c.line)
		if !errors.Is(err, c.err) || !slices.Equal(got, c.want) {
			t.Errorf("Tokenize(%q) = %q, %v; want %q, %v", c.line, got, err, c.want, c.err)
		}
	}
}

// Every shell metacharacter is an ordinary character: a line is one
// command, and what would be an escape elsewhere reaches tacctl as a
// literal word (an unknown command or an invalid argument).
func TestTokenizeEscapeAttempts(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"user list; id", []string{"user", "list;", "id"}},
		{"user list;id", []string{"user", "list;id"}},
		{"user list | sh", []string{"user", "list", "|", "sh"}},
		{"user list|sh", []string{"user", "list|sh"}},
		{"user list && id", []string{"user", "list", "&&", "id"}},
		{"user list & ", []string{"user", "list", "&"}},
		{"user show $(id)", []string{"user", "show", "$(id)"}},
		{"user show `id`", []string{"user", "show", "`id`"}},
		{"user show $USER ${HOME}", []string{"user", "show", "$USER", "${HOME}"}},
		{"user list > /tmp/x", []string{"user", "list", ">", "/tmp/x"}},
		{"user list >/tmp/x 2>&1", []string{"user", "list", ">/tmp/x", "2>&1"}},
		{"user list < /etc/shadow", []string{"user", "list", "<", "/etc/shadow"}},
		{"user list\nid", []string{"user", "list\nid"}},
		{"user list\rid", []string{"user", "list\rid"}},
		{"!!", []string{"!!"}},
		{"!-1 x", []string{"!-1", "x"}},
		{"user show *", []string{"user", "show", "*"}},
		{"user show ~root", []string{"user", "show", "~root"}},
		{"user list # comment", []string{"user", "list", "#", "comment"}},
		{"user\u00a0list", []string{"user\u00a0list"}},
		{"user\u2003list", []string{"user\u2003list"}},
		{"user\u3000list", []string{"user\u3000list"}},
		{"user\u200blist", []string{"user\u200blist"}},
		{"user\vlist\f", []string{"user\vlist\f"}},
		{"(id)", []string{"(id)"}},
		{"{id,ls}", []string{"{id,ls}"}},
		{"a=b id", []string{"a=b", "id"}},
		{`"$(id)"`, []string{"$(id)"}},
		{"'`id`'", []string{"`id`"}},
		{"\x00id", []string{"\x00id"}},
		{"\x1b[31mred", []string{"\x1b[31mred"}},
	}
	for _, c := range cases {
		got, err := Tokenize(c.line)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("Tokenize(%q) = %q, %v; want %q", c.line, got, err, c.want)
		}
	}
}

func TestQuoteRoundTrip(t *testing.T) {
	for _, w := range []string{"", "a", "a b", "it's", `a"b`, `a\b`, "\t", "list;", "$(id)", "é ü"} {
		got, err := Tokenize(Quote(w))
		if err != nil || len(got) != 1 || got[0] != w {
			t.Errorf("Tokenize(Quote(%q)) = %q, %v", w, got, err)
		}
	}
}

// FuzzTokenize holds the tokenizer to its contract on any input: it never
// panics; a line it accepts is re-quoted word by word into a line that
// tokenizes to the same words; a word never holds a blank that was not
// quoted or escaped in the line; a line without quotes or backslashes
// splits exactly at blanks.
func FuzzTokenize(f *testing.F) {
	for _, s := range []string{"user list", `a "b c" 'd'`, `a\ b`, "x;y|z", "$(id)", "'", `"\`, "\u00a0", "\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		words, err := Tokenize(line)
		if err != nil {
			if !errors.Is(err, ErrUnterminatedQuote) && !errors.Is(err, ErrTrailingBackslash) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		quoted := make([]string, len(words))
		for i, w := range words {
			quoted[i] = Quote(w)
		}
		again, err := Tokenize(strings.Join(quoted, " "))
		if err != nil || !slices.Equal(again, words) {
			t.Fatalf("round trip of %q: %q -> %q, %v", line, words, again, err)
		}
		if !strings.ContainsAny(line, `'"\`) {
			want := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
			if !slices.Equal(words, want) {
				t.Fatalf("Tokenize(%q) = %q, want %q", line, words, want)
			}
		}
	})
}
