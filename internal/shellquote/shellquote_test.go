package shellquote

import (
	"bytes"
	"context"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

func TestQExamples(t *testing.T) {
	for in, want := range map[string]string{
		"":                   "''",
		"abc":                "abc",
		"a b":                `a\ b`,
		"it's":               `it\'s`,
		`say "hi"`:           `say\ \"hi\"`,
		"$HOME":              `\$HOME`,
		"a;b|c&d":            `a\;b\|c\&d`,
		"#x":                 `\#x`,
		"a#x":                "a#x",
		"~":                  `\~`,
		"a~b":                "a~b",
		"a=~b":               `a=\~b`,
		"a:~b":               `a:\~b`,
		"x=y":                "x=y",
		"/usr/bin:/bin":      "/usr/bin:/bin",
		"a%b+c-d.e@f_g":      "a%b+c-d.e@f_g",
		"a\nb":               `$'a\nb'`,
		"a\tb c":             `$'a\tb c'`,
		"\x1b[0m":            `$'\E[0m'`,
		"a\x01b":             `$'a\001b'`,
		"x\x7f":              `$'x\177'`,
		`a\b`:                `a\\b`,
		"$'a'\n":             `$'$\'a\'\n'`,
		"alice:1:2\nbob:3:4": `$'alice:1:2\nbob:3:4'`,
		"é":                  `$'\303\251'`,
	} {
		if got := Q(in); got != want {
			t.Errorf("Q(%q) = %s, want %s", in, got, want)
		}
	}
}

// corpus is deterministic: every single byte alone and in context, the
// shell-special characters in pairs, the TAC_USERS shape, and random strings.
func corpus() []string {
	var c []string
	for b := 1; b < 256; b++ {
		ch := string([]byte{byte(b)})
		c = append(c, ch, "a"+ch, ch+"a", "a"+ch+"b", "a="+ch, "a:"+ch, ch+ch)
	}
	special := " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\t\n"
	for i := 0; i < len(special); i++ {
		for j := 0; j < len(special); j++ {
			c = append(c, special[i:i+1]+special[j:j+1])
		}
	}
	c = append(c,
		"alice:superuser:1001\nbob:readonly:1002", "S3cr3t+/=base64Pa55word==", "10.0.0.1", "lab", "radius",
		"a very long value with spaces and 'quotes' and \"doubles\" and $vars and `ticks`",
		strings.Repeat("a", 1000), strings.Repeat("\x01", 50), "\\", "'", "''", "\"\"", "$'x'",
	)
	rng := rand.New(rand.NewSource(20261003))
	alpha := []byte(" !\"#$%&'()*+,-./0123456789:;<=>?@AZaz[\\]^_`{|}~\t\n\r\x01\x1b\x7f\x80\xc3\xa9\xff")
	for i := 0; i < 3000; i++ {
		n := 1 + rng.Intn(12)
		b := make([]byte, n)
		for j := range b {
			b[j] = alpha[rng.Intn(len(alpha))]
		}
		c = append(c, string(b))
	}
	return c
}

// printfQ runs every string through bash's printf %q under the locale.
func printfQ(t *testing.T, in []string, locale string) [][]byte {
	t.Helper()
	var stdin bytes.Buffer
	for _, s := range in {
		stdin.WriteString(s)
		stdin.WriteByte(0)
	}
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{
		Name:  "bash",
		Args:  []string{"-c", `while IFS= read -r -d '' s; do printf '%q\0' "$s"; done`},
		Stdin: &stdin,
		Env:   []string{"LC_ALL=" + locale, "PATH=/usr/bin:/bin"},
	})
	if err != nil || res.Code != 0 {
		t.Fatalf("bash: %v (exit %d): %s", err, res.Code, res.Stderr)
	}
	out := bytes.Split(bytes.TrimSuffix(res.Stdout, []byte{0}), []byte{0})
	if len(out) != len(in) {
		t.Fatalf("bash printed %d results for %d inputs", len(out), len(in))
	}
	return out
}

// Q equals bash's printf %q for the whole corpus in the C locale, and for
// its ASCII strings in a UTF-8 locale.
func TestQEqualsPrintfQ(t *testing.T) {
	all := corpus()
	var ascii []string
	for _, s := range all {
		ok := true
		for i := 0; i < len(s); i++ {
			ok = ok && s[i] < 0x80
		}
		if ok {
			ascii = append(ascii, s)
		}
	}
	for _, tc := range []struct {
		locale string
		in     []string
	}{{"C", all}, {"C.UTF-8", ascii}} {
		out := printfQ(t, tc.in, tc.locale)
		bad := 0
		for i, s := range tc.in {
			if got := Q(s); got != string(out[i]) {
				bad++
				if bad <= 10 {
					t.Errorf("%s: Q(%q) = %s, printf %%q = %s", tc.locale, s, got, out[i])
				}
			}
		}
		t.Logf("%s: %d strings compared with bash printf %%q, %d differ", tc.locale, len(tc.in), bad)
	}
}

// The quoted text, sourced by bash, gives the value back.
func TestQRoundTripsThroughBash(t *testing.T) {
	in := corpus()
	var script bytes.Buffer
	for i, s := range in {
		script.WriteString("v" + strconv.Itoa(i) + "=" + Q(s) + "\n")
	}
	var names []string
	for i := range in {
		names = append(names, `"$v`+strconv.Itoa(i)+`"`)
	}
	script.WriteString(`for v in ` + strings.Join(names, " ") + `; do printf '%s\0' "$v"; done` + "\n")
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{
		Name:  "bash",
		Args:  []string{"-s"},
		Stdin: &script,
		Env:   []string{"LC_ALL=C", "PATH=/usr/bin:/bin"},
	})
	if err != nil || res.Code != 0 {
		t.Fatalf("bash: %v (exit %d): %s", err, res.Code, res.Stderr)
	}
	out := bytes.Split(bytes.TrimSuffix(res.Stdout, []byte{0}), []byte{0})
	if len(out) != len(in) {
		t.Fatalf("got %d values for %d inputs", len(out), len(in))
	}
	for i, s := range in {
		if string(out[i]) != s {
			t.Errorf("round trip of %q gave %q (quoted %s)", s, out[i], Q(s))
			break
		}
	}
}
