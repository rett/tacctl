package ui

import (
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// Echo and EchoE agree with bash's builtin 'echo -e' on the escapes it
// knows, \c included.
func TestEchoMatchesBash(t *testing.T) {
	bash, err := execx.Real{}.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	cases := []string{``, `plain`, `tab\there`, `nl\nx`, `'\t' and '\\'`, `\x41\x4`, `\x`, `\0101\07`, `é\U0001F600`,
		`\u`, `\q unknown`, `\a\b\e\E\f\r\v`, `end\cnever`, `\c`, `trailing\`, `\1\2`, `%s`}
	for _, in := range cases {
		res, err := execx.Real{}.Run(t.Context(), execx.Cmd{Name: bash, Args: []string{"-c", `echo -e "$1"`, "bash", in}})
		if err != nil {
			t.Fatal(err)
		}
		if got := Echo(in); got != string(res.Stdout) {
			t.Errorf("Echo(%q) = %q, bash %q", in, got, res.Stdout)
		}
		res, err = execx.Real{}.Run(t.Context(), execx.Cmd{Name: bash, Args: []string{"-c", `echo -n -e "$1"`, "bash", in}})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := EchoE(in); got != string(res.Stdout) {
			t.Errorf("EchoE(%q) = %q, bash %q", in, got, res.Stdout)
		}
	}
	if _, stop := EchoE(`a\cb`); !stop {
		t.Fatal("no stop at \\c")
	}
	if _, stop := EchoE(`a\\cb`); stop {
		t.Fatal("stop at an escaped backslash")
	}
}
