package tacacs

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// tests/e2e/log.bats below the CLI ('tacctl log' with no sub-command and
// the multi-backend headings are internal/cli's), and listeners.bats "log
// tail: one listener calls journalctl as before; more listeners add their
// units".

const journalLines = `2026-04-21 10:00:00 tacquito[1]: INFO auth OK user=alice
2026-04-21 10:01:00 tacquito[1]: ERROR bad secret from 10.0.0.5
2026-04-21 10:02:00 tacquito[1]: INFO auth OK user=bob
2026-04-21 10:03:00 tacquito[1]: FAIL auth user=carol: bcrypt mismatch
`

func (e *tenv) logEnv() {
	e.run.On([]string{"journalctl"}, execx.Result{Stdout: []byte(journalLines)})
}

func (e *tenv) log(sub string, args ...string) (string, error) {
	var w bytes.Buffer
	err := e.b.Log(context.Background(), sub, args, &w)
	return w.String(), err
}

func TestLogTail(t *testing.T) {
	e := newTenv(t)
	e.logEnv()
	out, err := e.log("tail")
	if err != nil {
		t.Fatal(err)
	}
	if want := "\n" + ui.Bold + "Recent TACACS+ Log Entries" + ui.NC + "\n" + rule + "\n" + journalLines + "\n"; out != want {
		t.Fatalf("%q", out)
	}
	if !e.called(`^journalctl -u tacquito --no-pager -n 20$`) {
		t.Fatal(e.run.Argvs())
	}
	e.writeOverrides("listeners:\n  tacacs:\n    mgmt: {network: tcp, address: '127.0.0.1:4949'}\n")
	_, _ = e.log("tail", "5")
	if !e.called(`^journalctl -u tacquito -u tacquito@mgmt\.service --no-pager -n 5$`) {
		t.Fatal(e.run.Argvs())
	}
	e.run.On([]string{"journalctl"}, execx.Result{Code: 1})
	out, _ = e.log("tail")
	mustContain(t, out, "  No log entries found.\n")
}

// "log search: filters journal output by keyword", "rejects missing
// argument", "reports 'No matches found' when empty".
func TestLogSearch(t *testing.T) {
	e := newTenv(t)
	e.logEnv()
	out, err := e.log("search", "ALICE")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "Log entries matching 'ALICE'")
	mustContain(t, out, "auth OK user=alice\n")
	mustNotContain(t, out, "user=bob")
	if !e.called(`^journalctl -u tacquito --no-pager --since 7 days ago$`) {
		t.Fatal(e.run.Argvs())
	}
	out, _ = e.log("search", "no-such-user-xyz")
	mustContain(t, out, "  No matches found.\n")
	// A basic regular expression, as grep reads it.
	out, _ = e.log("search", `user=\(bob\|carol\)`)
	mustContain(t, out, "user=bob")
	mustContain(t, out, "user=carol")
	mustNotContain(t, out, "user=alice")
	out, _ = e.log("search", `\(`)
	mustContain(t, out, "No matches found.")

	_, err = e.log("search")
	wantCode(t, err, 1)
	mustContain(t, e.stderr.String(), "Usage: tacctl log search <username>")
}

// "log failures: reports entries matching ERROR|fail|bad secret".
func TestLogFailures(t *testing.T) {
	e := newTenv(t)
	e.logEnv()
	out, _ := e.log("failures")
	mustContain(t, out, "Authentication Failures (last 24 hours)")
	mustContain(t, out, "ERROR bad secret")
	mustContain(t, out, "FAIL auth user=carol")
	mustNotContain(t, out, "user=alice")
	e.run.On([]string{"journalctl"}, execx.Result{})
	out, _ = e.log("failures")
	mustContain(t, out, "  "+ui.Green+"No failures in the last 24 hours"+ui.NC)
}

// "log clear: cancels on empty/n response and leaves logs intact", "with
// --force skips prompt and rotates+vacuums+truncates", "with 'y'
// confirmation proceeds".
func TestLogClear(t *testing.T) {
	e := newTenv(t)
	mgmt := filepath.Join(e.p.Log, "accounting-mgmt.log")
	writeFile(t, e.p.AcctLog, "keepme\n")
	writeFile(t, mgmt, "keepme too\n")
	e.stdin("\n")
	out, err := e.log("clear")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, out, "Cancelled")
	mustContain(t, out, "Also truncated: "+mgmt)
	if e.called(`^journalctl`) || readFile(t, e.p.AcctLog) != "keepme\n" {
		t.Fatal("cleared")
	}

	out, _ = e.log("clear", "--force")
	mustContain(t, out, "Logs cleared")
	if !e.called(`^journalctl --rotate$`) || !e.called(`^journalctl --vacuum-time=1s -u tacquito$`) {
		t.Fatal(e.run.Argvs())
	}
	if readFile(t, e.p.AcctLog) != "" || readFile(t, mgmt) != "" {
		t.Fatal("not truncated")
	}

	e.reset()
	writeFile(t, e.p.AcctLog, "old\n")
	e.stdin("y\n")
	e.run.Fail([]string{"journalctl", "--vacuum-time=1s"}, 1, "")
	out, _ = e.log("clear")
	mustContain(t, out, "Logs cleared")
	mustContain(t, out, "journalctl vacuum failed — run manually: sudo journalctl --vacuum-time=1s -u tacquito")
	if readFile(t, e.p.AcctLog) != "" {
		t.Fatal("not truncated")
	}
	for _, flag := range []string{"-y", "--yes"} {
		e.stdin("")
		out, _ = e.log("clear", flag)
		mustContain(t, out, "Logs cleared")
	}
}

// "log accounting: reads from $ACCT_LOG when present", "reports helpful
// message when file missing", and every listener's log.
func TestAccounting(t *testing.T) {
	e := newTenv(t)
	acc := func(args ...string) string {
		var w bytes.Buffer
		if err := e.b.Accounting(context.Background(), "tail", args, &w); err != nil {
			t.Fatal(err)
		}
		return w.String()
	}
	out := acc()
	mustContain(t, out, "  No accounting log found at "+e.p.AcctLog)
	writeFile(t, e.p.AcctLog, "2026-04-21T10:00:00Z START user=alice task_id=1\n2026-04-21T10:00:05Z STOP  user=alice task_id=1 elapsed=5\n")
	out = acc("10")
	want := "\n" + ui.Bold + "Recent Accounting Entries" + ui.NC + "\n" + rule + "\n" +
		"2026-04-21T10:00:00Z START user=alice task_id=1\n2026-04-21T10:00:05Z STOP  user=alice task_id=1 elapsed=5\n\n"
	if out != want {
		t.Fatalf("%q", out)
	}
	if out = acc("1"); !bytes.Contains([]byte(out), []byte("STOP")) || bytes.Contains([]byte(out), []byte("START")) {
		t.Fatalf("%q", out)
	}
	mgmt := filepath.Join(e.p.Log, "accounting-mgmt.log")
	writeFile(t, mgmt, "2026/05/02 08:00:00 x")
	out = acc("5")
	mustContain(t, out, "\n"+ui.Bold+mgmt+ui.NC+"\n2026/05/02 08:00:00 x\n")
	if err := e.b.Accounting(context.Background(), "head", nil, &bytes.Buffer{}); err != backend.ErrUnsupported {
		t.Fatal(err)
	}
}

func TestTail(t *testing.T) {
	e := newTenv(t)
	p := filepath.Join(e.w, "f")
	writeFile(t, p, "1\n2\n3\n4")
	for count, want := range map[string]string{"2": "3\n4", "10": "1\n2\n3\n4", "0": "", "-1": "4", "+3": "3\n4", "+0": "1\n2\n3\n4", "+9": ""} {
		var w bytes.Buffer
		e.b.tail(&w, p, count)
		if w.String() != want {
			t.Fatalf("%s: %q, want %q", count, w.String(), want)
		}
	}
	var w bytes.Buffer
	e.b.tail(&w, p, "abc")
	if w.Len() != 0 {
		t.Fatal(w.String())
	}
	mustContain(t, e.stderr.String(), "tail: invalid number of lines: 'abc'")
	writeFile(t, p, "a\nb\n")
	w.Reset()
	e.b.tail(&w, p, "1")
	if w.String() != "b\n" {
		t.Fatalf("%q", w.String())
	}
}

// grep -i -e <pattern>: GNU basic regular expressions.
func TestGrepRegexp(t *testing.T) {
	for _, c := range []struct {
		pat, line string
		match     bool
	}{
		{"alice", "user=ALICE", true},
		{"a.c", "abc", true},
		{"a+", "a+", true},
		{"a+", "aa", false},
		{`a\+`, "aa", true},
		{"(x)", "(x)", true},
		{`\(x\)`, "x", true},
		{`x\|y`, "y", true},
		{"x|y", "x|y", true},
		{"*a", "*a", true},
		{"^user", "user=x", true},
		{"^user", "a user", false},
		{"a^b", "a^b", true},
		{"x$", "ax", true},
		{"x$y", "x$y", true},
		{"[[:digit:]]\\{3\\}", "a123", true},
		{"[]a]", "]", true},
		{"[^a]", "a", false},
		{`[\]`, `\`, true},
		{`\<bob\>`, "user=bob ok", true},
		{`\<bob\>`, "bobby", false},
		{"a{2}", "a{2}", true},
		{"10.0.0.5", "from 10.0.0.5", true},
		{"one\ntwo", "two", true},
	} {
		re, err := grepRegexp(c.pat)
		if err != nil {
			t.Fatalf("%q: %v", c.pat, err)
		}
		if re.MatchString(c.line) != c.match {
			t.Fatalf("%q on %q: %v (%s)", c.pat, c.line, !c.match, re)
		}
	}
	for _, bad := range []string{`\(`, `\)`, `a\`, "[a", `\1`, "[[:alpha:"} {
		if _, err := grepRegexp(bad); err == nil {
			t.Fatalf("%q compiled", bad)
		}
	}
}
