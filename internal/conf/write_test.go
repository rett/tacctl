package conf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

func TestDefaultsTextIsConfEmitDefaults(t *testing.T) {
	src, err := os.ReadFile("../../lib/conf.sh")
	if err != nil {
		t.Skip("lib/conf.sh is gone (the bash tree is retired); testdata/gen.py checks the tag")
	}
	text := string(src)
	start := strings.Index(text, "    cat <<'YAML'\n") + len("    cat <<'YAML'\n")
	end := strings.Index(text[start:], "\nYAML\n")
	if text[start:start+end+1] != DefaultsText {
		t.Fatal("internal/conf/defaults.yaml differs from conf_emit_defaults in lib/conf.sh")
	}
	keys := Defaults().Keys()
	if strings.Join(keys, " ") != "password secret bcrypt scope host mgmt_acl privileges commands" {
		t.Fatalf("keys %v", keys)
	}
}

func TestListItems(t *testing.T) {
	for in, want := range map[string][]string{
		"":                      nil,
		"a\nb\n":                {"a", "b"},
		"a\n\n  \n b \r\nc\rd":  {"a", " b ", "c", "d"},
		"\u00a0\n x\t\n":        {" x\t"},
		"no newline at the end": {"no newline at the end"},
	} {
		if got := ListItems(in); strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
			t.Errorf("ListItems(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetNestedReplacesScalarsAndUnsetPrunesUpward(t *testing.T) {
	m := yamlpy.NewMap("a", 5, "keep", 1)
	setNested(m, "a.b.c", "x")
	if py.Repr(m) != "{'a': {'b': {'c': 'x'}}, 'keep': 1}" {
		t.Fatalf("got %s", py.Repr(m))
	}
	unsetNested(m, "a.b.missing")
	unsetNested(m, "a.x.y")
	if py.Repr(m) != "{'a': {'b': {'c': 'x'}}, 'keep': 1}" {
		t.Fatalf("got %s", py.Repr(m))
	}
	unsetNested(m, "a.b.c")
	if py.Repr(m) != "{'keep': 1}" {
		t.Fatalf("got %s", py.Repr(m))
	}
	m = yamlpy.NewMap("a", yamlpy.NewMap("b", nil, "e", yamlpy.NewMap()))
	unsetNested(m, "a.b.c") // a.b is null: nothing happens, not even pruning
	unsetNested(m, "a.e.f") // the empty a.e is pruned on the way up
	if py.Repr(m) != "{'a': {'b': None}}" {
		t.Fatalf("got %s", py.Repr(m))
	}
}

func TestSetJSONAndSetValue(t *testing.T) {
	c := tempConf(t)
	refused(t, c.SetJSON("commands.lab", "{bad json"),
		"commands.lab: invalid JSON payload (Expecting property name enclosed in double quotes: line 1 column 2 (char 1))")
	must(t, c.SetJSON("scope.default", "")) // "" is null, which scope.default accepts
	if !c.HasOverride("scope.default") {
		t.Fatal("null not written")
	}
	must(t, c.SetValue("commands.lab", []any{yamlpy.NewMap("name", "*", "action", "deny")}))
	if s, _ := c.GetJSON("commands.lab"); s != `[{"name": "*", "action": "deny"}]` {
		t.Fatalf("got %s", s)
	}
	must(t, c.SetValue("scope.default", nil))
	if !c.HasOverride("scope.default") || get(t, c, "scope.default") != "" {
		t.Fatal("explicit null")
	}
}

func TestWritePathKeepsUnknownKeysAndRewritesWithoutComments(t *testing.T) {
	c := tempConf(t)
	writeFile(t, c.Path, "# operator notes\ncustom:\n  thing: [a, b]   # trailing\nbcrypt: {cost: 13}\n")
	c.Reload()
	must(t, c.Set("password.max_age_days", "30"))
	want := Header + "custom:\n  thing:\n  - a\n  - b\nbcrypt:\n  cost: 13\npassword:\n  max_age_days: 30\n"
	if got := readFile(t, c.Path); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestWriteRefusesUnsupportedYAMLLikeAParseError(t *testing.T) {
	c := tempConf(t)
	writeFile(t, c.Path, "a: &x 1\nb: *x\n")
	c.Reload()
	if c.Problem() != "line 2, column 4: an alias is not supported in this file" {
		t.Fatalf("problem %q", c.Problem())
	}
	var pe *ParseError
	if err := c.Set("bcrypt.cost", "13"); !errors.As(err, &pe) {
		t.Fatalf("got %v", err)
	}
}

func TestWriteKeepsNonASCIIWithPyYAMLEscapes(t *testing.T) {
	c := tempConf(t)
	writeFile(t, c.Path, "custom: caf\u00e9\n")
	c.Reload()
	must(t, c.Set("bcrypt.cost", "13"))
	if got := readFile(t, c.Path); !strings.Contains(got, "custom: \"caf\\xE9\"\n") {
		t.Fatalf("got:\n%s", got)
	}
}

func TestWriteOfAValueOutsideTheEmittersDomainFailsAndKeepsTheFile(t *testing.T) {
	c := tempConf(t)
	const text = "custom: \"a\\x01b\"\n"
	writeFile(t, c.Path, text)
	c.Reload()
	err := c.Set("bcrypt.cost", "13")
	if err == nil || !strings.Contains(err.Error(), "cannot write") {
		t.Fatalf("got %v", err)
	}
	if readFile(t, c.Path) != text {
		t.Fatal("file changed")
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(c.Path), "tmp*"))
	if len(matches) != 0 {
		t.Fatalf("temporary files left: %v", matches)
	}
}

func TestWriteGivesTheFileToTheOwner(t *testing.T) {
	c := tempConf(t)
	called := 0
	c.Owner = func() (int, int, bool) { called++; return os.Getuid(), os.Getgid(), true }
	must(t, c.Set("bcrypt.cost", "13"))
	refused(t, c.Set("bcrypt.cost", "99"), "must be <=")
	if called != 2 {
		t.Fatalf("chown %d times", called)
	}
	writeFile(t, c.Path, brokenOverrides)
	_ = c.Set("bcrypt.cost", "13") // a parse refusal does not chown
	if called != 2 {
		t.Fatalf("chown %d times", called)
	}
	if _, _, ok := tacquitoOwner(); ok {
		t.Log("a tacquito user exists here")
	}
}

func TestWriteCreatesTheDirectoryAndLeavesNoLockFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "deeper")
	c := Load(filepath.Join(dir, "tacctl.yaml"), DefaultBackends)
	c.Owner = nil
	must(t, c.Set("bcrypt.cost", "13"))
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "tacctl.yaml" {
		t.Fatalf("directory holds %v", entries)
	}
}

func TestConcurrentWritersAreSerialised(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tacctl.yaml")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := Load(path, DefaultBackends)
			c.Owner = nil
			if err := c.Set(fmt.Sprintf("aaa.order.s%d", i), "local-first"); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	c := Load(path, DefaultBackends)
	if got := len(c.GetKeys("aaa.order")); got != 8 {
		t.Fatalf("%d of 8 writes survived:\n%s", got, readFile(t, path))
	}
}

func TestReadOverridesOSErrors(t *testing.T) {
	dir := t.TempDir()
	if m, why := ReadOverrides(dir); m.Len() != 0 || why != "[Errno 21] Is a directory: '"+dir+"'" {
		t.Fatalf("got %q", why)
	}
	if _, why := ReadOverrides(""); why != "" {
		t.Fatal("empty path")
	}
	if _, why := ReadOverrides(filepath.Join(dir, "missing")); why != "" {
		t.Fatal("missing file")
	}
	if os.Getuid() != 0 {
		p := filepath.Join(dir, "locked")
		writeFile(t, p, "a: 1\n")
		must(t, os.Chmod(p, 0))
		if _, why := ReadOverrides(p); why != "[Errno 13] Permission denied: '"+p+"'" {
			t.Fatalf("got %q", why)
		}
	}
	p := filepath.Join(dir, "bad-utf8")
	writeFile(t, p, "a: \xff\n")
	if _, why := ReadOverrides(p); why != "'utf-8' codec can't decode byte 0xff in position 3: invalid start byte" {
		t.Fatalf("got %q", why)
	}
}

func TestDump(t *testing.T) {
	c := tempConf(t)
	var b bytes.Buffer
	must(t, c.Dump(&b))
	for _, want := range []string{"\033[1mtacctl configuration\033[0m\n", "  Overrides: " + c.Path + "\n",
		"  (no overrides — running on defaults)\n", "\033[1m--- Effective (merged) ---\033[0m\npassword:\n  max_age_days: 90\n",
		"  - name: '*'\n    action: deny\n\n"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("dump lacks %q:\n%s", want, b.String())
		}
	}
	if !strings.HasSuffix(b.String(), "    action: deny\n\n") {
		t.Fatalf("dump ends %q", b.String()[b.Len()-40:])
	}
}

func TestWarningAndProblem(t *testing.T) {
	c := tempConf(t)
	if c.Warning() != "" || c.Problem() != "" {
		t.Fatal("no file, no warning")
	}
	var b bytes.Buffer
	c.WarnOnce(&b)
	if b.Len() != 0 {
		t.Fatal("warned")
	}
	writeFile(t, c.Path, "bcrypt:\n\tcost: 14\n")
	c.Reload()
	c.WarnOnce(&b)
	// echo -e turns the '\t' of the problem into a tab, as warn() does.
	want := "\033[1;33m[WARN]\033[0m tacctl.yaml: could not parse " + c.Path +
		": line 2, column 1: found character '\t' that cannot start any token; using the defaults " +
		"(fix or remove the file; 'tacctl config validate' checks it).\n"
	if b.String() != want {
		t.Fatalf("got %q\nwant %q", b.String(), want)
	}
	if !strings.Contains(c.Warning(), `'\t'`) {
		t.Fatal("Warning() is the text before echo -e")
	}
}

func TestMergedViewAccessors(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("bcrypt.cost", "13"))
	if v, ok := c.Value("bcrypt.cost"); !ok || v != 13 {
		t.Fatalf("got %v %v", v, ok)
	}
	if _, ok := c.Value("nope"); ok {
		t.Fatal("nope")
	}
	if c.Overrides().Len() != 1 || c.Merged().Len() != 8 {
		t.Fatalf("overrides %d merged %d", c.Overrides().Len(), c.Merged().Len())
	}
	if _, printed := c.Get("mgmt_acl", "x"); printed {
		t.Fatal("a mapping prints nothing")
	}
	if got, _ := c.Get("bcrypt", "x"); got != "" {
		t.Fatal("mapping")
	}
	if s, err := c.GetJSON(""); err != nil || s != "null" {
		t.Fatalf("GetJSON(\"\") = %q %v", s, err)
	}
	if s := NewSchema([]string{"tacacs"}).Validate("backends.enabled", []any{"radius"}, true); s != "element 0: 'radius' is not a backend (known: tacacs)" {
		t.Fatalf("registry: %q", s)
	}
}

// echoE agrees with bash's builtin 'echo -e' on the escapes it knows.
func TestEchoEMatchesBash(t *testing.T) {
	bash, err := execx.Real{}.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	cases := []string{`plain`, `tab\there`, `nl\nx`, `'\t' and '\\'`, `\x41\x4`, `\x`, `\0101\07`, `\u00e9\U0001F600`,
		`\u`, `\q unknown`, `\a\b\e\E\f\r\v`, `end\cnever`, `trailing\`, `\1\2`, `%s`}
	for _, in := range cases {
		res, err := execx.Real{}.Run(t.Context(), execx.Cmd{Name: bash, Args: []string{"-c", `echo -n -e "$1"`, "bash", in}})
		if err != nil {
			t.Fatal(err)
		}
		if got := echoE(in); got != string(res.Stdout) {
			t.Errorf("echoE(%q) = %q, bash %q", in, got, res.Stdout)
		}
	}
}
