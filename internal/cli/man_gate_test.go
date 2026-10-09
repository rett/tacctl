package cli

// The completeness gate of the manual page (docs/plans/0.2.3-plan.md D57).
// man/tacctl.1 is hand-written and shows everything, whatever the caller's
// tier. man_test.go checks that it names every command of the tree; the
// tests here check that it also has, for the code as it is:
//
//   - every flag of every command in the command's entry,
//   - every key of tacctl.yaml and of console.yaml (with type and default),
//   - every path of internal/paths under FILES,
//   - every environment variable the code reads under ENVIRONMENT,
//   - every exit status the tests pin under EXIT STATUS,
//   - every row of tier.Rules under TIERS, in the tier it is open to.
//
// The reference blocks that can be derived from the code (the tiers, the
// configuration keys, each command's tier line and flag list) are generated
// into marked regions by man_gen_test.go ('make man') and compared byte for
// byte, so they cannot drift. Every failure names the missing item and the
// part of the page to edit.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// manEntry is one '.TP' entry of the page that is about a command: its tag
// resolves to the commands in cmds ('config allow { list | add }' is both).
type manEntry struct {
	cmds       [][]string
	tag        string
	start, end int // raw lines [start, end): the '.TP' to the next entry or heading
	section    string
	sub        string // the '.SS' heading
}

// manDoc is man/tacctl.1 read as lines, with its headings and entries.
type manDoc struct {
	lines    []string
	entries  []manEntry
	sections map[string][2]int // '.SH' name -> raw lines [start, end)
}

var manWord = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// manTagCommands are the commands a '.TP' tag is about: the leading words
// that name commands of the tree, for each alternative of a braced group.
func manTagCommands(root *cobra.Command, tag string) [][]string {
	var out [][]string
	for _, v := range expandAlternatives(tag) {
		var path []string
		c := root
		for _, w := range strings.Fields(v) {
			if !manWord.MatchString(w) {
				break
			}
			next := child(c, w)
			if next == nil {
				break
			}
			path = append(path, next.Name())
			c = next
		}
		if len(path) > 0 && !slices.ContainsFunc(out, func(p []string) bool { return slices.Equal(p, path) }) {
			out = append(out, path)
		}
	}
	return out
}

// readManDoc reads the page and finds its entries.
func readManDoc(t *testing.T) *manDoc {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "man", "tacctl.1"))
	if err != nil {
		t.Fatal(err)
	}
	d := &manDoc{lines: strings.Split(strings.TrimSuffix(string(src), "\n"), "\n"), sections: map[string][2]int{}}
	root := newRoot(&invocation{app: newHarness(t, nil).app})
	section, sub, last := "", "", ""
	closeEntry := func(i int) {
		if n := len(d.entries); n > 0 && d.entries[n-1].end == 0 {
			d.entries[n-1].end = i
		}
	}
	for i, l := range d.lines {
		switch {
		case strings.HasPrefix(l, ".SH "):
			closeEntry(i)
			if last != "" {
				d.sections[last] = [2]int{d.sections[last][0], i}
			}
			section, _ = manLineText(l)
			sub, last = "", section
			d.sections[section] = [2]int{i, 0}
		case strings.HasPrefix(l, ".SS "):
			closeEntry(i)
			sub, _ = manLineText(l)
		case l == ".TP" && i+1 < len(d.lines):
			tag, _ := manLineText(d.lines[i+1])
			if cmds := manTagCommands(root, tag); len(cmds) > 0 {
				closeEntry(i)
				d.entries = append(d.entries, manEntry{cmds: cmds, tag: tag, start: i, section: section, sub: sub})
			}
		}
	}
	closeEntry(len(d.lines))
	if last != "" {
		d.sections[last] = [2]int{d.sections[last][0], len(d.lines)}
	}
	return d
}

// text is the cleaned text of the raw lines [from, to), one string per line
// that prints something.
func (d *manDoc) text(from, to int) []string {
	var out []string
	for _, l := range d.lines[from:to] {
		if s, ok := manLineText(l); ok {
			out = append(out, s)
		}
	}
	return out
}

// tags are the '.TP' tags (cleaned, braced alternatives expanded) and, for
// each, the cleaned lines of its body up to the next '.TP' or heading, in
// the raw lines [from, to).
func (d *manDoc) tagged(from, to int) (tags []string, body map[string]string) {
	body = map[string]string{}
	cur := ""
	for i := from; i < to; i++ {
		l := d.lines[i]
		switch {
		case l == ".TP" && i+1 < to:
			text, _ := manLineText(d.lines[i+1])
			cur = text
			tags = append(tags, text)
			i++
			continue
		case strings.HasPrefix(l, ".SH "), strings.HasPrefix(l, ".SS "):
			cur = ""
		}
		if text, ok := manLineText(l); ok && cur != "" {
			body[cur] += " " + text
		}
	}
	return tags, body
}

// section is the raw line range of a '.SH' section; the test fails, naming
// the section to add, when the page lacks it.
func (d *manDoc) section(t *testing.T, name, why string) (from, to int) {
	t.Helper()
	r, ok := d.sections[name]
	if !ok {
		t.Fatalf("man/tacctl.1 has no .SH %s section; add it (%s)", name, why)
	}
	return r[0], r[1]
}

// entriesOf are the entries about the command at path.
func (d *manDoc) entriesOf(path []string) []manEntry {
	var out []manEntry
	for _, e := range d.entries {
		if slices.ContainsFunc(e.cmds, func(p []string) bool { return slices.Equal(p, path) }) {
			out = append(out, e)
		}
	}
	return out
}

// visibleLeaves are the commands that run something and are not hidden,
// with their cobra command.
func visibleLeaves(root *cobra.Command) (paths [][]string, cmds []*cobra.Command) {
	var walk func(c *cobra.Command, prefix []string)
	walk = func(c *cobra.Command, prefix []string) {
		for _, sub := range c.Commands() {
			if sub.Hidden {
				continue
			}
			p := append(slices.Clone(prefix), sub.Name())
			if len(sub.Commands()) == 0 {
				paths, cmds = append(paths, p), append(cmds, sub)
			}
			walk(sub, p)
		}
	}
	walk(root, nil)
	return paths, cmds
}

// manHas reports whether text holds word as a whole token: not inside a
// longer word, flag or path.
func manHas(text, word string) bool {
	re := regexp.MustCompile(`(^|[^A-Za-z0-9_.-])` + regexp.QuoteMeta(word) + `($|[^A-Za-z0-9_-])`)
	return re.MatchString(text)
}

// Every flag of every command, in every spelling, is in the entry of its
// command: the flags are those of the argument-spec tables (specFor, what
// TestEveryFlagHasADescription walks).
func TestManPageDocumentsEveryFlag(t *testing.T) {
	d := readManDoc(t)
	root := newRoot(&invocation{app: newHarness(t, nil).app})
	var all [][]string
	treeVerbs(root, nil, &all)
	checked := 0
	for _, p := range all {
		spec, ok := specFor(p)
		if !ok || len(spec.Flags) == 0 {
			continue
		}
		words := strings.Join(p, " ")
		entries := d.entriesOf(p)
		var text strings.Builder
		for _, e := range entries {
			text.WriteString(strings.Join(d.text(e.start, e.end), "\n") + "\n")
		}
		for _, f := range spec.Flags {
			for _, n := range f.Names {
				checked++
				switch {
				case len(entries) == 0:
					t.Errorf("man/tacctl.1: 'tacctl %s' has flag %s but no .TP entry (add one whose tag starts '%s')", words, n, words)
				case !manHas(text.String(), n):
					t.Errorf("man/tacctl.1: flag %s of 'tacctl %s' is not in its entry (section %q, the entry %q): run 'make man', or describe it there", n, words, entries[0].sub, entries[0].tag)
				}
			}
		}
	}
	if checked < 150 {
		t.Fatalf("only %d flags checked", checked)
	}
}

// Env: the variables the code reads.

// manEnvExempt are the variables the code reads that the page does not
// document, each with the reason. Every one must still be read.
var manEnvExempt = func() map[string]string {
	m := map[string]string{}
	add := func(reason string, names ...string) {
		for _, n := range names {
			m[n] = reason
		}
	}
	add("relocates a path for the test sandbox (paths.Resolve; tests/README.md), not an operator interface",
		"TACCTL_ETC", "TACCTL_STATE_DIR", "TACCTL_LOG", "TACCTL_BIN", "TACCTL_CONFIG", "TACCTL_SSHD_DROPIN",
		"TACCTL_SSHD_ENGINEER_DROPIN", "TACCTL_SSH_DIR", "TACCTL_SHELLS_FILE", "TACCTL_VAR_LIB", "TACCTL_SUDOERS_FILE",
		"TACCTL_TIER_SUDOERS_FILE", "TACCTL_OVERRIDE_DIR", "TACCTL_SYSTEMD_DIR", "TACCTL_LOGROTATE_DIR",
		"TACCTL_LINUX_DIR", "TACCTL_LOGIN_DEFS", "TACCTL_PATCH_DIR", "TACCTL_TREE")
	add("forces the FreeRADIUS layout or one of its paths in the test sandbox (paths.Radius), not an operator interface",
		"TACCTL_RADIUS_FAMILY", "TACCTL_RADIUS_DIR", "TACCTL_RADIUS_BIN", "TACCTL_RADIUS_LOG", "TACCTL_RADIUS_DICT")
	add("shortens the settle wait of a restarted unit in the test sandbox, not an operator interface", "TACCTL_SETTLE_SECONDS")
	add("turns off the sudo re-exec in the test sandbox (tests only; paths.Paths.SkipSudo)", "TACCTL_SKIP_SUDO")
	add("a test knob, read only by a binary built with -tags testknobs (tests/README.md)",
		"TACCTL_TEST_NOW", "TACCTL_TEST_RANDOM", "TACCTL_FAULT", "TACCTL_TEST_ROOT", "TACCTL_TEST_CONSOLE_ENV", "TACCTL_TEST_PROC")
	return m
}()

var reEnvName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// envReads are the environment variables the non-test code of internal/ and
// cmd/ reads: a string literal (or a string constant) given to
// Env.Get/Lookup/Or of a paths.Env, or to os.Getenv/LookupEnv. The reads
// whose name is not a literal or a constant are returned in dynamic.
func envReads(t *testing.T) (names map[string][]string, dynamic []string) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	var rels []string
	root := filepath.Join("..", "..")
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, de fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if de.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			files = append(files, f)
			rel, _ := filepath.Rel(root, p)
			rels = append(rels, rel)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	// String constants by name (the Env* names of internal/app and
	// internal/console).
	consts := map[string]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
							if v, err := strconv.Unquote(lit.Value); err == nil && reEnvName.MatchString(v) {
								consts[n.Name] = v
							}
						}
					}
				}
			}
		}
	}
	names = map[string][]string{}
	lastName := func(e ast.Expr) string {
		switch x := e.(type) {
		case *ast.Ident:
			return x.Name
		case *ast.SelectorExpr:
			return x.Sel.Name
		}
		return ""
	}
	for i, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			recv := lastName(sel.X)
			switch {
			case slices.Contains([]string{"Get", "Lookup", "Or"}, sel.Sel.Name) && (recv == "env" || recv == "Env"):
			case slices.Contains([]string{"Getenv", "LookupEnv"}, sel.Sel.Name) && recv == "os":
			default:
				return true
			}
			var name string
			switch a := call.Args[0].(type) {
			case *ast.BasicLit:
				name, _ = strconv.Unquote(a.Value)
			default:
				name = consts[lastName(a)]
			}
			if !reEnvName.MatchString(name) {
				dynamic = append(dynamic, rels[i]+":"+strconv.Itoa(fset.Position(call.Pos()).Line))
				return true
			}
			if !slices.Contains(names[name], rels[i]) {
				names[name] = append(names[name], rels[i])
			}
			return true
		})
	}
	return names, dynamic
}

// Every environment variable the code reads is under ENVIRONMENT, or is
// exempt with a reason.
func TestManPageDocumentsEveryEnvironmentVariable(t *testing.T) {
	reads, dynamic := envReads(t)
	if len(dynamic) > 0 {
		t.Errorf("an environment read whose name is neither a literal nor a string constant cannot be checked against the page; name it by a constant: %v", dynamic)
	}
	if len(reads) < 20 {
		t.Fatalf("only %d environment variables found in the code", len(reads))
	}
	d := readManDoc(t)
	from, to := d.section(t, "ENVIRONMENT", "one .TP per variable the code reads")
	tags, _ := d.tagged(from, to)
	documented := map[string]bool{}
	for _, tag := range tags {
		for _, w := range regexp.MustCompile(`[A-Z][A-Z0-9_]+`).FindAllString(tag, -1) {
			documented[w] = true
		}
	}
	for name, files := range reads {
		_, exempt := manEnvExempt[name]
		switch {
		case exempt && documented[name]:
			t.Errorf("%s is documented under ENVIRONMENT but also in manEnvExempt (%s): drop the exemption", name, manEnvExempt[name])
		case !exempt && !documented[name]:
			t.Errorf("environment variable %s is read (%s) but not documented: add a .TP %s entry under .SH ENVIRONMENT in man/tacctl.1 (or, for a test-only knob, an entry with a reason in manEnvExempt)", name, strings.Join(files, ", "), name)
		}
	}
	for name := range manEnvExempt {
		if _, ok := reads[name]; !ok {
			t.Errorf("manEnvExempt lists %s, which the code no longer reads: drop it", name)
		}
	}
	for name := range documented {
		if _, ok := reads[name]; !ok && regexp.MustCompile(`^[A-Z][A-Z0-9_]{3,}$`).MatchString(name) && !slices.Contains([]string{"ENVIRONMENT"}, name) {
			t.Errorf(".SH ENVIRONMENT documents %s, which the code does not read", name)
		}
	}
}

// Exit: the statuses the tests pin.

// manExitStatuses are the exit statuses the CLI tests pin: the table of
// TestExitCode (every error class exitCode maps), the sudo re-exec's 126 and
// 127, and the exit column of the usage goldens.
func manExitStatuses(t *testing.T) []int {
	t.Helper()
	set := map[int]bool{}
	for _, c := range exitCodeCases() {
		set[c.code] = true
	}
	tsv, err := os.ReadFile(filepath.Join("testdata", "usage", "cases.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(tsv), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if n, err := strconv.Atoi(f[1]); err == nil {
			set[n] = true
		}
	}
	var out []int
	for n := range set {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// Every exit status the tests pin is under EXIT STATUS.
func TestManPageDocumentsEveryExitStatus(t *testing.T) {
	codes := manExitStatuses(t)
	if len(codes) < 6 {
		t.Fatalf("only %v pinned", codes)
	}
	d := readManDoc(t)
	from, to := d.section(t, "EXIT STATUS", "one .TP per status")
	tags, body := d.tagged(from, to)
	for _, c := range codes {
		n := strconv.Itoa(c)
		if !slices.ContainsFunc(tags, func(tag string) bool { return tag == n || strings.HasPrefix(tag, n+" ") }) {
			t.Errorf("exit status %d is pinned by the tests but not documented: add a .TP %d entry under .SH EXIT STATUS in man/tacctl.1", c, c)
		}
	}
	for _, tag := range tags {
		if w, _, _ := strings.Cut(tag, " "); regexp.MustCompile(`^[0-9]+$`).MatchString(w) {
			if n, _ := strconv.Atoi(w); !slices.Contains(codes, n) {
				t.Errorf(".SH EXIT STATUS documents %s (%q), which no test pins", w, strings.TrimSpace(body[tag]))
			}
		}
	}
}

// Paths: internal/paths.

// manPathExempt are the paths of internal/paths that FILES does not list,
// each with the reason.
var manPathExempt = map[string]string{
	"/usr/local/bin":                              "the directory of tacctl, tacquito and tacquito-hashgen, which FILES lists one by one",
	"/var/log/tacquito":                           "the directory of accounting.log, which FILES lists",
	"/etc/systemd/system":                         "systemd's own directory; FILES lists the units and drop-ins tacctl writes in it",
	"/etc/systemd/system/tacquito.service.d":      "the directory of tacctl.conf, which FILES lists",
	"/etc/logrotate.d":                            "logrotate's own directory; FILES names the files tacctl writes in it",
	"/etc/ssh":                                    "sshd's own directory; FILES lists the drop-ins in sshd_config.d and the host keys by their glob",
	"/etc/ssh/sshd_config.d/tacctl-engineer.conf": "the earlier name of the engineer drop-in, which FILES names (tacctl-engineer.conf) as renamed",
	"/etc/tacctl/snmp":                            "the directory of the per-scope credential files, which FILES lists as snmp/<scope>.yaml",
	"/etc/tacctl/backups/password-dates":          "a directory inside backups/, which FILES lists",
	"/opt/tacctl/patches":                         "the tacquito patches inside the checkout, which FILES lists as /opt/tacctl/",
	"<raddb>/tacctl-radius-dictionary":            "the directory of the dictionary file, which FILES lists",
}

// pathValues are the paths internal/paths resolves with no override, the
// RADIUS ones written as FILES writes them (<raddb>, <logs>), and each with
// the name it has in the code.
func pathValues(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	p := paths.Resolve(paths.NewEnv(nil), "", func(string) bool { return false })
	v := reflect.ValueOf(p)
	for i := range v.NumField() {
		f := v.Type().Field(i)
		if f.Type.Kind() != reflect.String || !f.IsExported() {
			continue
		}
		if s := v.Field(i).String(); strings.HasPrefix(s, "/") {
			out[s] = "paths.Paths." + f.Name
		}
	}
	r := p.Radius("debian")
	rv := reflect.ValueOf(r)
	for i := range rv.NumField() {
		f := rv.Type().Field(i)
		s := rv.Field(i).String()
		if f.Type.Kind() != reflect.String || !strings.HasPrefix(s, "/") {
			continue
		}
		s = strings.Replace(strings.Replace(s, r.LogDir, "<logs>", 1), r.Dir, "<raddb>", 1)
		out[s] = "paths.RadiusPaths." + f.Name
	}
	// The string constants of paths.go that are paths.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join("..", "paths", "paths.go"), nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, err := strconv.Unquote(lit.Value); err == nil && strings.HasPrefix(s, "/") {
							if _, dup := out[s]; !dup {
								out[s] = "paths." + n.Name
							}
						}
					}
				}
			}
		}
	}
	return out
}

// Every path of internal/paths is under FILES, or exempt with a reason.
func TestManPageDocumentsEveryPath(t *testing.T) {
	vals := pathValues(t)
	if len(vals) < 30 {
		t.Fatalf("only %d paths found", len(vals))
	}
	d := readManDoc(t)
	from, to := d.section(t, "FILES", "one .TP per file or directory tacctl reads or writes")
	text := strings.Join(d.text(from, to), "\n")
	for _, p := range slices.Sorted(maps.Keys(vals)) {
		_, exempt := manPathExempt[p]
		documented := regexp.MustCompile(`(^|[^A-Za-z0-9_./<>-])` + regexp.QuoteMeta(p) + `/?($|[^A-Za-z0-9_./<*-])`).MatchString(text)
		switch {
		case exempt && documented:
			t.Errorf("%s is under FILES but also in manPathExempt (%s): drop the exemption", p, manPathExempt[p])
		case !exempt && !documented:
			t.Errorf("path %s (%s) is not under .SH FILES in man/tacctl.1: add a .TP %s entry in the part it belongs to (or, with a reason, to manPathExempt)", p, vals[p], p)
		}
	}
	for p := range manPathExempt {
		if _, ok := vals[p]; !ok {
			t.Errorf("manPathExempt lists %s, which internal/paths no longer resolves: drop it", p)
		}
	}
	// The RHEL names of the unit and the RADIUS drop-in.
	for _, want := range []string{"radiusd.service.d", "/etc/raddb"} {
		if !strings.Contains(text, want) {
			t.Errorf("FILES does not name the RHEL layout (%s)", want)
		}
	}
}

// Tiers.

// Every row of tier.Rules is under TIERS, in the tier it is open to.
func TestManPageListsEveryTierRow(t *testing.T) {
	d := readManDoc(t)
	from, to := d.section(t, "TIERS", "the generated tier table: 'make man'")
	_, body := d.tagged(from, to)
	for _, r := range tier.Rules {
		name := manRowName(r)
		found := false
		for tag, text := range body {
			if tag == string(r.Tier) && slices.Contains(strings.Split(strings.TrimSpace(text), ", "), manClean(manRowName(r))) {
				found = true
			}
		}
		if !found {
			t.Errorf("tier.Rules row %q (%s) is not listed under .SH TIERS, in the %s entry: run 'make man'", name, r.Tier, r.Tier)
		}
	}
}
