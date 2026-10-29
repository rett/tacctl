package cli

// What Tab and '?' list, held to one style (0.2.18 item 7): every usage
// row and every flag has a description, the descriptions follow one
// convention, the placeholders one syntax, the columns line up, and the
// usage and the argument specs name the same flags. The rows and the
// descriptions are the usage's (shellUsage, flagHelp), so the man page's
// option lists follow the same rules.

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/spf13/cobra"
)

// styleNames are the lower-case words a description may begin with: names
// that are written in lower case.
var styleNames = []string{"tacctl", "pam_tacplus"}

// styleFault is what is wrong with a description of a list, or "": it is
// there, is one line without tabs and doubled blanks, begins with a capital
// (after a '(verbs) ' opening; a name such as tacctl stays as it is) and
// ends without a full stop or another mark, as its neighbours do.
func styleFault(desc string) string {
	rest := desc
	if strings.HasPrefix(rest, "(") {
		if i := strings.Index(rest, ") "); i > 0 {
			rest = rest[i+2:]
		}
	}
	first, _, _ := strings.Cut(rest, " ")
	switch {
	case desc == "":
		return "no description"
	case strings.ContainsAny(desc, "\t\n"):
		return "a tab or a line break"
	case strings.TrimSpace(desc) != desc || strings.Contains(desc, "  "):
		return "blanks at an end or doubled"
	case strings.ContainsAny(desc[len(desc)-1:], ".;,:") && !strings.HasSuffix(desc, "..."):
		return "ends with " + desc[len(desc)-1:]
	case strings.Contains(desc, "TODO") || strings.Contains(desc, "FIXME"):
		return "a placeholder text"
	case reLetterPlaceholder.MatchString(desc):
		return "names a value by a letter, not its placeholder"
	case first != "" && unicode.IsLower(rune(first[0])) && !slices.Contains(styleNames, strings.TrimRight(first, ",:;")):
		return "begins in lower case"
	}
	return ""
}

// reLetterPlaceholder is a value a description names by a capital letter
// ('the last N entries') where the row has its placeholder ('<n>').
var reLetterPlaceholder = regexp.MustCompile(`(^|\s)[NMK](\s|$)`)

func TestStyleFault(t *testing.T) {
	for _, ok := range []string{"Show the list", "(add) Put the rule first", "tacctl tier (readonly, operator)", "Remove one or more ...", "(add, remove) A regex"} {
		if f := styleFault(ok); f != "" {
			t.Errorf("%q: %s", ok, f)
		}
	}
	for _, bad := range []string{"", "Show the list.", "show the list", "(add) put it first", "Show  the list", "Show the list ", "Show;", "Show\tit", "Show the last N entries"} {
		if styleFault(bad) == "" {
			t.Errorf("%q passes", bad)
		}
	}
}

// reFlagValueWord is a flag's value as the lists show it: a placeholder
// ('<name>', '<s>[,s...]'), a choice of fixed words ('tacacs|radius') or a
// fixed word with a placeholder ('SHA256:<fp>').
var reFlagValueWord = regexp.MustCompile(`^(<[^<>]+>(\[[^\]]*\])?|[a-z0-9]+(\|[a-z0-9]+)+|[A-Za-z0-9]+:<[^<>]+>)$`)

// reLeftFlag finds the flags a usage row names.
var reLeftFlag = regexp.MustCompile(`(?:^|[\s\[|(,])(--?[a-zA-Z][a-zA-Z0-9-]*)`)

// Every command '?' explains has usage rows with a description in the
// style, and every flag of its spec has a description and a value in the
// lists' syntax; the rows name no flag the spec (what Tab offers) lacks.
func TestShellUsageAndFlagsFollowTheStyle(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	paths, cmds := visibleLeaves(root)
	for i, p := range paths {
		name := strings.Join(p, " ")
		rows, block := inv.shellUsage(cmds[i], p)
		if len(rows) == 0 {
			t.Errorf("%s: no usage row", name)
		}
		spec, hasSpec := specFor(p)
		for _, r := range rows {
			if r.Left != oneBlank(r.Left) || strings.HasPrefix(r.Left, "tacctl ") {
				t.Errorf("%s: usage row %q is not one blank between words, without the program", name, r.Left)
			}
			if f := styleFault(r.Desc); f != "" {
				t.Errorf("%s: usage row %q: %s (%q)", name, r.Left, f, r.Desc)
			}
			for _, m := range reLeftFlag.FindAllStringSubmatch(r.Left, -1) {
				if hasSpec && !slices.ContainsFunc(spec.Flags, func(f Flag) bool { return slices.Contains(f.Names, m[1]) }) {
					t.Errorf("%s: the usage row %q names %s, which completion does not offer", name, r.Left, m[1])
				}
			}
		}
		for _, f := range spec.Flags {
			value, desc := flagHelp(block, rows, f)
			if fault := styleFault(desc); fault != "" {
				t.Errorf("%s %s: %s (%q)", name, f.Names[0], fault, desc)
			}
			if f.Value && !reFlagValueWord.MatchString(value) {
				t.Errorf("%s %s: value %q is not '<name>', 'a|b' or 'WORD:<name>'", name, f.Names[0], value)
			}
		}
	}
}

// Every family lists each of its verbs with a description in the style,
// and its block (help <family>) has a row for each.
func TestShellFamilyListsFollowTheStyle(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	complete := inv.shellCompleter(root)
	for _, c := range complete(nil, "") {
		if f := styleFault(c.Desc); f != "" {
			t.Errorf("top level %s: %s (%q)", c.Word, f, c.Desc)
		}
	}
	var walk func(c *cobra.Command, path []string)
	walk = func(c *cobra.Command, path []string) {
		if c.Hidden || len(c.Commands()) == 0 {
			return
		}
		if len(path) > 0 {
			for _, cand := range complete(path, "") {
				if f := styleFault(cand.Desc); f != "" {
					t.Errorf("%s %s: %s (%q)", strings.Join(path, " "), cand.Word, f, cand.Desc)
				}
			}
			if blk, ok := shellHelpBlocks[strings.Join(path, " ")]; ok {
				for _, sub := range c.Commands() {
					if !sub.Hidden && len(verbRows(blk(inv), path, sub.Name())) == 0 {
						t.Errorf("help %s has no row for %s", strings.Join(path, " "), sub.Name())
					}
				}
			}
		}
		for _, sub := range c.Commands() {
			walk(sub, append(slices.Clone(path), sub.Name()))
		}
	}
	walk(root, nil)
}

// The placeholders of the usage rows are '<name>', optional '[<name>]':
// no bare '[name]' and no upper-case '<NAME>'.
func TestUsagePlaceholderSyntax(t *testing.T) {
	inv, _, _ := shellTestInv(t)
	blocks := map[string]string{"top": Usage("top", UsageVars{"version": "v"})}
	for k, f := range shellHelpBlocks {
		blocks[k] = f(inv)
	}
	bare := regexp.MustCompile(`\[([a-z][a-z0-9-]*)\]`)
	upper := regexp.MustCompile(`<[A-Z][A-Z0-9_-]*>`)
	for k, b := range blocks {
		for _, line := range blockBody(b) {
			if !strings.HasPrefix(line, "  ") || strings.HasPrefix(strings.TrimSpace(line), "-") {
				continue
			}
			left, _, ok := splitRow(line)
			if !ok {
				left = line
			}
			for _, m := range bare.FindAllStringSubmatch(left, -1) {
				if m[1] != "options" && m[1] != "arguments" {
					t.Errorf("help %s: %q writes the placeholder %s without <>", k, strings.TrimSpace(left), m[0])
				}
			}
			if m := upper.FindString(left); m != "" {
				t.Errorf("help %s: %q writes the placeholder %s in upper case", k, strings.TrimSpace(left), m)
			}
		}
	}
}

// alignRows lines the descriptions up two blanks after the widest left
// column of the rows that have one; a row without a description is its
// left column alone, and does not widen the others.
func TestAlignRowsContract(t *testing.T) {
	got := alignRows([][2]string{{"a", "One"}, {"a-much-longer-row-alone", ""}, {"abc <x>", "Two"}, {"", "Three"}})
	want := "  a        One\n  a-much-longer-row-alone\n  abc <x>  Two\n           Three\n"
	if got != want {
		t.Errorf("alignRows:\n%s\nwant\n%s", got, want)
	}
}

// What '?' prints where no word can be offered, for every command: the
// sections' lines are indented rows without tabs or trailing blanks, the
// descriptions of a section start in one column, and it ends with Next.
func TestShellExplainIsClean(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	explain := inv.plainExplain(root)
	paths, _ := visibleLeaves(root)
	for _, p := range paths {
		out, ok := explain(p)
		if !ok {
			t.Errorf("%s: '?' explains nothing", strings.Join(p, " "))
			continue
		}
		lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if !strings.HasPrefix(lines[len(lines)-1], "Next: ") {
			t.Errorf("%s: no Next line:\n%s", strings.Join(p, " "), out)
		}
		col := -1
		for _, l := range lines {
			switch {
			case strings.ContainsAny(l, "\t") || strings.TrimRight(l, " ") != l:
				t.Errorf("%s: tab or trailing blank in %q", strings.Join(p, " "), l)
			case l == "Usage:" || l == "Options:":
				col = -1
			case strings.HasPrefix(l, "  "):
				// The description starts after the last run of two blanks.
				if i := strings.LastIndex(l, "  "); i > 2 {
					at := i + 2
					if col >= 0 && at != col && strings.Count(l[2:], "  ") == 1 {
						t.Errorf("%s: %q starts its description at %d, not %d", strings.Join(p, " "), l, at, col)
					}
					if strings.Count(l[2:], "  ") == 1 {
						col = at
					}
				}
			case strings.HasPrefix(l, "Next: "), strings.HasPrefix(l, "Needs the "):
			default:
				t.Errorf("%s: unexpected line %q", strings.Join(p, " "), l)
			}
		}
	}
}

// The fixed words a position takes are described by the row that has the
// word there alone, and only then; Next names the choice where the rows
// part, each word once.
func TestShellDescribesFixedWords(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	complete := inv.shellCompleter(root)
	desc := func(words []string, w string) string {
		for _, c := range complete(words, "") {
			if c.Word == w {
				return c.Desc
			}
		}
		t.Fatalf("%v: %s not offered", words, w)
		return ""
	}
	for _, c := range []struct {
		words      []string
		word, want string
	}{
		{[]string{"group", "edit", "ops"}, "priv-lvl", "Change Cisco privilege level"},
		{[]string{"scope", "prefixes", "lab"}, "list", "Show entries"},
		{[]string{"console", "forwarding"}, "gateway-ports", "Opt in to forwarded ports"},
		{[]string{"scope", "snmp", "lab"}, "show", "The scope's SNMP settings"},
		// one of a choice: the row is about the verb
		{[]string{"user", "scope", "alice"}, "remove", ""},
		{[]string{"user", "scope", "alice"}, "add", ""},
	} {
		if got := desc(c.words, c.word); !strings.HasPrefix(got, c.want) || (c.want == "" && got != "") {
			t.Errorf("%v %s: %q, want %q", c.words, c.word, got, c.want)
		}
	}
	explain := inv.plainExplain(root)
	for _, c := range []struct {
		words []string
		next  string
	}{
		{[]string{"group", "edit"}, "Next: <name> priv-lvl|juniper-class|wti-level|tier ...\n"},
		{[]string{"group", "edit", "ops", "tier"}, "Next: auto|<tier>\n"},
		{[]string{"user", "scope"}, "Next: <user> list|add|remove|replace\n"},
		{[]string{"scope", "prefixes"}, "Next: <scope> list|add|remove|move ...\n"},
		// 'install' is a command word, not a positional: the rows are the
		// 'sudoers' rows of 'config'
		{[]string{"config", "sudoers", "install"}, "Next: [<group>], or <Enter> to run\n"},
		{[]string{"config", "allow", "add"}, "Next: <cidr>[,<cidr>...]\n"},
	} {
		out, _ := explain(c.words)
		if !strings.HasSuffix(out, c.next) {
			t.Errorf("%v:\n%s\nwant it to end %q", c.words, out, c.next)
		}
	}
}

// Of the option lines a block has for one flag name, '?' takes the one of
// the verb: under its own rows, else the one that names it.
func TestShellFlagHelpIsTheVerbs(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	for _, c := range []struct {
		path       []string
		flag, want string
	}{
		{[]string{"config", "cisco"}, "--legacy", "(cisco) The IOS 12.x syntax"},
		{[]string{"config", "restore"}, "--legacy", "The timestamp names an old-style backup"},
		{[]string{"rollback"}, "--yes", "Acknowledge the warnings"},
		{[]string{"install"}, "--yes", "Answer yes to the confirmations"},
		{[]string{"device", "list"}, "--stale", "Only the devices not seen for stale-days"},
		{[]string{"device", "config", "list"}, "--stale", "(pull, diff, plan, apply, list) Only the devices never read"},
		{[]string{"device", "config", "apply"}, "--all", "(pull, diff, plan, apply, forget)"},
		{[]string{"host", "provisioner"}, "--yes", "(provisioner) Rotate without asking"},
		{[]string{"backend", "disable"}, "--yes", "Answer yes to the confirmation"},
		{[]string{"host", "move"}, "--remove-home", "(enroll, sync and move) Delete removed users' home directories"},
		{[]string{"host", "move"}, "--allow-uid-mismatch", "(enroll, sync and move) Accept a UID conflict"},
		{[]string{"breakglass", "hold"}, "--reason", "(hold) Why"},
	} {
		cmd, _ := resolve(root, c.path)
		spec, _ := specFor(c.path)
		helps := inv.flagHelps(cmd, c.path, spec, []string{c.flag})
		if got := helps[c.flag][1]; !strings.HasPrefix(got, c.want) {
			t.Errorf("%v %s: %q, want %q...", c.path, c.flag, got, c.want)
		}
	}
	// A description goes on over the lines that continue it.
	cmd, _ := resolve(root, []string{"host", "forget"})
	rows, _ := inv.shellUsage(cmd, []string{"host", "forget"})
	if len(rows) != 1 || !strings.HasSuffix(rows[0].Desc, "Refused for a held host") {
		t.Errorf("host forget rows %+v", rows)
	}
}

// styleLefts are the argument columns the lists and the usage show, by
// where they come from: every usage block's rows and every command's Use
// (the hidden ones too).
func styleLefts(t *testing.T) map[string][]string {
	inv, root, _ := shellTestInv(t)
	out := map[string][]string{}
	blocks := map[string]string{"top": Usage("top", UsageVars{"version": "v"})}
	for k, f := range shellHelpBlocks {
		blocks[k] = f(inv)
	}
	// The blocks of the usage files, their slots filled as help fills
	// them ('lab' for the scope).
	for _, c := range goldenCases {
		blocks["usage "+c.id] = strings.ReplaceAll(Usage(c.id, c.vars), " lab ", " <scope> ")
	}
	for k, b := range blocks {
		for _, line := range blockBody(b) {
			if !strings.HasPrefix(line, "  ") {
				continue
			}
			left, _, ok := splitRow(line)
			if !ok {
				left = line
			}
			out["help "+k] = append(out["help "+k], strings.TrimSpace(left))
		}
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		out["Use of "+c.CommandPath()] = []string{c.Use}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
	return out
}

// reRange is a number range a placeholder stands for ('10-14'), and
// reRangeOK the one way to write it: '<10-14>' ('[<10-14>]' optional).
var (
	reRange   = regexp.MustCompile(`[\[{(<]?\b[0-9]+-[0-9]+\b[\]})>]?`)
	reRangeOK = regexp.MustCompile(`^<[0-9]+-[0-9]+>$`)
)

// A range is '<lo-hi>' wherever the usage, the rows or a Use name it, and a
// choice of words is 'a|b' without braces, in the order the lists use
// (cisco before juniper).
func TestUsageRangeAndChoiceStyle(t *testing.T) {
	for where, lefts := range styleLefts(t) {
		for _, l := range lefts {
			for _, m := range reRange.FindAllString(l, -1) {
				if !reRangeOK.MatchString(m) {
					t.Errorf("%s: %q writes the range %s, not <lo-hi>", where, l, m)
				}
			}
			if strings.HasPrefix(where, "help ") && strings.ContainsAny(l, "{}") {
				t.Errorf("%s: %q puts a choice in braces", where, l)
			}
			if strings.Contains(l, "juniper|cisco") {
				t.Errorf("%s: %q names juniper before cisco", where, l)
			}
		}
	}
}

// reUsageLit is a 'Usage: tacctl ...' text of the code, up to where a
// value is joined in.
var reUsageLit = regexp.MustCompile(`"(?:  )?Usage: tacctl ([^"]*)"`)

// The usage lines of the errors write ranges and choices as the rows do:
// no '<a|b>' choice of words a row does not name as a placeholder, no
// '[args]' and no range other than '<lo-hi>'.
func TestUsageErrorLinesFollowTheStyle(t *testing.T) {
	known := map[string]bool{}
	for _, lefts := range styleLefts(t) {
		for _, l := range lefts {
			for _, m := range regexp.MustCompile(`<[^<> ]+>`).FindAllString(l, -1) {
				known[m] = true
			}
		}
	}
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range reUsageLit.FindAllStringSubmatch(string(src), -1) {
			// A note after the usage ('   (for example 80000-89999)') is
			// text, not the usage.
			l, _, _ := strings.Cut(m[1], "   ")
			for _, ph := range regexp.MustCompile(`<[^<> ]*\|[^<> ]*>`).FindAllString(l, -1) {
				if !known[ph] {
					t.Errorf("%s: %q writes %s, which no row names (a choice of words is a|b)", f, l, ph)
				}
			}
			if strings.Contains(l, "[args]") {
				t.Errorf("%s: %q ends in [args], not the row's arguments", f, l)
			}
			for _, r := range reRange.FindAllString(l, -1) {
				if !reRangeOK.MatchString(r) {
					t.Errorf("%s: %q writes the range %s, not <lo-hi>", f, l, r)
				}
			}
		}
	}
}

// What a wrong or missing argument prints as its usage is the rows '?'
// and help show for the command, word for word (the scope typed in place
// of <scope>).
func TestUsageErrorRepeatsTheRows(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	sb := newSandbox(t, true)
	for _, c := range []struct{ path, args []string }{
		{[]string{"scope", "breakglass"}, nil},
		{[]string{"scope", "breakglass"}, []string{"lab", "add"}},
		{[]string{"scope", "breakglass"}, []string{"lab", "remove"}},
		{[]string{"scope", "protocols"}, nil},
		{[]string{"scope", "protocols"}, []string{"lab", "set"}},
		{[]string{"scope", "vendor-attrs"}, nil},
		{[]string{"scope", "vendor-attrs"}, []string{"lab", "enable"}},
		{[]string{"scope", "devices"}, nil},
		{[]string{"scope", "devices"}, []string{"lab", "set"}},
		{[]string{"scope", "devices"}, []string{"lab", "unset"}},
		{[]string{"scope", "staging"}, []string{"frob"}},
		{[]string{"scope", "staging"}, []string{"remove"}},
		{[]string{"scope", "mgmt-acl"}, nil},
		{[]string{"scope", "mgmt-acl"}, []string{"lab", "add"}},
		{[]string{"scope", "mgmt-acl"}, []string{"lab", "remove"}},
		{[]string{"scope", "snmp"}, nil},
		{[]string{"group", "edit"}, nil},
		{[]string{"config", "get"}, nil},
		{[]string{"config", "get-list"}, nil},
		{[]string{"device", "snmp"}, nil},
		{[]string{"breakglass", "hold"}, nil},
	} {
		name := strings.Join(append(slices.Clone(c.path), c.args...), " ")
		cmd, _ := resolve(root, c.path)
		rows, _ := inv.shellUsage(cmd, c.path)
		_, n := inv.helpBlock(cmd, c.path)
		lead := "tacctl " + strings.Join(c.path[:min(n, len(c.path)-1)], " ") + " "
		var want []string
		for _, r := range rows {
			want = append(want, lead+r.Left, lead+strings.ReplaceAll(r.Left, "<scope>", "lab"))
		}
		sb.run("", append(slices.Clone(c.path), c.args...))
		var got []string
		for _, l := range strings.Split(plain(sb.out.String()+sb.err.String()), "\n") {
			l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "[ERROR]"))
			if u, ok := strings.CutPrefix(l, "Usage: "); ok {
				got = append(got, u)
			} else if strings.HasPrefix(l, "tacctl ") && len(got) > 0 {
				got = append(got, l)
			}
		}
		if len(got) == 0 {
			t.Errorf("%s: no usage line:\n%s%s", name, sb.out.String(), sb.err.String())
		}
		for _, g := range got {
			if !slices.Contains(want, oneBlank(g)) {
				t.Errorf("%s: the usage line %q is not a row of the command:\n  %s", name, g, strings.Join(want, "\n  "))
			}
		}
	}
}
