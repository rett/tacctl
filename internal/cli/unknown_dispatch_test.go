package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The check before sudo (unknownBelow) takes every word of a command with
// sub-commands that is none of its cobra children for unknown. That is only
// right while the dispatcher of the command accepts no other word: a key
// added to a verb map, or a case, without a verb in the tree would be
// refused before sudo for everybody. This reads the dispatchers of the
// commands that have one (the maps of verbs and the cases of the switch on
// the word) and requires each word to be a child of its command.
func TestDispatcherWordsAreChildren(t *testing.T) {
	dispatchers := []struct {
		path []string
		fn   string
	}{
		{[]string{"device"}, "device"},
		{[]string{"device", "config"}, "deviceConfig"},
		{[]string{"console"}, "console"},
		{[]string{"host"}, "host"},
		{[]string{"emergency"}, "emergency"},
		{[]string{"server"}, "server"},
		{[]string{"breakglass"}, "breakglass"},
		{[]string{"config", "snmp"}, "configSNMP"},
		{[]string{"config", "devices"}, "configDevices"},
		{[]string{"config", "linux"}, "configLinux"},
		{[]string{"config", "metrics"}, "configMetrics"},
		{[]string{"config", "sudoers"}, "configSudoers"},
		{[]string{"config", "sudoers", "tiers"}, "configSudoersTiers"},
		{[]string{"config", "mgmt-acl"}, "configMgmtACL"},
		{[]string{"config", "allow"}, "configFilter"},
		{[]string{"config", "deny"}, "configFilter"},
		{[]string{"group", "commands"}, "groupCommands"},
		{[]string{"group", "privilege"}, "groupPrivilege"},
		// (group preset takes its one word, roles, with an if, not a switch)
	}
	funcs := map[string]*ast.FuncDecl{}
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if n := e.Name(); !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil {
				funcs[fd.Name.Name] = fd
			}
		}
	}
	root := newRoot(&invocation{})
	// the words a dispatcher answers on its own account, not verbs
	own := []string{"", "help", "-h", "--help"}
	for _, d := range dispatchers {
		fd := funcs[d.fn]
		if fd == nil {
			t.Errorf("%v: no function %s", d.path, d.fn)
			continue
		}
		words := dispatcherWords(fd)
		node, rest := resolve(root, d.path)
		if len(rest) != 0 || len(node.Commands()) == 0 {
			t.Errorf("%v is not a command with sub-commands", d.path)
			continue
		}
		if len(words) < 2 {
			t.Errorf("%v: read %d words of %s; the reader is broken", d.path, len(words), d.fn)
		}
		for _, w := range words {
			if !slices.Contains(own, w) && child(node, w) == nil {
				t.Errorf("%v: %s accepts %q, which is no sub-command in the tree: unknownBelow would refuse it before sudo", d.path, d.fn, w)
			}
		}
	}
}

// dispatcherWords are the words a dispatcher function takes apart at its top
// level: the keys of a map literal of verbs, and the strings of the cases of
// a switch on the word ('sub', or 'arg(args, 0)').
func dispatcherWords(fd *ast.FuncDecl) []string {
	var out []string
	str := func(e ast.Expr) {
		if l, ok := e.(*ast.BasicLit); ok && l.Kind == token.STRING {
			if s, err := strconv.Unquote(l.Value); err == nil {
				out = append(out, s)
			}
		}
	}
	for _, st := range fd.Body.List {
		switch s := st.(type) {
		case *ast.AssignStmt:
			for _, r := range s.Rhs {
				if cl, ok := r.(*ast.CompositeLit); ok {
					if _, isMap := cl.Type.(*ast.MapType); isMap {
						for _, el := range cl.Elts {
							if kv, ok := el.(*ast.KeyValueExpr); ok {
								str(kv.Key)
							}
						}
					}
				}
			}
		case *ast.SwitchStmt:
			if !wordSwitch(s) {
				continue
			}
			for _, c := range s.Body.List {
				for _, e := range c.(*ast.CaseClause).List {
					str(e)
				}
			}
		}
	}
	return out
}

// wordSwitch reports whether a switch is on the command's word: the variable
// 'sub', or the call arg(args, 0), possibly set in its init statement.
func wordSwitch(s *ast.SwitchStmt) bool {
	switch tag := s.Tag.(type) {
	case *ast.Ident:
		return tag.Name == "sub"
	case *ast.CallExpr:
		if id, ok := tag.Fun.(*ast.Ident); ok && id.Name == "arg" && len(tag.Args) == 2 {
			l, ok := tag.Args[1].(*ast.BasicLit)
			return ok && l.Value == "0"
		}
	}
	if as, ok := s.Init.(*ast.AssignStmt); ok && len(as.Lhs) == 1 {
		id, ok := as.Lhs[0].(*ast.Ident)
		return ok && id.Name == "sub"
	}
	return false
}
