package cli

import (
	"slices"
	"strings"
	"testing"
)

// Every command of the tree has a row in the class table, and every row
// names a command (docs/plans/0.2.17-plan.md D255 1): a new verb is covered
// from the day it exists, and a removed one leaves no row behind.
func TestEveryCommandIsClassified(t *testing.T) {
	parallel(t)
	root := newRoot(&invocation{})
	keys := commandKeys(root)
	for _, k := range keys {
		if _, _, _, ok := auditLookup(strings.Fields(k)); !ok {
			t.Errorf("'tacctl %s' has no row in auditTable (internal/cli/audit.go): classify it read, action or mixed", k)
		}
	}
	for k, e := range auditTable {
		// A row of one word may stand for a family whose words have no rows of
		// their own ('hash').
		covers := slices.ContainsFunc(keys, func(c string) bool { return strings.HasPrefix(c, k+" ") })
		if !slices.Contains(keys, k) && !covers {
			t.Errorf("auditTable has a row for %q, which names no command of the tree", k)
		}
		switch e.Class {
		case classRead, classAction, classMixed:
		default:
			t.Errorf("auditTable[%q] has class %q", k, e.Class)
		}
		if e.Class == classRead && e.Notice {
			t.Errorf("auditTable[%q]: a read command writes no line, so it has no weight", k)
		}
	}
}

// A hidden command (the drivers and helpers) is classified too: the tree
// walk above reaches them, and the ones that change nothing are reads.
func TestHelperCommandsAreReads(t *testing.T) {
	parallel(t)
	for _, k := range []string{"_askpass", "_completion-names", "_console-policy", "completion", "shell", "version", "status", "hash"} {
		if e := auditTable[k]; e.Class != classRead {
			t.Errorf("%q is %q, want read", k, e.Class)
		}
	}
	if e := auditTable["_phase"]; e.Class != classAction {
		t.Errorf("_phase is %q, want action", e.Class)
	}
}

// The weighty commands of D245/D249 are written at auth.notice.
func TestWeightyCommands(t *testing.T) {
	parallel(t)
	for _, k := range []string{"install", "upgrade", "uninstall", "rollback", "log clear", "store import", "store rollback",
		"backup restore", "config restore", "config sudoers", "console system-shell"} {
		if !auditTable[k].isNotice(nil) {
			t.Errorf("%q is not weighty", k)
		}
	}
	e := auditTable["group edit"]
	for _, c := range []struct {
		rest []string
		want bool
	}{
		{[]string{"ops", "tier", "engineer"}, true},
		{[]string{"ops", "priv-lvl", "9"}, true},
		{[]string{"ops", "juniper-class", "X"}, false},
		{[]string{"ops", "wti-level", "2"}, false},
		{nil, false},
	} {
		if got := e.isNotice(c.rest); got != c.want {
			t.Errorf("group edit %q: notice %v, want %v", c.rest, got, c.want)
		}
	}
	for _, k := range []string{"user add", "scope secret", "device add", "host sync"} {
		if auditTable[k].isNotice(nil) {
			t.Errorf("%q is weighty", k)
		}
	}
}

// The lookup takes the first word when it is a leaf of its own, else the
// first two, whatever follows.
func TestAuditLookup(t *testing.T) {
	parallel(t)
	for _, c := range []struct {
		path []string
		key  string
		n    int
		ok   bool
	}{
		{[]string{"ssh"}, "ssh", 1, true},
		{[]string{"user", "add"}, "user add", 2, true},
		{[]string{"device", "config", "pull"}, "device config", 2, true},
		{[]string{"hash", "generate"}, "hash", 1, true},
		{[]string{"user"}, "", 0, false},
		{nil, "", 0, false},
	} {
		key, n, _, ok := auditLookup(c.path)
		if key != c.key || n != c.n || ok != c.ok {
			t.Errorf("%q: %q %d %v, want %q %d %v", c.path, key, n, ok, c.key, c.n, c.ok)
		}
	}
}
