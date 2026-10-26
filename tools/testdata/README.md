# Test data for tools/

`tree-0.2.19.tsv` is the command tree of tacctl 0.2.19 as the code builds it:
one line per command that is not hidden, its words, a tab, and its flags
(comma-separated, from the argument-spec tables). `test_check_commands.py`
compares it with what `check_commands.py` reads from `man/tacctl.1` at the
0.2.19 tag (when the clone has that tag).

It was written by this throwaway Go test, dropped into `internal/cli/` of an
export of the tag (`git archive 0.2.19 | tar -x -C /tmp/src`) and run with
`go test -mod=vendor ./internal/cli -run TestDumpTree`; nothing was committed
to the code branches:

```go
package cli

import (
	"os"
	"sort"
	"strings"
	"testing"
)

func TestDumpTree(t *testing.T) {
	root := newRoot(&invocation{app: newHarness(t, nil).app, hooks: newTestHooks()})
	var all [][]string
	treeVerbs(root, nil, &all)
	var out []string
	for _, p := range all {
		var fl []string
		if spec, ok := specFor(p); ok {
			for _, f := range spec.Flags {
				fl = append(fl, f.Names...)
			}
		}
		sort.Strings(fl)
		out = append(out, strings.Join(p, " ")+"\t"+strings.Join(fl, ","))
	}
	os.WriteFile("/tmp/tree.tsv", []byte(strings.Join(out, "\n")+"\n"), 0o644)
}
```

At 0.2.3 and earlier, drop `, hooks: newTestHooks()`.
