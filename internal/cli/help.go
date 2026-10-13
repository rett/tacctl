package cli

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/ui"
)

// UsageVars fills the {{name}} slots of a usage block.
type UsageVars map[string]string

// Usage returns usage block id (a key of usageBlocks) with its slots filled
// and the usageMarkup turned into escapes: <b> is bold, <o> cyan (an option
// name or a placeholder). With the escapes stripped, the bytes are the ones
// the bash implementation prints. A missing block or an unfilled slot is a
// programming error and panics; help_test.go renders every block.
func Usage(id string, vars UsageVars) string {
	text, ok := usageBlocks[id]
	if !ok {
		panic(fmt.Sprintf("cli.Usage: no usage block %q", id))
	}
	pairs := []string{"<b>", ui.Bold, "</b>", ui.NC, "<o>", ui.Cyan, "</o>", ui.NC}
	for k, v := range vars {
		pairs = append(pairs, "{{"+k+"}}", v)
	}
	out := strings.NewReplacer(pairs...).Replace(text)
	if i := strings.Index(out, "{{"); i >= 0 {
		end := strings.Index(out[i:], "}}")
		panic(fmt.Sprintf("cli.Usage(%q): slot %s not filled", id, out[i:i+end+2]))
	}
	return out
}

// plainBlock is a usage block as the shell reads it for its lists: the
// usageMarkup and the escapes they resolve to removed, so a row splits and
// matches the same whether the block is raw or resolved.
func plainBlock(s string) string {
	if !strings.ContainsAny(s, "<\x1b") {
		return s
	}
	return reSGR.ReplaceAllString(usageMarkup.Replace(s), "")
}

var (
	usageMarkup = strings.NewReplacer("<b>", "", "</b>", "", "<o>", "", "</o>", "")
	reSGR       = regexp.MustCompile("\x1b\\[[0-9;]*m")
)

// UsageIDs lists the usage blocks, sorted.
func UsageIDs() []string {
	ids := make([]string, 0, len(usageBlocks))
	for id := range usageBlocks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
