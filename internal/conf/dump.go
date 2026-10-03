package conf

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/rett/tacctl/internal/ui"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Dump writes what 'tacctl config dump' (cmd_config_dump) prints: the
// defaults text, the overrides file as it is on disk, and the merged view
// in tacctl.yaml's YAML style.
func (c *Config) Dump(w io.Writer) error {
	effective, err := yamlpy.Emit(c.merged, yamlpy.ConfOptions)
	if err != nil {
		return fmt.Errorf("tacctl config dump: %w", err)
	}
	var b bytes.Buffer
	b.WriteString("\n")
	b.WriteString(ui.Bold + "tacctl configuration" + ui.NC + "\n")
	b.WriteString("--------------------------------------------\n")
	b.WriteString("  Defaults:  embedded in lib/conf.sh (conf_emit_defaults)\n")
	b.WriteString(echoE("  Overrides: "+c.Path) + "\n")
	b.WriteString("\n")
	b.WriteString(ui.Bold + "--- Defaults (canonical) ---" + ui.NC + "\n")
	b.WriteString(DefaultsText)
	b.WriteString("\n")
	b.WriteString(ui.Bold + "--- Overrides (operator-set) ---" + ui.NC + "\n")
	if data, err := os.ReadFile(c.Path); err == nil {
		b.Write(data)
	} else {
		b.WriteString("  (no overrides — running on defaults)\n")
	}
	b.WriteString("\n")
	b.WriteString(ui.Bold + "--- Effective (merged) ---" + ui.NC + "\n")
	b.Write(bytes.TrimRight(effective, " \t\n\r\v\f"))
	b.WriteString("\n\n")
	_, err = w.Write(b.Bytes())
	return err
}
