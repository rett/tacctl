package tacacs

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/paths"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
)

// The shipped files of the TACACS+ backend (config/backends/tacacs), the
// two tests of tests/unit/listeners.bats that WP1.5 left: their content is
// what this module's listeners and drop-ins rely on. (When internal/assets
// embeds these files, these tests can read the embedded copies.)

// section is sed -n '/<from>/,/<to>/p': the lines from the first line
// starting with from through the next line starting with to.
func section(text, from, to string) string {
	var out []string
	in := false
	for _, l := range strings.Split(text, "\n") {
		if !in && strings.HasPrefix(l, from) {
			in = true
		}
		if in {
			out = append(out, l)
			if strings.HasPrefix(l, to) && len(out) > 1 {
				in = false
			}
		}
	}
	return strings.Join(out, "\n")
}

// "units: the template runs the same daemon under the same hardening as
// tacquito.service".
func TestTemplateRunsTheSameDaemonUnderTheSameHardening(t *testing.T) {
	unit := readFile(t, filepath.Join(sharedDir, "tacquito.service"))
	tmpl := readFile(t, filepath.Join(sharedDir, "tacquito@.service"))
	hu, ht := section(unit, "# Security hardening", "[Install]"), section(tmpl, "# Security hardening", "[Install]")
	if hu == "" || hu != ht {
		t.Fatalf("hardening differs:\n%s\n---\n%s", hu, ht)
	}
	eu, et := section(unit, "ExecStart=", "RestartSec="), section(tmpl, "ExecStart=", "RestartSec=")
	if eu == "" || eu != et {
		t.Fatalf("ExecStart..RestartSec differs:\n%s\n---\n%s", eu, et)
	}
	// Ports below 1024 and the per-listener accounting log stay possible.
	for _, want := range []string{"AmbientCapabilities=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
		"ReadWritePaths=/var/log/tacquito"} {
		mustContain(t, ht, want)
	}
}

// "logrotate: one stanza covers every listener's accounting log,
// restarting once".
func TestLogrotateCoversEveryListener(t *testing.T) {
	f := readFile(t, filepath.Join(sharedDir, "tacquito.logrotate"))
	for _, want := range []string{"/var/log/tacquito/accounting.log /var/log/tacquito/accounting-*.log {", "sharedscripts",
		"systemctl restart tacquito"} {
		mustContain(t, f, want)
	}
	// The paths are the ones the drop-ins give the daemon on a machine
	// with nothing overridden.
	prod := paths.Resolve(paths.NewEnv(nil), "", func(string) bool { return false })
	mustContain(t, f, prod.AcctLog+" "+rtacacs.AcctLog(rtacacs.PathsFrom(prod), "*")+" {")
}
