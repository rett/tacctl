package cli

import (
	"os"
	"strings"
	"testing"
)

// The offer to rename the host's own scope (D197-D201).

const scopeLabHosts = "web1|root@198.51.100.10||linux-web1|192.0.2.1|\nweb2|root@192.168.1.12||lab|192.0.2.1|\n"

// scopeRenameLab has the host web1 alone in its own scope linux-web1.
func scopeRenameLab(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "add", "linux-web1", "--prefixes", "198.51.100.10/32", "--secret", "generate"})
	sb.expect(0, "", "")
	sb.write("state/linux-hosts", scopeLabHosts, 0o600)
	sb.write("state/staging", "198.51.100.10/32|linux-web1|host|web1|2026-01-01\n192.0.2.7/32|lab|host|web2|2026-01-01\n", 0o600)
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	return sb
}

// hasScope reports whether the store has the scope.
func (sb *sandbox) hasScope(name string) bool {
	sb.t.Helper()
	return strings.Contains(plain(sb.run("", []string{"scope", "list"})), name)
}

func TestHostRenameOffersTheHostsOwnScope(t *testing.T) {
	sb := scopeRenameLab(t)
	snaps := len(sb.snapshotDirs())

	// The question names the scope and says why it is asked.
	holdTTY(t, sb, "y\n")
	sb.run("", []string{"host", "rename", "web1", "web9"})
	sb.tty = nil
	sb.expect(0, "Scope renamed: linux-web1 -> linux-web9", "  Scope 'linux-web1' is this host's own (no other host uses it). Rename it to 'linux-web9' too? [y/N]: ")
	// The host first, the scope second: both written, the registry's and the
	// staging file's scope fields follow, the host that was just renamed too.
	if got, want := sb.registryText(), "web9|root@198.51.100.10||linux-web9|192.0.2.1|\nweb2|root@192.168.1.12||lab|192.0.2.1|\n"; got != want {
		t.Errorf("registry %q, want %q", got, want)
	}
	if got, want := sb.read("state/staging"), "198.51.100.10/32|linux-web9|host|web9|2026-01-01\n192.0.2.7/32|lab|host|web2|2026-01-01\n"; got != want {
		t.Errorf("staging %q, want %q", got, want)
	}
	if !strings.Contains(plain(sb.out.String()), "Enrolled hosts registered in 'linux-web1' now name 'linux-web9': 1.") {
		t.Errorf("stdout:\n%s", sb.out.String())
	}
	if !sb.hasScope("linux-web9") || sb.hasScope("linux-web1") {
		t.Error("the store's scopes")
	}
	// Two undo points: the host rename's snapshot and the scope rename's.
	if n := len(sb.snapshotDirs()); n != snaps+2 {
		t.Errorf("%d snapshots, want %d", n, snaps+2)
	}
	if sb.sshCalls() != 0 {
		t.Error("ssh was used")
	}
}

func TestHostRenameScopeOfferDeclined(t *testing.T) {
	for _, stdin := range []string{"n\n", "", "\n", "maybe\n"} {
		sb := scopeRenameLab(t)
		sb.run(stdin, []string{"host", "rename", "web1", "web9"})
		sb.expect(0, "To rename the scope as well: tacctl scope rename linux-web1 linux-web9", "")
		if got, want := sb.registryText(), "web9|root@198.51.100.10||linux-web1|192.0.2.1|\nweb2|root@192.168.1.12||lab|192.0.2.1|\n"; got != want {
			t.Errorf("%q: registry %q, want %q", stdin, got, want)
		}
		if !sb.hasScope("linux-web1") || sb.hasScope("linux-web9") {
			t.Errorf("%q: the store's scopes", stdin)
		}
		// And the hint is the real command.
		sb.run("", []string{"scope", "rename", "linux-web1", "linux-web9"})
		sb.expect(0, "Scope renamed: linux-web1 -> linux-web9", "")
		if !strings.Contains(sb.registryText(), "web9|root@198.51.100.10||linux-web9|") {
			t.Errorf("%q: after the hinted command: %q", stdin, sb.registryText())
		}
	}
}

func TestHostRenameYesAnswersBothQuestions(t *testing.T) {
	sb := scopeRenameLab(t)
	sb.seedPin("web1", "198.51.100.10")
	sb.write("state/hosts/web9.json", "stale\n", 0o600)
	sb.run("", []string{"host", "rename", "web1", "web9", "--yes"})
	sb.expect(0, "Scope renamed: linux-web1 -> linux-web9", "")
	if !strings.Contains(sb.registryText(), "web9|root@198.51.100.10||linux-web9|") || !sb.hasScope("linux-web9") {
		t.Errorf("registry %q", sb.registryText())
	}
}

// Where the scope cannot be offered, one line says why and nothing is asked.
func TestHostRenameScopeStays(t *testing.T) {
	type tc struct {
		name  string
		setup func(sb *sandbox)
		args  []string
		why   string
	}
	for _, c := range []tc{
		{"linux-<new> exists", func(sb *sandbox) {
			sb.run("", []string{"scope", "add", "linux-web9", "--prefixes", "198.51.100.99/32", "--secret", "generate"})
		}, nil, "Scope 'linux-web1' keeps its name: scope 'linux-web9' exists."},
		{"another host uses it", func(sb *sandbox) {
			sb.write("state/linux-hosts", scopeLabHosts+"web3|root@198.51.100.11||linux-web1|192.0.2.1|\n", 0o600)
		}, nil, "Scope 'linux-web1' keeps its name: other enrolled hosts use it."},
		{"the store lacks it", func(sb *sandbox) {
			sb.run("", []string{"scope", "rename", "linux-web1", "lab-edge"})
			sb.write("state/linux-hosts", scopeLabHosts, 0o600)
		}, nil, "Scope 'linux-web1' keeps its name: the store has no such scope."},
		{"the scope check refuses", func(sb *sandbox) {
			sb.write("state/snmp/linux-web1.yaml", "community: x\n", 0o600)
			sb.write("state/snmp/linux-web9.yaml", "community: y\n", 0o600)
		}, nil, "Scope 'linux-web1' keeps its name: "},
	} {
		sb := scopeRenameLab(t)
		c.setup(sb)
		before := sb.registryText()
		sb.run("y\ny\n", []string{"host", "rename", "web1", "web9", "--yes"})
		if sb.code != 0 || !strings.Contains(sb.printed(), "[WARN] "+c.why) {
			t.Errorf("%s: %d\n%s", c.name, sb.code, sb.printed())
			continue
		}
		if strings.Contains(sb.printed(), "To rename the scope as well") || strings.Contains(sb.printed(), "Scope renamed") {
			t.Errorf("%s: the scope was offered or renamed:\n%s", c.name, sb.printed())
		}
		if !strings.Contains(sb.registryText(), "web9|") || sb.registryText() == before {
			t.Errorf("%s: the host was not renamed: %q", c.name, sb.registryText())
		}
	}

	// A host in a scope not named for it is not asked, and nothing is said.
	sb := scopeRenameLab(t)
	sb.run("y\n", []string{"host", "rename", "web2", "web8"})
	sb.expect(0, "Host 'web2' renamed to 'web8'.", "")
	if strings.Contains(sb.printed(), "scope") && !strings.Contains(sb.printed(), "Config snapshot") || strings.Contains(sb.printed(), "keeps its name") {
		t.Errorf("a scope was spoken of:\n%s", sb.printed())
	}
	// Nor is a host whose scope is named after another host.
	sb.write("state/linux-hosts", "web2|root@192.168.1.12||linux-web1|192.0.2.1|\n", 0o600)
	sb.run("y\n", []string{"host", "rename", "web2", "web8"})
	sb.expect(0, "renamed to 'web8'", "")
	if strings.Contains(sb.printed(), "Rename it to") || strings.Contains(sb.printed(), "keeps its name") {
		t.Errorf("a scope was offered:\n%s", sb.printed())
	}
}

// If the scope step fails after the host was renamed, the host keeps the old
// scope, which is a valid state, and the way on is said. The scope check
// passes at the offer and fails by the time the step runs.
func TestHostRenameScopeStepFails(t *testing.T) {
	sb := scopeRenameLab(t)
	sb.hooks.hostRenameStep = func(step string) {
		if step == "pins" {
			sb.write("state/snmp/linux-web1.yaml", "community: x\n", 0o600)
			sb.write("state/snmp/linux-web9.yaml", "community: y\n", 0o600)
		}
	}
	sb.run("", []string{"host", "rename", "web1", "web9", "--yes"})
	sb.expect(1, "Host 'web1' renamed to 'web9'.", "Host renamed. Scope 'linux-web1' was NOT renamed: ")
	for _, want := range []string{"; the host keeps it. Retry: tacctl scope rename linux-web1 linux-web9."} {
		if !strings.Contains(sb.stderr(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, sb.stderr())
		}
	}
	if got, want := sb.registryText(), "web9|root@198.51.100.10||linux-web1|192.0.2.1|\nweb2|root@192.168.1.12||lab|192.0.2.1|\n"; got != want {
		t.Errorf("registry %q, want %q", got, want)
	}
	if !sb.hasScope("linux-web1") {
		t.Error("the scope is gone")
	}
	_ = os.Remove(sb.path("state", "snmp", "linux-web9.yaml"))
}
