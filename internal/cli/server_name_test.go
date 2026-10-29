package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/names"
)

// With no word 'server name' shows the name in effect and where it comes
// from: the host name until one is set.
func TestServerNameShows(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "server", "name")
	hs.expect(0, "  Server name: "+shortHostname()+"  (the host name; none is set: tacctl server name <label>)", "")
	hs.run(nil, "server", "name", "core-1")
	hs.expect(0, "Server name set: core-1. The console shows it from the next session.", "")
	if got := hs.read("state/tacctl.yaml"); !strings.Contains(got, "server:\n  name: core-1\n") {
		t.Errorf("tacctl.yaml:\n%s", got)
	}
	hs.run(nil, "server", "name")
	hs.expect(0, "  Server name: core-1  (the setting server.name)", "")
	hs.run(nil, "config", "get", "server.name")
	hs.expect(0, "core-1", "")
}

// Set, set again, remove, remove again: each says what it did; a change
// writes the command's pair of lines and its own, a no-op none.
func TestServerNameSetAndUnset(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "server", "name", "unset")
	hs.expect(0, "No server name is set. Nothing was changed.", "")
	r := hs.runner()
	hs.run(r, "server", "name", "core-1")
	var start, own bool
	for _, l := range auditLines(r) {
		start = start || strings.Contains(l, "cmd start") && strings.Contains(l, `cmd="server name"`)
		own = own || strings.Contains(l, "server name from=- to=core-1")
	}
	if !start || !own {
		t.Errorf("start %v own %v:\n%s", start, own, strings.Join(auditLines(r), "\n"))
	}
	r = hs.runner()
	hs.run(r, "server", "name", "core-1")
	hs.expect(0, "The server name is core-1 already. Nothing was changed.", "")
	if hasAuditPrefix(r, "", "cmd start") {
		t.Error("a no-op wrote a start line")
	}
	hs.run(nil, "server", "name", "core-2")
	hs.expect(0, "Server name set: core-2.", "")
	hs.run(nil, "server", "name", "unset")
	hs.expect(0, "Server name removed: the console shows the host name ("+shortHostname()+") from the next session.", "")
	// the file goes with its last key
	if got, err := os.ReadFile(hs.path("state", "tacctl.yaml")); err == nil && strings.Contains(string(got), "name") {
		t.Errorf("the key stayed:\n%s", got)
	}
	hs.run(nil, "server", "name")
	hs.expect(0, "(the host name; none is set", "")
}

// The label is a lower-case DNS label that starts with a letter: what is
// refused changes nothing.
func TestServerNameRefusals(t *testing.T) {
	hs := newHostSandbox(t)
	before := hs.yamlOrNone()
	for _, c := range []struct{ name, why string }{
		{"Core", "has upper case: a server name is lower case"},
		{"1core", "is not a name of letters, digits and hyphens that starts with a letter"},
		{"core-", "does not end in a hyphen"},
		{"-core", "starts with a letter"},
		{"core.example.net", "starts with a letter and does not end in a hyphen"},
		{"co re", "starts with a letter"},
		{"core_1", "starts with a letter"},
		{strings.Repeat("a", 64), "is longer than 63 characters"},
	} {
		hs.run(nil, "server", "name", c.name)
		if hs.code != 1 || !strings.Contains(hs.err.String(), "'"+c.name+"' ") || !strings.Contains(hs.err.String(), c.why) || !strings.Contains(hs.err.String(), "Nothing was changed.") {
			t.Errorf("%q: exit %d %q", c.name, hs.code, hs.err.String())
		}
	}
	hs.run(nil, "server", "name", "core-1", "x")
	hs.expect(1, "", "Usage: tacctl server name [<label>|unset]")
	if hs.yamlOrNone() != before {
		t.Error("tacctl.yaml changed")
	}
	// the longest label, and a single letter, are fine
	for _, ok := range []string{strings.Repeat("a", 63), "a", "a1-b2"} {
		hs.run(nil, "server", "name", ok)
		hs.expect(0, "Server name set: "+ok+".", "")
	}
}

// A file with a bad name is a validation error, not a name.
func TestServerNameKeyIsValidated(t *testing.T) {
	hs := newHostSandbox(t)
	hs.write("state/tacctl.yaml", "server:\n  name: Core.Example\n", 0o600)
	hs.run(nil, "config", "validate")
	if got := hs.out.String() + hs.err.String(); hs.code == 0 || !strings.Contains(got, "server.name") {
		t.Errorf("exit %d\n%s", hs.code, got)
	}
	// a name that is not valid is not the name in effect
	hs.run(nil, "server", "name")
	hs.expect(0, "(the host name; none is set", "")
}

// The console's policy answer carries the name when one is set, and the
// parser of the console takes only a valid one.
func TestConsolePolicyCarriesTheServerName(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "_console-policy")
	if strings.Contains(hs.out.String(), " name=") {
		t.Errorf("no name is set:\n%s", hs.out.String())
	}
	hs.run(nil, "server", "name", "core-1")
	hs.run(nil, "_console-policy")
	line := strings.TrimSpace(hs.out.String())
	r, ok := console.ParseRemote(line)
	if !ok || r.Name != "core-1" || !strings.HasSuffix(line, " name=core-1") {
		t.Errorf("%q: %+v", line, r)
	}
	// a name alone is no policy answer (Known stays false)
	if r, ok := console.ParseRemote("name=core-1"); ok || r.Known {
		t.Errorf("a line with a name alone was taken as an answer: %+v", r)
	}
	if r, ok := console.ParseRemote("name= shell=console"); !ok || r.Name != "" {
		t.Errorf("a lone name= field: %+v %v", r, ok)
	}
	for _, bad := range []string{"name=Core", "name=", "name=core.example", "name=" + names.ServerNameReserved} {
		if r, _ := console.ParseRemote("shell=console idle=30 " + bad); r.Name != "" {
			t.Errorf("%s was taken: %q", bad, r.Name)
		}
	}
	if r, _ := console.ParseRemote("shell=console idle=30"); r.Name != "" {
		t.Errorf("an answer without a name: %q", r.Name)
	}
}

// 'device client-config' names the server by the setting, else the host name.
func TestServerNameInClientConfig(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "server", "name", "core-1")
	hs.run(nil, "device", "client-config")
	if got := hs.out.String(); hs.code != 0 || !strings.Contains(got, "core-1") {
		t.Errorf("exit %d\n%s%s", hs.code, got, hs.err.String())
	}
}

// yamlOrNone is tacctl.yaml, "" when there is none.
func (hs *hostSandbox) yamlOrNone() string {
	b, _ := os.ReadFile(hs.path("state", "tacctl.yaml"))
	return string(b)
}

// A name that is a YAML word (no, on, off, yes, true, null) is a string in
// tacctl.yaml: it is written quoted (yamlpy.EmitChecked) and read back as the
// string it was, by 'server name', 'config get' and 'server show'.
func TestServerNameThatIsAYAMLWordRoundTrips(t *testing.T) {
	for _, name := range []string{"no", "yes", "on", "off", "true", "false", "null"} {
		hs := newHostSandbox(t)
		hs.run(nil, "server", "name", name)
		hs.expect(0, "Server name set: "+name+".", "")
		if got := hs.yamlOrNone(); strings.Contains(got, "name: "+name+"\n") {
			t.Errorf("%s is written bare:\n%s", name, got)
		}
		hs.run(nil, "server", "name")
		hs.expect(0, "Server name: "+name+"  (the setting server.name)", "")
		hs.run(nil, "config", "get", "server.name")
		hs.expect(0, name, "")
		hs.run(nil, "config", "validate")
		if hs.code != 0 {
			t.Errorf("%s: config validate %d\n%s%s", name, hs.code, hs.out.String(), hs.err.String())
		}
		hs.run(nil, "server", "name", name)
		hs.expect(0, "The server name is "+name+" already.", "")
		hs.run(nil, "server", "name", "unset")
		hs.expect(0, "Server name removed", "")
	}
}
