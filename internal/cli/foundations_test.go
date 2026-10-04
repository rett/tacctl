package cli

import (
	"reflect"
	"slices"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// WP6.0: the shared tables the device registry, 'ssh' and the shell register
// into (docs/plans/operator-console-wp.md 4.1).

// 'ssh', 'device' and 'host' carry the agent socket across sudo; 'shell'
// runs as the user.
func TestReexecTablesForSSHDeviceAndShell(t *testing.T) {
	env := func(name string) string {
		if name == "SSH_AUTH_SOCK" {
			return "/s"
		}
		return ""
	}
	for _, word := range []string{"host", "ssh", "device"} {
		want := []string{"sudo", "SSH_AUTH_SOCK=/s", "/x", word, "arg"}
		if got := sudoArgv("/x", []string{word, "arg"}, env); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %q", word, got)
		}
	}
	if !noSudo["shell"] {
		t.Error("'shell' must run without sudo")
	}
	for _, word := range []string{"ssh", "device", "host"} {
		if noSudo[word] {
			t.Errorf("%q must re-exec under sudo", word)
		}
	}
}

// A family registers its command and its specs from its own file; the
// registrations are visible to the tree and to specFor without an edit of
// root.go or completion.go.
func TestFamilyAndSpecRegistries(t *testing.T) {
	saveF, saveS := families, specLookups
	t.Cleanup(func() { families, specLookups = saveF, saveS })
	specLookups = map[string]func([]string) (Spec, bool){}
	for k, v := range saveS {
		specLookups[k] = v
	}

	registerFamily(func(*invocation) *cobra.Command {
		return verb("zfam <subcommand>", "test family", verb("go", "a verb"))
	})
	registerSpecs("zfam", map[string]Spec{"go": {MaxArgs: 1, Args: []string{KindDevices}}})

	root := newRoot(&invocation{})
	var names []string
	for _, c := range root.Commands() {
		names = append(names, c.Name())
	}
	if !slices.Contains(names, "zfam") {
		t.Errorf("registered family missing from %v", names)
	}
	s, ok := specFor([]string{"zfam", "go"})
	if !ok || !reflect.DeepEqual(s.Args, []string{KindDevices}) {
		t.Errorf("specFor(zfam go) = %v %v", s, ok)
	}
	if _, ok := specFor([]string{"zfam", "nope"}); ok {
		t.Error("an unregistered verb has a spec")
	}
	// The families that were there before still resolve.
	for _, p := range [][]string{{"user", "add"}, {"group", "add"}, {"config", "linux", "script"}, {"host", "sync"}, {"version"}, {"install"}} {
		if _, ok := specFor(p); !ok {
			t.Errorf("specFor(%v) lost", p)
		}
	}
	defer func() {
		if recover() == nil {
			t.Error("registering a family's specs twice must panic")
		}
	}()
	registerSpecs("zfam", nil)
}

func TestHostSpecsCompleteEnrolledNames(t *testing.T) {
	for _, verb := range []string{"sync", "unenroll"} {
		if got := hostSpecs[verb].Args; !reflect.DeepEqual(got, []string{KindHosts}) {
			t.Errorf("host %s args = %q", verb, got)
		}
	}
	if KindVendors != "cisco|juniper|wti|other" {
		t.Errorf("KindVendors = %q", KindVendors)
	}
}

const linuxHostsFixture = "web1|root@192.0.2.10||lab|192.0.2.1|\n" +
	"db1|root@192.0.2.11||prod|192.0.2.1|\n" +
	"dmz1|root@192.0.2.12||dmz|192.0.2.1|\n"

// 'hosts' answers the registry's names; 'devices' adds the registered
// providers' and sorts; an administrator sees all, a lower tier its own
// scopes (carol: lab, dmz).
func TestCompletionNamesHostsAndDevices(t *testing.T) {
	saved := deviceNameProviders
	t.Cleanup(func() { deviceNameProviders = saved })
	registerDeviceNames(func(_ *invocation, f scopeFilter) []string {
		out := []string{"zz-core"}
		if f.allows("prod") {
			out = append(out, "prod-core")
		}
		return append(out, "web1") // a duplicate of a host name: once
	})

	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", linuxHostsFixture, 0o600)

	out := sb.run("", []string{"_completion-names", "hosts"})
	if want := "web1\ndb1\ndmz1\n"; out != want {
		t.Errorf("hosts (unrestricted) = %q", out)
	}
	out = sb.run("", []string{"_completion-names", "devices"})
	if want := "db1\ndmz1\nprod-core\nweb1\nzz-core\n"; out != want {
		t.Errorf("devices (unrestricted) = %q", out)
	}

	carol := func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	}
	out = sb.cfgRun("", []string{"_completion-names", "hosts"}, carol, "SUDO_USER=carol")
	if want := "web1\ndmz1\n"; out != want {
		t.Errorf("hosts (readonly carol) = %q (stderr %q)", out, sb.err.String())
	}
	out = sb.cfgRun("", []string{"_completion-names", "devices"}, carol, "SUDO_USER=carol")
	if want := "dmz1\nweb1\nzz-core\n"; out != want {
		t.Errorf("devices (readonly carol) = %q", out)
	}

	// No registry file: no names, exit 0.
	sb.write("state/linux-hosts", "", 0o600)
	if out = sb.run("", []string{"_completion-names", "hosts"}); out != "" || sb.code != 0 {
		t.Errorf("empty registry: %q exit %d", out, sb.code)
	}
}
