package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// Linux host deployment is the superuser's (WP10.2j): an engineer reads
// hosts and syncs none. The user's condition: an engineer must not be able
// to update any tacctl setting that would cause a host sync to be required.
// syncInputs is everything a 'host sync' of each registered host is built
// from, read the way the sync reads it; TestEngineerRowsWriteNoGlobalSetting
// takes it before and after every command line an Engineer row opens and
// fails with the row and the field when any of it differs.
//
// The inputs, per registered host:
//   - the script the sync would send, whole (header, users with their
//     UIDs, tiers and shells, TAC_ENGINEER_SUDO, the protocol, the server
//     address, the scope's secret, the method, the scope);
//   - the request it was built from (the same, before they are rendered)
//     and the console policy's answer for every user, for the server's own
//     entry;
//   - the registry of hosts (linux-hosts), the pins and recorded addresses
//     of devices.yaml ('hosts:'), the settings of tacctl.yaml a sync reads
//     (linux.*, host.*, tier.*), and
//   - the scope and prefix that answer each host's address (recorded, and
//     the address its target names), tag included: which scope's secret and
//     users the host's logins meet.

var reGenerated = regexp.MustCompile(`Generated [0-9TZ:-]+\.`)

// syncInputs returns the inputs by field name. It reads the sandbox the way
// the sync does and writes only what a sync writes first (the UID map, which
// a second call finds as the first left it).
func syncInputs(t *testing.T, sb *sandbox) map[string]string {
	t.Helper()
	out := map[string]string{}
	runner := &fake.Runner{}
	runner.On([]string{"logger"}, execx.Result{})
	runner.On([]string{"id"}, execx.Result{Stdout: []byte("root\n")})
	fakePasswd(runner)
	var stdout, stderr bytes.Buffer
	env := append(append([]string(nil), sb.env...), "TACCTL_LINUX_DIR="+sb.path("var-lib", "linux"))
	a := app.New(nil, paths.NewEnv(env), "/opt/x/dist/tacctl", 0, app.Stdio{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}, runner)
	a.Resolve = sb.resolve
	a.Paths = a.Paths.Reroot(sb.dir)
	inv := &invocation{ctx: context.Background(), app: a}

	reg, err := inv.registry()
	if err != nil {
		t.Fatalf("hosts registry: %v", err)
	}
	m, err := inv.model()
	if err != nil {
		t.Fatalf("model: %v", err)
	}
	devs, err := devreg.Load(a.Paths.DevicesFile)
	if err != nil {
		t.Fatalf("devices.yaml: %v", err)
	}
	out["registry linux-hosts"] = sb.read("state/linux-hosts")
	out["devices.yaml hosts (pins, recorded addresses, acknowledged notices)"] = fmt.Sprintf("%+v", devs.Hosts)
	for k, v := range flatKeys(t, sb.path("state", "tacctl.yaml")) {
		if strings.HasPrefix(k, "linux.") || strings.HasPrefix(k, "host.") || strings.HasPrefix(k, "tier.") {
			out["tacctl.yaml "+k] = v
		}
	}
	for _, e := range reg.Entries() {
		prefix := "host " + e.Name + ": "
		answer := func(what, addr string) {
			if addr == "" {
				return
			}
			info, found := m.LookupAddr(addr)
			out[prefix+"the scope that answers "+what+" "+addr] = fmt.Sprintf("found=%v scope=%q prefix=%q tag=%q", found, info.Scope, info.Prefix, info.Tag)
		}
		answer("its recorded address", devs.HostAddressOf(e.Name))
		answer("its server address", e.Server)
		if host, _, ok := hosts.ScanTarget(e.Target, e.Port); ok {
			answer("its target", host)
		} else {
			answer("this server", "127.0.0.1")
		}

		he := inv.hostsEnv()
		he.Range, _ = inv.configuredUIDRange()
		req, err := inv.scriptRequest(e.Scope, e.Server, reg.Method(e.Name), filepath.Join(t.TempDir(), "script"))
		if err != nil {
			out[prefix+"request"] = "error: " + err.Error()
			continue
		}
		req.Temp, req.AccountsOnly, req.Local = true, true, e.Target == hosts.Local
		var tiers []string
		for _, r := range req.Rows {
			name, lvl, _ := strings.Cut(r, "|")
			tiers = append(tiers, fmt.Sprintf("%s=%s/group-tier:%q", name, inv.userTier(name, lvl), req.GroupTier(name)))
		}
		if req.Local {
			pol, err := inv.consolePolicy()
			if err != nil {
				t.Fatalf("console policy: %v", err)
			}
			req.ConsoleShell = func(name, tr string) string { return pol.Shell(name, tier.Tier(tr)) }
			for _, r := range req.Rows {
				name, lvl, _ := strings.Cut(r, "|")
				tr := inv.userTier(name, lvl)
				tiers = append(tiers, fmt.Sprintf("%s console=%+v shell=%s", name, pol.Decide(name, tr), pol.Shell(name, tr)))
			}
		}
		out[prefix+"request"] = fmt.Sprintf("scope=%q server=%q method=%q secret=%q rows=%q inactive=%q engineer_sudo=%q revoke=%v local=%v listeners=%+v",
			req.Scope, req.Server, req.Method, req.Secret, req.Rows, req.Inactive, req.EngineerSudo, req.RevokeEngineer, req.Local, req.Listeners)
		out[prefix+"users and tiers"] = strings.Join(tiers, "\n")
		if _, err := he.WriteScript(req); err != nil {
			out[prefix+"script"] = "error: " + err.Error() + " " + stderr.String()
			continue
		}
		text, err := os.ReadFile(req.Output)
		if err != nil {
			t.Fatalf("script of %s: %v", e.Name, err)
		}
		// The clock is the one input that is not the state's.
		out[prefix+"script"] = reGenerated.ReplaceAllString(string(text), "Generated <time>.")
	}
	if n := len(reg.Entries()); n < 3 {
		t.Fatalf("the sync inputs of %d hosts were read, not three", n)
	}
	return out
}

// diffSyncInputs lists the fields that differ (sorted), each with both
// values.
func diffSyncInputs(before, after map[string]string) []string {
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	var names []string
	for k := range keys {
		names = append(names, k)
	}
	slices.Sort(names)
	var out []string
	for _, k := range names {
		b, bok := before[k]
		a, aok := after[k]
		if bok && aok && a == b {
			continue
		}
		switch {
		case !bok:
			out = append(out, fmt.Sprintf("%s: appeared: %q", k, a))
		case !aok:
			out = append(out, fmt.Sprintf("%s: gone (was %q)", k, b))
		default:
			out = append(out, fmt.Sprintf("%s:\n  before %q\n  after  %q", k, b, a))
		}
	}
	return out
}

// The inputs of a sync are read, whole and the same, on every call; a change
// to any of them is seen.
func TestSyncInputsSeeEveryInput(t *testing.T) {
	sb := engineerSandbox(t)
	nosyncSetup(t, sb)
	base := syncInputs(t, sb)
	if again := diffSyncInputs(base, syncInputs(t, sb)); len(again) > 0 {
		t.Fatalf("two reads of the same state differ: %v", again)
	}
	for _, f := range []string{"registry linux-hosts", "host web1: script", "host web1: request", "host web1: users and tiers", "host authsrv: users and tiers",
		"host web1: the scope that answers its recorded address 192.168.1.10", "devices.yaml hosts (pins, recorded addresses, acknowledged notices)",
		"tacctl.yaml host.default_method"} {
		if _, ok := base[f]; !ok {
			t.Errorf("the sync inputs lack %q", f)
		}
	}
	// Each kind of change is a difference.
	for name, change := range map[string]func(sb *sandbox){
		"a host's pin": func(sb *sandbox) {
			mutateDevices(t, sb, func(f *devreg.File) { f.SetHostKeys("web1", nil) })
		},
		"a host's address": func(sb *sandbox) {
			mutateDevices(t, sb, func(f *devreg.File) { f.SetHostAddress("web1", "10.99.0.77", "2026-01-01 00:00") })
		},
		"a scope's prefixes": func(sb *sandbox) {
			sb.cfgRun("", []string{"scope", "prefixes", "lab", "remove", "192.168.0.0/16"}, nil)
		},
		"engineer-sudo": func(sb *sandbox) {
			sb.cfgRun("", []string{"config", "linux", "engineer-sudo", "/usr/bin/id"}, nil)
		},
		"a scope's secret": func(sb *sandbox) {
			sb.cfgRun("", []string{"scope", "secret", "lab", "set", "abcdefgh12345678ABCDEFGH"}, nil)
		},
		"a user's group": func(sb *sandbox) {
			sb.cfgRun("", []string{"user", "move", "bob", "readonly"}, nil)
		},
		"a group's tier": func(sb *sandbox) {
			sb.cfgRun("", []string{"group", "edit", "operator", "tier", "operator"}, nil)
		},
		"the default method": func(sb *sandbox) {
			sb.cfgRun("", []string{"host", "default-method", "radius"}, nil)
		},
		"the host registry": func(sb *sandbox) {
			sb.write("state/linux-hosts", sb.read("state/linux-hosts")+"extra|root@192.0.2.30||lab|192.0.2.1|\n", 0o600)
		},
	} {
		sb := engineerSandbox(t)
		nosyncSetup(t, sb)
		before := syncInputs(t, sb)
		change(sb)
		if d := diffSyncInputs(before, syncInputs(t, sb)); len(d) == 0 {
			t.Errorf("%s changes no sync input (exit %d, %q)", name, sb.code, sb.stderr())
		}
	}
}

// nosyncSetup gives the sandbox what the invariant needs: the settings a
// sync reads (the tier of the engineer's group, the default method, the
// engineer sudo list), two hosts in two scopes at addresses the scopes
// answer, with their pins and recorded addresses, and this server's own
// entry, so the console policy is in the inputs.
func nosyncSetup(t *testing.T, sb *sandbox) {
	t.Helper()
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\nhost:\n  default_method: tacplus\nlinux:\n  engineer_sudo: [/usr/bin/systemctl]\n", 0o600)
	sb.write("state/linux-hosts", "web1|root@192.168.1.10||lab|192.168.1.250|\ndb1|root@10.99.0.10||prod|10.99.0.250|\nauthsrv|local||lab|127.0.0.1|\nedge|root@100.64.0.5||lab|192.168.1.250|\n", 0o600)
	key := devreg.KeyStrings(devreg.ParsePubKeys([]byte(rotPub)))
	mutateDevices(t, sb, func(f *devreg.File) {
		f.SetHostKeys("web1", key)
		f.SetHostAddress("web1", "192.168.1.10", "2026-01-01 00:00")
		f.SetHostKeys("db1", key)
		f.SetHostAddress("db1", "10.99.0.10", "2026-01-01 00:00")
	})
}

func mutateDevices(t *testing.T, sb *sandbox, fn func(*devreg.File)) {
	t.Helper()
	if _, err := devreg.Mutate(sb.path("state", "devices.yaml"), "", nil, func(f *devreg.File) error { fn(f); return nil }); err != nil {
		t.Fatalf("devices.yaml: %v", err)
	}
}
