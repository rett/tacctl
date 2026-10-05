package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/tier"
)

// '_completion-names <kind>' is bash completion's bridge to live names
// ('sudo -n tacctl _completion-names <kind>', bin/tacctl.sh at 0.1.16): it
// runs the tier gate and preflight, then prints the names one per line.
// A kind is answered when completionKinds or completionArgKinds has it; any
// other kind prints nothing (exit 0). A new kind is one entry.
var completionKinds = map[string]func(m *model.Model) []string{
	// model_users: every user, the accounting sink included, sorted.
	KindUsers: (*model.Model).UserNames,
	// model_groups and model_scopes: every name, sorted.
	KindGroups: (*model.Model).GroupNames,
	KindScopes: (*model.Model).ScopeNames,
}

// completionArgKinds are the native kinds that are not model names: they
// are answered from the invocation's services, with the words after the
// kind ('_completion-names listeners [<backend>]').
var completionArgKinds = map[string]func(inv *invocation, args []string) []string{
	// _completion_listeners: listener names, every backend's or one's.
	KindListeners: (*invocation).listenerNames,
	// backup_names | head -50: snapshots newest first, then old-style ids.
	KindBackups: (*invocation).backupNames,
	// BACKEND_IDS, and backends_enabled 2>/dev/null || true.
	KindBackends:        (*invocation).backendNames,
	KindEnabledBackends: (*invocation).enabledBackendNames,
	// The enrolled hosts' names (the registry at Paths.LinuxHosts), and every
	// name 'ssh' and 'device' accept; both filtered to the caller's scopes.
	KindHosts:   (*invocation).hostNames,
	KindDevices: (*invocation).deviceNames,
}

// scopeFilter is what a caller may see of the registries: everything for
// an administrator (superuser, unrestricted), the user's own scopes for
// the lower tiers (docs/plans/operator-console.md 8).
type scopeFilter struct {
	restricted bool
	scopes     []string
}

// allows reports whether an entry of scope may be named.
func (f scopeFilter) allows(scope string) bool {
	return !f.restricted || slices.Contains(f.scopes, scope)
}

// callerScopes is the filter of the caller (SUDO_USER); a lower-tier caller
// whose model cannot be read sees nothing.
func (inv *invocation) callerScopes() scopeFilter {
	switch inv.tierGate().Caller(inv.ctx) {
	case tier.Readonly, tier.Operator:
	default:
		return scopeFilter{}
	}
	m, err := inv.model()
	if err != nil {
		return scopeFilter{restricted: true}
	}
	f := scopeFilter{restricted: true}
	if u := m.User(inv.app.Env.Get("SUDO_USER")); u != nil {
		f.scopes = u.Scopes
	}
	return f
}

// hostNames are the enrolled hosts' names, in file order.
func (inv *invocation) hostNames([]string) []string {
	reg, err := hosts.LoadRegistry(inv.app.Paths.LinuxHosts)
	if err != nil {
		return nil
	}
	f := inv.callerScopes()
	var out []string
	for _, e := range reg.Entries() {
		if f.allows(e.Scope) {
			out = append(out, e.Name)
		}
	}
	return out
}

// nameProvider lists names of one more source for the 'devices' kind: the
// scope filter of the caller says which entries it may see. The device
// registry (WP6.1a) registers one from its file's init.
type nameProvider func(inv *invocation, f scopeFilter) []string

var deviceNameProviders []nameProvider

// registerDeviceNames adds a source of names to the 'devices' kind.
func registerDeviceNames(p nameProvider) { deviceNameProviders = append(deviceNameProviders, p) }

// deviceNames are the hosts' names and every provider's, sorted, once each.
func (inv *invocation) deviceNames([]string) []string {
	f := inv.callerScopes()
	seen := map[string]bool{}
	var out []string
	add := func(l []string) {
		for _, n := range l {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	add(inv.hostNames(nil))
	for _, p := range deviceNameProviders {
		add(p(inv, f))
	}
	slices.Sort(out)
	return out
}

func completionNamesCmd(inv *invocation) *cobra.Command {
	c := hidden("_completion-names")
	c.RunE = func(cmd *cobra.Command, args []string) error {
		kind := arg(args, 0)
		return inv.native(withPreflight, func(args []string) error {
			if names, ok := completionArgKinds[kind]; ok {
				if l := names(inv, args[1:]); len(l) > 0 {
					inv.write(strings.Join(l, "\n") + "\n")
				}
				return nil
			}
			names, ok := completionKinds[kind]
			if !ok {
				return nil
			}
			// 'model_users 2>/dev/null': a model that cannot be read is
			// exit 1 with nothing printed (set -e).
			m, err := inv.model()
			if err != nil {
				return exit(1)
			}
			if l := names(m); len(l) > 0 {
				inv.write(strings.Join(l, "\n") + "\n")
			}
			return nil
		})(cmd, args)
	}
	return c
}
