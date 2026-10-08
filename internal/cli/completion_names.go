package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/devreg"
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

// completionDescKinds answer '_completion-names <kind> --desc' (the shell's
// Tab listing): one 'name<TAB>description' line per name, the same names,
// in the same order, behind the same scope filter, as without --desc. A
// kind that is not here answers --desc with its plain names.
var completionDescKinds = map[string]func(inv *invocation) []string{
	KindHosts:   (*invocation).hostDescs,
	KindDevices: (*invocation).deviceDescs,
}

// descLine is 'name<TAB>description' with the words of the description
// that are not empty.
func descLine(name string, words ...string) string {
	var d []string
	for _, w := range words {
		if w != "" {
			d = append(d, w)
		}
	}
	if len(d) == 0 {
		return name
	}
	return name + "\t" + strings.Join(d, " ")
}

// hostOf is the host of a [user@]host target.
func hostOf(target string) string {
	_, after, ok := strings.Cut(target, "@")
	if ok {
		return after
	}
	return target
}

// hostDescs are the enrolled hosts as 'name<TAB>linux <host> <scope>'.
func (inv *invocation) hostDescs() []string {
	reg, err := hosts.LoadRegistry(inv.app.Paths.LinuxHosts)
	if err != nil {
		return nil
	}
	f := inv.callerScopes()
	var out []string
	for _, e := range reg.Entries() {
		if f.allows(e.Scope) {
			out = append(out, descLine(e.Name, "linux", hostOf(e.Target), e.Scope))
		}
	}
	return out
}

// deviceDescs are the names of the 'devices' kind, each with '<vendor>
// <address> <scope>' (an enrolled host: 'linux <host> <scope>'); only
// entries the caller's scopes allow are named, as for the names. When the
// registry cannot be joined with the store the names come without a
// description.
func (inv *invocation) deviceDescs() []string {
	names := inv.deviceNames(nil)
	_, res, err := inv.deviceLoad()
	if err != nil {
		return names
	}
	f := inv.callerScopes()
	by := map[string]string{}
	for _, e := range res.Visible(devreg.ScopeFilter{Restricted: f.restricted, Scopes: f.scopes}) {
		where := e.Address
		if where == "" {
			where = hostOf(e.Target)
		}
		if where == "" {
			where = e.Hostname
		}
		by[e.Name] = descLine(e.Name, e.Vendor, where, e.Scope)
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if l, ok := by[n]; ok {
			out = append(out, l)
		} else {
			out = append(out, n)
		}
	}
	return out
}

// scopeFilter is what a caller may see of the registries: everything for
// an administrator (superuser, unrestricted), the user's own scopes for
// the lower tiers (docs/plans/operator-console.md 8). It is also what an
// engineer may change: the devices and hosts of their own scopes (D18).
type scopeFilter struct {
	restricted bool
	scopes     []string
}

// allows reports whether an entry of scope may be named.
func (f scopeFilter) allows(scope string) bool {
	return !f.restricted || slices.Contains(f.scopes, scope)
}

// ownScope is nil when the caller may change what scope holds (its devices,
// tags, staging addresses and hosts): always, but for a caller f restricts
// (an engineer: the tier gate keeps the lower tiers from every change),
// whose own scopes it must be one of (D18). The refusal is printed, exit 1.
func (inv *invocation) ownScope(f scopeFilter, scope string) error {
	if f.allows(scope) {
		return nil
	}
	yours := "none"
	if len(f.scopes) > 0 {
		yours = strings.Join(f.scopes, ", ")
	}
	return inv.usageErr("Scope '" + scope + "' is not one of yours: the engineer tier changes the devices and hosts of its own scopes only (yours: " + yours + "). Nothing was changed.")
}

// callerScopes is the filter of the caller (SUDO_USER); a lower-tier caller
// whose model cannot be read sees nothing.
func (inv *invocation) callerScopes() scopeFilter {
	switch inv.tierGate().Caller(inv.ctx) {
	case tier.Readonly, tier.Operator, tier.Engineer:
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
			if n := len(args); n == 2 && args[1] == "--desc" {
				if descs, ok := completionDescKinds[kind]; ok {
					if l := descs(inv); len(l) > 0 {
						inv.write(strings.Join(l, "\n") + "\n")
					}
					return nil
				}
				args = args[:1]
			}
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
