package conf

// The per-scope NETCONF service setting of tacctl 0.2.10 in tacctl.yaml
// (D145 of docs/plans/0.2.10-plan.md): netconf_scope.<scope>.state,
// .connection_limit and .rate_limit. Only a scope that decided has them: an
// absent state is "leave" (tacctl plans and compares nothing of the service),
// so a tacctl.yaml that never had one does not change. A device's own value
// is a field of its registry entry (internal/devreg), not here.

// NetconfScopePrefix starts every per-scope NETCONF key.
const NetconfScopePrefix = "netconf_scope."

// The settings of a scope, as the keys under netconf_scope.<scope> name them.
const (
	NetconfKeyState           = "state"
	NetconfKeyConnectionLimit = "connection_limit"
	NetconfKeyRateLimit       = "rate_limit"
)

// NetconfKeys are the settings of a scope, in the order they are shown.
var NetconfKeys = []string{NetconfKeyState, NetconfKeyConnectionLimit, NetconfKeyRateLimit}

// The states of the setting. NetconfLeave is the default and is never stored
// for a scope (leaving the scope's state unset is the same word).
const (
	NetconfEnable  = "enable"
	NetconfDisable = "disable"
	NetconfLeave   = "leave"
)

// The bounds of the two limits of 'system services netconf ssh' [A: the Junos
// reference; no lab run has settled them].
const (
	NetconfMinLimit = 1
	NetconfMaxLimit = 250
)

// NetconfPath is the tacctl.yaml key of a scope's setting.
func NetconfPath(scope, key string) string { return NetconfScopePrefix + scope + "." + key }

// netconfScopeWildcards are the schema's entries for
// netconf_scope.<scope>.<key>.
func netconfScopeWildcards() []wildcard {
	return []wildcard{
		{NetconfScopePrefix, Rule{Type: TypeEnum, Values: []string{NetconfEnable, NetconfDisable}, Tail: NetconfKeyState}},
		{NetconfScopePrefix, Rule{Type: TypeInt, Min: intp(NetconfMinLimit), Max: intp(NetconfMaxLimit), Tail: NetconfKeyConnectionLimit}},
		{NetconfScopePrefix, Rule{Type: TypeInt, Min: intp(NetconfMinLimit), Max: intp(NetconfMaxLimit), Tail: NetconfKeyRateLimit}},
	}
}
