package conf

// The timing scale of tacctl 0.2.22 in tacctl.yaml: one whole number that
// multiplies every network timing used to reach a device (devssh's
// timescale.go). The default of the whole server is device.timeout_scale; a
// scope decides for its devices with timeout_scale_scope.<scope>, and a
// device's own value is a field of its registry entry (internal/devreg).
// The order is the device's, then the scope's, then the default's, then 1,
// which is every timing as it has always been. The scope's key is written
// only when the scope decided.

// The bounds of a scale (a test holds them equal to devssh's and devreg's).
const (
	TimeoutScaleMin = 1
	TimeoutScaleMax = 10
)

// TimeoutScaleKey is the tacctl.yaml key of the default of the whole server.
const TimeoutScaleKey = "device.timeout_scale"

// TimeoutScaleScopeFamily is the mapping of per-scope scales, and
// TimeoutScaleScopePrefix starts every key of it.
const (
	TimeoutScaleScopeFamily = "timeout_scale_scope"
	TimeoutScaleScopePrefix = TimeoutScaleScopeFamily + "."
)

// TimeoutScaleScopePath is the tacctl.yaml key of a scope's scale.
func TimeoutScaleScopePath(scope string) string { return TimeoutScaleScopePrefix + scope }

// timeoutScaleScopeWildcards are the schema's entries for
// timeout_scale_scope.<scope>; no default on purpose: unset follows the
// default of the whole server.
func timeoutScaleScopeWildcards() []wildcard {
	return []wildcard{
		{TimeoutScaleScopePrefix, Rule{Type: TypeInt, Min: intp(TimeoutScaleMin), Max: intp(TimeoutScaleMax)}},
	}
}
