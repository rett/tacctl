//go:build testknobs

package cli

// A -tags testknobs binary (the bats suite, the differential runner) finds a
// command classified read that reaches a write the way the Go tests do: it
// panics (audit.go). Its two test-only commands, the fake device and the
// SNMP test agent, change no state of tacctl's.
func init() {
	auditPanics = true
	auditTable["_fake-device"] = read()
	auditTable["_snmp-agent"] = read()
}
