// Package paths holds the process environment and every filesystem location
// tacctl uses, resolved once per invocation from the TACCTL_* variables with
// the production defaults of the bash implementation (lib/core.sh,
// lib/store.sh, lib/backend.sh, lib/dispatch.sh, lib/linux_hosts.sh,
// lib/backends/tacacs.sh, lib/backends/radius.sh at the 0.1.16 tag).
//
// It is the only package that reads the environment (the test knobs aside):
// cmd/tacctl hands os.Environ() to cli.Main, which wraps it in an Env.
package paths

import "strings"

// Env is a snapshot of the process environment in its original order.
// The zero value is an empty environment.
type Env struct {
	list []string
	vals map[string]string
}

// NewEnv wraps an environment in os.Environ() form ("KEY=value"). Entries
// without '=' are kept for Environ but have no value; for a key that occurs
// twice the last value wins, as getenv(3) does with a well-formed environ.
func NewEnv(environ []string) Env {
	e := Env{list: append([]string(nil), environ...), vals: make(map[string]string, len(environ))}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			e.vals[k] = v
		}
	}
	return e
}

// Lookup returns the value of key and whether it is set (possibly empty).
func (e Env) Lookup(key string) (string, bool) {
	v, ok := e.vals[key]
	return v, ok
}

// Get returns the value of key, or "" when unset.
func (e Env) Get(key string) string {
	return e.vals[key]
}

// Or returns the value of key when it is set and not empty, else def: the
// bash expansion ${KEY:-def}.
func (e Env) Or(key, def string) string {
	if v := e.vals[key]; v != "" {
		return v
	}
	return def
}

// Environ returns a copy of the environment as given to NewEnv, for handing
// unchanged to a process tacctl execs.
func (e Env) Environ() []string {
	return append([]string(nil), e.list...)
}
