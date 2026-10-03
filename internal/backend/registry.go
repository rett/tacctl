package backend

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"time"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// Env is what a backend module, and the machinery of this package, work
// with in one invocation. Build it once (internal/cli), with Conf loaded
// for the registry's ids: conf.Load(paths.Overrides, registry.IDs()).
type Env struct {
	Paths  paths.Paths
	Conf   *conf.Config
	Runner execx.Runner
	Out    ui.Output
	Stdin  io.Reader
	// Now is the clock (nil: time.Now); pass the App's knob clock.
	Now func() time.Time
	// Fault is the TACCTL_FAULT check (nil: no faults); pass the App's
	// Knobs.Fault. The points of this package are FaultStage and
	// FaultCommit.
	Fault func(point string) error
	// Snapshots takes the pre-change snapshots (nil: none are taken).
	Snapshots *snapshot.Snapshotter
	// Set is the invocation's backend set, filled in by NewSet, so a module
	// can run its own changes through Set.StoreApply.
	Set *Set
}

// fault is the Env's fault check.
func (e *Env) fault(point string) error {
	if e.Fault == nil {
		return nil
	}
	return e.Fault(point)
}

// MutateOptions are the store.MutateOptions of a store write made in this
// invocation: the snapshot hook (quiet while StoreApply holds its own
// snapshot) and the clock.
func (e *Env) MutateOptions() store.MutateOptions {
	o := store.MutateOptions{Now: e.Now}
	if e.Snapshots != nil {
		o.Snapshot = e.Snapshots.Hook
	}
	return o
}

// Factory makes a module's backend for one invocation.
type Factory func(env *Env) Backend

// The ids of the shipped modules, in registration order: TACACS+ first.
const (
	TACACS = "tacacs"
	RADIUS = "radius"
	// TACACSS is TACACS+ over TLS: a reserved id with no module (the
	// listener schema's tls fields are refused as "reserved" in
	// internal/conf). Registering it is refused.
	TACACSS = "tacacss"
)

// Reserved are the ids no module may register.
var Reserved = []string{TACACSS}

// IsReserved reports whether id is reserved.
func IsReserved(id string) bool { return slices.Contains(Reserved, id) }

// DefaultEnabled is backends.enabled when tacctl.yaml does not set it
// (BACKENDS_DEFAULT_ENABLED; internal/conf's schema carries the same
// default, which a test pins).
var DefaultEnabled = []string{TACACS}

var idRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Registry is the set of backend modules this tacctl has (BACKEND_IDS):
// ids with their factories. The order is fixed by the slots it was made
// with, then by registration, never by Go's package initialisation order.
type Registry struct {
	slots     []string
	order     []string
	factories map[string]Factory
}

// NewRegistry is an empty registry whose ids come in the order of slots
// (registered ones only), then any other id in the order it was added.
func NewRegistry(slots ...string) *Registry {
	return &Registry{slots: slices.Clone(slots), factories: map[string]Factory{}}
}

// defaultRegistry is the one the shipped modules register with: tacacs
// (WP2.2, internal/backend/tacacs) and radius (WP2.3,
// internal/backend/radius) fill its slots from their init functions.
var defaultRegistry = NewRegistry(TACACS, RADIUS)

// Default is the registry of the shipped modules.
func Default() *Registry { return defaultRegistry }

// Register adds a module to the default registry; for a module's init
// function. It panics on an invalid, reserved or duplicate id (a
// programming error, found by the first test that loads the module).
func Register(id string, f Factory) {
	if err := defaultRegistry.Add(id, f); err != nil {
		panic(err)
	}
}

// Add registers a module. An id must be [a-z][a-z0-9_]*, not reserved and
// not registered yet, and the factory non-nil.
func (r *Registry) Add(id string, f Factory) error {
	switch {
	case !idRE.MatchString(id):
		return fmt.Errorf("backend: invalid backend id %q", id)
	case IsReserved(id):
		return fmt.Errorf("backend: backend id %q is reserved", id)
	case f == nil:
		return fmt.Errorf("backend: backend %q has no factory", id)
	}
	if _, dup := r.factories[id]; dup {
		return fmt.Errorf("backend: backend %q is registered twice", id)
	}
	r.factories[id] = f
	if !slices.Contains(r.slots, id) {
		r.order = append(r.order, id)
	}
	return nil
}

// Has is backend_registered.
func (r *Registry) Has(id string) bool {
	_, ok := r.factories[id]
	return ok
}

// IDs is BACKEND_IDS: every registered id, the slots' order first.
func (r *Registry) IDs() []string {
	var out []string
	for _, id := range r.slots {
		if r.Has(id) {
			out = append(out, id)
		}
	}
	return append(out, r.order...)
}

// factory is the id's factory, or nil.
func (r *Registry) factory(id string) Factory { return r.factories[id] }
