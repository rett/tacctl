package backend

import (
	"context"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/ui"
)

// Set is the backends of one invocation: the registry's modules, made on
// first use with the invocation's Env.
type Set struct {
	Registry *Registry
	Env      *Env
	made     map[string]Backend
}

// NewSet is the backends of r for one invocation.
func NewSet(r *Registry, env *Env) *Set {
	s := &Set{Registry: r, Env: env, made: map[string]Backend{}}
	if env != nil && env.Set == nil {
		env.Set = s
	}
	return s
}

// IDs is every registered id (BACKEND_IDS).
func (s *Set) IDs() []string { return s.Registry.IDs() }

// Get is the backend with that id (backend_call's lookup): an
// *UnknownError for an id no module registered.
func (s *Set) Get(id string) (Backend, error) {
	if b, ok := s.made[id]; ok {
		return b, nil
	}
	f := s.Registry.factory(id)
	if f == nil {
		return nil, &UnknownError{ID: id}
	}
	b := f(s.Env)
	s.made[id] = b
	return b, nil
}

// must is Get for an id known to be registered.
func (s *Set) must(id string) Backend {
	b, err := s.Get(id)
	if err != nil {
		panic(err)
	}
	return b
}

// EnabledError is _backends_load's refusal of a backends.enabled that
// names a backend this tacctl has no module for. Its message has not been
// printed.
type EnabledError struct {
	ID    string
	Known []string
}

func (e *EnabledError) Error() string {
	return "tacctl.yaml: backends.enabled names '" + e.ID + "', and this tacctl has no such backend (it has: " +
		strings.Join(e.Known, " ") + ")."
}

// Enabled is _backends_load: backends.enabled from tacctl.yaml (default
// DefaultEnabled when it is unset or empty), in order, duplicates and
// empty names dropped. A name no module registered is an *EnabledError.
// It is read from Env.Conf on every call, so it follows every tacctl.yaml
// write (which reloads Conf) without a cache to invalidate.
func (s *Set) Enabled() ([]string, error) {
	var ids []string
	if s.Env != nil && s.Env.Conf != nil {
		ids = s.Env.Conf.GetList("backends.enabled")
	}
	if len(ids) == 0 {
		ids = DefaultEnabled
	}
	var out []string
	for _, id := range ids {
		if id == "" || slices.Contains(out, id) {
			continue
		}
		if !s.Registry.Has(id) {
			return nil, &EnabledError{ID: id, Known: s.IDs()}
		}
		out = append(out, id)
	}
	return out, nil
}

// IsEnabled reports whether id is enabled (false when the enabled list
// cannot be read).
func (s *Set) IsEnabled(id string) bool {
	ids, err := s.Enabled()
	return err == nil && slices.Contains(ids, id)
}

// Present is backends_select_present, for uninstall: every backend that is
// enabled or installed (a disabled backend's daemon is still on the
// machine), the enabled ones first. A tacctl.yaml that cannot say which
// are enabled does not stop an uninstall: every backend is taken then.
func (s *Set) Present() []string {
	ids, err := s.Enabled()
	if err != nil {
		ids = s.IDs()
	}
	ids = slices.Clone(ids)
	for _, id := range s.IDs() {
		if !slices.Contains(ids, id) && s.must(id).Installed() {
			ids = append(ids, id)
		}
	}
	return ids
}

// Artifacts is backends_artifacts: every artifact of every enabled
// backend, in order.
func (s *Set) Artifacts() ([]string, error) {
	ids, err := s.Enabled()
	if err != nil {
		return nil, err
	}
	return s.artifactsOf(ids), nil
}

func (s *Set) artifactsOf(ids []string) []string {
	var out []string
	for _, id := range ids {
		out = append(out, s.must(id).Artifacts()...)
	}
	return out
}

// ArtifactNames is backend_artifact_names <id>: the backend's artifacts as
// 'a, b' for a message.
func (s *Set) ArtifactNames(id string) (string, error) {
	b, err := s.Get(id)
	if err != nil {
		return "", err
	}
	return strings.Join(b.Artifacts(), ", "), nil
}

// AllArtifactNames is backends_artifact_names: the same for every enabled
// backend ("" when the enabled list cannot be read).
func (s *Set) AllArtifactNames() string {
	a, err := s.Artifacts()
	if err != nil {
		return ""
	}
	return strings.Join(a, ", ")
}

// Owner is backends_artifact_owner: the id of the registered backend that
// lists path among its artifacts, or "".
func (s *Set) Owner(path string) string {
	for _, id := range s.IDs() {
		if slices.Contains(s.must(id).Artifacts(), path) {
			return id
		}
	}
	return ""
}

// LastLogin is backends_last_login: the most recent login any enabled
// backend knows of, or "never".
func (s *Set) LastLogin(ctx context.Context, user string) string {
	best := ""
	if ids, err := s.Enabled(); err == nil {
		for _, id := range ids {
			ts, err := s.must(id).LastLogin(ctx, user)
			if err != nil {
				continue
			}
			if ts != "" && ts != "never" && (best == "" || ts > best) {
				best = ts
			}
		}
	}
	if best == "" {
		return "never"
	}
	return best
}

// Heading is backend_heading: the heading of a backend's section in a
// report that covers more than one backend (status, log, config show...):
// an empty line, then '== Backend: <id> (<protocol>[, <impl>]) ==' in bold.
func Heading(b Backend) string {
	d := b.Describe()
	proto := d.Protocol
	if proto == "" {
		proto = b.ID()
	}
	if d.Impl != "" {
		proto += ", " + d.Impl
	}
	return "\n" + ui.Bold + "== Backend: " + b.ID() + " (" + proto + ") ==" + ui.NC + "\n"
}
