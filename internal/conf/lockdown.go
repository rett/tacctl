package conf

// The emergency lockdown of a scope (0.2.19) in tacctl.yaml:
// emergency.lockdown.<scope>.groups, .since, .by and .reason. The record of
// the groups whose logins a scope refuses: both renderers take the scope out
// of the users of those groups (model.WithoutMembers), so the server answers
// FAIL or Reject and never stays silent (silence is the break-glass hold's,
// and makes a device fall back to its local accounts). The store is never
// changed, so lifting the lockdown restores the rendered files byte for byte.
// Nothing here has a default and there is no expiry: a lockdown ends only
// when it is lifted. No credential is ever recorded.

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// LockdownPrefix starts every lockdown key.
const LockdownPrefix = "emergency.lockdown."

// The leaves of a lockdown.
const (
	LockdownKeyGroups = "groups"
	LockdownKeySince  = "since"
	LockdownKeyBy     = "by"
	LockdownKeyReason = "reason"
)

// MaxLockdownGroups is how many groups one scope may lock.
const MaxLockdownGroups = 64

// TypeLockdownGroups is emergency.lockdown.<scope>.groups: a non-empty list
// of group names.
const TypeLockdownGroups = "lockdown_groups"

// LockdownPath is the tacctl.yaml key of one leaf of a scope's lockdown.
func LockdownPath(scope, leaf string) string { return LockdownPrefix + scope + "." + leaf }

// Lockdown is one record.
type Lockdown struct {
	Scope  string
	Groups []string
	// Since is the RFC 3339 time the lockdown began (kept when groups are
	// added to it), By the user who began it and Reason the why.
	Since, By, Reason string
}

// SinceTime is the time of the lockdown (the zero time when since does not
// parse).
func (l Lockdown) SinceTime() time.Time {
	t, _ := parseHoldTime(l.Since)
	return t
}

// Locks reports whether the lockdown locks the group.
func (l Lockdown) Locks(group string) bool { return slices.Contains(l.Groups, group) }

// lockdownWildcards are the schema's entries for
// emergency.lockdown.<scope>.<leaf>.
func lockdownWildcards() []wildcard {
	return []wildcard{
		{LockdownPrefix, Rule{Type: TypeLockdownGroups, Tail: LockdownKeyGroups}},
		{LockdownPrefix, Rule{Type: TypeHoldSince, Tail: LockdownKeySince}},
		{LockdownPrefix, Rule{Type: TypeHoldText, Tail: LockdownKeyBy}},
		{LockdownPrefix, Rule{Type: TypeHoldText, Tail: LockdownKeyReason}},
	}
}

// lockdownGroupsProblem is the Validate branch of .groups.
func lockdownGroupsProblem(value any) string {
	items, isList := py.List(value)
	if !isList || len(items) == 0 {
		return "must be a non-empty list of group names"
	}
	if len(items) > MaxLockdownGroups {
		return fmt.Sprintf("at most %d groups per lockdown; got %d", MaxLockdownGroups, len(items))
	}
	seen := map[string]bool{}
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return fmt.Sprintf("element %d: must be a string", i)
		}
		if !names.MatchGroup(s) {
			return fmt.Sprintf("element %d: %s is not a group name", i, py.ReprString(s))
		}
		if seen[s] {
			return fmt.Sprintf("element %d: %s is listed twice", i, py.ReprString(s))
		}
		seen[s] = true
	}
	return ""
}

// Lockdowns reads the usable records of the merged view, ordered by scope.
func (c *Config) Lockdowns() []Lockdown {
	return LockdownsOf(c.Merged())
}

// LockdownsOf reads the usable records of a merged view: those with at least
// one group. A record with none (the schema accepts each leaf alone, so a
// hand-edited file can hold a partial one) locks nothing; LockdownDefects
// names it for the validator.
func LockdownsOf(view *yamlpy.Map) []Lockdown {
	var out []Lockdown
	for _, r := range lockdownRecordsOf(view) {
		if r.Defect == "" || len(r.Groups) > 0 {
			out = append(out, r.Lockdown)
		}
	}
	return out
}

// LockdownRecord is one entry of emergency.lockdown as the file has it.
type LockdownRecord struct {
	Lockdown
	// Defect is what is wrong with the entry ("" when nothing): it is not a
	// record, or has no groups.
	Defect string
}

// LockdownDefects are the entries of the merged view that have a defect, in
// scope order: what 'config validate' names, so that none stays invisible.
func (c *Config) LockdownDefects() []LockdownRecord {
	var out []LockdownRecord
	for _, r := range lockdownRecordsOf(c.Merged()) {
		if r.Defect != "" {
			out = append(out, r)
		}
	}
	return out
}

func lockdownRecordsOf(view *yamlpy.Map) []LockdownRecord {
	if view == nil {
		return nil
	}
	e, _ := view.Get("emergency")
	em, ok := e.(*yamlpy.Map)
	if !ok {
		return nil
	}
	v, _ := em.Get("lockdown")
	m, ok := v.(*yamlpy.Map)
	if !ok {
		return nil
	}
	var out []LockdownRecord
	for scope, e := range m.All() {
		r := LockdownRecord{Lockdown: Lockdown{Scope: scope}}
		leaves, ok := e.(*yamlpy.Map)
		if !ok {
			r.Defect = "is not a record (groups, since, by and reason)"
			out = append(out, r)
			continue
		}
		str := func(k string) string {
			x, _ := leaves.Get(k)
			s, _ := x.(string)
			return s
		}
		r.Since, r.By, r.Reason = str(LockdownKeySince), str(LockdownKeyBy), str(LockdownKeyReason)
		if g, _ := leaves.Get(LockdownKeyGroups); g != nil {
			items, _ := py.List(g)
			for _, it := range items {
				if s, ok := it.(string); ok && names.MatchGroup(s) {
					r.Groups = append(r.Groups, s)
				}
			}
		}
		if len(r.Groups) == 0 {
			r.Defect = "has no groups, so it locks nothing"
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

// LockedGroups maps each scope of a merged view that has a lockdown to the
// groups it locks: what the renderers take out of the users' scopes.
func LockedGroups(view *yamlpy.Map) map[string][]string {
	var out map[string][]string
	for _, l := range LockdownsOf(view) {
		if len(l.Groups) == 0 {
			continue
		}
		if out == nil {
			out = map[string][]string{}
		}
		out[l.Scope] = slices.Clone(l.Groups)
	}
	return out
}

// UpdateLockdown changes the record of one scope under the file's lock: fn
// gets the record the file holds now (nil when there is none) and returns the
// record to write, or nil to remove it; a non-nil error is returned as it is
// and nothing is written. Nothing is written when the result is what is
// there.
func (c *Config) UpdateLockdown(scope string, fn func(cur *Lockdown) (*Lockdown, error)) error {
	return c.edit(func(overrides *yamlpy.Map) (bool, error) {
		var cur *Lockdown
		for _, r := range lockdownRecordsOf(overrides) {
			if r.Scope == scope && len(r.Groups) > 0 {
				l := r.Lockdown
				cur = &l
			}
		}
		next, err := fn(cur)
		if err != nil {
			return false, err
		}
		if next == nil {
			return unsetLockdown(overrides, scope), nil
		}
		next.Scope = scope
		pairs := []PathValue{
			{LockdownPath(scope, LockdownKeyGroups), anyStrings(next.Groups)},
			{LockdownPath(scope, LockdownKeySince), next.Since},
			{LockdownPath(scope, LockdownKeyBy), next.By},
		}
		if next.Reason != "" {
			pairs = append(pairs, PathValue{LockdownPath(scope, LockdownKeyReason), next.Reason})
		}
		for _, pv := range pairs {
			_, isList := py.List(pv.Value)
			if msg := c.Schema.Validate(pv.Path, pv.Value, isList); msg != "" {
				return false, &ValidationError{Path: pv.Path, Msg: msg}
			}
		}
		if cur != nil && slices.Equal(cur.Groups, next.Groups) && cur.Since == next.Since && cur.By == next.By && cur.Reason == next.Reason {
			return false, nil
		}
		unsetLockdown(overrides, scope)
		for _, pv := range pairs {
			setNested(overrides, pv.Path, pv.Value)
		}
		return true, nil
	})
}

func anyStrings(s []string) []any {
	out := make([]any, len(s))
	for i, x := range s {
		out[i] = x
	}
	return out
}

// unsetLockdown removes a scope's record (and the mappings it leaves empty);
// it reports whether there was one.
func unsetLockdown(overrides *yamlpy.Map, scope string) bool {
	e, _ := overrides.Get("emergency")
	em, ok := e.(*yamlpy.Map)
	if !ok {
		return false
	}
	v, _ := em.Get("lockdown")
	m, ok := v.(*yamlpy.Map)
	if !ok {
		return false
	}
	if _, ok := m.Get(scope); !ok {
		return false
	}
	m.Delete(scope)
	if m.Len() == 0 {
		em.Delete("lockdown")
	}
	if em.Len() == 0 {
		overrides.Delete("emergency")
	}
	return true
}

// LockdownKeysOf lists the dotted paths under emergency.lockdown in the
// file's own overrides (not the merged view): what a rollback names.
func (c *Config) LockdownKeysOf() []string {
	var out []string
	walkLeaves(c.Overrides(), "", func(p string, _ any) {
		if strings.HasPrefix(p, LockdownPrefix) {
			out = append(out, p)
		}
	})
	return out
}
