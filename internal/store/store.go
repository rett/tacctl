// Package store is tacctl's canonical store, store.yaml: the schema and
// its validator, the normalised in-memory form, the canonical and disk
// forms, the locked atomic writer and the typed mutations. It is the port
// of lib/store.sh (_store_base_py, _store_py and the bash writers at the
// 0.1.16 tag); the read side (views, accessors, model JSON) is
// internal/model.
//
// The in-memory store is the document store_normalize builds: ordered
// mappings (*yamlpy.Map) and lists ([]any) of the values yamlpy.Decode
// returns. It is kept generic rather than typed because the validator must
// report on whatever a hand-edited file holds, with the messages of
// 0.1.16, and because a mutation may run on a store that does not validate
// (the write then fails with the validator's list). internal/model builds
// the typed view for readers.
//
// Secrets and password hashes pass through here. No message this package
// produces contains a 'secret' or 'hash' value.
package store

import (
	"errors"
	"slices"
	"time"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Version is STORE_VERSION.
const Version = 1

// Header is STORE_HEADER: the comment block every write puts first.
const Header = "# tacctl canonical store: users, groups, scopes, prefix filters.\n" +
	"# Managed by tacctl -- change it with tacctl commands. Contains shared\n" +
	"# secrets and password hashes; keep it 0600.\n\n"

// NotInitialisedMsg is STORE_NOT_INITIALISED_MSG, what every mutation says
// while the install is in legacy read-only mode.
const NotInitialisedMsg = "store not initialised — review 'tacctl store import --check' and run 'tacctl store import [--force]'"

// BuiltinGroup is one entry of BUILTIN_GROUPS.
type BuiltinGroup struct {
	Name         string
	PrivLvl      int
	JuniperClass string
}

// BuiltinGroups are the groups present in every store, in BUILTIN_GROUPS
// order (which is also the display order of 'group-info').
var BuiltinGroups = []BuiltinGroup{
	{"readonly", 1, "RO-CLASS"},
	{"operator", 7, "OP-CLASS"},
	{"superuser", 15, "RW-CLASS"},
}

// IsBuiltinGroup reports whether name is a built-in group.
func IsBuiltinGroup(name string) bool {
	for _, b := range BuiltinGroups {
		if b.Name == name {
			return true
		}
	}
	return false
}

// FilterKeys are the two prefix filter lists, in stored order.
var FilterKeys = []string{"allow", "deny"}

// TopKeys are the top-level keys of a store, in disk order.
var TopKeys = []string{"version", "groups", "users", "scopes", "filters"}

// SeedUser is one account of SEED_USERS.
type SeedUser struct{ Name, Group string }

// SeedUsers are the accounts a fresh install starts with besides the
// built-in groups ('root' is the accounting sink).
var SeedUsers = []SeedUser{
	{"engineer", "superuser"}, {"operator", "operator"},
	{"viewer", "readonly"}, {"root", "readonly"},
}

// Error is a StoreError: a problem reported to the operator as one
// 'tacctl store: <message>' line on stderr (exit 1). The message never
// contains a secret or a hash.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// Report is the line the 0.1.16 dispatcher prints for err on stderr:
// 'tacctl store: <message>' for an *Error or a file-system error (an
// OSError in Python: '<path>: <strerror>'), err.Error() otherwise.
// Callers print it as it is (no [ERROR] prefix), then exit 1.
func Report(err error) string {
	var se *Error
	if errors.As(err, &se) {
		return "tacctl store: " + se.Msg
	}
	var oe *osError
	if errors.As(err, &oe) {
		return "tacctl store: " + osErrorText(oe.err)
	}
	return err.Error()
}

// osError marks a file-system failure the dispatcher reports as an
// OSError.
type osError struct{ err error }

func (e *osError) Error() string { return osErrorText(e.err) }
func (e *osError) Unwrap() error { return e.err }

func storeErr(format string, args ...any) error {
	return &Error{Msg: sprintf(format, args...)}
}

// Store is a loaded (normalised) store: store_normalize's document, which
// the mutations change in place and Write canonicalises, validates and
// writes. The zero value is not usable; get one from Load, Normalize or
// Empty.
type Store struct {
	doc *yamlpy.Map
	// Now is the clock of 'password_changed=today' (local date, as
	// Python's date.today()); nil means time.Now.
	Now func() time.Time
}

// Doc returns the normalised document: version, groups, users, scopes,
// filters (then any unknown top-level keys of the file), each section a
// *yamlpy.Map keyed by name. Callers that change it must keep that shape.
func (s *Store) Doc() *yamlpy.Map { return s.doc }

func (s *Store) section(name string) *yamlpy.Map {
	v, _ := s.doc.Get(name)
	m, _ := v.(*yamlpy.Map)
	if m == nil {
		m = yamlpy.NewMap()
		s.doc.Set(name, m)
	}
	return m
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Empty is empty_model: version 1, the built-in groups, nothing else.
func Empty() *Store {
	groups := yamlpy.NewMap()
	for _, b := range BuiltinGroups {
		groups.Set(b.Name, yamlpy.NewMap("priv_lvl", b.PrivLvl, "juniper_class", b.JuniperClass, "builtin", true))
	}
	return &Store{doc: yamlpy.NewMap(
		"version", Version,
		"groups", groups,
		"users", yamlpy.NewMap(),
		"scopes", yamlpy.NewMap(),
		"filters", yamlpy.NewMap("allow", []any{}, "deny", []any{}),
	)}
}

func inList(list []string, v string) bool { return slices.Contains(list, v) }

// isKnownVendor and friends take any: a hand-edited list may hold numbers.
func isIn(list []string, v any) bool {
	s, ok := v.(string)
	return ok && inList(list, s)
}

var (
	knownVendors  = names.KnownVendors
	reservedUsers = names.ReservedUsers
	sinkUsers     = names.SinkUsers
)
