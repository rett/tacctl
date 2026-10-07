package devreg

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
)

// Source says where an entry comes from.
type Source string

// The two sources of entries: the registry and the enrolled hosts' file
// (read-only through 'device').
const (
	SourceDevice Source = "device"
	SourceHost   Source = "host"
)

// Entry is a registry device or an enrolled host as the commands see it,
// with the facts derived from the store: scope, vendor tag, shadowing.
type Entry struct {
	Device
	Source Source
	// Identity is the host's ssh key file ('' for a device).
	Identity string
	// Target is the host's [user@]host.
	Target string
	// Scope is the scope that answers the address (a host: its own scope);
	// Prefix the prefix that routes there; Tag the vendor tag covering the
	// address ('' when untagged); Shadowed the scopes that lose to Scope.
	Scope, Prefix, Tag string
	Shadowed           []string
	// Configured: a scope answers the address (a host: its scope exists).
	Configured bool
	// PrevAddress and AddressChanged: a host's address before the last
	// change 'host sync' recorded, and when ('' when none).
	PrevAddress, AddressChanged string
	// Method is a host's login method (tacplus or radius; '' for a device).
	Method string
}

// State is 'configured' or 'unconfigured'.
func (e Entry) State() string {
	if e.Configured {
		return "configured"
	}
	return "unconfigured"
}

// ScopeFilter says which scopes a caller may see: all of them, or the
// listed ones (the tier gate's "own scopes only", docs/plans/
// operator-console.md 8). An entry no scope answers is no one's.
type ScopeFilter struct {
	Restricted bool
	Scopes     []string
}

// Allows reports whether an entry of scope may be seen.
func (f ScopeFilter) Allows(scope string) bool {
	return !f.Restricted || (scope != "" && slices.Contains(f.Scopes, scope))
}

// Resolver joins the registry, the enrolled hosts and the store's scopes
// into one namespace: names compare case-insensitively across the registry
// and the hosts, and a device is found by name or by its registered
// address.
type Resolver struct {
	File  *File
	Hosts []hosts.Entry
	Model *model.Model
	// Seen is the seen cache the scan-time notices come from (nil: none).
	Seen *Seen

	idx *noticeIndex
}

// NewResolver joins the three; hostReg and m may be nil.
func NewResolver(f *File, hostReg *hosts.Registry, m *model.Model) *Resolver {
	r := &Resolver{File: f, Model: m}
	if hostReg != nil {
		r.Hosts = hostReg.Entries()
	}
	return r
}

func (r *Resolver) extraGeneric() []string { return r.File.GenericNames }

// derive fills the facts that come from the store.
func (r *Resolver) derive(e *Entry) {
	if r.Model == nil {
		return
	}
	if e.Source == SourceHost {
		e.Configured = e.Scope != "" && r.Model.Exists("scopes", e.Scope)
		return
	}
	if info, ok := r.Model.LookupAddr(e.Address); ok {
		e.Scope, e.Prefix, e.Tag, e.Shadowed, e.Configured = info.Scope, info.Prefix, info.Tag, info.Shadowed, true
	}
}

// hostEntry is an enrolled host as a vendor=linux entry: hostname, port
// and identity from 'target|port|identity' (the target's user is the
// provisioning account, never a login for 'tacctl ssh'); the address is the
// one 'host enroll'/'host sync' recorded, else (a host not synced since
// addresses were recorded) the scope's single /32 or /128 when it has one.
func (r *Resolver) hostEntry(h hosts.Entry) Entry {
	e := Entry{Source: SourceHost, Target: h.Target, Identity: h.Identity, Method: h.EffectiveMethod()}
	e.Name, e.Vendor, e.Scope = h.Name, VendorLinux, h.Scope
	if rec := r.File.Host(h.Name); rec != nil {
		e.HostKeys, e.Ack = slices.Clone(rec.Keys), slices.Clone(rec.Ack)
		e.Address, e.PrevAddress, e.AddressChanged = rec.Address, rec.PrevAddress, rec.Changed
	}
	host := h.Target
	if _, after, ok := strings.Cut(h.Target, "@"); ok {
		host = after
	}
	e.Hostname = host
	if n, err := strconv.Atoi(h.Port); err == nil && n != DefaultPort {
		e.Port = n
	}
	if r.Model != nil && e.Address == "" {
		if ps := r.Model.ScopePrefixes(h.Scope); len(ps) == 1 {
			if a, ok := strings.CutSuffix(ps[0], "/32"); ok {
				e.Address = a
			} else if a, ok := strings.CutSuffix(ps[0], "/128"); ok {
				e.Address = a
			}
		}
	}
	r.derive(&e)
	return e
}

// All is every entry, unfiltered: the registry's devices in file order,
// then the enrolled hosts in theirs.
func (r *Resolver) All() []Entry {
	var out []Entry
	for _, d := range r.File.Devices {
		e := Entry{Device: d.Clone(), Source: SourceDevice}
		r.derive(&e)
		out = append(out, e)
	}
	for _, h := range r.Hosts {
		out = append(out, r.hostEntry(h))
	}
	return out
}

// Visible is the entries f may see.
func (r *Resolver) Visible(f ScopeFilter) []Entry {
	var out []Entry
	for _, e := range r.All() {
		if f.Allows(e.Scope) {
			out = append(out, e)
		}
	}
	return out
}

// Lookup finds an entry f may see by name (case-insensitively) or by its
// registered address; an entry hidden from f is not found.
func (r *Resolver) Lookup(key string, f ScopeFilter) (Entry, bool) {
	addr, aerr := NormalizeAddress(key)
	var byAddr *Entry
	all := r.Visible(f)
	for i, e := range all {
		if strings.EqualFold(e.Name, key) {
			return e, true
		}
		if aerr == nil && byAddr == nil && e.Address == addr {
			byAddr = &all[i]
		}
	}
	if byAddr != nil {
		return *byAddr, true
	}
	return Entry{}, false
}

// NameTaken is the entry that already holds name in the shared namespace.
func (r *Resolver) NameTaken(name string) (Entry, bool) {
	for _, e := range r.All() {
		if strings.EqualFold(e.Name, name) {
			return e, true
		}
	}
	return Entry{}, false
}

// AddressTaken is the entry already registered at address.
func (r *Resolver) AddressTaken(address string) (Entry, bool) {
	a, err := NormalizeAddress(address)
	if err != nil {
		return Entry{}, false
	}
	for _, e := range r.All() {
		if e.Address == a {
			return e, true
		}
	}
	return Entry{}, false
}

// CheckName is the refusal of a name that cannot be registered: a
// duplicate in the shared namespace (compared case-insensitively), then a
// generic name unless allowGeneric. Shape and reserved words are
// ValidateName's.
func (r *Resolver) CheckName(name, vendor string, allowGeneric bool, keep string) error {
	if e, ok := r.NameTaken(name); ok {
		switch {
		case e.Source == SourceHost:
			return fail("'" + name + "' is an enrolled host; choose another name, or see 'tacctl device show " + e.Name + "'")
		case e.Address != "":
			return fail("'" + e.Name + "' is already registered (" + e.Address + "); choose another name, or see 'tacctl device show " + e.Name + "'")
		}
		return fail("'" + e.Name + "' is already registered; choose another name, or see 'tacctl device show " + e.Name + "'")
	}
	if !allowGeneric && IsGeneric(name, r.extraGeneric()) {
		return GenericRefusal(name, vendor, keep)
	}
	return nil
}

// CheckAddress is the refusal of an address another entry holds; except is
// the name that may keep it.
func (r *Resolver) CheckAddress(address, except string) error {
	e, ok := r.AddressTaken(address)
	if !ok || strings.EqualFold(e.Name, except) {
		return nil
	}
	if e.Source == SourceHost {
		return fail(address + " belongs to the enrolled host '" + e.Name + "'.")
	}
	return fail(address + " is already registered as '" + e.Name + "'; rename it with 'tacctl device rename " + e.Name + " <new>'")
}

// CheckHostName is what 'host enroll' asks before it takes a name: the
// name must be free in the registry's namespace, and not generic unless the
// host is already enrolled (hosts enrolled under a generic name before the
// registry existed are not refused retroactively; they carry a notice).
func CheckHostName(f *File, name string, enrolled bool) error {
	if d := f.Find(name); d != nil {
		return fail("'" + d.Name + "' is already registered as a device (" + d.Address + "); choose another --name, or see 'tacctl device show " + d.Name + "'")
	}
	if !enrolled && IsGeneric(name, f.GenericNames) {
		return fail("'"+name+"' is a generic name (a factory or image default); hosts are told apart by name.",
			"Pass --name <a name of its own>, or give the host one first: 'hostnamectl set-hostname <name>'.")
	}
	return nil
}
