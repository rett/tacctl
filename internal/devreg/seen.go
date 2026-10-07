package devreg

// The seen cache (docs/plans/operator-console.md 3.4):
// /var/lib/tacctl/devices-seen.json, root 0600 (the directory 0711,
// paths.MkVarLib). It is derived from the
// daemons' logs by 'tacctl device scan' and rebuildable at any time, so it
// is never snapshotted. Per address and per source (backend) it keeps when
// the address was first and last seen, how often, the last user and
// outcome, the last NAS-Identifier and the one before it; per source the
// point the next scan resumes from and the window the last scan read; per
// registry entry the result of the last host-key re-scan. Addresses no
// scope covers are kept: they are what 'device discover' lists. A source's
// record of an address is dropped after twice stale_days without a
// sighting.

import (
	"cmp"
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/paths"
)

// SeenVersion is the format of the seen cache.
const SeenVersion = 1

// SeenLockName is the lock file beside the seen cache.
const SeenLockName = ".devices-seen.lock"

// SourceSeen is what one source's log showed of one address.
type SourceSeen struct {
	First       time.Time `json:"first"`
	Last        time.Time `json:"last"`
	Count       int       `json:"count"`
	LastUser    string    `json:"last_user,omitempty"`
	LastOutcome string    `json:"last_outcome"`
	// LastOK is the last exchange that was not a refusal.
	LastOK time.Time `json:"last_ok,omitzero"`
	// LastNASID is the last NAS-Identifier the address sent; PrevNASID the
	// one before it changed, at NASChanged.
	LastNASID  string    `json:"last_nas_id,omitempty"`
	PrevNASID  string    `json:"prev_nas_id,omitempty"`
	NASChanged time.Time `json:"nas_changed,omitzero"`
}

// SourceState is a source's scan state.
type SourceState struct {
	// Resume is the opaque point the source's next read starts from.
	Resume string `json:"resume,omitempty"`
	// Window is what the last scan read, as the source described it.
	Window  string    `json:"window,omitempty"`
	Scanned time.Time `json:"scanned"`
	// Unattributed counts the sightings of the last scan that named no
	// address.
	Unattributed int `json:"unattributed,omitempty"`
}

// KeyScan is the last host-key re-scan of a registry entry: the keys it
// offered, or no answer, and when it last answered.
type KeyScan struct {
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	Scanned     time.Time `json:"scanned"`
	Unreachable bool      `json:"unreachable,omitempty"`
	Offered     []string  `json:"offered,omitempty"`
	LastGood    time.Time `json:"last_good,omitzero"`
}

// Seen is the seen cache.
type Seen struct {
	Version int                               `json:"version"`
	Updated time.Time                         `json:"updated,omitzero"`
	Sources map[string]*SourceState           `json:"sources"`
	Addrs   map[string]map[string]*SourceSeen `json:"addresses"`
	// HostKeys are keyed by the entry's name in lower case.
	HostKeys map[string]*KeyScan `json:"hostkeys"`
}

// NewSeen is an empty cache.
func NewSeen() *Seen {
	return &Seen{Version: SeenVersion, Sources: map[string]*SourceState{},
		Addrs: map[string]map[string]*SourceSeen{}, HostKeys: map[string]*KeyScan{}}
}

// HasData reports whether any scan has filled the cache.
func (s *Seen) HasData() bool { return s != nil && !s.Updated.IsZero() }

// LoadSeen reads the cache; an absent file is an empty cache. A file that
// cannot be read as one is an error (the scan rebuilds it).
func LoadSeen(path string) (*Seen, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return NewSeen(), nil
	}
	if err != nil {
		return NewSeen(), fail("Cannot read " + path + ": " + errText(err))
	}
	s := NewSeen()
	if err := json.Unmarshal(data, s); err != nil || s.Version != SeenVersion {
		return NewSeen(), fail(path + " is not a seen cache of this tacctl; 'tacctl device scan --full' rebuilds it.")
	}
	if s.Sources == nil {
		s.Sources = map[string]*SourceState{}
	}
	if s.Addrs == nil {
		s.Addrs = map[string]map[string]*SourceSeen{}
	}
	if s.HostKeys == nil {
		s.HostKeys = map[string]*KeyScan{}
	}
	return s, nil
}

// Save writes the cache (0600, through a temporary file).
func (s *Seen) Save(path string) error {
	if err := paths.MkVarLib(filepath.Dir(path)); err != nil {
		return fail("Cannot create " + filepath.Dir(path) + ": " + errText(err))
	}
	data, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0o600)
}

// LockSeen takes the cache's exclusive lock and returns its release.
func LockSeen(path string) (unlock func(), err error) {
	d := filepath.Dir(path)
	if err := paths.MkVarLib(d); err != nil {
		return nil, fail("Cannot create " + d + ": " + errText(err))
	}
	lf, err := os.OpenFile(filepath.Join(d, SeenLockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fail("Cannot open the seen cache lock: " + errText(err))
	}
	for {
		err = unix.Flock(int(lf.Fd()), unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = lf.Close()
		return nil, fail("Cannot lock the seen cache: " + err.Error())
	}
	return func() { _ = lf.Close() }, nil
}

// Apply adds a source's sightings, in log order. It returns how many named
// no address (they are counted, not kept).
func (s *Seen) Apply(source string, ss []backend.Sighting) (unattributed int) {
	for _, x := range ss {
		if x.Address == "" {
			unattributed++
			continue
		}
		bySrc := s.Addrs[x.Address]
		if bySrc == nil {
			bySrc = map[string]*SourceSeen{}
			s.Addrs[x.Address] = bySrc
		}
		r := bySrc[source]
		if r == nil {
			r = &SourceSeen{}
			bySrc[source] = r
		}
		r.Count++
		if r.First.IsZero() || x.Time.Before(r.First) {
			r.First = x.Time
		}
		if !backend.Rejected(x.Outcome) && x.Time.After(r.LastOK) {
			r.LastOK = x.Time
		}
		if x.Time.Before(r.Last) {
			continue
		}
		r.Last = x.Time
		// A debug line says the device talked, nothing about the user: it
		// does not replace what an authentication line said.
		if x.Outcome != backend.SightSeen || r.LastOutcome == "" {
			r.LastOutcome = x.Outcome
			r.LastUser = x.User
		}
		if x.NASID != "" {
			if r.LastNASID != "" && !strings.EqualFold(r.LastNASID, x.NASID) {
				r.PrevNASID, r.NASChanged = r.LastNASID, x.Time
			}
			r.LastNASID = x.NASID
		}
	}
	return unattributed
}

// ResetSource forgets everything a source contributed (a full re-read).
func (s *Seen) ResetSource(source string) {
	delete(s.Sources, source)
	for a, bySrc := range s.Addrs {
		delete(bySrc, source)
		if len(bySrc) == 0 {
			delete(s.Addrs, a)
		}
	}
}

// Prune drops each source's record of an address last seen more than
// twice staleDays before now, and the host-key results of entries that are
// gone (names: the entries there are).
func (s *Seen) Prune(now time.Time, staleDays int, names []string) {
	if staleDays < 1 {
		staleDays = DefaultStaleDays
	}
	cut := now.AddDate(0, 0, -2*staleDays)
	for a, bySrc := range s.Addrs {
		for src, r := range bySrc {
			if r.Last.Before(cut) {
				delete(bySrc, src)
			}
		}
		if len(bySrc) == 0 {
			delete(s.Addrs, a)
		}
	}
	keep := map[string]bool{}
	for _, n := range names {
		keep[strings.ToLower(n)] = true
	}
	for n := range s.HostKeys {
		if !keep[n] {
			delete(s.HostKeys, n)
		}
	}
}

// Sighted is what the cache knows of an address, every source merged: the
// first and last time, the count, and the last user, outcome and source
// (via); the NAS-Identifier is the most recent one any source carried.
type Sighted struct {
	Address     string
	First, Last time.Time
	LastOK      time.Time
	Count       int
	LastUser    string
	LastOutcome string
	Via         string
	LastNASID   string
	PrevNASID   string
	NASChanged  time.Time
}

// Rejected reports whether the last exchange was a refusal.
func (x Sighted) Rejected() bool { return backend.Rejected(x.LastOutcome) }

// Of is the merged record of an address.
func (s *Seen) Of(addr string) (Sighted, bool) {
	if s == nil {
		return Sighted{}, false
	}
	bySrc, ok := s.Addrs[addr]
	if !ok || len(bySrc) == 0 {
		return Sighted{}, false
	}
	x := Sighted{Address: addr}
	var nasAt time.Time
	srcs := make([]string, 0, len(bySrc))
	for src := range bySrc {
		srcs = append(srcs, src)
	}
	slices.Sort(srcs)
	for _, src := range srcs {
		r := bySrc[src]
		x.Count += r.Count
		if x.First.IsZero() || r.First.Before(x.First) {
			x.First = r.First
		}
		if r.LastOK.After(x.LastOK) {
			x.LastOK = r.LastOK
		}
		if x.Via == "" || r.Last.After(x.Last) {
			x.Last, x.LastUser, x.LastOutcome, x.Via = r.Last, r.LastUser, r.LastOutcome, src
		}
		if r.LastNASID != "" && (nasAt.IsZero() || r.Last.After(nasAt)) {
			nasAt = r.Last
			x.LastNASID, x.PrevNASID, x.NASChanged = r.LastNASID, r.PrevNASID, r.NASChanged
		}
	}
	return x, true
}

// All is every address's merged record, in address order.
func (s *Seen) All() []Sighted {
	if s == nil {
		return nil
	}
	addrs := make([]string, 0, len(s.Addrs))
	for a := range s.Addrs {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, compareAddr)
	var out []Sighted
	for _, a := range addrs {
		if x, ok := s.Of(a); ok {
			out = append(out, x)
		}
	}
	return out
}

// KeyScanOf is the last host-key re-scan of the entry called name.
func (s *Seen) KeyScanOf(name string) (*KeyScan, bool) {
	if s == nil {
		return nil, false
	}
	k, ok := s.HostKeys[strings.ToLower(name)]
	return k, ok
}

// RecordKeyScan keeps the result of a host-key re-scan of an entry: the
// keys offered, or none (unreachable). Nothing is pinned here: a scan never
// changes devices.yaml.
func (s *Seen) RecordKeyScan(name, address string, port int, offered []HostKey, at time.Time) {
	k := s.HostKeys[strings.ToLower(name)]
	if k == nil || k.Address != address || k.Port != port {
		k = &KeyScan{Address: address, Port: port}
		s.HostKeys[strings.ToLower(name)] = k
	}
	k.Scanned = at
	k.Unreachable = len(offered) == 0
	if !k.Unreachable {
		k.Offered = KeyStrings(offered)
		k.LastGood = at
	}
}

// compareAddr orders addresses: IPv4 before IPv6, then numerically;
// anything that does not parse last, as text.
func compareAddr(a, b string) int {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	switch {
	case errA == nil && errB == nil:
		return x.Compare(y)
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return cmp.Compare(a, b)
}
