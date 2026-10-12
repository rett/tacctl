package devreg

// The scan (docs/plans/operator-console.md 3.4, 3.7): read every source's
// sightings into the seen cache, re-scan the pinned entries' host keys, and
// list the addresses that authenticated without being registered. The
// command line around it is internal/cli/device_scan.go. A scan never
// writes devices.yaml: a re-scanned key is kept in the cache and compared
// with the pin, and only 'device hostkey <name> accept|set' changes a pin.

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
)

// ScanSource is one backend the scan reads; a nil Sighter is a backend
// whose daemon keeps no log of its devices.
type ScanSource struct {
	ID      string
	Sighter backend.Sighter
}

// ScanOptions say what a scan reads: by default each source from where
// the last scan stopped (the first time, the last stale_days); Full
// re-reads everything the logs still hold, Since the stretch before Now.
// Both replace what the cache held of those sources.
type ScanOptions struct {
	Now       time.Time
	StaleDays int
	Full      bool
	Since     time.Duration
}

// SourceReport is what a scan read from one source.
type SourceReport struct {
	ID string
	// Window is the stretch of log read, as the source describes it.
	Window string
	// Sightings and Addresses count what was read; Unattributed the
	// sightings that named no address.
	Sightings, Addresses, Unattributed int
	// NoLog: the backend keeps no log of its devices.
	NoLog bool
	// Err is a source that could not be read (the cache keeps what it had).
	Err error
}

// ScanSources reads each source into s and reports what it read.
func ScanSources(ctx context.Context, s *Seen, srcs []ScanSource, o ScanOptions) []SourceReport {
	stale := o.StaleDays
	if stale < 1 {
		stale = DefaultStaleDays
	}
	var out []SourceReport
	for _, src := range srcs {
		rep := SourceReport{ID: src.ID}
		if src.Sighter == nil {
			rep.NoLog = true
			out = append(out, rep)
			continue
		}
		resume, since, reset := "", time.Time{}, false
		st := s.Sources[src.ID]
		switch {
		case o.Full:
			reset = true
		case o.Since > 0:
			reset, since = true, o.Now.Add(-o.Since)
		case st != nil && st.Resume != "":
			resume = st.Resume
		default:
			since = o.Now.AddDate(0, 0, -stale)
		}
		ss, next, window, err := src.Sighter.Sightings(ctx, since, resume)
		if err != nil {
			rep.Err = err
			out = append(out, rep)
			continue
		}
		if reset {
			s.ResetSource(src.ID)
		}
		rep.Unattributed = s.Apply(src.ID, ss)
		rep.Window, rep.Sightings = window, len(ss)
		addrs := map[string]bool{}
		for _, x := range ss {
			if x.Address != "" {
				addrs[x.Address] = true
			}
		}
		rep.Addresses = len(addrs)
		s.Sources[src.ID] = &SourceState{Resume: next, Window: window, Scanned: o.Now, Unattributed: rep.Unattributed}
		out = append(out, rep)
	}
	s.Updated = o.Now
	return out
}

var reSince = regexp.MustCompile(`^([0-9]{1,6})([wdhm])$`)

// ParseSince reads a --since duration: <n>w, <n>d, <n>h or <n>m, or a Go
// duration such as 90m or 1h30m.
func ParseSince(v string) (time.Duration, error) {
	bad := fail("Invalid --since '" + v + "': expected a duration such as 7d, 12h, 30m or 2w.")
	if m := reSince.FindStringSubmatch(v); m != nil {
		n, _ := strconv.Atoi(m[1])
		unit := map[string]time.Duration{"w": 7 * 24 * time.Hour, "d": 24 * time.Hour, "h": time.Hour, "m": time.Minute}[m[2]]
		if n == 0 {
			return 0, bad
		}
		return time.Duration(n) * unit, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, bad
	}
	return d, nil
}

// --- host keys ---------------------------------------------------------------------

// KeyTarget is an entry whose host keys a scan reads again.
type KeyTarget struct {
	Name    string
	Address string
	Port    int
	Legacy  bool
}

// KeyResult is one re-scan: the keys offered, ErrNoAnswer, or another error
// (ssh-keyscan could not be run).
type KeyResult struct {
	Target KeyTarget
	Keys   []HostKey
	Err    error
}

// KeyscanParallel is how many ssh-keyscan run at once.
const KeyscanParallel = 8

// RescanKeys reads the host keys of every target, a few at a time, with
// ScanWith (fallback may be nil).
func RescanKeys(ctx context.Context, r execx.Runner, targets []KeyTarget, fallback KeyFallback) []KeyResult {
	out := make([]KeyResult, len(targets))
	sem := make(chan struct{}, KeyscanParallel)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			keys, err := ScanWith(ctx, r, t.Address, t.Port, t.Legacy, fallback)
			out[i] = KeyResult{Target: t, Keys: keys, Err: err}
		}()
	}
	wg.Wait()
	return out
}

// RecordKeyResults keeps the re-scans in s: a device that did not answer
// is unreachable; a scan that could not run is not recorded, and its error
// is returned (the first one).
func (s *Seen) RecordKeyResults(results []KeyResult, at time.Time) error {
	var first error
	for _, res := range results {
		switch {
		case res.Err == nil:
			s.RecordKeyScan(res.Target.Name, res.Target.Address, res.Target.Port, res.Keys, at)
		case errors.Is(res.Err, ErrNoAnswer):
			s.RecordKeyScan(res.Target.Name, res.Target.Address, res.Target.Port, nil, at)
		case first == nil:
			first = res.Err
		}
	}
	return first
}

// --- discover ----------------------------------------------------------------------

// Unregistered is an address the logs show that no entry holds, with the
// scope and vendor tag that answer it and the name 'device add' would
// suggest ('<name>' when the NAS-Identifier cannot be one).
type Unregistered struct {
	Sighted
	Scope, Tag string
	Suggest    string
}

// Unregistered are the seen addresses no entry holds: those that ever
// authenticated, or every one with all.
func (r *Resolver) Unregistered(all bool) []Unregistered {
	held := map[string]bool{}
	for _, e := range r.All() {
		if e.Address != "" {
			held[e.Address] = true
		}
	}
	var out []Unregistered
	for _, s := range r.Seen.All() {
		if held[s.Address] || (!all && s.LastOK.IsZero()) {
			continue
		}
		u := Unregistered{Sighted: s, Suggest: "<name>"}
		if r.Model != nil {
			if info, ok := r.Model.LookupAddr(s.Address); ok {
				u.Scope, u.Tag = info.Scope, info.Tag
			}
		}
		if n := s.LastNASID; n != "" && ValidateName(n) == nil && r.CheckName(n, VendorOther, false, "") == nil &&
			len(r.index().byNAS[strings.ToLower(n)]) == 1 {
			u.Suggest = n
		}
		out = append(out, u)
	}
	return out
}
