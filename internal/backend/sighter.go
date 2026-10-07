package backend

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Sighting is one exchange a device had with the server, as the daemon's
// log records it (docs/plans/operator-console.md 2.2, 3.3): when, from
// which device address, for which user and with what outcome, and the name
// the device gave itself (RADIUS NAS-Identifier) when there is one.
type Sighting struct {
	Time time.Time
	// Address is the device's address in canonical form; "" when the line
	// names none (it is then only counted).
	Address string
	// User is the user name of the exchange ("" when the line has none).
	User string
	// Outcome is one of the Sight* words.
	Outcome string
	// NASID is the NAS-Identifier the device sent ("" for none, and for a
	// NAS-IP-Address standing in for it).
	NASID string
}

// The outcomes of a sighting.
const (
	// SightAccept: a user was authenticated.
	SightAccept = "accept"
	// SightReject: a user was refused.
	SightReject = "reject"
	// SightBadSecret: the device's packets could not be read (wrong shared
	// secret).
	SightBadSecret = "bad-secret"
	// SightNoScope: no scope's prefixes cover the device's address.
	SightNoScope = "no-scope"
	// SightSeen: the device talked to the server; the line says nothing
	// about a user (tacquito's debug line).
	SightSeen = "seen"
)

// Rejected reports whether an outcome is a refusal of any kind.
func Rejected(outcome string) bool {
	return outcome == SightReject || outcome == SightBadSecret || outcome == SightNoScope
}

// Sighter is a backend whose daemon logs which devices talk to it: the
// source of 'tacctl device scan'. It is optional, as Summarizer is: a
// backend without it is reported as having no sightings.
type Sighter interface {
	// Sightings reads the daemon's log from resume (an opaque point a
	// previous call returned; "" for none) or, without one, from since (the
	// zero time: everything the log still holds). It returns what it read
	// in log order, the point to resume from next time, and a one-line
	// description of the stretch of log it read (the window the scan
	// prints).
	Sightings(ctx context.Context, since time.Time, resume string) (sightings []Sighting, nextResume string, window string, err error)
}

// CanonAddr is the canonical text of an address as a log writes it: an
// IPv4 or IPv6 address without brackets, port or zone ("" when s is none,
// or 'unknown'). An IPv4-mapped IPv6 address is the IPv4 address.
func CanonAddr(s string) string {
	s = strings.TrimSpace(s)
	if h, _, ok := strings.Cut(s, "%"); ok {
		s = h
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	a, err := netip.ParseAddr(s)
	if err != nil || a.IsUnspecified() {
		return ""
	}
	return a.Unmap().String()
}

// CanonHostPort is CanonAddr of an 'address:port' ('[v6]:port') or of a
// bare address.
func CanonHostPort(s string) string {
	if ap, err := netip.ParseAddrPort(strings.TrimSpace(s)); err == nil {
		return CanonAddr(ap.Addr().String())
	}
	return CanonAddr(s)
}

// TimeWindow is the window text of what a scan read: 'first to last
// (n lines)', or none when nothing new was read.
func TimeWindow(what string, first, last time.Time, n int) string {
	if n == 0 || first.IsZero() {
		return what + ": no new entries"
	}
	unit := "entries"
	if n == 1 {
		unit = "entry"
	}
	const layout = "2006-01-02 15:04:05"
	return what + " " + first.Format(layout) + " to " + last.Format(layout) + " (" + strconv.Itoa(n) + " " + unit + ")"
}
