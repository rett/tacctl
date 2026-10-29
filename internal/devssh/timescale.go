package devssh

// The timing scale (0.2.22): one whole number that multiplies every network
// timing tacctl uses to reach a device, for a device that sits behind a long
// round trip or has a slow CPU. 1 is the timings as they have always been.
// The scale itself is a setting of the device, of its scope and of the whole
// server (internal/cli resolves it in that order); this file only holds its
// bounds and what a scale does to a timing.

import "time"

// The bounds of a timing scale. A scale of 1 changes nothing.
const (
	MinTimeoutScale = 1
	MaxTimeoutScale = 10
)

// ValidTimeoutScale reports whether n is a scale a setting may hold.
func ValidTimeoutScale(n int) bool { return n >= MinTimeoutScale && n <= MaxTimeoutScale }

// ScaleDuration is d multiplied by scale. A scale below 1 (a setting that is
// not there, or that a hand-edited file made nonsense) is 1, and one above
// MaxTimeoutScale is the largest, so a bad value never shrinks a timeout nor
// makes it absurd.
func ScaleDuration(d time.Duration, scale int) time.Duration {
	return d * time.Duration(min(max(scale, MinTimeoutScale), MaxTimeoutScale))
}

// ConnectTimeoutFor is DefaultConnectTimeout at scale: the budget of the TCP
// connect, the handshake and the authentication of a session, and of the
// first prompt of a shell or the hello of a NETCONF session.
func ConnectTimeoutFor(scale int) time.Duration { return ScaleDuration(DefaultConnectTimeout, scale) }

// Scaled is t, with its zero fields set to the defaults, multiplied by
// scale: ssh-keyscan's two -T, the connect budget, the handshake and the
// per-type attempt of the built-in client. Scale 1 is t.WithDefaults().
func (t ScanTiming) Scaled(scale int) ScanTiming {
	t = t.WithDefaults()
	return ScanTiming{
		Keyscan:      ScaleDuration(t.Keyscan, scale),
		KeyscanRetry: ScaleDuration(t.KeyscanRetry, scale),
		Connect:      ScaleDuration(t.Connect, scale),
		Handshake:    ScaleDuration(t.Handshake, scale),
		Attempt:      ScaleDuration(t.Attempt, scale),
	}
}
