package hosts

// Whether a host can hold tacctl's UID range at all. A host that is an
// unprivileged container (rootless podman, an LXC/LXD container) sees only
// the IDs its user namespace maps, usually 0-65535: useradd there accepts
// a larger UID, but the account cannot log in and its files cannot be
// given to it. 'host enroll' and 'host sync' read the host's
// /proc/self/uid_map and gid_map before anything runs there and refuse a
// host that does not map the whole range; 'host target' reports it.

import (
	"context"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/ui"
)

// IDMapCommand is the read-only remote command that prints the host's user
// namespace maps, each after a marker line.
const IDMapCommand = `echo uid_map; cat /proc/self/uid_map; echo gid_map; cat /proc/self/gid_map; true`

// IDMaps are a user namespace's maps: the IDs inside it that exist, as
// ranges.
type IDMaps struct {
	UID, GID []Range
}

// ParseIDMaps reads IDMapCommand's output (each map line: first ID inside,
// first ID outside, count).
func ParseIDMaps(out string) IDMaps {
	var m IDMaps
	var cur *[]Range
	for _, l := range strings.Split(out, "\n") {
		switch strings.TrimSpace(l) {
		case "uid_map":
			cur = &m.UID
			continue
		case "gid_map":
			cur = &m.GID
			continue
		}
		f := strings.Fields(l)
		if cur == nil || len(f) != 3 {
			continue
		}
		in, err1 := strconv.ParseInt(f[0], 10, 64)
		n, err2 := strconv.ParseInt(f[2], 10, 64)
		if err1 != nil || err2 != nil || n <= 0 {
			continue
		}
		*cur = append(*cur, Range{Min: int(in), Max: int(in + n - 1)})
	}
	return m
}

// covers reports whether the ranges hold every number of r.
func covers(rs []Range, r Range) bool {
	next := r.Min
	for {
		moved := false
		for _, x := range rs {
			if x.Has(next) {
				if x.Max >= r.Max {
					return true
				}
				next, moved = x.Max+1, true
			}
		}
		if !moved {
			return false
		}
	}
}

// rangesText is the ranges in words ("0-65535, 100000-165535").
func rangesText(rs []Range) string {
	w := make([]string, len(rs))
	for i, r := range rs {
		w[i] = r.String()
	}
	return strings.Join(w, ", ")
}

// Lacks is why the maps cannot hold r ("" when they can, or when nothing
// was read: a host that says nothing is not refused): the UIDs, else the
// GIDs, the namespace maps.
func (m IDMaps) Lacks(r Range) string {
	switch {
	case len(m.UID) > 0 && !covers(m.UID, r):
		return rangesText(m.UID)
	case len(m.GID) > 0 && !covers(m.GID, r):
		return "GIDs " + rangesText(m.GID)
	}
	return ""
}

// IDMapRefusal is the message for a host that cannot hold r (lacks:
// IDMaps.Lacks).
func IDMapRefusal(name string, r Range, lacks string) string {
	return "'" + name + "' cannot hold UIDs " + r.String() + ": its user namespace maps only " + lacks +
		" (an unprivileged container). Give it an ID map that covers " + r.String() +
		", run it privileged, or choose a range it can hold: tacctl config linux uid-range <min>-<max> (one range for all hosts)."
}

// ReadIDMaps reads target's maps: over ssh (the connection the script run
// then shares), or this server's own (ProcSelf) for a --local host. Nothing
// read (ssh failed, no such files) is the zero IDMaps.
func (e *Env) ReadIDMaps(ctx context.Context, target, port, identity string) (IDMaps, error) {
	if target == Local {
		dir := e.Paths.ProcSelf
		if dir == "" {
			dir = "/proc/self"
		}
		u, err1 := os.ReadFile(dir + "/uid_map")
		g, err2 := os.ReadFile(dir + "/gid_map")
		if err1 != nil || err2 != nil {
			return IDMaps{}, nil
		}
		return ParseIDMaps("uid_map\n" + string(u) + "gid_map\n" + string(g)), nil
	}
	c := e.ssh(port, identity).Cmd("-T", target, IDMapCommand)
	c.Stderr = io.Discard
	res, err := e.Runner.Run(ctx, c)
	if interrupted(ctx) {
		return IDMaps{}, ui.ErrInterrupted
	}
	if err != nil || res.Code != 0 {
		return IDMaps{}, nil
	}
	return ParseIDMaps(string(res.Stdout)), nil
}

// CheckIDMap refuses (printed, ErrFailed) a host whose user namespace
// cannot hold the range.
func (e *Env) CheckIDMap(ctx context.Context, name, target, port, identity string) error {
	m, err := e.ReadIDMaps(ctx, target, port, identity)
	if err != nil {
		return err
	}
	if lacks := m.Lacks(e.rng()); lacks != "" {
		e.Out.ErrorE(IDMapRefusal(name, e.rng(), lacks))
		return ErrFailed
	}
	return nil
}
