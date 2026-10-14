package devrollout

// The shape store (D135, D138): '<dir>/shapes.json', 0600, a map from a
// shape's hash to its masked lines, the algorithm that made them and the
// devices that confirmed it. It holds no secret (the lines are plan.Shape's:
// values elided, per-device values masked) and no device output.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// ShapesFile is the store's file name in its directory.
const ShapesFile = "shapes.json"

// Confirmation is one device's proof of a shape: an applied rollout, or a
// person's word (Seeded).
type Confirmation struct {
	Device string    `json:"device"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`
	ID     string    `json:"id,omitempty"`
	Seeded bool      `json:"seeded,omitempty"`
}

// ShapeEntry is one shape of the store.
type ShapeEntry struct {
	Algo      int            `json:"algo"`
	Lines     []string       `json:"lines"`
	Confirmed []Confirmation `json:"confirmed"`
}

// Shapes is the store in one directory. Each write takes the store's lock
// ('<dir>/shapes.lock') and replaces the file atomically.
type Shapes struct {
	dir string
}

// OpenShapes is the store in dir (created 0700 at the first write).
func OpenShapes(dir string) *Shapes { return &Shapes{dir: dir} }

// Load reads the store; a missing file is an empty store. A shape filed
// under an older algorithm is re-filed from its lines (plan.ShapeHash).
func (s *Shapes) Load() (map[string]ShapeEntry, error) {
	b, err := os.ReadFile(filepath.Join(s.dir, ShapesFile))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]ShapeEntry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var m map[string]ShapeEntry
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("devrollout: %s: %w", ShapesFile, err)
	}
	if m == nil {
		m = map[string]ShapeEntry{}
	}
	out := map[string]ShapeEntry{}
	for h, e := range m {
		if e.Algo != plan.ShapeAlgo {
			h = plan.ShapeHash(e.Lines)
			e.Algo = plan.ShapeAlgo
		}
		if prev, ok := out[h]; ok {
			e.Confirmed = append(prev.Confirmed, e.Confirmed...)
		}
		out[h] = e
	}
	return out, nil
}

// Confirmed reports whether a shape has been confirmed by any device.
func (s *Shapes) Confirmed(hash string) (bool, error) {
	m, err := s.Load()
	if err != nil {
		return false, err
	}
	e, ok := m[hash]
	return ok && len(e.Confirmed) > 0, nil
}

// Confirm files the shape with the device's confirmation. The hash must be
// the lines' (a store never files lines under another shape's name).
func (s *Shapes) Confirm(hash string, lines []string, c Confirmation) error {
	if hash == "" || plan.ShapeHash(lines) != hash {
		return fmt.Errorf("devrollout: the shape's lines do not hash to %q", hash)
	}
	if c.Device == "" {
		return errors.New("devrollout: a confirmation names a device")
	}
	return s.update(func(m map[string]ShapeEntry) {
		e := m[hash]
		e.Algo, e.Lines = plan.ShapeAlgo, slices.Clone(lines)
		e.Confirmed = append(e.Confirmed, c)
		sort.SliceStable(e.Confirmed, func(i, j int) bool { return e.Confirmed[i].At.Before(e.Confirmed[j].At) })
		m[hash] = e
	})
}

// update applies fn to the store under its lock and writes it back.
func (s *Shapes) update(fn func(map[string]ShapeEntry)) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	lf, err := os.OpenFile(filepath.Join(s.dir, "shapes.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = lf.Close() }()
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(lf.Fd()), unix.LOCK_UN) }()
	m, err := s.Load()
	if err != nil {
		return err
	}
	fn(m)
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".shapes-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(s.dir, ShapesFile))
}
