package radius

// Sightings (backend.Sighter): which devices talked to FreeRADIUS, read
// from tacctl's own linelog, tacctl-auth.log (docs/plans/operator-console.md
// 3.3). A line is
//
//	2026-10-02 14:07:40 Access-Accept scope=prod device=wti client=10.99.0.9 nas=oob-con1 reason='-' user=jdoe
//
// client= is the device, nas= the NAS-Identifier it sent (or its
// NAS-IP-Address, or '-'). The log is rotated weekly with copytruncate,
// .1 plain and older ones gzipped; the scan resumes by inode and offset:
// the same file grown is read from the offset, a file that shrank
// (copytruncate) is read on from the offset in .1 and then from the start,
// a file replaced (rotation by rename) is read on in the rotated file that
// has the old inode. The first bytes of the file are kept with the offset,
// so a file truncated and written past the old offset before the next scan
// is not taken for the same file grown. When none of that fits, every file
// is read again from the time of the last line read.

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rett/tacctl/internal/backend"
)

var _ backend.Sighter = (*Module)(nil)

const authTimeForm = "2006-01-02 15:04:05"

// ParseAuthLine is the sighting one tacctl-auth.log line records: an
// Access-Accept or Access-Reject with its time (local), client address,
// NAS-Identifier and user.
func ParseAuthLine(line string) (backend.Sighting, bool) {
	var s backend.Sighting
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 21 || line[19] != ' ' {
		return s, false
	}
	at, err := time.ParseInLocation(authTimeForm, line[:19], time.Local)
	if err != nil {
		return s, false
	}
	s.Time = at
	rest := line[20:]
	kind, _, _ := strings.Cut(rest, " ")
	switch kind {
	case "Access-Accept":
		s.Outcome = backend.SightAccept
	case "Access-Reject":
		s.Outcome = backend.SightReject
	default:
		return s, false
	}
	if _, v, ok := strings.Cut(rest, " client="); ok {
		v, _, _ = strings.Cut(v, " ")
		s.Address = backend.CanonAddr(v)
	}
	if _, v, ok := strings.Cut(rest, " nas="); ok {
		if before, _, ok := strings.Cut(v, " reason="); ok {
			v = before
		} else {
			v, _, _ = strings.Cut(v, " ")
		}
		if _, err := netip.ParseAddr(v); v != "-" && err != nil {
			s.NASID = v
		}
	}
	if i := strings.LastIndex(rest, " user="); i >= 0 {
		s.User = rest[i+len(" user="):]
	}
	return s, true
}

// authResume is where the next scan of the log starts.
type authResume struct {
	Ino uint64 `json:"ino"`
	Off int64  `json:"off"`
	// Head is the SHA-256 of the file's first HeadLen bytes.
	Head    string    `json:"head,omitempty"`
	HeadLen int       `json:"head_len,omitempty"`
	Last    time.Time `json:"last,omitzero"`
}

// headSize is how many leading bytes identify a log file.
const headSize = 256

// headOf is the hash of path's first n bytes ("" when it has fewer).
func headOf(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		return ""
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

// sameHead reports whether path starts as the file of r did.
func (r *authResume) sameHead(path string) bool {
	return r.HeadLen == 0 || headOf(path, r.HeadLen) == r.Head
}

// authReader accumulates what a scan reads.
type authReader struct {
	ss          []backend.Sighting
	first, last time.Time
	n           int
	after       time.Time // only lines after this (zero: every line)
	inclusive   bool      // ... or at it
}

func (r *authReader) line(text string) {
	s, ok := ParseAuthLine(text)
	if !ok {
		return
	}
	if !r.after.IsZero() && (s.Time.Before(r.after) || (!r.inclusive && s.Time.Equal(r.after))) {
		return
	}
	r.n++
	if r.first.IsZero() {
		r.first = s.Time
	}
	r.last = s.Time
	r.ss = append(r.ss, s)
}

// read reads path (gzipped when gz) from off; it returns the offset after
// the last complete line (a line still being written is left for later).
func (r *authReader) read(path string, off int64, gz bool) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return off, err
	}
	defer func() { _ = f.Close() }()
	var in io.Reader = f
	if gz {
		z, err := gzip.NewReader(f)
		if err != nil {
			return off, err
		}
		defer func() { _ = z.Close() }()
		in = z
	} else if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return off, err
		}
	}
	br := bufio.NewReaderSize(in, 64*1024)
	pos := off
	for {
		text, err := br.ReadString('\n')
		if err != nil {
			// A last line with no newline yet: not consumed.
			if err == io.EOF {
				return pos, nil
			}
			return pos, err
		}
		pos += int64(len(text))
		r.line(text)
	}
}

// rotated is one rotated log: its number and whether it is gzipped.
type rotated struct {
	path string
	num  int
	gz   bool
}

// rotatedLogs are path.N and path.N.gz, oldest (highest N) first.
func rotatedLogs(path string) []rotated {
	matches, _ := filepath.Glob(path + ".*")
	var out []rotated
	for _, m := range matches {
		suf := strings.TrimPrefix(m, path+".")
		gz := strings.HasSuffix(suf, ".gz")
		suf = strings.TrimSuffix(suf, ".gz")
		n, err := strconv.Atoi(suf)
		if err != nil || n < 1 {
			continue
		}
		out = append(out, rotated{path: m, num: n, gz: gz})
	}
	slices.SortFunc(out, func(a, b rotated) int { return b.num - a.num })
	return out
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// Sightings implements backend.Sighter over tacctl-auth.log and its
// rotations.
func (m *Module) Sightings(_ context.Context, since time.Time, resume string) ([]backend.Sighting, string, string, error) {
	path := m.L.AuthLog
	what := filepath.Base(path)
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, resume, what + ": no log yet", nil
		}
		return nil, resume, "", err
	}
	cur := authResume{Ino: inode(fi)}
	var prev *authResume
	if resume != "" {
		var p authResume
		if json.Unmarshal([]byte(resume), &p) == nil && p.Ino != 0 {
			prev = &p
		}
	}
	r := &authReader{}
	// rescan reads every file again, keeping lines from t on.
	rescan := func(t time.Time, inclusive bool) error {
		r.after, r.inclusive = t, inclusive
		for _, rf := range rotatedLogs(path) {
			if _, err := r.read(rf.path, 0, rf.gz); err != nil {
				return err
			}
		}
		cur.Off, err = r.read(path, 0, false)
		return err
	}
	switch {
	case prev == nil:
		err = rescan(since, true)
	case prev.Ino == cur.Ino && fi.Size() >= prev.Off && prev.sameHead(path):
		cur.Off, err = r.read(path, prev.Off, false)
	default:
		// Shrunk in place (copytruncate) or replaced (rename): the lines
		// after the offset are in the rotated file that had them.
		var from string
		for _, rf := range rotatedLogs(path) {
			if rf.num != 1 || rf.gz {
				continue
			}
			rfi, serr := os.Stat(rf.path)
			if serr != nil {
				continue
			}
			sameInode := prev.Ino != cur.Ino && inode(rfi) == prev.Ino
			copied := prev.Ino == cur.Ino && inode(rfi) != prev.Ino
			if (sameInode || copied) && rfi.Size() >= prev.Off && prev.sameHead(rf.path) {
				from = rf.path
			}
		}
		if from == "" {
			err = rescan(prev.Last, false)
			break
		}
		if _, err = r.read(from, prev.Off, false); err == nil {
			cur.Off, err = r.read(path, 0, false)
		}
	}
	if err != nil {
		return nil, resume, "", err
	}
	if size := min(cur.Off, headSize); size > 0 {
		cur.HeadLen = int(size)
		cur.Head = headOf(path, cur.HeadLen)
	}
	cur.Last = r.last
	if cur.Last.IsZero() && prev != nil {
		cur.Last = prev.Last
	}
	next, _ := json.Marshal(cur)
	return r.ss, string(next), backend.TimeWindow(what, r.first, r.last, r.n), nil
}
