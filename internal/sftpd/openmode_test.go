package sftpd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The SFTP packet types a raw client needs.
const (
	rawInit     = 1
	rawOpen     = 3
	rawClose    = 4
	rawSetstat  = 9
	rawFsetstat = 10
	rawMkdir    = 14
	rawWrite    = 6
	rawRead     = 5
	rawVersion  = 2
	rawStatus   = 101
	rawHandle   = 102

	rawFlagRead  = 0x1
	rawFlagWrite = 0x2
	rawFlagCreat = 0x8
	rawFlagTrunc = 0x10
	rawFlagExcl  = 0x20

	rawAttrSize     = 0x1
	rawAttrExtended = 0x80000000
	rawAttrPerm     = 0x4
	rawAttrTimes    = 0x8
)

// rawConn speaks SFTP by hand, so that a test can put attributes in an open
// request, which the client library never does.
type rawConn struct {
	t    *testing.T
	c    net.Conn
	done chan error
	id   uint32
}

func newRawConn(t *testing.T, home string) *rawConn {
	t.Helper()
	return newRawConnCfg(t, Config{Home: home}, seams{})
}

// newRawConnCfg is newRawConn with the whole configuration and the seams.
func newRawConnCfg(t *testing.T, cfg Config, sm seams) *rawConn {
	t.Helper()
	cs, ss := net.Pipe()
	r := &rawConn{t: t, c: cs, done: make(chan error, 1)}
	go func() { r.done <- serve(ss, cfg, sm) }()
	t.Cleanup(func() { _ = r.close() })
	r.send(rawInit, binary.BigEndian.AppendUint32(nil, 3))
	if typ, _ := r.recv(); typ != rawVersion {
		t.Fatalf("answer to init has type %d", typ)
	}
	return r
}

func (r *rawConn) close() error {
	if r.c == nil {
		return nil
	}
	_ = r.c.Close()
	r.c = nil
	select {
	case err := <-r.done:
		return err
	case <-time.After(10 * time.Second): // only if the session does not end
		return errors.New("the session did not end")
	}
}

func (r *rawConn) send(typ byte, body []byte) {
	r.t.Helper()
	b := binary.BigEndian.AppendUint32(nil, uint32(1+len(body)))
	b = append(b, typ)
	b = append(b, body...)
	if _, err := r.c.Write(b); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rawConn) recv() (byte, []byte) {
	r.t.Helper()
	var l [4]byte
	if _, err := io.ReadFull(r.c, l[:]); err != nil {
		r.t.Fatal(err)
	}
	b := make([]byte, binary.BigEndian.Uint32(l[:]))
	if _, err := io.ReadFull(r.c, b); err != nil {
		r.t.Fatal(err)
	}
	return b[0], b[1:]
}

func str(b []byte, s string) []byte {
	return append(binary.BigEndian.AppendUint32(b, uint32(len(s))), s...)
}

// request sends a packet that starts with a fresh id and returns the type and
// the body of the answer, without the id.
func (r *rawConn) request(typ byte, body []byte) (byte, []byte) {
	r.t.Helper()
	r.id++
	r.send(typ, append(binary.BigEndian.AppendUint32(nil, r.id), body...))
	t, b := r.recv()
	if got := binary.BigEndian.Uint32(b); got != r.id {
		r.t.Fatalf("answer to request %d has id %d", r.id, got)
	}
	return t, b[4:]
}

// status is the code of a status answer.
func status(t *testing.T, typ byte, b []byte) uint32 {
	t.Helper()
	if typ != rawStatus {
		t.Fatalf("answer of type %d, want a status", typ)
	}
	return binary.BigEndian.Uint32(b)
}

// open sends an open request with the open flags pflags, the attribute flags
// aflags and the attribute block attrs, and returns the handle ("" and the
// status code when it is refused).
func (r *rawConn) open(path string, pflags, aflags uint32, attrs []byte) (string, uint32) {
	r.t.Helper()
	b := str(nil, path)
	b = binary.BigEndian.AppendUint32(b, pflags)
	b = binary.BigEndian.AppendUint32(b, aflags)
	b = append(b, attrs...)
	typ, body := r.request(rawOpen, b)
	if typ == rawHandle {
		n := binary.BigEndian.Uint32(body)
		return string(body[4 : 4+n]), 0
	}
	return "", status(r.t, typ, body)
}

// finish writes data at the start of the open handle h and closes it.
func (r *rawConn) finish(h, data string) {
	r.t.Helper()
	b := str(nil, h)
	b = binary.BigEndian.AppendUint64(b, 0)
	b = str(b, data)
	typ, body := r.request(rawWrite, b)
	if c := status(r.t, typ, body); c != 0 {
		r.t.Fatalf("write: status %d", c)
	}
	typ, body = r.request(rawClose, str(nil, h))
	if c := status(r.t, typ, body); c != 0 {
		r.t.Fatalf("close: status %d", c)
	}
}

// fsetstat sends an fsetstat request for the handle h with the attribute flags
// aflags and the block attrs, and returns the status code.
func (r *rawConn) fsetstat(h string, aflags uint32, attrs []byte) uint32 {
	r.t.Helper()
	b := str(nil, h)
	b = binary.BigEndian.AppendUint32(b, aflags)
	b = append(b, attrs...)
	typ, body := r.request(rawFsetstat, b)
	return status(r.t, typ, body)
}

// closeHandle closes the handle h.
func (r *rawConn) closeHandle(h string) {
	r.t.Helper()
	typ, body := r.request(rawClose, str(nil, h))
	if c := status(r.t, typ, body); c != 0 {
		r.t.Fatalf("close: status %d", c)
	}
}

func sizeAttrs(size uint64) []byte { return binary.BigEndian.AppendUint64(nil, size) }

func permAttrs(mode uint32) []byte { return binary.BigEndian.AppendUint32(nil, mode) }

// The open request carries the mode of the new file: its permission bits,
// less the umask of the process (the console runs with 077). The library does
// not deliver the attribute flags of the request to the handlers, so the
// server rewrites the request before the library reads it (openattrs.go): the
// permissions are found whatever else the block holds.
func TestOpenModeOfTheRequest(t *testing.T) {
	const (
		creatTrunc = rawFlagWrite | rawFlagCreat | rawFlagTrunc
		times      = 8 // acmodtime attribute flag
	)
	twelve := append(permAttrs(0o755), make([]byte, 8)...) // permissions and times
	tests := []struct {
		name     string
		umask    int
		pflags   uint32
		aflags   uint32
		attrs    []byte
		existing os.FileMode // 0: the file does not exist
		want     os.FileMode
	}{
		{"0755 under the console umask", 0o077, creatTrunc, rawAttrPerm, permAttrs(0o755), 0, 0o700},
		{"0644 under the console umask", 0o077, creatTrunc, rawAttrPerm, permAttrs(0o644), 0, 0o600},
		{"0755 under umask 022", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o755), 0, 0o755},
		{"0600 under umask 022", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o600), 0, 0o600},
		{"set-user-ID is ignored", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o4755), 0, 0o755},
		{"set-group-ID is ignored", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o2755), 0, 0o755},
		{"sticky is ignored", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o1755), 0, 0o755},
		{"all special bits and the file type are ignored", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o107777), 0, 0o755},
		{"no attributes: 0644 under umask 022", 0o022, creatTrunc, 0, nil, 0, 0o644},
		{"no attributes: 0600 under the console umask", 0o077, creatTrunc, 0, nil, 0, 0o600},
		{"create and exclusive", 0o022, rawFlagWrite | rawFlagCreat | rawFlagExcl, rawAttrPerm, permAttrs(0o755), 0, 0o755},
		{"mode 0 asks for nothing: 0644 under umask 022", 0o022, creatTrunc, rawAttrPerm, permAttrs(0), 0, 0o644},
		{"mode 0 asks for nothing: 0600 under the console umask", 0o077, creatTrunc, rawAttrPerm, permAttrs(0), 0, 0o600},
		{"only file type bits ask for nothing: 0644 under umask 022", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o100000), 0, 0o644},
		{"only file type bits ask for nothing: 0600 under the console umask", 0o077, creatTrunc, rawAttrPerm, permAttrs(0o100000), 0, 0o600},
		{"all file type bits ask for nothing: 0644 under umask 022", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o170000), 0, 0o644},
		{"all file type bits ask for nothing: 0600 under the console umask", 0o077, creatTrunc, rawAttrPerm, permAttrs(0o170000), 0, 0o600},
		{"only special bits ask for nothing: 0644 under umask 022", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o7000), 0, 0o644},
		{"extended attributes without any: 0644 under umask 022", 0o022, creatTrunc, rawAttrExtended, permAttrs(0), 0, 0o644},
		{"extended attributes without any: 0600 under the console umask", 0o077, creatTrunc, rawAttrExtended, permAttrs(0), 0, 0o600},
		{"permissions with times are read: 0755 under umask 022", 0o022, creatTrunc, rawAttrPerm | times, twelve, 0, 0o755},
		{"permissions with times are read: 0755 under the console umask", 0o077, creatTrunc, rawAttrPerm | times, twelve, 0, 0o700},
		{"times alone ask for nothing: 0644 under umask 022", 0o022, creatTrunc, times, make([]byte, 8), 0, 0o644},
		{"an existing file keeps its mode", 0o022, creatTrunc, rawAttrPerm, permAttrs(0o755), 0o640, 0o640},
		{"an existing file without create keeps its mode", 0o022, rawFlagWrite, rawAttrPerm, permAttrs(0o755), 0o640, 0o640},
		{"a read-only open changes nothing", 0o022, rawFlagRead, rawAttrPerm, permAttrs(0o755), 0o640, 0o640},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old := syscall.Umask(tc.umask)
			defer syscall.Umask(old)
			home := filepath.Join(t.TempDir(), "home")
			if err := os.Mkdir(home, 0o755); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(home, "f")
			if tc.existing != 0 {
				if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, tc.existing); err != nil {
					t.Fatal(err)
				}
			}
			r := newRawConn(t, home)
			h, code := r.open("f", tc.pflags, tc.aflags, tc.attrs)
			if h == "" {
				t.Fatalf("open refused: status %d", code)
			}
			if tc.pflags&rawFlagWrite != 0 {
				r.finish(h, "new")
			} else {
				typ, body := r.request(rawClose, str(nil, h))
				if c := status(t, typ, body); c != 0 {
					t.Fatalf("close: status %d", c)
				}
			}
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode() != tc.want {
				t.Errorf("mode %v, want %v", fi.Mode(), tc.want)
			}
		})
	}
}

// A read-only open of a missing file creates nothing, whatever mode the
// request carries.
func TestOpenModeReadOnlyCreatesNothing(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	r := newRawConn(t, home)
	if h, code := r.open("f", rawFlagRead, rawAttrPerm, permAttrs(0o755)); h != "" || code != fxNoSuchFile {
		t.Errorf("open = %q, status %d, want status %d", h, code, fxNoSuchFile)
	}
	if _, err := os.Lstat(filepath.Join(home, "f")); err == nil {
		t.Error("the open created the file")
	}
}

// The mode a client asks for in a mkdir, a setstat and an open goes through
// the same mask.
func TestPermBits(t *testing.T) {
	for in, want := range map[uint32]uint32{0o755: 0o755, 0o4755: 0o755, 0o2750: 0o750, 0o1777: 0o777, 0o100644: 0o644, 0: 0} {
		if got := permBits(in); got != want {
			t.Errorf("permBits(%o) = %o, want %o", in, got, want)
		}
	}
}

// An upload of a file whose mode lacks the owner's write bit (scp without -p
// sends 0444 or 0555 for a read-only source) ends with a size step: the client
// sets the size of the handle it wrote, which the library turns into a setstat
// of the path, a truncate that needs write permission. The file must be
// writable by its owner until the handle is closed, and have the mode the
// client asked for after it.
func TestOpenModeWithoutOwnerWrite(t *testing.T) {
	const creatTrunc = rawFlagWrite | rawFlagCreat | rawFlagTrunc
	tests := []struct {
		name   string
		umask  int
		mode   uint32
		pflags uint32
		want   os.FileMode
	}{
		{"0400 under the console umask", 0o077, 0o400, creatTrunc, 0o400},
		{"0444 under the console umask", 0o077, 0o444, creatTrunc, 0o400},
		{"0500 under the console umask", 0o077, 0o500, creatTrunc, 0o500},
		{"0555 under the console umask", 0o077, 0o555, creatTrunc, 0o500},
		{"0444 under umask 022", 0o022, 0o444, creatTrunc, 0o444},
		{"0555 under umask 022", 0o022, 0o555, creatTrunc, 0o555},
		{"0444 and exclusive", 0o022, 0o444, rawFlagWrite | rawFlagCreat | rawFlagExcl, 0o444},
		{"0444 for reading and writing", 0o022, 0o444, rawFlagRead | creatTrunc, 0o444},
		{"the special bits are dropped", 0o022, 0o4444, creatTrunc, 0o444},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old := syscall.Umask(tc.umask)
			defer syscall.Umask(old)
			home := filepath.Join(t.TempDir(), "home")
			if err := os.Mkdir(home, 0o755); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(home, "f")
			r := newRawConn(t, home)
			h, code := r.open("f", tc.pflags, rawAttrPerm, permAttrs(tc.mode))
			if h == "" {
				t.Fatalf("open refused: status %d", code)
			}
			b := str(nil, h)
			b = binary.BigEndian.AppendUint64(b, 0)
			b = str(b, "newdata")
			typ, body := r.request(rawWrite, b)
			if c := status(t, typ, body); c != 0 {
				t.Fatalf("write: status %d", c)
			}
			// What scp does after the data: the size of the handle.
			if c := r.fsetstat(h, rawAttrSize, sizeAttrs(7)); c != 0 {
				t.Errorf("fsetstat of the size: status %d, want 0", c)
			}
			r.closeHandle(h)
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode() != tc.want {
				t.Errorf("mode %v, want %v", fi.Mode(), tc.want)
			}
			if fi.Size() != 7 {
				t.Errorf("size %d, want 7", fi.Size())
			}
		})
	}
}

// writeAt writes data at offset 0 of the handle h.
func (r *rawConn) writeAt(h, data string) {
	r.t.Helper()
	b := binary.BigEndian.AppendUint64(str(nil, h), 0)
	typ, body := r.request(rawWrite, str(b, data))
	if c := status(r.t, typ, body); c != 0 {
		r.t.Fatalf("write: status %d", c)
	}
}

func newHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

func modeOfFile(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode()
}

// A file that exists is not touched by an open that asks for a mode without
// the owner's write bit, with or without truncation: it keeps its mode, and
// the client's size step works on it as on any file its owner can write.
func TestOpenModeWithoutOwnerWriteExistingFile(t *testing.T) {
	for _, pflags := range []uint32{
		rawFlagWrite | rawFlagCreat | rawFlagTrunc,
		rawFlagWrite | rawFlagCreat,
		rawFlagRead | rawFlagWrite | rawFlagCreat,
	} {
		t.Run(fmt.Sprintf("pflags %#x", pflags), func(t *testing.T) {
			setUmask(t, 0o077)
			home := newHome(t)
			p := filepath.Join(home, "f")
			if err := os.WriteFile(p, []byte("old data"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0o640); err != nil {
				t.Fatal(err)
			}
			r := newRawConn(t, home)
			h, code := r.open("f", pflags, rawAttrPerm, permAttrs(0o400))
			if h == "" {
				t.Fatalf("open refused: status %d", code)
			}
			r.writeAt(h, "new")
			if c := r.fsetstat(h, rawAttrSize, sizeAttrs(3)); c != 0 {
				t.Errorf("fsetstat of the size: status %d", c)
			}
			r.closeHandle(h)
			if got := modeOfFile(t, p); got != 0o640 {
				t.Errorf("mode %v, want -rw-r-----", got)
			}
		})
	}
}

// A client that sets the permissions of the file between the data and the
// close gets what it set: the close does not put the mode of the open back.
func TestOpenModeWithoutOwnerWriteSetstatWins(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	home := newHome(t)
	p := filepath.Join(home, "f")
	r := newRawConn(t, home)
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm, permAttrs(0o400))
	if h == "" {
		t.Fatalf("open refused: status %d", code)
	}
	r.writeAt(h, "data")
	if c := r.fsetstat(h, rawAttrSize, sizeAttrs(4)); c != 0 {
		t.Fatalf("fsetstat of the size: status %d", c)
	}
	if c := r.fsetstat(h, rawAttrPerm, permAttrs(0o755)); c != 0 {
		t.Fatalf("fsetstat of the permissions: status %d", c)
	}
	r.closeHandle(h)
	if got := modeOfFile(t, p); got != 0o755 {
		t.Errorf("mode %v, want -rwxr-xr-x", got)
	}
}

// A session that ends with the handle open still gives the file the mode the
// client asked for: the library closes the handles it holds.
func TestOpenModeWithoutOwnerWriteSessionEnds(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	home := newHome(t)
	p := filepath.Join(home, "f")
	r := newRawConn(t, home)
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm, permAttrs(0o444))
	if h == "" {
		t.Fatalf("open refused: status %d", code)
	}
	r.writeAt(h, "data")
	_ = r.close() // the client leaves with the handle open
	if got := modeOfFile(t, p); got != 0o400 {
		t.Errorf("mode %v, want -r--------", got)
	}
}

// With a quota the size step of the upload is measured as always, and with an
// audit the upload is one event.
func TestOpenModeWithoutOwnerWriteQuotaAndAudit(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	home := newHome(t)
	var events []Event
	var mu sync.Mutex
	cfg := Config{Home: home, Quota: 10, Audit: func(e Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}}
	r := newRawConnCfg(t, cfg, seams{})
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm, permAttrs(0o444))
	if h == "" {
		t.Fatalf("open refused: status %d", code)
	}
	r.writeAt(h, "12345")
	if c := r.fsetstat(h, rawAttrSize, sizeAttrs(100)); c == 0 {
		t.Errorf("a size over the quota: status %d, want a refusal", c)
	}
	if c := r.fsetstat(h, rawAttrSize, sizeAttrs(5)); c != 0 {
		t.Errorf("fsetstat of the size: status %d", c)
	}
	r.closeHandle(h)
	if got := modeOfFile(t, filepath.Join(home, "f")); got != 0o400 {
		t.Errorf("mode %v, want -r--------", got)
	}
	mu.Lock()
	defer mu.Unlock()
	var up int
	for _, e := range events {
		if e.Op == "upload" {
			up++
			if e.Err != nil || e.Bytes != 5 {
				t.Errorf("upload event %+v", e)
			}
		}
	}
	if up != 1 {
		t.Errorf("%d upload events, want 1: %+v", up, events)
	}
}

// mkdir sends a mkdir request with the attribute flags aflags and the block
// attrs, and returns the status code.
func (r *rawConn) mkdir(path string, aflags uint32, attrs []byte) uint32 {
	r.t.Helper()
	b := binary.BigEndian.AppendUint32(str(nil, path), aflags)
	typ, body := r.request(rawMkdir, append(b, attrs...))
	return status(r.t, typ, body)
}

// A new directory is 0755 less the umask whatever the request asks: the library
// reads only the attribute flags of a mkdir packet (vendor/github.com/pkg/sftp,
// sshFxpMkdirPacket.UnmarshalBinary) and sets no Request.Flags for it, so the
// handler is never told the permissions. The docs say so; this test fails if a
// library upgrade starts to deliver them (and the docs and the handler are then
// to be looked at together).
func TestMkdirIgnoresTheModeOfTheRequest(t *testing.T) {
	tests := []struct {
		name  string
		umask int
		mode  uint32
		want  os.FileMode
	}{
		{"0500 under the console umask", 0o077, 0o500, 0o700},
		{"0777 under the console umask", 0o077, 0o777, 0o700},
		{"0500 under umask 022", 0o022, 0o500, 0o755},
		{"0700 under umask 022", 0o022, 0o700, 0o755},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := newHome(t)
			old := syscall.Umask(tc.umask)
			defer syscall.Umask(old)
			r := newRawConn(t, home)
			if c := r.mkdir("d", rawAttrPerm, permAttrs(tc.mode)); c != 0 {
				t.Fatalf("mkdir: status %d", c)
			}
			fi, err := os.Stat(filepath.Join(home, "d"))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode() != tc.want|os.ModeDir {
				t.Errorf("mode %v, want %v", fi.Mode(), tc.want|os.ModeDir)
			}
		})
	}
}

// What scp -p does: the open carries the permissions and the times (twelve
// bytes, read as the permissions, so the file is created 0755 less the
// umask), and after the data an fsetstat sets the same permissions and times,
// which are applied as given: the umask of the console does not reduce them.
func TestOpenModeWithTimesThenSetstat(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	home := newHome(t)
	p := filepath.Join(home, "f")
	const mtime = 1_700_000_000
	times := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, mtime), mtime)
	r := newRawConn(t, home)
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm|rawAttrTimes, append(permAttrs(0o755), times...))
	if h == "" {
		t.Fatalf("open refused: status %d", code)
	}
	if got := modeOfFile(t, p); got != 0o700 {
		t.Errorf("mode after the open %v, want -rwx------", got)
	}
	r.writeAt(h, "#!/bin/sh\n")
	if c := r.fsetstat(h, rawAttrPerm|rawAttrTimes, append(permAttrs(0o755), times...)); c != 0 {
		t.Fatalf("fsetstat: status %d", c)
	}
	r.closeHandle(h)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != 0o755 {
		t.Errorf("mode %v, want -rwxr-xr-x", fi.Mode())
	}
	if fi.ModTime().Unix() != mtime {
		t.Errorf("mtime %d, want %d", fi.ModTime().Unix(), mtime)
	}
}

// setUmask sets the umask of the process for the test and puts it back when
// the test ends, whatever way it ends.
func setUmask(t *testing.T, m int) {
	t.Helper()
	old := syscall.Umask(m)
	t.Cleanup(func() { syscall.Umask(old) })
}

// A client that asks for O_EXCL on a name that exists is told so, as it is for
// any file, and the file is not touched, whatever mode the request asks.
func TestOpenModeWithoutOwnerWriteExclOnExistingFile(t *testing.T) {
	setUmask(t, 0o022)
	home := newHome(t)
	p := filepath.Join(home, "f")
	if err := os.WriteFile(p, []byte("old data"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	r := newRawConn(t, home)
	const pflags = rawFlagWrite | rawFlagCreat | rawFlagExcl
	_, want := r.open("f", pflags, 0, nil)
	if want == 0 {
		t.Fatal("an exclusive create of an existing file succeeded")
	}
	for _, mode := range []uint32{0o400, 0o444} {
		if h, code := r.open("f", pflags, rawAttrPerm, permAttrs(mode)); h != "" || code != want {
			t.Errorf("mode %o: open = %q, status %d, want status %d", mode, h, code, want)
		}
	}
	if got := modeOfFile(t, p); got != 0o640 {
		t.Errorf("mode %v, want -rw-r-----", got)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "old data" {
		t.Errorf("content %q, %v; want the old data", b, err)
	}
}

// An error after the file was created, before the handle is given out (here a
// file that gained a second name between the open and the check), leaves the
// file with the mode the client asked for, not with the owner's write bit the
// open added. The other such errors (the descriptor that cannot be made
// blocking, the truncation that fails) share the code and cannot be provoked
// from a test.
func TestOpenModeWithoutOwnerWriteFailedOpenRestoresTheMode(t *testing.T) {
	setUmask(t, 0o022)
	home := newHome(t)
	p := filepath.Join(home, "f")
	var once sync.Once
	var linkErr error
	r := newRawConnCfg(t, Config{Home: home}, seams{afterOpen: func() {
		once.Do(func() { linkErr = os.Link(p, filepath.Join(home, "g")) })
	}})
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm, permAttrs(0o444))
	if linkErr != nil {
		t.Fatal(linkErr)
	}
	if h != "" || code != fxPermissionDenied {
		t.Fatalf("open = %q, status %d, want status %d", h, code, fxPermissionDenied)
	}
	if got := modeOfFile(t, p); got != 0o444 {
		t.Errorf("mode %v, want -r--r--r--", got)
	}
}

// A change of the permissions made outside the handle (another session, the
// user's shell) between the data and the close is kept: the close puts the mode
// asked for back only on a file that still has the mode the open gave it.
func TestOpenModeWithoutOwnerWriteChmodElsewhereWins(t *testing.T) {
	setUmask(t, 0o077)
	home := newHome(t)
	p := filepath.Join(home, "f")
	r := newRawConn(t, home)
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm, permAttrs(0o444))
	if h == "" {
		t.Fatalf("open refused: status %d", code)
	}
	r.writeAt(h, "data")
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	r.closeHandle(h)
	if got := modeOfFile(t, p); got != 0o640 {
		t.Errorf("mode %v, want -rw-r-----", got)
	}
}

// A name that is a directory, a symbolic link or a FIFO is refused with a
// mode without the owner's write bit exactly as with any other mode, and what
// is at the name is not changed.
func TestOpenModeWithoutOwnerWriteNotARegularFile(t *testing.T) {
	setUmask(t, 0o022)
	tests := []struct {
		name  string
		make  func(t *testing.T, home string)
		check func(t *testing.T, p string)
	}{
		{"directory", func(t *testing.T, home string) {
			if err := os.Mkdir(filepath.Join(home, "f"), 0o750); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, p string) {
			if got := modeOfFile(t, p); got != 0o750|os.ModeDir {
				t.Errorf("mode %v, want drwxr-x---", got)
			}
		}},
		{"symbolic link", func(t *testing.T, home string) {
			if err := os.WriteFile(filepath.Join(home, "target"), []byte("old"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(home, "target"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("target", filepath.Join(home, "f")); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, p string) {
			if got := modeOfFile(t, filepath.Join(filepath.Dir(p), "target")); got != 0o640 {
				t.Errorf("mode of the target %v, want -rw-r-----", got)
			}
			if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("the link is gone or changed: %v, %v", fi, err)
			}
		}},
		{"FIFO", func(t *testing.T, home string) {
			if err := syscall.Mkfifo(filepath.Join(home, "f"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(home, "f"), 0o640); err != nil {
				t.Fatal(err)
			}
		}, func(t *testing.T, p string) {
			if got := modeOfFile(t, p); got != 0o640|os.ModeNamedPipe {
				t.Errorf("mode %v, want prw-r-----", got)
			}
		}},
	}
	for _, tc := range tests {
		for _, pflags := range []uint32{rawFlagWrite | rawFlagCreat | rawFlagTrunc, rawFlagRead | rawFlagWrite | rawFlagCreat} {
			t.Run(fmt.Sprintf("%s %#x", tc.name, pflags), func(t *testing.T) {
				home := newHome(t)
				tc.make(t, home)
				r := newRawConn(t, home)
				_, want := r.open("f", pflags, 0, nil) // the answer without a mode in the request
				if want == 0 {
					t.Fatal("the open without a mode succeeded")
				}
				for _, mode := range []uint32{0o400, 0o444} {
					if h, code := r.open("f", pflags, rawAttrPerm, permAttrs(mode)); h != "" || code != want {
						t.Errorf("mode %o: open = %q, status %d, want status %d", mode, h, code, want)
					}
				}
				tc.check(t, filepath.Join(home, "f"))
			})
		}
	}
}

// A umask that clears the owner's write bit leaves the new file as the kernel
// made it: the file is created, and the close changes nothing.
func TestOpenModeWithoutOwnerWriteUmaskClearsOwnerWrite(t *testing.T) {
	home := newHome(t) // before the umask: the test's directories need the owner's write bit
	setUmask(t, 0o277)
	p := filepath.Join(home, "f")
	r := newRawConn(t, home)
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm, permAttrs(0o444))
	if h == "" {
		t.Fatalf("open refused: status %d", code)
	}
	if got := modeOfFile(t, p); got != 0o400 {
		t.Errorf("mode after the open %v, want -r--------", got)
	}
	r.writeAt(h, "data")
	r.closeHandle(h)
	if got := modeOfFile(t, p); got != 0o400 {
		t.Errorf("mode after the close %v, want -r--------", got)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "data" {
		t.Errorf("content %q, %v; want data", b, err)
	}
}

// An fsetstat of the times alone does not say anything about the permissions:
// the close still gives the mode asked for.
func TestOpenModeWithoutOwnerWriteTimesOnlyKeepsTheRestore(t *testing.T) {
	setUmask(t, 0o022)
	home := newHome(t)
	p := filepath.Join(home, "f")
	const mtime = 1_700_000_000
	times := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, mtime), mtime)
	r := newRawConn(t, home)
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm, permAttrs(0o444))
	if h == "" {
		t.Fatalf("open refused: status %d", code)
	}
	r.writeAt(h, "data")
	if c := r.fsetstat(h, rawAttrTimes, times); c != 0 {
		t.Fatalf("fsetstat of the times: status %d", c)
	}
	r.closeHandle(h)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode() != 0o444 {
		t.Errorf("mode %v, want -r--r--r--", fi.Mode())
	}
	if fi.ModTime().Unix() != mtime {
		t.Errorf("mtime %d, want %d", fi.ModTime().Unix(), mtime)
	}
}

// The mode is given to the descriptor, not to the name: a file renamed before
// the close gets it, and nothing is left at the old name.
func TestOpenModeWithoutOwnerWriteRenamedBeforeClose(t *testing.T) {
	setUmask(t, 0o022)
	home := newHome(t)
	p, moved := filepath.Join(home, "f"), filepath.Join(home, "g")
	r := newRawConn(t, home)
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm, permAttrs(0o444))
	if h == "" {
		t.Fatalf("open refused: status %d", code)
	}
	r.writeAt(h, "data")
	if err := os.Rename(p, moved); err != nil {
		t.Fatal(err)
	}
	r.closeHandle(h)
	if got := modeOfFile(t, moved); got != 0o444 {
		t.Errorf("mode of the renamed file %v, want -r--r--r--", got)
	}
	if _, err := os.Lstat(p); err == nil {
		t.Error("a file is at the old name")
	}
}
