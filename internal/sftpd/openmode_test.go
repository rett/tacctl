package sftpd

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The SFTP packet types a raw client needs.
const (
	rawInit    = 1
	rawOpen    = 3
	rawClose   = 4
	rawWrite   = 6
	rawVersion = 2
	rawStatus  = 101
	rawHandle  = 102

	rawFlagRead  = 0x1
	rawFlagWrite = 0x2
	rawFlagCreat = 0x8
	rawFlagTrunc = 0x10
	rawFlagExcl  = 0x20

	rawAttrPerm = 0x4
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
	cs, ss := net.Pipe()
	r := &rawConn{t: t, c: cs, done: make(chan error, 1)}
	go func() { r.done <- serve(ss, Config{Home: home}, seams{}) }()
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
	return <-r.done
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

func permAttrs(mode uint32) []byte { return binary.BigEndian.AppendUint32(nil, mode) }

// The open request carries the mode of the new file: its permission bits,
// less the umask of the process (the console runs with 077). The attribute
// flags of the request are not delivered to the handlers by the library, so
// only a block of the permissions alone (the four bytes the OpenSSH clients
// send) is read.
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
		{"permissions with times are not read", 0o022, creatTrunc, rawAttrPerm | times, twelve, 0, 0o644},
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
