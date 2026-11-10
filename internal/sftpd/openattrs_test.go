package sftpd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"
)

// openPacket is an open request, whole with its length, as a client sends it.
func openPacket(id uint32, path string, pflags, aflags uint32, attrs []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, id)
	b = str(b, path)
	b = binary.BigEndian.AppendUint32(b, pflags)
	b = binary.BigEndian.AppendUint32(b, aflags)
	b = append(b, attrs...)
	return frame(rawOpen, b)
}

// writePacket is a write request of n bytes of data.
func writePacket(id uint32, n int) []byte {
	b := binary.BigEndian.AppendUint32(nil, id)
	b = str(b, "h")
	b = binary.BigEndian.AppendUint64(b, 0)
	b = str(b, string(bytes.Repeat([]byte{'x'}, n)))
	return frame(rawWrite, b)
}

func u32(v ...uint32) []byte {
	var b []byte
	for _, x := range v {
		b = binary.BigEndian.AppendUint32(b, x)
	}
	return b
}

// What the library is given for an open: the attribute flags the client sent
// are read where they are known, and the block is the permissions alone or
// nothing.
func TestRewriteOpen(t *testing.T) {
	const mtime = 1_700_000_000
	times := u32(mtime, mtime)
	size := binary.BigEndian.AppendUint64(nil, 0x1ED_00000000) // its high word reads as 0755
	owner := binary.BigEndian.AppendUint64(nil, 0x1ED_00000000)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	tests := []struct {
		name   string
		aflags uint32
		attrs  []byte
		want   []byte // the block the library gets; nil with the flags 0
	}{
		{"no attributes", 0, nil, nil},
		{"permissions alone", rawAttrPerm, u32(0o755), u32(0o755)},
		{"permissions with times", rawAttrPerm | rawAttrTimes, cat(u32(0o755), times), u32(0o755)},
		{"size with permissions", openAttrSize | rawAttrPerm, cat(size, u32(0o600)), u32(0o600)},
		{"owner with permissions", openAttrUIDGID | rawAttrPerm, cat(owner, u32(0o640)), u32(0o640)},
		{"size, owner, permissions and times", openAttrSize | openAttrUIDGID | rawAttrPerm | rawAttrTimes, cat(size, owner, u32(0o750), times), u32(0o750)},
		{"permissions with no extended attributes", rawAttrPerm | rawAttrExtended, u32(0o755, 0), u32(0o755)},
		{"times alone", rawAttrTimes, times, nil},
		{"size alone", openAttrSize, size, nil},
		{"extended attributes alone", rawAttrExtended, u32(0), nil},
		{"permissions flag, block too short", rawAttrPerm, []byte{0, 0, 1}, nil},
		{"size and permissions flags, block holds the size only", openAttrSize | rawAttrPerm, size, nil},
		{"bytes without a flag", 0, u32(0o755), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := openPacket(7, "f", rawFlagWrite|rawFlagCreat, tc.aflags, tc.attrs)
			var wantFlags uint32
			if tc.want != nil {
				wantFlags = rawAttrPerm
			}
			want := openPacket(7, "f", rawFlagWrite|rawFlagCreat, wantFlags, tc.want)
			got := readAll(t, newOpenFilter(bytes.NewReader(in)))
			if !bytes.Equal(got, want) {
				t.Errorf("rewritten to %x, want %x", got, want)
			}
		})
	}
}

func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A stream of packets comes out with the open rewritten and every other packet
// as it was, however the reader asks for it (a byte at a time, in the sizes of
// the library, in one go), and a zero length packet and a long open are passed
// on for the library to judge.
func TestOpenFilterStream(t *testing.T) {
	times := u32(1, 2)
	long := openPacket(9, string(bytes.Repeat([]byte{'p'}, maxOpenPacket)), rawFlagWrite, rawAttrPerm|rawAttrTimes, append(u32(0o755), times...))
	var in, want []byte
	add := func(inp, wantp []byte) { in, want = append(in, inp...), append(want, wantp...) }
	init := frame(rawInit, u32(3))
	add(init, init)
	w1 := writePacket(2, 30000)
	add(w1, w1)
	add(openPacket(3, "a", rawFlagWrite|rawFlagCreat, rawAttrPerm|rawAttrTimes, append(u32(0o755), times...)),
		openPacket(3, "a", rawFlagWrite|rawFlagCreat, rawAttrPerm, u32(0o755)))
	add([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 0})
	add(long, long) // too long to be an open: as it came
	add(openPacket(4, "b", rawFlagRead, 0, nil), openPacket(4, "b", rawFlagRead, 0, nil))
	add(writePacket(5, 1), writePacket(5, 1))
	for name, wrap := range map[string]func(io.Reader) io.Reader{
		"whole":    func(r io.Reader) io.Reader { return r },
		"one byte": iotest.OneByteReader,
		"half":     iotest.HalfReader,
		"data err": iotest.DataErrReader,
	} {
		t.Run(name, func(t *testing.T) {
			got := readAll(t, newOpenFilter(wrap(bytes.NewReader(in))))
			if !bytes.Equal(got, want) {
				t.Errorf("the stream differs: %d bytes, want %d", len(got), len(want))
			}
		})
	}
}

// A stream that ends inside a packet gives the bytes that came, then the
// error, at every cut of an open and of a write.
func TestOpenFilterTruncated(t *testing.T) {
	for _, pkt := range [][]byte{
		openPacket(3, "a", rawFlagWrite|rawFlagCreat, rawAttrPerm|rawAttrTimes, append(u32(0o755), u32(1, 2)...)),
		writePacket(2, 20),
	} {
		for cut := 1; cut < len(pkt); cut++ {
			got, err := io.ReadAll(newOpenFilter(bytes.NewReader(pkt[:cut])))
			// io.ReadAll hides a plain end of stream: the library meets
			// the same end where it expects the rest of the packet.
			if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("cut at %d: error %v", cut, err)
			}
			if !bytes.Equal(got, pkt[:cut]) {
				t.Fatalf("cut at %d: got %x, want the bytes that came, %x", cut, got, pkt[:cut])
			}
		}
	}
	if got, err := io.ReadAll(newOpenFilter(bytes.NewReader(nil))); err != nil || len(got) != 0 {
		t.Errorf("an empty stream: %x, %v", got, err)
	}
}

// The session: the file is created with the permission bits of the open
// whatever else the block holds (what the scp of OpenSSH 9 sends with -p is
// the permissions and the times), and a block that holds no permissions gives
// the default, so a size is never read as a mode.
func TestOpenModeBlocksOfTheOpenRequest(t *testing.T) {
	const creat = rawFlagWrite | rawFlagCreat | rawFlagTrunc
	times := u32(1_700_000_000, 1_700_000_000)
	size := binary.BigEndian.AppendUint64(nil, 0x1ED_00000000) // its high word reads as 0755
	owner := binary.BigEndian.AppendUint64(nil, 0)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	tests := []struct {
		name   string
		aflags uint32
		attrs  []byte
		want   os.FileMode // under umask 022
	}{
		{"permissions with times, twelve bytes", rawAttrPerm | rawAttrTimes, cat(u32(0o755), times), 0o755},
		{"size with permissions, twelve bytes, is not permissions with times", openAttrSize | rawAttrPerm, cat(size, u32(0o600)), 0o600},
		{"owner with permissions, twelve bytes", openAttrUIDGID | rawAttrPerm, cat(owner, u32(0o750)), 0o750},
		{"everything", openAttrSize | openAttrUIDGID | rawAttrPerm | rawAttrTimes, cat(size, owner, u32(0o700), times), 0o700},
		{"permissions with extended attributes", rawAttrPerm | rawAttrExtended, u32(0o755, 0), 0o755},
		{"size alone, eight bytes", openAttrSize, size, 0o644},
		{"times alone, eight bytes", rawAttrTimes, times, 0o644},
		{"bytes the flags do not announce", 0, cat(u32(0o755), times), 0o644},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setUmask(t, 0o022)
			home := newHome(t)
			r := newRawConn(t, home)
			h, code := r.open("f", creat, tc.aflags, tc.attrs)
			if h == "" {
				t.Fatalf("open refused: status %d", code)
			}
			if got := modeOfFile(t, filepath.Join(home, "f")); got != tc.want {
				t.Errorf("mode after the open %v, want %v", got, tc.want)
			}
			r.finish(h, "data")
		})
	}
}

// The requests that follow a rewritten open are read where they begin: a long
// upload after an open with times goes through, byte for byte.
func TestOpenModeWithTimesThenData(t *testing.T) {
	setUmask(t, 0o077)
	home := newHome(t)
	r := newRawConn(t, home)
	h, code := r.open("f", rawFlagWrite|rawFlagCreat|rawFlagTrunc, rawAttrPerm|rawAttrTimes, append(u32(0o755), u32(1, 2)...))
	if h == "" {
		t.Fatalf("open refused: status %d", code)
	}
	data := string(bytes.Repeat([]byte("0123456789"), 3000))
	r.finish(h, data)
	b, err := os.ReadFile(filepath.Join(home, "f"))
	if err != nil || string(b) != data {
		t.Errorf("content: %d bytes, %v, want %d", len(b), err, len(data))
	}
}
