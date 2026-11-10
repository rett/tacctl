package sftpd

import (
	"bufio"
	"encoding/binary"
	"io"
)

// The library hands a handler the attribute block of an open request as raw
// bytes and drops the attribute flags that say which fields it holds, so a
// block of twelve bytes could be the permissions with the times (what the
// OpenSSH scp sends with -p) or a size with the permissions, and a block of
// four bytes could be the permissions or the count of the extended attributes
// of a version 3 block that holds nothing else. The open is therefore
// rewritten on its way in, before the library reads it: the attribute flags
// are read here, where they are known, and the block the library gets is the
// permissions alone (four bytes, the flag of the permissions) or nothing (no
// flags, no bytes). openMode reads that.
//
// Only the open request is touched, the bytes of every other packet go through
// as they came, and an open that is not well formed is passed on as it is,
// which openMode reads as asking for nothing: the new file gets the default
// mode, the safe side. So is an open too long to be read whole (maxOpenPacket:
// its path is longer than the file system takes, and the open fails).
const (
	sshFxpOpen = 3 // the type of an open request

	// maxOpenPacket is the longest open request that is read whole to be
	// rewritten: a path (at most a few thousand bytes), the flags and a
	// block of attributes are far below it. A longer one cannot be a real
	// open and is passed through.
	maxOpenPacket = 64 * 1024

	openAttrSize   = 0x1 // the size field (8 bytes)
	openAttrUIDGID = 0x2 // the owner and group (8 bytes)
	openAttrPerm   = 0x4 // the permissions (4 bytes)
)

// openFilter is the reader the library reads the client's packets from. It
// frames the stream (a packet is a four byte length, a type byte and the
// rest), keeps the bytes of every packet but an open as they came and
// rewrites the attribute block of an open.
type openFilter struct {
	r       *bufio.Reader
	out     []byte // bytes ready to be read: a header, or a rewritten packet
	passing int    // bytes of the current packet still to be passed through
	err     error  // the error that ends the stream, given once out is read
}

func newOpenFilter(r io.Reader) *openFilter {
	return &openFilter{r: bufio.NewReaderSize(r, 4096)}
}

func (f *openFilter) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(f.out) == 0 {
		if f.err != nil {
			return 0, f.err
		}
		if f.passing > 0 {
			n, err := f.r.Read(p[:min(len(p), f.passing)])
			f.passing -= n
			if err != nil {
				f.err = err
			}
			if n > 0 {
				return n, nil
			}
			continue
		}
		f.next()
	}
	n := copy(p, f.out)
	f.out = f.out[n:]
	return n, nil
}

// next reads the header of the next packet and, for an open request, the
// whole packet; it sets out and passing. A failure of the stream is kept in
// err, to be given after the bytes read so far.
func (f *openFilter) next() {
	var hdr [5]byte
	n, err := io.ReadFull(f.r, hdr[:4])
	if err != nil {
		f.out, f.err = hdr[:n], err
		return
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	if length == 0 {
		f.out = hdr[:4] // the library refuses it
		return
	}
	n, err = io.ReadFull(f.r, hdr[4:5])
	if err != nil {
		f.out, f.err = hdr[:4+n], err
		return
	}
	if hdr[4] != sshFxpOpen || length > maxOpenPacket {
		f.out, f.passing = hdr[:], int(length)-1
		return
	}
	body := make([]byte, length-1)
	n, err = io.ReadFull(f.r, body)
	if err != nil {
		// A stream that ends inside the open: what came goes on as it is.
		f.out, f.err = append(hdr[:], body[:n]...), err
		return
	}
	f.out = rewriteOpen(hdr[4], body)
}

// rewriteOpen returns the open request of type typ and body (the bytes after
// the type), whole with its length, with its attribute block cut down to the
// permissions, or to nothing when the request carries none. A request that is
// too short to hold the open flags and the attribute flags is returned as it
// is.
func rewriteOpen(typ byte, body []byte) []byte {
	// The id, the path (a length and its bytes), the open flags, then the
	// attribute flags.
	if len(body) < 8 {
		return frame(typ, body)
	}
	pathLen := uint64(binary.BigEndian.Uint32(body[4:]))
	end := 8 + pathLen + 4 // the end of the open flags
	if uint64(len(body)) < end+4 {
		return frame(typ, body)
	}
	aflags := binary.BigEndian.Uint32(body[end:])
	attrs := body[end+4:]

	// The fields come in the order of the flags: size, owner and group,
	// permissions, times, extended attributes. Only what precedes the
	// permissions has to be skipped.
	skip := 0
	if aflags&openAttrSize != 0 {
		skip += 8
	}
	if aflags&openAttrUIDGID != 0 {
		skip += 8
	}
	out := append([]byte(nil), body[:end]...)
	if aflags&openAttrPerm != 0 && len(attrs) >= skip+4 {
		out = binary.BigEndian.AppendUint32(out, openAttrPerm)
		out = append(out, attrs[skip:skip+4]...)
	} else {
		out = binary.BigEndian.AppendUint32(out, 0)
	}
	return frame(typ, out)
}

// frame is a packet of the type typ and the content body, with its length.
func frame(typ byte, body []byte) []byte {
	b := binary.BigEndian.AppendUint32(make([]byte, 0, 5+len(body)), uint32(1+len(body)))
	b = append(b, typ)
	return append(b, body...)
}
