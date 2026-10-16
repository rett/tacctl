// Package utmp reads the login records of /var/run/utmp for one terminal:
// the host a login on that terminal came from, as sshd recorded it. tacctl
// uses it to name the client of a session in its audit lines, because sudo
// drops SSH_CONNECTION on the way to root.
package utmp

import (
	"bytes"
	"encoding/binary"
	"os"
)

// DefaultFile is the login-records file of a Linux system.
const DefaultFile = "/var/run/utmp"

// The struct utmp of glibc, 384 bytes on every 64-bit Linux ABI.
const (
	recordSize  = 384
	offType     = 0
	offLine     = 8
	lenLine     = 32
	offHost     = 76
	lenHost     = 256
	userProcess = 7
)

// Remote is the host field of the newest login record on terminal line
// ("pts/3": the device name without /dev/) in file ("" is DefaultFile), ""
// when there is none or the file cannot be read. For an ssh login it is the
// client's address, or its name when sshd resolves names.
func Remote(file, line string) string {
	if file == "" {
		file = DefaultFile
	}
	return remote(file, line)
}

func remote(path, line string) string {
	if line == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	host := ""
	for off := 0; off+recordSize <= len(data); off += recordSize {
		rec := data[off : off+recordSize]
		if binary.LittleEndian.Uint16(rec[offType:]) != userProcess {
			continue
		}
		if cstring(rec[offLine:offLine+lenLine]) != line {
			continue
		}
		host = cstring(rec[offHost : offHost+lenHost])
	}
	return host
}

func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
