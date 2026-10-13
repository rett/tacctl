package utmp

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func record(typ uint16, line, host string) []byte {
	rec := make([]byte, recordSize)
	binary.LittleEndian.PutUint16(rec[offType:], typ)
	copy(rec[offLine:offLine+lenLine], line)
	copy(rec[offHost:offHost+lenHost], host)
	return rec
}

func TestRemoteFindsTheNewestUserProcessOnTheLine(t *testing.T) {
	var data []byte
	data = append(data, record(userProcess, "pts/1", "192.0.2.10")...)
	data = append(data, record(8, "pts/3", "dead-record")...) // DEAD_PROCESS: not a login
	data = append(data, record(userProcess, "pts/3", "198.51.100.7")...)
	data = append(data, record(userProcess, "pts/3", "203.0.113.9")...)
	data = append(data, record(userProcess, "tty1", "")...)
	p := filepath.Join(t.TempDir(), "utmp")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	for line, want := range map[string]string{
		"pts/3": "203.0.113.9", "pts/1": "192.0.2.10", "tty1": "", "pts/9": "", "": "",
	} {
		if got := remote(p, line); got != want {
			t.Errorf("remote(%q) = %q, want %q", line, got, want)
		}
	}
	if got := remote(filepath.Join(t.TempDir(), "missing"), "pts/1"); got != "" {
		t.Errorf("missing file: %q", got)
	}
}

func TestRemoteIgnoresATruncatedRecord(t *testing.T) {
	p := filepath.Join(t.TempDir(), "utmp")
	if err := os.WriteFile(p, record(userProcess, "pts/1", "192.0.2.1")[:recordSize-1], 0o644); err != nil {
		t.Fatal(err)
	}
	if got := remote(p, "pts/1"); got != "" {
		t.Errorf("got %q", got)
	}
}
