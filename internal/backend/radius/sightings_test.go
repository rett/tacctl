package radius

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/paths"
)

func TestParseAuthLine(t *testing.T) {
	for _, c := range []struct {
		line                         string
		ok                           bool
		addr, nas, user, outcome, at string
	}{
		{"2026-10-02 14:07:40 Access-Accept scope=prod device=wti client=203.0.113.9 nas=oob-con1 reason='-' user=jdoe",
			true, "203.0.113.9", "oob-con1", "jdoe", backend.SightAccept, "2026-10-02 14:07:40"},
		{"2026-10-02 14:07:41 Access-Reject scope=prod device=generic client=203.0.113.9 nas=oob con 1 reason='Invalid password for x' user=jdoe",
			true, "203.0.113.9", "oob con 1", "jdoe", backend.SightReject, "2026-10-02 14:07:41"},
		{"2026-10-02 14:07:42 Access-Accept scope=lab device=generic client=2001:DB8::7 nas=- reason='-' user=a b",
			true, "2001:db8::7", "", "a b", backend.SightAccept, "2026-10-02 14:07:42"},
		// A NAS-IP-Address standing in for the identifier is no name.
		{"2026-10-02 14:07:43 Access-Accept scope=lab device=generic client=198.51.100.2 nas=198.51.100.2 reason='-' user=x",
			true, "198.51.100.2", "", "x", backend.SightAccept, "2026-10-02 14:07:43"},
		{"2026-10-02 14:07:44 Access-Accept scope=lab device=generic client= nas=- reason='-' user=x",
			true, "", "", "x", backend.SightAccept, "2026-10-02 14:07:44"},
		{"2026-10-02 14:07:45  scope=lab device=generic client=198.51.100.2 nas=- reason='-' user=x", false, "", "", "", "", ""},
		{"2026-10-02 14:07:46 Access-Challenge client=198.51.100.2", false, "", "", "", "", ""},
		{"garbage", false, "", "", "", "", ""},
		{"2026-13-02 14:07:46 Access-Accept client=198.51.100.2 user=x", false, "", "", "", "", ""},
	} {
		s, ok := ParseAuthLine(c.line + "\n")
		if ok != c.ok {
			t.Errorf("%q: ok %v", c.line, ok)
			continue
		}
		if ok && (s.Address != c.addr || s.NASID != c.nas || s.User != c.user || s.Outcome != c.outcome || s.Time.Format(authTimeForm) != c.at) {
			t.Errorf("%q: %+v", c.line, s)
		}
	}
}

// authLog is a module whose auth log is <dir>/tacctl-auth.log.
func authLog(t *testing.T) (*Module, string) {
	t.Helper()
	dir := t.TempDir()
	return &Module{L: paths.RadiusPaths{AuthLog: filepath.Join(dir, "tacctl-auth.log")}}, filepath.Join(dir, "tacctl-auth.log")
}

func line(at, client, nas, user string) string {
	return at + " Access-Accept scope=lab device=generic client=" + client + " nas=" + nas + " reason='-' user=" + user + "\n"
}

func write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
}

func appendTo(t *testing.T, path, data string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}
}

func users(ss []backend.Sighting) string {
	var u []string
	for _, s := range ss {
		u = append(u, s.User)
	}
	return strings.Join(u, ",")
}

func TestSightingsAuthLogRotationsAndResume(t *testing.T) {
	m, path := authLog(t)
	ctx := t.Context()
	ss, next, window, err := m.Sightings(ctx, time.Time{}, "")
	if err != nil || ss != nil || next != "" || window != "tacctl-auth.log: no log yet" {
		t.Fatalf("no log: %v %q %q %v", ss, next, window, err)
	}

	// The rotated files are read oldest first: .3.gz, .2.gz, .1, then the log.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(line("2026-09-01 10:00:00", "203.0.113.1", "a", "u3")))
	_ = zw.Close()
	if err := os.WriteFile(path+".3.gz", gz.Bytes(), 0o640); err != nil {
		t.Fatal(err)
	}
	gz.Reset()
	zw = gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(line("2026-09-08 10:00:00", "203.0.113.1", "a", "u2")))
	_ = zw.Close()
	if err := os.WriteFile(path+".2.gz", gz.Bytes(), 0o640); err != nil {
		t.Fatal(err)
	}
	write(t, path+".1", line("2026-09-15 10:00:00", "203.0.113.1", "a", "u1"))
	write(t, path+".old", line("2026-09-15 10:00:00", "203.0.113.1", "a", "ignored"))
	write(t, path, line("2026-09-22 10:00:00", "203.0.113.1", "a", "u0")+"partial line wi")
	ss, next, window, err = m.Sightings(ctx, time.Time{}, "")
	if err != nil || users(ss) != "u3,u2,u1,u0" {
		t.Fatalf("full: %q %v", users(ss), err)
	}
	if window != "tacctl-auth.log 2026-09-01 10:00:00 to 2026-09-22 10:00:00 (4 entries)" {
		t.Errorf("window %q", window)
	}
	// since: only the lines at or after it.
	since, _ := time.ParseInLocation(authTimeForm, "2026-09-15 10:00:00", time.Local)
	if ss, _, _, _ := m.Sightings(ctx, since, ""); users(ss) != "u1,u0" {
		t.Errorf("since: %q", users(ss))
	}

	// Resume: the line being written when the scan ran is read once done.
	appendTo(t, path, "th no newline\n"+line("2026-09-22 11:00:00", "203.0.113.2", "b", "n1"))
	ss, next, _, err = m.Sightings(ctx, time.Time{}, next)
	if err != nil || users(ss) != "n1" {
		t.Fatalf("resume: %q %v", users(ss), err)
	}
	ss, next, window, _ = m.Sightings(ctx, time.Time{}, next)
	if len(ss) != 0 || window != "tacctl-auth.log: no new entries" {
		t.Errorf("nothing new: %v %q", ss, window)
	}

	// copytruncate: the log is copied to .1 (with a line the last scan did
	// not see), truncated, and written on.
	appendTo(t, path, line("2026-09-22 12:00:00", "203.0.113.3", "c", "before-rotate"))
	data, _ := os.ReadFile(path)
	write(t, path+".1", string(data))
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, line("2026-09-22 13:00:00", "203.0.113.3", "c", "after-rotate"))
	ss, next, _, err = m.Sightings(ctx, time.Time{}, next)
	if err != nil || users(ss) != "before-rotate,after-rotate" {
		t.Fatalf("copytruncate: %q %v", users(ss), err)
	}

	// Rotation by rename: the old file (same inode) is read on, then the
	// new one from the start.
	appendTo(t, path, line("2026-09-22 14:00:00", "203.0.113.4", "d", "renamed-tail"))
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	write(t, path, line("2026-09-22 15:00:00", "203.0.113.4", "d", "new-file"))
	ss, next, _, err = m.Sightings(ctx, time.Time{}, next)
	if err != nil || users(ss) != "renamed-tail,new-file" {
		t.Fatalf("rename: %q %v", users(ss), err)
	}

	// No rotated file can be the one the resume point names: everything is
	// read again from after the last line read.
	_ = os.Remove(path + ".1")
	write(t, path, line("2026-09-22 15:00:00", "203.0.113.4", "d", "seen-before")+line("2026-09-22 16:00:00", "203.0.113.5", "e", "later"))
	ss, _, _, err = m.Sightings(ctx, time.Time{}, `{"ino":1,"off":999999,"last":"`+mustTime("2026-09-22 15:00:00").Format(time.RFC3339)+`"}`)
	if err != nil || users(ss) != "later" {
		t.Errorf("fallback: %q %v", users(ss), err)
	}
	_ = next

	// A resume point that is not one is no resume point.
	if ss, _, _, err := m.Sightings(ctx, time.Time{}, "garbage"); err != nil || users(ss) != "u3,u2,seen-before,later" {
		t.Errorf("bad resume: %q %v", users(ss), err)
	}
}

func mustTime(s string) time.Time {
	t, err := time.ParseInLocation(authTimeForm, s, time.Local)
	if err != nil {
		panic(err)
	}
	return t
}

// A log truncated and written past the old offset before the next scan is
// not the same file grown: its first bytes differ.
func TestSightingsAuthLogTruncatedAndRefilled(t *testing.T) {
	m, path := authLog(t)
	ctx := t.Context()
	write(t, path, line("2026-09-22 10:00:00", "203.0.113.1", "a", "u0"))
	_, next, _, err := m.Sightings(ctx, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	write(t, path+".1", string(data)+line("2026-09-22 10:30:00", "203.0.113.1", "a", "tail"))
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, line("2026-09-22 11:00:00", "203.0.113.2", "a-longer-identifier", "first-after")+
		line("2026-09-22 11:01:00", "203.0.113.2", "b", "second-after"))
	ss, _, _, err := m.Sightings(ctx, time.Time{}, next)
	if err != nil || users(ss) != "tail,first-after,second-after" {
		t.Errorf("%q %v", users(ss), err)
	}
}
