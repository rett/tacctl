package tacacs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
)

func TestParseSightingLine(t *testing.T) {
	at := time.Date(2026, 10, 2, 14, 3, 0, 0, time.UTC)
	const pre = "INFO: 2026/10/02 14:03:00 /tacquito/cmds/server/config/authenticators/bcrypt/bcrypt.go:143: "
	for _, c := range []struct {
		msg                 string
		ok                  bool
		addr, user, outcome string
	}{
		{pre + "accepting user [alice] from [203.0.113.1] using a bcrypt password", true, "203.0.113.1", "alice", backend.SightAccept},
		{pre + "accepting user [alice] from [2001:DB8::0:1] using a bcrypt password", true, "2001:db8::1", "alice", backend.SightAccept},
		{pre + "accepting user [alice] from [::ffff:203.0.113.4] using a bcrypt password", true, "203.0.113.4", "alice", backend.SightAccept},
		{pre + "accepting user [alice] from [unknown] using a bcrypt password", true, "", "alice", backend.SightAccept},
		{"ERROR: x bcrypt.go:152: failed to validate the user [bob] from [198.51.100.7] using a bcrypt password", true, "198.51.100.7", "bob", backend.SightReject},
		{"ERROR: x server.go:159: closing connection, unable to read, bad secret detected for ip [203.0.113.20:51234]", true, "203.0.113.20", "", backend.SightBadSecret},
		{"ERROR: x server.go:159: closing connection, unable to read, bad secret detected for ip [[2001:db8::9]:51234]", true, "2001:db8::9", "", backend.SightBadSecret},
		{"ERROR: x server.go:159: closing connection, unable to read, no matching prefix secret provider found", true, "", "", backend.SightNoScope},
		{"ERROR: x server.go:159: closing connection for ip [192.0.2.66:4000], no matching prefix secret provider found", true, "192.0.2.66", "", backend.SightNoScope},
		{"DEBUG: x provider.go:105: prefix secret provider matches remote [203.0.113.1] against prefix [203.0.113.0/24]", true, "203.0.113.1", "", backend.SightSeen},
		// The unpatched line names no device.
		{pre + "accepting user [alice] using a bcrypt password", false, "", "", ""},
		{"INFO: tacquito started", false, "", "", ""},
		{"", false, "", "", ""},
	} {
		s, ok := ParseSightingLine(c.msg, at)
		if ok != c.ok || s.Address != c.addr || s.User != c.user || s.Outcome != c.outcome || (ok && !s.Time.Equal(at)) {
			t.Errorf("%q: %+v %v", c.msg, s, ok)
		}
	}
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixDir, "sightings", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseJournal(t *testing.T) {
	data := fixture(t, "tacquito.journal-2.json")
	// A MESSAGE journald could not store as text is an array of bytes.
	data = append(data, []byte(`{"__CURSOR":"s=f00d;i=209","__REALTIME_TIMESTAMP":"1791072000000000","MESSAGE":[97,99,99,101,112,116,105,110,103,32,117,115,101,114,32,91,122,93,32,102,114,111,109,32,91,49,57,50,46,48,46,50,46,57,93,32,117,115,105,110,103,32,97,32,98,99,114,121,112,116,32,112,97,115,115,119,111,114,100]}`+"\n")...)
	data = append(data, []byte(`{"__CURSOR":"broken","__REALTIME_TIMESTAMP":"x","MESSAGE":"accepting user [q] from [192.0.2.1] using a bcrypt password"}`+"\n{\"truncated\n")...)
	ss, cursor, first, last, n := ParseJournal(data)
	if cursor != "s=f00d;i=209" || n != 9 {
		t.Errorf("cursor %q, n %d", cursor, n)
	}
	if first.UTC().Format(time.DateTime) != "2026-10-02 14:03:00" || last.UTC().Format(time.DateTime) != "2026-10-04 00:00:00" {
		t.Errorf("first %v last %v", first.UTC(), last.UTC())
	}
	var got []string
	for _, s := range ss {
		got = append(got, s.Outcome+" "+s.Address+" "+s.User)
	}
	want := []string{
		"accept 203.0.113.1 alice", "bad-secret 203.0.113.20 ", "accept 203.0.113.77 carol", "bad-secret 192.0.2.66 ",
		"reject 2001:db8::5 mallory", "no-scope  ", "accept 192.0.2.9 z",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("sightings\n%q\nwant\n%q", got, want)
	}
}

func TestSightingsJournalArgsAndResume(t *testing.T) {
	e := newTenv(t)
	e.run.On([]string{"journalctl"}, execx.Result{Stdout: fixture(t, "tacquito.journal-1.json")})
	since := time.Date(2026, 9, 4, 12, 0, 0, 0, time.Local)
	ss, next, window, err := e.b.Sightings(t.Context(), since, "")
	if err != nil || len(ss) != 1 || next != "s=f00d;i=101" {
		t.Fatalf("%v %q %v", ss, next, err)
	}
	if !strings.HasPrefix(window, "journal ") || !strings.HasSuffix(window, "(1 entry)") {
		t.Errorf("window %q", window)
	}
	if !e.called(`^journalctl -u tacquito -o json --no-pager --since 2026-09-04 12:00:00$`) {
		t.Errorf("argv %q", e.run.Argvs())
	}

	// Resuming: after the cursor, no --since.
	e.run.Reset()
	e.run.On([]string{"journalctl"}, execx.Result{})
	ss, next, window, err = e.b.Sightings(t.Context(), since, "s=f00d;i=101")
	if err != nil || len(ss) != 0 || next != "s=f00d;i=101" || window != "journal: no new entries" {
		t.Fatalf("%v %q %q %v", ss, next, window, err)
	}
	if !e.called(`^journalctl -u tacquito -o json --no-pager --after-cursor s=f00d;i=101$`) {
		t.Errorf("argv %q", e.run.Argvs())
	}

	// A cursor journald no longer knows: read from since instead.
	e.run.Reset()
	e.run.When(func(c execx.Cmd) bool { return strings.Contains(strings.Join(c.Args, " "), "--after-cursor") },
		execx.Result{Code: 1, Stderr: []byte("Failed to seek to cursor: Invalid argument\n")}, nil)
	e.run.When(func(c execx.Cmd) bool { return strings.Contains(strings.Join(c.Args, " "), "--since") },
		execx.Result{Stdout: fixture(t, "tacquito.journal-1.json")}, nil)
	ss, next, _, err = e.b.Sightings(t.Context(), since, "s=gone")
	if err != nil || len(ss) != 1 || next != "s=f00d;i=101" {
		t.Fatalf("fallback: %v %q %v", ss, next, err)
	}

	// No since and no cursor: the whole journal.
	e.run.Reset()
	e.run.On([]string{"journalctl"}, execx.Result{})
	if _, _, _, err := e.b.Sightings(t.Context(), time.Time{}, ""); err != nil {
		t.Fatal(err)
	}
	if !e.called(`^journalctl -u tacquito -o json --no-pager$`) {
		t.Errorf("argv %q", e.run.Argvs())
	}
}

func TestSightingsJournalFailures(t *testing.T) {
	e := newTenv(t)
	e.run.On([]string{"journalctl"}, execx.Result{Code: 1, Stderr: []byte("No journal files were opened due to insufficient permissions.\n")})
	if _, next, _, err := e.b.Sightings(t.Context(), time.Time{}, ""); err == nil || next != "" ||
		!strings.Contains(err.Error(), "insufficient permissions") {
		t.Errorf("%q %v", next, err)
	}
	e.run.Reset()
	e.run.When(func(execx.Cmd) bool { return true }, execx.Result{Code: 127}, errors.New("exec: journalctl: not found"))
	if _, _, _, err := e.b.Sightings(t.Context(), time.Time{}, ""); err == nil {
		t.Error("a missing journalctl is an error")
	}
}
