package devapply

import (
	"errors"
	"strings"
	"testing"
)

// A dual-routing-engine or virtual-chassis device commits with 'commit
// synchronize', and the entry keeps the word. The pre-flight read entry 0
// 'commit synchronize' as no command it knew and refused the device.
func TestParseHistorySynchronizeEntries(t *testing.T) {
	const out = `0   2026-05-19 12:37:55 UTC by alice via cli commit synchronize
1   2026-05-19 12:37:06 UTC by alice via cli commit confirmed, rollback in 5mins synchronize
2   2026-05-19 11:02:40 UTC by root via other
`
	h, err := parseHistory(out)
	if err != nil || len(h) != 3 {
		t.Fatalf("%+v %v", h, err)
	}
	if h[0].RollbackIn != 0 || h[0].User != "alice" || h[0].Via != "cli" {
		t.Errorf("entry 0: %+v", h[0])
	}
	if h[1].RollbackIn != 5 {
		t.Errorf("entry 1: %+v", h[1])
	}
	// the confirmed commit is the one that matters when it is entry 0
	h, err = parseHistory("0   2026-05-19 12:37:06 UTC by alice via cli commit confirmed, rollback in 5mins synchronize\n")
	if err != nil || len(h) != 1 || h[0].RollbackIn != 5 || h[0].Until() != "2026-05-19 12:42:06 UTC" {
		t.Errorf("confirmed with synchronize as entry 0: %+v %v", h, err)
	}
}

// Every spelling of a commit command that 'show system commit' prints at the
// end of an entry is read, and the window of a confirmed commit is kept.
func TestParseHistoryCommitSpellings(t *testing.T) {
	for _, c := range []struct {
		tail string
		mins int
	}{
		{"", 0},
		{" commit", 0},
		{" commit and-quit", 0},
		{" commit synchronize", 0},
		{" commit synchronize and-quit", 0},
		{" commit and-quit synchronize", 0},
		{" commit synchronize force", 0},
		{" commit force", 0},
		{" commit full", 0},
		{" commit prepare", 0},
		{" commit at 02:00", 0},
		{" commit at 02:00:30", 0},
		{" commit at 2026-10-13 02:00:00", 0},
		{` commit at "2026-10-13 02:00:00"`, 0},
		{` commit at "02:00" synchronize`, 0},
		{" commit at 2026-10-13 02:00:00 synchronize force", 0},
		{" commit at reboot", 0},
		{" commit confirmed, rollback in 10mins", 10},
		{" commit confirmed, rollback in 1min", 1},
		{" commit confirmed, rollback in 0mins", 0},
		{" commit confirmed, rollback in 5mins synchronize", 5},
		{" commit confirmed, rollback in 5mins synchronize force", 5},
		{" commit confirmed, rollback in 5mins and-quit", 5},
		{" commit confirmed, rollback in 5mins at 02:00", 5},
		{" commit confirmed, rollback in 5mins prepare", 5},
		{"   commit   synchronize  ", 0},
	} {
		const e0 = "0   2026-10-13 14:00:00 UTC by alice via cli commit\n"
		entry := "   2026-10-13 14:00:00 UTC by alice via cli" + c.tail + "\n"
		// as the newest entry, and as an older one
		for _, in := range []string{"0" + entry, e0 + "1" + entry} {
			h, err := parseHistory(in)
			if err != nil || h[len(h)-1].RollbackIn != c.mins {
				t.Errorf("%q: %+v %v", in, h, err)
			}
		}
	}
}

// The entry that is no commit command stays an error for entry 0, which says
// what could not be read, and is kept as it is for a later entry.
func TestParseHistoryUnknownCommandText(t *testing.T) {
	for _, tail := range []string{
		" something else",
		" commit something new",
		" commit synchronized",
		" commit synchronizeforce",
		" commits",
		" committed",
		" commit confirmed",
		" commit confirmed, rollback in mins",
		" commit confirmed, rollback in 5mins confirmed, rollback in 5mins",
		" commit at",
		" commit at noon",
		" commit at 2:00",
		" commit synchronize,",
		" commit force-synchronize",
		" commit peers-synchronize",
		" commit and-quit confirmed, rollback in 7mins",
		" commit synchronize confirmed, rollback in 15mins",
		" synchronize",
		" cli",
	} {
		_, err := parseHistory("0   2026-10-13 14:00:00 UTC by alice via cli" + tail + "\n")
		if !errors.Is(err, ErrUnrecognised) {
			t.Errorf("entry 0 %q: %v", tail, err)
			continue
		}
		strip := strings.TrimSpace(tail)
		if !strings.Contains(err.Error(), "entry 0") || !strings.Contains(err.Error(), `"`+strip+`"`) ||
			!strings.Contains(err.Error(), "not a commit command") {
			t.Errorf("the message does not say what could not be read: %v", err)
		}
		h, err := parseHistory("0   2026-10-13 14:00:00 UTC by alice via cli\n1   2026-10-12 14:00:00 UTC by alice via cli" + tail + "\n")
		if err != nil || len(h) != 2 || h[1].RollbackIn != 0 {
			t.Errorf("entry 1 %q: %+v %v", tail, h, err)
		}
	}
}

// The rest of the entry layout: the user, the way, the zone, the log lines.
func TestParseHistoryEntryLayout(t *testing.T) {
	for _, c := range []struct {
		name, line string
		user, via  string
		time       string
	}{
		{"root", "root via cli commit synchronize", "root", "cli", "UTC"},
		{"dotted user", "alice.admin via cli commit synchronize", "alice.admin", "cli", "UTC"},
		{"user with digit", "alice2 via cli", "alice2", "cli", "UTC"},
		{"user with dash and at", "alice-ops@example.net via cli", "alice-ops@example.net", "cli", "UTC"},
		{"netconf", "alice via netconf commit confirmed, rollback in 3mins", "alice", "netconf", "UTC"},
		{"junoscript", "alice via junoscript commit synchronize", "alice", "junoscript", "UTC"},
		{"snmp", "alice via snmp", "alice", "snmp", "UTC"},
		{"button", "root via button", "root", "button", "UTC"},
		{"other", "root via other", "root", "other", "UTC"},
		{"other with text", "root via other commit synchronize", "root", "other", "UTC"},
		{"CET", "alice via cli commit synchronize", "alice", "cli", "CET"},
		{"CEST", "alice via cli commit synchronize", "alice", "cli", "CEST"},
	} {
		zone := c.time
		in := "0   2026-10-13 14:00:00 " + zone + " by " + c.line + "\n"
		h, err := parseHistory(in)
		if err != nil || len(h) != 1 || h[0].User != c.user || h[0].Via != c.via || h[0].TimeText != "2026-10-13 14:00:00 "+zone || h[0].Time.IsZero() {
			t.Errorf("%s: %+v %v", c.name, h, err)
		}
	}
	// a time with no zone, with a numeric zone (the offset counts), with an
	// abbreviation of the form GMT+3
	for _, c := range []struct {
		zone   string
		offset int // seconds east of UTC
	}{{"", 0}, {" +03", 3 * 3600}, {" -03", -3 * 3600}, {" +0300", 3 * 3600}, {" -0330", -(3*3600 + 1800)}, {" GMT+3", 3 * 3600}, {" UTC", 0}} {
		h, err := parseHistory("0   2026-10-13 14:00:00" + c.zone + " by alice via cli commit synchronize\n")
		if err != nil || len(h) != 1 || h[0].Time.IsZero() || h[0].TimeText != "2026-10-13 14:00:00"+c.zone {
			t.Errorf("zone %q: %+v %v", c.zone, h, err)
			continue
		}
		if _, off := h[0].Time.Zone(); off != c.offset && c.zone != "" {
			t.Errorf("zone %q: offset %d, want %d", c.zone, off, c.offset)
		}
	}
	// a confirmed commit's end is written in the zone the device printed
	h, err := parseHistory("0   2026-10-13 14:00:00 +0530 by alice via cli commit confirmed, rollback in 5mins\n")
	if err != nil || h[0].Until() != "2026-10-13 14:05:00 +0530" {
		t.Errorf("until %q %v", h[0].Until(), err)
	}
	// device text in the error is cut: no control character reaches it
	_, err = parseHistory("0   2026-10-13 14:00:00 UTC by al\x1bice via cl\x07i commit bogus\n")
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\x07") {
		t.Errorf("control characters in %q", err)
	}
}

// Log lines under an entry: one, several, indented with a tab, a log line
// that looks like a commit command, and one under a synchronized entry.
func TestParseHistoryLogLines(t *testing.T) {
	const out = `0   2026-10-13 14:00:00 UTC by alice via cli commit confirmed, rollback in 5mins synchronize
    tacctl apply sw1.example.net by alice
    second line
1   2026-10-13 13:00:00 UTC by root via other
2   2026-10-13 12:00:00 UTC by alice via cli commit synchronize
	tabbed
3   2026-10-13 11:00:00 UTC by bob via cli commit and-quit
    commit confirmed, rollback in 9mins
4   2026-10-13 10:00:00 UTC by carol via netconf
    rollback pending
`
	h, err := parseHistory(out)
	if err != nil || len(h) != 5 {
		t.Fatalf("%+v %v", h, err)
	}
	if h[0].Comment != "tacctl apply sw1.example.net by alice second line" || h[0].RollbackIn != 5 {
		t.Errorf("0: %+v", h[0])
	}
	if h[1].Comment != "" || h[2].Comment != "tabbed" {
		t.Errorf("1, 2: %+v %+v", h[1], h[2])
	}
	// the text of a log line is no command
	if h[3].Comment != "commit confirmed, rollback in 9mins" || h[3].RollbackIn != 0 {
		t.Errorf("3: %+v", h[3])
	}
	if !h[4].Pending || h[4].Comment != "" {
		t.Errorf("4: %+v", h[4])
	}
}

// Lines that are no commit entry still fail closed.
func TestParseHistoryNoEntryFailsClosed(t *testing.T) {
	const e0 = "0   2026-10-13 14:00:00 UTC by alice via cli commit synchronize\n"
	for name, in := range map[string]string{
		"no number":      "   2026-10-13 14:00:00 UTC by alice via cli commit synchronize\n",
		"no user":        "0   2026-10-13 14:00:00 UTC via cli commit synchronize\n",
		"no way":         "0   2026-10-13 14:00:00 UTC by alice\n",
		"no way, text":   "0   2026-10-13 14:00:00 UTC by alice commit synchronize\n",
		"no time":        "0   by alice via cli commit synchronize\n",
		"bad time":       "0   2026-13-45 14:00:00 UTC by alice via cli commit synchronize\n",
		"a header":       "Commit history\n" + e0,
		"unindented":     e0 + "tacctl apply\n",
		"second entry 0": e0 + e0,
		"gap":            e0 + "2   2026-10-12 14:00:00 UTC by alice via cli\n",
	} {
		if _, err := parseHistory(in); !errors.Is(err, ErrUnrecognised) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
