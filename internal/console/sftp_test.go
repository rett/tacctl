package console

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestQuoteName(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"/a.txt", `"/a.txt"`},
		{"/dir/a b", `"/dir/a b"`},
		{"/é.txt", `"/é.txt"`},
		{"a\nb", `"a\nb"`},
		{"a\rb", `"a\rb"`},
		{"x\x1b[31mred", `"x\x1b[31mred"`},
		{"say \"hi\"", `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
		{"a\x00b", `"a\x00b"`},
		{"bad\xffutf", `"bad\xffutf"`},
		{"rtl\u202eexe.txt", `"rtl\u202eexe.txt"`},
		{"nel\u0085x", `"nel\u0085x"`},
		{"", `""`},
	} {
		if got := QuoteName(c.in); got != c.want {
			t.Errorf("QuoteName(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestQuoteNameCapsTheLength(t *testing.T) {
	long := strings.Repeat("n", NameMax+50)
	if got, want := QuoteName(long), `"`+strings.Repeat("n", NameMax)+`"...`; got != want {
		t.Errorf("long name: %s", got)
	}
	if got := QuoteName(long[:NameMax]); strings.HasSuffix(got, "...") {
		t.Errorf("a name of exactly NameMax bytes was cut: %s", got)
	}
	// the cut falls inside a multi-byte character: the whole character goes
	multi := strings.Repeat("n", NameMax-1) + "é" + "tail"
	got := QuoteName(multi)
	if want := `"` + strings.Repeat("n", NameMax-1) + `"...`; got != want {
		t.Errorf("cut inside a character: %s", got)
	}
	if !utf8.ValidString(got) {
		t.Errorf("cut name is not UTF-8: %q", got)
	}
	// the worst case, a name of bytes that need four characters each, stays
	// within a log line
	worst := strings.Repeat("\x01", NameMax+50)
	if got := QuoteName(worst); len(got) > 4*NameMax+8 {
		t.Errorf("worst case %d bytes", len(got))
	}
}

func TestSFTPLines(t *testing.T) {
	s := Session{ID: "0123456789ab", User: "carol", From: "192.0.2.9", Mode: ModeSFTP}
	if got, want := s.SFTPStartLine("operator", "/home/user", 256<<20, 0),
		`console sftp start session=0123456789ab user=carol tier=operator from=192.0.2.9 home="/home/user" quota=256M rate=off`; got != want {
		t.Errorf("start:\n got %s\nwant %s", got, want)
	}
	if got, want := s.SFTPStartLine("superuser", "/home/user", 0, 1<<20),
		`console sftp start session=0123456789ab user=carol tier=superuser from=192.0.2.9 home="/home/user" quota=unlimited rate=1M`; got != want {
		t.Errorf("start, no quota:\n got %s\nwant %s", got, want)
	}
	if got, want := s.SFTPEndLine(10, 20, 4, 1), `console sftp end session=0123456789ab user=carol up=10 down=20 ops=4 refused=1`; got != want {
		t.Errorf("end: %s", got)
	}
	if got, want := s.SFTPDenyLine("file-transfer"), `console DENY session=0123456789ab user=carol reason=file-transfer subsystem=sftp`; got != want {
		t.Errorf("deny: %s", got)
	}
	for _, c := range []struct {
		op, path, to string
		bytes        int64
		err          string
		priority     string
		want         string
	}{
		{"upload", "/a b", "", 12, "", "auth.info", `console sftp upload session=0123456789ab user=carol path="/a b" bytes=12`},
		{"download", "/a", "", 3, "", "auth.info", `console sftp download session=0123456789ab user=carol path="/a" bytes=3`},
		{"delete", "/a", "", 0, "", "auth.info", `console sftp delete session=0123456789ab user=carol path="/a"`},
		{"rename", "/a", "/b\n", 0, "", "auth.info", `console sftp rename session=0123456789ab user=carol path="/a" to="/b\n"`},
		{"mkdir", "/d", "", 0, "", "auth.info", `console sftp mkdir session=0123456789ab user=carol path="/d"`},
		{"setstat", "/a", "", 0, "", "auth.info", `console sftp setstat session=0123456789ab user=carol path="/a"`},
		{"delete", "/a", "", 0, "no such file", "auth.info", `console sftp delete session=0123456789ab user=carol path="/a" error="no such file"`},
		{"refused", "/.ssh/k", "", 0, ".ssh", "auth.warning", `console sftp DENY session=0123456789ab user=carol path="/.ssh/k" reason=.ssh`},
		{"refused", "/x", "", 0, "outside the home", "auth.warning", `console sftp DENY session=0123456789ab user=carol path="/x" reason=outside-the-home`},
		{"refused", "/q", "", 0, "quota", "auth.warning", `console sftp DENY session=0123456789ab user=carol path="/q" reason=quota`},
	} {
		priority, line := s.SFTPEventLine(c.op, c.path, c.to, c.bytes, c.err)
		if priority != c.priority || line != c.want {
			t.Errorf("%s: %s %s\nwant %s %s", c.op, priority, line, c.priority, c.want)
		}
	}
	// A user name with a space or a quote cannot forge a field.
	forged := Session{ID: "0123456789ab", User: "x\" path=\"/y"}
	_, line := forged.SFTPEventLine("delete", "/a", "", 0, "")
	if strings.Contains(line, `path="/y`) || strings.Count(line, " path=") != 1 {
		t.Errorf("forged user: %s", line)
	}
}
