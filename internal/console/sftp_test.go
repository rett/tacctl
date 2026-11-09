package console

import (
	"strconv"
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
}

// NameMax bounds the escaped text, and a cut never falls inside an escape
// sequence or a character: what is kept reads back as a Go string literal.
func TestQuoteNameBoundsTheEscapedText(t *testing.T) {
	for name, in := range map[string]string{
		"control bytes":   strings.Repeat("\x01", NameMax+50),
		"invalid bytes":   strings.Repeat("\xff", NameMax+50),
		"quotes":          strings.Repeat(`"`, NameMax+50),
		"backslashes":     strings.Repeat(`\`, NameMax+50),
		"override marks":  strings.Repeat("\u202e", NameMax+50),
		"two-byte":        strings.Repeat("é", NameMax+50),
		"four-byte":       strings.Repeat("\U0001F600", NameMax+50),
		"plain then ctrl": strings.Repeat("n", NameMax-2) + "\x01\x01",
		"plain then rtl":  strings.Repeat("n", NameMax-5) + "\u202e",
	} {
		got := QuoteName(in)
		inner := strings.TrimSuffix(got, "...")
		if len(inner) > NameMax+2 {
			t.Errorf("%s: %d bytes of text, more than NameMax", name, len(inner)-2)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: not UTF-8: %q", name, got)
		}
		if !strings.HasSuffix(got, "...") {
			t.Errorf("%s: a name over NameMax was not marked as cut: %s", name, got)
		}
		if _, err := strconv.Unquote(inner); err != nil {
			t.Errorf("%s: the cut falls inside an escape: %s: %v", name, got, err)
		}
	}
	// the cut is as late as it can be: 199 plain bytes, then an escape that
	// would not fit
	if got, want := QuoteName(strings.Repeat("n", NameMax-1)+"\x01"), `"`+strings.Repeat("n", NameMax-1)+`"...`; got != want {
		t.Errorf("late cut: %s", got)
	}
	// and an escape that fits exactly is kept, uncut
	if got, want := QuoteName(strings.Repeat("n", NameMax-4)+"\x01"), `"`+strings.Repeat("n", NameMax-4)+`\x01"`; got != want {
		t.Errorf("exact fit: %s", got)
	}
}

// A line of every kind, with the longest user, tier, path, new name and
// error text there are, and every byte of them an escape, fits in what
// logger keeps of a line (1 KiB by default); the trailing fields survive.
func TestSFTPEventLinesFitALogLine(t *testing.T) {
	s := Session{ID: "0123456789ab", User: strings.Repeat("u", 80), From: strings.Repeat("1", 80), Mode: ModeSFTP}
	hostile := strings.Repeat("\x01", 400)
	check := func(kind, line string) {
		t.Helper()
		if len(line) >= 1000 {
			t.Errorf("%s: %d bytes: %s", kind, len(line), line)
		}
	}
	for _, op := range []string{"upload", "download", "delete", "rename", "mkdir", "setstat"} {
		to := ""
		if op == "rename" {
			to = hostile
		}
		_, line := s.SFTPEventLine(op, "superuser", hostile, to, 1<<62, hostile)
		check(op, line)
		if !strings.Contains(line, " error=") {
			t.Errorf("%s: the error field is lost: %s", op, line)
		}
	}
	for _, why := range []string{".ssh", "outside the home", "symlink", "link", "quota", "unsupported", "bad path", "too many open files"} {
		_, line := s.SFTPEventLine("refused", "superuser", hostile, hostile, 0, why)
		check("refused "+why, line)
		if !strings.HasSuffix(line, " reason="+strings.ReplaceAll(why, " ", "-")) {
			t.Errorf("refused %s: the reason is lost: %s", why, line)
		}
	}
	check("start", s.SFTPStartLine("superuser", hostile, 1<<62, 1<<62))
	check("end", s.SFTPEndLine(1<<62, 1<<62, 1<<30, 1<<30))
	check("deny", s.SFTPDenyLine("password-change"))
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
		{"upload", "/a b", "", 12, "", "auth.info", `console sftp upload session=0123456789ab user=carol tier=operator path="/a b" bytes=12`},
		{"download", "/a", "", 3, "", "auth.info", `console sftp download session=0123456789ab user=carol tier=operator path="/a" bytes=3`},
		{"delete", "/a", "", 0, "", "auth.info", `console sftp delete session=0123456789ab user=carol tier=operator path="/a"`},
		{"rename", "/a", "/b\n", 0, "", "auth.info", `console sftp rename session=0123456789ab user=carol tier=operator path="/a" to="/b\n"`},
		{"mkdir", "/d", "", 0, "", "auth.info", `console sftp mkdir session=0123456789ab user=carol tier=operator path="/d"`},
		{"setstat", "/a", "", 0, "", "auth.info", `console sftp setstat session=0123456789ab user=carol tier=operator path="/a"`},
		{"delete", "/a", "", 0, "no such file", "auth.info", `console sftp delete session=0123456789ab user=carol tier=operator path="/a" error="no such file"`},
		{"refused", "/.ssh/k", "", 0, ".ssh", "auth.warning", `console sftp DENY session=0123456789ab user=carol tier=operator path="/.ssh/k" reason=.ssh`},
		{"refused", "/x", "", 0, "outside the home", "auth.warning", `console sftp DENY session=0123456789ab user=carol tier=operator path="/x" reason=outside-the-home`},
		{"refused", "/q", "", 0, "quota", "auth.warning", `console sftp DENY session=0123456789ab user=carol tier=operator path="/q" reason=quota`},
	} {
		priority, line := s.SFTPEventLine(c.op, "operator", c.path, c.to, c.bytes, c.err)
		if priority != c.priority || line != c.want {
			t.Errorf("%s: %s %s\nwant %s %s", c.op, priority, line, c.priority, c.want)
		}
	}
	// A user name with a space or a quote cannot forge a field.
	forged := Session{ID: "0123456789ab", User: "x\" path=\"/y"}
	_, line := forged.SFTPEventLine("delete", "operator", "/a", "", 0, "")
	if strings.Contains(line, `path="/y`) || strings.Count(line, " path=") != 1 {
		t.Errorf("forged user: %s", line)
	}
}
