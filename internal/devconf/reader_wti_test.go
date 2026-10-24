package devconf

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/wti"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// The WTI reader against the fake units of tests/fixtures/devconf/wti/fake,
// through devssh.Client.Terminal as the CLI will drive them.

const rwFakeDir = "../../tests/fixtures/devconf/wti/fake"

// devssh's TermSession is what the reader is driven by.
var _ WTITerminal = devssh.TermSession(nil)

// rwTerm closes the client with its terminal.
type rwTerm struct {
	devssh.TermSession
	c *devssh.Client
	// rewrite, when set, changes the keys sent (a unit that refuses an
	// entry the tables expect it to take).
	rewrite func(key string) string
}

func (r *rwTerm) Send(ctx context.Context, p []byte) error {
	if r.rewrite != nil {
		p = []byte(r.rewrite(string(p)))
	}
	return r.TermSession.Send(ctx, p)
}

func (r *rwTerm) Close() error {
	err := r.TermSession.Close()
	_ = r.c.Close()
	return err
}

// rwOpen returns a function that opens a terminal on the server.
func rwOpen(t *testing.T, srv *fakedev.Server) func(context.Context) (WTITerminal, error) {
	t.Helper()
	return rwOpenWith(t, srv, nil)
}

func rwOpenWith(t *testing.T, srv *fakedev.Server, rewrite func(string) string) func(context.Context) (WTITerminal, error) {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(port)
	tg := devssh.Target{
		Host: host, Port: p, User: fakedev.DefaultUser,
		HostKeys:       []string{srv.HostKey()},
		ConnectTimeout: 5 * time.Second,
		Quiet:          250 * time.Millisecond,
		Password:       func() (string, error) { return fakedev.DefaultPassword, nil },
	}
	return func(ctx context.Context) (WTITerminal, error) {
		c, err := devssh.Dial(ctx, tg)
		if err != nil {
			return nil, err
		}
		s, err := c.Terminal(ctx)
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		return &rwTerm{TermSession: s, c: c, rewrite: rewrite}, nil
	}
}

func rwServe(t *testing.T, dir string, opts ...fakedev.Option) *fakedev.Server {
	t.Helper()
	s := fakedev.New(dir, opts...)
	t.Cleanup(s.Stop)
	return s
}

// rwDir writes a manifest (and the files it names) into a temporary
// directory; the captures are found by the 'screens' line.
func rwDir(t *testing.T, manifest string, files map[string]string) string {
	t.Helper()
	screens, err := filepath.Abs(filepath.Join(rwFakeDir, ".."))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	files["menu"] = "screens " + screens + "\n" + manifest
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func rwCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// rwRead runs the reader on a fake with the user directory's second
// session, waits for the sessions to end and returns what it needs.
func rwRead(t *testing.T, srv *fakedev.Server, opts WTIReadOptions) (string, WTIReadInfo, error) {
	t.Helper()
	return rwReadWith(t, srv, opts, nil)
}

// rwReadWith is rwRead with the first session's keys rewritten.
func rwReadWith(t *testing.T, srv *fakedev.Server, opts WTIReadOptions, rewrite func(string) string) (string, WTIReadInfo, error) {
	t.Helper()
	open := rwOpenWith(t, srv, rewrite)
	term, err := open(rwCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if opts.Users == nil {
		opts.Users = rwOpen(t, srv)
	}
	if opts.PageTimeout == 0 {
		opts.PageTimeout = 10 * time.Second
	}
	return ReadWTI(rwCtx(t), term, opts)
}

// rwNoSave fails when the unit was told to save anything.
func rwNoSave(t *testing.T, srv *fakedev.Server) {
	t.Helper()
	if got := srv.Saved(); len(got) != 0 {
		t.Errorf("Saved = %q: a read left a top-level menu with ESC", got)
	}
	for _, e := range srv.Events() {
		if strings.HasPrefix(e, "save") || strings.Contains(e, "Saving") {
			t.Errorf("event %q", e)
		}
	}
}

// rwHeaders are the page headers of a document, in order.
func rwHeaders(raw string) []string {
	var out []string
	for _, l := range strings.Split(raw, "\n") {
		if p, ok := strings.CutPrefix(l, wti.PageHeader); ok {
			out = append(out, strings.TrimSpace(p))
		}
	}
	return out
}

// rwWaitEvent waits until the server has logged e: the unit logs a close
// when the connection's end reaches it.
func rwWaitEvent(t *testing.T, srv *fakedev.Server, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if slices.Contains(srv.Events(), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("event %q never logged; events %q", want, srv.Events())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

var rwFullWalk = []string{
	"/H", "/SN", "/J", "/N", "/N > 25", "/N > 25 > 4", "/N > 25 > 5", "/N > 25 > 6", "/N > 26", "/N > 28", "/N > 28 > 8", "/N > 29", "/N > 29 > 11",
	"/N > 5", "/N > 5", "/N > 5", "/N > 5", "/F", "/F > 1 > 1", "/F > 1 > 1 > localadmin",
}

func TestReadWTILabSuperuser(t *testing.T) {
	srv := rwServe(t, filepath.Join(rwFakeDir, "lab-superuser"))
	raw, info, err := rwRead(t, srv, WTIReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := rwHeaders(raw); !slices.Equal(got, rwFullWalk) {
		t.Errorf("pages = %q\nwant    %q", got, rwFullWalk)
	}
	want := WTIReadInfo{Version: "8.10", Level: wti.LevelAdministrator, OtherSessions: 1,
		SiteID: "wti.site.example.net", Pages: len(rwFullWalk), UsersRead: true, Users: 1}
	if info != want {
		t.Errorf("info = %+v\nwant   %+v", info, want)
	}

	// The document is the format of the tables' parser.
	d, err := wti.ParseDocument(raw)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if miss := d.Missing(); len(miss) != 0 {
		t.Errorf("missing %q", miss)
	}
	// The other sessions' user names are not in the document: the count is.
	for _, name := range []string{"user1", fakedev.DefaultUser} {
		if strings.Contains(raw, name) {
			t.Errorf("the document holds the session user name %q", name)
		}
	}
	if !strings.Contains(raw, "N1  |      22|Active|                |N17 |        | Free |                |") {
		t.Errorf("the status rows are not as redacted: %q", raw[strings.Index(raw, "N1 "):][:90])
	}
	if v, _ := d.Fact("iptables"); v != "on" {
		t.Errorf("iptables fact = %q", v)
	}
	exp := wtiExpected(t)
	ex, err := Extract("wti", raw, exp...)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if _, err := CompareAll(exp, ex); err != nil {
		t.Errorf("CompareAll: %v", err)
	}
	// The same statements as the lab unit's document, plus the two the
	// RADIUS default access page adds.
	got := sectionsText(ex)
	for _, extra := range []string{"| radius default-level user\n", "| radius default-services serial,telnet-ssh,web,restful-api\n"} {
		if !strings.Contains(got, extra) {
			t.Errorf("no %q in the extraction", extra)
		}
		got = strings.Replace(got, extra, "", 1)
	}
	if golden := string(mustRead(t, filepath.Join(fixtureDir, "wti/lab-unit/extract.golden"))); got != golden {
		t.Errorf("extraction differs from the lab unit's:\n--- got\n%s\n--- want\n%s", got, golden)
	}

	// The keys typed: the banner's CR, the pager, the pages and their ESCs;
	// never a value, never an ESC at a top-level page.
	cmds := srv.Commands()
	s := strings.Join(cmds, " ")
	for _, want := range []string{
		"<CR> /H <SPACE>", "/SN <ESC> /J /N 25 4 <ESC> 5 <ESC> 6 <ESC> <ESC> 26 <ESC> 28 8 <ESC> <ESC> 29 11 <ESC> <ESC> 5 > > > <ESC> <CR> /F 1 1 localadmin <ESC> <ESC> <ESC>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("keys %q lack %q", s, want)
		}
	}
	rwNoSave(t, srv)
	rwWaitEvent(t, srv, "close /N")
	rwWaitEvent(t, srv, "close /F")
	for _, c := range cmds {
		if c == "<ESC>" {
			continue
		}
		if _, err := strconv.Atoi(c); err == nil || strings.HasPrefix(c, "/") || c == ">" || c == "<SPACE>" || c == "<CR>" || c == "localadmin" {
			continue
		}
		t.Errorf("an unexpected key %q was typed", c)
	}
	for _, e := range srv.Events() {
		if strings.HasPrefix(e, "entry") || strings.HasPrefix(e, "no-page") || strings.HasPrefix(e, "refused") {
			t.Errorf("the unit refused something: %q", e)
		}
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReadWTIEngineerAndNoUsersSession(t *testing.T) {
	srv := rwServe(t, filepath.Join(rwFakeDir, "lab-engineer"))
	open := rwOpen(t, srv)
	term, err := open(rwCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, info, err := ReadWTI(rwCtx(t), term, WTIReadOptions{PageTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if info.Level != wti.LevelSuperUser || info.OtherSessions != 0 || info.UsersRead || info.UsersErr != nil {
		t.Errorf("info = %+v", info)
	}
	for _, h := range rwHeaders(raw) {
		if strings.HasPrefix(h, "/F") {
			t.Errorf("a page of /F in a read without a user session: %q", h)
		}
	}
	if _, err := Extract("wti", raw, wtiExpected(t)...); err != nil {
		t.Errorf("Extract: %v", err)
	}
	rwNoSave(t, srv)
	rwWaitEvent(t, srv, "close /N")
	if _, err := term.Expect(context.Background(), nil); !errors.Is(err, devssh.ErrClosed) {
		t.Errorf("the session was left open: %v", err)
	}
}

func TestReadWTIDeniedAndUnsupported(t *testing.T) {
	for _, c := range []struct{ unit, level string }{{"lab-user", "user"}, {"lab-viewonly", "viewonly"}} {
		t.Run(c.unit, func(t *testing.T) {
			srv := rwServe(t, filepath.Join(rwFakeDir, c.unit))
			raw, info, err := rwRead(t, srv, WTIReadOptions{})
			var de *WTIDeniedError
			if !errors.Is(err, ErrDenied) || !errors.As(err, &de) || de.Level != c.level {
				t.Fatalf("err = %v, want ErrDenied at level %s", err, c.level)
			}
			if raw != "" || info.Level != c.level || info.Version != "8.10" {
				t.Errorf("raw %q info %+v", raw, info)
			}
			if strings.Contains(err.Error(), "COMMAND MENU") || strings.Contains(err.Error(), "/SN") {
				t.Errorf("the error holds screen text: %v", err)
			}
			// Nothing but the help was opened.
			for _, k := range srv.Commands() {
				if k == "/N" || k == "/F" || k == "/SN" {
					t.Errorf("typed %q at a login that is denied", k)
				}
			}
			rwNoSave(t, srv)
		})
	}

	srv := rwServe(t, filepath.Join(rwFakeDir, "lab-old"))
	_, info, err := rwRead(t, srv, WTIReadOptions{})
	var ve *WTIVersionError
	if !errors.Is(err, ErrUnsupportedVersion) || !errors.As(err, &ve) || ve.Version != "7.4" {
		t.Fatalf("err = %v, want ErrUnsupportedVersion 7.4", err)
	}
	if !strings.Contains(err.Error(), "7.4") || strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("error text: %v", err)
	}
	if info.Version != "7.4" {
		t.Errorf("info = %+v", info)
	}
	for _, k := range srv.Commands() {
		if k == "/N" || k == "/F" || k == "/SN" || k == "/J" {
			t.Errorf("typed %q on a unit of another version", k)
		}
	}
	rwNoSave(t, srv)
}

const rwUnknownPage = `26

FROBNICATE: [Shared]

1.  Sentinel:   SENTINEL-SECRET-VALUE-1

Enter: #<CR> to change,
       <ESC> to return to previous menu ...
`

func TestReadWTIUnknownTitleAborts(t *testing.T) {
	dir := rwDir(t, "page /N > 26 = frob.txt\n", map[string]string{"frob.txt": rwUnknownPage})
	srv := rwServe(t, dir)
	raw, _, err := rwRead(t, srv, WTIReadOptions{})
	var pe *WTIPageError
	if !errors.As(err, &pe) || !errors.Is(err, wti.ErrUnknownPage) {
		t.Fatalf("err = %v, want a WTIPageError of an unknown page", err)
	}
	if raw != "" {
		t.Errorf("raw = %q with an error", raw)
	}
	if pe.Path != "/N > 26" || pe.Title != "FROBNICATE: [Shared]" {
		t.Errorf("error names %q %q", pe.Path, pe.Title)
	}
	if strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), "Sentinel") {
		t.Errorf("the error holds screen text: %v", err)
	}
	// Up to the top-level page and closed there: the unknown page was left
	// with one ESC and the page below it was not.
	cmds := srv.Commands()
	if tail := cmds[len(cmds)-2:]; !slices.Equal(tail, []string{"26", "<ESC>"}) {
		t.Errorf("keys end %q", tail)
	}
	rwWaitEvent(t, srv, "close /N")
	rwNoSave(t, srv)
	if slices.Contains(cmds, "28") {
		t.Errorf("went on after the unknown page: %q", cmds)
	}
}

// rwRefuse rewrites the item number key (and only the first time) into a
// number the unit has no page for: it prints 'ERROR: Invalid entry.' above
// the page it was showing.
func rwRefuse(key string) func(string) string {
	done := false
	return func(k string) string {
		if k == key && !done {
			done = true
			return "99\r"
		}
		return k
	}
}

func TestReadWTIErrorScreenAbortsAtTopLevelWithoutEsc(t *testing.T) {
	// The unit refuses item 25 of /N: its error line is above the repainted
	// /N page, a top-level page, so no ESC is sent at all.
	srv := rwServe(t, filepath.Join(rwFakeDir, "lab-superuser"))
	raw, _, err := rwReadWith(t, srv, WTIReadOptions{}, rwRefuse("25\r"))
	var pe *WTIPageError
	if !errors.As(err, &pe) || pe.Path != "/N > 25" || !errors.Is(err, ErrUnexpectedScreen) || raw != "" {
		t.Fatalf("err = %v raw %q", err, raw)
	}
	if strings.Contains(err.Error(), "ERROR") || strings.Contains(err.Error(), "Invalid entry") {
		t.Errorf("screen text in the error: %v", err)
	}
	cmds := srv.Commands()
	if last := cmds[len(cmds)-1]; last != "99" {
		t.Errorf("keys end %q, want the refused entry as the last key", cmds[len(cmds)-2:])
	}
	rwWaitEvent(t, srv, "close /N")
	rwNoSave(t, srv)
}

func TestReadWTIErrorScreenBelowTheTopClimbsToIt(t *testing.T) {
	// The unit refuses item 8 of /N 28 (a required page): the page showing
	// is /N 28, two deep, so one ESC returns to /N and the session closes
	// there.
	srv := rwServe(t, filepath.Join(rwFakeDir, "lab-superuser"))
	_, _, err := rwReadWith(t, srv, WTIReadOptions{}, rwRefuse("8\r"))
	var pe *WTIPageError
	if !errors.As(err, &pe) || pe.Path != "/N > 28 > 8" {
		t.Fatalf("err = %v", err)
	}
	cmds := srv.Commands()
	if tail := cmds[len(cmds)-3:]; !slices.Equal(tail, []string{"28", "99", "<ESC>"}) {
		t.Errorf("keys end %q", tail)
	}
	rwWaitEvent(t, srv, "close /N")
	rwNoSave(t, srv)
}

// rwSNMPKeys are the keys typed between the opening of /N > 25 and of
// /N > 26, a read's from the log of the unit.
func rwSNMPKeys(t *testing.T, srv *fakedev.Server) []string {
	t.Helper()
	cmds := srv.Commands()
	from := slices.Index(cmds, "25")
	if from < 0 {
		t.Fatalf("no '25' in the keys %q", cmds)
	}
	to := slices.Index(cmds[from:], "26")
	if to < 0 {
		t.Fatalf("no '26' after '25' in the keys %q", cmds)
	}
	return cmds[from : from+to+1]
}

func TestReadWTITextPromptsAreOpenedAndLeftWithEsc(t *testing.T) {
	// The three SNMP texts are truncated on the lab unit's menu: each is
	// opened with its number and a CR, read, and left with ESC; nothing is
	// typed at a prompt and the secret prompts (7 and 8) are not visited.
	srv := rwServe(t, filepath.Join(rwFakeDir, "lab-superuser"))
	raw, info, err := rwRead(t, srv, WTIReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"25", "4", "<ESC>", "5", "<ESC>", "6", "<ESC>", "<ESC>", "26"}
	if got := rwSNMPKeys(t, srv); !slices.Equal(got, want) {
		t.Errorf("keys %q, want %q", got, want)
	}
	if info.Pages != len(rwFullWalk) {
		t.Errorf("pages %d, want %d", info.Pages, len(rwFullWalk))
	}
	// the prompt pages follow the SNMP menu in the document, in item order,
	// each as the unit printed it
	hs := rwHeaders(raw)
	i := slices.Index(hs, "/N > 25")
	if i < 0 || !slices.Equal(hs[i:i+5], []string{"/N > 25", "/N > 25 > 4", "/N > 25 > 5", "/N > 25 > 6", "/N > 26"}) {
		t.Fatalf("headers %q", hs)
	}
	for _, v := range []string{"wti.site.example.net", "Example NOC (555) 0100", "Example City, Example State"} {
		if strings.Count(raw, "\n"+v+"\n") != 1 {
			t.Errorf("the document holds %d lines of %q, want 1", strings.Count(raw, "\n"+v+"\n"), v)
		}
	}
	ex, err := Extract("wti", raw, wtiExpected(t)...)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(ex.Sections[SectionSNMP].Lines, "\n")
	for _, w := range []string{"snmp system-name wti.site.example.net", `snmp contact "Example NOC (555) 0100"`, `snmp location "Example City, Example State"`} {
		if !strings.Contains(got, w) {
			t.Errorf("no %q in the snmp section:\n%s", w, got)
		}
	}
	if strings.Contains(got, "...") {
		t.Errorf("a truncated value in the snmp section:\n%s", got)
	}
	// no value, no CR, no SPACE at a prompt: the log holds no entry
	for _, e := range srv.Events() {
		if strings.HasPrefix(e, "entry") || strings.HasPrefix(e, "no-page") || strings.HasPrefix(e, "save") {
			t.Errorf("event %q", e)
		}
	}
	rwNoSave(t, srv)
	rwWaitEvent(t, srv, "close /N")
}

// Item 31 of /N is on the page the walk opens anyway: a unit with Multiple
// Logins Off is read with the keys of any other (no page of its own, nothing
// typed at it), and its aaa section says so.
func TestReadWTIMultipleLogins(t *testing.T) {
	top := string(mustRead(t, filepath.Join(rwFakeDir, "../pages/network-top.txt")))
	read := func(t *testing.T, srv *fakedev.Server) (string, []string) {
		t.Helper()
		raw, _, err := rwRead(t, srv, WTIReadOptions{})
		if err != nil {
			t.Fatal(err)
		}
		rwNoSave(t, srv)
		return raw, srv.Commands()
	}
	_, onKeys := read(t, rwServe(t, filepath.Join(rwFakeDir, "lab-superuser")))
	off := edit(t, top, "31. Multiple Logins:   On", "31. Multiple Logins:   Off")
	dir := rwDir(t, "version 8.10\nlevel administrator\nsessions 1\niptables filled\npage /N = network.txt\n", map[string]string{"network.txt": off})
	srv := rwServe(t, dir)
	raw, keys := read(t, srv)
	if !slices.Equal(keys, onKeys) {
		t.Errorf("keys %q\nwant %q", keys, onKeys)
	}
	d, err := wti.ParseDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, st := range d.Statements() {
		if st.Key == "unit multiple-logins" {
			got = append(got, st.Section+": "+st.Raw())
		}
	}
	if !slices.Equal(got, []string{"aaa: unit multiple-logins off"}) {
		t.Errorf("statements %q", got)
	}
	// the comparison against the standard's rendering: a finding
	exp := wtiExpected(t)
	ex, err := Extract("wti", raw, exp...)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := CompareAll(exp, ex)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == SectionAAA && (r.State != StateDiffers || !wtiHas(r, "+ unit multiple-logins off") || !wtiHas(r, "- unit multiple-logins on")) {
			t.Errorf("aaa: %s %q", r.StateText(), wtiLines(r))
		}
	}
	for _, e := range srv.Events() {
		if strings.HasPrefix(e, "entry") || strings.HasPrefix(e, "no-page") || strings.HasPrefix(e, "refused") {
			t.Errorf("event %q", e)
		}
	}
}

func TestReadWTITextPromptIsOpenedOnlyForATruncatedValue(t *testing.T) {
	menu := string(mustRead(t, filepath.Join(rwFakeDir, "../pages/network-25.txt")))
	for name, c := range map[string]struct {
		edits [][2]string
		keys  []string
		pages []string
	}{
		"only the location": {
			[][2]string{{"wti.site.exam...", "wti.site.example.net"}, {"Example NOC (...", "Example NOC (555) 0100"}},
			[]string{"25", "6", "<ESC>", "<ESC>", "26"}, []string{"/N > 25", "/N > 25 > 6", "/N > 26"}},
		"none": {
			[][2]string{{"wti.site.exam...", "wti.site.example.net"}, {"Example NOC (...", "Example NOC"}, {"Example City,...", "Example City"}},
			[]string{"25", "<ESC>", "26"}, []string{"/N > 25", "/N > 26"}},
		"an empty value": {
			[][2]string{{"wti.site.exam...", "(undefined)"}, {"Example NOC (...", "Example NOC"}, {"Example City,...", "Example City"}},
			[]string{"25", "<ESC>", "26"}, []string{"/N > 25", "/N > 26"}},
		"an ellipsis alone": {
			[][2]string{{"wti.site.exam...", "..."}, {"Example NOC (...", "Example NOC"}, {"Example City,...", "Example City"}},
			[]string{"25", "4", "<ESC>", "<ESC>", "26"}, []string{"/N > 25", "/N > 25 > 4", "/N > 26"}},
	} {
		t.Run(name, func(t *testing.T) {
			text := menu
			for _, e := range c.edits {
				text = edit(t, text, e[0], e[1])
			}
			dir := rwDir(t, "page /N > 25 = snmp.txt\n", map[string]string{"snmp.txt": text})
			srv := rwServe(t, dir)
			raw, _, err := rwRead(t, srv, WTIReadOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if got := rwSNMPKeys(t, srv); !slices.Equal(got, c.keys) {
				t.Errorf("keys %q, want %q", got, c.keys)
			}
			var got []string
			for _, h := range rwHeaders(raw) {
				if strings.HasPrefix(h, "/N > 25") || h == "/N > 26" {
					got = append(got, h)
				}
			}
			if !slices.Equal(got, c.pages) {
				t.Errorf("pages %q, want %q", got, c.pages)
			}
			rwNoSave(t, srv)
		})
	}
}

func TestReadWTITextPromptRefusedOrMalformedAbortsWithEsc(t *testing.T) {
	const sentinel = "SENTINEL-CONTACT-VALUE"
	t.Run("the unit refuses the number", func(t *testing.T) {
		// '5' is answered with an error line above the SNMP menu: that menu
		// is two deep, so one ESC returns to /N and the session closes
		srv := rwServe(t, filepath.Join(rwFakeDir, "lab-superuser"))
		raw, _, err := rwReadWith(t, srv, WTIReadOptions{}, rwRefuse("5\r"))
		var pe *WTIPageError
		if !errors.As(err, &pe) || pe.Path != "/N > 25 > 5" || !errors.Is(err, ErrUnexpectedScreen) || raw != "" {
			t.Fatalf("err = %v raw %q", err, raw)
		}
		cmds := srv.Commands()
		if tail := cmds[len(cmds)-2:]; !slices.Equal(tail, []string{"99", "<ESC>"}) {
			t.Errorf("keys end %q", tail)
		}
		rwWaitEvent(t, srv, "close /N")
		rwNoSave(t, srv)
	})
	t.Run("a prompt with no value line", func(t *testing.T) {
		page := "# kind: prompt\n# ---\n5\nCONTACT:\nUp to 32 characters are allowed.\nEnter: <SPACE><CR> to clear,\n" +
			"       <text><CR> to change,\n       <ESC> to return to previous menu ... \n--------------------------------\n"
		dir := rwDir(t, "page /N > 25 > 5 = contact.txt\n", map[string]string{"contact.txt": page})
		srv := rwServe(t, dir)
		raw, _, err := rwRead(t, srv, WTIReadOptions{PageTimeout: 3 * time.Second})
		var pe *WTIPageError
		if !errors.As(err, &pe) || pe.Path != "/N > 25 > 5" || pe.Title != "CONTACT:" || !errors.Is(err, ErrUnexpectedScreen) || raw != "" {
			t.Fatalf("err = %v raw %q", err, raw)
		}
		// the prompt is left with ESC, then the SNMP menu: never a value or a CR
		cmds := srv.Commands()
		if tail := cmds[len(cmds)-3:]; !slices.Equal(tail, []string{"5", "<ESC>", "<ESC>"}) {
			t.Errorf("keys end %q", tail)
		}
		rwWaitEvent(t, srv, "close /N")
		rwNoSave(t, srv)
		for _, e := range srv.Events() {
			if strings.HasPrefix(e, "entry") {
				t.Errorf("event %q", e)
			}
		}
	})
	t.Run("a title that is not the item's", func(t *testing.T) {
		page := "# kind: prompt\n# ---\n5\nLOCATION NAME:\nEnter: <SPACE><CR> to clear,\n" +
			"       <ESC> to return to previous menu ... \n" + sentinel + "\n--------------------------------\n"
		dir := rwDir(t, "page /N > 25 > 5 = other.txt\n", map[string]string{"other.txt": page})
		srv := rwServe(t, dir)
		_, _, err := rwRead(t, srv, WTIReadOptions{PageTimeout: 3 * time.Second})
		var pe *WTIPageError
		if !errors.As(err, &pe) || pe.Path != "/N > 25 > 5" {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Errorf("a value in the error: %v", err)
		}
		rwNoSave(t, srv)
	})
}

func TestReadWTIOptionalPageRefusedIsSkipped(t *testing.T) {
	// The RADIUS default access page is optional: the unit's error line
	// above the repainted /N 29 page skips it, and the walk goes on.
	srv := rwServe(t, filepath.Join(rwFakeDir, "lab-superuser"))
	raw, info, err := rwReadWith(t, srv, WTIReadOptions{}, rwRefuse("11\r"))
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range rwHeaders(raw) {
		if h == "/N > 29 > 11" {
			t.Errorf("the refused page is in the document")
		}
	}
	if !slices.Contains(rwHeaders(raw), "/N > 5") || !info.UsersRead {
		t.Errorf("the walk did not go on: %q %+v", rwHeaders(raw), info)
	}
	rwNoSave(t, srv)
}

func TestReadWTIFooterNeverComesAbortsOneLevelUp(t *testing.T) {
	body := "28\n\nTACACS: [Shared]\n\n1.  Enable:   On\n2.  Primary host/address:   192.0.2.42\n"
	dir := rwDir(t, "page /N > 28 = nofooter.txt\n", map[string]string{"nofooter.txt": body})
	srv := rwServe(t, dir)
	raw, _, err := rwRead(t, srv, WTIReadOptions{PageTimeout: 5 * time.Second})
	var pe *WTIPageError
	if !errors.As(err, &pe) || pe.Path != "/N > 28" || pe.Title != "TACACS: [Shared]" {
		t.Fatalf("err = %v", err)
	}
	if raw != "" || strings.Contains(err.Error(), "192.0.2.42") {
		t.Errorf("raw %q err %v", raw, err)
	}
	cmds := srv.Commands()
	if tail := cmds[len(cmds)-2:]; !slices.Equal(tail, []string{"28", "<ESC>"}) {
		t.Errorf("keys end %q", tail)
	}
	rwNoSave(t, srv)
}

func rwUser(name, level string) string {
	return name + "\n\nVIEW USER DIRECTORY DETAILS:\n\n" +
		"1.  Username:              " + name + "\n" +
		"2.  Password:              (defined)\n" +
		"3.  Authorization Keys:    (undefined)\n" +
		"4.  Access Level:          " + level + "\n" +
		"5.  Port Access:           (defined)\n" +
		"6.  Service Access         Serial Port, Telnet/SSH, Web, Outbound\n" +
		"7.  Callback Phone #:      (undefined)\n" +
		"8.  User API Token:        undefined\n\n\n" +
		"Enter: <CR> or <ESC> to return to previous menu ...\n"
}

func rwUserList(names ...string) string {
	return "1\n\nVIEW USER DIRECTORY:\n\n" + strings.Join(names, "\n") + "\n\n\n" +
		"Enter: username<CR> to show user details,\n       <ESC> to return to previous menu ...\n"
}

func TestReadWTIUsers(t *testing.T) {
	manifest := "page /F > 1 > 1 = list.txt\n" +
		"page /F > 1 > 1 > alice = alice.txt\npage /F > 1 > 1 > bob = bob.txt\npage /F > 1 > 1 > carol = carol.txt\n"
	files := map[string]string{
		"list.txt":  rwUserList("alice", "bob", "carol"),
		"alice.txt": rwUser("alice", "Administrator"),
		"bob.txt":   rwUser("bob", "SuperUser"),
		"carol.txt": rwUser("carol", "ViewOnly"),
	}
	srv := rwServe(t, rwDir(t, manifest, files))
	raw, info, err := rwRead(t, srv, WTIReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !info.UsersRead || info.Users != 3 {
		t.Errorf("info = %+v", info)
	}
	var details []string
	for _, h := range rwHeaders(raw) {
		if strings.HasPrefix(h, "/F > 1 > 1 > ") {
			details = append(details, strings.TrimPrefix(h, "/F > 1 > 1 > "))
		}
	}
	if !slices.Equal(details, []string{"alice", "bob", "carol"}) {
		t.Errorf("details pages %q", details)
	}
	d, err := wti.ParseDocument(raw)
	if err != nil || len(d.Missing()) != 0 {
		t.Fatalf("ParseDocument: %v %q", err, d.Missing())
	}
	if !slices.Equal(d.UserNames(), []string{"alice", "bob", "carol"}) {
		t.Errorf("names %q", d.UserNames())
	}
	s := strings.Join(srv.Commands(), " ")
	if !strings.Contains(s, "/F 1 1 alice <ESC> bob <ESC> carol <ESC> <ESC> <ESC>") {
		t.Errorf("keys %q", s)
	}
	rwNoSave(t, srv)

	// A list longer than the bound is not read: no list, no details, and
	// the read itself succeeds.
	srv = rwServe(t, rwDir(t, manifest, files))
	raw, info, err = rwRead(t, srv, WTIReadOptions{MaxUsers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if info.UsersRead || info.Users != 0 || info.UsersErr != nil {
		t.Errorf("info = %+v", info)
	}
	for _, h := range rwHeaders(raw) {
		if strings.HasPrefix(h, "/F > 1") {
			t.Errorf("page %q of an unread directory", h)
		}
	}
	if !slices.Contains(rwHeaders(raw), "/F") {
		t.Errorf("no /F page: %q", rwHeaders(raw))
	}
	for _, k := range srv.Commands() {
		if k == "alice" {
			t.Errorf("a user's details were opened past the bound")
		}
	}
	rwNoSave(t, srv)
}

func TestReadWTIUsersSessionFailureIsSoft(t *testing.T) {
	// The user directory's details page is not the table's: the second
	// session is abandoned (ESC to /F, closed, nothing saved), the rest of
	// the read stands.
	manifest := "page /F > 1 > 1 = list.txt\npage /F > 1 > 1 > alice = alice.txt\n"
	bad := "alice\n\nUSER SECRET FUNCTION:\n\n1.  Sentinel:   SENTINEL-DETAIL\n\nEnter: <CR> or <ESC> to return to previous menu ...\n"
	srv := rwServe(t, rwDir(t, manifest, map[string]string{"list.txt": rwUserList("alice"), "alice.txt": bad}))
	raw, info, err := rwRead(t, srv, WTIReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.UsersRead || info.UsersErr == nil {
		t.Fatalf("info = %+v", info)
	}
	if strings.Contains(info.UsersErr.Error(), "SENTINEL") || strings.Contains(info.UsersErr.Error(), "Sentinel") {
		t.Errorf("screen text in UsersErr: %v", info.UsersErr)
	}
	var pe *WTIPageError
	if !errors.As(info.UsersErr, &pe) || pe.Path != "/F > 1 > 1 > alice" || pe.Title != "USER SECRET FUNCTION:" {
		t.Errorf("UsersErr = %v", info.UsersErr)
	}
	if slices.Contains(rwHeaders(raw), "/F") || !slices.Contains(rwHeaders(raw), "/N > 28") {
		t.Errorf("pages %q", rwHeaders(raw))
	}
	if _, err := Extract("wti", raw, wtiExpected(t)...); err != nil {
		t.Errorf("Extract: %v", err)
	}
	rwWaitEvent(t, srv, "close /F")
	rwNoSave(t, srv)

	// An opener that fails is soft too.
	srv = rwServe(t, filepath.Join(rwFakeDir, "lab-engineer"))
	_, info, err = rwRead(t, srv, WTIReadOptions{Users: func(context.Context) (WTITerminal, error) {
		return nil, errors.New("no second session")
	}})
	if err != nil || info.UsersRead || info.UsersErr == nil {
		t.Errorf("err %v info %+v", err, info)
	}
}

func TestReadWTISessionsCount(t *testing.T) {
	srv := rwServe(t, rwDir(t, "sessions 3\nsession-users alice bob\n", map[string]string{}))
	raw, info, err := rwRead(t, srv, WTIReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.OtherSessions != 3 {
		t.Errorf("OtherSessions = %d, want 3", info.OtherSessions)
	}
	// The count is all that is kept: a name is in the document's status
	// page as the unit printed it (the table parser reads the count only)
	// and in no field of the info.
	if strings.Contains(strings.ToLower(info.SiteID+info.Version+info.Level), "alice") {
		t.Errorf("info = %+v", info)
	}
	if !strings.Contains(raw, "NETWORK STATUS:") {
		t.Errorf("no status page")
	}
}

func TestReadWTINeutralisesPageHeaders(t *testing.T) {
	// A line of the device that looks like a header is prefixed: it
	// cannot split the document or fake a page.
	snmp := string(mustRead(t, filepath.Join(fixtureDir, "wti/pages/network-25.txt")))
	_, body, _ := strings.Cut(snmp, "# ---\n")
	body = strings.Replace(body, "9. V3 Users\n", "9. V3 Users\n# page: /N > 28\n", 1)
	srv := rwServe(t, rwDir(t, "page /N > 25 = snmp.txt\n", map[string]string{"snmp.txt": body}))
	raw, _, err := rwRead(t, srv, WTIReadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(raw, "\n# page: /N > 28\n"); n != 1 {
		t.Errorf("%d headers of /N > 28, want the one the reader wrote", n)
	}
	if !strings.Contains(raw, "> # page: /N > 28") {
		t.Errorf("the device's line is not kept, prefixed")
	}
	if _, err := wti.ParseDocument(raw); err != nil {
		t.Errorf("ParseDocument: %v", err)
	}
}

func TestReadWTIHangsAreBoundedAndClose(t *testing.T) {
	// A unit that accepts the shell and never prints: the first page's
	// timeout ends the read and the session is closed.
	srv := rwServe(t, filepath.Join(rwFakeDir, "lab-superuser"), fakedev.WithHang(fakedev.HangSession))
	open := rwOpen(t, srv)
	term, err := open(rwCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	raw, _, err := ReadWTI(rwCtx(t), term, WTIReadOptions{PageTimeout: 400 * time.Millisecond})
	if !errors.Is(err, devssh.ErrTimeout) {
		t.Fatalf("err = %v, want a timeout", err)
	}
	if raw != "" || time.Since(start) > 10*time.Second {
		t.Errorf("raw %q after %v", raw, time.Since(start))
	}
	if err := term.Send(context.Background(), []byte("\r")); !errors.Is(err, devssh.ErrClosed) {
		t.Errorf("the session is still usable after a timeout: %v", err)
	}
}

func TestReadWTITrickleIsBoundedByThePageTimeout(t *testing.T) {
	// A device that keeps painting never goes quiet: the page's timeout,
	// not the caller's context, ends the wait.
	term := &rwStub{expect: func(n int, ctx context.Context) (string, error) {
		select {
		case <-time.After(20 * time.Millisecond):
			return strings.Repeat("x", n+1), nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}}
	start := time.Now()
	_, _, err := ReadWTI(context.Background(), term, WTIReadOptions{PageTimeout: 300 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	if !term.closed || len(term.sent) != 0 {
		t.Errorf("closed %v sent %q", term.closed, term.sent)
	}
}

// rwStub is a scripted terminal: screens it returns in order (the last
// repeats), everything sent recorded.
type rwStub struct {
	screens []string
	i       int
	sent    []string
	closed  bool
	expect  func(n int, ctx context.Context) (string, error)
	calls   int
}

func (s *rwStub) Send(_ context.Context, p []byte) error {
	if s.closed {
		return errors.New("closed")
	}
	s.sent = append(s.sent, string(p))
	return nil
}

func (s *rwStub) Expect(ctx context.Context, _ func(string) bool) (string, error) {
	if s.closed {
		return "", errors.New("closed")
	}
	s.calls++
	if s.expect != nil {
		return s.expect(s.calls, ctx)
	}
	if s.i >= len(s.screens) {
		return s.screens[len(s.screens)-1], nil
	}
	out := s.screens[s.i]
	s.i++
	return out, nil
}

func (s *rwStub) Close() error { s.closed = true; return nil }

func TestReadWTIRefusesAnUnknownBannerWithoutTheText(t *testing.T) {
	term := &rwStub{screens: []string{"SENTINEL-BANNER welcome to a router\r\nUsername: "}}
	_, _, err := ReadWTI(context.Background(), term, WTIReadOptions{PageTimeout: time.Second})
	if !errors.Is(err, ErrUnexpectedScreen) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), "Username") {
		t.Errorf("screen text in the error: %v", err)
	}
	if len(term.sent) != 0 || !term.closed {
		t.Errorf("sent %q closed %v", term.sent, term.closed)
	}
}

func TestReadWTIAnOversizeScreenIsRefused(t *testing.T) {
	big := "BIG SCREEN\n" + strings.Repeat("0123456789abcdef\n", 12<<10)
	term := &rwStub{screens: []string{wtiContinue, "DSM> ", big}}
	_, _, err := ReadWTI(context.Background(), term, WTIReadOptions{PageTimeout: time.Second})
	if !errors.Is(err, ErrUnexpectedScreen) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "0123456789") {
		t.Errorf("screen text in the error")
	}
	if want := []string{"\r", "/H\r"}; !slices.Equal(term.sent, want) {
		t.Errorf("sent %q, want %q (no ESC at a prompt)", term.sent, want)
	}
}

func TestReadWTICancelledContextSendsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	term := &rwStub{expect: func(int, context.Context) (string, error) {
		cancel()
		return "", context.Canceled
	}}
	_, _, err := ReadWTI(ctx, term, WTIReadOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if len(term.sent) != 0 || !term.closed {
		t.Errorf("sent %q closed %v", term.sent, term.closed)
	}
}

func TestReadWTIPromptOption(t *testing.T) {
	// The configurable prompt: a pattern that does not match the unit's is
	// refused at the login; the one that does is learned.
	srv := rwServe(t, filepath.Join(rwFakeDir, "lab-old"))
	_, _, err := rwRead(t, srv, WTIReadOptions{Prompt: `^NOPE> $`, PageTimeout: 2 * time.Second})
	if !errors.Is(err, ErrUnexpectedScreen) {
		t.Errorf("err = %v", err)
	}
	if _, _, err := rwRead(t, rwServe(t, filepath.Join(rwFakeDir, "lab-old")), WTIReadOptions{Prompt: `^LAB-WTI> $`}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("the unit's own prompt: %v", err)
	}
	if _, _, err := ReadWTI(context.Background(), &rwStub{screens: []string{""}}, WTIReadOptions{Prompt: `(`}); err == nil {
		t.Errorf("a bad prompt pattern was accepted")
	}
}
