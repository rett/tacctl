package devssh_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// The fake WTI units of tests/fixtures/devconf/wti/fake, driven through
// Client.Terminal the way the WTI reader will drive them.

const wtiFakeDir = "../../tests/fixtures/devconf/wti/fake"

// wtiScreens is the captures' directory as a manifest in a temporary
// directory names it.
func wtiScreens(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(wtiFakeDir, ".."))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type wtiUnit struct {
	t    *testing.T
	srv  *fakedev.Server
	s    devssh.TermSession
	user string
}

// openWTI starts the named fixture unit and opens a terminal on it; the
// banner is not read.
func openWTI(t *testing.T, name string, opts ...fakedev.Option) *wtiUnit {
	t.Helper()
	return openWTIDir(t, filepath.Join(wtiFakeDir, name), opts...)
}

func openWTIDir(t *testing.T, dir string, opts ...fakedev.Option) *wtiUnit {
	t.Helper()
	srv := serve(t, dir, opts...)
	c := dial(t, target(t, srv, nil))
	s, err := c.Terminal(bg())
	if err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return &wtiUnit{t: t, srv: srv, s: s, user: fakedev.DefaultUser}
}

func (u *wtiUnit) ctx() context.Context {
	u.t.Helper()
	ctx, cancel := context.WithTimeout(bg(), 10*time.Second)
	u.t.Cleanup(cancel)
	return ctx
}

// send types text.
func (u *wtiUnit) send(text string) {
	u.t.Helper()
	if err := u.s.Send(u.ctx(), []byte(text)); err != nil {
		u.t.Fatalf("Send(%q): %v", text, err)
	}
}

// expect is the screen up to the point done holds.
func (u *wtiUnit) expect(done func(string) bool) string {
	u.t.Helper()
	out, err := u.s.Expect(u.ctx(), done)
	if err != nil {
		u.t.Fatalf("Expect: %v (screen so far %q)", err, out)
	}
	return out
}

func isPrompt(prompt string) func(string) bool {
	return func(s string) bool { return strings.HasSuffix(s, prompt) }
}

// atFooter is a menu page's end: its footer ends in '...'.
func atFooter(s string) bool {
	return strings.HasSuffix(strings.TrimRight(s, " \n"), "...")
}

// login answers the banner and returns the port list screen.
func (u *wtiUnit) login(prompt string) string {
	u.t.Helper()
	b := u.expect(contains("Do you wish to continue? (<CR> to continue, /X to exit)"))
	if !strings.Contains(b, "Unauthorized Access is Prohibited!") {
		u.t.Errorf("no banner: %q", b)
	}
	u.send("\r")
	return u.expect(isPrompt(prompt))
}

// page types text and returns the screen it paints, up to its footer.
func (u *wtiUnit) page(text string) string {
	u.t.Helper()
	u.send(text)
	return u.expect(atFooter)
}

// help types /H and answers every pager with answer; it returns the text
// of all the pages.
func (u *wtiUnit) help(prompt, answer string) string {
	u.t.Helper()
	u.send("/H\r")
	var all strings.Builder
	for i := 0; ; i++ {
		s := u.expect(func(s string) bool {
			return strings.HasSuffix(s, prompt) || strings.HasSuffix(s, "Enter: SPACE for page, ENTER for line")
		})
		all.WriteString(s)
		all.WriteString("\n")
		if strings.HasSuffix(s, prompt) {
			return all.String()
		}
		if i > 5 {
			u.t.Fatalf("pager does not end: %q", all.String())
		}
		u.send(answer)
	}
}

// waitEvent waits for an event the server logs after the client acted.
func waitEvent(t *testing.T, srv *fakedev.Server, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, e := range srv.Events() {
			if e == want {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("event %q never logged; events %q", want, srv.Events())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWTIFakeBannerAndPortList(t *testing.T) {
	u := openWTI(t, "lab-superuser")
	ports := u.login("DSM> ")
	for _, want := range []string{"Console Server", "Site ID: wti.site.example.net", "PORT|", "Enter /H for command menu."} {
		if !strings.Contains(ports, want) {
			t.Errorf("port list lacks %q:\n%s", want, ports)
		}
	}
	if strings.Contains(ports, "Do you wish to continue") {
		t.Errorf("the banner is still on the screen: %q", ports)
	}
	// A second CR at the prompt is a fresh prompt, no error.
	u.send("\r")
	if s := u.expect(isPrompt("DSM> ")); strings.Contains(s, "Invalid") {
		t.Errorf("an empty line was refused: %q", s)
	}
	if got := u.srv.Commands(); len(got) != 2 || got[0] != "<CR>" || got[1] != "<CR>" {
		t.Errorf("Commands = %q", got)
	}
}

func TestWTIFakeBannerAsksAgainAndExit(t *testing.T) {
	u := openWTI(t, "lab-user")
	u.expect(contains("Do you wish to continue?"))
	u.send("hello\r")
	if s := u.expect(contains("Do you wish to continue?")); !strings.Contains(s, "hello") {
		t.Errorf("no echo: %q", s)
	}
	u.send("/X\r")
	if _, err := u.s.Expect(u.ctx(), never); !errors.Is(err, devssh.ErrClosed) {
		t.Errorf("after /X: err = %v, want ErrClosed", err)
	}
	waitEvent(t, u.srv, "exit")
}

func TestWTIFakeHelpPerLevel(t *testing.T) {
	cases := []struct {
		unit    string
		present []string
		absent  []string
	}{
		{"lab-viewonly",
			[]string{"COMMAND MENU:", "Version 8.10", "/SN           Network Status", "/TELNET <ip>", "| n   Port #/name", "| ,   Link multiple plug commands |"},
			[]string{"/N [*]", "CONFIGURATION COMMANDS", "/C <n> [n]"}},
		{"lab-user",
			[]string{"/C <n> [n]    Connect", "/E            Erase Buffer", "| ,   Link multiple plug commands |"},
			[]string{"/N [*]", "/TEST", "CONFIGURATION COMMANDS"}},
		{"lab-engineer",
			[]string{"/V            View Port", "/TEST", "CONFIGURATION COMMANDS", "/N [*]        Network Configuration", "/AC           Alarm Configuration"},
			[]string{"/UFW", "/WOF"}},
		{"lab-superuser",
			[]string{"/UFW          Upgrade Firmware", "/WOF", "/DF [ztp]", "CONFIGURATION COMMANDS", "/N [*]        Network Configuration", "| ,   Link multiple plug commands |"},
			nil},
	}
	for _, c := range cases {
		t.Run(c.unit, func(t *testing.T) {
			u := openWTI(t, c.unit)
			u.login("DSM> ")
			text := u.help("DSM> ", " ")
			for _, w := range c.present {
				if !strings.Contains(text, w) {
					t.Errorf("/H lacks %q:\n%s", w, text)
				}
			}
			for _, w := range c.absent {
				if strings.Contains(text, w) {
					t.Errorf("/H holds %q:\n%s", w, text)
				}
			}
			// The pager prompt was answered, not printed into the text of the
			// last page, and the erase left no residue of it.
			last := text[strings.LastIndex(text, "Enter: SPACE")+1:]
			if strings.Contains(last, "Enter: SPACE for page, ENTER for line") {
				t.Errorf("the pager prompt stays: %q", last)
			}
		})
	}
}

func TestWTIFakeHelpPagerKeys(t *testing.T) {
	// ENTER gives one line and asks again.
	u := openWTI(t, "lab-user")
	u.login("DSM> ")
	u.send("/H\r")
	u.expect(contains("Enter: SPACE for page, ENTER for line"))
	u.send("\r")
	s := u.expect(func(s string) bool { return strings.HasSuffix(s, "Enter: SPACE for page, ENTER for line") })
	if !strings.Contains(s, "| n   Port #/name") || strings.Contains(s, "| Nn  Network port #") {
		t.Errorf("ENTER must give one line only: %q", s)
	}
	// q ends the listing at the prompt.
	u.send("q")
	s = u.expect(isPrompt("DSM> "))
	if strings.Contains(s, "| ,   Link") {
		t.Errorf("q did not stop the listing: %q", s)
	}
	if got := u.srv.Commands(); got[len(got)-1] != "q" {
		t.Errorf("Commands = %q", got)
	}
}

func TestWTIFakeLevelRefusesWhatHelpDoesNotList(t *testing.T) {
	u := openWTI(t, "lab-user")
	u.login("DSM> ")
	for _, cmd := range []string{"/N", "/F", "/P", "/AC"} {
		u.send(cmd + "\r")
		s := u.expect(isPrompt("DSM> "))
		if !strings.Contains(s, "Invalid command") || strings.Contains(s, "PARAMETERS") {
			t.Errorf("%s at User level: %q", cmd, s)
		}
		waitEvent(t, u.srv, "refused "+cmd)
	}
	// What the level lists works; a lower-case command is the same.
	u.send("/j\r")
	if s := u.expect(isPrompt("DSM> ")); !strings.Contains(s, "Site ID: wti.site.example.net") {
		t.Errorf("/J: %q", s)
	}
	// A number is no command.
	u.send("28\r")
	u.expect(isPrompt("DSM> "))
	waitEvent(t, u.srv, "invalid")
}

func TestWTIFakeNetworkStatus(t *testing.T) {
	u := openWTI(t, "lab-superuser")
	u.login("DSM> ")
	u.send("/SN\r")
	s := u.expect(contains("<ESC> to quit"))
	if !strings.Contains(s, "NETWORK STATUS:") || !strings.HasSuffix(strings.TrimRight(s, " "), "Enter: <CR> for more ports, <ESC> to quit ...") {
		t.Errorf("status screen:\n%s", s)
	}
	active, own := 0, 0
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "|Active|") {
			active++
		}
		if strings.Contains(l, "|"+u.user+" ") {
			own++
		}
	}
	// One other session and the login's own.
	if active != 2 || own != 1 || !strings.Contains(s, "N1  |      22|Active|user1 ") {
		t.Errorf("sessions: active %d own %d:\n%s", active, own, s)
	}
	u.send("\x1b")
	u.expect(isPrompt("DSM> "))
	if got := u.srv.Commands(); got[len(got)-1] != "<ESC>" {
		t.Errorf("Commands = %q", got)
	}
	if len(u.srv.Saved()) != 0 {
		t.Errorf("a status listing saved: %q", u.srv.Events())
	}
	// No other session on an engineer unit.
	e := openWTI(t, "lab-engineer")
	e.login("DSM> ")
	e.send("/SN\r")
	s = e.expect(contains("<ESC> to quit"))
	if n := strings.Count(s, "|Active|"); n != 1 {
		t.Errorf("lab-engineer shows %d active sessions, want only its own:\n%s", n, s)
	}
}

func TestWTIFakeSessionUsersAndSiteID(t *testing.T) {
	dir := t.TempDir()
	manifest := "screens " + wtiScreens(t) + "\nsessions 3\nsession-users alice " + fakedev.DefaultUser + "\n"
	if err := os.WriteFile(filepath.Join(dir, "menu"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	u := openWTIDir(t, dir)
	u.login("DSM> ")
	u.send("/SN\r")
	s := u.expect(contains("<ESC> to quit"))
	for _, want := range []string{"|alice ", "|user3 ", "|" + fakedev.DefaultUser + " "} {
		if !strings.Contains(s, want) {
			t.Errorf("status lacks %q:\n%s", want, s)
		}
	}
	if n := strings.Count(s, "|Active|"); n != 4 {
		t.Errorf("%d active rows, want 4", n)
	}
}

func TestWTIFakeWalkAndBackWithoutSaving(t *testing.T) {
	u := openWTI(t, "lab-superuser")
	u.login("DSM> ")
	top := u.page("/N\r")
	for _, want := range []string{"NETWORK PARAMETERS: [eth0] IPv4", "5.  IP Tables:         On ", "28. TACACS:            On", "<ESC> to exit and save configuration ..."} {
		if !strings.Contains(top, want) {
			t.Errorf("/N lacks %q:\n%s", want, top)
		}
	}
	tac := u.page("28\r")
	for _, want := range []string{"TACACS: [Shared]", "4.  Secret Word:                (defined)", "8.  Default User Access:        On", "<ESC> to return to previous menu ..."} {
		if !strings.Contains(tac, want) {
			t.Errorf("/N 28 lacks %q:\n%s", want, tac)
		}
	}
	if strings.Contains(tac, "NETWORK PARAMETERS") {
		t.Errorf("the /N screen is still there: %q", tac)
	}
	acc := u.page("8\r")
	if !strings.Contains(acc, "TACACS Default User Access: [Shared]:") || !strings.Contains(acc, "2.  Access Level:         View Only") {
		t.Errorf("/N 28 8:\n%s", acc)
	}
	// ESC goes up one level at a time and repaints the parent.
	if back := u.page("\x1b"); !strings.Contains(back, "TACACS: [Shared]") || strings.Contains(back, "Saving configuration") {
		t.Errorf("ESC from /N 28 8:\n%s", back)
	}
	if back := u.page("\x1b"); !strings.Contains(back, "NETWORK PARAMETERS") || strings.Contains(back, "Saving configuration") {
		t.Errorf("ESC from /N 28:\n%s", back)
	}
	// The read ends here, on a page: closing sends nothing and the unit
	// never wrote its configuration.
	if err := u.s.Close(); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, u.srv, "close /N")
	if got := u.srv.Saved(); len(got) != 0 {
		t.Errorf("Saved = %q after a walk that closed on a page", got)
	}
	for _, e := range u.srv.Events() {
		if strings.HasPrefix(e, "save") || strings.Contains(e, "Saving") {
			t.Errorf("event %q", e)
		}
	}
	want := []string{"<CR>", "/N", "28", "8", "<ESC>", "<ESC>"}
	if got := u.srv.Commands(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("Commands = %q, want %q", got, want)
	}
}

func TestWTIFakeEscAtTopSaves(t *testing.T) {
	u := openWTI(t, "lab-engineer")
	u.login("DSM> ")
	for _, top := range []string{"/N", "/F", "/P", "/AC"} {
		u.page(top + "\r")
		u.send("\x1b")
		s := u.expect(isPrompt("DSM> "))
		if !strings.Contains(s, "Saving configuration to flash - Please wait...") {
			t.Errorf("ESC at the top of %s: %q", top, s)
		}
	}
	got := u.srv.Saved()
	if strings.Join(got, ",") != "/N,/F,/P,/AC" {
		t.Errorf("Saved = %q", got)
	}
}

func TestWTIFakeTopLevelPages(t *testing.T) {
	u := openWTI(t, "lab-engineer")
	u.login("DSM> ")
	for _, c := range []struct{ cmd, want string }{
		{"/F", "SYSTEM PARAMETERS:"},
		{"/P", "PORT PARAMETERS #01:"},
		{"/AC", "ALARM CONFIGURATION:"},
		{"/N", "5.  IP Tables:         Off"},
	} {
		s := u.page(c.cmd + "\r")
		if !strings.Contains(s, c.want) {
			t.Errorf("%s lacks %q:\n%s", c.cmd, c.want, s)
		}
		u.send("\x1b")
		u.expect(isPrompt("DSM> "))
	}
}

func TestWTIFakeIPTablesPages(t *testing.T) {
	u := openWTI(t, "lab-superuser")
	u.login("DSM> ")
	u.page("/N\r")
	p1 := u.page("5\r")
	for _, want := range []string{"IPTABLES ENTRIES: IPv4", "1.  iptables -A INPUT -i lo -j ACCEPT", "12. iptables -A INPUT -s 10.0.60.0/24 -p tcp --dport 22 -j ACCEPT", "'>' for next entries,"} {
		if !strings.Contains(p1, want) {
			t.Errorf("page 1 lacks %q:\n%s", want, p1)
		}
	}
	p2 := u.page(">\r")
	if !strings.Contains(p2, "13. iptables -A INPUT -s 10.0.70.0/24") || !strings.Contains(p2, "24. iptables -P OUTPUT DROP") || strings.Contains(p2, "1.  iptables") {
		t.Errorf("page 2:\n%s", p2)
	}
	p3 := u.page(">\r")
	if !strings.Contains(p3, "25. iptables -P FORWARD DROP") || !strings.Contains(p3, "26.\n") || !strings.Contains(p3, "36.\n") {
		t.Errorf("page 3:\n%s", p3)
	}
	p4 := u.page(">\r")
	if !strings.Contains(p4, "37.\n") || !strings.Contains(p4, "48.") || strings.Contains(p4, "iptables -") {
		t.Errorf("page 4:\n%s", p4)
	}
	if p5 := u.page(">\r"); !strings.Contains(p5, "37.\n") {
		t.Errorf("past the last page:\n%s", p5)
	}
	if back := u.page("<\r"); !strings.Contains(back, "25. iptables -P FORWARD DROP") {
		t.Errorf("'<':\n%s", back)
	}
	// ESC returns to /N; entering the list again starts on its first page.
	if top := u.page("\x1b"); !strings.Contains(top, "NETWORK PARAMETERS") {
		t.Errorf("ESC from the list:\n%s", top)
	}
	if again := u.page("5\r"); !strings.Contains(again, "1.  iptables -A INPUT -i lo") {
		t.Errorf("list again:\n%s", again)
	}
	if got := u.srv.Saved(); len(got) != 0 {
		t.Errorf("Saved = %q", got)
	}
}

func TestWTIFakeIPTablesEmpty(t *testing.T) {
	u := openWTI(t, "lab-engineer")
	u.login("DSM> ")
	u.page("/N\r")
	p := u.page("5\r")
	if !strings.Contains(p, "IPTABLES ENTRIES: IPv4") || !strings.Contains(p, "\n1.\n") || !strings.Contains(p, "\n12.\n") || strings.Contains(p, "iptables -") {
		t.Errorf("empty list:\n%s", p)
	}
	if next := u.page(">\r"); !strings.Contains(next, "\n13.\n") {
		t.Errorf("empty list, next:\n%s", next)
	}
}

func TestWTIFakeIPTablesFromFile(t *testing.T) {
	dir := t.TempDir()
	var list strings.Builder
	list.WriteString("iptables -A INPUT -j ACCEPT\niptables -P INPUT DROP\n")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("list", list.String())
	write("menu", "screens "+wtiScreens(t)+"\niptables file list\n")
	u := openWTIDir(t, dir)
	u.login("DSM> ")
	u.page("/N\r")
	p := u.page("5\r")
	if !strings.Contains(p, "1.  iptables -A INPUT -j ACCEPT") || !strings.Contains(p, "2.  iptables -P INPUT DROP") || !strings.Contains(p, "\n3.\n") {
		t.Errorf("list from a file:\n%s", p)
	}
}

func TestWTIFakeUserDirectory(t *testing.T) {
	u := openWTI(t, "lab-superuser")
	u.login("DSM> ")
	u.page("/F\r")
	if menu := u.page("1\r"); !strings.Contains(menu, "1. View User Directory") {
		t.Errorf("/F 1:\n%s", menu)
	}
	view := u.page("1\r")
	if !strings.Contains(view, "VIEW USER DIRECTORY:") || !strings.Contains(view, "\nlocaladmin\n") || !strings.Contains(view, "Enter: username<CR> to show user details,") {
		t.Errorf("view:\n%s", view)
	}
	det := u.page("localadmin\r")
	for _, want := range []string{"VIEW USER DIRECTORY DETAILS:", "1.  Username:              localadmin", "2.  Password:              (defined)", "4.  Access Level:          Administrator", "Enter: <CR> or <ESC> to return to previous menu ..."} {
		if !strings.Contains(det, want) {
			t.Errorf("details lack %q:\n%s", want, det)
		}
	}
	// CR at the details returns to the list.
	if back := u.page("\r"); !strings.Contains(back, "VIEW USER DIRECTORY:") {
		t.Errorf("CR at details:\n%s", back)
	}
	// An unknown name is an invalid entry and logs no details.
	if bad := u.page("nobody\r"); !strings.Contains(bad, "ERROR: Invalid entry.") || !strings.Contains(bad, "VIEW USER DIRECTORY:") {
		t.Errorf("unknown name:\n%s", bad)
	}
	for _, up := range []string{"USER DIRECTORY:", "SYSTEM PARAMETERS:"} {
		if s := u.page("\x1b"); !strings.Contains(s, up) {
			t.Errorf("ESC: want %q:\n%s", up, s)
		}
	}
}

func TestWTIFakeUnknownEntries(t *testing.T) {
	u := openWTI(t, "lab-superuser")
	u.login("DSM> ")
	u.page("/N\r")
	// A number with no page.
	s := u.page("99\r")
	if !strings.Contains(s, "ERROR: Invalid entry.") || !strings.Contains(s, "NETWORK PARAMETERS") {
		t.Errorf("99:\n%s", s)
	}
	waitEvent(t, u.srv, "no-page /N > 99")
	// Text at a menu.
	s = u.page("abc\r")
	if !strings.Contains(s, "ERROR: Invalid entry.") {
		t.Errorf("abc:\n%s", s)
	}
	waitEvent(t, u.srv, "no-page /N")
	// A pick page takes no value: the fake is read-only.
	u.page("28\r")
	u.page("1\r")
	s = u.page("2\r")
	if !strings.Contains(s, "ERROR: Invalid entry.") || !strings.Contains(s, "ENABLE:") {
		t.Errorf("value at a pick page:\n%s", s)
	}
	waitEvent(t, u.srv, "entry /N > 28 > 1")
	// '>' is no key at an ordinary page.
	s = u.page(">\r")
	if !strings.Contains(s, "ERROR: Invalid entry.") {
		t.Errorf("'>' at a pick page:\n%s", s)
	}
	// The secret word page (4) has no capture: opening it is refused, so
	// no reader can print the secret off this fake.
	u.page("\x1b")
	s = u.page("4\r")
	if !strings.Contains(s, "ERROR: Invalid entry.") || !strings.Contains(s, "TACACS: [Shared]") {
		t.Errorf("/N 28 4:\n%s", s)
	}
	waitEvent(t, u.srv, "no-page /N > 28 > 4")
}

// The SNMP texts' prompt pages print the whole value under the footer and
// take nothing: a value or a CR is an 'entry' event and the page again, ESC
// repaints the SNMP access menu, and no save is logged.
func TestWTIFakeTextPromptPages(t *testing.T) {
	u := openWTI(t, "lab-superuser")
	u.login("DSM> ")
	u.page("/N\r")
	menu := u.page("25\r")
	for _, want := range []string{"4. System Name:            wti.site.exam...", "5. Contact:                Example NOC (...", "6. SNMP Location:          Example City,..."} {
		if !strings.Contains(menu, want) {
			t.Errorf("the menu lacks %q:\n%s", want, menu)
		}
	}
	atRule := func(s string) bool { return strings.HasSuffix(strings.TrimRight(s, " \n"), "--------") }
	for _, c := range []struct{ key, title, limit, value string }{
		{"4", "SYSTEM NAME:", "Up to 32 characters are allowed.", "wti.site.example.net"},
		{"5", "CONTACT:", "Up to 32 characters are allowed.", "Example NOC (555) 0100"},
		{"6", "SNMP LOCATION:", "Up to 64 characters are allowed.", "Example City, Example State"},
	} {
		u.send(c.key + "\r")
		s := u.expect(atRule)
		for _, want := range []string{c.title, c.limit, "<ESC> to return to previous menu", "\n" + c.value + "\n---"} {
			if !strings.Contains(s, want) {
				t.Errorf("page %s lacks %q:\n%q", c.key, want, s)
			}
		}
		u.send("\x1b")
		if back := u.expect(atFooter); !strings.Contains(back, "SNMP ACCESS:") {
			t.Errorf("ESC at page %s:\n%s", c.key, back)
		}
	}
	// a value is not taken, and neither is a CR alone
	u.send("4\r")
	u.expect(atRule)
	u.send("changed.example.net\r")
	s := u.expect(atRule)
	if !strings.Contains(s, "ERROR: Invalid entry.") || !strings.Contains(s, "wti.site.example.net") || strings.Contains(s, "changed.example.net\n---") {
		t.Errorf("a value at the prompt:\n%q", s)
	}
	u.send("\r")
	if s := u.expect(atRule); !strings.Contains(s, "wti.site.example.net") || strings.Contains(s, "ERROR:") {
		t.Errorf("a CR at the prompt:\n%q", s)
	}
	waitEvent(t, u.srv, "entry /N > 25 > 4")
	entries := 0
	for _, e := range u.srv.Events() {
		if e == "entry /N > 25 > 4" {
			entries++
		}
		if strings.HasPrefix(e, "save") {
			t.Errorf("event %q", e)
		}
	}
	if entries != 2 {
		t.Errorf("%d entry events, want 2: %q", entries, u.srv.Events())
	}
	u.send("\x1b")
	u.expect(atFooter)
	// the communities' prompts have no page
	s = u.page("7\r")
	if !strings.Contains(s, "ERROR: Invalid entry.") || !strings.Contains(s, "SNMP ACCESS:") {
		t.Errorf("/N 25 7:\n%s", s)
	}
	waitEvent(t, u.srv, "no-page /N > 25 > 7")
}

func TestWTIFakeCloseMidPager(t *testing.T) {
	u := openWTI(t, "lab-superuser")
	u.login("DSM> ")
	u.send("/H\r")
	u.expect(contains("Enter: SPACE for page, ENTER for line"))
	if err := u.s.Close(); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, u.srv, "close /H")
	if _, err := u.s.Expect(bg(), never); !errors.Is(err, devssh.ErrClosed) {
		t.Errorf("Expect after Close: %v", err)
	}
}

func TestWTIFakeCloseAtBannerPromptAndStatus(t *testing.T) {
	u := openWTI(t, "lab-superuser")
	u.expect(contains("Do you wish to continue?"))
	_ = u.s.Close()
	waitEvent(t, u.srv, "close banner")

	v := openWTI(t, "lab-superuser")
	v.login("DSM> ")
	_ = v.s.Close()
	waitEvent(t, v.srv, "close prompt")

	w := openWTI(t, "lab-superuser")
	w.login("DSM> ")
	w.send("/SN\r")
	w.expect(contains("<ESC> to quit"))
	_ = w.s.Close()
	waitEvent(t, w.srv, "close /SN")
}

func TestWTIFakeOldVersion(t *testing.T) {
	u := openWTI(t, "lab-old")
	ports := u.login("LAB-WTI> ")
	if !strings.HasSuffix(ports, "LAB-WTI> ") {
		t.Errorf("prompt: %q", ports)
	}
	text := u.help("LAB-WTI> ", " ")
	if !strings.Contains(text, "Version 7.4") || strings.Contains(text, "8.10") {
		t.Errorf("/H of a 7.4 unit:\n%s", text)
	}
}

func TestWTIFakeScreensOption(t *testing.T) {
	// A manifest copied away from the captures finds them by the option.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "menu"), []byte("level user\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := openWTIDir(t, dir, fakedev.WithMenuScreens(wtiScreens(t)))
	u.login("DSM> ")
	u.send("/H\r")
	u.expect(contains("COMMAND MENU:"))
}

func TestWTIFakeBadManifestIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "menu"), []byte("lvel user\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := openWTIDir(t, dir)
	s := u.expect(contains("fakedev:"))
	if !strings.Contains(s, `unknown key "lvel"`) {
		t.Errorf("screen %q", s)
	}
}
