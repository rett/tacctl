package devconf

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

type fakeRunner struct {
	out  map[string]string
	errs map[string]error
	ran  []string
}

func (f *fakeRunner) Run(_ context.Context, cmd string) (string, error) {
	f.ran = append(f.ran, cmd)
	if err := f.errs[cmd]; err != nil {
		return "", err
	}
	return f.out[cmd], nil
}

func TestCommands(t *testing.T) {
	setup, read, err := Commands("juniper")
	if err != nil || len(setup) != 0 || read != "show configuration | display inheritance no-comments | display set" {
		t.Errorf("junos: %q %q %v", setup, read, err)
	}
	setup, read, err = Commands("ios-xe")
	if err != nil || !slices.Equal(setup, []string{"terminal length 0", VersionCommand}) || read != "show running-config" {
		t.Errorf("ios: %q %q %v", setup, read, err)
	}
	if _, _, err := Commands("wti"); !errors.Is(err, ErrUnsupportedVendor) {
		t.Errorf("wti: %v", err)
	}
	if _, err := Reader("wti"); !errors.Is(err, ErrUnsupportedVendor) {
		t.Errorf("wti reader: %v", err)
	}
}

// The plain view is read for Junos only, and only a text that holds a 'set'
// statement is one: an error text is never a configuration with nothing in it.
func TestReadPlain(t *testing.T) {
	ctx := context.Background()
	const cmd = "show configuration | display set"
	if PlainCommand("juniper") != cmd || PlainCommand("cisco") != "" || PlainCommand("wti") != "" {
		t.Errorf("commands: %q %q %q", PlainCommand("juniper"), PlainCommand("cisco"), PlainCommand("wti"))
	}
	f := &fakeRunner{out: map[string]string{cmd: "set system a b\r\nset snmp c d\r\n"}}
	if got := ReadPlain(ctx, f, "juniper"); !strings.Contains(got, "set system a b\nset snmp c d") {
		t.Errorf("plain: %q", got)
	}
	f = &fakeRunner{out: map[string]string{cmd: "syntax error, expecting <command>.\n"}}
	if got := ReadPlain(ctx, f, "juniper"); got != "" {
		t.Errorf("an error text is a view: %q", got)
	}
	f = &fakeRunner{out: map[string]string{}}
	if got := ReadPlain(ctx, f, "juniper"); got != "" {
		t.Errorf("no answer is a view: %q", got)
	}
	f = &fakeRunner{errs: map[string]error{cmd: errors.New("boom")}}
	if got := ReadPlain(ctx, f, "juniper"); got != "" {
		t.Errorf("an error is a view: %q", got)
	}
	f = &fakeRunner{out: map[string]string{"show running-config": "set a b\n"}}
	if got := ReadPlain(ctx, f, "cisco"); got != "" || len(f.ran) != 0 {
		t.Errorf("IOS has a plain view: %q %v", got, f.ran)
	}
}

func TestReader(t *testing.T) {
	ctx := context.Background()
	t.Run("junos", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{"show configuration | display inheritance no-comments | display set": "set a b\r\n---(more)---\r\nset c d\r\n"}}
		read, err := Reader("junos")
		if err != nil {
			t.Fatal(err)
		}
		got, err := read(ctx, f)
		if err != nil || got != "set a b\nset c d\n" || !slices.Equal(f.ran, []string{"show configuration | display inheritance no-comments | display set"}) {
			t.Errorf("%q %v %q", got, err, f.ran)
		}
	})
	t.Run("ios", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{"show running-config": "version 15.2\n"}}
		read, _ := Reader("ios")
		got, err := read(ctx, f)
		if err != nil || got != "version 15.2" && got != "version 15.2\n" || !slices.Equal(f.ran, []string{"terminal length 0", VersionCommand, "show running-config"}) {
			t.Errorf("%q %v %q", got, err, f.ran)
		}
	})
	t.Run("empty", func(t *testing.T) {
		f := &fakeRunner{out: map[string]string{}}
		read, _ := Reader("junos")
		if _, err := read(ctx, f); !errors.Is(err, ErrParse) {
			t.Errorf("%v", err)
		}
	})
	t.Run("run error", func(t *testing.T) {
		boom := errors.New("boom")
		f := &fakeRunner{errs: map[string]error{"terminal length 0": boom}}
		read, _ := Reader("ios")
		if _, err := read(ctx, f); !errors.Is(err, boom) || len(f.ran) != 1 {
			t.Errorf("%v %q", err, f.ran)
		}
	})
}

func TestUnwrapNetconf(t *testing.T) {
	for _, tc := range []struct{ name, reply, want string }{
		{"command", `<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><configuration-output>set a b
set snmp contact &quot;NOC &lt;noc@example.net&gt;&quot;
</configuration-output></rpc-reply>`, "set a b\nset snmp contact \"NOC <noc@example.net>\"\n"},
		{"get-configuration", `<rpc-reply><configuration-set>set x y
</configuration-set></rpc-reply>`, "set x y\n"},
		{"declared charset", `<?xml version="1.0" encoding="us-ascii"?><rpc-reply><configuration-output>set a b
</configuration-output></rpc-reply>`, "set a b\n"},
	} {
		got, _, err := UnwrapNetconf(tc.reply)
		if err != nil || got != tc.want {
			t.Errorf("%s: %q %v", tc.name, got, err)
		}
	}
	for name, reply := range map[string]string{
		"rpc-error": `<rpc-reply><rpc-error><error-severity>error</error-severity><error-message>syntax error</error-message></rpc-error></rpc-reply>`,
		"none":      `<rpc-reply><ok/></rpc-reply>`,
		"not xml":   `<<<`,
	} {
		if _, _, err := UnwrapNetconf(reply); !errors.Is(err, ErrParse) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_, _, err := UnwrapNetconf(`<rpc-reply><rpc-error><error-severity>error</error-severity><error-message>bad thing</error-message></rpc-error></rpc-reply>`)
	if err == nil || !strings.Contains(err.Error(), "bad thing") {
		t.Errorf("%v", err)
	}
}

func TestHierarchyCommandAndRead(t *testing.T) {
	if got := HierarchyCommand("juniper", "snmp"); got != "show configuration snmp | display set" {
		t.Errorf("snmp: %q", got)
	}
	if got := HierarchyCommand("juniper", "system"); got != "show configuration system | display set" {
		t.Errorf("system: %q", got)
	}
	if got := HierarchyCommand("cisco", "snmp"); got != "show running-config | include ^snmp-server" {
		t.Errorf("cisco snmp: %q", got)
	}
	if got := HierarchyCommand("cisco", "system"); got != "show running-config | include ^(banner|ip domain|ip name-server|clock timezone|ntp )" {
		t.Errorf("cisco system: %q", got)
	}
	for _, c := range [][2]string{{"cisco", "snmp | include x"}, {"juniper", "firewall"}, {"juniper", "snmp | display xml"}, {"wti", "snmp"}} {
		if got := HierarchyCommand(c[0], c[1]); got != "" {
			t.Errorf("%v: %q", c, got)
		}
	}
	r := &scriptRunner{out: "set snmp name x\r\nset snmp community c authorization read-only\r\n"}
	got, err := ReadHierarchy(context.Background(), r, "juniper", "snmp")
	if err != nil || got != "set snmp name x\nset snmp community c authorization read-only\n" || r.cmd != "show configuration snmp | display set" {
		t.Errorf("%q %v (%q)", got, err, r.cmd)
	}
	// nothing under the hierarchy is no error
	if got, err := ReadHierarchy(context.Background(), &scriptRunner{out: "\n"}, "juniper", "snmp"); err != nil || strings.TrimSpace(got) != "" {
		t.Errorf("empty: %q %v", got, err)
	}
	for _, refusal := range []string{"error: permission denied", "syntax error, expecting <command>.", "unknown command."} {
		if _, err := ReadHierarchy(context.Background(), &scriptRunner{out: refusal + "\n"}, "juniper", "snmp"); !errors.Is(err, ErrParse) {
			t.Errorf("%q: %v", refusal, err)
		}
	}
	if _, err := ReadHierarchy(context.Background(), &scriptRunner{out: "% Invalid input detected at '^' marker.\n"}, "cisco", "system"); !errors.Is(err, ErrParse) {
		t.Errorf("cisco system: %v", err)
	}
}

// mapRunner answers each command with a text of its own and keeps the order
// of the commands.
type mapRunner struct {
	out map[string]string
	ran []string
}

func (r *mapRunner) Run(_ context.Context, cmd string) (string, error) {
	r.ran = append(r.ran, cmd)
	return r.out[cmd], nil
}

// An IOS device's system lines are read with the first command, and its login
// banner with the section command ('include' shows the first line of a
// banner only); a device that does not know '| section' is read in full once.
func TestReadHierarchyIOSSystem(t *testing.T) {
	const include = "show running-config | include ^(banner|ip domain|ip name-server|clock timezone|ntp )"
	r := &mapRunner{out: map[string]string{
		include: "banner exec ^C\r\nbanner login ^C\r\nip domain name lab.example.net\r\nip name-server 192.0.2.53 192.0.2.54\r\n" +
			"clock timezone CET 1 0\r\nntp authentication-key 5 md5 0822455D0A16 7\r\nntp server 192.0.2.123 prefer\r\n",
		"show running-config | section ^banner login": "banner login ^C\r\nAuthorized use only.\r\n! not a comment\r\n^C\r\n",
	}}
	got, err := ReadHierarchy(context.Background(), r, "cisco", "system")
	if err != nil {
		t.Fatal(err)
	}
	want := "ip domain name lab.example.net\nip name-server 192.0.2.53 192.0.2.54\nclock timezone CET 1 0\n" +
		"ntp authentication-key 5 md5 0822455D0A16 7\nntp server 192.0.2.123 prefer\n" +
		"banner login ^C\nAuthorized use only.\n! not a comment\n^C"
	if got != strings.TrimSuffix(want, "\n") && got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
	if len(r.ran) != 3 || r.ran[0] != "terminal length 0" || r.ran[1] != include {
		t.Errorf("commands: %q", r.ran)
	}
	// a device that does not know '| section': the whole configuration, once
	r = &mapRunner{out: map[string]string{
		include: "banner login ^C\r\nntp server 192.0.2.123\r\n",
		"show running-config | section ^banner login": "% Invalid input detected at '^' marker.\r\n",
		"show running-config":                         "hostname r1\r\n!\r\nbanner motd ^C\r\nmotd\r\n^C\r\nbanner login ^C\r\nHello\r\n^C\r\nline con 0\r\n",
	}}
	got, err = ReadHierarchy(context.Background(), r, "cisco", "system")
	if err != nil || got != "ntp server 192.0.2.123\nbanner login ^C\nHello\n^C" {
		t.Errorf("full read: %q %v", got, err)
	}
	// a single-line banner, with the section command silent: the first read
	r = &mapRunner{out: map[string]string{include: "banner login ^CHello^C\r\nntp server 192.0.2.123\r\n"}}
	got, err = ReadHierarchy(context.Background(), r, "cisco", "system")
	if err != nil || got != "ntp server 192.0.2.123\nbanner login ^CHello^C" {
		t.Errorf("one line banner: %q %v", got, err)
	}
	// no banner at all
	r = &mapRunner{out: map[string]string{include: "ntp server 192.0.2.123\r\n"}}
	got, err = ReadHierarchy(context.Background(), r, "cisco", "system")
	if err != nil || got != "ntp server 192.0.2.123" {
		t.Errorf("no banner: %q %v", got, err)
	}
}

// An IOS device is read with its SNMP lines and, for each standard access
// list a community names, the section of that list, filtered to the list's
// own header ('| section' matches by pattern).
func TestReadHierarchyIOS(t *testing.T) {
	r := &mapRunner{out: map[string]string{
		"show running-config | include ^snmp-server": "snmp-server community c1 RO POLLERS\r\nsnmp-server community c2 RW 10\r\n" +
			"snmp-server community c3 RO POLLERS\r\nsnmp-server host 192.0.2.50 version 2c c1\r\nsnmp-server enable traps config\r\n",
		"show running-config | section ip access-list standard POLLERS": "ip access-list standard POLLERS\r\n permit 192.0.2.10\r\n permit 198.51.100.0 0.0.0.255\r\n" +
			"ip access-list standard POLLERS-2\r\n permit any\r\n",
	}}
	got, err := ReadHierarchy(context.Background(), r, "cisco", "snmp")
	if err != nil {
		t.Fatal(err)
	}
	want := "snmp-server community c1 RO POLLERS\nsnmp-server community c2 RW 10\nsnmp-server community c3 RO POLLERS\n" +
		"snmp-server host 192.0.2.50 version 2c c1\nsnmp-server enable traps config\n" +
		"ip access-list standard POLLERS\n permit 192.0.2.10\n permit 198.51.100.0 0.0.0.255"
	if got != want {
		t.Errorf("text:\n%s\nwant\n%s", got, want)
	}
	wantRan := []string{"terminal length 0", "show running-config | include ^snmp-server", "show running-config | section ip access-list standard POLLERS"}
	if !slices.Equal(r.ran, wantRan) {
		t.Errorf("commands: %q", r.ran)
	}

	// an image that does not know '| section': the configuration is read in
	// full once and the list cut out of it
	r = &mapRunner{out: map[string]string{
		"show running-config | include ^snmp-server":                    "snmp-server community c1 RO POLLERS\n",
		"show running-config | section ip access-list standard POLLERS": "% Invalid input detected at '^' marker.\n",
		"show running-config": "hostname rt1\n!\nip access-list standard OTHER\n permit any\n!\nip access-list standard POLLERS\n permit host 192.0.2.10\n!\nend\n",
	}}
	got, err = ReadHierarchy(context.Background(), r, "cisco", "snmp")
	if err != nil || got != "snmp-server community c1 RO POLLERS\nip access-list standard POLLERS\n permit host 192.0.2.10" {
		t.Errorf("fallback: %q %v", got, err)
	}
	// a device with no SNMP line is no error
	got, err = ReadHierarchy(context.Background(), &mapRunner{out: map[string]string{}}, "cisco", "snmp")
	if err != nil || got != "" {
		t.Errorf("empty: %q %v", got, err)
	}
	// a refusal of the first command is
	r = &mapRunner{out: map[string]string{"show running-config | include ^snmp-server": "% Invalid input detected at '^' marker.\n"}}
	if _, err := ReadHierarchy(context.Background(), r, "cisco", "snmp"); !errors.Is(err, ErrParse) {
		t.Errorf("refused: %v", err)
	}
	// a list name that is no word of a name is never put in a command
	r = &mapRunner{out: map[string]string{"show running-config | include ^snmp-server": "snmp-server community c1 RO a;b\n"}}
	if _, err := ReadHierarchy(context.Background(), r, "cisco", "snmp"); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.ran {
		if strings.Contains(c, ";") {
			t.Errorf("a command holds the odd name: %q", c)
		}
	}
}

type scriptRunner struct {
	out string
	cmd string
}

func (r *scriptRunner) Run(_ context.Context, cmd string) (string, error) {
	r.cmd = cmd
	return r.out, nil
}
