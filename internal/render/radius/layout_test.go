package radius_test

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/render/radius"
)

func TestLayoutDebian(t *testing.T) {
	l := layout("debian")
	want := map[string]string{
		"Unit": "freeradius.service", "User": "freerad", "Group": "freerad", "Dir": "/etc/freeradius/3.0",
		"LogDir": "/var/log/freeradius", "Bin": "/usr/sbin/freeradius", "PIDFile": "/run/freeradius/freeradius.pid",
		"LibDir": "/usr/lib/freeradius", "SystemDict": "/usr/share/freeradius/dictionary",
		"Conf":  "/etc/freeradius/3.0/tacctl-radius.conf",
		"Users": "/etc/freeradius/3.0/tacctl-radius.users",
		"Dict":  "/etc/freeradius/3.0/tacctl-radius-dictionary/dictionary",
	}
	checkLayout(t, l, want)
}

func TestLayoutRHEL(t *testing.T) {
	l := layout("rhel")
	want := map[string]string{
		"Unit": "radiusd.service", "User": "radiusd", "Group": "radiusd", "Dir": "/etc/raddb",
		"LogDir": "/var/log/radius", "Bin": "/usr/sbin/radiusd", "PIDFile": "/run/radiusd/radiusd.pid",
		"LibDir": "/usr/lib64/freeradius", "SystemDict": "/usr/share/freeradius/dictionary",
		"Conf": "/etc/raddb/tacctl-radius.conf",
		"Dict": "/etc/raddb/tacctl-radius-dictionary/dictionary",
	}
	checkLayout(t, l, want)
}

func checkLayout(t *testing.T, l paths.RadiusPaths, want map[string]string) {
	t.Helper()
	fields := map[string]string{
		"Unit": l.Unit, "User": l.User, "Group": l.Group, "Dir": l.Dir, "LogDir": l.LogDir, "Bin": l.Bin,
		"PIDFile": l.PIDFile, "LibDir": l.LibDir, "SystemDict": l.SystemDict, "Conf": l.Conf, "Users": l.Users, "Dict": l.Dict,
	}
	for k, w := range want {
		if fields[k] != w {
			t.Errorf("%s = %q, want %q", k, fields[k], w)
		}
	}
	if got := radius.ParamsFor(l); got.Name != "tacctl-radius" || got.User != l.User || got.Group != l.Group ||
		got.LogDir != l.LogDir || got.PIDFile != l.PIDFile || got.LibDir != l.LibDir || got.SystemDict != l.SystemDict {
		t.Errorf("ParamsFor = %+v", got)
	}
}

func TestLayoutOverrides(t *testing.T) {
	env := paths.NewEnv([]string{
		"TACCTL_RADIUS_DIR=/t/raddb", "TACCTL_RADIUS_LOG=/t/log", "TACCTL_RADIUS_BIN=/t/bin/radiusd",
		"TACCTL_RADIUS_DICT=/t/share/dictionary", "TACCTL_SYSTEMD_DIR=/t/systemd", "TACCTL_LOGROTATE_DIR=/t/lr",
	})
	l := radius.Layout(paths.Resolve(env, "", func(string) bool { return false }), "rhel")
	if l.Conf != "/t/raddb/tacctl-radius.conf" || l.LogDir != "/t/log" || l.Bin != "/t/bin/radiusd" ||
		l.SystemDict != "/t/share/dictionary" || l.DropIn != "/t/systemd/radiusd.service.d/tacctl.conf" ||
		l.Logrotate != "/t/lr/tacctl-radius" {
		t.Errorf("layout: %+v", l)
	}
	// An unrecognised family ("") has the Debian layout.
	if got := radius.Layout(paths.Resolve(paths.NewEnv(nil), "", nil), ""); got.Family != "debian" || got.Unit != "freeradius.service" {
		t.Errorf("family '' layout: %+v", got)
	}
}

func TestDropin(t *testing.T) {
	debian := strings.Split(radius.DropinText(layout("debian")), "\n")
	args := "-d /etc/freeradius/3.0 -D /etc/freeradius/3.0/tacctl-radius-dictionary -n tacctl-radius"
	for _, want := range []string{
		"ExecStartPre=", "ExecStart=",
		"ExecStartPre=/usr/sbin/freeradius -C -lstdout " + args,
		"ExecStart=/usr/sbin/freeradius -f " + args,
		"ExecReload=/usr/sbin/freeradius -C -lstdout " + args,
	} {
		if !has(debian, want) {
			t.Errorf("debian drop-in lacks %q", want)
		}
	}
	rhel := strings.Split(radius.DropinText(layout("rhel")), "\n")
	args = "-d /etc/raddb -D /etc/raddb/tacctl-radius-dictionary -n tacctl-radius"
	for _, want := range []string{
		"ExecStartPre=-/bin/chown -R radiusd:radiusd /var/run/radiusd",
		"ExecStartPre=/usr/sbin/radiusd -C -lstdout " + args,
		"ExecStart=/usr/sbin/radiusd " + args,
		"ExecReload=/bin/kill -HUP $MAINPID",
	} {
		if !has(rhel, want) {
			t.Errorf("rhel drop-in lacks %q", want)
		}
	}
}

// The whole text, as 0.1.16's _radius_dropin_text prints it for Debian.
func TestDropinText(t *testing.T) {
	const want = `# Installed by tacctl ('tacctl backend enable radius'), removed by 'tacctl backend disable radius'.
# freeradius.service runs tacctl's FreeRADIUS instance (/etc/freeradius/3.0/tacctl-radius.conf) instead of the package's radiusd.conf.
[Service]
ExecStartPre=
ExecStartPre=/usr/sbin/freeradius -C -lstdout -d /etc/freeradius/3.0 -D /etc/freeradius/3.0/tacctl-radius-dictionary -n tacctl-radius
ExecStart=
ExecStart=/usr/sbin/freeradius -f -d /etc/freeradius/3.0 -D /etc/freeradius/3.0/tacctl-radius-dictionary -n tacctl-radius
ExecReload=
ExecReload=/usr/sbin/freeradius -C -lstdout -d /etc/freeradius/3.0 -D /etc/freeradius/3.0/tacctl-radius-dictionary -n tacctl-radius
ExecReload=/bin/kill -HUP $MAINPID
`
	if got := radius.DropinText(layout("debian")); got != want {
		t.Errorf("drop-in:\n%s", got)
	}
}

func TestSecretConstraints(t *testing.T) {
	if radius.SecretMaxLen != 63 || radius.SecretCharset != "[!-~]" {
		t.Errorf("%d %q", radius.SecretMaxLen, radius.SecretCharset)
	}
}

func TestDetectFamily(t *testing.T) {
	dirs := func(ds ...string) func(string) bool {
		return func(p string) bool {
			for _, d := range ds {
				if p == d {
					return true
				}
			}
			return false
		}
	}
	env := func(kv ...string) paths.Env { return paths.NewEnv(kv) }
	cases := []struct {
		name    string
		env     paths.Env
		isDir   func(string) bool
		missing []string
		want    string
	}{
		{"override debian", env("TACCTL_RADIUS_FAMILY=debian"), dirs("/etc/raddb"), nil, "debian"},
		{"override rhel", env("TACCTL_RADIUS_FAMILY=rhel"), dirs("/etc/freeradius/3.0"), nil, "rhel"},
		{"bad override is ignored", env("TACCTL_RADIUS_FAMILY=suse"), dirs("/etc/raddb"), nil, "rhel"},
		{"debian raddb", env(), dirs("/etc/freeradius/3.0", "/etc/raddb"), nil, "debian"},
		{"rhel raddb", env(), dirs("/etc/raddb"), nil, "rhel"},
		{"TACCTL_RADIUS_DIR does not matter", env("TACCTL_RADIUS_DIR=/etc/raddb"), dirs(), nil, "debian"}, // apt-get is found
		{"apt-get", env(), dirs(), nil, "debian"},
		{"dnf", env(), dirs(), []string{"apt-get"}, "rhel"},
		{"yum", env(), dirs(), []string{"apt-get", "dnf"}, "rhel"},
		{"neither", env(), dirs(), []string{"apt-get", "dnf", "yum"}, ""},
	}
	for _, c := range cases {
		r := &fake.Runner{}
		r.Missing(c.missing...)
		if got := radius.DetectFamily(c.env, c.isDir, r); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// With no probe given the file system is asked; the answer is one of
	// the three, and a family override still wins.
	r := &fake.Runner{}
	switch got := radius.DetectFamily(env(), nil, r); got {
	case "debian", "rhel":
	default:
		t.Errorf("the real file system gave %q with apt-get on PATH", got)
	}
}

func TestWorst(t *testing.T) {
	cases := []struct {
		in   []string
		want string
		ok   bool
	}{
		{[]string{"current", "same", "ok"}, "ok", true},
		{[]string{"current", "current", "current"}, "current", true},
		{[]string{"same", "current", "same"}, "same", true},
		{[]string{"ok", "drift", "missing"}, "drift", true},
		{[]string{"missing", "unrecorded", "ok"}, "unrecorded", true},
		{[]string{"current", "unreadable", "drift"}, "unreadable", true},
		{[]string{"ok", "bogus"}, "ok", true},
		{[]string{"bogus"}, "", false},
		{nil, "", false},
	}
	for _, c := range cases {
		if got, ok := radius.Worst(c.in...); got != c.want || ok != c.ok {
			t.Errorf("Worst(%v) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
