package cli

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'device ios-syntax' completes the Cisco devices and 'device netconf' the
// Junos devices (D276): the generated scripts ask the bridge for the vendor's
// kind, not for every device and host.
func TestCompleteVendorDevices(t *testing.T) {
	live := map[string]string{
		"devices":         "jsw1\nsw1\nweb1\n",
		"devices.cisco":   "sw1\n",
		"devices.juniper": "jsw1\n",
	}
	for _, c := range []struct {
		words []string
		want  []string
	}{
		{[]string{"device", "ios-syntax", ""}, []string{"sw1"}},
		{[]string{"device", "netconf", ""}, []string{"jsw1"}},
		{[]string{"device", "netconf", "s"}, nil},
		// the second word is unchanged
		{[]string{"device", "ios-syntax", "sw1", ""}, []string{"auto", "ios12", "modern", "--apply"}},
		// other verbs still name every device and host
		{[]string{"device", "show", ""}, []string{"jsw1", "sw1", "web1"}},
	} {
		got, _ := completeWords(t, live, c.words...)
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: %q, want %q", c.words, got, c.want)
		}
	}
}

// The shell asks for the vendor's kind with --desc, and the '?' listing
// shows the same columns as for every device.
func TestShellCompletionVendorDevices(t *testing.T) {
	inv, _, runner := shellTestInv(t)
	runner.OnFunc([]string{"sudo", "-n", "tacctl", "_completion-names"}, func(c execx.Cmd) (execx.Result, error) {
		switch strings.Join(c.Args[3:], " ") {
		case "devices.cisco --desc":
			return execx.Result{Stdout: []byte("core-sw\tcisco 10.0.0.1 prod\nsw1\tcisco 192.168.1.1 lab\n")}, nil
		case "devices.juniper --desc":
			return execx.Result{Stdout: []byte("jsw1\tjuniper 192.168.1.9 lab\n")}, nil
		case "devices --desc":
			return execx.Result{Stdout: []byte("jsw1\tjuniper 192.168.1.9 lab\nsw1\tcisco 192.168.1.1 lab\nweb1\tlinux 192.0.2.10 lab\n")}, nil
		}
		return execx.Result{}, nil
	})
	inv.app.Runner = &namesCache{Runner: runner, ttl: time.Hour, now: time.Now}
	complete := inv.shellCompleter(newRoot(inv))
	cs := complete([]string{"device", "ios-syntax"}, "")
	var got []string
	for _, c := range cs {
		if !strings.HasPrefix(c.Word, "-") {
			got = append(got, c.Word+"|"+c.Desc)
		}
	}
	if want := []string{"core-sw|cisco 10.0.0.1    prod", "sw1|cisco 192.168.1.1 lab"}; !slices.Equal(got, want) {
		t.Errorf("ios-syntax: %q, want %q", got, want)
	}
	if got := words(complete([]string{"device", "netconf"}, "")); !slices.Contains(got, "jsw1") || slices.Contains(got, "sw1") || slices.Contains(got, "web1") {
		t.Errorf("netconf: %q", got)
	}
	for _, c := range complete([]string{"device", "netconf"}, "") {
		if c.Word == "jsw1" && c.Kind != KindDevices {
			t.Errorf("jsw1 is listed as %q", c.Kind)
		}
	}
}

// '_completion-names devices.cisco|devices.juniper': the registry devices of
// that vendor, no enrolled host, behind the caller's scope filter, with and
// without --desc (the shape of the 'devices' kind's lines).
func TestCompletionNamesVendorDevices(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "prod-sw", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	sb.dev("", "add", "lab-sw", "192.168.1.1", "--vendor", "cisco", "--no-host-key")
	sb.dev("", "add", "lab-js", "192.168.1.9", "--vendor", "juniper", "--no-host-key")
	sb.dev("", "add", "prod-js", "10.99.0.9", "--vendor", "juniper", "--no-host-key")
	sb.dev("", "add", "dmz-fw", "203.0.113.9", "--no-host-key")
	sb.write("state/linux-hosts", "web1|root@192.0.2.10||lab|192.0.2.1|\n", 0o600)
	carol := func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	}
	for _, c := range []struct {
		args []string
		as   bool
		want string
	}{
		{[]string{"devices.cisco"}, false, "lab-sw\nprod-sw\n"},
		{[]string{"devices.juniper"}, false, "lab-js\nprod-js\n"},
		{[]string{"devices.cisco"}, true, "lab-sw\n"},
		{[]string{"devices.juniper"}, true, "lab-js\n"},
		{[]string{"devices.cisco", "--desc"}, false, "lab-sw\tcisco 192.168.1.1 lab\nprod-sw\tcisco 10.99.0.1 prod\n"},
		{[]string{"devices.juniper", "--desc"}, true, "lab-js\tjuniper 192.168.1.9 lab\n"},
	} {
		var out string
		if c.as {
			out = plain(sb.cfgRun("", append([]string{"_completion-names"}, c.args...), carol, "SUDO_USER=carol"))
		} else {
			out = sb.run("", append([]string{"_completion-names"}, c.args...))
		}
		if sb.code != 0 || out != c.want {
			t.Errorf("%q (carol %v): %d %q, want %q", c.args, c.as, sb.code, out, c.want)
		}
	}
}
