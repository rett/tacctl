//go:build testknobs

package cli

// '_fake-device', in a -tags testknobs build only ('make build', which the
// bats suite and the differential runner use): the fake network device of
// internal/devssh/fakedev, so 'device config pull|diff|list' run their real
// ssh and NETCONF exchange on 127.0.0.1 against the transcripts of
// tests/fixtures/devconf. A production binary has no such command (and does
// not link the fake device at all).
//
//	tacctl _fake-device <dir> [--user <name> --password <text>] [--info-file <file>]
//	    [--netconf off] [--seconds <n>]
//
// It listens on a loopback port, prints '<host:port>' and the host key
// ('<type> <base64>', the line devices.yaml pins), one per line, writes the
// same two lines to --info-file when given, and serves until --seconds
// (default 120) or until it is killed. The knob that sends a pull to it is
// TACCTL_TEST_DEVICE_DIAL=<host:port> (internal/app/knobs.go).

import (
	"flag"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/devssh/fakedev"
)

func init() {
	registerFamily(fakeDeviceCmd)
}

func fakeDeviceCmd(inv *invocation) *cobra.Command {
	c := hidden("_fake-device")
	c.RunE = func(_ *cobra.Command, args []string) error { return inv.fakeDevice(args) }
	return c
}

func (inv *invocation) fakeDevice(args []string) error {
	usage := "Usage: tacctl _fake-device <dir> [--user <name> --password <text>] [--info-file <file>] [--netconf off] [--seconds <n>]"
	fs := flag.NewFlagSet("_fake-device", flag.ContinueOnError)
	fs.SetOutput(inv.app.Out.Stderr)
	user := fs.String("user", "", "")
	password := fs.String("password", "", "")
	info := fs.String("info-file", "", "")
	netconf := fs.String("netconf", "", "")
	seconds := fs.Int("seconds", 120, "")
	// The directory comes first; the flags after it.
	if len(args) == 0 || len(args[0]) == 0 || args[0][0] == '-' {
		return inv.usageErr(usage)
	}
	dir := args[0]
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 || (*user == "") != (*password == "") ||
		(*netconf != "" && *netconf != "off") {
		return inv.usageErr(usage)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return inv.usageErr("_fake-device: '" + dir + "' is not a transcript directory.")
	}
	var opts []fakedev.Option
	if *user != "" {
		opts = append(opts, fakedev.WithCredentials(*user, *password))
	}
	if *netconf == "off" {
		opts = append(opts, fakedev.WithNetconfOff())
	}
	srv := fakedev.New(dir, opts...)
	defer srv.Stop()
	text := srv.Addr() + "\n" + srv.HostKey() + "\n"
	inv.write(text)
	if *info != "" {
		if err := os.WriteFile(*info, []byte(text), 0o644); err != nil {
			return err
		}
	}
	select {
	case <-inv.ctx.Done():
	case <-time.After(time.Duration(*seconds) * time.Second):
	}
	return nil
}
