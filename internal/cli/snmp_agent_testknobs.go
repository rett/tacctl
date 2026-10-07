//go:build testknobs

package cli

// '_snmp-agent', in a -tags testknobs build only ('make build', which the
// bats suite runs): the stub SNMP agent the bats files point snmp.port at,
// so 'device add', 'device check' and 'config snmp test' run their real
// lookup over UDP on 127.0.0.1 (internal/snmp's Agent). A production
// binary has no such command.
//
//	tacctl _snmp-agent --port-file <file> --sysname <name> [--community <c>]
//	    [--user <u> --auth-pass <p> --priv-pass <p> [--auth sha|sha256]]
//	    [--seconds <n>]
//
// It binds 127.0.0.1 on a free port, writes the port to --port-file and
// answers for --seconds (default 120), or until it is killed.

import (
	"flag"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/snmp"
)

func init() {
	registerFamily(snmpAgentCmd)
}

func snmpAgentCmd(inv *invocation) *cobra.Command {
	c := hidden("_snmp-agent")
	c.RunE = func(_ *cobra.Command, args []string) error { return inv.snmpAgent(args) }
	return c
}

func (inv *invocation) snmpAgent(args []string) error {
	fs := flag.NewFlagSet("_snmp-agent", flag.ContinueOnError)
	fs.SetOutput(inv.app.Out.Stderr)
	a := &snmp.Agent{}
	portFile := fs.String("port-file", "", "")
	seconds := fs.Int("seconds", 120, "")
	fs.StringVar(&a.SysName, "sysname", "", "")
	fs.StringVar(&a.Community, "community", "", "")
	fs.StringVar(&a.User, "user", "", "")
	fs.StringVar(&a.AuthPass, "auth-pass", "", "")
	fs.StringVar(&a.PrivPass, "priv-pass", "", "")
	fs.StringVar(&a.Auth, "auth", snmp.AuthSHA, "")
	if err := fs.Parse(args); err != nil || *portFile == "" {
		return inv.usageErr("Usage: tacctl _snmp-agent --port-file <file> --sysname <name> [--community <c>] " +
			"[--user <u> --auth-pass <p> --priv-pass <p> [--auth sha|sha256]] [--seconds <n>]")
	}
	conn, err := a.Listen("127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	port := strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)
	if err := os.WriteFile(*portFile, []byte(port+"\n"), 0o644); err != nil {
		return err
	}
	select {
	case <-inv.ctx.Done():
	case <-time.After(time.Duration(*seconds) * time.Second):
	}
	return nil
}
