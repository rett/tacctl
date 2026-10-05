package cli

// 'host target <name> [<user@host>] [--port <n>] [--identity <file>|
// --no-identity]': show or change how tacctl reaches an enrolled host over
// ssh. A change is tested first: tacctl logs in to the new target as 'host
// enroll' and 'host sync' would, checks how the login reaches root, reads
// the host's keys over that session and compares them with the pinned ones
// (the host is the same machine: its keys must not change), and records
// the address it reached. Only then is the registry line rewritten (scope,
// server and method kept), after a snapshot. The client script is not run.

import (
	"os"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/ui"
)

// hostTargetUsage is the usage line of 'host target'.
const hostTargetUsage = "Usage: tacctl host target <name> [<[user@]host>] [--port <n>] [--identity <file>|--no-identity]"

func (inv *invocation) hostTarget(args []string) error {
	a := inv.app
	var name, target, port, identity string
	setTarget, setPort, setIdentity, noIdentity := false, false, false, false
	for i := 0; i < len(args); i++ {
		switch w := args[i]; w {
		case "--port", "--identity":
			if i+1 >= len(args) {
				return inv.usageErr(w+" needs a value.", hostTargetUsage)
			}
			if w == "--port" {
				port, setPort = args[i+1], true
			} else {
				identity, setIdentity = args[i+1], true
			}
			i++
		case "--no-identity":
			noIdentity = true
		default:
			switch {
			case strings.HasPrefix(w, "-"):
				return inv.usageErr("Unknown option: '"+w+"'", hostTargetUsage)
			case name == "":
				name = w
			case !setTarget:
				target, setTarget = w, true
			default:
				return inv.usageErr("Unexpected argument: '"+w+"'", hostTargetUsage)
			}
		}
	}
	if name == "" {
		return inv.usageErr(hostTargetUsage)
	}
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	e, ok := reg.Find(name)
	if !ok || e.Line == "" {
		return inv.usageErr("No enrolled host named '" + name + "'. See 'tacctl host list'.")
	}
	if !setTarget && !setPort && !setIdentity && !noIdentity {
		return inv.hostTargetShow(e)
	}
	if e.Target == hosts.Local {
		return inv.usageErr("'" + name + "' is this server (enrolled with --local); it is not reached over ssh, so it has no target to change.")
	}
	if setIdentity && noIdentity {
		return inv.usageErr("Give --identity or --no-identity, not both.")
	}
	next := e
	if setTarget {
		if !reTarget.MatchString(target) || target == hosts.Local {
			return inv.usageErr("Invalid target '"+target+"': expected [user@]host.", hostTargetUsage)
		}
		next.Target = target
	}
	if setPort {
		if port == "22" {
			port = ""
		}
		if port != "" && (!rePort.MatchString(port) || port == "0") {
			return inv.usageErr("Invalid --port '" + port + "'.")
		}
		next.Port = port
	}
	switch {
	case noIdentity:
		next.Identity = ""
	case setIdentity:
		if !isRegularFile(identity) {
			return inv.usageErr("Identity file '" + identity + "' not found.")
		}
		next.Identity = identity
	}
	if next.Target == e.Target && next.Port == e.Port && next.Identity == e.Identity {
		a.Out.Info("'" + name + "' is already reached that way; nothing was changed.")
		return nil
	}
	hostPart := next.Target
	if _, after, ok := strings.Cut(next.Target, "@"); ok {
		hostPart = after
	}
	if login, explicit, isUser, err := inv.provisioningLogin(next.Target); err != nil {
		return err
	} else if isUser {
		msg := "The provisioning account '" + login + "' (the ssh login for " + next.Target + ") is a tacctl user."
		if !explicit {
			msg = "The provisioning account defaults to your username '" + login + "', which is a tacctl user."
		}
		return inv.usageErr(msg,
			"Enrolment logs in with a local account on the host that does not authenticate through tacctl (root or a dedicated",
			"administration account, kept working when this server is unreachable): tacctl host target "+name+" <account>@"+hostPart)
	}
	resolved := inv.resolveV4(hostPart)
	if resolved == "" {
		return inv.usageErr("Cannot resolve '" + hostPart + "'")
	}

	// The test connection.
	he := inv.hostsEnv()
	a.Out.InfoE("Testing " + name + " at " + targetText(next) + "...")
	p := he.TestTarget(inv.ctx, next.Target, next.Port, next.Identity)
	if inv.ctx.Err() != nil {
		return ui.ErrInterrupted
	}
	if !p.Connected {
		return inv.usageErr("Could not log in to " + targetText(next) + " (ssh failed, see above); nothing was changed.")
	}
	switch p.Root {
	case "root", "sudo":
	case "sudo-password":
		if !he.TTYAvailable() {
			return inv.usageErr("The login on "+targetText(next)+" is not root and sudo there needs a password (or the login may not sudo);",
				"'host sync' without a terminal could not run there. Allow passwordless sudo for this login, or log in as root. Nothing was changed.")
		}
		a.Out.WarnE(name + ": sudo on " + targetText(next) + " needs a password (or the login may not sudo); 'host sync' asks for it on a terminal, and fails without one.")
	default:
		return inv.usageErr("Unexpected reply from " + targetText(next) + " while testing it; nothing was changed.")
	}
	if err := inv.hostTargetKeys(name, p); err != nil {
		return err
	}

	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	if err := reg.Replace(next); err != nil {
		return err
	}
	a.Logger(inv.ctx, "auth.info", "host target name="+name+" target="+next.Target+" port="+dash(next.Port)+" by="+inv.sudoUser())
	a.Out.InfoE("Host '" + name + "' is now reached at " + targetText(next) + " (scope, server and method unchanged).")
	inv.hostFacts(he, name, next.Target, resolved)
	// A host that cannot hold the UID range: 'host sync' will refuse it.
	if m, err := he.ReadIDMaps(inv.ctx, next.Target, next.Port, next.Identity); err == nil {
		if lacks := m.Lacks(he.UIDRange()); lacks != "" {
			a.Out.WarnE(hosts.IDMapRefusal(name, he.UIDRange(), lacks))
			a.Out.WarnE("'tacctl host sync " + name + "' refuses it until then.")
		}
	}
	return nil
}

// hostTargetKeys compares the keys a test connection read with the ones
// pinned for name: the host is the same machine, so a pinned key type with
// another key, or keys that cannot be read, refuse the change. With
// nothing pinned the next 'host sync' pins them.
func (inv *invocation) hostTargetKeys(name string, p hosts.Probe) error {
	a := inv.app
	f, err := devreg.Load(a.Paths.DevicesFile)
	if err != nil {
		return err
	}
	pinned := f.HostKeysOf(name)
	var own []devreg.HostKey
	if p.KeysErr == nil {
		own = devreg.ParsePubKeys(p.Keys)
	}
	if len(pinned) == 0 {
		a.Out.WarnE(name + ": no host key is pinned to compare with; the next 'tacctl host sync " + name + "' pins them.")
		return nil
	}
	if len(own) == 0 {
		return inv.usageErr("The host's ssh keys could not be read over the test connection, so it cannot be told to be '" + name + "'; nothing was changed.")
	}
	if devreg.Compare(pinned, own).Changed {
		a.Logger(inv.ctx, "auth.warning", "host target hostkey-mismatch name="+name)
		return inv.usageErr("The host reached is not '"+name+"' as pinned: its ssh keys differ; nothing was changed.",
			"  Pinned:      "+devreg.Displays(devreg.ParseHostKeys(pinned)),
			"  On the host: "+devreg.Displays(own),
			"If the host was reinstalled, check its keys there ("+devreg.VerifyHint(devreg.VendorLinux)+"), then: tacctl device hostkey "+name+" accept")
	}
	return nil
}

// targetText is the target with a port other than 22.
func targetText(e hosts.Entry) string {
	if e.Port != "" {
		return e.Target + " port " + e.Port
	}
	return e.Target
}

// hostTargetShow prints how name is reached.
func (inv *invocation) hostTargetShow(e hosts.Entry) error {
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return err
	}
	port := e.Port
	if port == "" {
		port = "22"
	}
	if e.Target == hosts.Local {
		port = "-"
	}
	_, statErr := os.Stat(e.Identity)
	ident := dash(e.Identity)
	if e.Identity != "" && statErr != nil {
		ident += "  (missing)"
	}
	inv.echo("")
	inv.echoE(ui.Bold + "Host " + e.Name + ui.NC)
	inv.echo(ui.Rule("Host " + e.Name))
	row := func(k, v string) { inv.echo("  " + padTo(k+":", 13) + " " + v) }
	row("Target", e.Target)
	row("Port", port)
	row("Identity", ident)
	row("Server", dash(e.Server))
	row("Address", dash(f.HostAddressOf(e.Name)))
	row("Scope", e.Scope)
	row("Method", e.EffectiveMethod())
	inv.echo("")
	return nil
}
