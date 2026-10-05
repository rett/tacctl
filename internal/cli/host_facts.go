package cli

// What 'host enroll' and 'host sync' record and report from the facts
// read over the enrolment session (hosts.Facts): the host's address, in
// the device registry's 'hosts:' section, so 'device add' refuses it, the
// registry finds the host by it and sightings and 'device discover'
// attribute it; and a warning when the host's local useradd can give out
// UIDs of tacctl's range.

import (
	"io"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/hosts"
)

// resolveV4 is the first IPv4 address 'getent ahostsv4' gives for host
// ("" when it gives none).
func (inv *invocation) resolveV4(host string) string {
	res, err := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "getent", Args: []string{"ahostsv4", host}, Stderr: io.Discard})
	if err != nil || res.Code != 0 {
		return ""
	}
	if lines := strings.SplitN(string(res.Stdout), "\n", 2); len(lines) > 0 {
		if f := strings.Fields(lines[0]); len(f) > 0 {
			return f[0]
		}
	}
	return ""
}

// hostFacts records the address of the enrolled host name and warns about
// its useradd range, from the facts the last RunScript read. resolved is
// what the target's name resolves to ("" for --local, or when it does not
// resolve). The address recorded is the one the enrolment session reached
// (sshd's SSH_CONNECTION on the host): it is the address this server's ssh
// actually connected to, whatever ssh_config aliases or several A records
// made of the name; when it differs from the name's resolution both are
// shown. Without it, the resolution is recorded. Every problem is a
// warning: the enrolment or sync itself has succeeded.
func (inv *invocation) hostFacts(he *hosts.Env, name, target, resolved string) {
	a := inv.app
	facts := he.Facts
	if facts == nil {
		facts = &hosts.Facts{}
	}
	for _, l := range facts.UIDWarning(name, he.UIDRange()) {
		a.Out.WarnE(l)
	}
	host := target
	if _, h, ok := strings.Cut(target, "@"); ok {
		host = h
	}
	addr := facts.Address
	switch {
	case addr != "" && resolved != "" && addr != resolved:
		a.Out.WarnE(name + ": the enrolment session reached " + addr + ", but '" + host + "' resolves to " + resolved +
			"; recorded " + addr + " (the address the connection reached).")
	case addr == "" && resolved != "":
		a.Out.InfoE(name + ": the session did not report the address it reached (SSH_CONNECTION); recorded " + resolved +
			", which '" + host + "' resolves to.")
		addr = resolved
	case addr == "":
		a.Out.WarnE(name + ": no address could be learned for the host; none recorded.")
		return
	}
	norm, err := devreg.NormalizeAddress(addr)
	if err != nil {
		a.Out.WarnE(name + ": the address " + addr + " is not one the registry can hold; none recorded.")
		return
	}
	f, err := devreg.Load(a.Paths.DevicesFile)
	if err != nil {
		a.Out.WarnE(name + ": address not recorded: " + strings.Join(msgs(err), " "))
		return
	}
	if d := f.FindAddress(norm); d != nil {
		a.Out.WarnE(name + ": " + norm + " is also registered as the device '" + d.Name +
			"'; one address answers for both. If they are the same machine: tacctl device remove " + d.Name)
	}
	if f.HostAddressOf(name) == norm {
		return
	}
	var previous string
	_, err = devreg.Mutate(a.Paths.DevicesFile, a.Paths.KnownHosts, nil, func(f *devreg.File) error {
		previous = f.SetHostAddress(name, norm, a.Knobs.Now().Format("2006-01-02 15:04"))
		return nil
	})
	if err != nil {
		a.Out.WarnE(name + ": address not recorded: " + strings.Join(msgs(err), " "))
		return
	}
	if previous != "" {
		a.Logger(inv.ctx, "auth.warning", "host address-changed name="+name+" old="+previous+" new="+norm+" by="+inv.sudoUser())
		a.Out.WarnE(name + ": its address changed from " + previous + " to " + norm + "; recorded " + norm +
			" (notice " + devreg.NoticeAddressChanged + ": tacctl device show " + name + ").")
	}
}
