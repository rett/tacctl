package cli

// The render input of one device (docs/plans/0.2.4-plan.md D63). The
// walkthrough verbs ('config cisco|juniper|wti', 'device config show') and
// the batch verbs ('device config pull|diff|list') build what the renderers
// read here, in one function: a Request and a Data. The renderers and
// devices.Managed are pure (no CLI, terminal, clock or global state), so a
// batch makes the Data of a vendor and scope once, before its pool starts,
// and calls Managed per device in parallel.

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/snmpcred"
	"github.com/rett/tacctl/internal/ui"
)

// renderParams are the settled inputs of one device config: the walkthrough
// verb's arguments after its checks, or a registered device's values.
type renderParams struct {
	Vendor, Scope string
	// Legacy is Cisco's IOS 12.x syntax (TACACS+ only).
	Legacy bool
	// Protocol and Source are devices.ResolveProtocol's answer.
	Protocol, Source string
	// Device is the device's own SNMP values (its sysName, description and
	// location); zero when the config is for no particular device.
	Device devices.SNMPInput
	// AuthServer, AuthName and SourceIP are --server and --source.
	AuthServer, AuthName, SourceIP string
	// Restricted is an engineer's config: the Cisco NETCONF step is a
	// superuser's, and the SNMP read is logged.
	Restricted bool
}

// deviceRenderInput builds the Request and the Data of one device config:
// the model and tacctl.yaml, the server's address, the scope's SNMP settings
// with the device's values, the management ACL and, for RADIUS, the
// backend's part. It is the part of 'config <vendor>' that does not depend
// on a command line, so the batch verbs reuse it. A refusal (RADIUS not
// enabled) is printed, as the walkthrough prints it, and returned.
func (inv *invocation) deviceRenderInput(p renderParams) (devices.Request, devices.Data, error) {
	a := inv.app
	req := devices.Request{Vendor: p.Vendor, Scope: p.Scope, Legacy: p.Legacy, Protocol: p.Protocol, Source: p.Source}
	m, err := inv.model()
	if err != nil {
		return req, devices.Data{}, err
	}
	d := devices.Data{
		Model:       m,
		Conf:        a.Conf(),
		TemplateDir: a.Paths.Templates,
		ServerIP:    devices.ServerIP(inv.ctx, a.Runner),
		Restricted:  p.Restricted,
		AuthServer:  p.AuthServer, AuthName: p.AuthName, SourceIP: p.SourceIP,
	}
	if d.SNMP, err = inv.walkthroughSNMP(p.Scope, p.Device); err != nil {
		// A credentials file that cannot be read leaves the step out; the
		// rest of the walkthrough is still good.
		ui.Output{Stdout: a.Out.Stderr}.Warn("The SNMP step is left out: " + strings.Join(msgs(err), " "))
		d.SNMP = p.Device
		d.SNMP.Scope = p.Scope
	}
	if p.Restricted && d.SNMP.Version != "" {
		inv.secretRead("snmp", p.Scope)
	}
	// A device's own credentials (D72) are a read of their own.
	if p.Restricted && d.SNMP.CredFrom == snmpcred.FromDevice && p.Device.DeviceName != "" {
		inv.secretRead("snmp-device", p.Device.DeviceName)
	}
	// The permit list is read for every vendor (WTI's IP Tables list, D42,
	// is built from it too); a WTI unit has no ACL name.
	d.ACL = devices.MgmtACL{CIDRs: inv.readMgmtACLCIDRs(p.Scope)}
	if p.Vendor != "wti" {
		d.ACL.Name = inv.readMgmtACLName(p.Vendor, p.Scope)
	}
	if p.Protocol == devices.RADIUS {
		if d.Radius, err = inv.deviceRadius(p.Vendor, p.Scope); err != nil {
			return req, d, err
		}
	}
	return req, d, nil
}

// managedOptions are the walkthrough options a batch applies to every
// device it renders for: --server and --source, as 'device config show'
// takes them.
type managedOptions struct {
	AuthServer, AuthName, SourceIP string
}

// managedKey is what a rendering shares: devices of one vendor and scope
// (and syntax) differ only in their own SNMP values.
type managedKey struct {
	vendor, scope string
	legacy        bool
}

// managedBase is the Request and Data of one managedKey, made once.
type managedBase struct {
	req devices.Request
	d   devices.Data
	// problem is why there is none (the walkthrough's refusal), "" when
	// there is.
	problem string
}

// managedRender makes the managed sections expected of registered devices
// (devices.Managed, D63). prepare reads what the renderers read, once per
// vendor and scope, before any worker starts; Expected is then pure and may
// be called from many goroutines.
type managedRender struct {
	inv  *invocation
	opts managedOptions
	// logReads: the render reads a scope's secret and SNMP credentials for
	// a caller the scope filter restricts (an engineer): the reads are
	// logged, never the values, as the walkthrough logs them (D45). A
	// caller who only lists states logs none.
	logReads bool
	base     map[managedKey]*managedBase
	// logged are the scopes whose reads were logged.
	logged map[string]bool
	// snmp is each prepared device's SNMP input, by lowercased name: the
	// scope's settings with the device's own over them (D72), and
	// snmpProblem why a device's own settings cannot be read (it is not
	// compared against the scope's, which would read as drift).
	snmp        map[string]devices.SNMPInput
	snmpProblem map[string]string
}

// newManagedRender is a render for the batch verbs. The expected
// configuration is the same for every caller (the superuser's, the
// complete one): what a device is compared with does not depend on who
// asks, so the states a pull records agree whoever pulled.
func (inv *invocation) newManagedRender(opts managedOptions, logReads bool) *managedRender {
	return &managedRender{inv: inv, opts: opts, logReads: logReads,
		base: map[managedKey]*managedBase{}, logged: map[string]bool{},
		snmp: map[string]devices.SNMPInput{}, snmpProblem: map[string]string{}}
}

// keyOf is the sharing key of a registered device.
func (r *managedRender) keyOf(e devreg.Entry) managedKey {
	return managedKey{vendor: e.Vendor, scope: e.Scope, legacy: r.legacyOf(e)}
}

// legacyOf says whether a Cisco device is compared against the IOS 12.x
// syntax: the registry's legacy-ssh flag marks the old IOS, whose AAA lines
// are 'tacacs-server host' (TACACS+ only: a RADIUS scope has one syntax).
func (r *managedRender) legacyOf(e devreg.Entry) bool {
	if e.Vendor != "cisco" || !e.LegacySSH || e.Scope == "" {
		return false
	}
	choice, source := r.inv.scopeProtocolChoice(e.Scope)
	protocol, _ := devices.ResolveProtocol("", choice, source)
	return protocol != devices.RADIUS
}

// prepare makes the bases of every vendor and scope the entries need. A
// refusal inside (RADIUS not enabled) is kept as the base's problem, not
// printed: the batch says it once per device in its own line.
func (r *managedRender) prepare(entries []devreg.Entry) {
	inv := r.inv
	for _, e := range entries {
		if e.Source != devreg.SourceDevice || !e.Configured || (e.Vendor != "cisco" && e.Vendor != "juniper") {
			continue
		}
		k := r.keyOf(e)
		if _, done := r.base[k]; done {
			r.prepareOwn(e, k)
			continue
		}
		b := &managedBase{}
		r.base[k] = b
		// An engineer's pull reads the scope's secret as the walkthrough
		// does: logged once per scope, never the value.
		if r.logReads && !r.logged[k.scope] {
			r.logged[k.scope] = true
			inv.secretRead("scope", k.scope)
		}
		choice, source := inv.scopeProtocolChoice(k.scope)
		protocol, psource := devices.ResolveProtocol("", choice, source)
		var errBuf bytes.Buffer
		realErr := inv.app.Out.Stderr
		inv.app.Out.Stderr = &errBuf
		req, d, err := inv.deviceRenderInput(renderParams{
			Vendor: k.vendor, Scope: k.scope, Legacy: k.legacy, Protocol: protocol, Source: psource,
			AuthServer: r.opts.AuthServer, AuthName: r.opts.AuthName, SourceIP: r.opts.SourceIP,
		})
		inv.app.Out.Stderr = realErr
		// What the build said on stderr: its warnings are the operator's to
		// see, its refusal is the base's problem.
		for _, l := range strings.Split(strings.TrimRight(errBuf.String(), "\n"), "\n") {
			if l == "" {
				continue
			}
			if rest, ok := strings.CutPrefix(stripColour(l), "[ERROR] "); ok {
				if b.problem == "" {
					b.problem = rest
				}
				continue
			}
			_, _ = realErr.Write([]byte(l + "\n"))
		}
		if err != nil && b.problem == "" {
			b.problem = strings.Join(msgs(err), " ")
		}
		if b.problem == "" {
			b.req, b.d = req, d
			if r.logReads && d.SNMP.Version != "" && !r.logged["snmp "+k.scope] {
				r.logged["snmp "+k.scope] = true
				inv.secretRead("snmp", k.scope)
			}
		}
		r.prepareOwn(e, k)
	}
}

// prepareOwn makes the SNMP input of one device: the base's with the
// device's own settings over it (D72), read now, before any worker starts.
// A device that has none gets the base's, with its own name, description
// and location as before.
func (r *managedRender) prepareOwn(e devreg.Entry, k managedKey) {
	inv := r.inv
	b := r.base[k]
	lc := strings.ToLower(e.Name)
	if b == nil || b.problem != "" {
		return
	}
	own, err := inv.deviceSNMPOwnOf(e.Device)
	if err != nil {
		r.snmpProblem[lc] = "the device's own SNMP settings cannot be read: " + strings.Join(msgs(err), " ")
		return
	}
	if !own.isSet() {
		return
	}
	in, err := inv.walkthroughSNMPOwn(k.scope, deviceSNMPValues(e), own)
	if err != nil {
		// The scope's or the default's credentials cannot be read: the base
		// has said so and left the step out; so does the device.
		return
	}
	r.snmp[lc] = in
	if r.logReads && !own.Creds.Empty() && !r.logged["snmp-device "+lc] {
		r.logged["snmp-device "+lc] = true
		inv.secretRead("snmp-device", e.Name)
	}
}

// Expected is devices.Managed for a registered device: its own SNMP values
// laid over the vendor and scope's Data. It reads nothing but the prepared
// base and the entry, so it is safe to call concurrently. The error is why
// the device cannot be rendered for.
func (r *managedRender) Expected(e devreg.Entry) ([]devices.Section, error) {
	b, ok := r.base[r.keyOf(e)]
	switch {
	case !ok:
		return nil, errNoRender
	case b.problem != "":
		return nil, &renderProblem{msg: b.problem}
	}
	lc := strings.ToLower(e.Name)
	if why, bad := r.snmpProblem[lc]; bad {
		return nil, &renderProblem{msg: why}
	}
	d := b.d
	if in, ok := r.snmp[lc]; ok {
		d.SNMP = in
	} else {
		own := deviceSNMPValues(e)
		d.SNMP.DeviceName, d.SNMP.SysName, d.SNMP.Description, d.SNMP.Location = own.DeviceName, own.SysName, own.Description, own.Location
	}
	return devices.Managed(b.req, d)
}

// renderProblem is a refusal of the walkthrough's build, as the batch tells
// it.
type renderProblem struct{ msg string }

func (e *renderProblem) Error() string { return e.msg }

// errNoRender is a device whose vendor, scope or kind has no expected
// configuration.
var errNoRender = &renderProblem{msg: "nothing is rendered for this device"}

// ansiRE matches the colour sequences of ui's tags.
var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// stripColour is s without colour sequences.
func stripColour(s string) string { return ansiRE.ReplaceAllString(s, "") }
