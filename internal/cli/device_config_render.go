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

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/policy"
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
	// BlockDevice names the registered device of the scope whose own
	// configuration blocks are laid over the scope's (empty: the scope's
	// alone, which is what a batch's shared base is).
	BlockDevice string
	// Override is a block text laid in place of the file in force
	// ('block check --against'); nil for none.
	Override *blockOverride
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
	// The snmp and system blocks of the scope, and of the device when it has
	// some of its own (0.2.7; the IOS snmp block for a Cisco device). One
	// with an error is never rendered in part: the refusal names the scope
	// or the device and the verb that says what is wrong.
	if p.Vendor == "juniper" || p.Vendor == "cisco" {
		blk, layers, err := inv.resolveBlocks(p.Vendor, p.Scope, p.BlockDevice, p.Override)
		if err != nil {
			return req, d, inv.usageErr(msgs(err)...)
		}
		d.Blocks = blk
		// An engineer's walkthrough shows the block's community strings as it
		// shows the scope's, and the system block's NTP key: a read of its
		// own, logged.
		if p.Restricted {
			inv.logBlockReads(blk, layers, p.Scope, p.BlockDevice)
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
	// recs are the configuration records as prepare read them: the pull's
	// version line is where a device's syntax comes from (D113), so the
	// render reads the records once, before any worker starts.
	recs *devconf.Records
	// logged are the scopes whose reads were logged.
	logged map[string]bool
	// snmp is each prepared device's SNMP input, by lowercased name: the
	// scope's settings with the device's own over them (D72), and
	// snmpProblem why a device's own settings cannot be read (it is not
	// compared against the scope's, which would read as drift).
	snmp        map[string]devices.SNMPInput
	snmpProblem map[string]string
	// devBlocks are the blocks of the devices that have some of their own,
	// by lowercased name: the scope's with the device's laid over them.
	devBlocks map[string]*deviceBlocks
	// override is a block text laid in place of the file in force
	// ('block check --against'); nil for none.
	override *blockOverride
}

// deviceBlocks is the resolution of one device's blocks, or why there is
// none (a block of the device with an error: the refusal names it).
type deviceBlocks struct {
	blocks  devices.Blocks
	problem string
}

// newManagedRender is a render for the batch verbs. The expected
// configuration is the same for every caller (the superuser's, the
// complete one): what a device is compared with does not depend on who
// asks, so the states a pull records agree whoever pulled.
func (inv *invocation) newManagedRender(opts managedOptions, logReads bool) *managedRender {
	return &managedRender{inv: inv, opts: opts, logReads: logReads,
		base: map[managedKey]*managedBase{}, logged: map[string]bool{},
		snmp: map[string]devices.SNMPInput{}, snmpProblem: map[string]string{}, devBlocks: map[string]*deviceBlocks{}}
}

// keyOf is the sharing key of a registered device. A device whose syntax is
// unknown (needs pull) is keyed as the modern syntax: it has no expectation
// of its own (Expected refuses it), and the pull renders it in the syntax
// it reads (ExpectedAs).
func (r *managedRender) keyOf(e devreg.Entry) managedKey {
	legacy, _ := r.syntaxFor(e)
	return managedKey{vendor: e.Vendor, scope: e.Scope, legacy: legacy}
}

// syntaxMatters says whether the configuration syntax is a fact that
// changes what a device is compared against: a Cisco device of a scope that
// is served over TACACS+ (a RADIUS scope has the one 'radius server'
// syntax, as before D113).
func (inv *invocation) syntaxMatters(e devreg.Entry) bool {
	if e.Vendor != "cisco" || e.Scope == "" {
		return false
	}
	choice, source := inv.scopeProtocolChoice(e.Scope)
	protocol, _ := devices.ResolveProtocol("", choice, source)
	return protocol != devices.RADIUS
}

// syntaxOf is the one resolution of a Cisco device's configuration
// syntax (D113 (3)): the explicit setting, else the syntax the last pull
// derived from the device's version line, else nothing. The comparison, the
// walkthrough and the planner all take it from here; the ssh flag has no
// part in it.
func syntaxOf(e devreg.Entry, rec *devconf.Record) devconf.SyntaxResolution {
	return devconf.ResolveSyntax(e.ConfigSyntax, rec)
}

// syntaxFor is the rendering syntax of a registered device: legacy is the
// IOS 12.x syntax (devices.Request.Legacy), and known is false for a
// device that needs a pull to say (a Cisco device of a TACACS+ scope whose
// setting is auto and whose record has no syntax).
func (r *managedRender) syntaxFor(e devreg.Entry) (legacy, known bool) {
	if !r.inv.syntaxMatters(e) {
		return false, true
	}
	var rec *devconf.Record
	if r.recs != nil {
		rec, _ = r.recs.Of(e.Name)
	}
	switch syntaxOf(e, rec).Syntax {
	case devconf.SyntaxIOS12:
		return true, true
	case devconf.SyntaxModern:
		return false, true
	}
	return false, false
}

// prepare makes the bases of every vendor and scope the entries need. A
// refusal inside (RADIUS not enabled) is kept as the base's problem, not
// printed: the batch says it once per device in its own line.
func (r *managedRender) prepare(entries []devreg.Entry) {
	r.recs, _ = r.inv.configStore().Load()
	for _, e := range entries {
		if e.Source != devreg.SourceDevice || !e.Configured || (e.Vendor != "cisco" && e.Vendor != "juniper" && e.Vendor != "wti") {
			continue
		}
		k := r.keyOf(e)
		r.prepareKey(e, k)
		// A device whose setting is auto is rendered by a pull in the syntax
		// it reads then (unknown before the first pull, and an upgraded
		// device says another one than its record): both bases are made
		// before the workers start.
		if r.inv.syntaxMatters(e) && e.ConfigSyntax == "" {
			k2 := k
			k2.legacy = !k.legacy
			r.prepareKey(e, k2)
		}
		r.prepareOwn(e, k)
		r.prepareDeviceBlocks(e, k)
	}
}

// prepareKey makes the base of one key, once.
func (r *managedRender) prepareKey(e devreg.Entry, k managedKey) {
	inv := r.inv
	if _, done := r.base[k]; done {
		return
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
		Override: r.override,
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
		// the scope's blocks carry community strings and NTP keys: a read of
		// their own, once per scope
		if r.logReads && (d.Blocks.SNMP != nil || d.Blocks.CiscoSNMP != nil || d.Blocks.System != nil) && !r.logged["blocks "+k.scope+" "+k.vendor] {
			r.logged["blocks "+k.scope+" "+k.vendor] = true
			inv.logBlockReads(d.Blocks, [2]policy.BlockLayers{{Scope: d.Blocks.SNMP != nil || d.Blocks.CiscoSNMP != nil}, {Scope: d.Blocks.System != nil}}, k.scope, "")
		}
	}
}

// prepareDeviceBlocks resolves the blocks of one device that has some of its
// own in force (or is the one a check --against plans): the scope's, with the
// device's laid over them. A device with none renders the base's, which was
// made once for the scope. Nothing is read by Expected: this runs before any
// worker starts.
func (r *managedRender) prepareDeviceBlocks(e devreg.Entry, k managedKey) {
	inv := r.inv
	b := r.base[k]
	if (e.Vendor != blocks.VendorJuniper && e.Vendor != blocks.VendorCisco) || b == nil || b.problem != "" {
		return
	}
	lc := strings.ToLower(e.Name)
	cfg := inv.app.Conf()
	has := len(policy.DeviceBlockNames(cfg, e.Name, e.Vendor)) > 0 ||
		(r.override != nil && r.override.level.IsDevice() && strings.EqualFold(r.override.level.Device, e.Name))
	if !has {
		return
	}
	blk, layers, err := inv.resolveBlocks(e.Vendor, e.Scope, e.Name, r.override)
	if err != nil {
		r.devBlocks[lc] = &deviceBlocks{problem: strings.Join(msgs(err), " ")}
		return
	}
	r.devBlocks[lc] = &deviceBlocks{blocks: blk}
	if r.logReads && !r.logged["blocks-device "+lc] {
		r.logged["blocks-device "+lc] = true
		for i := range layers {
			layers[i].Scope = false // the scope's own were logged with its base
		}
		inv.logBlockReads(blk, layers, e.Scope, e.Name)
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
// the device cannot be rendered for; a Cisco device whose syntax is unknown
// is one (errSyntaxUnknown: it needs a pull).
func (r *managedRender) Expected(e devreg.Entry) ([]devices.Section, error) {
	legacy, known := r.syntaxFor(e)
	if !known {
		return nil, errSyntaxUnknown
	}
	return r.expectedFor(e, managedKey{vendor: e.Vendor, scope: e.Scope, legacy: legacy})
}

// ExpectedAs is Expected for a syntax the pull has just read from the
// device (legacy: the IOS 12.x syntax), for a device whose own resolution
// is unknown or out of date. A device the syntax does not matter for has
// one expectation, whatever is asked.
func (r *managedRender) ExpectedAs(e devreg.Entry, legacy bool) ([]devices.Section, error) {
	if !r.inv.syntaxMatters(e) {
		return r.Expected(e)
	}
	return r.expectedFor(e, managedKey{vendor: e.Vendor, scope: e.Scope, legacy: legacy})
}

func (r *managedRender) expectedFor(e devreg.Entry, k managedKey) ([]devices.Section, error) {
	b, ok := r.base[k]
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
	if db, ok := r.devBlocks[lc]; ok {
		if db.problem != "" {
			return nil, &renderProblem{msg: db.problem}
		}
		d.Blocks = db.blocks
	}
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

// errSyntaxUnknown is a Cisco device that has no configuration syntax yet
// (D113): its setting is auto and no pull has read its version line. It is
// neither compared as IOS 12.x nor as the modern syntax.
var errSyntaxUnknown = &renderProblem{msg: devconf.NeedsPullText}

// ansiRE matches the colour sequences of ui's tags.
var ansiRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// stripColour is s without colour sequences.
func stripColour(s string) string { return ansiRE.ReplaceAllString(s, "") }
