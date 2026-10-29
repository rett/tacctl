package cli

// 'config show' (lib/groups.sh cmd_config_show) and 'config validate'
// (lib/service.sh cmd_config_validate), the two reports of the config
// family. Every 'echo -e' line of 0.1.16 is printed through echoE, so a
// value with a backslash escape prints the same bytes.

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// --- show ---------------------------------------------------------------------

// configShow is cmd_config_show: the scopes with their secret length,
// users and prefixes; the built-in groups' levels and classes; the global
// management-ACL names; the connection filters; then per enabled backend
// its config file, service state and listeners (probed with ss).
func (inv *invocation) configShow([]string) error {
	a := inv.app
	B, NC, R, C := ui.Bold, ui.NC, ui.Red, ui.Cyan
	inv.echo("")
	inv.echoE(B + "Configuration" + NC)
	inv.echo("--------------------------------------------")

	m, err := inv.model()
	if err != nil {
		return err
	}
	view := m.ConfigShow()
	cs := map[string]string{}
	for _, l := range view {
		k, v, _ := strings.Cut(l, "=")
		if k != "scope" && k != "prefix" && k != "" {
			cs[k] = v
		}
	}
	def, err := inv.defaultScope()
	if err != nil {
		return err
	}
	inv.echo("")
	inv.echoE("  " + B + "Scopes:" + NC)
	empty := "        " + R + "(empty — no clients can auth against this scope)" + NC
	hasScope := false
	for _, l := range view {
		if strings.HasPrefix(l, "scope=") {
			hasScope = true
		}
	}
	if !hasScope {
		inv.echoE("    " + R + "(none configured)" + NC)
	} else {
		// A scope's prefix lines follow its scope line; the "(empty)" note
		// comes when the next scope (or the end) arrives without any.
		pending := false
		for _, l := range view {
			k, v, _ := strings.Cut(l, "=")
			switch k {
			case "scope":
				if pending {
					inv.echoE(empty)
				}
				f := strings.SplitN(v, "|", 3)
				for len(f) < 3 {
					f = append(f, "")
				}
				marker := ""
				if f[0] == def {
					marker = "  " + C + "(default)" + NC
				}
				inv.echoE("    " + B + f[0] + NC + marker)
				inv.echoE("      Secret:             " + f[1] + " chars")
				inv.echoE("      Users:              " + f[2])
				inv.echoE("      Prefixes:")
				pending = true
			case "prefix":
				inv.echo("        - " + v)
				pending = false
			}
		}
		if pending {
			inv.echoE(empty)
		}
	}
	inv.echo("")
	inv.echoE("  " + B + "Cisco (priv-lvl):" + NC)
	inv.echoE("    Super-user:         " + cs["cisco_rw"])
	inv.echoE("    Operator:           " + cs["cisco_op"])
	inv.echoE("    Read-only:          " + cs["cisco_ro"])
	inv.echo("")
	inv.echoE("  " + B + "Juniper (local-user-name):" + NC)
	inv.echoE("    Super-user class:   " + cs["juniper_rw"])
	inv.echoE("    Operator class:     " + cs["juniper_op"])
	inv.echoE("    Read-only class:    " + cs["juniper_ro"])

	// The global management-ACL names (read_mgmt_acl_name <vendor>): what
	// new scopes inherit; per-scope ones are in 'tacctl scope show'.
	cfg := a.Conf()
	cisco, _ := cfg.Get("mgmt_acl.names.cisco", "VTY-ACL")
	juniper, _ := cfg.Get("mgmt_acl.names.juniper", "MGMT-ACL")
	inv.echo("")
	inv.echoE("  " + B + "Management ACL names (global defaults):" + NC)
	inv.echoE("    Cisco ACL:          " + cisco)
	inv.echoE("    Juniper filter:     " + juniper)

	// The interface a scope's Cisco devices source their server requests
	// from (D119): listed when a scope sets one; unset renders nothing.
	var sources []string
	for _, s := range m.ScopeNames() {
		if v, _ := cfg.Get(ciscoSourceInterfaceKey(s), ""); v != "" {
			sources = append(sources, "    "+s+": "+v)
		}
	}
	if len(sources) > 0 {
		inv.echo("")
		inv.echoE("  " + B + "Cisco source interface (per scope):" + NC)
		for _, l := range sources {
			inv.echoE(l)
		}
	}

	inv.echo("")
	inv.echoE("  " + B + "Connection Filters:" + NC + " " + C + "(deny takes precedence over allow)" + NC)
	if cs["deny"] != "" {
		inv.echoE("    Deny:               " + cs["deny"])
	} else {
		inv.echoE("    Deny:               " + C + "(none)" + NC)
	}
	if cs["allow"] != "" {
		inv.echoE("    Allow:              " + cs["allow"])
	} else {
		inv.echoE("    Allow:              " + C + "(all)" + NC)
	}

	// What each enabled backend serves: its rendered config, its service and
	// the listeners it should have, probed where the listener model says
	// (tcp or udp, the port of the listener). With one backend these are
	// plain lines; with more, each has a labelled block.
	set := a.Backends()
	enabled, err := set.Enabled()
	if err != nil {
		a.Out.ErrorE(err.Error())
		return exit(1)
	}
	ind := ""
	for _, id := range enabled {
		b, err := set.Get(id)
		if err != nil {
			return err
		}
		inv.echo("")
		if len(enabled) > 1 {
			inv.echoE("  " + B + "Backend: " + id + NC)
			ind = "  "
		}
		artifact := ""
		if arts := b.Artifacts(); len(arts) > 0 {
			artifact = arts[0]
		}
		inv.echoE(ind + "  " + B + "Config file:" + NC + "          " + artifact)
		state, _ := b.Service(inv.ctx, backend.ServiceIsActive, "")
		if state == "" {
			state = "unknown"
		}
		inv.echoE(ind + "  " + B + "Service status:" + NC + "       " + state)
		ls, _ := b.Listeners().List()
		for _, l := range ls {
			if l.Name == "" {
				continue
			}
			label, pad := "Listening on:", "         "
			if l.Name != "default" {
				label, pad = "Listening on ("+l.Name+"):", " "
			}
			if bound := inv.listenerProbe(l.Network, l.Address); bound != "" {
				inv.echoE(ind + "  " + B + label + NC + pad + bound)
			} else {
				inv.echoE(ind + "  " + B + label + NC + pad + R + "port " + l.Address[strings.LastIndexByte(l.Address, ':')+1:] + " not detected" + NC)
			}
		}
	}
	inv.echo("")
	return nil
}

// listenerProbe is backend_listener_probe: the local address of the first
// line of 'ss -tlnp' (-ulnp for a udp network) that has ":<port> ", or "".
func (inv *invocation) listenerProbe(network, address string) string {
	flags := "-tlnp"
	if strings.HasPrefix(network, "udp") {
		flags = "-ulnp"
	}
	res, _ := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "ss", Args: []string{flags}})
	needle := ":" + address[strings.LastIndexByte(address, ':')+1:] + " "
	for _, line := range strings.Split(string(res.Stdout), "\n") {
		if strings.Contains(line, needle) {
			if f := strings.Fields(line); len(f) >= 4 {
				return f[3]
			}
			return ""
		}
	}
	return ""
}

// --- validate -------------------------------------------------------------------

// configValidate is cmd_config_validate. With a store: the store against
// its schema, tacctl.yaml against its own, the model's structure, the
// default scope, then per enabled backend a trial render (is the live
// artifact that render?) and drift, and RADIUS's vendor-attribute gaps.
// Without one (legacy read-only mode): tacquito.yaml must parse, and the
// model read from it gets the full reference checks. Exit 1 when anything
// is an error. With --json the findings are printed as one JSON object and
// nothing else goes to standard output (D220). With --fix-names the report
// is followed by the offer to rename each name with upper case (D226).
func (inv *invocation) configValidate(args []string) error {
	p, err := Parse(configSpecs["validate"], args)
	if err != nil {
		msg := err.Error()
		if uf, ok := err.(*UnknownFlagError); ok {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.usageErr(msg, configValidateUsage)
	}
	fix := p.Has("--fix-names")
	switch {
	case fix && p.Has("--json"):
		return inv.usageErr("--fix-names asks questions and renames; it does not go with --json.", configValidateUsage)
	case p.Has("-y") && !fix:
		return inv.usageErr("-y goes with --fix-names.", configValidateUsage)
	}
	if fix {
		if err := inv.fixNamesAllowed(); err != nil {
			return err
		}
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	if p.Has("--json") {
		return inv.configValidateJSON()
	}
	r := &validateReport{sink: inv.printValidateText}
	inv.collectValidate(r)
	inv.printValidateTextEnd(r)
	failed := r.textErrors() > 0
	if fix {
		left, err := inv.fixNames(p.Has("-y"))
		if err != nil {
			return err
		}
		failed = failed || left
	}
	if failed {
		return exit(1)
	}
	return nil
}

// configValidateUsage is the usage line of 'config validate'.
const configValidateUsage = "Usage: tacctl config validate [--json | --fix-names [-y]]"

// collectValidate runs the checks of 'config validate' and adds what they
// print, and the findings that are, to r in the order the text report has
// them (D219).
func (inv *invocation) collectValidate(r *validateReport) {
	a := inv.app
	G, R, Y, B, NC := ui.Green, ui.Red, ui.Yellow, ui.Bold, ui.NC
	storeMode := model.Mode(a.Paths.StoreFile) == "store"
	r.storeMode = storeMode
	r.line(howEcho, "")
	if storeMode {
		r.line(howEchoE, B+"Validating "+a.Paths.StoreFile+"..."+NC)
	} else {
		r.line(howEchoE, B+"Validating "+a.Paths.Config+"..."+NC)
	}
	r.line(howEcho, "")

	if storeMode {
		// store_validate: one 'tacctl store: <problem>' line per error.
		problems, err := store.ValidateFile(a.Paths.StoreFile)
		if err != nil {
			problems = strings.Split(store.Report(err), "\n")
		}
		if len(problems) == 0 {
			r.line(howEchoE, "  "+G+"Store:"+NC+"                valid")
		}
		for _, p := range problems {
			p = strings.TrimPrefix(p, "tacctl store: ")
			if p == "" {
				continue
			}
			r.found(howEchoE, "  "+R+"Store:"+NC+"                "+p, validateFinding{Section: "store", Level: levelError, Text: p})
		}
	} else {
		if problem := cfgYAMLProblem(a.Paths.Config); problem == nil {
			r.line(howEchoE, "  "+G+"YAML syntax:"+NC+"          valid")
		} else {
			// 0.1.16 printed the first three lines of the Python traceback
			// here; this prints the first three lines of the YAML error.
			lines := strings.Split(problem.Error(), "\n")
			if len(lines) > 3 {
				lines = lines[:3]
			}
			r.found(howEchoE, "  "+R+"YAML syntax:"+NC+"          INVALID", validateFinding{
				Section: "yaml", Level: levelError, Text: "the YAML is not valid: " + strings.Join(lines, " ")})
			r.line(howRaw, strings.Join(lines, "\n")+"\n")
		}
		r.found(howEchoE, "  "+Y+"Store:"+NC+"                not initialised — read-only until 'tacctl store import' ('tacctl store import --check' reports what it would do)",
			validateFinding{Section: "store", Level: levelWarning, Text: "not initialised: tacctl is read-only until the legacy file is imported", Fix: "tacctl store import"})
	}

	// tacctl.yaml: does it parse (yaml.safe_load), then the schema walk of
	// the file itself (hand edits the setters would have refused).
	ovr := a.Paths.Overrides
	cfg := a.Conf()
	switch {
	case !cfgIsFile(ovr):
		r.line(howEchoE, "  "+G+"tacctl.yaml:"+NC+"          no overrides")
	case cfgYAMLProblem(ovr) == nil:
		r.line(howEchoE, "  "+G+"tacctl.yaml:"+NC+"          valid")
		for _, l := range cfg.Schema.ValidateFile(ovr) {
			if l == "" {
				continue
			}
			r.found(howEchoE, "  "+R+"tacctl.yaml:"+NC+"          "+l, validateFinding{Section: "overrides", Level: levelError, Text: l})
		}
	default:
		first := ""
		if lines := cfg.Schema.ValidateFile(ovr); len(lines) > 0 {
			first = lines[0]
		}
		why := "the YAML is not valid"
		if first != "" {
			why += ": " + first
		}
		r.found(howEchoE, "  "+R+"tacctl.yaml:"+NC+"          INVALID — "+first, validateFinding{Section: "overrides", Level: levelError, Text: why})
	}

	// Command rules that cannot work as written (an empty or invalid match,
	// a prefix form that matches the exact arguments only, a rule an
	// earlier one makes unreachable): warnings, the file is still valid.
	for _, l := range inv.commandRuleWarnings() {
		r.found(howEcho, "  "+Y+"Command rules:"+NC+"        "+l, validateFinding{Section: "command_rules", Level: levelWarning, Text: l})
	}

	// What the model says: is there anything to serve, are the secrets
	// real. A store has had its references checked above; a legacy model
	// gets the full set here.
	r.counts = map[string]string{"users": "?", "groups": "?", "scopes": "?"}
	counts := r.counts
	structure := 0
	var scopeNames []string
	m, merr := inv.model()
	if merr == nil {
		for _, l := range m.Validate(!storeMode) {
			switch {
			case strings.HasPrefix(l, "COUNT:"):
				k, v, _ := strings.Cut(strings.TrimPrefix(l, "COUNT:"), "=")
				counts[k] = v
			case strings.HasPrefix(l, "ERROR:"):
				text := strings.TrimPrefix(l, "ERROR:")
				r.found(howEchoE, "  "+R+"Error:"+NC+"                "+text, validateFinding{Section: "structure", Level: levelError, Text: text})
				structure++
			}
		}
		// the count and the names leave out the managed scope
		shown := m.WithoutScope(inv.managedScope())
		counts["scopes"] = strconv.Itoa(len(shown.Scopes))
		scopeNames = shown.ScopeNames()
	} else {
		// The model's own complaint, once, then the line that points at it.
		r.modelErr(merr)
		r.found(howEchoE, "  "+R+"Error:"+NC+"                users, groups and scopes could not be read (see above)",
			validateFinding{Section: "structure", Level: levelError, Text: "users, groups and scopes could not be read (see standard error)"})
		structure = 1
	}
	if structure == 0 {
		r.line(howEchoE, "  "+G+"Config structure:"+NC+"     valid")
	}

	// scope.default in tacctl.yaml must name an existing scope.
	if def, _ := cfg.Get("scope.default", ""); merr == nil && def != "" && !contains(scopeNames, def) {
		text := "Default scope override points at '" + def + "' which is not a defined scope"
		r.found(howEchoE, "  "+R+"Error:"+NC+"                "+text, validateFinding{Section: "scope_default", Level: levelError, Text: text})
	} else {
		r.line(howEchoE, "  "+G+"Scopes integrity:"+NC+"     valid")
	}

	// Enrolled Linux hosts: is each one's registered scope the one that
	// answers its address? A warning: the host is not moved.
	if reg, err := inv.registry(); err == nil && merr == nil && !reg.Empty() {
		drift := 0
		for _, e := range reg.Entries() {
			if msg := inv.hostScopeDrift(e, inv.hostAddress(e)); msg != "" {
				r.found(howEchoE, "  "+Y+"Linux hosts:"+NC+"          "+msg, validateFinding{
					Section: "linux_hosts", Level: levelWarning, Text: msg, Hosts: []string{e.Name}})
				drift++
			}
		}
		if drift == 0 {
			r.line(howEchoE, "  "+G+"Linux hosts:"+NC+"          each answered by its scope")
		}
	}
	// Hosts registered twice under one name, a host named like a device, two
	// hosts at one address, and what a registry line no longer has: warnings
	// that name the verb that puts each right (D187).
	for _, fnd := range inv.hostFindings() {
		r.found(howEchoE, "  "+Y+"Linux hosts:"+NC+"          "+fnd.String(), validateFinding{
			Section: "linux_hosts", Level: levelWarning, Text: fnd.Text, Fix: fnd.Fix, Hosts: fnd.Hosts})
	}

	// Names with upper case: they keep working, and each is listed with the
	// verb that renames it (D204).
	for _, fnd := range inv.caseFindings() {
		r.found(howEchoE, "  "+Y+"Names:"+NC+"                "+fnd.String(), validateFinding{
			Section: "names", Level: levelWarning, Text: fnd.Text, Fix: fnd.Fix, Hosts: fnd.Hosts,
			Kind: fnd.Kind, Name: fnd.Name, To: fnd.To, Verb: fnd.Verb})
	}

	// A user whose name has a period (0.2.20 and 0.2.21 allowed it): an
	// error with the verb that renames it. `tacctl upgrade` refuses while
	// one stands.
	for _, fnd := range inv.dottedUserFindings() {
		r.found(howEchoE, "  "+R+"Names:"+NC+"                "+fnd.Text+" ("+fnd.Fix+")", fnd)
	}

	// Break-glass local users (D55): a scope without one is a lockout risk
	// when the server is unreachable, and a name that is also a tacctl user
	// of its scope is shadowed on the device. Warnings, never errors.
	if merr == nil {
		var bare, rootOnly []string
		for _, s := range scopeNames {
			users := policy.BreakGlassUsers(cfg, s)
			if len(users) == 0 {
				bare = append(bare, s)
			}
			if onlyJunosRoot(users) {
				rootOnly = append(rootOnly, s)
			}
			for _, u := range users {
				if containsFold(m.Members(s), u.Name) {
					text := "'" + u.Name + "' in scope '" + s + "' is also a tacctl user of the scope; a local account of that name shadows the server's"
					r.found(howEchoE, "  "+Y+"Break-glass:"+NC+"          "+text, validateFinding{Section: "breakglass", Level: levelWarning, Text: text})
				}
			}
		}
		if len(bare) > 0 {
			word := "scope"
			if len(bare) > 1 {
				word = "scopes"
			}
			text := word + " " + quoteJoin(bare) + " without a break-glass local user — a lockout risk with the server unreachable"
			fix := "tacctl scope breakglass <scope> add <name>"
			r.found(howEchoE, "  "+Y+"Break-glass:"+NC+"          "+text+" ("+fix+")", validateFinding{Section: "breakglass", Level: levelWarning, Text: text, Fix: fix})
		}
		// 'root' is a Junos account: a scope whose only entry it is has no
		// local account on its Cisco and WTI devices.
		for _, fnd := range inv.rootOnlyFindings(rootOnly) {
			r.found(howEchoE, "  "+Y+"Break-glass:"+NC+"          "+fnd.Text+" ("+fnd.Fix+")", validateFinding{Section: "breakglass", Level: levelWarning, Text: fnd.Text, Fix: fnd.Fix})
		}
	}

	// Break-glass holds: a warning per hold while it stands; red when it
	// holds no registered device (an orphan: none of its name is registered,
	// or the one that is stands at another address; the record still
	// silences its address, and 'breakglass release' removes it), and red
	// for an entry the file holds that is not a usable hold (no address, an
	// address that is not one, a key with a dot in it), so none is invisible.
	// An orphan does not count toward the exit status: its finding is a
	// warning.
	if hs := inv.holdSeenBy(); len(hs) > 0 {
		orphans := inv.holdOrphans(hs)
		now := a.Knobs.Now()
		for _, h := range hs {
			fix := "tacctl breakglass release " + h.Device
			if why, ok := orphans[h.Device]; ok {
				text := h.Device + " is an orphan record: " + why + "; it still silences " + h.Address
				r.found(howEchoE, "  "+R+"Break-glass hold:"+NC+"    "+text+" ("+fix+")", validateFinding{Section: "breakglass_hold", Level: levelWarning, Text: text, Fix: fix})
				continue
			}
			text := h.Device + " (" + h.Address + ") held since " + holdTime(h) + " by " + h.By +
				" (" + holdAge(h, now) + "): the server does not answer it"
			r.found(howEchoE, "  "+Y+"Break-glass hold:"+NC+"    "+text+" ("+fix+")", validateFinding{Section: "breakglass_hold", Level: levelWarning, Text: text, Fix: fix})
		}
	}
	if !inv.callerScopes().restricted {
		for _, d := range cfg.HoldDefects() {
			fix := "tacctl breakglass release " + d.Device
			note := "'" + fix + "' releases it, and the hold can then be made again"
			if !d.Usable {
				note = fix + " removes it"
			}
			text := "breakglass_hold." + d.Key + " (device " + d.Device + ") " + d.Defect
			// The schema walk above names a wrong address and a key it
			// does not know; a record without its address it accepts.
			level := levelWarning
			if d.Address == "" {
				level = levelError
			}
			r.found(howEchoE, "  "+R+"Break-glass hold:"+NC+"    "+text+" ("+note+")", validateFinding{Section: "breakglass_hold", Level: level, Text: text, Fix: fix})
		}
	}

	// Emergency lockdowns (0.2.19): one warning per lockdown that stands, an
	// error for a record that names a scope or group that is gone, a
	// superuser group, or nothing.
	for _, fnd := range inv.lockdownFindings(m) {
		label, color := "Emergency lockdown:", Y
		if fnd.Level == levelError {
			color = R
		}
		r.found(howEchoE, "  "+color+label+NC+"  "+fnd.Text+" ("+fnd.Fix+")", fnd)
	}

	// Configuration blocks (0.2.7): a name with no file is an error (it
	// renders nothing), a file no list names a warning (it is ignored), and so
	// is a device's orphan; a block in force that has errors is an error (it
	// refuses every Junos device it reaches). Nothing is printed for an
	// installation that has none.
	if inv.blocksExist() {
		bErrs, bWarns := inv.blockValidation()
		for _, l := range bErrs {
			r.found(howEchoE, "  "+R+"Config blocks:"+NC+"        "+l, validateFinding{Section: "config_blocks", Level: levelError, Text: l})
		}
		for _, l := range bWarns {
			r.found(howEchoE, "  "+Y+"Config blocks:"+NC+"        "+l, validateFinding{Section: "config_blocks", Level: levelWarning, Text: l})
		}
		if len(bErrs)+len(bWarns) == 0 {
			r.line(howEchoE, "  "+G+"Config blocks:"+NC+"        valid")
		}
	}

	// Stored settings that still give the operator or the viewer what
	// 0.2.5 removed (a clear, a capture, a flood form of ping): a warning
	// naming each with the command that takes the shipped value.
	for _, s := range policy.StaleOperatorPolicy(cfg) {
		text := s.String() + " still gives the operator or the viewer a command that can interrupt service"
		r.found(howEchoE, "  "+Y+"Operator policy:"+NC+"      "+text+"; '"+s.Fix()+"' puts back "+s.Restores(),
			validateFinding{Section: "operator_policy", Level: levelWarning, Text: text + "; the fix puts back " + s.Restores(), Fix: s.Fix()})
	}

	// Tier, WTI-level and Junos settings of a group the store does not have
	// (a group removed by an import or a restore): the next group of that
	// name would take them over. A warning.
	if merr == nil && storeMode {
		for _, l := range inv.staleGroupLines(m) {
			r.found(howEchoE, "  "+Y+"Group settings:"+NC+"       "+l, validateFinding{Section: "group_settings", Level: levelWarning, Text: l})
		}
	}

	// Keys of a group or scope the store does not have, in the families the
	// block above does not cover: the next one of that name would take them
	// over. Warnings; 'scope remove' and 'group remove' drop what they own,
	// so these come from an import, a restore or a hand edit.
	if merr == nil && storeMode {
		for _, l := range inv.orphanKeyLines(m) {
			r.found(howEchoE, "  "+Y+"Orphan settings:"+NC+"      "+l, validateFinding{Section: "orphan_settings", Level: levelWarning, Text: l})
		}
		for _, l := range inv.orphanFileLines(m) {
			r.found(howEchoE, "  "+Y+"Orphan files:"+NC+"         "+l, validateFinding{Section: "orphan_files", Level: levelWarning, Text: l})
		}
	}

	// An empty privileges.<group> on a built-in group that ships a list: the
	// empty list hides it. A warning; 'group privilege reset' removes it.
	for _, g := range policy.EmptyPrivilegeOverrides(cfg) {
		def := policy.DefaultPrivileges(g)
		n := "1 mapping"
		if len(def) != 1 {
			n = strconv.Itoa(len(def)) + " mappings"
		}
		text := "privileges." + g + " is an empty list in tacctl.yaml: it hides the shipped default (" + n + ": " + strings.Join(def, ", ") + ")"
		fix := "tacctl group privilege reset " + g
		r.found(howEchoE, "  "+Y+"Group settings:"+NC+"       "+text+"; '"+fix+"' removes it", validateFinding{Section: "group_settings", Level: levelWarning, Text: text, Fix: fix})
	}

	// What an interrupted command left in the state directory: the private
	// copies of store.yaml and tacctl.yaml that StoreApply, a restore, an
	// enable and a settings change take. A command that is running holds the
	// apply lock and its directory is young; an old one is a leftover (a
	// kill), and it holds secrets. A warning.
	for _, l := range inv.leftoverLines() {
		r.found(howEchoE, "  "+Y+"Leftovers:"+NC+"           "+l, validateFinding{Section: "leftovers", Level: levelWarning, Text: l})
	}

	// Rendered artifacts: can the store be rendered, and are the live files
	// that render? A hand-edited file is reported by the DRIFT line
	// instead, and counted once. With one enabled backend these are plain
	// lines; with more, each backend has a labelled block, and the
	// artifacts no backend claims come first.
	set := a.Backends()
	enabled, err := set.Enabled()
	if err != nil {
		if storeMode {
			r.found(howErrorE, err.Error(), validateFinding{Section: "backends", Level: levelError, Text: err.Error()})
		}
		enabled = nil
	}
	r.backends = enabled
	multi := len(enabled) > 1
	targets := enabled
	if len(targets) == 0 {
		targets = []string{""}
	}
	drifted := func(sel backend.DriftSelection, id string) {
		for i, d := range set.DriftReports(sel) {
			r.found(howRaw, strings.Join(d.Lines(), ""),
				validateFinding{Section: "drift", Level: levelError, Backend: id, Text: d.Path + " — " + d.What, Fix: d.Advice, repeat: i > 0})
		}
	}
	if multi {
		drifted(backend.DriftUnowned, "")
	}
	ind := ""
	for _, id := range targets {
		sel := backend.DriftAll
		if multi {
			r.line(howEchoE, "  "+B+"Backend "+id+":"+NC)
			ind = "  "
			sel = backend.DriftOf(id)
		}
		hasDrift := len(set.CheckDrift(sel)) > 0
		if storeMode && id != "" {
			label, lerr := set.ArtifactNames(id)
			if lerr != nil {
				label = id
			}
			b, gerr := set.Get(id)
			var state string
			if gerr == nil {
				state, gerr = b.RenderCheck(inv.ctx)
			}
			switch {
			case gerr != nil:
				r.found(howEchoE, ind+"  "+R+"Rendered config:"+NC+"      the store cannot be rendered (see above)",
					validateFinding{Section: "rendered", Level: levelError, Backend: id, Text: "the store cannot be rendered (see standard error)"})
			case hasDrift:
			case state == "current" || state == "same":
				r.line(howEchoE, ind+"  "+G+"Rendered config:"+NC+"      up to date")
			case state == "missing":
				r.found(howEchoE, ind+"  "+R+"Rendered config:"+NC+"      "+label+" is missing — run 'tacctl config render'",
					validateFinding{Section: "rendered", Level: levelError, Backend: id, Text: label + " is missing", Fix: "tacctl config render"})
			case state == "unrecorded":
				text := label + " was not rendered by tacctl yet — the next change replaces it if it says what the store says"
				r.found(howEchoE, ind+"  "+Y+"Rendered config:"+NC+"      "+text+"; otherwise run 'tacctl config render --force'",
					validateFinding{Section: "rendered", Level: levelWarning, Backend: id, Text: text, Fix: "tacctl config render --force"})
			default:
				r.found(howEchoE, ind+"  "+R+"Rendered config:"+NC+"      "+label+" is out of date with the store — run 'tacctl config render'",
					validateFinding{Section: "rendered", Level: levelError, Backend: id, Text: label + " is out of date with the store", Fix: "tacctl config render"})
			}
		}
		if hasDrift {
			drifted(sel, id)
		}
		// RADIUS sends a vendor's privilege attribute only where a scope
		// opts in: a warning for the scopes of devices that opt into none
		// (Linux-host scopes, told apart by the host registry, need none).
		if storeMode && id == backend.RADIUS && merr == nil {
			if gaps := m.VendorGaps(cfgHostCounts(a.Paths.LinuxHosts)); len(gaps) > 0 {
				text := "not sent to the devices of scope(s) " + strings.Join(gaps, ", ") +
					" over RADIUS: Cisco, Juniper and WTI devices there get Service-Type only (Linux hosts need none)"
				fix := "tacctl scope vendor-attrs <scope> enable cisco|juniper|wti"
				r.found(howEchoE, ind+"  "+Y+"Vendor attributes:"+NC+"    not sent to the devices of scope(s) "+strings.Join(gaps, ", ")+
					" over RADIUS: Cisco, Juniper and WTI devices there get Service-Type only",
					validateFinding{Section: "vendor_attrs", Level: levelWarning, Backend: id, Text: text, Fix: fix})
				r.line(howEchoE, ind+"                        (Linux hosts need none). Enable what they need: "+fix)
			}
		}
	}

	r.line(howEchoE, "  "+G+"Groups defined:"+NC+"       "+counts["groups"])
	r.line(howEchoE, "  "+G+"Scopes defined:"+NC+"       "+counts["scopes"])
	r.line(howEchoE, "  "+G+"Users defined:"+NC+"        "+counts["users"])
}

// cfgYAMLProblem is 'python3 -c "import yaml; yaml.safe_load(open(f))"'
// failing: the error, or nil when the file parses. YAML that safe_load
// reads but tacctl does not support (docs/plans/go-rewrite.md 3.9 item 15)
// parses here; the schema walk reports it.
func cfgYAMLProblem(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, err = pyyaml.Load(data, path)
	var ue *pyyaml.UnsupportedError
	if err == nil || errors.As(err, &ue) {
		return nil
	}
	return err
}

// reportModelError prints the model's load error on stderr the way
// exit.go would (model_load's message), for a report that goes on.
func (inv *invocation) reportModelError(err error) {
	out := inv.app.Out
	var ns *model.NoSourceError
	switch {
	case store.Reportable(err):
		inv.stderrLine(store.Report(err))
	case errors.As(err, &ns):
		out.Error(err.Error())
	default:
		out.Error(err.Error())
	}
}

// cfgHostCounts is what model_vendor_gaps passes the view: field 4 of
// every line of the host registry ('cut -d| -f4': a line without a '|' is
// its own field 4), lines that are blank there left out, counted.
func cfgHostCounts(path string) map[string]int {
	counts := map[string]int{}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return counts
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		f := line
		if strings.Contains(line, "|") {
			fl := strings.Split(line, "|")
			f = ""
			if len(fl) >= 4 {
				f = fl[3]
			}
		}
		if strings.TrimSpace(f) != "" {
			counts[f]++
		}
	}
	return counts
}

// leftoverMinAge is how old a private copy under the state directory must be
// before it is a leftover and not a command at work.
const leftoverMinAge = 10 * time.Minute

// leftoverLines names the directories (and the one file) that an interrupted
// command left in the state directory, each with the age and what to do.
func (inv *invocation) leftoverLines() []string {
	dir := inv.app.Paths.StateDir
	if applylock.Busy(dir) {
		return nil // a command is at work: its directories are not leftovers
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	now := inv.app.Knobs.Now()
	var out []string
	for _, e := range entries {
		name := e.Name()
		match := false
		for _, p := range []string{".apply.", ".restore.", ".enable.", ".units.", ".disable."} {
			if strings.HasPrefix(name, p) {
				match = true
			}
		}
		if !match {
			continue
		}
		fi, err := e.Info()
		if err != nil || now.Sub(fi.ModTime()) < leftoverMinAge {
			continue
		}
		out = append(out, filepath.Join(dir, name)+" is a leftover of an interrupted command ("+
			strconv.Itoa(int(now.Sub(fi.ModTime()).Round(time.Minute)/time.Minute))+" minutes old) and holds a copy of the configuration; "+
			"check 'tacctl backup list' and 'tacctl status', then remove it")
	}
	return out
}
