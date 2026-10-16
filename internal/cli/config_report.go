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
// is an error.
func (inv *invocation) configValidate([]string) error {
	a := inv.app
	out := a.Out
	G, R, Y, B, NC := ui.Green, ui.Red, ui.Yellow, ui.Bold, ui.NC
	storeMode := model.Mode(a.Paths.StoreFile) == "store"
	inv.echo("")
	if storeMode {
		inv.echoE(B + "Validating " + a.Paths.StoreFile + "..." + NC)
	} else {
		inv.echoE(B + "Validating " + a.Paths.Config + "..." + NC)
	}
	inv.echo("")
	errs := 0

	if storeMode {
		// store_validate: one 'tacctl store: <problem>' line per error.
		problems, err := store.ValidateFile(a.Paths.StoreFile)
		if err != nil {
			problems = strings.Split(store.Report(err), "\n")
		}
		if len(problems) == 0 {
			inv.echoE("  " + G + "Store:" + NC + "                valid")
		}
		for _, p := range problems {
			p = strings.TrimPrefix(p, "tacctl store: ")
			if p == "" {
				continue
			}
			inv.echoE("  " + R + "Store:" + NC + "                " + p)
			errs++
		}
	} else {
		if problem := cfgYAMLProblem(a.Paths.Config); problem == nil {
			inv.echoE("  " + G + "YAML syntax:" + NC + "          valid")
		} else {
			inv.echoE("  " + R + "YAML syntax:" + NC + "          INVALID")
			// 0.1.16 printed the first three lines of the Python traceback
			// here; this prints the first three lines of the YAML error.
			lines := strings.Split(problem.Error(), "\n")
			if len(lines) > 3 {
				lines = lines[:3]
			}
			inv.write(strings.Join(lines, "\n") + "\n")
			errs++
		}
		inv.echoE("  " + Y + "Store:" + NC + "                not initialised — read-only until 'tacctl store import' ('tacctl store import --check' reports what it would do)")
	}

	// tacctl.yaml: does it parse (yaml.safe_load), then the schema walk of
	// the file itself (hand edits the setters would have refused).
	ovr := a.Paths.Overrides
	cfg := a.Conf()
	switch {
	case !cfgIsFile(ovr):
		inv.echoE("  " + G + "tacctl.yaml:" + NC + "          no overrides")
	case cfgYAMLProblem(ovr) == nil:
		inv.echoE("  " + G + "tacctl.yaml:" + NC + "          valid")
		for _, l := range cfg.Schema.ValidateFile(ovr) {
			if l == "" {
				continue
			}
			inv.echoE("  " + R + "tacctl.yaml:" + NC + "          " + l)
			errs++
		}
	default:
		first := ""
		if lines := cfg.Schema.ValidateFile(ovr); len(lines) > 0 {
			first = lines[0]
		}
		inv.echoE("  " + R + "tacctl.yaml:" + NC + "          INVALID — " + first)
		errs++
	}

	// Command rules that cannot work as written (an empty or invalid match,
	// a prefix form that matches the exact arguments only, a rule an
	// earlier one makes unreachable): warnings, the file is still valid.
	for _, l := range inv.commandRuleWarnings() {
		inv.echo("  " + Y + "Command rules:" + NC + "        " + l)
	}

	// What the model says: is there anything to serve, are the secrets
	// real. A store has had its references checked above; a legacy model
	// gets the full set here.
	counts := map[string]string{"users": "?", "groups": "?", "scopes": "?"}
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
				inv.echoE("  " + R + "Error:" + NC + "                " + strings.TrimPrefix(l, "ERROR:"))
				structure++
			}
		}
		scopeNames = m.ScopeNames()
	} else {
		// The model's own complaint, once, then the line that points at it.
		inv.reportModelError(merr)
		inv.echoE("  " + R + "Error:" + NC + "                users, groups and scopes could not be read (see above)")
		structure = 1
	}
	if structure == 0 {
		inv.echoE("  " + G + "Config structure:" + NC + "     valid")
	}
	errs += structure

	// scope.default in tacctl.yaml must name an existing scope.
	if def, _ := cfg.Get("scope.default", ""); merr == nil && def != "" && !contains(scopeNames, def) {
		inv.echoE("  " + R + "Error:" + NC + "                Default scope override points at '" + def + "' which is not a defined scope")
		errs++
	} else {
		inv.echoE("  " + G + "Scopes integrity:" + NC + "     valid")
	}

	// Enrolled Linux hosts: is each one's registered scope the one that
	// answers its address? A warning: the host is not moved.
	if reg, err := inv.registry(); err == nil && merr == nil && !reg.Empty() {
		drift := 0
		for _, e := range reg.Entries() {
			if msg := inv.hostScopeDrift(e, inv.hostAddress(e)); msg != "" {
				inv.echoE("  " + Y + "Linux hosts:" + NC + "          " + msg)
				drift++
			}
		}
		if drift == 0 {
			inv.echoE("  " + G + "Linux hosts:" + NC + "          each answered by its scope")
		}
	}

	// Break-glass local users (D55): a scope without one is a lockout risk
	// when the server is unreachable, and a name that is also a tacctl user
	// of its scope is shadowed on the device. Warnings, never errors.
	if merr == nil {
		var bare []string
		for _, s := range scopeNames {
			users := policy.BreakGlassUsers(cfg, s)
			if len(users) == 0 {
				bare = append(bare, s)
			}
			for _, u := range users {
				if containsFold(m.Members(s), u.Name) {
					inv.echoE("  " + Y + "Break-glass:" + NC + "          '" + u.Name + "' in scope '" + s + "' is also a tacctl user of the scope; a local account of that name shadows the server's")
				}
			}
		}
		if len(bare) > 0 {
			word := "scope"
			if len(bare) > 1 {
				word = "scopes"
			}
			inv.echoE("  " + Y + "Break-glass:" + NC + "          " + word + " " + quoteJoin(bare) + " without a break-glass local user — a lockout risk with the server unreachable (tacctl scope breakglass <scope> add <name>)")
		}
	}

	// Break-glass holds: a warning per hold while it stands; red when it
	// holds no registered device (an orphan: none of its name is registered,
	// or the one that is stands at another address; the record still
	// silences its address, and 'breakglass release' removes it), and red
	// for an entry the file holds that is not a usable hold (no address, an
	// address that is not one, a key with a dot in it), so none is invisible.
	if hs := inv.holdSeenBy(); len(hs) > 0 {
		orphans := inv.holdOrphans(hs)
		now := a.Knobs.Now()
		for _, h := range hs {
			if why, ok := orphans[h.Device]; ok {
				inv.echoE("  " + R + "Break-glass hold:" + NC + "    " + h.Device + " is an orphan record: " + why + "; it still silences " + h.Address + " (tacctl breakglass release " + h.Device + ")")
				continue
			}
			inv.echoE("  " + Y + "Break-glass hold:" + NC + "    " + h.Device + " (" + h.Address + ") held since " + holdTime(h) + " by " + h.By +
				" (" + holdAge(h, now) + "): the server does not answer it (tacctl breakglass release " + h.Device + ")")
		}
	}
	if !inv.callerScopes().restricted {
		for _, d := range cfg.HoldDefects() {
			fix := "tacctl breakglass release " + d.Device
			if !d.Usable {
				fix += " removes it"
			} else {
				fix = "'" + fix + "' releases it, and the hold can then be made again"
			}
			inv.echoE("  " + R + "Break-glass hold:" + NC + "    breakglass_hold." + d.Key + " (device " + d.Device + ") " + d.Defect + " (" + fix + ")")
			// The schema walk above names a wrong address and a key it
			// does not know; a record without its address it accepts.
			if d.Address == "" {
				errs++
			}
		}
	}

	// Configuration blocks (0.2.7): a name with no file is an error (it
	// renders nothing), a file no list names a warning (it is ignored), and so
	// is a device's orphan; a block in force that has errors is an error (it
	// refuses every Junos device it reaches). Nothing is printed for an
	// installation that has none.
	if inv.blocksExist() {
		bErrs, bWarns := inv.blockValidation()
		for _, l := range bErrs {
			inv.echoE("  " + R + "Config blocks:" + NC + "        " + l)
			errs++
		}
		for _, l := range bWarns {
			inv.echoE("  " + Y + "Config blocks:" + NC + "        " + l)
		}
		if len(bErrs)+len(bWarns) == 0 {
			inv.echoE("  " + G + "Config blocks:" + NC + "        valid")
		}
	}

	// Stored settings that still give the operator or the viewer what
	// 0.2.5 removed (a clear, a capture, a flood form of ping): a warning
	// naming each with the command that takes the shipped value.
	for _, s := range policy.StaleOperatorPolicy(cfg) {
		inv.echoE("  " + Y + "Operator policy:" + NC + "      " + s.String() + " still gives the operator or the viewer a command that can interrupt service; '" + s.Fix() + "' puts back " + s.Restores())
	}

	// Tier, WTI-level and Junos settings of a group the store does not have
	// (a group removed by an import or a restore): the next group of that
	// name would take them over. A warning.
	if merr == nil && storeMode {
		for _, l := range inv.staleGroupLines(m) {
			inv.echoE("  " + Y + "Group settings:" + NC + "       " + l)
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
		inv.echoE("  " + Y + "Group settings:" + NC + "       privileges." + g + " is an empty list in tacctl.yaml: it hides the shipped default (" +
			n + ": " + strings.Join(def, ", ") + "); 'tacctl group privilege reset " + g + "' removes it")
	}

	// What an interrupted command left in the state directory: the private
	// copies of store.yaml and tacctl.yaml that StoreApply, a restore, an
	// enable and a settings change take. A command that is running holds the
	// apply lock and its directory is young; an old one is a leftover (a
	// kill), and it holds secrets. A warning.
	for _, l := range inv.leftoverLines() {
		inv.echoE("  " + Y + "Leftovers:" + NC + "           " + l)
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
			out.ErrorE(err.Error())
			errs++
		}
		enabled = nil
	}
	multi := len(enabled) > 1
	targets := enabled
	if len(targets) == 0 {
		targets = []string{""}
	}
	if multi && len(set.CheckDrift(backend.DriftUnowned)) > 0 {
		inv.write(strings.Join(set.DriftLines(backend.DriftUnowned), ""))
		errs++
	}
	ind := ""
	for _, id := range targets {
		sel := backend.DriftAll
		if multi {
			inv.echoE("  " + B + "Backend " + id + ":" + NC)
			ind = "  "
			sel = backend.DriftOf(id)
		}
		drifted := len(set.CheckDrift(sel)) > 0
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
				inv.echoE(ind + "  " + R + "Rendered config:" + NC + "      the store cannot be rendered (see above)")
				errs++
			case drifted:
			case state == "current" || state == "same":
				inv.echoE(ind + "  " + G + "Rendered config:" + NC + "      up to date")
			case state == "missing":
				inv.echoE(ind + "  " + R + "Rendered config:" + NC + "      " + label + " is missing — run 'tacctl config render'")
				errs++
			case state == "unrecorded":
				inv.echoE(ind + "  " + Y + "Rendered config:" + NC + "      " + label + " was not rendered by tacctl yet — the next change replaces it if it says what the store says; otherwise run 'tacctl config render --force'")
			default:
				inv.echoE(ind + "  " + R + "Rendered config:" + NC + "      " + label + " is out of date with the store — run 'tacctl config render'")
				errs++
			}
		}
		if drifted {
			inv.write(strings.Join(set.DriftLines(sel), ""))
			errs++
		}
		// RADIUS sends a vendor's privilege attribute only where a scope
		// opts in: a warning for the scopes of devices that opt into none
		// (Linux-host scopes, told apart by the host registry, need none).
		if storeMode && id == backend.RADIUS && merr == nil {
			if gaps := m.VendorGaps(cfgHostCounts(a.Paths.LinuxHosts)); len(gaps) > 0 {
				inv.echoE(ind + "  " + Y + "Vendor attributes:" + NC + "    not sent to the devices of scope(s) " + strings.Join(gaps, ", ") +
					" over RADIUS: Cisco, Juniper and WTI devices there get Service-Type only")
				inv.echoE(ind + "                        (Linux hosts need none). Enable what they need: tacctl scope vendor-attrs <scope> enable cisco|juniper|wti")
			}
		}
	}

	inv.echoE("  " + G + "Groups defined:" + NC + "       " + counts["groups"])
	inv.echoE("  " + G + "Scopes defined:" + NC + "       " + counts["scopes"])
	inv.echoE("  " + G + "Users defined:" + NC + "        " + counts["users"])
	inv.echo("")
	if errs > 0 {
		out.Error("Validation failed with " + strconv.Itoa(errs) + " error(s).")
		return exit(1)
	}
	out.Info("Configuration is valid.")
	inv.echo("")
	return nil
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
