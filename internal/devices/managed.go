package devices

// The managed sections of a device (D62, D63): the statements tacctl would
// render for one device, per section, that a pull compares with what the
// device runs. Managed is pure, reads only Request and Data, and shares its
// builders with the renderers without changing them: the statements are
// the live lines of the blocks JuniperVars and CiscoVars build for the
// walkthrough (comments, prose and the 'delete' commands dropped), so what
// the walkthrough tells a device and what a pull expects of it cannot
// drift. No template is read: the operator's copies of a template change
// the walkthrough around the blocks, not what tacctl manages.
//
// The few statements that only the shipped templates carry, never a
// builder (Cisco's 'aaa new-model', the server and group blocks, the VTY
// and console line headers with their 'login authentication default'),
// are written here with the values the builders give them;
// the test that every statement is in the walkthrough of the same input
// keeps them honest.

import (
	"errors"
	"regexp"
	"strings"
)

// ErrUnsupported is returned by Managed for a vendor with no managed
// sections (any but cisco, juniper and wti).
var ErrUnsupported = errors.New("no managed sections for this vendor")

// Section is one managed section of a device (D62): its name, and the
// statements tacctl expects in it, one per line, in the order rendered.
type Section struct {
	// Name is the section's name (aaa, roles, mgmt-acl, snmp, netconf,
	// breakglass).
	Name string
	// Lines are the expected statements.
	Lines []string
	// Secret marks, per line, a statement the device stores encrypted or
	// hashed; it is compared by presence only (D64). Secret[i] belongs to
	// Lines[i].
	Secret []bool
	// Block marks, per line, a statement that comes from a configuration
	// block of the scope (0.2.7) and not from the structured settings: the
	// planner owns a block's community or trap group as a whole object, the
	// structured community by the leaves it renders. Nil when no line is a
	// block's; else Block[i] belongs to Lines[i]. Every line of the system
	// section is a block's.
	Block []bool
}

// The sections, in the order Managed returns them.
const (
	sectionAAA        = "aaa"
	sectionRoles      = "roles"
	sectionMgmtACL    = "mgmt-acl"
	sectionSNMP       = "snmp"
	sectionSystem     = "system"
	sectionNetconf    = "netconf"
	sectionBreakGlass = "breakglass"
)

// Managed returns the managed sections expected for one device, built from
// the same inputs as its walkthrough, in the order aaa, roles, mgmt-acl,
// snmp, system, netconf, breakglass. A section tacctl renders no statement
// for (SNMP not configured, no management ACL, the NETCONF step commented
// out, no break-glass user, and the system section of a scope with no system
// block) is left out, so a device is never told it lacks what tacctl does not
// render.
//
// Lines are the statements exactly as the walkthrough prints them, a
// secret's value included (Secret marks them): a caller that shows a
// statement elides the value. Junos statements are 'set' lines; Cisco's
// are configuration lines, a submode's lines indented under the line that
// opens it ('line vty 0 15', then its 'access-class').
//
// The walkthrough's protocol decides the AAA statements (a RADIUS request
// needs Data.Radius, as Render does); any other vendor returns
// ErrUnsupported. A WTI unit's statements are the canonical 'key value' lines
// of its menu pages (wti_managed.go), in the sections aaa, mgmt-acl, snmp and
// breakglass.
func Managed(req Request, d Data) ([]Section, error) {
	if req.Vendor != "cisco" && req.Vendor != "juniper" && req.Vendor != "wti" {
		return nil, ErrUnsupported
	}
	if d.Model == nil || d.Conf == nil {
		return nil, errors.New("devices: Managed needs the model and tacctl.yaml in Data")
	}
	if req.Protocol == RADIUS && d.Radius == nil {
		return nil, errors.New("devices: a RADIUS device needs Data.Radius, as its walkthrough does")
	}
	if err := d.blockProblem(req); err != nil {
		return nil, err
	}
	switch req.Vendor {
	case "cisco":
		return managedCisco(req, d), nil
	case "wti":
		return managedWTI(req, d), nil
	}
	return managedJuniper(req, d), nil
}

// sections collects the sections of one device, in order; a section with
// no statement is not kept.
type sections struct {
	out    []Section
	secret func(string) bool
}

func (s *sections) add(name string, lines []string) {
	s.addFrom(name, lines, nil)
}

// addFrom is add for a section some of whose lines come from a block:
// block holds those statements.
func (s *sections) addFrom(name string, lines []string, block map[string]bool) {
	if len(lines) == 0 {
		return
	}
	sec := Section{Name: name, Lines: lines, Secret: make([]bool, len(lines))}
	var from []bool
	for i, l := range lines {
		sec.Secret[i] = s.secret(l)
		if block[l] {
			if from == nil {
				from = make([]bool, len(lines))
			}
			from[i] = true
		}
	}
	sec.Block = from
	s.out = append(s.out, sec)
}

// addTail is add for a section whose last n lines come from a block: the
// marks are by position, because an access list entry of a block can be the
// same text as one of the structured settings'.
func (s *sections) addTail(name string, lines []string, n int) {
	if len(lines) == 0 {
		return
	}
	s.add(name, lines)
	if n <= 0 || n > len(lines) {
		return
	}
	sec := &s.out[len(s.out)-1]
	sec.Block = make([]bool, len(lines))
	for i := len(lines) - n; i < len(lines); i++ {
		sec.Block[i] = true
	}
}

// addSystem is add for the system section of an IOS device: every line is
// the block's, and a line inside the banner is text, never a statement and
// never a secret.
func (s *sections) addSystem(name string, lines []string) {
	if len(lines) == 0 {
		return
	}
	sec := Section{Name: name, Lines: lines, Secret: make([]bool, len(lines)), Block: make([]bool, len(lines))}
	delim := ""
	for i, l := range lines {
		sec.Block[i] = true
		if delim != "" {
			if l == delim {
				delim = ""
			}
			continue
		}
		sec.Secret[i] = s.secret(l)
		if f := strings.Fields(l); len(f) == 3 && f[0] == "banner" && f[1] == "login" {
			delim = f[2]
		}
	}
	s.out = append(s.out, sec)
}

// --- Junos --------------------------------------------------------------------

// managedJuniper is Managed for a Junos device.
func managedJuniper(req Request, d Data) []Section {
	v := JuniperVars(req, d)
	s := &sections{secret: juniperSecret}

	// Step 2: the AAA block of the protocol (authentication-order, the
	// server and its secret, accounting).
	aaa := v["TACPLUS_CONFIG"]
	if req.Protocol == RADIUS {
		aaa = v["RADIUS_CONFIG"]
	}
	// 'system login idle-timeout' (and, for a release before 16.1, the same
	// statement under each class) is in the block, but under no section of
	// D62: its hierarchy is the classes' and users', which are compared by
	// the names tacctl renders.
	s.add(sectionAAA, withoutIdleTimeout(junosStatements(aaa)))
	// Step 1: the classes and their template users.
	s.add(sectionRoles, junosStatements(v["TEMPLATE_USERS"]))
	// Step 4: the lo0 filter (SNMP terms included).
	s.add(sectionMgmtACL, junosStatements(v["MGMT_ACL_BLOCK"]))
	// Step 5 and 6. The scope's snmp block follows the structured settings
	// in the same step: its statements are the live lines of the same
	// block, marked as the block's.
	s.addFrom(sectionSNMP, junosStatements(v["SNMP_STEP"]), d.blockSNMPSet())
	// The scope's system block follows in the same step: a section of its
	// own, present only when a block is in force (so the device's own login
	// message, domain and NTP are no business of a scope without one).
	sys := junosStatements(v["SYSTEM_BLOCK"])
	s.addFrom(sectionSystem, sys, setOf(sys))
	s.add(sectionNetconf, junosStatements(v["NETCONF_BLOCK"]))
	// Step 7: the account lines are rendered commented, to be completed
	// with a hash; the statement is the line as it is once pasted.
	s.add(sectionBreakGlass, uncommented(juniperBreakGlass(BreakGlassFor(req, d)), "# ", "# set system login user "))
	return s.out
}

// setOf is the set of the lines.
func setOf(lines []string) map[string]bool {
	if len(lines) == 0 {
		return nil
	}
	out := make(map[string]bool, len(lines))
	for _, l := range lines {
		out[l] = true
	}
	return out
}

// junosStatements are the 'set' lines of a block: comments, blanks and
// 'delete' commands (which a device's configuration never shows) dropped,
// and a line a block repeats (two groups that share a class give its lines
// twice) kept once, as the device holds it.
func junosStatements(block string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(l, "set ") && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

// reJuniperSecret is a Junos statement that carries a secret, the device
// stores it encrypted (the '$9$' form) or hashed, so it is compared by
// presence: a server's secret, an SNMP community (its name is the secret) and
// a trap group (its name is the community its traps are sent with, 0.2.7:
// only a block has one), an SNMPv3 user's authentication and privacy
// passwords, an NTP authentication key's value (the system block, 0.2.7), a
// local user's hash.
var reJuniperSecret = regexp.MustCompile(`^set (` +
	`system (tacplus|radius)-server \S+ secret ` +
	`|snmp (community|trap-group) ` +
	`|snmp v3 usm local-engine user \S+ (authentication-\S+ authentication|privacy-\S+ privacy)-password ` +
	`|system ntp authentication-key \S+ (type \S+ )?value ` +
	`|system login user \S+ class \S+ authentication encrypted-password )`)

func juniperSecret(line string) bool { return reJuniperSecret.MatchString(line) }

// --- Cisco --------------------------------------------------------------------

// managedCisco is Managed for an IOS or IOS-XE device: the managed part of
// the standard block (plan §13, D116 (A)), in the order the region types it
// (D118). The walkthrough's templates carry the same lines in the same
// order; the test that every statement is in the walkthrough of the same
// input keeps the two honest.
func managedCisco(req Request, d Data) []Section {
	v := CiscoVars(req, d)
	s := &sections{secret: ciscoSecret}
	radius := req.Protocol == RADIUS

	group := v["TACACS_GROUP"]
	if radius {
		group = v["RADIUS_GROUP"]
	}

	// (1) 'aaa new-model' first: on IOS nothing under 'aaa' but it exists
	// until it is set, so a group and its server leaf typed before it are
	// rejected. (2), (3): the server and its group, then (4) the source
	// interface when the scope sets one (an unset value renders nothing:
	// PolicyGaps names it in a plan's report).
	aaa := []string{"aaa new-model"}
	switch {
	case radius:
		aaa = append(aaa,
			"radius server "+ciscoRadiusServer,
			"  address ipv4 "+v["SERVER_IP"]+" auth-port "+v["AUTH_PORT"]+" acct-port "+v["ACCT_PORT"],
			"  key "+v["SECRET"],
			"  timeout 5",
			"  retransmit 2",
			"aaa group server radius "+group,
			"  server name "+ciscoRadiusServer)
	case req.Legacy:
		aaa = append(aaa,
			"tacacs-server host "+v["SERVER_IP"]+" single-connection timeout 5 key "+v["SECRET"],
			"aaa group server tacacs+ "+group,
			"  server "+v["SERVER_IP"])
	default:
		aaa = append(aaa,
			"tacacs server "+ciscoTacacsServer,
			"  address ipv4 "+v["SERVER_IP"],
			"  key "+v["SECRET"],
			"  single-connection",
			"  timeout 5",
			"aaa group server tacacs+ "+group,
			"  server name "+ciscoTacacsServer)
	}
	if ifc := ciscoSourceInterface(d.Conf, req.Scope); ifc != "" {
		aaa = append(aaa, ciscoSourceCommand(req.Protocol)+" "+ifc)
	}
	// (5)-(8): the login lists (the console's own, local only), exec
	// authorization, accounting and the session id. There is no enable list:
	// a list that asks the server lets any user the server knows reach
	// privilege 15 with their own password (the server answers 'enable' with
	// the user's password), so 'enable' stays with the local enable secret.
	aaa = append(aaa,
		"aaa authentication login default "+v["AUTHN_METHODS"],
		"aaa authentication login "+ciscoConsoleList+" local",
		"aaa authorization exec default "+v["AUTHZ_EXEC_METHODS"],
		"aaa accounting exec default start-stop group "+group)
	if !radius {
		aaa = append(aaa, ciscoStatements(v["ACCT_COMMANDS_BLOCK"])...)
	}
	aaa = append(aaa, "aaa session-id common")
	// (10): the lines that use the lists, the console first, then the vty
	// ranges. The console names its own list; the VTY lines the default one
	// (D107). 'no aaa new-model' leaves a line with no login method, and a
	// line that still says 'login local' bypasses the list, so the leaves are
	// part of what AAA is.
	aaa = append(aaa,
		"line con 0",
		"  login authentication "+ciscoConsoleList,
		"line vty 0 15",
		"  login authentication default")
	// (11): command authorization last. RADIUS has none.
	if !radius {
		aaa = append(aaa, ciscoStatements(v["AUTHZ_COMMANDS_BLOCK"])...)
	}
	s.add(sectionAAA, aaa)

	// The privilege lines of the groups below level 15.
	s.add(sectionRoles, ciscoStatements(v["PRIVILEGE_COMMANDS"]))

	// The VTY access list, and its binding to the lines.
	acl := ciscoStatements(v["VTY_ACL_BLOCK"])
	if class := ciscoStatements(v["VTY_ACCESS_CLASS"]); len(class) > 0 {
		acl = append(acl, "line vty 0 15")
		acl = append(acl, class...)
	}
	s.add(sectionMgmtACL, acl)

	// The scope's snmp block follows the structured settings in the same
	// step: its statements are the last lines of the block, marked as the
	// block's.
	snmp := ciscoStatements(v["SNMP_STEP"])
	s.addTail(sectionSNMP, snmp, len(d.Blocks.ciscoSNMPStatements()))
	// The scope's system block follows in the same step: a section of its
	// own, present only when a block is in force (so the device's own banner,
	// domain and NTP are no business of a scope without one). Every line is
	// the block's; a banner's lines are the lines typed, its text no
	// statement and never a secret.
	s.addSystem(sectionSystem, ciscoSystemStatements(v["SYSTEM_BLOCK"]))
	s.add(sectionNetconf, ciscoStatements(v["NETCONF_BLOCK"]))
	s.add(sectionBreakGlass, uncommented(ciscoBreakGlass(BreakGlassFor(req, d)), "! ", "! username "))
	return s.out
}

// ciscoStatements are the configuration lines of a block: blanks and
// comments ('!' lines, which the builders use for every note and for the
// lines left for the operator to uncomment) dropped, a submode's
// indentation kept.
func ciscoStatements(block string) []string {
	var out []string
	for _, l := range strings.Split(block, "\n") {
		if t := strings.TrimLeft(l, " \t"); t != "" && !strings.HasPrefix(t, "!") {
			out = append(out, l)
		}
	}
	return out
}

// ciscoSystemStatements are the lines of the system block of a walkthrough:
// comment lines ('!') and blank lines outside the banner dropped, every line
// of the banner kept as it is (a body line may be blank or begin with '!').
func ciscoSystemStatements(block string) []string {
	var out []string
	delim := ""
	for _, l := range strings.Split(block, "\n") {
		if delim != "" {
			out = append(out, l)
			if l == delim {
				delim = ""
			}
			continue
		}
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "!") {
			continue
		}
		out = append(out, l)
		if f := strings.Fields(t); len(f) == 3 && f[0] == "banner" && f[1] == "login" {
			delim = f[2]
		}
	}
	return out
}

// reCiscoSecret is a Cisco statement that carries a secret, which the
// device stores encrypted or hashed ('key 7', 'key 6', 'secret 9'): the
// key of a server block (or the legacy global line), an SNMP community, a
// trap host (it names the community its notifications are sent with) or v3
// user, an NTP authentication key's string (the system block), a local
// user's hash.
var reCiscoSecret = regexp.MustCompile(`^(` +
	`\s+key \S` +
	`|tacacs-server host \S+ .*\bkey \S` +
	`|snmp-server community \S` +
	`|snmp-server host \S+ ` +
	`|snmp-server user \S` +
	`|ntp authentication-key \S+ \S+ \S` +
	`|username \S+ privilege \d+ secret \d+ \S` +
	`)`)

func ciscoSecret(line string) bool { return reCiscoSecret.MatchString(line) }

// --- shared -------------------------------------------------------------------

// without are the lines that do not begin with any of the prefixes.
func without(lines []string, prefixes ...string) []string {
	var out []string
next:
	for _, l := range lines {
		for _, p := range prefixes {
			if strings.HasPrefix(l, p) {
				continue next
			}
		}
		out = append(out, l)
	}
	return out
}

// uncommented are the lines of block that begin with prefix, without the
// comment leader: the statements a builder renders commented out, to be
// completed and uncommented by hand (the break-glass accounts).
func uncommented(block, leader, prefix string) []string {
	var out []string
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(l, prefix) {
			out = append(out, strings.TrimPrefix(l, leader))
		}
	}
	return out
}

// withoutIdleTimeout is lines without the idle-timeout statements: the global
// one and the per-class form a release before 16.1 gets.
func withoutIdleTimeout(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.HasPrefix(l, "set system login idle-timeout ") ||
			(strings.HasPrefix(l, "set system login class ") && strings.Contains(l, " idle-timeout ")) {
			continue
		}
		out = append(out, l)
	}
	return out
}
