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
// line header), are written here with the values the builders give them;
// the test that every statement is in the walkthrough of the same input
// keeps them honest.

import (
	"errors"
	"regexp"
	"strings"
)

// ErrUnsupported is returned by Managed for a vendor with no managed
// sections (wti today).
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
}

// The sections, in the order Managed returns them.
const (
	sectionAAA        = "aaa"
	sectionRoles      = "roles"
	sectionMgmtACL    = "mgmt-acl"
	sectionSNMP       = "snmp"
	sectionNetconf    = "netconf"
	sectionBreakGlass = "breakglass"
)

// Managed returns the managed sections expected for one device, built from
// the same inputs as its walkthrough, in the order aaa, roles, mgmt-acl,
// snmp, netconf, breakglass. A section tacctl renders no statement for
// (SNMP not configured, no management ACL, the NETCONF step commented out,
// no break-glass user) is left out, so a device is never told it lacks
// what tacctl does not render.
//
// Lines are the statements exactly as the walkthrough prints them, a
// secret's value included (Secret marks them): a caller that shows a
// statement elides the value. Junos statements are 'set' lines; Cisco's
// are configuration lines, a submode's lines indented under the line that
// opens it ('line vty 0 15', then its 'access-class').
//
// The walkthrough's protocol decides the AAA statements (a RADIUS request
// needs Data.Radius, as Render does); wti and any other vendor return
// ErrUnsupported.
func Managed(req Request, d Data) ([]Section, error) {
	if req.Vendor != "cisco" && req.Vendor != "juniper" {
		return nil, ErrUnsupported
	}
	if d.Model == nil || d.Conf == nil {
		return nil, errors.New("devices: Managed needs the model and tacctl.yaml in Data")
	}
	if req.Protocol == RADIUS && d.Radius == nil {
		return nil, errors.New("devices: a RADIUS device needs Data.Radius, as its walkthrough does")
	}
	if req.Vendor == "cisco" {
		return managedCisco(req, d), nil
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
	if len(lines) == 0 {
		return
	}
	sec := Section{Name: name, Lines: lines, Secret: make([]bool, len(lines))}
	for i, l := range lines {
		sec.Secret[i] = s.secret(l)
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
	// 'system login idle-timeout' is in the block, but under no section of
	// D62: its hierarchy is the classes' and users', which are compared by
	// the names tacctl renders.
	s.add(sectionAAA, without(junosStatements(aaa), "set system login idle-timeout "))
	// Step 1: the classes and their template users.
	s.add(sectionRoles, junosStatements(v["TEMPLATE_USERS"]))
	// Step 4: the lo0 filter (SNMP terms included).
	s.add(sectionMgmtACL, junosStatements(v["MGMT_ACL_BLOCK"]))
	// Step 5 and 6.
	s.add(sectionSNMP, junosStatements(v["SNMP_BLOCK"]))
	s.add(sectionNetconf, junosStatements(v["NETCONF_BLOCK"]))
	// Step 7: the account lines are rendered commented, to be completed
	// with a hash; the statement is the line as it is once pasted.
	s.add(sectionBreakGlass, uncommented(juniperBreakGlass(BreakGlassFor(req, d)), "# ", "# set system login user "))
	return s.out
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
// presence: a server's secret, an SNMP community (its name is the secret),
// an SNMPv3 user's authentication and privacy passwords, a local user's
// hash.
var reJuniperSecret = regexp.MustCompile(`^set (` +
	`system (tacplus|radius)-server \S+ secret ` +
	`|snmp community ` +
	`|snmp v3 usm local-engine user \S+ (authentication-\S+ authentication|privacy-\S+ privacy)-password ` +
	`|system login user \S+ class \S+ authentication encrypted-password )`)

func juniperSecret(line string) bool { return reJuniperSecret.MatchString(line) }

// --- Cisco --------------------------------------------------------------------

// managedCisco is Managed for an IOS or IOS-XE device.
func managedCisco(req Request, d Data) []Section {
	v := CiscoVars(req, d)
	s := &sections{secret: ciscoSecret}
	radius := req.Protocol == RADIUS

	// The AAA lines: the server and its group (the shipped templates' own
	// text, with the builders' values), then the method lines and the
	// per-level lines the builders give.
	aaa := []string{"aaa new-model"}
	switch {
	case radius:
		aaa = append(aaa,
			"radius server RADIUS",
			"  address ipv4 "+v["SERVER_IP"]+" auth-port "+v["AUTH_PORT"]+" acct-port "+v["ACCT_PORT"],
			"  key "+v["SECRET"],
			"  timeout 5",
			"  retransmit 2",
			"aaa group server radius "+v["RADIUS_GROUP"],
			"  server name RADIUS")
	case req.Legacy:
		aaa = append(aaa,
			"tacacs-server host "+v["SERVER_IP"]+" single-connection timeout 5 key "+v["SECRET"],
			"aaa group server tacacs+ "+v["TACACS_GROUP"],
			"  server "+v["SERVER_IP"])
	default:
		aaa = append(aaa,
			"tacacs server TACACS",
			"  address ipv4 "+v["SERVER_IP"],
			"  key "+v["SECRET"],
			"  single-connection",
			"  timeout 5",
			"aaa group server tacacs+ "+v["TACACS_GROUP"],
			"  server name TACACS")
	}
	group := v["TACACS_GROUP"]
	if radius {
		group = v["RADIUS_GROUP"]
	}
	aaa = append(aaa,
		"aaa authentication login default "+v["AUTHN_METHODS"],
		"aaa authorization exec default "+v["AUTHZ_EXEC_METHODS"],
		"aaa accounting exec default start-stop group "+group)
	if !radius {
		aaa = append(aaa, ciscoStatements(v["ACCT_COMMANDS_BLOCK"])...)
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

	s.add(sectionSNMP, ciscoStatements(v["SNMP_BLOCK"]))
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

// reCiscoSecret is a Cisco statement that carries a secret, which the
// device stores encrypted or hashed ('key 7', 'key 6', 'secret 9'): the
// key of a server block (or the legacy global line), an SNMP community or
// v3 user, a local user's hash.
var reCiscoSecret = regexp.MustCompile(`^(` +
	`\s+key \S` +
	`|tacacs-server host \S+ .*\bkey \S` +
	`|snmp-server community \S` +
	`|snmp-server user \S` +
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
