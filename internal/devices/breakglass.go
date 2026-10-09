package devices

// The break-glass local users of a scope in the walkthroughs (decision D55
// of docs/plans/0.2.3-plan.md): the local accounts that let someone in when
// the server cannot be reached. tacctl records the names and roles
// ('tacctl scope breakglass'); it never holds a credential, so every account
// line is rendered with a placeholder where the credential goes, commented
// out (a paste must not create an account with a literal placeholder as its
// password), and every account is named in the output's 'Unfilled' line:
// tacctl cannot tell whether the operator has put in a credential of their
// own, so the line stays for as long as the account is recorded.
//
// Each vendor's builder reads BreakGlassInput and nothing else: no model,
// configuration file, terminal, clock or global state, so the push
// provisioning of a later release can render the same lines for one device.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// breakGlassVar is the template variable of the break-glass step.
const breakGlassVar = "BREAKGLASS_BLOCK"

// withBreakGlassVar is a template's variable whitelist and the break-glass
// block, so the whitelists of the vendors stay as they were.
func withBreakGlassVar(allowed []string) []string {
	return append(slices.Clone(allowed), breakGlassVar)
}

// The placeholders where the credential goes in an account line. Cisco's
// 'secret 9' and 'secret 5' take the hash itself ('algorithm-type scrypt
// secret' would take a plaintext password and hash it, so a pasted hash
// would become the password); Junos takes a crypt hash; WTI is typed on the
// unit, so it is a password.
const (
	breakGlassHash      = "<HASH>"
	breakGlassType9Hash = "<TYPE9-HASH>"
	breakGlassPassword  = "<PASSWORD>"
)

// breakGlassGroup is the built-in group whose device-side level a role
// takes: an admin is a superuser, and the other roles are the groups of
// the same name.
var breakGlassGroup = map[string]string{
	conf.BreakGlassAdmin:    "superuser",
	conf.BreakGlassOperator: "operator",
	conf.BreakGlassReadonly: "readonly",
}

// BreakGlassInput is what the break-glass builders render: the scope's
// users and, per role, the level an account of that role gets on each
// vendor.
type BreakGlassInput struct {
	Scope string
	Users []policy.BreakGlassUser
	// Legacy is a Cisco IOS 12.x config, which has no type 9 (scrypt).
	Legacy bool
	// LocalFirst is the scope's aaa-order local-first: the device tries
	// the local accounts before the server.
	LocalFirst bool
	// Privilege is the Cisco privilege level of a role, Class its Junos
	// login class, Level its WTI access level (the group's 'wti-level'
	// override when it has one, as the mapping table of the same output).
	Privilege map[string]int
	Class     map[string]string
	Level     map[string]string
}

// BreakGlassFor is the input for the scope of req: its users from
// tacctl.yaml and the levels of the built-in groups the roles map to (the
// model's value where the group has one, else the built-in's: the single
// source is store.BuiltinGroups).
func BreakGlassFor(req Request, d Data) BreakGlassInput {
	in := BreakGlassInput{
		Scope:      req.Scope,
		Legacy:     req.Vendor == "cisco" && req.Legacy && req.Protocol != RADIUS,
		LocalFirst: localFirst(d.Conf, req.Scope),
		Privilege:  map[string]int{},
		Class:      map[string]string{},
		Level:      map[string]string{},
	}
	if d.Conf != nil {
		in.Users = policy.BreakGlassUsers(d.Conf, req.Scope)
	}
	groups := groupInfo(d.Model)
	wti := wtiGroups(d)
	for role, name := range breakGlassGroup {
		var b store.BuiltinGroup
		for _, g := range store.BuiltinGroups {
			if g.Name == name {
				b = g
			}
		}
		priv, class := b.PrivLvl, b.JuniperClass
		for _, g := range groups {
			if g.name != name {
				continue
			}
			if n, err := strconv.Atoi(strings.TrimSpace(g.priv)); err == nil {
				priv = n
			}
			if g.class != "" {
				class = g.class
			}
		}
		in.Privilege[role], in.Class[role] = priv, class
		_, in.Level[role] = wtiLevel(strconv.Itoa(priv))
		for _, w := range wti {
			if w.name == name {
				in.Level[role] = w.level
			}
		}
	}
	return in
}

// breakGlassNotice is the lines (each starting with prefix) a scope without
// break-glass users gets next to the vendor's existing advice.
func breakGlassNotice(in BreakGlassInput, prefix string) string {
	return prefix + "No break-glass local user is recorded for scope '" + in.Scope + "': with the server\n" +
		prefix + "unreachable and no local account on the device, nobody can log in. Record one with\n" +
		prefix + "  tacctl scope breakglass " + in.Scope + " add <name> [--role admin|operator|readonly]"
}

// ciscoBreakGlass is the ${BREAKGLASS_BLOCK} of the Cisco templates.
func ciscoBreakGlass(in BreakGlassInput) string {
	if len(in.Users) == 0 {
		return breakGlassNotice(in, "! ")
	}
	var b strings.Builder
	b.WriteString("! --- Break-glass local users (scope: " + in.Scope + ") ---\n")
	if in.LocalFirst {
		b.WriteString("! The scope's aaa-order is local-first: the 'local' method of 'aaa authentication login'\n")
		b.WriteString("! above tries these accounts before the server.\n")
	} else {
		b.WriteString("! The 'local' method of 'aaa authentication login' above admits these only when no\n")
		b.WriteString("! server answers.\n")
	}
	if in.Legacy {
		b.WriteString("! tacctl stores no credential: replace " + breakGlassHash + " with the type 5 hash ($1$...) of a password you keep,\n")
		b.WriteString("! then remove the '! '. (IOS 12.x has no type 9.)\n")
	} else {
		b.WriteString("! tacctl stores no credential: replace " + breakGlassType9Hash + " with the type 9 hash ($9$...) of a password\n")
		b.WriteString("! you keep (the hash, not the password: 'secret 9' takes a hash as it appears in 'show running-config'),\n")
		b.WriteString("! then remove the '! '.\n")
	}
	for _, u := range in.Users {
		secret, hash := "secret 9 ", breakGlassType9Hash
		if in.Legacy {
			secret, hash = "secret 5 ", breakGlassHash
		}
		b.WriteString("! username " + u.Name + " privilege " + strconv.Itoa(in.Privilege[u.Role]) + " " + secret + hash + "\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// juniperBreakGlass is the ${BREAKGLASS_BLOCK} of the Juniper templates.
func juniperBreakGlass(in BreakGlassInput) string {
	if len(in.Users) == 0 {
		return breakGlassNotice(in, "# ")
	}
	var b strings.Builder
	b.WriteString("# Break-glass local users (scope: " + in.Scope + "):\n")
	if in.LocalFirst {
		b.WriteString("# the scope's aaa-order is local-first, so the authentication-order above tries these accounts\n")
		b.WriteString("# before the server.\n")
	} else {
		b.WriteString("# the authentication-order above names the server only, so Junos falls back to these local\n")
		b.WriteString("# accounts only when no server answers.\n")
	}
	b.WriteString("# tacctl stores no credential: replace " + breakGlassHash + " with your own crypt hash ($6$...),\n")
	b.WriteString("# remove the '# ' before the commit of Step 8.\n")
	for _, u := range in.Users {
		b.WriteString("# set system login user " + u.Name + " class " + in.Class[u.Role] +
			" authentication encrypted-password '" + breakGlassHash + "'\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// wtiBreakGlass is the ${BREAKGLASS_BLOCK} of the WTI templates: menu
// steps, indented as the template's steps are.
func wtiBreakGlass(in BreakGlassInput) string {
	const ind = "        "
	if len(in.Users) == 0 {
		return breakGlassNotice(in, ind)
	}
	var b strings.Builder
	b.WriteString(ind + "Local accounts let someone in when the server is unreachable (Fallback Local, Step 3).\n")
	b.WriteString(ind + "tacctl stores no password: on the serial session of Step 1 add each account to the unit's\n")
	b.WriteString(ind + "user directory (/H lists its command) with the access level shown, and set a password you keep:\n")
	for _, u := range in.Users {
		b.WriteString(ind + "  " + u.Name + "  Access Level: " + in.Level[u.Role] + "  Password: " + breakGlassPassword + "\n")
	}
	b.WriteString(ind + "Save as in Step 7.\n")
	return strings.TrimSuffix(b.String(), "\n")
}

// breakGlassUnfilled is the 'Unfilled' output line: every recorded account,
// since tacctl cannot see whether a credential was put in on the device;
// "" for a scope without any.
func breakGlassUnfilled(in BreakGlassInput) string {
	if len(in.Users) == 0 {
		return ""
	}
	parts := make([]string, len(in.Users))
	for i, u := range in.Users {
		parts[i] = u.Name + " (" + u.Role + ")"
	}
	return "Unfilled break-glass credentials (tacctl stores none; put in your own): " + strings.Join(parts, ", ")
}

// unfilledBreakGlass writes the 'Unfilled' line of a config (nothing for a
// scope without break-glass users), above the closing blank line.
func (o *out) unfilledBreakGlass(in BreakGlassInput) {
	if line := breakGlassUnfilled(in); line != "" {
		o.heading(ui.Yellow, line)
		o.echo("")
	}
}

// junosPredefinedClasses are the login classes Junos ships; a local user
// named like one would be confusing next to the template users.
var junosPredefinedClasses = []string{"super-user", "operator", "read-only", "unauthorized"}

// JunosSystemAccounts are the Junos login accounts that exist without being
// configured as users: root, and 'remote', the template account every
// TACACS+/RADIUS user without a local-user-name is mapped to. A local
// break-glass account named 'remote' (admin: the superuser class) would put
// every unmapped remote user into that class.
var JunosSystemAccounts = []string{"root", "remote"}

// TemplateUserNames are the names the Juniper walkthrough's Step 1 gives
// its template users and local classes (the Juniper class of every group,
// the built-ins' included) and Junos's predefined classes: a break-glass
// user may not take one.
func TemplateUserNames(m *model.Model) []string {
	var out []string
	for _, b := range store.BuiltinGroups {
		out = append(out, b.JuniperClass)
	}
	for _, g := range groupInfo(m) {
		if g.class != "" && !slices.Contains(out, g.class) {
			out = append(out, g.class)
		}
	}
	return append(out, junosPredefinedClasses...)
}
