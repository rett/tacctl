package cli

// WP10.4j: the fixes to the review of the per-scope break-glass users (D55).

import (
	"strings"
	"testing"
)

// B2: the collision is refused from the user side as well. A tacctl user
// named like a break-glass account of a scope the user is (or would be) in
// would get the local account's class on the device.
func TestUserVerbsRefuseABreakGlassName(t *testing.T) {
	sb := newSandbox(t, true)
	// Recorded: 'ghost' in lab, 'bob' in dmz (bob is a user of lab only),
	// 'zed' in dmz.
	for _, a := range [][]string{{"lab", "add", "ghost"}, {"dmz", "add", "bob"}, {"dmz", "add", "zed"}} {
		sb.run("", append([]string{"scope", "breakglass"}, a...))
		sb.expect(0, "recorded", "")
	}
	way := "Remove the break-glass user first (tacctl scope breakglass lab remove ghost) or pick another name."

	// user add: any scope of the new user.
	sb.run("", []string{"user", "add", "ghost", "readonly", "--scopes", "lab", "--hash", testHash})
	sb.expect(1, "", "'ghost' is a break-glass local user of scope 'lab' (admin)")
	sb.expect(1, "", way)
	sb.run("", []string{"user", "add", "GHOST", "readonly", "--scopes", "prod,lab", "--hash", testHash})
	sb.expect(1, "", "break-glass local user of scope 'lab'")
	// The default scope counts as well, and so does a scope that is not the
	// one the account is recorded in: no collision there.
	sb.run("", []string{"user", "add", "ghost", "readonly", "--scopes", "prod", "--hash", testHash})
	sb.expect(0, "User 'ghost' added", "")
	if o := sb.read("state/store.yaml"); !strings.Contains(o, "ghost:") {
		t.Errorf("store.yaml lacks the user that has no collision:\n%s", o)
	}

	// user scope add|replace: the scopes the user would be in.
	for _, verb := range []string{"add", "replace"} {
		sb.run("", []string{"user", "scope", "bob", verb, "dmz"})
		sb.expect(1, "", "'bob' is a break-glass local user of scope 'dmz' (admin)")
		sb.expect(1, "", "tacctl scope breakglass dmz remove bob")
	}
	sb.run("", []string{"user", "scope", "bob", "add", "prod"})
	sb.expect(0, "Granted 1 scope(s)", "")
	// Taking a scope away is never refused.
	sb.run("", []string{"user", "scope", "bob", "remove", "prod"})
	sb.expect(0, "Revoked 1 scope(s)", "")

	// user rename: the scopes of the renamed user.
	sb.run("", []string{"user", "rename", "alice", "ghost2"})
	sb.expect(0, "User renamed: alice -> ghost2", "")
	sb.run("", []string{"scope", "breakglass", "lab", "add", "newname"})
	sb.run("", []string{"user", "rename", "bob", "newname"})
	sb.expect(1, "", "'newname' is a break-glass local user of scope 'lab' (admin)")
	sb.run("", []string{"user", "rename", "bob", "Newname"})
	sb.expect(1, "", "break-glass local user of scope 'lab'")
	// carol is in lab and dmz: 'zed' is recorded for dmz.
	sb.run("", []string{"user", "rename", "carol", "zed"})
	sb.expect(1, "", "'zed' is a break-glass local user of scope 'dmz'")
	// Nothing changed.
	if o := sb.read("state/store.yaml"); strings.Contains(o, "  newname:") || strings.Contains(o, "  zed:") {
		t.Errorf("store.yaml after the refusals:\n%s", o)
	}
}

// Names compare without regard to case: a duplicate, and 'remove'.
func TestBreakGlassNamesCompareWithoutCase(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "Lab-Admin"})
	sb.expect(0, "'Lab-Admin' (admin) recorded", "")
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.expect(1, "", "already has break-glass user 'Lab-Admin'")
	sb.run("", []string{"scope", "breakglass", "lab", "remove", "LAB-ADMIN"})
	sb.expect(0, "removed from scope 'lab'", "")
	if o := sb.overrides(); o != "" {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
}

// The hand-edited list is held to the same rule.
func TestBreakGlassValidateRefusesCaseDuplicates(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "breakglass_scope:\n  lab:\n    users: [lab-admin:admin, Lab-Admin:readonly]\n", 0o600)
	sb.run("", []string{"config", "validate"})
	sb.expect(1, "breakglass_scope.lab.users: element 1: 'Lab-Admin' is listed twice", "")
}

// The note the add verb prints does not claim tacctl can see the credential.
func TestBreakGlassAddDoesNotClaimToSeeTheCredential(t *testing.T) {
	sb := newSandbox(t, true)
	out := plain(sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"}))
	if strings.Contains(out, "until you") || !strings.Contains(out, "cannot tell whether you have put in a credential") {
		t.Errorf("\n%s", out)
	}
}
