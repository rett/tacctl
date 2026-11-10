package cli

// A new user name starts with a lower case letter (names.CheckNewUsername):
// every new user gets a Linux account, here and on the enrolled hosts. The rule
// is on the creation paths only ('user add' and the new name of 'user
// rename'): a user that exists as '9dave', '_svc' or '-x' (a store from an
// earlier release) keeps working, is restored as it is, and is warned of by
// 'config validate' when it has no Linux account.

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hash"
)

// letterWant is the refusal of a new name that does not start with a letter.
func letterWant(name string) string {
	return "Username '" + name + "' must start with a letter (a to z): every new user gets a Linux account, and a name that starts with a digit or '-' is no account name (a new name does not start with '_' either)."
}

// A digit, '-' and '_' are refused as the first character by 'user add' and
// by the new name of 'user rename', and nothing is changed; the order of the
// checks puts upper case first: 'Alice' and '1Alice' get the lower-case
// spelling, and the letter rule follows on the retry.
func TestNewUserNamesStartWithALetter(t *testing.T) {
	sb := newSandbox(t, true)
	before := sb.store()
	for _, bad := range []string{"1alice", "9dave", "_svc", "_", "0", "1-a", "-x"} {
		sb.run("", []string{"user", "add", bad, "operator", "--hash", testHash, "--scopes", "lab"})
		sb.expect(1, "", letterWant(bad))
		sb.run("", []string{"user", "rename", "bob", bad})
		sb.expect(1, "", letterWant(bad))
	}
	if sb.store() != before {
		t.Error("a refusal changed the store")
	}

	// upper case first, then the letter rule on the retry
	sb.run("", []string{"user", "add", "1Alice", "operator", "--hash", testHash, "--scopes", "lab"})
	sb.expect(1, "", "Names are lower case: use '1alice'. Nothing was changed.")
	sb.run("", []string{"user", "add", "Alice", "operator", "--hash", testHash, "--scopes", "lab"})
	sb.expect(1, "", "Names are lower case: use 'alice'. Nothing was changed.")
	sb.run("", []string{"user", "rename", "bob", "_Svc"})
	sb.expect(1, "", "Names are lower case: use '_svc'. Nothing was changed.")
	// the length comes before the first character
	long := "1" + strings.Repeat("a", 40)
	sb.run("", []string{"user", "add", long, "operator", "--hash", testHash, "--scopes", "lab"})
	sb.expect(1, "", longWant(long))
	if sb.store() != before {
		t.Error("a refusal changed the store")
	}

	for _, ok := range []string{"a", "alice2", "a_b-c", "z9"} {
		sb.run("", []string{"user", "add", ok, "operator", "--hash", testHash, "--scopes", "lab"})
		sb.expect(0, "User '"+ok+"' added", "")
	}
	sb.run("", []string{"user", "rename", "bob", "robert-2"})
	sb.expect(0, "User renamed: bob -> robert-2", "")
}

// A user that exists with a name a new user could not have is shown, changed,
// renamed away to a good name and removed as ever, and a snapshot with such
// users is restored as it was: the first-character rule is not part of the
// check every verb runs.
func TestUsersWithAnyFirstCharacterKeepWorking(t *testing.T) {
	h, err := hash.Generate("CorrectHorse99", 4)
	if err != nil {
		t.Fatal(err)
	}
	sb := newSandbox(t, true)
	sb.legacyStoreCase("  alice:", "  9dave:")
	sb.legacyStoreCase("  bob:", "  _svc:")
	for _, name := range []string{"9dave", "_svc"} {
		sb.run("", []string{"user", "show", name})
		sb.expect(0, name, "")
		sb.run("", []string{"user", "passwd", name, "--hash", h})
		sb.expect(0, "Password changed for '"+name+"'.", "")
		sb.run("CorrectHorse99\n", []string{"user", "verify", name})
		sb.expect(0, "Password is correct.", "")
		sb.run("", []string{"user", "disable", name})
		sb.expect(0, "", "")
		sb.run("", []string{"user", "enable", name})
		sb.expect(0, "", "")
	}
	sb.run("", []string{"user", "list"})
	sb.expect(0, "9dave", "")

	// renamed away to a name a new user can have; the new name is checked, the old is not
	sb.run("", []string{"user", "rename", "9dave", "dave"})
	sb.expect(0, "User renamed: 9dave -> dave", "")
	sb.run("", []string{"user", "rename", "_svc", "9svc"})
	sb.expect(1, "", letterWant("9svc"))
	sb.run("", []string{"user", "rename", "_svc", "svc"})
	sb.expect(0, "User renamed: _svc -> svc", "")

	sb2 := newSandbox(t, true)
	sb2.legacyStoreCase("  alice:", "  9dave:")
	sb2.run("y\n", []string{"user", "remove", "9dave"})
	sb2.expect(0, "", "")
	if strings.Contains(sb2.store(), "9dave") {
		t.Errorf("the store after the removal:\n%s", sb2.store())
	}

	sb3 := renderedSandbox(t)
	snap := strings.ReplaceAll(strings.ReplaceAll(fixture(t, "store.multiscope.yaml"), "  alice:", "  9dave:"), "  bob:", "  _svc:")
	sb3.mkSnapshot("20200101_000000_001", snap, "")
	sb3.run("y\n", []string{"backup", "restore", "20200101_000000_001"})
	sb3.expect(0, "Restored snapshot 20200101_000000_001.", "")
	if sb3.read("state/store.yaml") != snap {
		t.Errorf("the store is not the snapshot's:\n%s", sb3.read("state/store.yaml"))
	}
	sb3.run("", []string{"user", "show", "9dave"})
	sb3.expect(0, "9dave", "")
}

// namesFindingsOf are the lines of the report of 'config validate' that are
// findings of the names section, and the findings of its json.
func namesFindingsOf(t *testing.T, sb *sandbox) (text string, found []validateFinding) {
	t.Helper()
	sb.run("", []string{"config", "validate"})
	text = plain(sb.out.String())
	v := validateJSONOf(t, sb.run("", []string{"config", "validate", "--json"}))
	for _, f := range v.Findings {
		if f.Section == "names" {
			found = append(found, f)
		}
	}
	return text, found
}

// A user that exists with a name that starts with a digit gets one warning, that
// it has no Linux account and the rename that fixes it; '_svc' has an account
// and gets none; nothing is fixed automatically.
func TestConfigValidateWarnsOfAUserWithNoLinuxAccountName(t *testing.T) {
	sb := newSandbox(t, true)
	sb.legacyStoreCase("  alice:", "  1alice:")
	sb.legacyStoreCase("  bob:", "  _svc:")
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	out, found := namesFindingsOf(t, sb)
	want := "the user '1alice' has a name that starts with a digit; new user names start with a letter (a to z), and this user has no Linux account, here or on a host (tacctl user rename 1alice <new-name>)"
	if !strings.Contains(out, want) {
		t.Errorf("config validate lacks %q:\n%s", want, out)
	}
	if strings.Contains(out, "_svc") {
		t.Errorf("a name that starts with '_' is warned of:\n%s", out)
	}
	if len(found) != 1 || found[0].Fix != "tacctl user rename 1alice <new-name>" || found[0].Kind != "" || found[0].Level != levelWarning {
		t.Errorf("the json names findings: %+v", found)
	}
	before := sb.store()
	sb.run("", []string{"config", "validate", "--fix-names", "--yes"})
	sb.expect(0, "Names: renamed 0, declined 0, not offered 0, failed 0.", "")
	if sb.store() != before || strings.Contains(sb.printed(), "Rename user") {
		t.Errorf("--fix-names changed something:\n%s", sb.printed())
	}
}

// A name that starts with '-' is warned of the same way, saying so.
func TestConfigValidateWarnsOfAUserStartingWithAHyphen(t *testing.T) {
	sb := newSandbox(t, true)
	sb.legacyStoreCase("  alice:", "  -x:")
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	out, found := namesFindingsOf(t, sb)
	want := "the user '-x' has a name that starts with '-'; new user names start with a letter (a to z), and this user has no Linux account, here or on a host (tacctl user rename -x <new-name>)"
	if !strings.Contains(out, want) || len(found) != 1 {
		t.Errorf("config validate lacks %q (%d json findings):\n%s", want, len(found), out)
	}
}

// '1Alice' has upper case and starts with a digit: its lower-case spelling
// would be refused by 'user rename', so --fix-names does not offer it and the
// one finding names the rename, with both faults; 'Alice' followed by 41
// characters has the same. Neither is counted as failed or not offered, and
// the run ends with status 0. A plain 'Alice' next to them is still offered
// its lower-case spelling.
func TestUpperCaseNamesThatCannotBeLowerCasedAreOneFindingEach(t *testing.T) {
	long := "Alice" + strings.Repeat("a", 41)
	for _, c := range []struct{ name, want string }{
		{"1Alice", "the user '1Alice' has a name that starts with a digit and has upper case letters; new user names are lower case and start with a letter (a to z), and this user has no Linux account, here or on a host (tacctl user rename 1Alice <new-name>)"},
		{long, "the user '" + long + "' has a name of 46 characters and has upper case letters; new user names are at most 32 and lower case, and this user has no Linux account, here or on a host (tacctl user rename " + long + " <new-name>)"},
		{"1Alice" + strings.Repeat("a", 41), "the user '1Alice" + strings.Repeat("a", 41) + "' has a name of 47 characters and starts with a digit and has upper case letters; new user names are at most 32 and lower case and start with a letter (a to z), and this user has no Linux account, here or on a host (tacctl user rename 1Alice" + strings.Repeat("a", 41) + " <new-name>)"},
	} {
		sb := newSandbox(t, true)
		sb.legacyStoreCase("  alice:", "  "+c.name+":")
		sb.legacyStoreCase("  bob:", "  Bobby:")
		sb.run("", []string{"config", "render"})
		sb.expect(0, "", "")

		out, found := namesFindingsOf(t, sb)
		if n := strings.Count(out, "'"+c.name+"'"); n != 1 {
			t.Errorf("%s: %d findings name the user, want 1:\n%s", c.name, n, out)
		}
		if strings.Contains(out, "rename "+c.name+" "+strings.ToLower(c.name)) {
			t.Errorf("%s: the lower-case rename is proposed:\n%s", c.name, out)
		}
		if !strings.Contains(out, c.want) {
			t.Errorf("config validate lacks %q:\n%s", c.want, out)
		}
		// the plain upper case user keeps its finding, with the fix --fix-names runs
		if !strings.Contains(out, "the user 'Bobby' has upper case in its name") {
			t.Errorf("Bobby lost its finding:\n%s", out)
		}
		var ofName, ofBobby int
		for _, f := range found {
			switch {
			case strings.Contains(f.Text, "'"+c.name+"'"):
				ofName++
				if f.Fix != "tacctl user rename "+c.name+" <new-name>" || f.Kind != "" {
					t.Errorf("%s: the json finding: %+v", c.name, f)
				}
			case strings.Contains(f.Text, "'Bobby'"):
				ofBobby++
				if f.Fix != "tacctl user rename Bobby bobby" {
					t.Errorf("Bobby's json finding: %+v", f)
				}
			}
		}
		if ofName != 1 || ofBobby != 1 {
			t.Errorf("%s: json findings %d and %d: %+v", c.name, ofName, ofBobby, found)
		}

		sb.run("", []string{"config", "validate", "--fix-names", "--yes"})
		sb.expect(0, "Names: renamed 1, declined 0, not offered 0, failed 0.", "")
		store := sb.store()
		if !strings.Contains(store, "  "+c.name+":") || !strings.Contains(store, "  bobby:") {
			t.Errorf("%s: the store after --fix-names:\n%s", c.name, store)
		}
		if strings.Contains(sb.printed(), "Rename user '"+c.name+"'") {
			t.Errorf("%s: a rename was offered:\n%s", c.name, sb.printed())
		}
		// and the same run only with the user: nothing to offer, status 0
		sb.run("", []string{"config", "validate", "--fix-names", "--yes"})
		sb.expect(0, "Names: renamed 0, declined 0, not offered 0, failed 0.", "")
	}
}

// A user with upper case whose name starts with '_' has no account (a Linux
// account name is lower case), and the rename to its lower-case spelling, which
// would be one, is refused because a new name starts with a letter: it gets one
// finding that says so and names the rename with a name of the person's choice, and
// --fix-names offers nothing.
func TestUpperCaseNameStartingWithAnUnderscoreIsNotOfferedTheLowerCaseSpelling(t *testing.T) {
	sb := newSandbox(t, true)
	sb.legacyStoreCase("  alice:", "  _Svc:")
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	out, found := namesFindingsOf(t, sb)
	want := "the user '_Svc' has upper case letters; new user names are lower case, but its lower-case spelling '_svc' is not a name 'user rename' takes: " + strings.TrimSuffix(letterWant("_svc"), ".") + " (tacctl user rename _Svc <new-name>)"
	if !strings.Contains(out, want) || strings.Count(out, "'_Svc'") != 1 {
		t.Errorf("config validate lacks %q:\n%s", want, out)
	}
	if len(found) != 1 || found[0].Kind != "" || found[0].Fix != "tacctl user rename _Svc <new-name>" {
		t.Errorf("the json names findings: %+v", found)
	}
	before := sb.store()
	sb.run("", []string{"config", "validate", "--fix-names", "--yes"})
	sb.expect(0, "Names: renamed 0, declined 0, not offered 0, failed 0.", "")
	if sb.store() != before {
		t.Error("--fix-names changed the store")
	}
}
