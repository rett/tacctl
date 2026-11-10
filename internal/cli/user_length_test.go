package cli

// A new user name is at most 32 characters, the longest a Linux account name
// can be. The limit is on the creation paths only ('user add' and the new name
// of 'user rename'): a user that exists with a longer name (a store from an
// earlier release) keeps working, is restored as it is, and has no account.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/names"
)

// longWant is the refusal of a new name of n characters.
func longWant(name string) string {
	return fmt.Sprintf("Username '%s' is %d characters; a user name is at most 32 (the longest a Linux account name can be).", name, len(name))
}

// The limit of a new user name is the longest a Linux account name can be:
// the two are written apart (internal/hosts, internal/lifecycle), so this
// keeps them equal.
func TestUserNameLimitIsTheLongestLinuxAccountName(t *testing.T) {
	if !hosts.LinuxName(strings.Repeat("a", names.UsernameMax)) || hosts.LinuxName(strings.Repeat("a", names.UsernameMax+1)) {
		t.Errorf("names.UsernameMax = %d is not the longest hosts.LinuxName accepts", names.UsernameMax)
	}
}

// 32 characters are accepted, 33 are refused, by 'user add' and by the new
// name of 'user rename', and nothing is changed by a refusal.
func TestNewUserNamesAreAtMost32Characters(t *testing.T) {
	sb := newSandbox(t, true)
	ok, long := strings.Repeat("a", 32), strings.Repeat("a", 33)

	before := sb.store()
	sb.run("", []string{"user", "add", long, "operator", "--hash", testHash, "--scopes", "lab"})
	sb.expect(1, "", longWant(long))
	sb.run("", []string{"user", "rename", "bob", long})
	sb.expect(1, "", longWant(long))
	if sb.store() != before {
		t.Error("a refusal changed the store")
	}

	sb.run("", []string{"user", "add", ok, "operator", "--hash", testHash, "--scopes", "lab"})
	sb.expect(0, "User '"+ok+"' added", "")
	renamed := strings.Repeat("b", 32)
	sb.run("", []string{"user", "rename", "bob", renamed})
	sb.expect(0, "User renamed: bob -> "+renamed, "")
	// The limit is on the new name, whatever the old one is.
	sb.run("", []string{"user", "rename", renamed, long})
	sb.expect(1, "", longWant(long))
}

// A user from before, with a name over the limit, is shown, changed, renamed
// away to a short name and removed as ever; the limit is not part of the check
// every verb runs.
func TestUserWithAnOverLongNameKeepsWorking(t *testing.T) {
	long := strings.Repeat("a", 40)
	h, err := hash.Generate("CorrectHorse99", 4)
	if err != nil {
		t.Fatal(err)
	}
	sb := newSandbox(t, true)
	sb.legacyStoreCase("  alice:", "  "+long+":")

	sb.run("", []string{"user", "show", long})
	sb.expect(0, long, "")
	sb.run("", []string{"user", "list"})
	sb.expect(0, long, "")
	sb.run("", []string{"user", "passwd", long, "--hash", h})
	sb.expect(0, "Password changed for '"+long+"'.", "")
	sb.run("CorrectHorse99\n", []string{"user", "verify", long})
	sb.expect(0, "Password is correct.", "")
	sb.run("", []string{"user", "disable", long})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "enable", long})
	sb.expect(0, "", "")

	// Renamed away to a short name.
	sb.run("", []string{"user", "rename", long, "alice"})
	sb.expect(0, "User renamed: "+long+" -> alice", "")
	if strings.Contains(sb.store(), long) {
		t.Errorf("the store after the rename:\n%s", sb.store())
	}

	// Removed.
	sb2 := newSandbox(t, true)
	sb2.legacyStoreCase("  alice:", "  "+long+":")
	sb2.run("y\n", []string{"user", "remove", long})
	sb2.expect(0, "", "")
	if strings.Contains(sb2.store(), long) {
		t.Errorf("the store after the removal:\n%s", sb2.store())
	}
}

// The restore of a snapshot with such a user puts the store back as it was
// written: the user is neither refused nor dropped.
func TestBackupRestoreKeepsAnOverLongUser(t *testing.T) {
	long := strings.Repeat("a", 40)
	sb := renderedSandbox(t)
	snap := strings.ReplaceAll(fixture(t, "store.multiscope.yaml"), "  alice:", "  "+long+":")
	sb.mkSnapshot("20200101_000000_001", snap, "")
	sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"})
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	if sb.read("state/store.yaml") != snap {
		t.Errorf("the store is not the snapshot's:\n%s", sb.read("state/store.yaml"))
	}
	sb.run("", []string{"user", "show", long})
	sb.expect(0, long, "")
}

// A user whose name has upper case and is over the limit gets one finding, the
// rename that fixes the length (the lower-case spelling would be over the
// limit too, and 'user rename' refuses it), and it says the name also has
// upper case. 'config validate --fix-names' offers nothing for it and ends as
// for a store with no fixable names.
func TestOverLongNameWithUpperCaseIsOneFinding(t *testing.T) {
	long := "A" + strings.Repeat("a", 39)
	sb := newSandbox(t, true)
	sb.legacyStoreCase("  alice:", "  "+long+":")
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")

	sb.run("", []string{"config", "validate"})
	out := plain(sb.out.String())
	if n := strings.Count(out, "'"+long+"'"); n != 1 {
		t.Errorf("%d findings name the user, want 1:\n%s", n, out)
	}
	if strings.Contains(out, "has upper case in its name") || strings.Contains(out, "rename "+long+" "+strings.ToLower(long)) {
		t.Errorf("the lower-case rename is proposed:\n%s", out)
	}
	want := "the user '" + long + "' has a name of 40 characters and has upper case letters; new user names are at most 32 and lower case, and this user has no Linux account, here or on a host (tacctl user rename " + long + " <new-name>)"
	if !strings.Contains(out, want) {
		t.Errorf("config validate lacks %q:\n%s", want, out)
	}

	v := validateJSONOf(t, sb.run("", []string{"config", "validate", "--json"}))
	var names []validateFinding
	for _, f := range v.Findings {
		if f.Section == "names" {
			names = append(names, f)
		}
	}
	if len(names) != 1 || names[0].Fix != "tacctl user rename "+long+" <new-name>" || names[0].Kind != "" {
		t.Errorf("the json names findings: %+v", names)
	}

	before := sb.store()
	snaps := len(sb.snapshotDirs())
	sb.run("", []string{"config", "validate", "--fix-names", "--yes"})
	sb.expect(0, "Names: renamed 0, declined 0, not offered 0, failed 0.", "")
	if sb.store() != before || len(sb.snapshotDirs()) != snaps {
		t.Error("--fix-names changed something")
	}
	if strings.Contains(sb.printed(), "Rename user") {
		t.Errorf("a rename was offered:\n%s", sb.printed())
	}
}
