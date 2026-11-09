package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/tier"
)

// 'console file-transfer' end to end, on the sandbox of console_test.go
// (alice superuser, bob operator, carol readonly).

// listing is the output of the list form without the line about sshd's sftp
// subsystem (console_filetransfer_subsystem_test.go).
func listing(out string) string {
	head, _, _ := strings.Cut(out, "\nsshd sftp subsystem:")
	return strings.TrimSpace(head)
}

// With no argument the command lists each tier (the superuser tier always on,
// the others off by default), '<tier>' prints one, '<tier> enable|disable'
// sets it, the engineer tier is not closed, and the file holds the tiers
// that have it.
func TestConsoleFileTransferPerTier(t *testing.T) {
	sb := consoleSandbox(t)
	const defaults = "readonly: disabled\noperator: disabled\nengineer: disabled\nsuperuser: enabled (always)"
	if got := listing(sb.con("file-transfer")); got != defaults {
		t.Errorf("defaults:\n%s", got)
	}
	if sb.consoleYAML() != "" {
		t.Error("a listing wrote console.yaml")
	}
	out := sb.con("file-transfer", "operator", "enable")
	if sb.code != 0 || !strings.Contains(out, "File transfer is enabled for the operator tier. It applies from the next console login.") {
		t.Errorf("enable operator: %d %q", sb.code, out)
	}
	if got := strings.TrimSpace(sb.con("file-transfer", "operator")); got != "enabled" {
		t.Errorf("operator: %q", got)
	}
	// unlike the system shell, the engineer tier can have it
	if out = sb.con("file-transfer", "engineer", "enable"); sb.code != 0 || !strings.Contains(out, "enabled for the engineer tier") {
		t.Errorf("enable engineer: %d %q", sb.code, out)
	}
	want := "readonly: disabled\noperator: enabled\nengineer: enabled\nsuperuser: enabled (always)"
	if got := listing(sb.con("file-transfer")); got != want {
		t.Errorf("both:\n%s", got)
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "\n  file_transfer:\n    tiers: [operator, engineer, superuser]\n") {
		t.Errorf("console.yaml:\n%s", y)
	}
	sb.con("file-transfer", "operator", "disable")
	sb.con("file-transfer", "engineer", "disable")
	if y := sb.consoleYAML(); strings.Contains(y, "file_transfer") {
		t.Errorf("the key is left while everything is the default:\n%s", y)
	}
	// The superuser tier cannot be disabled and enabling it changes nothing.
	before := sb.consoleYAML()
	sb.con("file-transfer", "superuser", "disable")
	sb.expect(1, "", "The superuser tier always has file transfer; it cannot be disabled. Nothing was changed.")
	if out = sb.con("file-transfer", "superuser", "enable"); sb.code != 0 || !strings.Contains(out, "The superuser tier always has file transfer. Nothing was changed.") {
		t.Errorf("superuser enable: %d %q", sb.code, out)
	}
	if sb.consoleYAML() != before {
		t.Errorf("a refusal wrote console.yaml:\n%s", sb.consoleYAML())
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"mode"}, "Unknown tier 'mode'"},
		{[]string{"root", "enable"}, "Unknown tier 'root'"},
		{[]string{"operator", "maybe"}, "Usage: tacctl console file-transfer"},
		{[]string{"operator", "enable", "x"}, "Unknown argument: 'x'"},
		{[]string{"quota", "operator", "1G", "x"}, "Unknown argument: 'x'"},
		{[]string{"user"}, "expected at least 1 argument(s), got 0"},
		{[]string{"user", "bob", "enable", "x"}, "Unknown argument: 'x'"},
		{[]string{"user", "bob", "maybe"}, "Usage: tacctl console file-transfer"},
		{[]string{"user", "zed"}, "User 'zed' does not exist."},
		{[]string{"user", "zed", "enable"}, "User 'zed' does not exist."},
	} {
		sb.con(append([]string{"file-transfer"}, c.args...)...)
		if sb.code != 1 || !strings.Contains(plain(sb.err.String()), c.want) {
			t.Errorf("%v: exit %d, stderr %q, want %q", c.args, sb.code, sb.err.String(), c.want)
		}
	}
	if sb.consoleYAML() != before {
		t.Errorf("a refusal wrote console.yaml:\n%s", sb.consoleYAML())
	}
}

// A user's setting beats the tier's in both directions, is listed with the
// user's tier, ends with a move to another tier, and a superuser cannot be
// disabled.
func TestConsoleFileTransferPerUser(t *testing.T) {
	sb := consoleSandbox(t)
	out := sb.con("file-transfer", "user", "carol", "enable")
	if sb.code != 0 || !strings.Contains(out, "File transfer is enabled for 'carol' while they are in the readonly tier (a move to another tier ends it until it is set again). It applies from the next console login.") {
		t.Errorf("enable carol: %d %q", sb.code, out)
	}
	for user, want := range map[string]string{"carol": "enabled (user setting)", "bob": "disabled (tier operator)", "alice": "enabled (always)"} {
		if got := strings.TrimSpace(sb.con("file-transfer", "user", user)); got != want {
			t.Errorf("%s: %q, want %q", user, got, want)
		}
	}
	sb.con("file-transfer", "operator", "enable")
	sb.con("file-transfer", "user", "bob", "disable")
	if got := strings.TrimSpace(sb.con("file-transfer", "user", "bob")); got != "disabled (user setting)" {
		t.Errorf("bob: %q", got)
	}
	list := strings.TrimSpace(sb.con("file-transfer"))
	for _, w := range []string{"readonly: disabled\noperator: enabled\nengineer: disabled\nsuperuser: enabled (always)\n\nUsers with a setting of their own:\n",
		"  bob: disabled (operator)\n", "  carol: enabled (readonly)"} {
		if !strings.Contains(list+"\n", w) {
			t.Errorf("listing lacks %q:\n%s", w, list)
		}
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "\n    users: {bob: disable, carol: 'enable:readonly'}\n") {
		t.Errorf("console.yaml:\n%s", y)
	}
	// console show lists the state next to the system shell's
	show := sb.con("show")
	for _, w := range []string{
		"File transfer (off by default; a user's own setting wins over the tier's):\n  readonly: disabled, quota 256M (default), rate off (default)\n  operator: enabled, quota 256M (default), rate off (default)\n" +
			"  engineer: disabled, quota 256M (default), rate off (default)\n  superuser: enabled (always), quota unlimited (default), rate off (default)\n",
		"SYSTEM SHELL", "FILE TRANSFER", "QUOTA", "RATE",
		"enabled (always)         unlimited  off\n",
		"disabled (user setting)  -          -\n",
		"enabled (user setting)   256M       off\n",
	} {
		if !strings.Contains(show, w) {
			t.Errorf("show lacks %q:\n%s", w, show)
		}
	}
	// clear: the tier decides again
	sb.con("file-transfer", "user", "bob", "clear")
	if out = sb.con("file-transfer", "user", "bob", "clear"); !strings.Contains(out, "'bob' has no file transfer setting of their own.") {
		t.Errorf("clear twice: %q", out)
	}
	sb.con("file-transfer", "user", "carol", "clear")
	sb.con("file-transfer", "operator", "disable")
	if y := sb.consoleYAML(); strings.Contains(y, "file_transfer") {
		t.Errorf("the key is left while everything is the default:\n%s", y)
	}
	// Superusers: disable is refused, enable is already so; neither writes.
	before := sb.consoleYAML()
	sb.con("file-transfer", "user", "alice", "disable")
	sb.expect(1, "", "'alice' is a superuser, and superusers always have file transfer; it cannot be disabled. Nothing was changed.")
	if out = sb.con("file-transfer", "user", "alice", "enable"); sb.code != 0 || !strings.Contains(out, "'alice' is a superuser, who always has file transfer. Nothing was changed.") {
		t.Errorf("alice enable: %d %q", sb.code, out)
	}
	// The engineer tier can be given it, and an engineer user can be switched.
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	if out = sb.con("file-transfer", "user", "bob", "enable"); sb.code != 0 || !strings.Contains(out, "while they are in the engineer tier") {
		t.Errorf("engineer bob: %d %q", sb.code, out)
	}
	if got := strings.TrimSpace(sb.con("file-transfer", "user", "bob")); got != "enabled (user setting)" {
		t.Errorf("engineer bob: %q", got)
	}
	sb.con("file-transfer", "user", "bob", "clear")
	if sb.consoleYAML() != before {
		t.Errorf("console.yaml:\n%s", sb.consoleYAML())
	}
	// A setting of a user who is gone stays, is listed, and clear removes it.
	sb.write("state/console.yaml", "version: 1\nsettings: {file_transfer: {tiers: [superuser], users: {ghost: 'enable:readonly'}}}\n", 0o600)
	if list = strings.TrimSpace(sb.con("file-transfer")); !strings.Contains(list, "  ghost: enabled (no such user)") {
		t.Errorf("listing:\n%s", list)
	}
	if got := strings.TrimSpace(sb.con("file-transfer", "user", "ghost")); got != "enabled (user setting; no such user)" {
		t.Errorf("ghost: %q", got)
	}
	if show = sb.con("show"); !strings.Contains(show, "File transfer settings of users that have no account here: ghost") {
		t.Errorf("show:\n%s", show)
	}
	sb.con("file-transfer", "user", "ghost", "clear")
	if sb.code != 0 || strings.Contains(sb.consoleYAML(), "ghost") {
		t.Errorf("clear ghost: %d\n%s", sb.code, sb.consoleYAML())
	}
}

// The quota and the rate: the built-in values, a tier's, a user's over the
// tier's, the words, and the refusals.
func TestConsoleFileTransferQuotaAndRate(t *testing.T) {
	sb := consoleSandbox(t)
	if got := strings.TrimSpace(sb.con("file-transfer", "quota")); got !=
		"readonly: 256M (default)\noperator: 256M (default)\nengineer: 256M (default)\nsuperuser: unlimited (default)" {
		t.Errorf("quota:\n%s", got)
	}
	if got := strings.TrimSpace(sb.con("file-transfer", "rate")); got !=
		"readonly: off (default)\noperator: off (default)\nengineer: off (default)\nsuperuser: off (default)" {
		t.Errorf("rate:\n%s", got)
	}
	out := sb.con("file-transfer", "quota", "operator", "1024M")
	if sb.code != 0 || !strings.Contains(out, "The quota of the operator tier is 1G. It applies from the next console login.") {
		t.Errorf("quota operator: %d %q", sb.code, out)
	}
	if out = sb.con("file-transfer", "rate", "operator", "512k"); sb.code != 0 || !strings.Contains(out, "The rate limit of the operator tier is 512K a second.") {
		t.Errorf("rate operator: %d %q", sb.code, out)
	}
	if got := strings.TrimSpace(sb.con("file-transfer", "quota", "operator")); got != "1G (set for the operator tier)" {
		t.Errorf("quota operator: %q", got)
	}
	if got := strings.TrimSpace(sb.con("file-transfer", "rate", "readonly")); got != "off (default)" {
		t.Errorf("rate readonly: %q", got)
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "\n    quota: {operator: 1G}\n") || !strings.Contains(y, "\n    rate: {operator: 512K}\n") {
		t.Errorf("console.yaml:\n%s", y)
	}
	sb.con("file-transfer", "operator", "enable")
	// unlimited and default
	if out = sb.con("file-transfer", "quota", "superuser", "2G"); sb.code != 0 {
		t.Errorf("quota superuser: %q", out)
	}
	if out = sb.con("file-transfer", "quota", "operator", "unlimited"); sb.code != 0 || !strings.Contains(out, "The operator tier has no quota.") {
		t.Errorf("quota unlimited: %d %q", sb.code, out)
	}
	if out = sb.con("file-transfer", "quota", "operator", "default"); sb.code != 0 || !strings.Contains(out, "The quota of the operator tier is back to its default (256M).") {
		t.Errorf("quota default: %d %q", sb.code, out)
	}
	if out = sb.con("file-transfer", "quota", "superuser", "default"); sb.code != 0 || !strings.Contains(out, "back to its default (unlimited)") {
		t.Errorf("quota superuser default: %d %q", sb.code, out)
	}
	if out = sb.con("file-transfer", "rate", "operator", "off"); sb.code != 0 || !strings.Contains(out, "The operator tier has no rate limit.") {
		t.Errorf("rate off: %d %q", sb.code, out)
	}
	if y := sb.consoleYAML(); strings.Contains(y, "quota") || strings.Contains(y, "rate") {
		t.Errorf("a default is stored:\n%s", y)
	}

	// per user: over the tier's, both ways; clear; listed
	sb.con("file-transfer", "quota", "operator", "1G")
	if out = sb.con("file-transfer", "quota", "user", "bob", "64M"); sb.code != 0 || !strings.Contains(out, "The quota of 'bob' is 64M.") {
		t.Errorf("quota user: %d %q", sb.code, out)
	}
	sb.con("file-transfer", "quota", "user", "carol", "unlimited")
	sb.con("file-transfer", "rate", "user", "bob", "2M")
	sb.con("file-transfer", "rate", "operator", "10M")
	if out = sb.con("file-transfer", "rate", "user", "carol", "off"); sb.code != 0 || !strings.Contains(out, "'carol' has no rate limit, whatever their tier has.") {
		t.Errorf("rate user off: %d %q", sb.code, out)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"quota", "user", "bob"}, "64M (user setting)"},
		{[]string{"quota", "user", "carol"}, "unlimited (user setting)"},
		{[]string{"quota", "user", "alice"}, "unlimited (default)"},
		{[]string{"rate", "user", "bob"}, "2M (user setting)"},
		{[]string{"rate", "user", "carol"}, "off (user setting)"},
		{[]string{"rate", "user", "alice"}, "off (default)"},
	} {
		if got := strings.TrimSpace(sb.con(append([]string{"file-transfer"}, c.args...)...)); got != c.want {
			t.Errorf("%v: %q, want %q", c.args, got, c.want)
		}
	}
	list := sb.con("file-transfer", "quota")
	if !strings.Contains(list, "Users with a quota of their own:\n  bob: 64M (operator)\n  carol: unlimited (readonly)\n") {
		t.Errorf("quota listing:\n%s", list)
	}
	if list = sb.con("file-transfer", "rate"); !strings.Contains(list, "operator: 10M (set for the operator tier)") ||
		!strings.Contains(list, "Users with a rate limit of their own:\n  bob: 2M (operator)\n  carol: off (readonly)\n") {
		t.Errorf("rate listing:\n%s", list)
	}
	sb.con("file-transfer", "user", "bob", "enable")
	sb.con("file-transfer", "user", "carol", "enable")
	show := sb.con("show")
	for _, w := range []string{"enabled (user setting)  64M ", "enabled (user setting)  unlimited  off"} {
		if !strings.Contains(show, w) {
			t.Errorf("show lacks %q:\n%s", w, show)
		}
	}
	if out = sb.con("file-transfer", "quota", "user", "bob", "clear"); sb.code != 0 || !strings.Contains(out, "The quota of 'bob' is cleared: the tier decides.") {
		t.Errorf("quota clear: %d %q", sb.code, out)
	}
	if out = sb.con("file-transfer", "quota", "user", "bob", "clear"); !strings.Contains(out, "'bob' has no quota of their own.") {
		t.Errorf("quota clear twice: %q", out)
	}
	sb.con("file-transfer", "rate", "user", "bob", "clear")
	if out = sb.con("file-transfer", "rate", "user", "bob", "clear"); !strings.Contains(out, "'bob' has no rate limit of their own.") {
		t.Errorf("rate clear twice: %q", out)
	}
	if got := strings.TrimSpace(sb.con("file-transfer", "quota", "user", "bob")); got != "1G (set for the operator tier)" {
		t.Errorf("bob after clear: %q", got)
	}
	// a setting of a user who is gone
	sb.write("state/console.yaml", "version: 1\nsettings: {file_transfer: {tiers: [superuser], quota_users: {ghost: 1M}, rate_users: {ghost: 'off'}}}\n", 0o600)
	if got := strings.TrimSpace(sb.con("file-transfer", "quota", "user", "ghost")); got != "1M (user setting; no such user)" {
		t.Errorf("ghost: %q", got)
	}
	if show = sb.con("show"); !strings.Contains(show, "File transfer settings of users that have no account here: ghost") {
		t.Errorf("show:\n%s", show)
	}
	sb.con("file-transfer", "quota", "user", "ghost", "clear")
	sb.con("file-transfer", "rate", "user", "ghost", "clear")
	if strings.Contains(sb.consoleYAML(), "ghost") {
		t.Errorf("ghost is left:\n%s", sb.consoleYAML())
	}

	// refusals, none of which writes the file
	before := sb.consoleYAML()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"quota", "operator", "0"}, "is zero"},
		{[]string{"quota", "operator", "-5M"}, "Unknown flag: '-5M'"},
		{[]string{"quota", "operator", "--", "-5M"}, "Invalid size '-5M'"},
		{[]string{"quota", "user", "bob", "--", "-1"}, "Invalid size '-1'"},
		{[]string{"quota", "operator", "1.5G"}, "Invalid size '1.5G'"},
		{[]string{"quota", "operator", "12X"}, "Invalid size '12X'"},
		{[]string{"quota", "operator", "2T"}, "too large"},
		{[]string{"quota", "operator", "99999999999999999999"}, "too large"},
		{[]string{"quota", "operator", "off"}, "Invalid size 'off'"},
		{[]string{"quota", "operator", ""}, "Invalid size ''"},
		{[]string{"quota", "operator"}, ""},
		{[]string{"rate", "operator", "0"}, "is zero"},
		{[]string{"rate", "operator", "unlimited"}, "Invalid size 'unlimited'"},
		{[]string{"rate", "operator", "default"}, "Invalid size 'default'"},
		{[]string{"rate", "operator", "2T"}, "too large"},
		{[]string{"quota", "root", "1G"}, "Unknown tier 'root'"},
		{[]string{"rate", "user", "bob", "fast"}, "Invalid size 'fast'"},
		{[]string{"quota", "user", "bob", "default"}, "Invalid size 'default'"},
		{[]string{"quota", "user", "zed", "1G"}, "User 'zed' does not exist."},
		{[]string{"quota", "user", "zed"}, "User 'zed' does not exist."},
		{[]string{"quota", "user"}, "expected at least 1 argument(s), got 0"},
		{[]string{"quota", "user", "bob", "1G", "x"}, "Unknown argument: 'x'"},
	} {
		sb.con(append([]string{"file-transfer"}, c.args...)...)
		failed := c.want != ""
		if (failed && (sb.code != 1 || !strings.Contains(plain(sb.err.String()), c.want))) || (!failed && sb.code != 0) {
			t.Errorf("%v: exit %d, stderr %q, want %q", c.args, sb.code, sb.err.String(), c.want)
		}
	}
	if sb.consoleYAML() != before {
		t.Errorf("a refusal wrote console.yaml:\n%s", sb.consoleYAML())
	}
}

// Who may read and who may set: the verb reads for the operator tier and up
// and sets for the superuser only. The tier table has no row for the verb in
// this change, so the gate in front of it refuses everyone below the
// superuser tier; the row the later change adds is put in place here for the
// test, to show that the verb itself holds the line.
func TestConsoleFileTransferIsTheSuperusersToSet(t *testing.T) {
	serial(t)
	sb := consoleSandbox(t)
	saved := tier.Rules
	t.Cleanup(func() { tier.Rules = saved })
	tier.Rules = append(append([]tier.Rule{}, saved...), tier.Rule{Tier: tier.Operator, Cmd: "console", Sub: "file-transfer"})
	as := func(user, group string, args ...string) {
		sb.cfgRun("", append([]string{"console", "file-transfer"}, args...), func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
		}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user))
	}
	writes := [][]string{
		{"operator", "enable"}, {"readonly", "disable"}, {"engineer", "enable"}, {"superuser", "disable"},
		{"user", "carol", "enable"}, {"user", "carol", "clear"},
		{"quota", "operator", "1G"}, {"quota", "operator", "default"}, {"quota", "user", "carol", "1G"}, {"quota", "user", "carol", "clear"},
		{"rate", "operator", "1M"}, {"rate", "operator", "off"}, {"rate", "user", "carol", "1M"}, {"rate", "user", "carol", "clear"},
	}
	reads := []struct {
		args []string
		want string
	}{
		{nil, "superuser: enabled (always)"}, {[]string{"readonly"}, "disabled"}, {[]string{"superuser"}, "enabled (always)"},
		{[]string{"user", "carol"}, "disabled (tier readonly)"},
		{[]string{"quota"}, "superuser: unlimited (default)"}, {[]string{"quota", "operator"}, "256M (default)"}, {[]string{"quota", "user", "carol"}, "256M (default)"},
		{[]string{"rate"}, "superuser: off (default)"}, {[]string{"rate", "operator"}, "off (default)"}, {[]string{"rate", "user", "carol"}, "off (default)"},
	}
	for _, who := range []struct{ user, group, tier string }{{"bob", "operator", "operator"}} {
		for _, r := range reads {
			as(who.user, who.group, r.args...)
			sb.expect(0, r.want, "")
		}
		for _, args := range writes {
			as(who.user, who.group, args...)
			sb.expect(1, "", "'tacctl console file-transfer' is not permitted for the "+who.tier+" tier.")
			if !hasAuditPrefix(sb.runner, "auth.warning", "tier DENY user=bob tier=operator cmd=console file-transfer") {
				t.Errorf("refusal of %v not logged: %q", args, sb.runner.Argvs())
			}
		}
	}
	if sb.consoleYAML() != "" {
		t.Errorf("a refusal wrote console.yaml:\n%s", sb.consoleYAML())
	}
	// below the row the gate refuses the verb altogether
	as("carol", "readonly")
	sb.expect(1, "", "'tacctl console file-transfer' is not permitted for the readonly tier.")
	// the superuser sets every form
	for _, args := range [][]string{{"operator", "enable"}, {"user", "carol", "enable"}, {"user", "carol", "clear"}, {"quota", "operator", "1G"},
		{"quota", "user", "carol", "unlimited"}, {"rate", "operator", "1M"}, {"rate", "user", "carol", "off"}, {"operator", "disable"}} {
		as("alice", "superuser", args...)
		if sb.code != 0 {
			t.Errorf("superuser %v: %d %q", args, sb.code, sb.stderr())
		}
	}
}

// Without the row in the tier table (this change), the verb is the
// superuser's alone; the gate says so.
func TestConsoleFileTransferGateWithoutARow(t *testing.T) {
	sb := consoleSandbox(t)
	sb.cfgRun("", []string{"console", "file-transfer"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-operator\n")})
	}, "SUDO_USER=bob", "SUDO_UID="+uidOf("bob"))
	sb.expect(1, "", "'tacctl console file-transfer' is not permitted for the operator tier.")
}

// 'user remove' drops the file transfer settings of the user, 'user rename'
// moves them to the new name; both say so and are logged as 'console set'.
func TestFileTransferSettingsFollowTheUser(t *testing.T) {
	sb := consoleSandbox(t)
	sb.con("file-transfer", "user", "carol", "enable")
	sb.con("file-transfer", "quota", "user", "carol", "1G")
	sb.con("file-transfer", "rate", "user", "carol", "1M")
	sb.con("file-transfer", "user", "bob", "disable")
	out := plain(sb.cfgRun("", []string{"user", "rename", "carol", "erin"}, nil, "SUDO_USER=alice", "SUDO_UID=1001"))
	if sb.code != 0 || !strings.Contains(out, "The file-transfer setting of 'carol' (enable:readonly, quota 1G, rate 1M) moves to 'erin'.") {
		t.Fatalf("rename: %d %q\n%s", sb.code, sb.stderr(), out)
	}
	y := sb.consoleYAML()
	for _, w := range []string{"users: {bob: disable, erin: 'enable:readonly'}", "quota_users: {erin: 1G}", "rate_users: {erin: 1M}"} {
		if !strings.Contains(y, w) {
			t.Errorf("console.yaml lacks %q:\n%s", w, y)
		}
	}
	if strings.Contains(y, "carol") {
		t.Errorf("carol is left:\n%s", y)
	}
	for _, w := range []string{
		"console set key=file-transfer item=user:carol from=\"enable:readonly, quota 1G, rate 1M\" to=none by=alice",
		"console set key=file-transfer item=user:erin from=none to=\"enable:readonly, quota 1G, rate 1M\" by=alice",
	} {
		if !hasAuditPrefix(sb.runner, "auth.notice", w) {
			t.Errorf("not logged: %s\n%q", w, sb.runner.Argvs())
		}
	}
	out = plain(sb.cfgRun("y\n", []string{"user", "remove", "erin"}, nil, "SUDO_USER=alice", "SUDO_UID=1001"))
	if sb.code != 0 || !strings.Contains(out, "The file-transfer setting of 'erin' (enable:readonly, quota 1G, rate 1M) is dropped.") {
		t.Fatalf("remove: %d %q\n%s", sb.code, sb.stderr(), out)
	}
	if y = sb.consoleYAML(); strings.Contains(y, "erin") || !strings.Contains(y, "bob: disable") {
		t.Errorf("console.yaml after the removal:\n%s", y)
	}
}

// The completion of each position of the forms.
func TestConsoleFileTransferCompletionKinds(t *testing.T) {
	args := consoleSpecs["file-transfer"].Args
	const tiers = "readonly|operator|engineer|superuser|user"
	for _, c := range []struct {
		words []string
		want  string
	}{
		{nil, "readonly|operator|engineer|superuser|user|quota|rate"},
		{[]string{"operator"}, "enable|disable"},
		{[]string{"user"}, "users"},
		{[]string{"quota"}, tiers},
		{[]string{"rate"}, tiers},
		{[]string{"user", "bob"}, "enable|disable|clear"},
		{[]string{"quota", "operator"}, "unlimited|default"},
		{[]string{"quota", "user"}, "users"},
		{[]string{"rate", "operator"}, "off"},
		{[]string{"rate", "user"}, "users"},
		{[]string{"quota", "user", "bob"}, "unlimited|clear"},
		{[]string{"rate", "user", "bob"}, "off|clear"},
		{[]string{"quota", "operator", "1G"}, ""},
		{[]string{"user", "bob", "enable"}, ""},
	} {
		if len(c.words) >= len(args) {
			continue
		}
		if got := resolveKind(args[len(c.words)], c.words); got != c.want {
			t.Errorf("after %v: %q, want %q", c.words, got, c.want)
		}
	}
}
