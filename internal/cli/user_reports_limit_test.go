package cli

import (
	"os"
	"strings"
	"testing"
)

// limitOf is the value the store holds for a user's key ("" when none).
func limitOf(t *testing.T, sb *sandbox, user, key string) string {
	t.Helper()
	data, err := os.ReadFile(sb.path("state", "store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(data), "\n  "+user+":\n")
	if !ok {
		t.Fatalf("no user %s in\n%s", user, data)
	}
	for _, l := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(l, "    ") {
			break
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), key+": "); ok {
			return v
		}
	}
	return ""
}

// 'user reports-limit' shows, sets and clears the two limits; the values are
// stored in bytes and as a count, shown by 'user show', and a user without one
// shows the server's setting.
func TestUserReportsLimitShowSetClear(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.asAlice("", "user", "reports-limit", "bob")
	for _, want := range []string{"Report limits of bob", "max-size:  10 MiB   (the server's setting)", "max-count: 100 reports   (the server's setting)"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	sb.asAlice("", "user", "reports-limit", "bob", "max-size", "20Mi")
	sb.expect(0, "The max-size of 'bob' set to 20 MiB.", "")
	sb.asAlice("", "user", "reports-limit", "bob", "max-count", "0")
	sb.expect(0, "The max-count of 'bob' set to no cap.", "")
	if got := limitOf(t, sb, "bob", "reports_max_size"); got != "20971520" {
		t.Errorf("stored size %q", got)
	}
	if got := limitOf(t, sb, "bob", "reports_max_count"); got != "0" {
		t.Errorf("stored count %q: 0 is a limit", got)
	}
	out = sb.asAlice("", "user", "reports-limit", "bob")
	for _, want := range []string{"max-size:  20 MiB   (own limit; the server's setting is 10 MiB)", "max-count: no cap   (own limit; the server's setting is 100 reports)"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if out := sb.asAlice("", "user", "reports-limit", "bob", "max-size"); strings.Contains(out, "max-count") || !strings.Contains(out, "max-size:  20 MiB") {
		t.Errorf("max-size alone:\n%s", out)
	}
	if out := sb.asAlice("", "user", "reports-limit", "bob", "max-count"); strings.Contains(out, "max-size") || !strings.Contains(out, "max-count: no cap") {
		t.Errorf("max-count alone:\n%s", out)
	}
	show := sb.asAlice("", "user", "show", "bob")
	for _, want := range []string{"  Report max-size:  20 MiB (own limit)\n", "  Report max-count: no cap (own limit)\n"} {
		if !strings.Contains(show, want) {
			t.Errorf("user show lacks %q:\n%s", want, show)
		}
	}
	if show := sb.asAlice("", "user", "show", "carol"); strings.Contains(show, "Report max") {
		t.Errorf("user show of a user with none:\n%s", show)
	}
	if list := sb.asAlice("", "user", "list"); strings.Contains(list, "Report") || strings.Contains(list, "20 MiB") {
		t.Errorf("user list shows the limits:\n%s", list)
	}
	if js := sb.asAlice("", "store", "show", "--json"); !strings.Contains(js, `"reports_max_size": 20971520`) || !strings.Contains(js, `"reports_max_count": 0`) {
		t.Errorf("store show --json lacks the limits:\n%s", js)
	}
	// the same value again: nothing to do
	sb.asAlice("", "user", "reports-limit", "bob", "max-size", "20971520")
	sb.expect(0, "has that max-size already", "")
	sb.asAlice("", "user", "reports-limit", "bob", "max-count", "0")
	sb.expect(0, "has that max-count already", "")
	// a rename carries both
	sb.asAlice("", "user", "rename", "bob", "robert")
	sb.expect(0, "", "")
	if limitOf(t, sb, "robert", "reports_max_size") != "20971520" || limitOf(t, sb, "robert", "reports_max_count") != "0" {
		t.Error("the rename lost a limit")
	}
	// clear one, then the other
	sb.asAlice("", "user", "reports-limit", "robert", "max-size", "clear")
	sb.expect(0, "The own max-size of 'robert' cleared; the server's setting applies.", "")
	if limitOf(t, sb, "robert", "reports_max_size") != "" || limitOf(t, sb, "robert", "reports_max_count") != "0" {
		t.Error("clear max-size did not remove just that key")
	}
	sb.asAlice("", "user", "reports-limit", "robert", "max-size", "clear")
	sb.expect(0, "nothing to clear", "")
	sb.asAlice("", "user", "reports-limit", "robert", "max-count", "clear")
	sb.expect(0, "The own max-count of 'robert' cleared", "")
	if b, _ := os.ReadFile(sb.path("state", "store.yaml")); strings.Contains(string(b), "reports_max") {
		t.Errorf("a key stays:\n%s", b)
	}
}

// 'clear' after the name removes both limits in one write; with none it says so.
func TestUserReportsLimitClearBoth(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "user", "reports-limit", "carol", "clear")
	sb.expect(0, "has no own max-size or max-count; nothing to clear", "")
	sb.asAlice("", "user", "reports-limit", "carol", "max-size", "512Ki")
	sb.asAlice("", "user", "reports-limit", "carol", "max-count", "5")
	if got := limitOf(t, sb, "carol", "reports_max_size"); got != "524288" {
		t.Errorf("stored size %q", got)
	}
	snaps := len(sb.snapshotDirs())
	sb.asAlice("", "user", "reports-limit", "carol", "clear")
	sb.expect(0, "The own max-size and max-count of 'carol' cleared; the server's setting applies.", "")
	if b, _ := os.ReadFile(sb.path("state", "store.yaml")); strings.Contains(string(b), "reports_max") {
		t.Errorf("a key stays:\n%s", b)
	}
	if n := len(sb.snapshotDirs()); n != snaps+1 {
		t.Errorf("snapshots %d -> %d: one write expected", snaps, n)
	}
}

// A bad value, an unknown word, extra words, an unknown user and the sink are
// refused with the store as it was.
func TestUserReportsLimitRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "user", "reports-limit", "bob", "max-size", "5Mi")
	sb.expect(0, "", "")
	before, _ := os.ReadFile(sb.path("state", "store.yaml"))
	const usage = "Usage: tacctl user reports-limit <username> [max-size|max-count [<value>|clear] | clear]"
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"user", "reports-limit"}, usage},
		{[]string{"user", "reports-limit", "bob", "max-size", "5Mi", "6Mi"}, usage},
		{[]string{"user", "reports-limit", "bob", "clear", "max-size"}, usage},
		{[]string{"user", "reports-limit", "bob", "max-sizes", "5"}, "Unknown argument: 'max-sizes'"},
		{[]string{"user", "reports-limit", "bob", "max-size", "2Gi"}, "over the largest size limit"},
		{[]string{"user", "reports-limit", "bob", "max-size", "-1"}, "is not a size"},
		{[]string{"user", "reports-limit", "bob", "max-size", "10MB"}, "is not a size"},
		{[]string{"user", "reports-limit", "bob", "max-size", "Mi"}, "is not a size"},
		{[]string{"user", "reports-limit", "bob", "max-count", "100001"}, "over the largest count limit"},
		{[]string{"user", "reports-limit", "bob", "max-count", "5Mi"}, "is not a count"},
		{[]string{"user", "reports-limit", "bob", "max-count", "-2"}, "is not a count"},
		{[]string{"user", "reports-limit", "bob", "max-count", "many"}, "is not a count"},
		{[]string{"user", "reports-limit", "nobody", "max-count", "3"}, "User 'nobody' does not exist."},
		{[]string{"user", "reports-limit", "nobody@example.net", "clear"}, "Username must contain only"},
	} {
		sb.asAlice("", c.args...)
		sb.expect(1, "", c.want)
	}
	if after, _ := os.ReadFile(sb.path("state", "store.yaml")); string(after) != string(before) {
		t.Errorf("a refusal changed the store:\n%s", after)
	}
}

// The accounting sink takes no limit.
func TestUserReportsLimitSinkTakesNone(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/store.yaml", strings.Replace(sb.read("state/store.yaml"), "\nusers:\n",
		"\nusers:\n  root:\n    group: readonly\n    scopes: []\n    hash: null\n    disabled: true\n    accounting_sink: true\n", 1), 0o600)
	sb.asAlice("", "user", "reports-limit", "root", "max-size", "5Mi")
	sb.expect(1, "", "accounting sink")
}

// A limit changes no rendered file: no backend is restarted.
func TestUserReportsLimitRestartsNothing(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	sb.asAlice("", "user", "reports-limit", "bob", "max-size", "5Mi")
	sb.asAlice("", "user", "reports-limit", "bob", "clear")
	sb.expect(0, "", "")
	if n := sb.runner.Count("systemctl", "restart"); n != 0 {
		t.Errorf("a limit restarted a backend %d times", n)
	}
}

// The detail line says who, which limit and the value (a size is no secret);
// an address typed in the place of the name is never logged.
func TestUserReportsLimitAuditLines(t *testing.T) {
	sb := newSandbox(t, true)
	logged := func() string {
		var lines []string
		for _, c := range sb.runner.Calls() {
			if c.Name == "logger" {
				lines = append(lines, strings.Join(c.Args, " "))
			}
		}
		return strings.Join(lines, "\n")
	}
	sb.cfgRun("", []string{"user", "reports-limit", "bob", "max-size", "20Mi"}, nil, "SUDO_USER=alice", "SUDO_UID=1001")
	sb.expect(0, "", "")
	all := logged()
	for _, want := range []string{"user reports-limit", "name=bob", "key=max-size", "op=set", "value=20971520", "by=alice"} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q in the audit lines:\n%s", want, all)
		}
	}
	sb.cfgRun("", []string{"user", "reports-limit", "bob", "clear"}, nil, "SUDO_USER=alice", "SUDO_UID=1001")
	if all := logged(); !strings.Contains(all, "op=clear") || !strings.Contains(all, "key=max-size") {
		t.Errorf("the clear is not logged:\n%s", all)
	}
	sb.cfgRun("", []string{"user", "reports-limit", "bob@example.net", "max-size", "1"}, nil, "SUDO_USER=alice", "SUDO_UID=1001")
	if strings.Contains(logged(), "bob@example.net") {
		t.Errorf("an address typed for the name is logged:\n%s", logged())
	}
}
