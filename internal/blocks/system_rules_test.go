package blocks

import (
	"strings"
	"testing"
)

func anyFindingHas(fs []Finding, sev Severity, want string) bool {
	for _, f := range fs {
		if f.Severity == sev && strings.Contains(f.Text, want) {
			return true
		}
	}
	return false
}

func TestSystemRulesParseGood(t *testing.T) {
	text := "set system syslog host 192.0.2.50 any warning\n" +
		"set system syslog host 192.0.2.50 authorization info\n" +
		"set system syslog host LogHost.Example.NET change-log any\n" +
		"set system syslog host 192.0.2.50 log-prefix tacctl-lab\n" +
		"set system syslog host 192.0.2.50 explicit-priority\n" +
		"set system syslog time-format millisecond\n" +
		"set system syslog time-format year\n" +
		"set system login retry-options tries-before-disconnect 4\n" +
		"set system login retry-options backoff-threshold 2\n" +
		"set system login retry-options backoff-factor 6\n" +
		"set system login retry-options minimum-time 30\n" +
		"set system login retry-options maximum-time 120\n" +
		"set system login password minimum-length 12\n" +
		"set system login password minimum-changes 3\n" +
		"set system login password change-type character-sets\n" +
		"set system login password format sha512\n" +
		"set system login announcement <<'EOF'\nAuthorized use only.\nEOF\n"
	b, fs := LintSystem(text, LayerScope)
	if HasErrors(fs) {
		t.Fatalf("errors:\n%s", dump(fs))
	}
	if len(b.Rules) != 16 || b.Announcement == nil || b.Announcement.Body != "Authorized use only." {
		t.Fatalf("%d rules, announcement %+v", len(b.Rules), b.Announcement)
	}
	st := SystemStatements(b)
	if st[0] != `set system login announcement "Authorized use only."` {
		t.Errorf("the announcement is the first statement: %q", st[0])
	}
	// the host name is lower case; the order is the table's
	want := []string{
		"set system syslog host 192.0.2.50 any warning",
		"set system syslog host 192.0.2.50 authorization info",
		"set system syslog host loghost.example.net change-log any",
		"set system syslog host 192.0.2.50 log-prefix tacctl-lab",
		"set system syslog host 192.0.2.50 explicit-priority",
		"set system syslog time-format millisecond",
		"set system syslog time-format year",
		"set system login retry-options tries-before-disconnect 4",
	}
	for i, w := range want {
		if st[1+i] != w {
			t.Errorf("statement %d = %q, want %q", i, st[1+i], w)
		}
	}
	// the text is the block: read back, the same block, the same text
	b2, fs2 := LintSystem(b.String(false), LayerScope)
	if HasErrors(fs2) || b2.String(false) != b.String(false) || strings.Join(SystemStatements(b2), "\n") != strings.Join(st, "\n") {
		t.Errorf("round trip:\n%s\n%s", b.String(false), b2.String(false))
	}
	// the summary form marks the announcement's size, as the message's; the
	// read (`block show`) prints it, since a device shows it before the login
	if e := b.String(true); strings.Contains(e, "Authorized") || !strings.Contains(e, "<message: 1 lines, 20 characters") {
		t.Errorf("elided:\n%s", e)
	}
	if s := b.Shown(); !strings.Contains(s, "set system login announcement <<'EOF'\nAuthorized use only.\nEOF\n") {
		t.Errorf("shown:\n%s", s)
	}
}

func TestSystemRulesRefuse(t *testing.T) {
	for _, c := range []struct{ text, want string }{
		{"set system syslog host 192.0.2.50 any\n", "this statement is not one of"},
		{"set system syslog host 192.0.2.50 nonsense warning\n", "is not a syslog facility"},
		{"set system syslog host 192.0.2.50 any loud\n", "is not a syslog level"},
		{"set system syslog host bad_name! any warning\n", "word 5 (bad_name!)"},
		{"set system syslog file messages any warning\n", "this statement is not one of"},
		{"set system syslog console any warning\n", "this statement is not one of"},
		{"set system syslog user * any emergency\n", "this statement is not one of"},
		{"set system syslog time-format bogus\n", "is not one of year, millisecond"},
		{"set system syslog host 192.0.2.50 log-prefix two words\n", "this statement is not one of"},
		{"set system login retry-options tries-before-disconnect 11\n", "is not a number from 1 to 10"},
		{"set system login retry-options lockout-period 0\n", "is not a number from 1 to 43200"},
		{"set system login password minimum-length 5\n", "is not a number from 6 to 20"},
		{"set system login password format des\n", "is not one of md5, sha1, sha256, sha512"},
		{"set system login password maximum-lifetime 90\n", "this statement is not one of"},
		{"set system login retry-options minimum-time 50\nset system login retry-options maximum-time 40\n", "maximum-time (40) is below minimum-time (50)"},
		{"set system syslog host 192.0.2.50 any warning\nset system syslog host 192.0.2.50 any error\n", "is stated twice"},
		{"set system login announcement hello\n", "is a heredoc"},
		{"set system login announcement <<'EOF'\nline\n", "is never closed"},
		{"set system login announcement <<'EOF'\nA\nEOF\nset system login announcement <<'EOF'\nB\nEOF\n", "is stated twice"},
		{"set system login class OPS permissions all\n", "are accepted under login"},
		{"set system login user bob class super-user\n", "are accepted under login"},
	} {
		_, fs := LintSystem(c.text, LayerScope)
		if !anyFindingHas(fs, SevError, c.want) {
			t.Errorf("%q: want an error with %q:\n%s", c.text, c.want, dump(fs))
		}
	}
}

func TestSystemRulesLayersAndDeleteLines(t *testing.T) {
	scope, fs := LintSystem("set system syslog host 192.0.2.50 any warning\nset system syslog host 192.0.2.51 any warning\n"+
		"set system login retry-options tries-before-disconnect 4\nset system login password minimum-length 12\n", LayerScope)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	dev, fs := LintSystem("set system syslog host 192.0.2.50 any error\n"+
		"delete system syslog host 192.0.2.51 any\ndelete system login password minimum-length\n"+
		"set system syslog source-address 192.0.2.9\n", LayerDevice)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	r := ResolveSystem(nil, scope, dev)
	got := strings.Join(SystemStatements(r), "|")
	want := "set system syslog host 192.0.2.50 any error|set system syslog source-address 192.0.2.9|set system login retry-options tries-before-disconnect 4"
	if got != want {
		t.Errorf("resolved:\n%s\nwant\n%s", got, want)
	}
	// the delete lines are kept, in the words they were written
	if !strings.Contains(dev.String(false), "delete system syslog host 192.0.2.51 any\n") ||
		!strings.Contains(dev.String(false), "delete system login password minimum-length\n") {
		t.Errorf("delete lines:\n%s", dev.String(false))
	}
	// a delete line must name the identity, nothing less and nothing more
	for _, bad := range []string{"delete system syslog\n", "delete system syslog host 192.0.2.51\n", "delete system login retry-options\n",
		"delete system login password minimum-length 12\n"} {
		if _, fs := LintSystem(bad, LayerDevice); !HasErrors(fs) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// 'syslog source-address' names an address of the device itself: only the
// device's own block states it.
func TestSystemRulesDeviceOnly(t *testing.T) {
	text := "set system syslog source-address 192.0.2.9\n"
	for _, l := range []Layer{LayerDefault, LayerScope} {
		if _, fs := LintSystem(text, l); !anyFindingHas(fs, SevError, "names an address or an interface of one device") {
			t.Errorf("layer %v:\n%s", l, dump(fs))
		}
	}
	if _, fs := LintSystem(text, LayerDevice); HasErrors(fs) {
		t.Errorf("device:\n%s", dump(fs))
	}
}

func TestSystemRulesLockoutNote(t *testing.T) {
	_, fs := LintSystem("set system login retry-options lockout-period 15\n", LayerScope)
	if HasErrors(fs) || !anyFindingHas(fs, SevNote, "locks an account for 15 minutes") {
		t.Errorf("%s", dump(fs))
	}
}

func TestSystemRulesFacilityOverride(t *testing.T) {
	if _, fs := LintSystem("set system syslog host 192.0.2.50 facility-override local7\n", LayerScope); HasErrors(fs) {
		t.Errorf("local7 refused:\n%s", dump(fs))
	}
	if _, fs := LintSystem("set system syslog host 192.0.2.50 facility-override local8\n", LayerScope); !anyFindingHas(fs, SevError, "is not a facility an override takes") {
		t.Errorf("local8 accepted:\n%s", dump(fs))
	}
}

// adopt reads the device's syslog hosts, retry options and password policy,
// leaves its files and users out, and leaves the device's source address out of
// a scope's draft.
func TestAdoptSystemTakesTheTableStatements(t *testing.T) {
	raw := `set system host-name sw1
set system syslog host 192.0.2.50 any warning
set system syslog host 192.0.2.50 explicit-priority
set system syslog file messages any notice
set system syslog user * any emergency
set system syslog source-address 192.0.2.9
set system login retry-options tries-before-disconnect 4
set system login password minimum-length 12
set system login announcement "Authorized use only."
set system login class OPS permissions all
`
	res := AdoptSystem(raw, nil, nil, LayerDevice)
	for _, want := range []string{"set system syslog host 192.0.2.50 any warning\n", "set system syslog host 192.0.2.50 explicit-priority\n",
		"set system syslog source-address 192.0.2.9\n", "set system login retry-options tries-before-disconnect 4\n",
		"set system login password minimum-length 12\n", "set system login announcement <<'EOF'\nAuthorized use only.\nEOF\n"} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("the draft lacks %q:\n%s", want, res.Text)
		}
	}
	if strings.Contains(res.Text, "syslog file") || strings.Contains(res.Text, "syslog user") || strings.Contains(res.Text, "class OPS") {
		t.Errorf("the draft holds what a block does not take:\n%s", res.Text)
	}
	if _, fs := LintSystem(res.Text, LayerDevice); HasErrors(fs) {
		t.Errorf("the draft does not lint:\n%s", dump(fs))
	}
	// a scope's draft leaves the device's own source address out
	sc := AdoptSystem(raw, nil, nil, LayerScope)
	if strings.Contains(sc.Text, "source-address") || !strings.Contains(strings.Join(sc.Left, "\n"), "syslog source-address") {
		t.Errorf("scope draft:\n%s\n%v", sc.Text, sc.Left)
	}
	if _, fs := LintSystem(sc.Text, LayerScope); HasErrors(fs) {
		t.Errorf("the scope draft does not lint:\n%s", dump(fs))
	}
	// a statement the block already states is not repeated, one it states
	// differently is a conflict left as it is
	same, _ := LintSystem("set system syslog host 192.0.2.50 any warning\nset system login password minimum-length 8\n", LayerScope)
	again := AdoptSystem(raw, same, nil, LayerDevice)
	if strings.Contains(again.Text, "192.0.2.50 any warning") || strings.Contains(again.Text, "minimum-length") {
		t.Errorf("repeated or conflicting statements are in the draft:\n%s", again.Text)
	}
}
