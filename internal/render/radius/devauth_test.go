package radius_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/render/radius"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The per-group device settings of tacctl.yaml in the users file
// (docs/plans/0.2.2-plan.md §6.2): Junos deny sets as internal control
// attributes, the WTI level instead of the priv-lvl band.

// devauth renders store.devauth.yaml with tacctl.devauth.yaml.
func devauth(t *testing.T) *radius.Output {
	t.Helper()
	out, err := radius.Render(loadModel(t, fixtures+"store.devauth.yaml"),
		loadConf(fixtures+"tacctl.devauth.yaml").Merged(), params("debian"))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

// mergedYAML is the merged view of a tacctl.yaml with the given text, written
// as it is (a hand edit: the schema does not vet it).
func mergedYAML(t *testing.T, text string) *yamlpy.Map {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tacctl.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadConf(path).Merged()
}

// controlOf is the part of user's (first) entry after the hash.
func controlOf(t *testing.T, users, user string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + user + `\t.*Crypt-Password := "[^"]*"(.*)$`).FindStringSubmatch(users)
	if m == nil {
		t.Fatalf("no entry for %s:\n%s", user, users)
	}
	return m[1]
}

func TestGoldenDevauth(t *testing.T) {
	out := devauth(t)
	compareGolden(t, out, "", golden+"radius.devauth.users", golden+"radius.dictionary")
	// The conf does not depend on the settings: the same as without them.
	plain := render(t, loadModel(t, fixtures+"store.devauth.yaml"), "debian")
	if out.Conf != strings.ReplaceAll(plain.Conf, plain.RenderID, out.RenderID) {
		t.Errorf("the conf depends on the device settings:\n%s", firstDiff(out.Conf, plain.Conf))
	}
}

func TestDevauthControlList(t *testing.T) {
	users := devauth(t).Users
	c := loadConf(fixtures + "tacctl.devauth.yaml")
	value := func(path string) string { return `"(` + c.GetList(path)[0] + `)"` }
	for _, e := range []struct{ user, want string }{
		// deny-commands only; the band's WTI level (no override).
		{"bob", `, Tacctl-Priv-Lvl := 7, Tacctl-Juniper-Class := "OP-CLASS", Tacctl-WTI-Super := 1, ` +
			`Tacctl-Juniper-Deny-Commands := ` + value("junos.operator.deny_commands")},
		// Both sets; WTI SuperUser below the Administrator band of 15.
		{"dave", `, Tacctl-Priv-Lvl := 15, Tacctl-Juniper-Class := "ENG-CLASS", Tacctl-WTI-Super := 2, ` +
			`Tacctl-Juniper-Deny-Commands := ` + value("junos.engineer.deny_commands") + `, ` +
			`Tacctl-Juniper-Deny-Configuration := ` + value("junos.engineer.deny_configuration")},
		// Neither: exactly what 0.2.1 rendered.
		{"alice", `, Tacctl-Priv-Lvl := 15, Tacctl-Juniper-Class := "RW-CLASS", Tacctl-WTI-Super := 3`},
	} {
		if got := controlOf(t, users, e.user); got != e.want {
			t.Errorf("%s:\n got  %s\n want %s", e.user, got, e.want)
		}
	}
}

func TestDevauthValueEscapingAndLevelAboveTheBand(t *testing.T) {
	// Two items joined; a quote and a backslash escaped and '%' doubled
	// (the files module expands a double-quoted value with a '%' in it);
	// operator (priv-lvl 7, the User band) raised to Administrator.
	merged := mergedYAML(t, "junos:\n  operator:\n    deny_commands: ['^request system', '^set cli prompt \".*\\d+%\"']\n"+
		"wti_level:\n  operator: administrator\n")
	out, err := radius.Render(radiusModel(t), merged, params("debian"))
	if err != nil {
		t.Fatal(err)
	}
	want := `, Tacctl-Priv-Lvl := 7, Tacctl-Juniper-Class := "OP-CLASS", Tacctl-WTI-Super := 3, ` +
		`Tacctl-Juniper-Deny-Commands := "(^request system)|(^set cli prompt \".*\\d+%%\")"`
	if got := controlOf(t, out.Users, "bob"); got != want {
		t.Errorf("bob:\n got  %s\n want %s", got, want)
	}
}

func TestDevauthGroupWithoutUsersOrSettingsRendersAsBefore(t *testing.T) {
	// The radius fixture with tacctl.devauth.yaml: of its served users only
	// bob (operator) is in a group with a setting (it has no engineer
	// group); every other entry is unchanged.
	m := radiusModel(t)
	plain := render(t, m, "debian")
	out, err := radius.Render(m, loadConf(fixtures+"tacctl.devauth.yaml").Merged(), params("debian"))
	if err != nil {
		t.Fatal(err)
	}
	strip := func(s, rid string) string {
		s = strings.ReplaceAll(s, rid, "<id>")
		return regexp.MustCompile(`, Tacctl-Juniper-Deny-[^"]*"[^"]*"`).ReplaceAllString(s, "")
	}
	if strip(out.Users, out.RenderID) != strip(plain.Users, plain.RenderID) {
		t.Errorf("the users file differs beyond operator's sets:\n%s", firstDiff(strip(out.Users, out.RenderID), strip(plain.Users, plain.RenderID)))
	}
	if n := strings.Count(out.Users, "Tacctl-Juniper-Deny-Commands :="); n != 1 {
		t.Errorf("%d entries with a deny-commands value, want 1 (bob)", n)
	}
}

func TestJunosValueOverTheLimitRefusesTheRender(t *testing.T) {
	m := radiusModel(t)
	// One item of n bytes is a value of n+2 (its parentheses). The limits
	// are TACACS+'s: 241 for deny-commands, 236 for deny-configuration.
	item := func(n int) string { return "^" + strings.Repeat("a", n-3) }
	for _, c := range []struct {
		attr  string
		limit int
	}{{"deny_commands", 241}, {"deny_configuration", 236}} {
		// readonly has no served user: the value is refused all the same.
		for _, group := range []string{"operator", "readonly"} {
			ok := mergedYAML(t, "junos:\n  "+group+":\n    "+c.attr+": ['"+item(c.limit)+"']\n")
			if _, err := radius.Render(m, ok, params("debian")); err != nil {
				t.Errorf("%s %s at the limit: %v", group, c.attr, err)
			}
			over := mergedYAML(t, "junos:\n  "+group+":\n    "+c.attr+": ['"+item(c.limit+1)+"']\n")
			out, err := radius.Render(m, over, params("debian"))
			if err == nil || out != nil {
				t.Fatalf("%s %s over the limit rendered", group, c.attr)
			}
			arg := strings.ReplaceAll(c.attr, "_", "-")
			want := "cannot render: group '" + group + "': " + arg + " is " + strconv.Itoa(c.limit+1) + " bytes; the limit is " + strconv.Itoa(c.limit) +
				" (TACACS+ carries '" + arg + "=<value>' in one argument of at most 255 bytes, and Junos refuses the login when it is longer)." +
				" Shorten a pattern or remove one: tacctl group junos " + group + " " + arg + " list"
			if err.Error() != want {
				t.Errorf("message:\n got  %s\n want %s", err, want)
			}
		}
	}
	// Bytes, not characters: 'é' is two, so '^' and 119 of them make a
	// value of 241 bytes (122 characters), which fits; one byte more does not.
	fits := mergedYAML(t, "junos:\n  operator:\n    deny_commands: ['^"+strings.Repeat("é", 119)+"']\n")
	if _, err := radius.Render(m, fits, params("debian")); err != nil {
		t.Errorf("241 bytes of UTF-8: %v", err)
	}
	over := mergedYAML(t, "junos:\n  operator:\n    deny_commands: ['^a"+strings.Repeat("é", 119)+"']\n")
	if _, err := radius.Render(m, over, params("debian")); err == nil || !strings.Contains(err.Error(), "is 242 bytes") {
		t.Errorf("242 bytes of UTF-8: %v", err)
	}
}

func TestWTILevelOverride(t *testing.T) {
	m := radiusModel(t)
	for level, want := range map[string]string{"viewonly": "0", "user": "1", "superuser": "2", "administrator": "3"} {
		out, err := radius.Render(m, mergedYAML(t, "wti_level:\n  superuser: "+level+"\n"), params("debian"))
		if err != nil {
			t.Fatal(err)
		}
		if got := controlOf(t, out.Users, "alice"); !strings.HasSuffix(got, "Tacctl-WTI-Super := "+want) {
			t.Errorf("superuser at %s: %s", level, got)
		}
		// bob (operator) keeps his band.
		if got := controlOf(t, out.Users, "bob"); !strings.HasSuffix(got, "Tacctl-WTI-Super := 1") {
			t.Errorf("operator: %s", got)
		}
	}
	_, err := radius.Render(m, mergedYAML(t, "wti_level:\n  superuser: root\n"), params("debian"))
	if err == nil || err.Error() != "cannot render: tacctl.yaml: wti_level.superuser is 'root'; it must be one of viewonly, user, superuser, administrator" {
		t.Errorf("an unknown level: %v", err)
	}
}

func TestNotesJunos(t *testing.T) {
	m := loadModel(t, fixtures+"store.devauth.yaml")
	var got []string
	for _, n := range radius.Notes(m, loadConf(fixtures+"tacctl.devauth.yaml").Merged()) {
		if n.Kind == "junos" {
			got = append(got, n.Detail)
		}
	}
	if len(got) != 1 || got[0] != "engineer, operator" {
		t.Errorf("junos note %q", got)
	}
	// None without a set; a group without a served user is not named.
	for _, n := range radius.Notes(m, cfg(t).Merged()) {
		if n.Kind == "junos" {
			t.Errorf("junos note without sets: %s", n.Detail)
		}
	}
	m.User("bob").Disabled = true
	for _, n := range radius.Notes(m, loadConf(fixtures+"tacctl.devauth.yaml").Merged()) {
		if n.Kind == "junos" && n.Detail != "engineer" {
			t.Errorf("junos note %q with operator's only user disabled", n.Detail)
		}
	}
}
