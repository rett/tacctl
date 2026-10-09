package policy

import (
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

// The preset's values are valid for the schema and tacquito, and fit
// their limits. (The sizes, the corpus and the nesting are in
// baseline_test.go, which decides with the tacquito-exact emulator.)
func TestRolePresetFitsAndValidates(t *testing.T) {
	s := conf.NewSchema(conf.DefaultBackends)
	for _, r := range RolePreset() {
		for attr, items := range r.Junos {
			if got, limit := len(conf.JunosValue(items)), conf.JunosLimit(attr); got > limit {
				t.Errorf("%s %s: %d bytes, over %d", r.Group, attr, got, limit)
			}
			if len(items) == 0 {
				continue
			}
			list := make([]any, len(items))
			for i, it := range items {
				list[i] = it
			}
			if msg := s.Validate("junos."+r.Group+"."+attr, list, true); msg != "" {
				t.Errorf("%s %s: %s", r.Group, attr, msg)
			}
		}
		if r.WTI == "" || s.Validate("wti_level."+r.Group, r.WTI, false) != "" {
			t.Errorf("%s: WTI level %q", r.Group, r.WTI)
		}
		if r.Commands != nil {
			for _, line := range r.Commands {
				f := strings.SplitN(line, "|", 3)
				if len(f) != 3 || (f[1] != "permit" && f[1] != "deny") {
					t.Errorf("rule %q", line)
				}
				if strings.Contains(f[2], ",") {
					t.Errorf("rule %q: a comma would split the match list", line)
				}
				if _, err := regexp.Compile(f[2]); err != nil {
					t.Errorf("rule %q: %v", line, err)
				}
			}
			// The whole list is valid command-rule content.
			c, path := newConf(t, "")
			if err := Write(c, r.Group, r.Commands); err != nil {
				t.Fatal(err)
			}
			if msg := s.ValidateFile(path); len(msg) != 0 {
				t.Errorf("%s: %v", r.Group, msg)
			}
			if !SameLines(Lines(c, r.Group), r.Commands) {
				t.Errorf("%s: the rules do not read back as written", r.Group)
			}
		}
	}
	eng := RolePreset()[2]
	if eng.Group != "engineer" || eng.Tier != "engineer" || eng.Class != EngineerClass || eng.Commands[len(eng.Commands)-1] != Catchall+"|permit|" {
		t.Fatalf("engineer %+v", eng)
	}
}

// 'tacctl upgrade' recognises 0.2.2's engineer preset, and only it.
func TestStale022Preset(t *testing.T) {
	c, _ := newConf(t, "")
	if got := Stale022Preset(c); len(got) != 0 {
		t.Fatalf("a clean install: %v", got)
	}
	if err := Write(c, "engineer", engineerCommands022); err != nil {
		t.Fatal(err)
	}
	if err := WriteJunosSet(c, "engineer", conf.JunosDenyCommands, []string{engineerDenyCommands022}); err != nil {
		t.Fatal(err)
	}
	for _, filter := range []string{"", "firewall .*MGMT-FILTER|"} {
		deny := engineerDenyConfigurationHead022 + filter + engineerDenyConfigurationTail022
		if err := WriteJunosSet(c, "engineer", conf.JunosDenyConfiguration, []string{deny}); err != nil {
			t.Fatal(err)
		}
		want := []string{"commands.engineer", "junos engineer deny-commands", "junos engineer deny-configuration"}
		if got := Stale022Preset(c); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("filter %q: %v, want %v", filter, got, want)
		}
	}
	// The current preset is not stale, and a customised value is left out.
	for _, r := range RolePreset() {
		if r.Group != "engineer" {
			continue
		}
		if err := Write(c, "engineer", r.Commands); err != nil {
			t.Fatal(err)
		}
		if err := WriteJunosSet(c, "engineer", conf.JunosDenyCommands, r.Junos[conf.JunosDenyCommands]); err != nil {
			t.Fatal(err)
		}
		if err := WriteJunosSet(c, "engineer", conf.JunosDenyConfiguration, []string{engineerDenyConfigurationHead022 + "x" + engineerDenyConfigurationTail022}); err != nil {
			t.Fatal(err)
		}
	}
	if got := Stale022Preset(c); len(got) != 0 {
		t.Errorf("the current preset and a customised set: %v", got)
	}
}

// The lint of command rules: invalid and empty matches, prefix forms
// without trailing arguments, and rules that cannot be reached.
func TestLintRules(t *testing.T) {
	for _, c := range []struct {
		lines []string
		want  []string // substrings of the findings, in order
	}{
		{[]string{"show|permit|", "*|deny|"}, nil},
		{[]string{"clear|permit|^(counters|line)( .*)?$", "*|deny|"}, nil},
		{[]string{"terminal|permit|^(length|width)$", "*|deny|"}, nil},
		{[]string{"show|deny|^(a|b).*", "*|permit|"}, nil},
		{[]string{"show|deny|^running-config", "*|permit|"}, []string{"matches only the exact arguments 'running-config'"}},
		{[]string{"show|deny|running-config|crypto", "*|permit|"}, []string{"'running-config|crypto' matches only"}},
		{[]string{"show|deny|^(a|b)", "*|permit|"}, []string{"^(a|b)( .*)?$"}},
		{[]string{"show|deny|^(a", "*|permit|"}, []string{"invalid regex"}},
		{[]string{"show|permit|", "show|deny|^x$", "*|deny|"}, []string{"never reached: rule #1 'show' has no match"}},
		{[]string{"show|permit|^x$", "show|deny|^y$", "*|deny|"}, nil},
		{[]string{"*|deny|", "show|permit|"}, []string{"rule #1 '*' decides every command"}},
	} {
		var got []string
		for _, f := range LintRules(c.lines) {
			got = append(got, f.Msg)
		}
		if len(got) != len(c.want) {
			t.Errorf("%q: %q, want %d finding(s) %q", c.lines, got, len(c.want), c.want)
			continue
		}
		for i := range got {
			if !strings.Contains(got[i], c.want[i]) {
				t.Errorf("%q: finding %d is %q, want it to contain %q", c.lines, i, got[i], c.want[i])
			}
		}
	}
	if e, _ := MatchProblems(""); e == "" {
		t.Error("an empty match is an error")
	}
}
