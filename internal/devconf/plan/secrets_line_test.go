package plan

// 0.2.20: the secrets line of the report is information, not a complaint.
// Secrets are compared by presence only, so once they were pushed the line is
// the same for good: it says which kinds are present (never a value, a name
// or a label), that only their presence is checked and that --secrets writes
// them again. It is no irregularity and no item. Secrets the pull's login
// could not read are a limit of the login, and the line says the plan could
// not check them.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// A device with four secrets of three kinds (the TACACS+ server key,
// the SNMP community with its two statements, an NTP key), everything
// pasted: the plan is consistent, the line names the kinds and is no item.
func TestSecretsLineIsNeutralWhenNothingIsToPaste(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-system")
	// the fixture lacks the description and holds a stray server
	d := planJ(t, f, func(c *JunosConfig) {
		c.Add(`set snmp description "Core switch"`)
		for _, s := range slices.Clone(c.stmts) {
			if strings.HasPrefix(s.text(), "set system tacplus-server 192.0.2.99") {
				c.Remove(s.text())
			}
		}
	}, Options{})
	if !d.Empty() || len(d.Items) != 0 || statusOf(d) != StatusConsistent {
		t.Fatalf("not consistent: %s %+v\n%s", statusOf(d), d.Items, d.Display())
	}
	if d.Counts.SecretsPresent != 4 {
		t.Fatalf("secrets present: %d", d.Counts.SecretsPresent)
	}
	out := Report(d, f.header(), Wrapper{ConfirmMinutes: 5})
	text := flat(out)
	for _, want := range []string{"CONSISTENT: nothing to paste.",
		"Secrets: 4 present (the TACACS+ server key, the SNMP community, an NTP key); only their presence is checked, --secrets writes them again."} {
		if !strings.Contains(text, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"not changed", "What is irregular", "not visible", "<secret", "EXAMPLE", "lab-secret", "lab-ro-community"} {
		if strings.Contains(out, bad) {
			t.Errorf("the report holds %q:\n%s", bad, out)
		}
	}
	// the line is one line of the report, not a finding: the cover page and the
	// left counts know nothing of it
	if st := StatusFor(d, f.header()); st.State != StatusConsistent || st.Left != 0 || st.Fixes != 0 {
		t.Errorf("cover: %+v", st)
	}
	// --json: the same facts, counts and kinds, no item
	raw, err := JSON(d, f.header(), Wrapper{ConfirmMinutes: 5})
	if err != nil {
		t.Fatal(err)
	}
	var j struct {
		Status         string
		Irregularities []jsonItem
		Secrets        *jsonSecrets
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatal(err)
	}
	if j.Status != StatusConsistent || len(j.Irregularities) != 0 || j.Secrets == nil || j.Secrets.Present != 4 || j.Secrets.NotVisible != 0 ||
		strings.Join(j.Secrets.Kinds, "|") != "the TACACS+ server key|the SNMP community|an NTP key" {
		t.Errorf("json: %+v %+v", j, j.Secrets)
	}
	if strings.Contains(string(raw), "EXAMPLE") || strings.Contains(string(raw), "lab-secret") {
		t.Errorf("the json holds a value:\n%s", raw)
	}
}

// Every vendor names kinds, and a kind it does not know is "another
// secret", never the statement.
func TestSecretKindsNeverNameAValue(t *testing.T) {
	for _, c := range []struct{ vendor, stem, want string }{
		{devconf.FamilyJunos, "set system tacplus-server 192.0.2.10 secret", "the TACACS+ server key"},
		{devconf.FamilyJunos, "set system radius-server 192.0.2.10 secret", "the RADIUS server key"},
		{devconf.FamilyJunos, "set snmp community <secret:1> authorization read-only", "the SNMP community"},
		{devconf.FamilyJunos, "set system ntp authentication-key 1 value", "an NTP key"},
		{devconf.FamilyJunos, "set system login user alice authentication encrypted-password", "a local account's password"},
		{devconf.FamilyJunos, "set system something-else", "another secret"},
		{devconf.FamilyIOS, "tacacs server TACACS" + pathSep + "key <secret>", "the TACACS+ server key"},
		{devconf.FamilyIOS, "radius server RADIUS" + pathSep + "key <secret>", "the RADIUS server key"},
		{devconf.FamilyIOS, "snmp-server community <secret:1> RO TACCTL-SNMP", "the SNMP community"},
		{devconf.FamilyIOS, "snmp-server host 192.0.2.61 version 2c <secret:3>", "the SNMP community"},
		{devconf.FamilyIOS, "ntp authentication-key 1", "an NTP key"},
		{devconf.FamilyIOS, "enable secret", "the enable secret"},
		{devconf.FamilyWTI, "tacacs secret <secret>", "the TACACS+ server key"},
		{devconf.FamilyWTI, "radius primary-secret <secret>", "the RADIUS server key"},
		{devconf.FamilyWTI, "snmp ro-community <secret:1>", "the SNMP community"},
	} {
		if got := secretWhat(c.vendor, c.stem); got != c.want {
			t.Errorf("%s %q: %q, want %q", c.vendor, c.stem, got, c.want)
		}
	}
}

// What the pull's login could not read is a limit of the login: the line
// says the plan could not check those, apart from the present ones, and the
// outputs carry the same counts.
func TestSecretsTheLoginCouldNotReadAreSaidApart(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	exp := expectedSections(t, f.expected)
	c := ParseJunos(capture(t, f.raw))
	// the login does not see the server's secret: it is omitted from the pull
	for _, s := range c.stmts {
		if strings.HasPrefix(s.text(), "set system tacplus-server 192.0.2.10 secret") {
			c.Remove(s.text())
			break
		}
	}
	cur, err := devconf.Extract(f.vendor, c.Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	cur.SecretsVisible = false
	d, err := Plan(f.vendor, exp, cur, cur, f.options())
	if err != nil {
		t.Fatal(err)
	}
	if d.Counts.SecretsNotVisible != 1 || d.Counts.SecretsPresent == 0 {
		t.Fatalf("counts: %+v", d.Counts)
	}
	text := flat(Report(d, f.header(), Wrapper{ConfirmMinutes: 5}))
	if !strings.Contains(text, "only their presence is checked, --secrets writes them again. 1 not visible to the pull's login: the plan could not check them (--secrets pushes them).") {
		t.Errorf("the line:\n%s", text)
	}
	raw, err := JSON(d, f.header(), Wrapper{ConfirmMinutes: 5})
	if err != nil {
		t.Fatal(err)
	}
	var j struct{ Secrets *jsonSecrets }
	if err := json.Unmarshal(raw, &j); err != nil || j.Secrets == nil || j.Secrets.NotVisible != 1 || j.Secrets.Present != d.Counts.SecretsPresent {
		t.Errorf("json: %v %+v", err, j.Secrets)
	}
	// no secret at all: no line, no object
	if l := secretsLine(Counts{}); l != "" {
		t.Errorf("a line for no secret: %q", l)
	}
	if l := secretsLine(Counts{SecretsNotVisible: 2}); l != "Secrets: 2 not visible to the pull's login: the plan could not check them (--secrets pushes them)." {
		t.Errorf("not visible alone: %q", l)
	}
	if l := secretsLine(Counts{SecretsPresent: 7, PresentKinds: []string{"a", "b", "c", "d", "e", "f"}}); !strings.Contains(l, "(a, b, c, d, e, ...)") {
		t.Errorf("many kinds: %q", l)
	}
}
