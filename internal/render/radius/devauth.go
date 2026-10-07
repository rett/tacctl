package radius

// The per-group device settings of tacctl.yaml (docs/plans/0.2.2-plan.md
// §4.1, §6.2) as the users file carries them: the Junos deny sets
// (junos.<group>.deny_commands / .deny_configuration) and the WTI level
// (wti_level.<group>). They are read from the merged view the renderer
// takes (conf.View); internal/policy has the same readers, but it imports
// this package (WTISuper), so this one cannot import it.

import (
	"fmt"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// junosControl is, per Junos attribute (conf.JunosAttrs), the internal
// attribute the users entry sets and post-auth copies into the Juniper VSA
// of the same name (vendor 2636: Juniper-Deny-Commands is 3,
// Juniper-Deny-Configuration 5).
var junosControl = map[string]string{
	conf.JunosDenyCommands:      "Tacctl-Juniper-Deny-Commands",
	conf.JunosDenyConfiguration: "Tacctl-Juniper-Deny-Configuration",
}

// junosSet is junos.<group>.<attr> of the merged view (what
// policy.JunosSet reads); nothing when it is unset or not a list.
func junosSet(merged *yamlpy.Map, group, attr string) []string {
	return conf.View(merged).GetList("junos." + group + "." + attr)
}

// junosValues is the group's Junos values in the order of conf.JunosAttrs
// (an attribute without a set is left out), or an *Error for a value
// longer than the attribute's limit (§4.2): a hand edit or an older binary
// can put one in tacctl.yaml, and Junos refuses a login that carries it.
func junosValues(merged *yamlpy.Map, group string) ([][2]string, error) {
	var out [][2]string
	for _, attr := range conf.JunosAttrs {
		items := junosSet(merged, group, attr)
		if len(items) == 0 {
			continue
		}
		value := conf.JunosValue(items)
		if n, limit := len(value), conf.JunosLimit(attr); n > limit {
			arg := conf.JunosArg(attr)
			return nil, errorf("cannot render: group '%s': %s is %d bytes; the limit is %d "+
				"(TACACS+ carries '%s=<value>' in one argument of at most 255 bytes, and Junos refuses the login "+
				"when it is longer). Shorten a pattern or remove one: tacctl group junos %s %s list",
				group, arg, n, limit, arg, group, arg)
		}
		out = append(out, [2]string{attr, value})
	}
	return out, nil
}

// wtiSuperOf is the WTI-Super value of a group: its wti_level when one is
// set, else the band of its priv-lvl (WTISuper). A level that is not one
// of conf.WTILevels is an *Error.
func wtiSuperOf(merged *yamlpy.Map, group string, privLvl int) (int, error) {
	v, ok := conf.View(merged).Value("wti_level." + group)
	if !ok || v == nil {
		value, _ := WTISuper(privLvl)
		return value, nil
	}
	level := py.Str(v)
	for _, b := range wtiSuperBands {
		if strings.ToLower(b.label) == level {
			return b.value, nil
		}
	}
	return 0, errorf("cannot render: tacctl.yaml: wti_level.%s is %s; it must be one of %s",
		group, py.Repr(v), strings.Join(conf.WTILevels, ", "))
}

// frDQx is frDQ for a value the files module expands at run time: a
// double-quoted value with a '%' in it is an xlat in a users file, so
// every '%' is doubled to stay literal.
func frDQx(s string) string { return frDQ(strings.ReplaceAll(s, "%", "%%")) }

// deviceControl is the part of a users entry's control list that comes
// from the group's device settings: Tacctl-WTI-Super (always) and the
// Junos values (when the group has them).
func deviceControl(merged *yamlpy.Map, g *model.Group, privLvl int) (string, error) {
	wti, err := wtiSuperOf(merged, g.Name, privLvl)
	if err != nil {
		return "", err
	}
	junos, err := junosValues(merged, g.Name)
	if err != nil {
		return "", err
	}
	s := fmt.Sprintf(", Tacctl-WTI-Super := %d", wti)
	for _, j := range junos {
		s += fmt.Sprintf(", %s := %s", junosControl[j[0]], frDQx(j[1]))
	}
	return s, nil
}

// checkJunosValues refuses the render for any group of the model whose
// Junos value is over the limit, whether or not RADIUS serves a user of
// it: no backend may receive the value (§4.2), and the refusal must not
// depend on who is enrolled where.
func checkJunosValues(m *model.Model, merged *yamlpy.Map) error {
	for _, name := range m.GroupNames() {
		if _, err := junosValues(merged, name); err != nil {
			return err
		}
	}
	return nil
}
