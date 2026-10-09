package policy

// A scope's own SNMP settings in tacctl.yaml (snmp_scope.<scope>.*, D41 and
// D46 of docs/plans/0.2.3-plan.md), read and written for 'tacctl scope snmp'
// and the device walkthroughs. The community and the v3 passphrases are not
// here (internal/snmpcred keeps them in StateDir/snmp/<scope>.yaml). The
// keys are written only when set: a tacctl.yaml that never had a scope's
// SNMP setting does not change.

import (
	"slices"
	"strconv"

	"github.com/rett/tacctl/internal/conf"
)

// SNMPScope is what snmp_scope.<scope> holds; the zero value of a field is
// "not set in the scope".
type SNMPScope struct {
	Version string
	Port    int
	Timeout int
	Auth    string
	Priv    string
	Contact string
	Clients []string
}

// SNMPSettings reads the settings of scope.
func SNMPSettings(c *conf.Config, scope string) SNMPScope {
	str := func(key string) string {
		v, ok := c.Get(conf.SNMPPath(scope, key), "")
		if !ok {
			return ""
		}
		return v
	}
	num := func(key string) int {
		n, err := strconv.Atoi(str(key))
		if err != nil {
			return 0
		}
		return n
	}
	return SNMPScope{
		Version: str(conf.SNMPKeyVersion), Port: num(conf.SNMPKeyPort), Timeout: num(conf.SNMPKeyTimeout),
		Auth: str(conf.SNMPKeyAuth), Priv: str(conf.SNMPKeyPriv), Contact: str(conf.SNMPKeyContact),
		Clients: SNMPClients(c, scope),
	}
}

// SNMPClients is the scope's allowed SNMP clients as stored, in the order
// given (nothing for none; the server's /32 and the final 0.0.0.0/0 restrict
// are not in it).
func SNMPClients(c *conf.Config, scope string) []string {
	return c.GetList(conf.SNMPPath(scope, conf.SNMPKeyClients))
}

// SNMPContact is the scope's contact ("" when not set).
func SNMPContact(c *conf.Config, scope string) string {
	v, _ := c.Get(conf.SNMPPath(scope, conf.SNMPKeyContact), "")
	return v
}

// SetSNMPClients stores the scope's client list (validated by the schema:
// IPv4, canonical, no 0.0.0.0/0, no repeats, at most cidr.MaxSNMPClients);
// an empty list removes the key.
func SetSNMPClients(c *conf.Config, scope string, list []string) error {
	return c.SetList(conf.SNMPPath(scope, conf.SNMPKeyClients), list)
}

// AddSNMPClients appends the entries not yet in the scope's list and stores
// it; skipped are those that already were. Nothing is written when nothing
// is new.
func AddSNMPClients(c *conf.Config, scope string, entries []string) (added, skipped []string, err error) {
	cur := slices.Clone(SNMPClients(c, scope))
	for _, e := range entries {
		if slices.Contains(cur, e) {
			skipped = append(skipped, e)
			continue
		}
		cur = append(cur, e)
		added = append(added, e)
	}
	if len(added) == 0 {
		return nil, skipped, nil
	}
	return added, skipped, SetSNMPClients(c, scope, cur)
}

// RemoveSNMPClients takes the entries out of the scope's list and stores
// it; missing are those that were not in it. Nothing is written when
// nothing is removed.
func RemoveSNMPClients(c *conf.Config, scope string, entries []string) (removed, missing []string, err error) {
	cur := slices.Clone(SNMPClients(c, scope))
	for _, e := range entries {
		if i := slices.Index(cur, e); i >= 0 {
			cur = slices.Delete(cur, i, i+1)
			removed = append(removed, e)
		} else {
			missing = append(missing, e)
		}
	}
	if len(removed) == 0 {
		return nil, missing, nil
	}
	return removed, missing, SetSNMPClients(c, scope, cur)
}

// SetSNMPContact stores the scope's contact (validated by the schema).
func SetSNMPContact(c *conf.Config, scope, text string) error {
	return c.Set(conf.SNMPPath(scope, conf.SNMPKeyContact), text)
}

// ClearSNMPKey removes one setting of the scope from tacctl.yaml.
func ClearSNMPKey(c *conf.Config, scope, key string) error {
	return c.Unset(conf.SNMPPath(scope, key))
}

// SNMPSet reports whether tacctl.yaml holds any SNMP setting of the scope.
func SNMPSet(c *conf.Config, scope string) bool {
	for _, k := range conf.SNMPKeys {
		if c.HasOverride(conf.SNMPPath(scope, k)) {
			return true
		}
	}
	return false
}

// MoveSNMPScope moves every SNMP setting of old to new, or drops them when
// newName is empty (a scope renamed or removed). Settings a rename cannot
// carry over (a value the schema refuses) are returned as lost.
func MoveSNMPScope(c *conf.Config, old, newName string) (lost []string, err error) {
	for _, k := range conf.SNMPKeys {
		from := conf.SNMPPath(old, k)
		if !c.HasOverride(from) {
			continue
		}
		v, _ := c.Value(from)
		if err := c.Unset(from); err != nil {
			return lost, err
		}
		if newName == "" {
			continue
		}
		if err := c.SetValue(conf.SNMPPath(newName, k), v); err != nil {
			lost = append(lost, from)
		}
	}
	return lost, nil
}
