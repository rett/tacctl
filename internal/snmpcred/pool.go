package snmpcred

// The unique-names rule of the user pools (D304 of docs/plans/0.2.23-
// plan.md). A device may be told to use a user of its own pool, of its
// scope's or of the default level's, so a name stands for one user wherever
// a device can see it: a scope's user cannot shadow the default level's, a
// device's cannot shadow its scope's. Two scopes, or two devices of
// different scopes, may use the same name for different users; nothing sees
// both. The verbs that add a user ask Peers for the pools the new name has
// to be unique against and refuse with the label of the first that holds it.

// Level kinds of Level.
const (
	LevelDefault = "default"
	LevelScope   = "scope"
	LevelDevice  = "device"
)

// Level is one place a pool lives: the default level (snmp.yaml), a scope
// (snmp/<scope>.yaml) or a device (snmp/devices/<name>.yaml). Name is the
// scope's or the device's.
type Level struct {
	Kind string
	Name string
}

// Label is how the level is called in a refusal: "the config", "scope lab",
// "device sw1".
func (l Level) Label() string {
	switch l.Kind {
	case LevelScope:
		return "scope " + l.Name
	case LevelDevice:
		return "device " + l.Name
	}
	return "the config"
}

// Pool is the users of one level.
type Pool struct {
	Level Level
	Creds Creds
}

// Holder is the first of the pools that holds a user called name.
func Holder(name string, pools []Pool) (Level, bool) {
	for _, p := range pools {
		if _, ok := p.Creds.Find(name); ok {
			return p.Level, true
		}
	}
	return Level{}, false
}

// Store is where the credential files are: snmp.yaml and the directory of the
// scopes' files (the devices' are under it).
type Store struct {
	File string
	Dir  string
	// Mapped says whether a device has an snmp: entry in devices.yaml (nil:
	// not known, taken as none, which keeps a device's file version 2).
	Mapped func(device string) bool
}

// Load reads the pool of one level.
func (s Store) Load(l Level) (Creds, error) {
	switch l.Kind {
	case LevelScope:
		return LoadScope(s.Dir, l.Name)
	case LevelDevice:
		return LoadDevice(s.Dir, l.Name)
	}
	return Load(s.File)
}

// Save writes the credentials of one level.
func (s Store) Save(l Level, c Creds) error {
	switch l.Kind {
	case LevelScope:
		return SaveScope(s.Dir, l.Name, c)
	case LevelDevice:
		return SaveDevice(s.Dir, l.Name, c, s.Mapped != nil && s.Mapped(l.Name))
	}
	return Save(s.File, c)
}

// Peers are the pools a user added at level at has to be unique against, at
// not among them:
//   - at the default level: every scope's and every device's pool;
//   - at a scope: the default level's and the pools of devicesOfScope (the
//     devices of that scope, by name);
//   - at a device: the default level's and, when scope is not empty, the
//     scope's.
//
// A file that cannot be read is an error: a name cannot be called free while
// a pool is unseen.
func (s Store) Peers(at Level, scope string, devicesOfScope []string) ([]Pool, error) {
	var levels []Level
	add := func(l Level) {
		if l != at {
			levels = append(levels, l)
		}
	}
	switch at.Kind {
	case LevelScope:
		add(Level{Kind: LevelDefault})
		for _, d := range devicesOfScope {
			add(Level{Kind: LevelDevice, Name: d})
		}
	case LevelDevice:
		add(Level{Kind: LevelDefault})
		if scope != "" {
			add(Level{Kind: LevelScope, Name: scope})
		}
	default:
		scopes, err := ScopeNames(s.Dir)
		if err != nil {
			return nil, err
		}
		devs, err := DeviceNames(s.Dir)
		if err != nil {
			return nil, err
		}
		for _, n := range scopes {
			add(Level{Kind: LevelScope, Name: n})
		}
		for _, n := range devs {
			add(Level{Kind: LevelDevice, Name: n})
		}
	}
	var out []Pool
	for _, l := range levels {
		c, err := s.Load(l)
		if err != nil {
			return nil, err
		}
		out = append(out, Pool{Level: l, Creds: c})
	}
	return out, nil
}

// Referrers are the devices whose default names the user though the user is
// not in their own pool (a device may choose a user of its scope's pool or of
// the default level's): the ones to be told before the user goes, since the
// next lookup of such a device would fail. A scope's and the default level's
// defaults only name their own pool. The devices searched are those of
// devicesOfScope for a scope, every device with a file for the default level,
// none for a device.
func (s Store) Referrers(name string, at Level, devicesOfScope []string) ([]Level, error) {
	var devs []string
	switch at.Kind {
	case LevelScope:
		devs = devicesOfScope
	case LevelDevice:
		return nil, nil
	default:
		var err error
		if devs, err = DeviceNames(s.Dir); err != nil {
			return nil, err
		}
	}
	var out []Level
	for _, d := range devs {
		l := Level{Kind: LevelDevice, Name: d}
		c, err := s.Load(l)
		if err != nil {
			return nil, err
		}
		if _, own := c.Find(name); c.Default == name && !own {
			out = append(out, l)
		}
	}
	return out, nil
}

// Path is the file of the level.
func (s Store) Path(l Level) (string, error) {
	switch l.Kind {
	case LevelScope:
		return ScopeFile(s.Dir, l.Name)
	case LevelDevice:
		return DeviceFile(s.Dir, l.Name)
	}
	return s.File, nil
}
