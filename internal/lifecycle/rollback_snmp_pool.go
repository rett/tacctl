package lifecycle

// The pool of SNMPv3 users (0.2.23, D303 to D305) in a rollback. The
// credential files (snmp.yaml, snmp/<scope>.yaml, snmp/devices/<name>.yaml)
// are version 2 (`users:` and `default:`) when a command of this release has
// saved something version 1 cannot hold: a second or a non-default user, a
// default that names another level's user, a device's file that counts
// without an snmp: entry (snmpcred.Creds.Text chooses; a community and one
// default user are saved in version 1). Every release before 0.2.23 reads
// version 1 only, with one v3 user, and its strict parser refuses a version 2
// file ("unsupported version"), so every target writes each version 2 file as
// version 1 again, after the snapshot --apply takes first
// (rollback_additions.go). A state with version 1 files only has nothing to
// convert: no step, no snapshot, no --yes.
//
// A level holds one v3 user in version 1: its default user stays and the rest
// are dropped. A level with several users and none that is its default has no
// answer to which one stays, so the rollback is refused, naming the level. A
// level with one user that is not its default drops it too (the lookups of
// this release do not use it). A device whose default names a user of its
// scope's or the config's pool has no such user in version 1: its choice
// goes, and it reads with its scope's or the config's user again.
//
// A device that has no `snmp:` entry in devices.yaml is the other case 0.2.22
// and before cannot hold: they ignore the credentials file of such a device (an
// orphan), so the file in version 1 would hand the device to another level's
// credential without a word. Such a file is removed instead, all of it, and
// the device is counted (orphans) with the users it loses: a warning, --yes,
// the kept snapshot and 'backup recover' cover it as they cover the rest.
//
// The plan, the warning and the audit line name the levels and count the
// users, never a user's name or a passphrase. The snapshot is the record,
// and the apply keeps it (snapshot.Keep, with a note that carries the
// counts) as the email step does: 'tacctl backup recover <snapshot> --only
// snmp-users' puts the users back once this release is installed again. A
// rollback that drops no user (every level has a default user and no other)
// only rewrites the files, asks nothing and loses nothing.

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/snmpcred"
)

// snmpPoolRelease is the release that made the change (its entry in rollbackAdditions).
const snmpPoolRelease = "0.2.23"

// snmpPoolFile is one credential file in version 2.
type snmpPoolFile struct {
	path, level, header string
	creds               snmpcred.Creds
	// kept is the user version 1 holds ("" for none), dropped how many users
	// go, and choice whether a default naming a user of another level goes.
	// orphan: a device without an snmp: entry, whose file goes whole.
	kept    string
	dropped int
	choice  bool
	orphan  bool
}

// SNMPPoolDrop is what the rollback drops from the pools: users and the
// levels they are in, the devices whose choice of another level's user goes
// and the devices without an snmp: entry whose credentials file goes.
type SNMPPoolDrop struct {
	Users, Levels, Choices, Orphans int
}

// Any reports whether anything is dropped.
func (d SNMPPoolDrop) Any() bool { return d.Users > 0 || d.Choices > 0 || d.Orphans > 0 }

// planSNMPPool reads the credential files for the ones in version 2. A file
// that cannot be read is not this change's (every release refuses it the
// same).
func (p *RollbackPlan) planSNMPPool() error {
	pa := p.in.Paths
	st := snmpcred.Store{File: pa.SNMPFile, Dir: pa.SNMPDir}
	reg, err := devreg.Load(pa.DevicesFile)
	if err != nil {
		return err
	}
	var files []snmpPoolFile
	add := func(l snmpcred.Level, header string) error {
		path, err := st.Path(l)
		if err != nil {
			return nil
		}
		c, err := st.Load(l)
		if err != nil || c.Format != snmpcred.Version {
			return nil
		}
		f := snmpPoolFile{path: path, level: l.Label(), header: header, creds: c}
		if l.Kind == snmpcred.LevelDefault {
			f.level = "the config"
		}
		if _, ok := c.Find(c.Default); ok {
			f.kept = c.Default
		}
		f.dropped = len(c.Users)
		if f.kept != "" {
			f.dropped--
		}
		f.choice = c.Default != "" && f.kept == ""
		// A device with no snmp: entry: the older releases ignore its file.
		if d := reg.Find(l.Name); l.Kind == snmpcred.LevelDevice && d != nil && d.SNMP.Empty() && !c.Empty() {
			f.orphan, f.kept, f.dropped, f.choice = true, "", len(c.Users), false
			files = append(files, f)
			return nil
		}
		if f.kept == "" && len(c.Users) > 1 {
			why := "none of them is its default"
			if f.choice {
				why = "its default names a user of another level's pool, so none of its own is the default"
			}
			return &RollbackRefusal{Lines: []string{
				f.level + " holds " + strconv.Itoa(len(c.Users)) + " SNMPv3 users and " + why + ", and " + p.target() + " reads one v3 user for each level: it cannot tell which one stays.",
				"Choose it first: " + setterOfLevel(l) + " v3-user default <user> (or remove the others with v3-user remove). Nothing was changed.",
			}}
		}
		files = append(files, f)
		return nil
	}
	if err := add(snmpcred.Level{Kind: snmpcred.LevelDefault}, snmpcred.Header); err != nil {
		return err
	}
	scopes, err := snmpcred.ScopeNames(pa.SNMPDir)
	if err != nil {
		return err
	}
	for _, n := range scopes {
		if err := add(snmpcred.Level{Kind: snmpcred.LevelScope, Name: n}, snmpcred.Header); err != nil {
			return err
		}
	}
	devs, err := snmpcred.DeviceNames(pa.SNMPDir)
	if err != nil {
		return err
	}
	for _, n := range devs {
		if err := add(snmpcred.Level{Kind: snmpcred.LevelDevice, Name: n}, snmpcred.DeviceHeader); err != nil {
			return err
		}
	}
	p.snmpPool = files
	return nil
}

// setterOfLevel is the verb family of a level, for the refusal.
func setterOfLevel(l snmpcred.Level) string {
	switch l.Kind {
	case snmpcred.LevelScope:
		return "tacctl scope snmp " + l.Name
	case snmpcred.LevelDevice:
		return "tacctl device snmp " + l.Name
	}
	return "tacctl config snmp"
}

// SNMPPoolDropped is what the rollback drops from the pools.
func (p *RollbackPlan) SNMPPoolDropped() SNMPPoolDrop {
	var d SNMPPoolDrop
	for _, f := range p.snmpPool {
		d.Users += f.dropped
		if f.dropped > 0 {
			d.Levels++
		}
		if f.orphan {
			d.Orphans++
		}
		if f.choice {
			d.Choices++
		}
	}
	return d
}

// SNMPPoolOrphans are the devices without an snmp: entry whose credentials
// file goes, by name.
func (p *RollbackPlan) SNMPPoolOrphans() []string {
	var out []string
	for _, f := range p.snmpPool {
		if f.orphan {
			out = append(out, strings.TrimPrefix(f.level, "device "))
		}
	}
	return out
}

// SNMPPoolLevels are the levels (and how many users each loses) that lose
// users, in the order of the files: 'scope lab (2)'.
func (p *RollbackPlan) SNMPPoolLevels() []string {
	var out []string
	for _, f := range p.snmpPool {
		if f.dropped > 0 {
			out = append(out, f.level+" ("+strconv.Itoa(f.dropped)+")")
		}
	}
	return out
}

// addSNMPPool adds the step, the warning and the note to the plan of any
// target older than 0.2.23.
func (p *RollbackPlan) addSNMPPool() {
	if len(p.snmpPool) == 0 {
		return
	}
	target, dir := p.target(), p.in.Paths.SNMPDir
	s := RollbackStep{Title: "write the SNMP credential files in version 1 (" + p.in.Paths.SNMPFile + ", " + dir + ")", Todo: true}
	for _, f := range p.snmpPool {
		line := f.level + ": "
		switch {
		case f.orphan:
			line += "no snmp: entry in devices.yaml beside the file, which " + target + " ignores: the file goes (" + strconv.Itoa(f.dropped) + " " + plural(f.dropped, "user", "users") + ")"
		case f.kept != "" && f.dropped > 0:
			line += "keep the default user, drop " + strconv.Itoa(f.dropped) + " " + plural(f.dropped, "user", "users")
		case f.kept != "":
			line += "keep the default user"
		case f.dropped > 0:
			line += "drop " + strconv.Itoa(f.dropped) + " " + plural(f.dropped, "user", "users") + " (none is the default)"
		default:
			line += "no user"
		}
		if f.choice && !f.orphan {
			line += "; its default names a user of another level's pool, which " + target + " cannot hold: dropped"
		}
		if f.creds.Community == "" && f.kept == "" && !f.orphan {
			line += "; nothing is left, the file goes"
		}
		s.Lines = append(s.Lines, line)
	}
	s.Lines = append(s.Lines, "("+target+"'s parser refuses version 2: \"unsupported version\"; the community stays)")
	at := len(p.Steps)
	for i := range p.Steps {
		if p.Steps[i].Title == "leave every other file untouched" {
			at = i
			// The credentials are no longer among the files left.
			if len(p.Steps[i].Lines) > 0 {
				p.Steps[i].Lines[0] = strings.Replace(p.Steps[i].Lines[0], "the SNMP credentials, ", "", 1)
			}
			break
		}
	}
	p.Steps = slices.Insert(p.Steps, at, s)

	d := p.SNMPPoolDropped()
	if !d.Any() {
		return
	}
	var lines []string
	if d.Users > 0 {
		lines = append(lines, target+" reads one SNMPv3 user for each level: "+strconv.Itoa(d.Users)+" "+plural(d.Users, "user is", "users are")+" dropped from "+
			strconv.Itoa(d.Levels)+" "+plural(d.Levels, "level", "levels")+" ("+strings.Join(p.SNMPPoolLevels(), ", ")+"); the default user of each level stays.")
	}
	if d.Orphans > 0 {
		lines = append(lines, strconv.Itoa(d.Orphans)+" "+plural(d.Orphans, "device has", "devices have")+" credentials and no snmp: entry in devices.yaml ("+strings.Join(p.SNMPPoolOrphans(), ", ")+
			"): "+target+" ignores such a file, so it is removed rather than left to hand the device to another level's credentials.")
	}
	if d.Choices > 0 {
		lines = append(lines, strconv.Itoa(d.Choices)+" "+plural(d.Choices, "device chooses", "devices choose")+" a user of its scope's or the config's pool: the choice goes, and the device reads with its scope's or the config's default user again.")
	}
	lines = append(lines, "What is dropped stays in the snapshot --apply takes first (tacctl backup list), whose id the apply names, and --apply keeps that snapshot in "+p.in.Paths.KeptDir+
		" ('tacctl backup keep': "+target+" prunes backups/ by its own retention and does not know the copy). Once "+snmpPoolRelease+
		" is installed again, 'tacctl backup recover <snapshot> --only snmp-users' puts them back.")
	p.Warnings = append(p.Warnings, RollbackWarning{Title: "SNMPv3 users are dropped from the credential files", Lines: lines})
}

// applySNMPPool writes the files in version 1, or removes the one nothing is
// left of. Each write is atomic and the step is idempotent: a file that is
// version 1 is not in the plan the next time.
func (p *RollbackPlan) applySNMPPool() (int, error) {
	n := 0
	for _, f := range p.snmpPool {
		c := snmpcred.Creds{Community: f.creds.Community}
		if f.orphan {
			c = snmpcred.Creds{}
		}
		if f.kept != "" {
			u, _ := f.creds.Find(f.kept)
			c.Users, c.Default = []snmpcred.User{u}, f.kept
		}
		if c.Empty() {
			if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
				return n, err
			}
		} else if err := snmpcred.SaveLegacy(f.path, c, f.header); err != nil {
			return n, err
		}
		n++
	}
	// A device's directory the last file left empty goes with it.
	_ = os.Remove(filepath.Join(p.in.Paths.SNMPDir, snmpcred.DevicesDir))
	_ = os.Remove(p.in.Paths.SNMPDir)
	return n, nil
}
