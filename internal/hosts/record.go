package hosts

// The per-host record (StateDir/hosts/<name>.json, one file per enrolled
// host): what 'host enroll' and 'host sync' saw at the last run, for 'host
// show' to print: when it ran, by whom, how it ended, the client script
// protocol it pushed and the accounts the script reported changing; and
// the host's facts read over that run's session. The record is written
// whole (a temporary file renamed over it), removed with the host and
// renamed with it. Nothing reads it to decide anything, but for the
// provisioner entry (Record.Provisioner).

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// Record is one host's record.
type Record struct {
	// LastSync is the last enroll or sync (nil before 0.2.2).
	LastSync *SyncRecord `json:"last_sync,omitempty"`
	// Facts are the host's facts as the last successful run read them
	// (nil before 0.2.2, or when nothing could be read).
	Facts *FactsRecord `json:"facts,omitempty"`
	// Provisioner is the last 'host provisioner rotate' (nil when none):
	// the one record 'rotate --remove-old' reads back, to find the login a
	// rotation replaced when it was interrupted or run without --remove-old.
	Provisioner *ProvisionerRecord `json:"provisioner,omitempty"`
}

// ProvisionerRecord is one 'host provisioner rotate' that switched a
// host's provisioning account.
type ProvisionerRecord struct {
	// At is when the registry switched (RFC 3339), By who ran it.
	At string `json:"at"`
	By string `json:"by"`
	// Old and New are the logins ('' for an old login that was the
	// invoking user's own name); Auth is 'key' or 'password'.
	Old  string `json:"old"`
	New  string `json:"new"`
	Auth string `json:"auth"`
	// OldRemoved: the old account was removed afterwards.
	OldRemoved bool `json:"old_removed"`
}

// SyncRecord is one run of 'host enroll' or 'host sync' on a host.
type SyncRecord struct {
	// At is when it ran (RFC 3339), By who ran it (the sudo user), Command
	// 'enroll' or 'sync'.
	At      string `json:"at"`
	By      string `json:"by"`
	Command string `json:"command"`
	// OK is how it ended; Reason why it failed ("" when it did not).
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
	// Protocol is the client script protocol pushed (TAC_PROTOCOL).
	Protocol string `json:"protocol"`
	// Created, Updated and Removed are the accounts the script reported
	// changing (AccountChanges).
	Created []string `json:"created"`
	Updated []string `json:"updated"`
	Removed []string `json:"removed"`
}

// FactsRecord is what a run read of the host (Facts) and when.
type FactsRecord struct {
	At        string      `json:"at"`
	OSName    string      `json:"os_name"`
	OSVersion string      `json:"os_version"`
	OSPretty  string      `json:"os_pretty_name"`
	SSHD      string      `json:"sshd"`
	PAM       []PAMModule `json:"pam_modules"`
	LoginDefs bool        `json:"login_defs"`
	UIDMin    int         `json:"uid_min"`
	UIDMax    int         `json:"uid_max"`
}

// RecordOfFacts is the record of f, read at at.
func RecordOfFacts(f Facts, at string) *FactsRecord {
	return &FactsRecord{At: at, OSName: f.OSName, OSVersion: f.OSVersion, OSPretty: f.OSPretty, SSHD: f.SSHD,
		PAM: append([]PAMModule{}, f.PAM...), LoginDefs: f.LoginDefs, UIDMin: f.UIDMin, UIDMax: f.UIDMax}
}

// Facts are the facts the record holds.
func (r FactsRecord) Facts() Facts {
	return Facts{OSName: r.OSName, OSVersion: r.OSVersion, OSPretty: r.OSPretty, SSHD: r.SSHD, PAM: r.PAM,
		LoginDefs: r.LoginDefs, UIDMin: r.UIDMin, UIDMax: r.UIDMax}
}

// Records is the directory of the records (StateDir/hosts).
type Records struct{ Dir string }

// path is the record file of name.
func (rs Records) path(name string) string { return filepath.Join(rs.Dir, name+".json") }

// Load is the record of name; a missing file is the empty record.
func (rs Records) Load(name string) (Record, error) {
	var r Record
	data, err := os.ReadFile(rs.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(data, &r)
	return r, err
}

// Save writes the record of name whole: a temporary file in the
// directory (0700, made when missing), mode 0600, renamed over the old one.
func (rs Records) Save(name string, r Record) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(rs.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(rs.Dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), rs.path(name))
}

// Update loads the record of name, lets fn change it and saves it, under
// the records' lock, so that two commands changing the same record (a sync
// and a rotation) do not lose each other's change.
func (rs Records) Update(name string, fn func(*Record)) error {
	unlock, err := rs.lockRecords()
	if err != nil {
		return err
	}
	defer unlock()
	r, err := rs.Load(name)
	if err != nil {
		// An unreadable record is replaced: it is only ever shown.
		r = Record{}
	}
	fn(&r)
	return rs.Save(name, r)
}

// Forget removes the record of name (none is no error).
func (rs Records) Forget(name string) error {
	if err := os.Remove(rs.path(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Rename moves the record of old to new (none is no error).
func (rs Records) Rename(old, new string) error {
	if err := os.Rename(rs.path(old), rs.path(new)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
