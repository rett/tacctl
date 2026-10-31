package snapshot

// Kept snapshots (0.2.23): 'backup keep' copies a snapshot of backups/ to
// backups-kept/<id>/, where no retention reaches. This release prunes
// backups/ only, and the older releases a rollback goes to keep the newest 30
// of it and know no marker, so a copy outside backups/ is the one thing that
// survives them. A kept copy is a snapshot like any other (the same files,
// the manifest included, 0600 in a directory of 0700) with one file more,
// KeptName, that says why it is kept and by whom.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// KeptName is the file of a kept copy that records the note, who kept it and
// when.
const KeptName = "kept"

// KeptInfo is what KeptName records. Note is free text of the operator's.
type KeptInfo struct {
	Note string
	// User and SID are who last set the note (the session id of the audit
	// lines), At when (UTC, RFC 3339): who kept the snapshot until a note
	// replaces the first one.
	User, SID, At string
}

// KeptIDs are the ids of the kept copies under keptDir, newest first.
func KeptIDs(keptDir string) []string { return IDs(keptDir) }

// KeptPath is the directory of the kept copy of id, "" when there is none (or
// id is no snapshot id, or the entry is not a directory).
func KeptPath(keptDir, id string) string {
	if !ValidID(id) {
		return ""
	}
	p := filepath.Join(keptDir, id)
	if st, err := os.Lstat(p); err != nil || !st.IsDir() {
		return ""
	}
	return p
}

// ReadKept is the record of a kept copy in dir; the zero value when it has
// none or cannot be read.
func ReadKept(dir string) KeptInfo {
	var m map[string]string
	data, err := os.ReadFile(filepath.Join(dir, KeptName))
	if err != nil || json.Unmarshal(data, &m) != nil {
		return KeptInfo{}
	}
	return KeptInfo{Note: m["note"], User: m["user"], SID: m["sid"], At: m["at"]}
}

func writeKept(dir string, k KeptInfo) error {
	m := map[string]string{"at": k.At}
	for key, v := range map[string]string{"note": k.Note, "user": k.User, "sid": k.SID} {
		if v != "" {
			m[key] = v
		}
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, KeptName), append(data, '\n'), 0o600)
}

// Keep copies the snapshot id of backupDir to keptDir/<id> (the directory
// 0700, its files 0600) with the record info, and returns the directory and
// whether it made the copy. A copy that exists is whole (it is built under a
// private name and renamed into place) and is left as it is, but for its
// record, which a non-empty info.Note replaces as a whole (the note, and who
// set it and when); its original need not be in backupDir any more. Two
// callers keeping one id at once both succeed: the one whose rename finds the
// copy made returns it. An id that is not a snapshot id, or a snapshot that is
// not there, is an error.
func Keep(backupDir, keptDir, id string, info KeptInfo) (dir string, created bool, err error) {
	if !ValidID(id) {
		return "", false, errors.New("not a snapshot id")
	}
	if p := KeptPath(keptDir, id); p != "" {
		if info.Note == "" {
			return p, false, nil
		}
		return p, false, writeKept(p, info)
	}
	src := filepath.Join(backupDir, id)
	if st, err := os.Lstat(src); err != nil || !st.IsDir() {
		return "", false, errors.New("snapshot " + id + " is not in " + backupDir)
	}
	if err := os.MkdirAll(keptDir, 0o700); err != nil {
		return "", false, err
	}
	_ = os.Chmod(keptDir, 0o700)
	tmp, err := os.MkdirTemp(keptDir, ".keep.")
	if err != nil {
		return "", false, err
	}
	if err := copyTree(src, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return "", false, err
	}
	if err := writeKept(tmp, info); err != nil {
		_ = os.RemoveAll(tmp)
		return "", false, err
	}
	final := filepath.Join(keptDir, id)
	if err := os.Rename(tmp, final); err != nil {
		_ = os.RemoveAll(tmp)
		// another keep of the same id won the rename: its copy is whole, and
		// a note given here still replaces the note
		if KeptPath(keptDir, id) != "" && isRegular(filepath.Join(final, "store.yaml")) && isRegular(filepath.Join(final, KeptName)) {
			p, _, err := Keep(backupDir, keptDir, id, KeptInfo{Note: info.Note, User: info.User, SID: info.SID, At: info.At})
			return p, false, err
		}
		return "", false, err
	}
	return final, true, nil
}

// Unkeep removes the kept copy of id.
func Unkeep(keptDir, id string) error {
	p := KeptPath(keptDir, id)
	if p == "" {
		return errors.New("snapshot " + id + " is not kept")
	}
	return os.RemoveAll(p)
}

// copyTree copies the directories (0700) and regular files (0600) under src
// into the existing directory dst; anything else is not part of a snapshot
// and is skipped.
func copyTree(src, dst string) error {
	des, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.Chmod(dst, 0o700); err != nil {
		return err
	}
	for _, de := range des {
		from, to := filepath.Join(src, de.Name()), filepath.Join(dst, de.Name())
		switch {
		case de.IsDir():
			if err := os.Mkdir(to, 0o700); err != nil {
				return err
			}
			if err := copyTree(from, to); err != nil {
				return err
			}
		case de.Type().IsRegular():
			if err := copyFile(from, to); err != nil {
				return err
			}
		}
	}
	return nil
}
