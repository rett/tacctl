package cli

// The files of 'device reports' (docs/plans/0.2.26-plan.md D324): a report is
// a file of the generating user's home, ~/reports/devices/<name>.<ext>, with
// <name>.<ext>.meta beside it. Every access to the directory runs with the
// file-system identity of the user whose directory it is (asIDs), so that a
// link in a user's directory never gives the reader root's reach and what is
// made is the user's own.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/reports"
)

// reportMetaMax is the largest .meta file read: a metadata file is a few
// hundred bytes.
const reportMetaMax = 1 << 20

// reportReadMax is the most that export and show --content read of one file.
const reportReadMax = 1 << 30

// reportUserRE is a user name as a directory is looked up for: letters,
// digits, '_' and '-'.
var reportUserRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)

// reportPlace is where one user's reports are kept.
type reportPlace struct {
	user string
	// home is the account's home, dir the reports directory in it.
	home, dir string
	uid, gid  int
}

// reportPlaceOf looks the user up in the account database (hooks.account, so
// that tests fake it) and returns the user's reports directory. A user with
// no account has none.
func (inv *invocation) reportPlaceOf(user string) (reportPlace, error) {
	if len(user) > 64 || !reportUserRE.MatchString(user) {
		return reportPlace{}, fmt.Errorf("'%s' is not a user name", user)
	}
	acct, err := inv.hooks.account(user)
	if err != nil || acct.Home == "" || !filepath.IsAbs(acct.Home) {
		return reportPlace{}, fmt.Errorf("the user '%s' has no account on this server", user)
	}
	if user == inv.sudoUser() && os.Geteuid() == 0 {
		if uid, _, ok := inv.callerIDs(); ok && uid != int(acct.UID) {
			return reportPlace{}, fmt.Errorf("the account of '%s' is not the one sudo ran this for", user)
		}
	}
	return reportPlace{user: user, home: acct.Home, dir: filepath.Join(acct.Home, "reports", "devices"),
		uid: int(acct.UID), gid: int(acct.GID)}, nil
}

// as runs fn with the user's file-system identity when this process is root;
// otherwise as it is (a process that is not root can touch only its own).
func (pl reportPlace) as(fn func() error) error {
	if os.Geteuid() != 0 {
		return fn()
	}
	return asIDs(pl.uid, pl.gid, fn)
}

// reportFile is one file of the reports directory.
type reportFile struct {
	// File is the file name with its extension, Name the name a report is
	// addressed by (File without the extension).
	File, Name string
	// Meta is the metadata; nil for a file tacctl did not make or whose
	// metadata cannot be read (Note says why in that case).
	Meta *reports.Meta
	Note string
	Size int64
	Mod  time.Time
}

// When is the time of the report: generated, else the file's own.
func (f reportFile) When() time.Time {
	if f.Meta != nil {
		return f.Meta.Generated
	}
	return f.Mod
}

// reportDir is what the directory holds.
type reportDir struct {
	Files []reportFile
	// Bases are the base names in use, in any extension and with or without
	// a .meta, which no new report may take.
	Bases map[string]bool
}

// Count is the number of reports tacctl made (those with a metadata file).
func (d reportDir) Count() int {
	n := 0
	for _, f := range d.Files {
		if f.Meta != nil {
			n++
		}
	}
	return n
}

// read lists the directory, newest first. A directory that is not there is an
// empty one.
func (pl reportPlace) read() (reportDir, error) {
	d := reportDir{Bases: map[string]bool{}}
	err := pl.as(func() error {
		ents, err := os.ReadDir(pl.dir)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("cannot read %s: %w", pl.dir, err)
		}
		for _, e := range ents {
			n := e.Name()
			if strings.HasPrefix(n, ".") {
				continue
			}
			if base, ok := strings.CutSuffix(n, ".meta"); ok {
				d.Bases[strings.TrimSuffix(base, filepath.Ext(base))] = true
				continue
			}
			st, err := os.Lstat(filepath.Join(pl.dir, n))
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			rf := reportFile{File: n, Size: st.Size(), Mod: st.ModTime().UTC()}
			rf.Name = strings.TrimSuffix(n, filepath.Ext(n))
			if m, note := readReportMeta(filepath.Join(pl.dir, n+".meta")); m != nil {
				rf.Meta = m
				if ext := reports.Ext(m.Format); ext != "" && strings.HasSuffix(n, ext) {
					rf.Name = strings.TrimSuffix(n, ext)
				}
			} else {
				rf.Note = note
			}
			d.Bases[rf.Name] = true
			d.Files = append(d.Files, rf)
		}
		return nil
	})
	sort.SliceStable(d.Files, func(i, j int) bool {
		a, b := d.Files[i].When(), d.Files[j].When()
		if !a.Equal(b) {
			return a.After(b)
		}
		return d.Files[i].File < d.Files[j].File
	})
	return d, err
}

// readReportMeta reads a metadata file: nil and a note when there is none or
// it cannot be used.
func readReportMeta(path string) (*reports.Meta, string) {
	st, err := os.Lstat(path)
	switch {
	case err != nil:
		return nil, ""
	case !st.Mode().IsRegular():
		return nil, "the metadata file is not a regular file"
	case st.Size() > reportMetaMax:
		return nil, "the metadata file is too large"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "the metadata file cannot be read"
	}
	m, err := reports.ParseMeta(b)
	if err != nil {
		return nil, err.Error()
	}
	return &m, ""
}

// find is the report a reference names: a file name, or a name without the
// extension. Two files with one name need the extension.
func (d reportDir) find(ref string) (*reportFile, error) {
	for i := range d.Files {
		if d.Files[i].File == ref {
			return &d.Files[i], nil
		}
	}
	var hit []*reportFile
	for i := range d.Files {
		if d.Files[i].Name == ref {
			hit = append(hit, &d.Files[i])
		}
	}
	switch len(hit) {
	case 0:
		return nil, fmt.Errorf("there is no report '%s' (list them with: tacctl device reports list)", ref)
	case 1:
		return hit[0], nil
	}
	var files []string
	for _, h := range hit {
		files = append(files, h.File)
	}
	sort.Strings(files)
	return nil, fmt.Errorf("'%s' names several reports (%s): give the file name with its extension", ref, strings.Join(files, ", "))
}

// write stores a report and its metadata, 0600, in the directory made 0700,
// as the user. The report is written first and removed again when the
// metadata cannot be.
func (pl reportPlace) write(file string, body, meta []byte) error {
	return pl.as(func() error {
		if err := os.MkdirAll(pl.dir, 0o700); err != nil {
			return fmt.Errorf("cannot create %s: %w", pl.dir, err)
		}
		p := filepath.Join(pl.dir, file)
		if err := writePrivate(p, body, false); err != nil {
			return err
		}
		if err := writePrivate(p+".meta", meta, false); err != nil {
			_ = os.Remove(p)
			return err
		}
		return nil
	})
}

// content reads the report file (at most reportReadMax bytes).
func (pl reportPlace) content(file string) ([]byte, error) {
	var b []byte
	err := pl.as(func() error {
		f, err := os.Open(filepath.Join(pl.dir, file))
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		b, err = io.ReadAll(io.LimitReader(f, reportReadMax+1))
		if err == nil && len(b) > reportReadMax {
			err = fmt.Errorf("%s is larger than %d bytes", file, reportReadMax)
		}
		return err
	})
	return b, err
}

// remove deletes a report and its metadata.
func (pl reportPlace) remove(file string) error {
	return pl.as(func() error {
		p := filepath.Join(pl.dir, file)
		if err := os.Remove(p); err != nil {
			return err
		}
		if err := os.Remove(p + ".meta"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
}

// rename gives a report a new name: the new file is linked (a name in use is
// refused, whatever it holds), its metadata written with the new name, then
// the old files go.
func (pl reportPlace) rename(old reportFile, newName string, meta []byte) (string, error) {
	newFile := newName + filepath.Ext(old.File)
	if old.Meta != nil {
		newFile = newName + reports.Ext(old.Meta.Format)
	}
	err := pl.as(func() error {
		from, to := filepath.Join(pl.dir, old.File), filepath.Join(pl.dir, newFile)
		if err := os.Link(from, to); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%s exists", newFile)
			}
			return err
		}
		if err := writePrivate(to+".meta", meta, false); err != nil {
			_ = os.Remove(to)
			return err
		}
		if err := os.Remove(from); err != nil {
			return err
		}
		if err := os.Remove(from + ".meta"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
	return newFile, err
}
