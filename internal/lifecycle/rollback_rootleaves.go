package lifecycle

// The root statements of the stored pulls (0.2.20). The pull of this release
// reads 'system root-authentication' (the leaf's name only: a hash or key is
// never kept) and the 'root-login' leaf of 'system services ssh' into the
// breakglass section of every Junos device, whether or not the scope records
// root (devconf/junos_root.go), and leaves them out of the comparison when
// the scope does not. No release before puts them in a section: their pull
// leaves them out, and their comparison takes them, read from a sections file
// of this release, for extra statements of the breakglass section, which then
// reads differs on every Junos device of a scope with a break-glass user
// until the next pull (checked with 0.2.19 built from its tag). The files are
// derived (a pull rebuilds them, nothing else writes them, and they are never
// in a snapshot), so every target that reads them (all but 0.2.3) takes the
// statements out of the breakglass section of the sections files and the
// plain views, under the records' lock, and leaves every other line as it is:
// the file is then what the target's own pull would have stored. This
// release, should it stay, reads them as missing until its next pull, as it
// reads a record of an older release.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
)

// reRootLeaf matches a stored statement of root's break-glass access.
var reRootLeaf = regexp.MustCompile(`^(?:set|deactivate)\s+system\s+(?:root-authentication|services\s+ssh\s+root-login)(?:\s|$)`)

// rootLeafFile is a stored sections file whose breakglass section holds root
// statements.
type rootLeafFile struct {
	path string
	n    int
}

// sectionsHeaderBreakGlass starts the breakglass block of a sections file
// (devconf's writeSections: one literal block per section, two spaces in).
const sectionsHeaderBreakGlass = devconf.SectionBreakGlass + ": |"

// stripRootLeaves is text without the root statements of its breakglass
// section, and how many there were. A section left with nothing is written
// as an empty one, as the file writes it.
func stripRootLeaves(text string) (string, int) {
	lines := strings.SplitAfter(text, "\n")
	out := make([]string, 0, len(lines))
	n, header, kept := 0, -1, 0
	closeBlock := func() {
		if header >= 0 && kept == 0 {
			out[header] = devconf.SectionBreakGlass + ": \"\"\n"
		}
		header = -1
	}
	for _, l := range lines {
		if header >= 0 {
			if strings.HasPrefix(l, "  ") {
				if reRootLeaf.MatchString(strings.TrimSpace(l)) {
					n++
					continue
				}
				kept++
				out = append(out, l)
				continue
			}
			closeBlock()
		}
		if strings.TrimRight(l, "\n") == sectionsHeaderBreakGlass {
			header, kept = len(out), 0
		}
		out = append(out, l)
	}
	closeBlock()
	if n == 0 {
		return text, 0
	}
	return strings.Join(out, ""), n
}

// planRootLeaves fills rootLeaf: the sections files and plain views of the
// configuration directory that hold root statements. A directory or a file
// that cannot be read holds none (derived files: the next pull writes them).
func (p *RollbackPlan) planRootLeaves() {
	ents, err := os.ReadDir(p.in.Paths.ConfigDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.Type().IsRegular() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".plain")) {
			continue
		}
		f := filepath.Join(p.in.Paths.ConfigDir, e.Name())
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if _, n := stripRootLeaves(string(b)); n > 0 {
			p.rootLeaf = append(p.rootLeaf, rootLeafFile{f, n})
		}
	}
}

// addRootLeaves adds the step of the root statements to the plan of a target
// that reads the records, before the step that lists what is left alone.
func (p *RollbackPlan) addRootLeaves() {
	p.planRootLeaves()
	if len(p.rootLeaf) == 0 {
		return
	}
	t := p.target()
	s := RollbackStep{Title: p.in.Paths.ConfigDir + ": take the Junos root statements out of the stored pulls", Todo: true}
	for _, f := range p.rootLeaf {
		s.Lines = append(s.Lines, "take "+strconv.Itoa(f.n)+" "+plural(f.n, "statement", "statements")+" out of the breakglass section of "+filepath.Base(f.path))
	}
	s.Lines = append(s.Lines, "(this release's pull keeps 'system root-authentication' (the leaf's name only) and 'system services ssh root-login' in the breakglass section of every Junos device; "+
		t+" takes them for extra statements there, so the section would read differs until the next pull, and its own pull keeps neither; every other statement stays;",
		" derived files, never in a snapshot: this release, if it stays, reads the two as missing until its next pull)")
	at := len(p.Steps)
	if i := slices.IndexFunc(p.Steps, func(s RollbackStep) bool { return s.Title == "leave every other file untouched" }); i >= 0 {
		at = i
	}
	p.Steps = slices.Insert(p.Steps, at, s)
}

// applyRootLeaves takes the root statements out of the files of rootLeaf,
// under the records' lock, each in one atomic write; the number of files
// changed.
func (p *RollbackPlan) applyRootLeaves() (int, error) {
	pt := p.in.Paths
	unlock, err := (devconf.Store{Records: pt.ConfigRecords, Dir: pt.ConfigDir}).Lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	changed := 0
	for _, f := range p.rootLeaf {
		b, err := os.ReadFile(f.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return changed, fmt.Errorf("cannot read %s: %w", f.path, err)
		}
		text, n := stripRootLeaves(string(b))
		if n == 0 {
			continue
		}
		if err := writeFileAtomic(f.path, []byte(text), 0o600); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// writeFileAtomic writes data to path through a temporary file in its
// directory (named as devconf names its own, so no reader takes it for a
// device's file), with mode, and renames it into place.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	d := filepath.Dir(path)
	tf, err := os.CreateTemp(d, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	tmp := tf.Name()
	fail := func(err error) error {
		_ = tf.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := tf.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := tf.Write(data); err != nil {
		return fail(err)
	}
	if err := tf.Sync(); err != nil {
		return fail(err)
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("cannot write %s: %w", path, err)
	}
	if df, err := os.Open(d); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}
