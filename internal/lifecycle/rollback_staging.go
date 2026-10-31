package lifecycle

// The staging entries marked covered (0.2.23, state/staging) in a rollback.
// This release writes one for a device at a bench address its scope answered
// already, by a prefix of its own: the line has a sixth field, "covered",
// and no /32 was added to the scope. An older release reads the line as any
// other staging entry and writes it back without the field, and its sweep
// and 'scope staging remove' take the /32 of the entry out of the scope: if
// the scope holds that exact /32 as a real prefix, a real prefix goes. So
// every target drops these lines from the file. The plan names them, the
// snapshot --apply takes first holds the file, and nothing needs an answer: no
// warning and no --yes. A clone still waiting for its 'device rename
// --replace' loses its entry: a re-upgrade cannot write it again, so the plan
// says to clone again or restore the snapshot.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// stagingCoveredFile is the staging file of the state directory.
func (p *RollbackPlan) stagingCoveredFile() string {
	return filepath.Join(p.in.Paths.StateDir, "staging")
}

// isCoveredLine reports whether a line of the staging file is an entry marked
// covered: <cidr>|<scope>|<kind>|<name>|<since>|covered.
func isCoveredLine(line string) bool {
	f := strings.Split(strings.TrimSpace(line), "|")
	return len(f) > 5 && f[0] != "" && f[5] == "covered"
}

// planStagingCovered reads the staging file for the covered entries. A file
// that is not there has none; one that cannot be read is not this change's
// to refuse (the older release reads it as little as this one does).
func (p *RollbackPlan) planStagingCovered() error {
	data, err := os.ReadFile(p.stagingCoveredFile())
	if err != nil {
		return nil
	}
	for _, l := range strings.Split(string(data), "\n") {
		if isCoveredLine(l) {
			f := strings.Split(strings.TrimSpace(l), "|")
			p.stagingCovered = append(p.stagingCovered, f[0]+" (scope "+f[1]+", "+f[2]+" "+f[3]+")")
		}
	}
	return nil
}

// StagingCovered are the staging entries the rollback drops, by address.
func (p *RollbackPlan) StagingCovered() []string { return slices.Clone(p.stagingCovered) }

// addStagingCovered adds the step to the plan of any target older than 0.2.23.
func (p *RollbackPlan) addStagingCovered() {
	if len(p.stagingCovered) == 0 {
		return
	}
	target := p.target()
	s := RollbackStep{Title: p.stagingCoveredFile() + ": drop the staging entries of addresses a scope answers already", Todo: true}
	for _, e := range p.stagingCovered {
		s.Lines = append(s.Lines, "drop "+e)
	}
	s.Lines = append(s.Lines, "(no /32 was added to the scope for them; "+target+" would take the /32 of such an entry out of the scope when its device moves, a prefix of the scope's own included; every other entry stays; a clone still waiting for its 'device rename --replace' loses its entry, and after a re-upgrade that verb refuses it as not staged: remove the clone and clone again from the original, or restore the snapshot)")
	at := len(p.Steps)
	for i := range p.Steps {
		if p.Steps[i].Title == "leave every other file untouched" {
			at = i
			break
		}
	}
	p.Steps = slices.Insert(p.Steps, at, s)
}

// applyStagingCovered rewrites the staging file without the covered entries
// (every other line as it is); a file nothing is left of is removed. It is
// idempotent: a file without them is not in the plan the next time.
func (p *RollbackPlan) applyStagingCovered() (int, error) {
	path := p.stagingCoveredFile()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var kept []string
	n := 0
	for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if isCoveredLine(l) {
			n++
			continue
		}
		kept = append(kept, l)
	}
	if n == 0 {
		return 0, nil
	}
	if len(kept) == 0 {
		return n, os.Remove(path)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		return 0, err
	}
	return n, os.Rename(tmp, path)
}
