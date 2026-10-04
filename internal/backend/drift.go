package backend

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/ui"
)

// DriftSelection says whose artifacts CheckDrift reports (the argument of
// backends_check_drift).
type DriftSelection struct {
	// Owner, when set, is one backend: only its artifacts.
	Owner string
	// Unowned: only the artifacts no registered backend claims, and
	// rendered.json itself when it cannot be read.
	Unowned bool
}

// DriftAll, DriftOf and DriftUnowned are the three selections. DriftAll is
// every artifact that matters: those of an enabled backend and those no
// backend claims; the artifacts a disabled backend left behind are not
// reported, since nothing serves them.
var DriftAll = DriftSelection{}

// DriftOf selects one backend's artifacts.
func DriftOf(id string) DriftSelection { return DriftSelection{Owner: id} }

// DriftUnowned selects the artifacts no backend claims.
var DriftUnowned = DriftSelection{Unowned: true}

// CheckDrift is backends_check_drift: every artifact tacctl rendered whose
// file is no longer what rendered.json records — status drift (edited by
// hand), missing (deleted) or unreadable (rendered.json itself cannot be
// read) — selected by sel. Nothing when everything matches or nothing has
// been rendered yet.
func (s *Set) CheckDrift(sel DriftSelection) []rendered.Entry {
	entries := rendered.CheckDrift(s.Env.Paths.Rendered)
	if len(entries) == 0 {
		return nil
	}
	enabled, err := s.Enabled()
	if err != nil {
		enabled = s.IDs()
	}
	var out []rendered.Entry
	for _, e := range entries {
		owner := ""
		if e.Path != s.Env.Paths.Rendered {
			owner = s.Owner(e.Path)
		}
		switch {
		case sel.Unowned:
			if owner != "" {
				continue
			}
		case sel.Owner != "":
			if owner != sel.Owner {
				continue
			}
		default:
			if owner != "" && !slices.Contains(enabled, owner) {
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// DriftLines is print_drift_lines: the red DRIFT lines 'status' and
// 'config validate' print, two per drifted artifact of sel (none when
// nothing drifted), each ending in a newline. The hint depends on whose
// artifact it is: only a backend whose Description has an ImportCmd can
// adopt a hand edit.
func (s *Set) DriftLines(sel DriftSelection) []string {
	var lines []string
	const indent = "                        "
	for _, e := range s.CheckDrift(sel) {
		var what string
		switch e.Status {
		case rendered.Drift:
			what = "edited since tacctl rendered it"
		case rendered.Missing:
			what = "rendered by tacctl but no longer there"
		default:
			what = "render records cannot be read"
		}
		lines = append(lines, "  "+ui.Red+"DRIFT:"+ui.NC+"                "+e.Path+" — "+what+"\n")
		owner, importCmd := "", ""
		if e.Path != s.Env.Paths.Rendered {
			owner = s.Owner(e.Path)
		}
		if owner != "" {
			importCmd = s.must(owner).Describe().ImportCmd
		}
		switch {
		case strings.HasSuffix(e.Path, "/tacctl.conf"):
			// A unit drop-in a backend renders (always under this name)
			// holds nothing tacctl.yaml does not: there is nothing to
			// import, and a render replaces it without --force.
			lines = append(lines, indent+"'tacctl config render' rewrites it from tacctl.yaml (a copy is kept); unit settings of your own belong in another .conf file of that directory\n")
		case importCmd != "" || owner == "":
			if importCmd == "" {
				importCmd = "tacctl store import --replace"
			}
			lines = append(lines, indent+"keep the edits: '"+importCmd+"' then 'tacctl config render --force'; discard them: 'tacctl config render --force'\n")
		default:
			lines = append(lines, indent+"discard the edits: 'tacctl config render --force' (a copy is kept); there is no way to adopt them into the store\n")
		}
	}
	return lines
}
