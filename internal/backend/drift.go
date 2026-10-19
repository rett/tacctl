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

// DriftReport is one drifted artifact: what is wrong with it and what to do
// about it.
type DriftReport struct {
	Path, What, Advice string
}

// DriftReports are the artifacts CheckDrift reports for sel, each with the
// words DriftLines prints for it.
func (s *Set) DriftReports(sel DriftSelection) []DriftReport {
	var reports []DriftReport
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
		owner, importCmd := "", ""
		if e.Path != s.Env.Paths.Rendered {
			owner = s.Owner(e.Path)
		}
		if owner != "" {
			importCmd = s.must(owner).Describe().ImportCmd
		}
		var advice string
		switch {
		case strings.HasSuffix(e.Path, "/tacctl.conf"):
			// A unit drop-in a backend renders (always under this name)
			// holds nothing tacctl.yaml does not: there is nothing to
			// import, and a render replaces it without --force.
			advice = "'tacctl config render' rewrites it from tacctl.yaml (a copy is kept); unit settings of your own belong in another .conf file of that directory"
		case importCmd != "" || owner == "":
			if importCmd == "" {
				importCmd = "tacctl store import --replace"
			}
			advice = "keep the edits: '" + importCmd + "' then 'tacctl config render --force'; discard them: 'tacctl config render --force'"
		default:
			advice = "discard the edits: 'tacctl config render --force' (a copy is kept); there is no way to adopt them into the store"
		}
		reports = append(reports, DriftReport{Path: e.Path, What: what, Advice: advice})
	}
	return reports
}

// Lines are the two lines DriftLines prints for the artifact: the red DRIFT
// line and the advice under it, each ending in a newline.
func (r DriftReport) Lines() []string {
	const indent = "                        "
	return []string{
		"  " + ui.Red + "DRIFT:" + ui.NC + "                " + r.Path + " — " + r.What + "\n",
		indent + r.Advice + "\n",
	}
}

// DriftLines is print_drift_lines: the red DRIFT lines 'status' and
// 'config validate' print, two per drifted artifact of sel (none when
// nothing drifted), each ending in a newline. The hint depends on whose
// artifact it is: only a backend whose Description has an ImportCmd can
// adopt a hand edit.
func (s *Set) DriftLines(sel DriftSelection) []string {
	var lines []string
	for _, r := range s.DriftReports(sel) {
		lines = append(lines, r.Lines()...)
	}
	return lines
}
