package lifecycle

// The limits of the stored reports a user has of their own (0.2.26,
// users.<name>.reports_max_size and reports_max_count in store.yaml) in a
// rollback. Every release before 0.2.26 refuses the keys ("user '<name>':
// unknown field 'reports_max_size'" on every store command, and 'backup
// restore' refuses a snapshot that has them), so every target removes them
// from the store (store.RollbackReportLimits), after the snapshot --apply
// takes first, and the target converts a file for it. The server's two
// settings in tacctl.yaml are keys of the same kind (conf.Added0226): they go
// with the key lists, and need no answer.
//
// Unlike the settings, an override is data somebody chose for one user, so the
// plan names each user with the value (a size is no secret), --apply needs
// --yes while any user has one, and the snapshot holds them: 0.2.26's
// 'tacctl user reports-limit' sets them again from the list.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/store"
)

// reportLimitsRelease is the release that made the change (its entry in
// rollbackAdditions).
const reportLimitsRelease = "0.2.26"

// planReportLimits reads the store for the users that have a limit. An
// install without a store has none; a store that cannot be read is an error (a
// limit that cannot be seen must not be hidden).
func (p *RollbackPlan) planReportLimits() error {
	if !p.in.HasStore {
		return nil
	}
	pa := p.in.Paths
	holders, err := store.ReportLimitHolders(pa.StoreFile)
	if err != nil {
		return &RollbackRefusal{Lines: []string{
			pa.StoreFile + " cannot be read, so a limit of the stored reports cannot be ruled out (" + strings.TrimSuffix(err.Error(), ".") + "); fix it first (tacctl config validate)."}}
	}
	p.limitUsers = holders
	return nil
}

// ReportLimitUsers are the users whose own limits the rollback removes, by
// name, each with the text of what it drops ("alice: max-size 20 MiB,
// max-count 50 reports").
func (p *RollbackPlan) ReportLimitUsers() []string {
	out := make([]string, 0, len(p.limitUsers))
	for _, h := range p.limitUsers {
		out = append(out, h.User+": "+describeReportLimits(h))
	}
	return out
}

// ReportLimitUserNames are the users alone.
func (p *RollbackPlan) ReportLimitUserNames() []string {
	out := make([]string, 0, len(p.limitUsers))
	for _, h := range p.limitUsers {
		out = append(out, h.User)
	}
	return out
}

// describeReportLimits says a user's limits in a few words.
func describeReportLimits(h store.ReportLimitHolder) string {
	var w []string
	if h.Size != "" {
		text := h.Size
		if n, err := strconv.ParseInt(h.Size, 10, 64); err == nil {
			text = names.FormatReportSize(n)
		}
		w = append(w, "max-size "+text)
	}
	if h.Count != "" {
		text := h.Count
		if n, err := strconv.Atoi(h.Count); err == nil {
			text = names.FormatReportCount(n)
		}
		w = append(w, "max-count "+text)
	}
	return strings.Join(w, ", ")
}

// addReportLimits adds the step and the warning to the plan of any target
// older than 0.2.26.
func (p *RollbackPlan) addReportLimits() {
	if len(p.limitUsers) == 0 {
		return
	}
	target, sf := p.target(), p.in.Paths.StoreFile
	s := RollbackStep{Title: sf + ": remove the limits of the stored reports " + target + " does not know", Todo: true}
	for _, h := range p.limitUsers {
		s.Lines = append(s.Lines, "remove the report limits of "+h.User+" ("+describeReportLimits(h)+")")
	}
	s.Lines = append(s.Lines, "("+target+"'s schema refuses the keys (\"unknown field 'reports_max_size'\"); every other field of the store stays)")
	p.insertStoreStep(s)

	var each []string
	for _, h := range p.limitUsers {
		each = append(each, h.User+" ("+describeReportLimits(h)+")")
	}
	n := len(p.limitUsers)
	p.Warnings = append(p.Warnings, RollbackWarning{
		Title: "Limits of the stored reports are removed from the store",
		Lines: []string{
			target + " has no limit of the stored reports (" + reportLimitsRelease + "): " + strings.Join(each, ", ") + " " + plural(n, "has", "have") + " an own limit, removed from the store (" + target + "'s schema refuses the keys).",
			"The values stay in the snapshot --apply takes first (tacctl backup list). Once " + reportLimitsRelease + " is installed again, 'tacctl user reports-limit <user> max-size|max-count <value>' sets them again from the list above.",
		}})
}

// insertStoreStep puts a step that converts the store where the store's
// 'leave untouched' line was (the 0.2.3 plan has a step of its own for it, the
// others name the file in the line of the files left), or after the step of
// the store that is there already, or last.
func (p *RollbackPlan) insertStoreStep(s RollbackStep) {
	sf := p.in.Paths.StoreFile
	at := len(p.Steps)
	for i := range p.Steps {
		switch {
		case p.Steps[i].Title == "leave "+sf+" untouched":
			p.Steps = slices.Delete(p.Steps, i, i+1)
			at = i
		case p.Steps[i].Title == "leave every other file untouched":
			at = i
			if len(p.Steps[i].Lines) > 0 {
				p.Steps[i].Lines[0] = strings.Replace(p.Steps[i].Lines[0], sf+", ", "", 1)
			}
		case strings.HasPrefix(p.Steps[i].Title, sf+": remove "):
			at = i + 1
			continue
		default:
			continue
		}
		break
	}
	p.Steps = slices.Insert(p.Steps, at, s)
}

// applyReportLimits removes the keys and returns the line that says so ("" when
// there was nothing).
func (p *RollbackPlan) applyReportLimits() (string, error) {
	if len(p.limitUsers) == 0 {
		return "", nil
	}
	removed, _, err := store.RollbackReportLimits(p.in.Paths.StoreFile, nil)
	if err != nil || len(removed) == 0 {
		return "", err
	}
	return p.in.Paths.StoreFile + ": removed the report limits of " + strconv.Itoa(len(removed)) + " " + plural(len(removed), "user", "users"), nil
}
