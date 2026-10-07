package backend

// UpgradeSummary is what a backend's upgrade phases of one invocation leave
// for the closing summary of 'tacctl upgrade' (UPGRADE_SUMMARY_HEAD,
// UPGRADE_SUMMARY_NOTES and its share of SCRIPTS_UPDATED in 0.1.16).
type UpgradeSummary struct {
	// Head is the headline ("" when the backend has none; 0.1.16 prints
	// "Upgrade Complete" when no backend set one).
	Head string
	// Notes are the lines its 'finish' phase added, in order.
	Notes []string
	// FilesUpdated is what its 'files' phase counted as replaced.
	FilesUpdated int
	// UpToDate is the headline to show instead of Head when the whole
	// upgrade updated no file ("" when the backend itself changed
	// something: a binary, a unit, its config).
	UpToDate string
}

// Summarizer is a backend that leaves something for the closing summaries
// of 'tacctl upgrade' and 'tacctl uninstall'. Run every phase of a command
// on the same Backend (Set.Get makes each once per invocation): the
// summaries are what those phases left on it.
type Summarizer interface {
	// UpgradeSummary is what the upgrade phases left.
	UpgradeSummary() UpgradeSummary
	// UninstallSaved are the lines the uninstall 'data' phase added to the
	// "Removed:" list (UNINSTALL_SAVED): where it saved what it was asked
	// to keep.
	UninstallSaved() []string
}
