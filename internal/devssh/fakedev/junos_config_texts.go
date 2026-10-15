package fakedev

// Every text the fake Junos configure model prints, in one place so that
// the lab spike (docs/plans/0.2.9-lab.md, the captures in
// tests/fixtures/devconf/juniper/apply/texts.txt) corrects them here. The
// marks are the plan's:
//
//	[S]  a text the plan took from the Junos reference or the helper
//	     script's own use of it
//	[A]  a phrase the helper script observed on a device, assumed to be
//	     whole
//	[L]  not confirmed on a device
//	[C]  captured from a Junos 25.4 virtual chassis (read-only, or the lab
//	     spike of 2026-10-13)
const (
	// The prompts and mode changes.
	jtEnterConfig = "Entering configuration mode" // [C]
	jtExitConfig  = "Exiting configuration mode"  // [C]
	jtMasterFmt   = "{%s}"                        // [C] '{master:0}' before the prompt of a switch
	// jtExclusiveWarning precedes the entering text of 'configure
	// exclusive'.
	jtExclusiveWarning = "warning: uncommitted changes will be discarded on exit" // [C]
	// jtPendingBannerFmt is the line before the location line of every
	// session's prompt while a confirmed commit is pending: the minutes
	// left and 'minute' or 'minutes'.
	jtPendingBannerFmt = "# commit confirmed will be rolled back in %d %s" // [C]

	// The editors and the lock.
	jtUsersEditing = "Users currently editing the configuration:"           // [A]
	jtLocked       = "error: configuration database locked by:"             // [C] 'configure exclusive' under an exclusive lock
	jtModified     = "error: configuration database modified"               // [L] 'configure exclusive' over a staged change
	jtNotCommitted = "The configuration has been changed but not committed" // [A]
	// jtPrivateUnderExcl is 'configure private' while another session
	// holds the exclusive lock (the session enters; the order of the lines
	// is [L]).
	jtPrivateUnderExcl = "warning: changes cannot be committed while 'configure exclusive' is active" // [C]

	// The statements.
	jtStatementNotFound = "warning: statement not found" // [A] a delete of an absent node
	jtSyntaxError       = "syntax error."                // [L]
	jtUnknownCommand    = "unknown command."             // [L]
	jtCaret             = "  ^"                          // [L] the caret line above a syntax error
	jtLoadComplete      = "load complete"                // [C] after rollback N
	jtBadRollback       = "error: invalid rollback number"
	jtNoRollback        = "error: no rollback file for that number" // [L]
	jtScreenLength      = "Screen length set to %d"                 // [L]
	jtScreenWidth       = "Screen width set to %d"                  // [L]

	// The commit family. Every commit prints the check's line first.
	jtCheckOK            = "configuration check succeeds"                                                      // [C]
	jtCheckFailed        = "error: configuration check-out failed"                                             // [L]
	jtCommitComplete     = "commit complete"                                                                   // [C]
	jtConfirmedFmt       = "commit confirmed will be automatically rolled back in %d minutes unless confirmed" // [C] '1 minutes' for 1
	jtNoConfirmedPrivate = "error: commit confirmed not supported for private configuration"                   // [C]
	jtBadConfirmed       = "error: commit confirmed takes a number of minutes from 1 to 65535"                 // [L]

	// The csh of a root login.
	jtCshNotFoundFmt = "%s: Command not found." // [L]
	jtCshPromptFmt   = "root@%s%% "             // [L] the csh prompt; '%%' is the prompt character

	// The show commands.
	jtLastCommitFmt = "## Last commit: %s by %s"                  // [L] first line of 'show configuration'
	jtEditingLine   = "  %s terminal pts/%d (pid %d) on since %s" // [C]
	jtEditingExcl   = "      exclusive %s[edit]"                  // [C] with the '{master:0}' of a switch
	jtEditingShared = "      %s[edit]"                            // [L]
	jtEditingPriv   = "      private %s[edit]"                    // [L]

	// The expiry of a confirmed commit is a commit of the device's own.
	jtExpiryUser = "root"    // [C] (capture of 2026-10-09)
	jtExpiryVia  = "other"   // [C] (capture of 2026-10-09)
	jtCommitVia  = "cli"     // [C]
	jtNetconfVia = "netconf" // [L] the way of a commit made over NETCONF

	// The layout of a commit's time in 'show system commit' [C]; the zone
	// is the fake's own clock's (UTC), the capture's was a local one.
	jtTimeLayout = "2006-01-02 15:04:05 MST"
	// jtRollbackInFmt ends the line of a confirmed commit's entry [C]. It
	// stays for good, also after a 'commit check' confirmed the commit: it
	// is a label, not a pending marker (the banner is).
	jtRollbackInFmt = "commit confirmed, rollback in %dmins"
	// jtRescueFmt is the line 'show system commit' ends with when a rescue
	// configuration is saved: the time, the user and the way [C]. It is no
	// entry and has no number.
	jtRescueFmt = "rescue  %s by %s via %s"
)

// The classes of a login and what they may do: a class name maps to the
// permission lines 'show cli authorization' prints and to whether it may
// enter configuration mode. A class that is not here may configure and
// prints no permission lines.
var jtClasses = map[string]struct {
	perms     []string
	configure bool
}{
	"super-user":   {[]string{"all"}, true},
	"read-only":    {[]string{"view", "view-configuration"}, false},
	"operator":     {[]string{"clear", "network", "reset", "trace", "view"}, false},
	"unauthorized": {nil, false},
}
