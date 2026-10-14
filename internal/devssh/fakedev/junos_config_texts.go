package fakedev

// Every text the fake Junos configure model prints, in one place so that
// the lab spike (docs/plans/0.2.9-apply-plan.md section 9, WP14.0) can
// correct them. The marks are the plan's:
//
//	[S]  a text the plan took from the Junos reference or the helper
//	     script's own use of it
//	[A]  a phrase the helper script observed on a device, assumed to be
//	     whole
//	[L]  not confirmed on a device: the lab spike settles it
//	[C]  captured read-only from a Junos 25.4 virtual chassis
const (
	// The prompts and mode changes.
	jtEnterConfig = "Entering configuration mode" // [C]
	jtExitConfig  = "Exiting configuration mode"  // [C]
	jtMasterFmt   = "{%s}"                        // [C] '{master:0}' before the prompt of a switch

	// The editors and the lock.
	jtUsersEditing = "Users currently editing the configuration:"           // [A]
	jtLocked       = "error: configuration database locked by:"             // [L] both for 'configure' and 'configure exclusive' under an exclusive lock
	jtModified     = "error: configuration database modified"               // [L] 'configure exclusive' over a staged change
	jtNotCommitted = "The configuration has been changed but not committed" // [A]

	// The statements.
	jtStatementNotFound = "warning: statement not found" // [A] a delete of an absent node
	jtSyntaxError       = "syntax error."                // [L]
	jtUnknownCommand    = "unknown command."             // [L]
	jtCaret             = "  ^"                          // [L] the caret line above a syntax error
	jtLoadComplete      = "load complete"                // [L] after rollback N
	jtBadRollback       = "error: invalid rollback number"
	jtNoRollback        = "error: no rollback file for that number" // [L]
	jtScreenLength      = "Screen length set to %d"                 // [L]
	jtScreenWidth       = "Screen width set to %d"                  // [L]

	// The commit family.
	jtCheckOK            = "configuration check succeeds"                                      // [S]
	jtCheckFailed        = "error: configuration check-out failed"                             // [L]
	jtCommitComplete     = "commit complete"                                                   // [S]
	jtConfirmedFmt       = "commit confirmed will be rolled back in %d minutes"                // [S]
	jtNoConfirmedPrivate = "error: commit confirmed not supported for private configuration"   // [A] (the helper's phrase is the prefix)
	jtBadConfirmed       = "error: commit confirmed takes a number of minutes from 1 to 65535" // [L]

	// The csh of a root login.
	jtCshNotFoundFmt = "%s: Command not found." // [L]
	jtCshPromptFmt   = "root@%s%% "             // [L] the csh prompt; '%%' is the prompt character

	// The show commands.
	jtLastCommitFmt = "## Last commit: %s by %s"                              // [L] first line of 'show configuration'
	jtEditingLine   = "  %s terminal p%d (pid %d) on since %s, idle 00:00:00" // [L]
	jtEditingExcl   = "      exclusive [edit]"                                // [L]
	jtEditingShared = "      [edit]"                                          // [L]
	jtEditingPriv   = "      [edit private]"                                  // [L]

	// The expiry of a confirmed commit is a commit of the device's own.
	jtExpiryUser = "root"  // [L]
	jtExpiryVia  = "other" // [L]
	jtCommitVia  = "cli"   // [C]

	// The layout of a commit's time in 'show system commit' [C]; the zone
	// is the fake's own clock's (UTC), the capture's was a local one.
	jtTimeLayout = "2006-01-02 15:04:05 MST"
	// jtRollbackInFmt ends the line of a confirmed commit's entry [C].
	jtRollbackInFmt = "commit confirmed, rollback in %dmins"
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
