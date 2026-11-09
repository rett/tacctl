package console

// The console's file transfer, from the console's side: how a session of the
// sftp subsystem is told apart in the log (internal/sftpd serves the
// protocol, internal/cli/console_sftp.go wires it).

// ModeSFTP is the mode of a session that serves the sftp subsystem (the
// 'mode=' of its start line, next to interactive, command and batch).
const ModeSFTP = "sftp"

// ReasonSFTP is the 'reason=' of the end line of a session that served the
// sftp subsystem, or refused it.
const ReasonSFTP = "sftp"

// SFTPDenyLine is the log line of the sftp subsystem refused: why is
// "file-transfer" (it is not enabled for the account), "password-change" (a
// password change is required of the caller first, or it could not be read
// whether one is), "policy" (there is no answer to read, and the caller is no
// superuser who would be held anyway), "home" (the account's home directory
// is not known) or "stream" (the process has no standard input or output).
func (s Session) SFTPDenyLine(why string) string {
	return "console DENY session=" + s.ID + " user=" + LogValue(s.User) + " reason=" + why + " subsystem=sftp"
}

// SFTPStatus is the exit status of a session of the sftp subsystem that
// failed after the protocol started (a protocol error, the stream cut
// mid-packet).
const SFTPStatus = 1
