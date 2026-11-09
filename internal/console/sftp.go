package console

// The console's file transfer, from the console's side: how a session of the
// sftp subsystem is told apart in the log (internal/sftpd serves the
// protocol, internal/cli/console_sftp.go wires it).

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

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

// NameMax is the most bytes of the escaped text of a file name (a path) that
// one field of a log line carries. logger cuts a line at 1 KiB by default, so
// the fields after the longest ones (reason=, error=) would be lost if the
// escapes were not counted.
const NameMax = 200

// QuoteName is a path a client sent, made safe for one field of a log line.
// The audit never logs a typed word that is not a verb, because it could be a
// password; a path is a file name and is logged, but as a Go string literal
// in double quotes: a control character (a newline, an escape sequence), a
// quote, a backslash, a byte that is not UTF-8 and a character that does not
// print (a bidirectional override) become escapes, so that no name can end
// the field or the line, forge a field or move a terminal that reads the
// log. At most NameMax bytes of the escaped text are kept, never a part of an
// escape sequence or of a character; a name that was cut ends with '...'
// after the closing quote.
func QuoteName(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	kept := 0
	cut := false
	for i := 0; i < len(s); {
		_, n := utf8.DecodeRuneInString(s[i:])
		q := strconv.Quote(s[i : i+n])
		piece := q[1 : len(q)-1]
		if kept+len(piece) > NameMax {
			cut = true
			break
		}
		b.WriteString(piece)
		kept += len(piece)
		i += n
	}
	b.WriteByte('"')
	if cut {
		b.WriteString("...")
	}
	return b.String()
}

// SFTPStartLine is the log line of a file transfer opened: the tier of the
// caller, the home directory that is "/" for the client, and the quota and
// the rate in effect (the words of 'console file-transfer': 256M, unlimited,
// off).
func (s Session) SFTPStartLine(tier, home string, quota, rate int64) string {
	return "console sftp start session=" + s.ID + " user=" + LogValue(s.User) + " tier=" + LogValue(tier) +
		" from=" + LogValue(s.From) + " home=" + QuoteName(home) + " quota=" + QuotaWord(quota) + " rate=" + RateWord(rate)
}

// SFTPEndLine is the log line of a file transfer closed: the bytes uploaded
// and downloaded, the requests audited (ops) and those of them that were
// refused.
func (s Session) SFTPEndLine(up, down int64, ops, refused int) string {
	return "console sftp end session=" + s.ID + " user=" + LogValue(s.User) + " up=" + strconv.FormatInt(up, 10) +
		" down=" + strconv.FormatInt(down, 10) + " ops=" + strconv.Itoa(ops) + " refused=" + strconv.Itoa(refused)
}

// SFTPEventLine is the log line, and its syslog priority, of one thing a
// client did (sftpd.Event): op is upload, download, delete, rename, mkdir,
// setstat or refused. A request the server refused (.ssh, outside the home, a
// symbolic link, the quota, an unsupported request, a bad path) is
// 'console sftp DENY ... reason=<why>' at auth.warning, like a refused command;
// the rest are info lines with the path (and the new name of a rename), the
// bytes moved by an upload or a download, and the error text of one that
// failed. errText is sanitised like a path; with a path, a new name and an
// error text each at NameMax, the line stays under 1000 bytes (logger cuts a
// line at 1 KiB).
func (s Session) SFTPEventLine(op, path, to string, bytes int64, errText string) (priority, line string) {
	head := "console sftp " + op
	priority = "auth.info"
	if op == "refused" {
		head = "console sftp DENY"
		priority = "auth.warning"
	}
	line = head + " session=" + s.ID + " user=" + LogValue(s.User) + " path=" + QuoteName(path)
	if to != "" {
		line += " to=" + QuoteName(to)
	}
	switch op {
	case "upload", "download":
		line += " bytes=" + strconv.FormatInt(bytes, 10)
	}
	switch {
	case op == "refused":
		line += " reason=" + LogValue(strings.ReplaceAll(errText, " ", "-"))
	case errText != "":
		line += " error=" + QuoteName(errText)
	}
	return priority, line
}
