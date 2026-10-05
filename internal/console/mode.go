package console

// Console mode (docs/plans/operator-console-wp-console.md 5.2): the tacctl
// binary started as 'tacctl-console' (the symlink paths.ConsoleCommand) is
// a login shell. sshd starts it as '-tacctl-console' for a login and as
// 'tacctl-console -c <command>' for a remote command, scp, sftp and rsync
// (with the console's sshd drop-in, ForceCommand, always as the latter:
// Forced); the -c guard lets one tacctl line through and refuses
// everything else.

import (
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/shell"
)

// Name is the console's program name (the base name of
// paths.ConsoleCommand).
const Name = "tacctl-console"

// The console's refusals, each with exit status RefusedStatus.
const (
	// RefusedText is the answer to a -c string that is not one tacctl line
	// (scp, sftp, rsync, a program, a shell word).
	RefusedText = "the tacctl console does not run programs; file transfer is not available"
	// NoOptionsText is the answer to any arguments but '-c <line>'.
	NoOptionsText = "the tacctl console takes no options"
	// RefusedStatus is the exit status of a refusal (the shell's "cannot
	// execute").
	RefusedStatus = 126
)

// IsConsole reports whether argv0 names the console: its base name, with
// the login shell's leading '-' taken off, is tacctl-console.
func IsConsole(argv0 string) bool {
	return strings.TrimPrefix(filepath.Base(argv0), "-") == Name
}

// Guard decides a -c string (design decision 25): it must be one line
// that tokenizes (shell.Tokenize) to words whose first is a tacctl command
// (isCommand) or help. The shell's own words (history, exit, quit,
// system-shell), an empty string and anything else are refused. first is
// the first word (for the log; "" when there is none).
func Guard(line string, isCommand func(string) bool) (first string, ok bool) {
	if len(line) > shell.LineMax || strings.ContainsAny(line, "\n\r\x00") {
		return firstWord(line), false
	}
	words, err := shell.Tokenize(line)
	if err != nil || len(words) == 0 {
		return firstWord(line), false
	}
	first = words[0]
	switch first {
	case "help":
		return first, true
	case "history", "exit", "quit", SystemShellWord, "":
		return first, false
	}
	return first, isCommand != nil && isCommand(first)
}

// OriginalCommand is the variable in which sshd hands a ForceCommand the
// command the client asked for.
const OriginalCommand = "SSH_ORIGINAL_COMMAND"

// Forced resolves sshd's ForceCommand. sshd's drop-in for tac-console
// forces the console (ForceCommand <command>), so sshd starts every login
// of a console user, with or without a command, and every subsystem
// (sftp, internal-sftp) as '<shell> -c <command>', the client's own command
// in SSH_ORIGINAL_COMMAND. Forced turns such an argv into what the console
// would have got without the drop-in: argv0 alone (a login: interactive or
// a batch) when environ has no SSH_ORIGINAL_COMMAND, else argv0 -c <that
// command>, which the -c guard then decides. Any other argv is returned as
// it is.
func Forced(argv, environ []string, command string) []string {
	if len(argv) != 3 || argv[1] != "-c" || (argv[2] != command && !IsConsole(argv[2])) {
		return argv
	}
	orig, ok := "", false
	for _, kv := range environ {
		if v, found := strings.CutPrefix(kv, OriginalCommand+"="); found {
			orig, ok = v, true
		}
	}
	if !ok {
		return argv[:1]
	}
	return []string{argv[0], "-c", orig}
}

// SystemShellWord is the console's word that starts the system shell.
const SystemShellWord = shell.SystemShellWord

// firstWord is the first blank-separated field of s (a refused line that
// does not tokenize still names something in the log).
func firstWord(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
