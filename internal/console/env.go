package console

import "strings"

// ConsolePath is the PATH of the console and of everything it starts.
const ConsolePath = "/usr/local/bin:/usr/bin:/bin"

// keptNames are the login environment's variables the console keeps:
// the terminal, the locale, who and where the user is. LC_* is kept by
// prefix.
var keptNames = map[string]bool{
	"TERM": true, "LANG": true, "HOME": true, "USER": true, "LOGNAME": true,
	"SSH_CONNECTION": true, "SSH_CLIENT": true, "SSH_TTY": true,
}

// Scrub is the console's environment made from the login environment:
// TERM, LANG, LC_*, HOME, USER, LOGNAME, SSH_CONNECTION, SSH_CLIENT and
// SSH_TTY as they come (in their order), then PATH=ConsolePath and
// SHELL=shellPath; everything else (ENV, BASH_ENV, LD_*, SSH_AUTH_SOCK,
// TACCTL_* ...) is dropped. keepTest keeps TACCTL_* and the PATH as they
// come as well: the -tags testknobs knob TACCTL_TEST_CONSOLE_ENV=1 of the
// bats sandbox, whose stubs and paths are there. Scrub of its own result
// is that result.
func Scrub(environ []string, shellPath string, keepTest bool) []string {
	var out []string
	path := ConsolePath
	seen := map[string]int{}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch {
		case k == "PATH":
			if keepTest {
				path = v
			}
			continue
		case k == "SHELL":
			continue
		case keptNames[k], strings.HasPrefix(k, "LC_"), keepTest && strings.HasPrefix(k, "TACCTL_"):
		default:
			continue
		}
		// The last of a name wins, in the place of the first (getenv(3)).
		if i, dup := seen[k]; dup {
			out[i] = kv
			continue
		}
		seen[k] = len(out)
		out = append(out, kv)
	}
	return append(out, "PATH="+path, "SHELL="+shellPath)
}

// ShellEnv is the environment of the system shell: environ without any
// TACCTL_* variable and with SHELL=shellPath.
func ShellEnv(environ []string, shellPath string) []string {
	var out []string
	for _, kv := range environ {
		if strings.HasPrefix(kv, "TACCTL_") || strings.HasPrefix(kv, "SHELL=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "SHELL="+shellPath)
}
