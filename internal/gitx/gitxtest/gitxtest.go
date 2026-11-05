// Package gitxtest is what a test of a command that talks to a git remote
// asserts about it: every clone, fetch and pull went through gitx.Net, and
// none was made bare.
package gitxtest

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// netVerbs are the git sub-commands that talk to the remote.
var netVerbs = []string{"clone", "fetch", "pull"}

// Verb is the git sub-command of c, a 'git ...' or the 'env ... git ...' of
// gitx.Net: the first word that is not an option and not the value of -C or
// -c. It is "" for a command that is not git.
func Verb(c execx.Cmd) string {
	args := c.Args
	switch c.Name {
	case "git":
	case "env":
		i := slices.Index(args, "git")
		if i < 0 {
			return ""
		}
		args = args[i+1:]
	default:
		return ""
	}
	for len(args) > 0 {
		switch {
		case args[0] == "-C" || args[0] == "-c":
			if len(args) < 2 {
				return ""
			}
			args = args[2:]
		case strings.HasPrefix(args[0], "-"):
			args = args[1:]
		default:
			return args[0]
		}
	}
	return ""
}

// Lacks is what the guard of gitx.Net is missing from c, as sentences; wantSSH
// is the GIT_SSH_COMMAND it must carry.
func Lacks(c execx.Cmd, wantSSH string) []string {
	var out []string
	if c.Name != "env" {
		return []string{"it is not run through env(1)"}
	}
	for _, w := range []string{"-u", "SSH_ASKPASS", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=false", "GIT_SSH_COMMAND=" + wantSSH} {
		if !slices.Contains(c.Args, w) {
			out = append(out, "no "+w)
		}
	}
	args := " " + strings.Join(c.Args, " ") + " "
	if !strings.Contains(args, " git -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=60 ") {
		out = append(out, "no low-speed limit on git")
	}
	return out
}

// Check fails t for every clone, fetch or pull in raw (the commands as they
// were made: fake.Runner.Raw) that is bare or lacks the guard, and when the
// guarded ones are not wantVerbs, in order. wantSSH is the GIT_SSH_COMMAND
// each must carry.
func Check(t testing.TB, raw []execx.Cmd, wantSSH string, wantVerbs ...string) {
	t.Helper()
	var got []string
	for _, c := range raw {
		verb := Verb(c)
		if !slices.Contains(netVerbs, verb) {
			continue
		}
		got = append(got, verb)
		if c.Name == "git" {
			t.Errorf("%q is not run through the guard against a prompt (gitx.Net)", strings.Join(c.Argv(), " "))
			continue
		}
		if lacks := Lacks(c, wantSSH); len(lacks) != 0 {
			t.Errorf("%q: %s", strings.Join(c.Argv(), " "), strings.Join(lacks, ", "))
		}
	}
	if !slices.Equal(got, wantVerbs) {
		t.Errorf("network git commands %v, want %v", got, wantVerbs)
	}
}
