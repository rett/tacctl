package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// asUser runs 'tacctl args' as a caller who is not root: the sudo re-exec is
// where it ends unless the line is answered before.
func asUser(args []string) (code int, stderr string, r *fake.Runner) {
	var out, errb bytes.Buffer
	r = &fake.Runner{}
	a := app.New(args, paths.NewEnv([]string{"PATH=/usr/bin"}), "/usr/local/bin/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}, r)
	code = exitCode(runWith(context.Background(), a, BuildInfo{Version: "t"}, newTestHooks()), a.Out)
	return code, stripSGR(errb.String()), r
}

// A word below the first that is none of the sub-commands of its command is
// answered before sudo runs (0.2.22), as an unknown first word is: the same
// short text, exit 1, no process started and so no password asked for. The
// command tree is walked with the fixed words typed; a name, a flag and its
// value, and a verb of another family are never taken for it.
func TestUnknownSubcommandBeforeSudo(t *testing.T) {
	parallel(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		// the second, the third and the fourth word
		{[]string{"device", "lisst"}, "[ERROR] Unknown subcommand: 'lisst'\nDid you mean: tacctl device list?\nRun 'tacctl device -h' for usage.\n"},
		{[]string{"device", "config", "seed", "jr1"}, "[ERROR] Unknown subcommand: 'seed'\nDid you mean: tacctl device config shapes seed?\nRun 'tacctl device config -h' for usage.\n"},
		{[]string{"config", "sudoers", "tiers", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl config sudoers tiers -h' for usage.\n"},
		// the families that printed their usage with no error line
		{[]string{"user", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl user -h' for usage.\n"},
		{[]string{"log", "bogus", "tail"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl log -h' for usage.\n"},
		// a verb of another family
		{[]string{"scope", "enroll", "sw1"}, "[ERROR] Unknown subcommand: 'enroll'\nRun 'tacctl scope -h' for usage.\n"},
	} {
		code, got, r := asUser(c.args)
		if code != 1 || got != c.want || len(r.Calls()) != 0 || len(r.Execs()) != 0 {
			t.Errorf("%q: exit %d stderr %q calls %v execs %v, want %q", c.args, code, got, r.Calls(), r.Execs(), c.want)
		}
	}
}

// What is not a fixed word of the tree is left to sudo, which asks and the
// command then answers: a name (a device, a host, a user: root-only data, never
// looked at), a name that looks like a verb, the value of a flag that looks
// like a verb, a flag before the verb, the words after a command that has
// no sub-commands, 'help', the verbs of a family and a verb that exists but
// that the caller's tier cannot run (the gate answers it, as before).
func TestSubcommandCheckLeavesTheRestToSudo(t *testing.T) {
	parallel(t)
	for _, args := range [][]string{
		{"device", "show", "sw1"},
		{"device", "show", "list"},
		{"device", "show", "shapes"},
		{"device", "config", "list", "--scope", "show"},
		{"device", "config", "plan", "enroll", "--plain"},
		{"device", "config", "shapes", "seed", "jr1", "-y"},
		{"device", "config", "forget", "sw1"},
		{"device", "help"},
		{"device", "--bogus"},
		{"log", "--backend", "tacacs", "tail"},
		{"log", "tail", "--backend", "seed"},
		{"host", "provisioner", "web1", "rotate", "alice", "--password"},
		{"scope", "secret", "lab", "bogus"},
		{"user", "scope", "alice", "bogus"},
		{"user", "show", "bogus"},
		{"config", "get", "bogus"},
		{"group", "commands", "list", "operator"},
		{"config", "sudoers", "tiers", "show"},
	} {
		code, got, r := asUser(args)
		ex := r.Execs()
		if code != 0 || got != "" || len(ex) != 1 || ex[0].Argv[0] != "sudo" {
			t.Errorf("%q: exit %d stderr %q execs %+v, want the sudo re-exec", args, code, got, ex)
		}
	}
}

// The unknown word is walked over the fixed words only: the walk reads no
// state and starts nothing (the answer is the same where tacctl is not
// installed), so a command that sudo would refuse for the caller's tier is
// not looked at.
func TestUnknownBelowWalk(t *testing.T) {
	root := newRoot(&invocation{})
	for _, c := range []struct {
		words []string
		path  []string
		sub   string
		ok    bool
	}{
		{[]string{"device", "config", "seed", "jr1"}, []string{"device", "config"}, "seed", true},
		{[]string{"device", "bogus"}, []string{"device"}, "bogus", true},
		{[]string{"device"}, nil, "", false},
		{[]string{"bogus", "list"}, nil, "", false}, // the first word is notACommand's
		{[]string{"device", "list", "bogus"}, nil, "", false},
		{[]string{"device", "--x", "bogus"}, nil, "", false},
		{[]string{"device", "-h"}, nil, "", false},
		{[]string{"device", "help"}, nil, "", false},
		{[]string{"device", ""}, nil, "", false},
		{[]string{"hash", "bogus"}, nil, "", false}, // runs as the user
		{[]string{"completion", "bogus"}, nil, "", false},
		{[]string{"_phase", "bogus"}, nil, "", false}, // hidden
		{[]string{"device", "_x"}, []string{"device"}, "_x", true},
	} {
		path, sub, ok := unknownBelow(root, c.words)
		if ok != c.ok || sub != c.sub || strings.Join(path, " ") != strings.Join(c.path, " ") {
			t.Errorf("%q: %q %q %v, want %q %q %v", c.words, path, sub, ok, c.path, c.sub, c.ok)
		}
	}
}

// The shell and the console run the same check before the line goes to
// sudo, with the tier's view for the hint, and start no process.
func TestUnknownSubcommandInTheShell(t *testing.T) {
	for _, c := range []struct {
		tier  tier.Tier
		words []string
		want  string
	}{
		{tier.Operator, []string{"device", "config", "seed", "jr1"}, "[ERROR] Unknown subcommand: 'seed'\nRun 'tacctl device config -h' for usage.\n"},
		{tier.Superuser, []string{"device", "config", "seed", "jr1"}, "[ERROR] Unknown subcommand: 'seed'\nDid you mean: tacctl device config shapes seed?\nRun 'tacctl device config -h' for usage.\n"},
		{tier.Readonly, []string{"device", "lisst"}, "[ERROR] Unknown subcommand: 'lisst'\nDid you mean: tacctl device list?\nRun 'tacctl device -h' for usage.\n"},
	} {
		for _, console := range []bool{false, true} {
			h := newHarness(t, nil)
			inv := &invocation{ctx: context.Background(), app: h.app, hooks: newTestHooks(), shellConsole: console}
			tr := c.tier
			inv.view = func() tier.Tier { return tr }
			exec := inv.shellExec(newRoot(inv), testExe, true, c.tier, nil)
			code := exec(context.Background(), c.words, nil)
			if got := stripSGR(h.err.String()); code != 1 || got != c.want || h.out.Len() != 0 || len(h.runner.Calls()) != 0 || len(h.runner.Execs()) != 0 {
				t.Errorf("%s console=%v %q: exit %d stderr %q calls %v, want %q", c.tier, console, c.words, code, got, h.runner.Calls(), c.want)
			}
		}
	}
	// a line with only fixed words of the tree goes to sudo as before
	h := newHarness(t, nil)
	inv := &invocation{ctx: context.Background(), app: h.app, hooks: newTestHooks()}
	exec := inv.shellExec(newRoot(inv), testExe, true, tier.Operator, nil)
	exec(context.Background(), []string{"device", "show", "list"}, nil)
	if len(h.runner.Calls())+len(h.runner.Execs()) == 0 {
		t.Error("device show list was not run")
	}
	if got := stripSGR(h.err.String()); strings.Contains(got, "Unknown subcommand") {
		t.Errorf("device show list: %q", got)
	}
}

// No command of the tree is taken for unknown, whatever follows it: every
// path is a command (the walk gives nothing for the path itself, and nothing
// for a name or a flag after a command without sub-commands), and only the
// word after a command with sub-commands can be refused.
func TestUnknownBelowNeverRefusesACommand(t *testing.T) {
	root := newRoot(&invocation{})
	var all [][]string
	commandPaths(root, nil, &all)
	if len(all) < 100 {
		t.Fatalf("tree has %d commands", len(all))
	}
	for _, p := range all {
		cmd, _ := resolve(root, p)
		if _, sub, ok := unknownBelow(root, p); ok {
			t.Errorf("%q is refused at %q", p, sub)
		}
		if len(cmd.Commands()) > 0 {
			continue
		}
		for _, extra := range [][]string{{"sw1"}, {"list"}, {"--scope", "show"}, {"seed", "x", "-y"}} {
			if _, sub, ok := unknownBelow(root, append(append([]string(nil), p...), extra...)); ok {
				t.Errorf("%q %q: refused at %q", p, extra, sub)
			}
		}
	}
}
