package cli

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/tier"
)

// short is the stderr of an unknown sub-command without the warnings the
// sandbox's missing configuration adds.
func (sb *sandbox) shortErr() string {
	var keep []string
	for _, l := range strings.Split(plain(sb.err.String()), "\n") {
		if l != "" && !strings.HasPrefix(l, "[WARN]") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n") + "\n"
}

// An unknown word below the first is one error line, the closest verbs of
// that level, and one line that points at the help of the command: not the
// usage page. Exit 1, nothing on stdout.
func TestUnknownSubcommandIsShort(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		// a verb of a command below the level typed
		{[]string{"device", "config", "seed", "jr1"},
			"[ERROR] Unknown subcommand: 'seed'\nDid you mean: tacctl device config shapes seed?\nRun 'tacctl device config -h' for usage.\n"},
		{[]string{"scope", "lst"},
			"[ERROR] Unknown subcommand: 'lst'\nDid you mean: tacctl scope list?\nRun 'tacctl scope -h' for usage.\n"},
		{[]string{"group", "commands", "sed", "x"},
			"[ERROR] Unknown subcommand: 'sed'\nDid you mean: tacctl group commands seed?\nRun 'tacctl group commands -h' for usage.\n"},
		{[]string{"device", "lisst"},
			"[ERROR] Unknown subcommand: 'lisst'\nDid you mean: tacctl device list?\nRun 'tacctl device -h' for usage.\n"},
		// no verb is near: no hint
		{[]string{"host", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl host -h' for usage.\n"},
		{[]string{"console", "frobnicate"}, "[ERROR] Unknown subcommand: 'frobnicate'\nRun 'tacctl console -h' for usage.\n"},
		{[]string{"breakglass", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl breakglass -h' for usage.\n"},
		{[]string{"server", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl server -h' for usage.\n"},
		{[]string{"emergency", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl emergency -h' for usage.\n"},
		{[]string{"hash", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl hash -h' for usage.\n"},
		{[]string{"config", "snmp", "frob"}, "[ERROR] Unknown subcommand: 'frob'\nRun 'tacctl config snmp -h' for usage.\n"},
		{[]string{"config", "devices", "frob"}, "[ERROR] Unknown subcommand: 'frob'\nRun 'tacctl config devices -h' for usage.\n"},
		{[]string{"config", "metrics", "frob"}, "[ERROR] Unknown subcommand: 'frob'\nRun 'tacctl config metrics -h' for usage.\n"},
		{[]string{"config", "mgmt-acl", "frob"}, "[ERROR] Unknown subcommand: 'frob'\nRun 'tacctl config mgmt-acl -h' for usage.\n"},
		// a verb that takes a name first: the name is not a verb
		{[]string{"scope", "secret", "lab", "shwo"},
			"[ERROR] Unknown subcommand: 'shwo'\nDid you mean: show?\nRun 'tacctl scope secret -h' for usage.\n"},
		{[]string{"scope", "vendor-attrs", "lab", "bogus"},
			"[ERROR] Unknown subcommand: 'bogus'. The verbs are enable and disable: nothing is sent until a vendor is enabled.\nRun 'tacctl scope vendor-attrs -h' for usage.\n"},
		{[]string{"scope", "prefixes", "lab", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl scope prefixes -h' for usage.\n"},
		{[]string{"user", "scope", "alice", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl user scope -h' for usage.\n"},
		// the families that printed their usage with no error line
		{[]string{"user", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl user -h' for usage.\n"},
		{[]string{"group", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl group -h' for usage.\n"},
		{[]string{"backend", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl backend -h' for usage.\n"},
		{[]string{"backup", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl backup -h' for usage.\n"},
		{[]string{"log", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl log -h' for usage.\n"},
		{[]string{"store", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl store -h' for usage.\n"},
		{[]string{"config", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl config -h' for usage.\n"},
		{[]string{"config", "allow", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl config allow -h' for usage.\n"},
		{[]string{"config", "linux", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl config linux -h' for usage.\n"},
		{[]string{"config", "sudoers", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl config sudoers -h' for usage.\n"},
		{[]string{"config", "sudoers", "tiers", "bogus"}, "[ERROR] Unknown subcommand: 'bogus'\nRun 'tacctl config sudoers tiers -h' for usage.\n"},
	} {
		sb := newSandbox(t, true)
		out := sb.run("", c.args)
		if got := sb.shortErr(); sb.code != 1 || got != c.want || out != "" {
			t.Errorf("%q: exit %d stdout %q stderr %q, want %q", c.args, sb.code, out, got, c.want)
		}
	}
}

// 'help', -h, --help and no word at all are still the usage of the command:
// only a word that is none of its sub-commands is the error.
func TestUnknownSubcommandKeepsHelp(t *testing.T) {
	for _, args := range [][]string{{"device", "config", "-h"}, {"scope", "help"}, {"server", "--help"}, {"hash"}, {"console"}} {
		sb := newSandbox(t, true)
		out := sb.run("", args)
		if strings.Contains(sb.shortErr(), "Unknown subcommand") || out == "" {
			t.Errorf("%q: exit %d stdout %q stderr %q", args, sb.code, out, sb.err.String())
		}
	}
}

// Every command with sub-commands answers a word that is none of them with
// the short form (the pre-sudo check of the same word relies on it, see
// TestUnknownSubcommandBeforeSudo).
func TestEveryNodeAnswersAnUnknownWord(t *testing.T) {
	h := newHarness(t, nil)
	root := newRoot(&invocation{app: h.app, hooks: newTestHooks()})
	var nodes [][]string
	var walk func(c *cobra.Command, p []string)
	walk = func(c *cobra.Command, p []string) {
		if len(p) > 0 && len(c.Commands()) > 0 && !c.Hidden {
			nodes = append(nodes, p)
		}
		for _, s := range c.Commands() {
			walk(s, append(append([]string(nil), p...), s.Name()))
		}
	}
	walk(root, nil)
	if len(nodes) < 20 {
		t.Fatalf("only %d nodes with sub-commands", len(nodes))
	}
	for _, p := range nodes {
		sb := newSandbox(t, true)
		out := sb.run("", append(append([]string(nil), p...), "zzbogus"))
		want := "[ERROR] Unknown subcommand: 'zzbogus'\nRun 'tacctl " + strings.Join(p, " ") + " -h' for usage.\n"
		if got := sb.shortErr(); sb.code != 1 || got != want || out != "" {
			t.Errorf("%q: exit %d stdout %q stderr %q, want %q", p, sb.code, out, got, want)
		}
	}
}

// The hint names the commands the caller's tier can run, where the tier is
// known (the shell and the console; a command under sudo has the tier the
// gate held the caller to): a verb a lower tier cannot run is not named.
func TestUnknownSubHintFollowsTheTier(t *testing.T) {
	for _, c := range []struct {
		tier tier.Tier
		want string
	}{
		{tier.Superuser, "Did you mean: tacctl device config shapes seed?\n"},
		{tier.Engineer, ""}, // shapes is the superuser's
		{tier.Operator, ""},
		{tier.Readonly, ""},
	} {
		h := newHarness(t, []string{"device", "config", "seed"})
		inv := &invocation{ctx: context.Background(), app: h.app, hooks: newTestHooks()}
		tr := c.tier
		inv.view = func() tier.Tier { return tr }
		root := newRoot(inv)
		err := inv.unknownSubAt(root, []string{"device", "config"}, "seed", nil)
		want := "[ERROR] Unknown subcommand: 'seed'\n" + c.want + "Run 'tacctl device config -h' for usage.\n"
		if got := stripSGR(h.err.String()); got != want || exitCode(err, h.app.Out) != 1 || h.out.Len() != 0 {
			t.Errorf("%s: %q, want %q (out %q)", c.tier, got, want, h.out.String())
		}
	}
	// a command run under sudo: the tier the gate held the caller to
	h := newHarness(t, []string{"device", "config", "seed"})
	inv := &invocation{ctx: context.Background(), app: h.app, hooks: newTestHooks(), callerTier: tier.Readonly}
	_ = inv.unknownSubAt(newRoot(inv), []string{"device", "config"}, "seed", nil)
	if got := stripSGR(h.err.String()); strings.Contains(got, "Did you mean") {
		t.Errorf("readonly under sudo: %q", got)
	}
}

// The hint: a verb further down the command is answered with the commands
// that have it, else the sub-commands within two letters; a word that starts
// with '-' or is empty has none, and the words of a leaf's own verbs are
// matched as given.
func TestSubSuggestions(t *testing.T) {
	root := newRoot(&invocation{})
	all := func([]string) bool { return true }
	for _, c := range []struct {
		path  []string
		w     string
		verbs []string
		want  []string
	}{
		{[]string{"device", "config"}, "seed", nil, []string{"tacctl device config shapes seed"}},
		{[]string{"device"}, "seed", nil, []string{"tacctl device config shapes seed"}},
		{[]string{"device"}, "apply", nil, []string{"tacctl device config apply"}},
		{[]string{"scope"}, "lst", nil, []string{"tacctl scope list"}},
		{[]string{"scope"}, "LIST", nil, []string{"tacctl scope list"}},
		{[]string{"scope"}, "xyzzy", nil, nil},
		{[]string{"scope"}, "-x", nil, nil},
		{[]string{"scope"}, "", nil, nil},
		{[]string{"scope", "secret"}, "shwo", []string{"show", "set", "generate"}, []string{"show"}},
		{[]string{"scope", "secret"}, "zzz", []string{"show", "set", "generate"}, nil},
	} {
		if got := subSuggestions(root, c.path, c.w, c.verbs, all); !slices.Equal(got, c.want) {
			t.Errorf("%q %q: %q, want %q", c.path, c.w, got, c.want)
		}
	}
	// a hidden command is never named
	if got := subSuggestions(root, nil, "_phas", nil, all); len(got) != 0 {
		t.Errorf("hidden: %q", got)
	}
}
