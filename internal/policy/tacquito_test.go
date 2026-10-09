package policy_test

// A tacquito-exact emulator of per-command authorization, shared by the
// baseline tests. It follows tacquito's authorizer as the probe of
// 2026-10-08 (docs/plans/0.2.3-plan.md section 3b) showed it:
//
//   - rules are tried top-down; a rule whose name is neither the command
//     word nor '*' is skipped;
//   - '*' decides at once, wherever it stands;
//   - a rule with no match (or an empty match list) decides at once;
//   - otherwise each regex is tested against the space-joined arguments
//     (never the command word), after '^' is prepended and '$' appended
//     when missing; the first that matches decides; none matching falls
//     through to the next rule;
//   - an empty regex is skipped; an invalid one denies at once;
//   - the end of the list denies.
//
// A group without any rule is not authorized per command at all: every
// command is permitted (the rendered file has no commands block).
//
// tacctl renders every stored regex as ^(?:regex)$ (rtacacs.WrapMatch),
// which the emulator applies first; wrap=false emulates the 0.2.2 files,
// where tacquito alone anchored the stored text.

import (
	"regexp"
	"strings"

	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
)

type tqRule struct {
	name, action string
	match        []string
}

// tqRules parses 'name|action|m1,m2' lines.
func tqRules(lines []string) []tqRule {
	var out []tqRule
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.SplitN(l, "|", 3)
		r := tqRule{name: f[0], action: "permit"}
		if len(f) > 1 {
			r.action = f[1]
		}
		if len(f) > 2 && f[2] != "" {
			r.match = strings.Split(f[2], ",")
		}
		out = append(out, r)
	}
	return out
}

// tqPermits is whether the rules authorize a command line ('show version':
// the word and its arguments).
func tqPermits(rules []tqRule, wrap bool, line string) bool {
	if len(rules) == 0 {
		return true
	}
	cmd, args, _ := strings.Cut(line, " ")
	for _, r := range rules {
		if r.name != "*" && r.name != cmd {
			continue
		}
		if r.name == "*" || len(r.match) == 0 {
			return r.action == "permit"
		}
		for _, rx := range r.match {
			if rx == "" {
				continue
			}
			if wrap {
				rx = rtacacs.WrapMatch(rx)
			}
			if !strings.HasPrefix(rx, "^") {
				rx = "^" + rx
			}
			if !strings.HasSuffix(rx, "$") {
				rx += "$"
			}
			re, err := regexp.Compile(rx)
			if err != nil {
				return false
			}
			if re.MatchString(args) {
				return r.action == "permit"
			}
		}
	}
	return false
}
