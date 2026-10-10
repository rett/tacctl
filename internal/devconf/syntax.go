package devconf

// The Cisco configuration syntax as a fact of its own (docs/plans/0.2.5-
// plan.md D113). Two lab devices that need the legacy ssh algorithms speak
// the modern 'tacacs server NAME' syntax, so the syntax cannot be read from
// the ssh flag: the pull reads the image's version line (show version |
// include Version), keeps it on the record as OS and derives the syntax from
// it; the registry's per-device setting overrides the derivation; the three
// users of the answer (the comparison, the walkthrough and the planner) all
// take it from Syntax or ResolveSyntax, never from the ssh flag.

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// The values of the registry's config_syntax setting (SyntaxAuto is the
// default, and is never written to the registry) and of Record.Syntax
// (SyntaxIOS12 or SyntaxModern, or empty).
const (
	// SyntaxAuto resolves from the last pull's version line.
	SyntaxAuto = "auto"
	// SyntaxIOS12 is the IOS 12.x syntax ('tacacs-server host ...', 'aaa
	// group server tacacs+ X' > 'server <ip>').
	SyntaxIOS12 = "ios12"
	// SyntaxModern is the 'tacacs server NAME' syntax of IOS 15.x, 16.x,
	// 17.x and IOS-XE.
	SyntaxModern = "modern"
)

// VersionCommand is the setup command of the Cisco read whose first useful
// line is kept on the record as OS (D113).
const VersionCommand = "show version | include Version"

// SyntaxRow is one row of the derivation table: a version line that matches
// Match is of Syntax. The rows are tried in order; the first match wins.
type SyntaxRow struct {
	// Name says what the row stands for (it is the test's name).
	Name string
	// Match is applied to the version line.
	Match *regexp.Regexp
	// Syntax is SyntaxIOS12 or SyntaxModern.
	Syntax string
}

// SyntaxRows is the derivation table (D113 (2)). A line no row matches is
// SyntaxModern with a note (DeriveSyntax's second result): the modern syntax
// is the one every image since 15.0 has, and a 12.x image always says
// 'Version 12.'.
var SyntaxRows = []SyntaxRow{
	{"IOS-XE, whatever its version", regexp.MustCompile(`IOS[- ]XE`), SyntaxModern},
	{"IOS 12.x", regexp.MustCompile(`Version 12\.`), SyntaxIOS12},
	{"IOS 15.x", regexp.MustCompile(`Version 15\.`), SyntaxModern},
	{"IOS 16.x", regexp.MustCompile(`Version 16\.`), SyntaxModern},
	{"IOS 17.x", regexp.MustCompile(`Version 17\.`), SyntaxModern},
}

// DeriveSyntax is the syntax a version line stands for. An empty line has
// none (""); a line no row of SyntaxRows matches is SyntaxModern with
// guessed set, for the caller to say so (syntax guessed from "<line>").
func DeriveSyntax(os string) (syntax string, guessed bool) {
	os = strings.TrimSpace(os)
	if os == "" {
		return "", false
	}
	for _, r := range SyntaxRows {
		if r.Match.MatchString(os) {
			return r.Syntax, false
		}
	}
	return SyntaxModern, true
}

// maxVersionLine bounds what the record keeps of a version line.
const maxVersionLine = 200

// VersionLine is the line of 'show version | include Version”s output that
// the record keeps: the first line that names the image ('Cisco IOS
// Software ... Version 15.6(2)T', 'Cisco IOS XE Software, Version
// 16.07.01'), else the first that has 'Version' in it. The device's error
// text ('% ...') and an echo of the command are no version line; the result
// is "" when there is none. The output is expected cleaned (cleanText).
func VersionLine(out string) string {
	var first string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "%") || strings.Contains(l, VersionCommand) {
			continue
		}
		if !strings.Contains(strings.ToLower(l), "version") {
			continue
		}
		if strings.Contains(l, "IOS") {
			return clipVersion(l)
		}
		if first == "" {
			first = l
		}
	}
	return clipVersion(first)
}

func clipVersion(l string) string {
	l = scrub(l)
	if len(l) > maxVersionLine {
		l = l[:maxVersionLine]
		for !utf8.ValidString(l) {
			l = l[:len(l)-1]
		}
	}
	return l
}

// SyntaxResolution is the answer of ResolveSyntax.
type SyntaxResolution struct {
	// Syntax is SyntaxIOS12 or SyntaxModern, or "" when neither the setting
	// nor the record says (no pull that read a version line).
	Syntax string
	// Source is "setting" (the registry's explicit value), "pull" (the
	// record's) or "" with Syntax "".
	Source string
	// Guessed is set when the record's syntax came from a version line no
	// row of SyntaxRows matched.
	Guessed bool
}

// ResolveSyntax is the one resolution of D113 (3): the explicit setting when
// it is SyntaxIOS12 or SyntaxModern, else the record's syntax, else nothing.
// Callers decide what nothing means: the comparison says 'needs pull', the
// walkthrough prints the modern syntax with a note. The ssh flag has no
// part in it.
func ResolveSyntax(setting string, rec *Record) SyntaxResolution {
	switch setting {
	case SyntaxIOS12, SyntaxModern:
		return SyntaxResolution{Syntax: setting, Source: "setting"}
	}
	if rec != nil && (rec.Syntax == SyntaxIOS12 || rec.Syntax == SyntaxModern) {
		_, guessed := DeriveSyntax(rec.OS)
		return SyntaxResolution{Syntax: rec.Syntax, Source: "pull", Guessed: guessed}
	}
	return SyntaxResolution{}
}

// Syntax is ResolveSyntax's syntax: SyntaxIOS12, SyntaxModern or "".
func Syntax(setting string, rec *Record) string { return ResolveSyntax(setting, rec).Syntax }

// SyntaxFromRead is the syntax a pull compares a device against, given the
// registry's setting, the version line the pull read ("" when it read none)
// and the record that was there before: the explicit setting, else what the
// line says now (a device that was upgraded is compared as it is), else the
// record's. "" is the pull that cannot say.
func SyntaxFromRead(setting, os string, old *Record) (syntax string, guessed bool) {
	switch setting {
	case SyntaxIOS12, SyntaxModern:
		return setting, false
	}
	if s, g := DeriveSyntax(os); s != "" {
		return s, g
	}
	r := ResolveSyntax(setting, old)
	return r.Syntax, r.Guessed
}
