package devconf

// The Cisco configuration syntax as a fact of its own (docs/plans/0.2.5-
// plan.md D113). Two lab devices that need the legacy ssh algorithms speak
// the modern 'tacacs server NAME' syntax, so the syntax cannot be read from
// the ssh flag: the pull reads the image's version line (show version |
// include Version), keeps it on the record as OS and derives the syntax from
// it; the registry's per-device setting overrides the derivation; the three
// users of the answer (the comparison, the walkthrough and the planner) all
// take it from Syntax or ResolveSyntax, never from the ssh flag. A version
// line the table does not know has no syntax: it is not guessed either way.

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
	// SyntaxModern is the 'tacacs server NAME' syntax of IOS 15.2 and
	// later, 16.x, 17.x and IOS-XE.
	SyntaxModern = "modern"
)

// VersionCommand is the setup command of the Cisco read whose first useful
// line is kept on the record as OS (D113).
const VersionCommand = "show version | include Version"

// SyntaxRow is one row of the derivation table: a version line that matches
// Match is of Syntax. The rows are tried in order; the first match wins. A
// row whose Syntax is "" says the image is recognised and has no syntax of
// its own to derive (it is not an IOS image of either dialect).
type SyntaxRow struct {
	// Name says what the row stands for (it is the test's name).
	Name string
	// Match is applied to the version line.
	Match *regexp.Regexp
	// Syntax is SyntaxIOS12, SyntaxModern or "" (unknown).
	Syntax string
}

// SyntaxRows is the derivation table (D113 (2)). A line no row matches has
// no syntax: IOS 11.x, an ASA registered as cisco, IOS XR, a line with no
// image. It is never guessed either way; the device takes the explicit
// setting.
//
// [A] 'Version 15.0' and 'Version 15.1' are unknown on purpose: the 'tacacs
// server NAME' syntax is believed to start at IOS 15.2 (IOS-XE 3.2), but
// that is not verified for 15.0 and 15.1, and the wrong dialect on a device
// is a half-applied AAA block. Those images need 'device ios-syntax
// <name> ios12|modern'. Confirm in the package that ships the 15.0/15.1
// lab image (docs/plans/0.2.5-plan.md D113).
var SyntaxRows = []SyntaxRow{
	// Images that are not the IOS family of either dialect, named first so
	// that a number in their text is never read as an IOS version.
	{"IOS XR", regexp.MustCompile(`(?i)IOS[- ]?XR`), ""},
	{"ASA", regexp.MustCompile(`(?i)Adaptive Security Appliance`), ""},
	{"NX-OS", regexp.MustCompile(`(?i)NX-OS`), ""},
	{"IOS-XE, whatever its version", regexp.MustCompile(`IOS[- ]XE`), SyntaxModern},
	{"IOS 12.x", regexp.MustCompile(`Version 12\.`), SyntaxIOS12},
	{"IOS 15.2 to 15.9", regexp.MustCompile(`Version 15\.[2-9]`), SyntaxModern},
	{"IOS 16.x", regexp.MustCompile(`Version 16\.`), SyntaxModern},
	{"IOS 17.x", regexp.MustCompile(`Version 17\.`), SyntaxModern},
}

// DeriveSyntax is the syntax a version line stands for: SyntaxIOS12,
// SyntaxModern, or "" for an empty line and for a line no row of SyntaxRows
// maps (never a guess).
func DeriveSyntax(os string) string {
	os = strings.TrimSpace(os)
	if os == "" {
		return ""
	}
	for _, r := range SyntaxRows {
		if r.Match.MatchString(os) {
			return r.Syntax
		}
	}
	return ""
}

// maxVersionLine bounds what the record keeps of a version line.
const maxVersionLine = 200

// VersionLine is the line of 'show version | include Version”s output that
// the record keeps: the first line that names the image ('Cisco IOS
// Software ... Version 15.6(2)T', 'Cisco IOS XE Software, Version
// 16.07.01', 'Cisco Adaptive Security Appliance Software Version 9.8(4)').
// The boot loader's lines ('ROM: System Bootstrap, Version 12.4(13r)T',
// 'BOOTLDR: ... Version 12.2(44)SE') name the loader, not the image, and
// are ignored whatever their case; so are the device's error text ('% ...')
// and an echo of the command. The result is "" when no line names an image.
// The output is expected cleaned (cleanText).
func VersionLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "%") || strings.Contains(l, VersionCommand) {
			continue
		}
		low := strings.ToLower(l)
		if strings.HasPrefix(low, "rom:") || strings.HasPrefix(low, "bootldr:") || strings.Contains(low, "system bootstrap") {
			continue
		}
		if !strings.Contains(low, "version") {
			continue
		}
		if strings.Contains(l, "IOS") || strings.Contains(low, "software") || strings.Contains(low, "appliance") {
			return clipVersion(l)
		}
	}
	return ""
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

// versionNumberRE is the number after 'Version' in an image line.
var versionNumberRE = regexp.MustCompile(`Version ([0-9][0-9A-Za-z.()]*[0-9A-Za-z)])`)

// ImageVersion is the version number a version line carries ('12.4(15)SW'
// from 'Cisco IOS Software, ... Version 12.4(15)SW, RELEASE SOFTWARE'), for
// a message; "" when the line has none.
func ImageVersion(os string) string {
	if m := versionNumberRE.FindStringSubmatch(os); m != nil {
		return m[1]
	}
	return ""
}

// SyntaxResolution is the answer of ResolveSyntax.
type SyntaxResolution struct {
	// Syntax is SyntaxIOS12 or SyntaxModern, or "" when neither the setting
	// nor the record says (no pull that read a version line the table
	// maps).
	Syntax string
	// Source is "setting" (the registry's explicit value), "pull" (the
	// record's) or "" with Syntax "".
	Source string
	// Conflict is set when the explicit setting is not the syntax the
	// record's version line derives to; ImageSyntax is that syntax. The
	// setting wins: the conflict is for the callers to say.
	Conflict    bool
	ImageSyntax string
}

// RecordSyntax is the syntax a record stands for: what its version line
// derives to (a record written by a build that guessed is not believed),
// else the stored field of a record that kept no line.
func RecordSyntax(rec *Record) string {
	if rec == nil {
		return ""
	}
	if strings.TrimSpace(rec.OS) != "" {
		return DeriveSyntax(rec.OS)
	}
	if rec.Syntax == SyntaxIOS12 || rec.Syntax == SyntaxModern {
		return rec.Syntax
	}
	return ""
}

// ConflictOf reports whether an explicit setting contradicts the syntax a
// version line derives to (imageSyntax). Only the settings ios12 and modern
// can; a line the table does not map contradicts nothing.
func ConflictOf(setting, os string) (imageSyntax string, conflict bool) {
	if setting != SyntaxIOS12 && setting != SyntaxModern {
		return "", false
	}
	d := DeriveSyntax(os)
	return d, d != "" && d != setting
}

// ResolveSyntax is the one resolution of D113 (3): the explicit setting when
// it is SyntaxIOS12 or SyntaxModern, else the record's syntax, else nothing.
// Callers decide what nothing means: the comparison says 'needs pull', the
// walkthrough prints the modern syntax with a note. The ssh flag has no
// part in it.
func ResolveSyntax(setting string, rec *Record) SyntaxResolution {
	switch setting {
	case SyntaxIOS12, SyntaxModern:
		r := SyntaxResolution{Syntax: setting, Source: "setting"}
		if rec != nil {
			r.ImageSyntax, r.Conflict = ConflictOf(setting, rec.OS)
		}
		return r
	}
	if s := RecordSyntax(rec); s != "" {
		return SyntaxResolution{Syntax: s, Source: "pull"}
	}
	return SyntaxResolution{}
}

// Syntax is ResolveSyntax's syntax: SyntaxIOS12, SyntaxModern or "".
func Syntax(setting string, rec *Record) string { return ResolveSyntax(setting, rec).Syntax }

// SyntaxFromRead is the syntax a pull compares a device against, given the
// registry's setting, the version line the pull read ("" when it read none)
// and the record that was there before: the explicit setting, else what the
// line says now (a device that was upgraded is compared as it is; a line the
// table does not map is unknown, not the record's), else, when the device
// answered no line at all, the record's. "" is the pull that cannot say.
func SyntaxFromRead(setting, os string, old *Record) string {
	switch setting {
	case SyntaxIOS12, SyntaxModern:
		return setting
	}
	if strings.TrimSpace(os) != "" {
		return DeriveSyntax(os)
	}
	return ResolveSyntax(setting, old).Syntax
}
