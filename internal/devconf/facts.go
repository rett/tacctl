package devconf

// Device facts: the release, model and serial number a device reports about
// itself. They are read from text a pull already has (a Junos configuration's
// 'set version' statement, the Cisco version line, a WTI unit's command menu
// version) and from more read commands in the same session, which are best
// effort: a device that refuses one, a class that may not run it, an old
// release that does not know it and a reply that is not what the command
// prints leave the field empty and never change the pull's result.

import (
	"context"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Facts are what a device reports about itself. A field the pull could not
// read is "". Release is the OS release ('25.4R1-S2.3', '15.6(2)T', '8.10'),
// Model the platform ('EX4300-48MP', 'CISCO7206VXR') and Serial the chassis
// serial number. A WTI unit has a release only: its command menu prints
// neither a model nor a serial number.
type Facts struct {
	Release string
	Model   string
	Serial  string
}

// Empty reports whether no fact was read.
func (f Facts) Empty() bool { return f.Release == "" && f.Model == "" && f.Serial == "" }

// The read commands of the facts. The Junos ones are also what a NETCONF
// <command> RPC carries, without the '| no-more' that keeps the CLI from
// paging (the NETCONF runner trims it).
const (
	// JunosChassisCommand prints the hardware inventory: the 'Chassis' row
	// holds the serial number and the model (its description).
	JunosChassisCommand = "show chassis hardware | no-more"
	// JunosVersionCommand prints the running release on its 'Junos:' line
	// (the configuration's 'set version' is the fallback) and the
	// platform's own 'Model:'.
	JunosVersionCommand = "show version | no-more"
	// IOSInventoryCommand prints the inventory: the first entry is the
	// chassis, with its 'PID:' (the model) and 'SN:' (the serial number).
	IOSInventoryCommand = "show inventory"
)

// maxFact bounds what the record keeps of one fact.
const maxFact = 100

// cleanFact is a fact as the record keeps it: control characters and
// unsafe runes shown as '?', blanks collapsed, at most maxFact bytes.
func cleanFact(s string) string {
	s = strings.Join(strings.Fields(scrub(s)), " ")
	if len(s) > maxFact {
		s = s[:maxFact]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// CleanFacts is f with each field cleaned as the record keeps it.
func CleanFacts(f Facts) Facts {
	return Facts{Release: cleanFact(f.Release), Model: cleanFact(f.Model), Serial: cleanFact(f.Serial)}
}

var (
	reJunosSetVersion = regexp.MustCompile(`^set version ("[^"]+"|\S+)$`)
	reJunosVersion    = regexp.MustCompile(`^Junos:\s+(\S+)`)
	reJunosModel      = regexp.MustCompile(`^Model:\s+(\S.*)$`)
)

// JunosRelease is the release a Junos configuration states ('set version
// 25.4R1-S2.3' of 'display set' text); "" when it has no such statement.
func JunosRelease(config string) string {
	for _, l := range strings.Split(config, "\n") {
		if m := reJunosSetVersion.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			return cleanFact(strings.Trim(m[1], `"`))
		}
	}
	return ""
}

// JunosHostName is the name a Junos configuration gives the device: its
// 'set system host-name' value, with 'set system domain-name' appended when
// the name has no dot (the helper's bootstrap rule); "" when it states no
// host name. The text is as the record keeps a fact: control characters
// shown as '?', at most maxFact bytes.
func JunosHostName(config string) string {
	var host, domain string
	for _, l := range strings.Split(config, "\n") {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "set system host-name "); ok && host == "" {
			host = firstWord(v)
		} else if v, ok := strings.CutPrefix(l, "set system domain-name "); ok && domain == "" {
			domain = firstWord(v)
		}
	}
	if host != "" && domain != "" && !strings.Contains(host, ".") {
		host += "." + domain
	}
	return cleanFact(host)
}

// IOSHostName is the name an IOS or IOS-XE running configuration gives the
// device: the value of its top-level 'hostname' line (the first one; the
// domain is not appended, IOS keeps it apart); "" when it states none. The
// text is as the record keeps a fact. 'device enroll' (0.2.17 D263) is the
// reader.
func IOSHostName(config string) string {
	for _, l := range strings.Split(config, "\n") {
		l = strings.TrimRight(l, "\r")
		if v, ok := strings.CutPrefix(l, "hostname "); ok {
			return cleanFact(firstWord(v))
		}
	}
	return ""
}

// firstWord is the first word of a statement's value: a quoted string
// whole, else up to the first blank.
func firstWord(v string) string {
	v = strings.TrimSpace(v)
	if rest, ok := strings.CutPrefix(v, `"`); ok {
		if i := strings.Index(rest, `"`); i >= 0 {
			return rest[:i]
		}
		return rest
	}
	f := strings.Fields(v)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// JunosVersion is the release and the model of the output of 'show version'
// (its 'Junos:' and 'Model:' lines); the first of each wins (a device with
// two routing engines prints a block for each). "" for a field the output
// does not carry.
func JunosVersion(out string) (release, model string) {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if release == "" {
			if m := reJunosVersion.FindStringSubmatch(l); m != nil {
				release = cleanFact(m[1])
			}
		}
		if model == "" {
			if m := reJunosModel.FindStringSubmatch(l); m != nil {
				model = cleanFact(m[1])
			}
		}
	}
	return release, model
}

// JunosChassis is the model (the description column) and the serial number
// of the first 'Chassis' row of the output of 'show chassis hardware'. The
// columns are cut where the header puts them, because a column may be
// empty (a virtual chassis has no serial number or none to show); a row
// that does not line up with its header is split on runs of blanks. Both are
// "" for an output that has no Chassis row (an error text, an empty reply).
func JunosChassis(out string) (model, serial string) {
	serialAt, descAt := -1, -1
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, " ")
		switch {
		case strings.HasPrefix(l, "Item") && strings.Contains(l, "Description"):
			serialAt, descAt = strings.Index(l, "Serial number"), strings.Index(l, "Description")
		case l == "Chassis" || strings.HasPrefix(l, "Chassis "):
			if serialAt > 0 && descAt > serialAt && len(l) > serialAt && l[serialAt-1] == ' ' {
				if len(l) <= descAt || l[descAt-1] == ' ' {
					serial = l[serialAt:min(descAt, len(l))]
					if len(l) > descAt {
						model = l[descAt:]
					}
					return cleanFact(model), cleanFact(serial)
				}
				// A serial number that fills its column runs into the
				// description's: it ends at the next blank.
				if tok, rest, _ := strings.Cut(l[serialAt:], " "); serialAt+len(tok) >= descAt && strings.TrimSpace(rest) != "" {
					return cleanFact(rest), cleanFact(tok)
				}
			}
			// Without a usable header: 'Chassis <serial> <description>', or
			// 'Chassis <description>' (not told apart: the serial is left).
			parts := splitBlanks(strings.TrimSpace(strings.TrimPrefix(l, "Chassis")))
			switch len(parts) {
			case 1:
				return cleanFact(parts[0]), ""
			case 2, 3:
				return cleanFact(parts[len(parts)-1]), cleanFact(parts[len(parts)-2])
			}
			return "", ""
		}
	}
	return "", ""
}

// splitBlanks splits on runs of two or more blanks.
func splitBlanks(s string) []string {
	var out []string
	for _, p := range regexp.MustCompile(` {2,}`).Split(s, -1) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// reIOSSoftware is the version of the 'Cisco IOS Software ... Version X,'
// line, the one that names the image the same way on IOS and on IOS-XE
// ('Cisco IOS XE Software, Version 16.07.01' is written with the build's
// own zero-padded number, and the line after it gives 16.7.1).
var reIOSSoftware = regexp.MustCompile(`^Cisco IOS Software\b.*\bVersion ([0-9][0-9A-Za-z.()]*[0-9A-Za-z)])`)

// IOSRelease is the release of the output of 'show version | include
// Version': the version of the 'Cisco IOS Software ... Version X,' line,
// else the number of the first image line (VersionLine; an XE-only or ASA
// answer); "" for an answer with none (a refused command, or only a boot
// loader's or a hardware line's 'Version X').
func IOSRelease(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if m := reIOSSoftware.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			return cleanFact(m[1])
		}
	}
	if v := ImageVersion(VersionLine(out)); v != "" {
		return cleanFact(v)
	}
	return ""
}

var reIOSPID = regexp.MustCompile(`^PID:\s*(.*?)\s*,\s*VID:.*?,\s*SN:\s*(.*?)\s*$`)

// IOSInventory is the model (PID) and the serial number (SN) of the first
// entry of the output of 'show inventory'; "" for a field the entry leaves
// empty and for an output that has no entry (a refused command).
func IOSInventory(out string) (model, serial string) {
	seenName := false
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "NAME:"):
			if seenName {
				return "", ""
			}
			seenName = true
		case strings.HasPrefix(t, "PID:"):
			if m := reIOSPID.FindStringSubmatch(t); m != nil {
				return cleanFact(m[1]), cleanFact(m[2])
			}
			return "", ""
		}
	}
	return "", ""
}

// ReadFacts completes the facts a read already holds (f: the release the
// reader took from the text it had) with the vendor's more read commands, in
// the session r that read the configuration. It never fails: whatever the
// device refuses or answers that is not the expected text leaves the field as
// it was. A WTI unit has nothing more to read. The caller bounds the time it
// takes with ctx.
func ReadFacts(ctx context.Context, r Runner, vendor string, f Facts) Facts {
	f = CleanFacts(f)
	if ctx.Err() != nil {
		return f
	}
	fam, err := Family(vendor)
	if err != nil {
		return f
	}
	switch fam {
	case FamilyJunos:
		if out, err := r.Run(ctx, JunosChassisCommand); err == nil {
			f.Model, f.Serial = JunosChassis(cleanText(out))
		}
		// The running release is 'show version''s; the configuration's
		// 'set version' (f.Release) is the release it was last committed
		// under, kept when the command answers none. The chassis
		// description is the model; 'Model:' is the platform's own words,
		// used when the chassis row gave none.
		if ctx.Err() == nil {
			if out, err := r.Run(ctx, JunosVersionCommand); err == nil {
				rel, model := JunosVersion(cleanText(out))
				if rel != "" {
					f.Release = rel
				}
				if model != "" && f.Model == "" {
					f.Model = model
				}
			}
		}
	case FamilyIOS:
		if out, err := r.Run(ctx, IOSInventoryCommand); err == nil {
			out = cleanText(out)
			if !iosRefused(out) {
				f.Model, f.Serial = IOSInventory(out)
			}
		}
	}
	return f
}
