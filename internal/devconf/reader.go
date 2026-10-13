package devconf

// The commands that read a vendor's configuration (D61) and the unwrapping
// of a NETCONF reply that carries the same text.

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/names"
)

// Runner runs one command on a device and returns its output. A CLI session
// of internal/devssh satisfies it, as does an adapter over a NETCONF
// <command> RPC; the command text is the same on both.
type Runner interface {
	Run(ctx context.Context, cmd string) (string, error)
}

// Commands returns the commands that read a vendor's configuration: the
// setup commands, whose output is discarded (IOS has its pager turned off),
// then the command whose output is the configuration. Junos: 'show
// configuration | display inheritance no-comments | display set' (a
// group-applied statement appears at its normal path; [S] the lab switch).
// IOS and IOS-XE: 'terminal length 0', 'show version | include Version'
// (whose output is the record's OS line, D113: ReadWithVersion keeps it),
// then 'show running-config'. The Junos command is also what a NETCONF
// <command> RPC carries.
func Commands(vendor string) (setup []string, read string, err error) {
	fam, err := Family(vendor)
	if err != nil {
		return nil, "", err
	}
	if fam == FamilyWTI {
		// A WTI unit has no command that prints its configuration: its
		// pages are walked by a terminal reader (package wti).
		return nil, "", fmt.Errorf("%w: %q", ErrUnsupportedVendor, vendor)
	}
	if fam == FamilyJunos {
		return nil, "show configuration | display inheritance no-comments | display set", nil
	}
	return []string{"terminal length 0", VersionCommand}, "show running-config", nil
}

// ReadFunc reads a device's configuration text through a Runner.
type ReadFunc func(ctx context.Context, r Runner) (string, error)

// ReadVersionFunc is ReadFunc that also returns the device's version line
// (VersionLine of the output of VersionCommand; "" for a vendor that has no
// such setup command and for a device that answered none).
type ReadVersionFunc func(ctx context.Context, r Runner) (text, version string, err error)

// Reader returns the function that reads a vendor's configuration through a
// session: the setup commands, then the read command. The text it returns is
// cleaned of line-end, escape and pager debris and is what Extract takes.
// An empty reply is an error (ErrParse).
func Reader(vendor string) (ReadFunc, error) {
	rv, err := ReaderWithVersion(vendor)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, r Runner) (string, error) {
		text, _, err := rv(ctx, r)
		return text, err
	}, nil
}

// ReaderWithVersion is Reader that also keeps the version line of a Cisco
// device (D113). A device that refuses the version command or answers with
// no line that names a version is not an error: the line is "" and the
// configuration is read all the same (what that means for the syntax is the
// caller's: the registry's setting, the record's or 'needs pull').
func ReaderWithVersion(vendor string) (ReadVersionFunc, error) {
	setup, read, err := Commands(vendor)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, r Runner) (string, string, error) {
		version := ""
		for _, c := range setup {
			out, err := r.Run(ctx, c)
			if err != nil {
				return "", "", err
			}
			if c == VersionCommand {
				version = VersionLine(cleanText(out))
			}
		}
		out, err := r.Run(ctx, read)
		if err != nil {
			return "", "", err
		}
		out = cleanText(out)
		if strings.TrimSpace(out) == "" {
			return "", "", fmt.Errorf("%w: the device returned no text", ErrParse)
		}
		return out, version, nil
	}, nil
}

// PlainCommand is the command that reads a Junos device's configuration
// without the inheritance of its groups applied (plan D97, L6): the same
// statements as Commands' read, minus the ones a group supplies. The planner
// compares the two views to tell a statement of the device's own from one a
// group owns. It is "" for a vendor that has no groups (IOS).
func PlainCommand(vendor string) string {
	if fam, err := Family(vendor); err == nil && fam == FamilyJunos {
		return "show configuration | display set"
	}
	return ""
}

// ReadPlain reads the plain view through a session. It returns "" when the
// vendor has none, when the device refuses or does not answer the command,
// or when the answer holds no 'set' statement at all (an error text must
// never be taken for a configuration with nothing in it: every statement
// would then look as if a group supplied it). The read is best effort: the
// caller's pull does not fail for want of it.
func ReadPlain(ctx context.Context, r Runner, vendor string) string {
	cmd := PlainCommand(vendor)
	if cmd == "" {
		return ""
	}
	out, err := r.Run(ctx, cmd)
	if err != nil {
		return ""
	}
	out = cleanText(out)
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "set ") {
			return out
		}
	}
	return ""
}

// HierarchyCommand is the command that reads one hierarchy of a device's
// configuration: on Junos as 'set' statements ('show configuration snmp |
// display set'), the plain view without the groups' inheritance: what the
// device itself states there; on IOS the 'snmp-server' lines of the running
// configuration (the access lists the communities name are read by
// ReadHierarchy with a command of their own each). Only the top-level
// hierarchies a configuration block adopts are accepted; the command is ""
// for anything else and for a vendor that has no such command.
func HierarchyCommand(vendor, hierarchy string) string {
	fam, err := Family(vendor)
	if err != nil {
		return ""
	}
	switch {
	case fam == FamilyJunos && (hierarchy == "snmp" || hierarchy == "system"):
		return "show configuration " + hierarchy + " | display set"
	case fam == FamilyIOS && hierarchy == "snmp":
		return iosSNMPCommand
	case fam == FamilyIOS && hierarchy == "system":
		return iosSystemCommand
	}
	return ""
}

// iosSNMPCommand reads the SNMP lines of an IOS device's running
// configuration; iosACLCommand the section of one named standard access
// list ('| section' matches by pattern, so the answer is filtered to the
// list's own header).
const (
	iosSNMPCommand = "show running-config | include ^snmp-server"
	// iosSystemCommand reads the lines of the system block; the banner's own
	// lines come from iosBannerCommand ('include' shows its first line only).
	iosSystemCommand = "show running-config | include ^(banner|ip domain|ip name-server|clock timezone|ntp )"
	iosBannerCommand = "show running-config | section ^banner login"
	iosACLCommand    = "show running-config | section ip access-list standard "
	iosFullCommand   = "show running-config"
)

// reIOSACLName is what a named list a read command is made for looks like: a
// word of letters, digits, '.', '_' and '-' (never a number, never anything
// a CLI would read specially).
var reIOSACLName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// iosRefused reports text that begins with a CLI error ('% Invalid input
// detected at ...', '% Ambiguous command', '% Incomplete command').
func iosRefused(text string) bool {
	for _, l := range strings.Split(text, "\n") {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		return strings.HasPrefix(t, "% ")
	}
	return false
}

// iosSection is a top-level line of a running configuration with the
// indented lines under it.
type iosSection struct {
	header string
	lines  []string
}

// iosSections splits running-config text into its top-level lines and what
// is indented under each ('!' lines end nothing and are dropped).
func iosSections(text string) []iosSection {
	var out []iosSection
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimRight(l, " \t\r")
		switch trim := strings.TrimSpace(l); {
		case trim == "" || strings.HasPrefix(trim, "!"):
		case l[0] == ' ' || l[0] == '\t':
			if len(out) > 0 {
				out[len(out)-1].lines = append(out[len(out)-1].lines, l)
			}
		default:
			out = append(out, iosSection{header: strings.Join(strings.Fields(trim), " ")})
		}
	}
	return out
}

// readIOSSNMP reads an IOS device's SNMP lines and, for each standard
// access list a community names, the list's section: the text a block's
// adoption is drafted from. A device that does not know '| section' (an old
// image) is read in full once instead and the lists are cut out of it.
func readIOSSNMP(ctx context.Context, r Runner) (string, error) {
	if _, err := r.Run(ctx, "terminal length 0"); err != nil {
		return "", err
	}
	out, err := r.Run(ctx, iosSNMPCommand)
	if err != nil {
		return "", err
	}
	out = cleanText(out)
	if iosRefused(out) {
		return "", fmt.Errorf("%w: the device refused the command", ErrParse)
	}
	var lines, acls []string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 || f[0] != "snmp-server" {
			continue
		}
		lines = append(lines, strings.Join(f, " "))
		if len(f) >= 4 && f[1] == "community" {
			for i := 3; i < len(f); i++ {
				w := f[i]
				if w == "view" || w == "ipv6" {
					i++
					continue
				}
				if w != "RO" && w != "RW" && w != "ro" && w != "rw" && reIOSACLName.MatchString(w) && !reAllDigitsWord.MatchString(w) &&
					!names.IsTacctlSNMPName(w) && !slices.Contains(acls, w) {
					acls = append(acls, w)
				}
			}
		}
	}
	text := strings.Join(lines, "\n")
	if len(acls) == 0 {
		return text, nil
	}
	var full []iosSection
	haveFull := false
	for _, name := range acls {
		o, err := r.Run(ctx, iosACLCommand+name)
		if err != nil {
			return "", err
		}
		o = cleanText(o)
		var secs []iosSection
		if iosRefused(o) {
			if !haveFull {
				all, err := r.Run(ctx, iosFullCommand)
				if err != nil {
					return "", err
				}
				all = cleanText(all)
				if iosRefused(all) {
					return "", fmt.Errorf("%w: the device refused the command", ErrParse)
				}
				full, haveFull = iosSections(all), true
			}
			secs = full
		} else {
			secs = iosSections(o)
		}
		for _, s := range secs {
			if s.header != "ip access-list standard "+name {
				continue
			}
			text += "\n" + s.header
			for _, l := range s.lines {
				text += "\n" + l
			}
		}
	}
	return text, nil
}

// readIOSSystem reads an IOS device's system lines and its login banner, the
// text a block's adoption is drafted from: the lines of the first command
// (the banners' first lines left out) and the banner's own lines, read with
// '| section' or, when the device does not know it, cut out of the whole
// running configuration.
func readIOSSystem(ctx context.Context, r Runner) (string, error) {
	if _, err := r.Run(ctx, "terminal length 0"); err != nil {
		return "", err
	}
	out, err := r.Run(ctx, iosSystemCommand)
	if err != nil {
		return "", err
	}
	out = cleanText(out)
	if iosRefused(out) {
		return "", fmt.Errorf("%w: the device refused the command", ErrParse)
	}
	var kept []string
	var first []string
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "banner ") {
			first = append(first, l)
			continue
		}
		kept = append(kept, strings.TrimSpace(l))
	}
	// the banner: the section read, the whole configuration when that is
	// refused, the first line of the first command when it is all there is
	banner := bannerLines(ctx, r, first)
	return strings.Join(append(kept, banner...), "\n"), nil
}

// bannerLines are the lines of the login banner (its opening line, its text
// and its closing delimiter), none when the device has none.
func bannerLines(ctx context.Context, r Runner, first []string) []string {
	cut := func(text string) []string {
		lines := strings.Split(text, "\n")
		for i, l := range lines {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "banner" && f[1] == "login" && l == strings.TrimLeft(l, " \t") {
				if _, took, ok := blocks.DeviceBanner(lines[i:]); ok {
					return lines[i : i+took]
				}
				return nil
			}
		}
		return nil
	}
	if o, err := r.Run(ctx, iosBannerCommand); err == nil {
		o = cleanText(o)
		if !iosRefused(o) {
			if b := cut(o); b != nil {
				return b
			}
		} else if all, err := r.Run(ctx, iosFullCommand); err == nil {
			all = cleanText(all)
			if !iosRefused(all) {
				if b := cut(all); b != nil {
					return b
				}
			}
		}
	}
	return cut(strings.Join(first, "\n"))
}

var reAllDigitsWord = regexp.MustCompile(`^[0-9]+$`)

// ReadHierarchy reads one hierarchy through a session (HierarchyCommand) and
// returns its text cleaned of line-end, escape and pager debris. The text is
// the caller's to use and drop: nothing is stored here. A hierarchy the
// device has nothing under is "" and no error; a refusal ('error:', 'syntax
// error', 'unknown command') or an unusable command is ErrParse.
func ReadHierarchy(ctx context.Context, r Runner, vendor, hierarchy string) (string, error) {
	cmd := HierarchyCommand(vendor, hierarchy)
	if cmd == "" {
		return "", fmt.Errorf("%w: there is no read of the '%s' hierarchy for vendor '%s'", ErrParse, hierarchy, vendor)
	}
	if cmd == iosSNMPCommand {
		return readIOSSNMP(ctx, r)
	}
	if cmd == iosSystemCommand {
		return readIOSSystem(ctx, r)
	}
	out, err := r.Run(ctx, cmd)
	if err != nil {
		return "", err
	}
	out = cleanText(out)
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "error:") || strings.HasPrefix(t, "syntax error") || strings.HasPrefix(t, "unknown command") {
			return "", fmt.Errorf("%w: the device refused the command", ErrParse)
		}
	}
	return out, nil
}

// UnwrapNetconf returns the text carried by a Junos NETCONF reply: the
// content of <configuration-output> (a <command> reply) or
// <configuration-set> (a <get-configuration format="set"/> reply), XML
// escapes resolved. An <rpc-error> of severity error fails the call with
// the device's message; one of another severity (a warning) is returned
// beside the text.
func UnwrapNetconf(reply string) (text string, warnings []string, err error) {
	dec := xml.NewDecoder(strings.NewReader(reply))
	// Junos declares encoding="us-ascii" on its replies; the text is already
	// valid UTF-8, so any declared charset is read as is.
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var out strings.Builder
	var inText, found bool
	var errDepth int
	var severity, msg string
	var field *string
	var fatal []string
	for {
		tok, e := dec.Token()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return "", nil, fmt.Errorf("%w: the NETCONF reply is not XML", ErrParse)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "configuration-output", "configuration-set", "configuration-text":
				inText, found = true, true
			case "rpc-error":
				errDepth++
				severity, msg = "", ""
			case "error-severity":
				if errDepth > 0 {
					field = &severity
				}
			case "error-message":
				if errDepth > 0 {
					field = &msg
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "configuration-output", "configuration-set", "configuration-text":
				inText = false
			case "error-severity", "error-message":
				field = nil
			case "rpc-error":
				errDepth--
				m := msg
				if m == "" {
					m = "no message"
				}
				if strings.EqualFold(severity, "warning") {
					warnings = append(warnings, m)
				} else {
					fatal = append(fatal, m)
				}
			}
		case xml.CharData:
			switch {
			case inText:
				out.Write(t)
			case field != nil:
				*field += strings.TrimSpace(string(t))
			}
		}
	}
	if len(fatal) > 0 {
		return "", warnings, fmt.Errorf("%w: the device answered rpc-error: %s", ErrParse, strings.Join(fatal, "; "))
	}
	if !found {
		return "", warnings, fmt.Errorf("%w: no configuration in the NETCONF reply", ErrParse)
	}
	return out.String(), warnings, nil
}
