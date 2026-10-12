package devconf

// The commands that read a vendor's configuration (D61) and the unwrapping
// of a NETCONF reply that carries the same text.

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
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

// HierarchyCommand is the command that reads one hierarchy of a Junos
// device's configuration as 'set' statements ('show configuration snmp |
// display set'), the plain view without the groups' inheritance: what the
// device itself states there. Only the top-level hierarchies a configuration
// block adopts are accepted; the command is "" for anything else and for a
// vendor that has no such command.
func HierarchyCommand(vendor, hierarchy string) string {
	fam, err := Family(vendor)
	if err != nil || fam != FamilyJunos {
		return ""
	}
	switch hierarchy {
	case "snmp", "system":
		return "show configuration " + hierarchy + " | display set"
	}
	return ""
}

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
