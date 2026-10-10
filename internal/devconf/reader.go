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
// IOS and IOS-XE: 'terminal length 0', then 'show running-config'. The
// Junos command is also what a NETCONF <command> RPC carries.
func Commands(vendor string) (setup []string, read string, err error) {
	fam, err := Family(vendor)
	if err != nil {
		return nil, "", err
	}
	if fam == FamilyJunos {
		return nil, "show configuration | display inheritance no-comments | display set", nil
	}
	return []string{"terminal length 0"}, "show running-config", nil
}

// ReadFunc reads a device's configuration text through a Runner.
type ReadFunc func(ctx context.Context, r Runner) (string, error)

// Reader returns the function that reads a vendor's configuration through a
// session: the setup commands, then the read command. The text it returns is
// cleaned of line-end, escape and pager debris and is what Extract takes.
// An empty reply is an error (ErrParse).
func Reader(vendor string) (ReadFunc, error) {
	setup, read, err := Commands(vendor)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, r Runner) (string, error) {
		for _, c := range setup {
			if _, err := r.Run(ctx, c); err != nil {
				return "", err
			}
		}
		out, err := r.Run(ctx, read)
		if err != nil {
			return "", err
		}
		out = cleanText(out)
		if strings.TrimSpace(out) == "" {
			return "", fmt.Errorf("%w: the device returned no text", ErrParse)
		}
		return out, nil
	}, nil
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
