// Package radius renders the FreeRADIUS side of tacctl: the model and the
// merged tacctl.yaml view become tacctl-radius.conf, tacctl-radius.users and
// tacctl's dictionary, byte for byte what lib/backends/radius.sh
// (_render_radius_py, the 0.1.16 tag) writes, for both distro families. It
// also holds the pieces of that file the renderer shares with the RADIUS
// module: family detection, the secret and hash conversions, the WTI-Super
// bands, the render notes and the unit drop-in text.
//
// Everything here is pure: no file is read except the directory probes of
// DetectFamily, nothing is written except by Output.WriteDir, and the output
// depends only on the inputs (no timestamps), so an unchanged model renders
// byte-identically. The render id (the first 16 hex digits of the SHA-256 of
// conf, users and dictionary) binds the three files to each other.
//
// What the module (WP2.3) still has to add around it: the drift states of
// render-live (internal/rendered, WP1.5), the daemon's config check, the
// stage/commit/gate wrappers, and the 'render_notes' warning texts built from
// Notes.
package radius

import (
	"errors"
	"fmt"
)

// Error is a problem with the input that stops the render, the StoreError of
// the Python program: one line, never containing a secret or a hash. The
// command prints it as "tacctl render: <message>" (Report).
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errorf(format string, args ...any) error {
	return &Error{Msg: fmt.Sprintf(format, args...)}
}

// Report is the line the 0.1.16 program prints on stderr for err:
// "tacctl render: <message>" for an *Error, err.Error() otherwise.
func Report(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return "tacctl render: " + e.Msg
	}
	return err.Error()
}

// The secret advice of backend_radius_secret_constraints: the shortest limit
// among the RADIUS clients a figure was found for, and printable ASCII
// without a space. Advice, not a refusal (Notes names the scopes beyond it).
const (
	SecretMaxLen  = 63
	SecretCharset = "[!-~]"
)
