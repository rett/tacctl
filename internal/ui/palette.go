package ui

// The palette of the command lists (the '?' list of the shell and the
// console, a second Tab, '-h' and '--help'): command names are bright white,
// the sub-commands, fixed words and options teal, live names (a user, a
// group, a device) bold in the terminal's own colour, and the descriptions
// are plain text. The sequences are emitted always; a stream that is not a
// terminal, NO_COLOR and TACCTL_COLOR take them out (Colour, Plain).
const (
	// BrightWhite is SGR 97: the name of a command (the first word at the top
	// level).
	BrightWhite = "\033[97m"
	// Teal is SGR 36: a sub-command, a fixed word or an option.
	Teal = "\033[36m"
)

// Paint is s in style, reset after it; s alone when it is empty.
func Paint(style, s string) string {
	if s == "" || style == "" {
		return s
	}
	return style + s + NC
}
