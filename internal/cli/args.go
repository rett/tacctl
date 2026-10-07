package cli

import (
	"fmt"
	"strings"
)

// The leaf commands parse their own arguments (cobra's flag parsing is off
// everywhere, docs/plans/go-rewrite.md 3.2) so that every message and exit
// code stays the bash implementation's. This is the skeleton the cut-over
// packages build on: a Spec lists the flags and positionals of a verb, Parse
// returns typed errors, and the verb turns them into its own bash message.
// The same Spec is meant to drive completion.

// Flag is one flag of a verb.
type Flag struct {
	// Names are the spellings, e.g. {"--yes", "-y"}; the first is the key
	// in Parsed.
	Names []string
	// Value: the flag takes a value, given as "--name value" or
	// "--name=value". Otherwise it is a switch, and "--name=x" is an error.
	Value bool
	// Repeat: the flag may be given more than once (each value is kept).
	Repeat bool
	// Only: completion offers the flag only after this positional word
	// ('remove --all'). Alone: no positional is offered once the flag is on
	// the line. Neither changes how the verb parses its arguments.
	Only  string
	Alone bool
	// Kind is what the value is, for completion: a _completion-names kind
	// (KindUsers, ...), KindList for a comma list of one, or "" for free
	// text.
	Kind string
}

// The value kinds of Flag.Kind and Spec.Args: completion offers the live
// names of a _completion-names kind (completionKinds).
const (
	KindUsers  = "users"
	KindGroups = "groups"
	KindScopes = "scopes"
	// KindHosts are the enrolled hosts' names (the host registry);
	// KindDevices are every name 'ssh' and 'device' accept: the hosts' and
	// the device registry's (registerDeviceNames).
	KindHosts   = "hosts"
	KindDevices = "devices"
	// KindVendors is the fixed list of device vendors.
	KindVendors = "cisco|juniper|wti|other"
	// KindFile is a file or directory name: the shell completes paths.
	KindFile = "file"
	// KindList marks a comma list: "<kind>,list" completes after each comma.
	KindList = ",list"
	// KindLine is a tacctl command line ('shell -c'): completion offers the
	// commands, for its first word.
	KindLine = "line"
)

// After is the kind of a positional that completion offers only when the
// word is among the positionals typed before it ('set <ip> <vendor>').
func After(word, kind string) string { return "@" + word + ":" + kind }

// Spec describes a verb's arguments.
type Spec struct {
	Flags []Flag
	// MinArgs and MaxArgs bound the positional count; MaxArgs < 0 is no
	// upper bound.
	MinArgs, MaxArgs int
	// Args are the kinds of the positionals, in order, for completion (""
	// for free text; a word list such as "list|add|remove" for a fixed
	// set).
	Args []string
}

// Parsed is the result of Parse.
type Parsed struct {
	Args  []string            // positionals, in order
	flags map[string][]string // by Flag.Names[0]; a switch has one "" per use
}

// Has reports whether flag (any spelling) was given.
func (p Parsed) Has(name string) bool { return len(p.flags[name]) > 0 }

// Value is the last value of flag name, or "".
func (p Parsed) Value(name string) string {
	v := p.flags[name]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

// Values are all values of flag name, in order.
func (p Parsed) Values(name string) []string { return append([]string(nil), p.flags[name]...) }

// UnknownFlagError: an argument that starts with '-' is no flag of the verb.
type UnknownFlagError struct{ Flag string }

func (e *UnknownFlagError) Error() string { return fmt.Sprintf("Unknown flag: '%s'", e.Flag) }

// MissingValueError: a value flag ends the arguments.
type MissingValueError struct{ Flag string }

func (e *MissingValueError) Error() string { return fmt.Sprintf("%s requires a value", e.Flag) }

// UnexpectedValueError: a switch given as --name=value.
type UnexpectedValueError struct{ Flag string }

func (e *UnexpectedValueError) Error() string { return fmt.Sprintf("%s takes no value", e.Flag) }

// RepeatedFlagError: a flag without Repeat given twice.
type RepeatedFlagError struct{ Flag string }

func (e *RepeatedFlagError) Error() string { return fmt.Sprintf("%s given more than once", e.Flag) }

// ArgCountError: too few or too many positionals.
type ArgCountError struct {
	Got      int
	Min, Max int
	// Extra is the first positional over Max ("" when there are too few).
	Extra string
}

func (e *ArgCountError) Error() string {
	if e.Extra != "" {
		return fmt.Sprintf("Unknown argument: '%s'", e.Extra)
	}
	return fmt.Sprintf("expected at least %d argument(s), got %d", e.Min, e.Got)
}

// Parse splits argv by spec. Flags and positionals may be mixed; "--" ends
// the flags; a lone "-" is a positional. The first error wins, so a caller
// can report it the way the bash parser of the verb does.
func Parse(spec Spec, argv []string) (Parsed, error) {
	p := Parsed{flags: map[string][]string{}}
	byName := map[string]*Flag{}
	for i := range spec.Flags {
		for _, n := range spec.Flags[i].Names {
			byName[n] = &spec.Flags[i]
		}
	}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			p.Args = append(p.Args, argv[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			p.Args = append(p.Args, a)
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		f, ok := byName[name]
		if !ok {
			return p, &UnknownFlagError{Flag: a}
		}
		key := f.Names[0]
		if len(p.flags[key]) > 0 && !f.Repeat {
			return p, &RepeatedFlagError{Flag: name}
		}
		switch {
		case !f.Value && hasVal:
			return p, &UnexpectedValueError{Flag: name}
		case !f.Value:
			val = ""
		case !hasVal:
			if i+1 >= len(argv) {
				return p, &MissingValueError{Flag: name}
			}
			i++
			val = argv[i]
		}
		p.flags[key] = append(p.flags[key], val)
	}
	if n := len(p.Args); n < spec.MinArgs {
		return p, &ArgCountError{Got: n, Min: spec.MinArgs, Max: spec.MaxArgs}
	} else if spec.MaxArgs >= 0 && n > spec.MaxArgs {
		return p, &ArgCountError{Got: n, Min: spec.MinArgs, Max: spec.MaxArgs, Extra: p.Args[spec.MaxArgs]}
	}
	return p, nil
}
