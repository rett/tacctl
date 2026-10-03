package hosts

import (
	"errors"
	"io/fs"
	"os"
	"strings"
)

// The registry of enrolled hosts (LINUX_HOSTS_FILE, mode 0600), one line per
// host:
//
//	name|target|port|scope|server|identity[|method]
//
// target is [user@]host for ssh, or 'local' for this machine. A line of six
// fields is a tacplus host: that is how every line was written before there
// were two methods, and how a tacplus host is still written, so the file of
// a server that only uses TACACS+ stays readable by the release before.

// Local is the target of a host enrolled with --local.
const Local = "local"

// Entry is one registry line, its fields as written.
type Entry struct {
	Name, Target, Port, Scope, Server, Identity string
	// Method is the seventh field: "" on a six-field (tacplus) line.
	Method string
	// Line is the line itself.
	Line string
}

// EffectiveMethod is host_method for the entry: its seventh field when
// that names a method, else tacplus.
func (e Entry) EffectiveMethod() string {
	if _, ok := MethodBackend(e.Method); ok {
		return e.Method
	}
	return Tacplus
}

// parseEntry splits a line into its fields (a seventh field is the
// method; anything after it is ignored, as host_method's 'cut -f7' does).
func parseEntry(line string) Entry {
	f := strings.Split(line, "|")
	get := func(i int) string {
		if i < len(f) {
			return f[i]
		}
		return ""
	}
	return Entry{
		Name: get(0), Target: get(1), Port: get(2), Scope: get(3),
		Server: get(4), Identity: get(5), Method: get(6), Line: line,
	}
}

// format is the registry line for e: host_remember's six fields, the
// method added when it is not tacplus.
func (e Entry) format() string {
	l := strings.Join([]string{e.Name, e.Target, e.Port, e.Scope, e.Server, e.Identity}, "|")
	if e.Method != "" && e.Method != Tacplus {
		l += "|" + e.Method
	}
	return l
}

// Registry is the host registry file.
type Registry struct {
	Path  string
	text  string
	found bool
}

// Load reads the registry; a missing file is an empty registry.
func (r *Registry) Load() error {
	data, err := os.ReadFile(r.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		r.text, r.found = "", false
		return nil
	case err != nil:
		return err
	}
	r.text, r.found = string(data), true
	return nil
}

// LoadRegistry reads the registry at path.
func LoadRegistry(path string) (*Registry, error) {
	r := &Registry{Path: path}
	return r, r.Load()
}

// Exists reports whether the file exists ('[[ -f ]]').
func (r *Registry) Exists() bool { return r.found }

// Empty is '[[ ! -s ]]': no file, or an empty one.
func (r *Registry) Empty() bool { return r.text == "" }

// Entries are the hosts, in file order: every line ending in a newline
// with a name ('while IFS="|" read ...; [[ -n "$name" ]] || continue',
// which leaves out a last line without one).
func (r *Registry) Entries() []Entry {
	var out []Entry
	lines := strings.Split(r.text, "\n")
	for _, l := range lines[:len(lines)-1] {
		if e := parseEntry(l); e.Name != "" {
			out = append(out, e)
		}
	}
	return out
}

// Names is "cut -d'|' -f1" of the file, each line's first field, blank
// ones included (what 'host sync --all' walks).
func (r *Registry) Names() []string {
	var out []string
	for _, l := range awkRecords(r.text) {
		name, _, _ := strings.Cut(l, "|")
		out = append(out, name)
	}
	return out
}

// Find is host_record: the first line whose name is name.
func (r *Registry) Find(name string) (Entry, bool) {
	for _, l := range awkRecords(r.text) {
		if awkEqual(awkField(awkFields(l, "|"), 1), name) {
			return parseEntry(l), true
		}
	}
	return Entry{}, false
}

// Method is host_method: the method a registered host was enrolled with,
// "" when it is not registered.
func (r *Registry) Method(name string) string {
	e, ok := r.Find(name)
	if !ok || e.Line == "" {
		return ""
	}
	// cut -d'|' -f7: the seventh field, or the whole line when it has no '|'.
	m := ""
	if f := strings.Split(e.Line, "|"); len(f) == 1 {
		m = e.Line
	} else if len(f) >= 7 {
		m = f[6]
	}
	if _, ok := MethodBackend(m); !ok {
		return Tacplus
	}
	return m
}

// ScopeInUse reports whether a host uses scope ("awk -F'|' '$4 == s'").
func (r *Registry) ScopeInUse(scope string) bool {
	for _, l := range awkRecords(r.text) {
		if awkEqual(awkField(awkFields(l, "|"), 4), scope) {
			return true
		}
	}
	return false
}

// OtherHostsUse reports whether a host other than name uses scope
// ("awk -F'|' '$4 == s && $1 != n'").
func (r *Registry) OtherHostsUse(scope, name string) bool {
	for _, l := range awkRecords(r.text) {
		f := awkFields(l, "|")
		if awkEqual(awkField(f, 4), scope) && !awkEqual(awkField(f, 1), name) {
			return true
		}
	}
	return false
}

// Forget is host_forget: every line of name removed, the file rewritten
// with mode 0600. Nothing happens when there is no file.
func (r *Registry) Forget(name string) error {
	if !r.found {
		return nil
	}
	var b strings.Builder
	for _, l := range awkRecords(r.text) {
		if !awkEqual(awkField(awkFields(l, "|"), 1), name) {
			b.WriteString(l + "\n")
		}
	}
	if err := replaceFile(r.Path, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return r.Load()
}

// Remember is host_remember: e's old lines forgotten, its line appended,
// the file mode 0600.
func (r *Registry) Remember(e Entry) error {
	if err := r.Forget(e.Name); err != nil {
		return err
	}
	f, err := os.OpenFile(r.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(e.format() + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(r.Path, 0o600); err != nil {
		return err
	}
	return r.Load()
}
