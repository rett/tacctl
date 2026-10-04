package devices

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/assets"
)

// Template is a device template as resolve_template finds it: the
// operator's copy in the state directory's templates/ when there is one,
// else the shipped one embedded in the binary.
type Template struct {
	Name string // e.g. "cisco-radius"
	// Path is the operator's file, or "" for the shipped template.
	Path string
	Text string
}

// Origin is what the 'Using template:' note names: the operator's file, or
// 'built-in <name>.template' (docs/plans/go-rewrite.md 3.9 item 3; 0.1.16
// printed the path of the shipped file in its checkout).
func (t Template) Origin() string {
	if t.Path != "" {
		return t.Path
	}
	return "built-in " + t.Name + ".template"
}

// ResolveTemplate is resolve_template <name>: overrideDir/<name>.template
// when it is a regular file (or a link to one), else the embedded template.
// The embedded copy always exists for the names tacctl renders, so the
// inline fallbacks of 0.1.16 are gone (3.7).
func ResolveTemplate(overrideDir, name string) (Template, error) {
	if overrideDir != "" {
		p := filepath.Join(overrideDir, name+".template")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return Template{}, err
			}
			return Template{Name: name, Path: p, Text: string(b)}, nil
		}
	}
	text, ok := assets.Template(name)
	if !ok {
		return Template{}, errors.New("internal: no template " + name + ".template")
	}
	return Template{Name: name, Text: text}, nil
}

// isNameStart and isNameChar are envsubst's variable-name characters
// (ASCII only, whatever the locale).
func isNameStart(c byte) bool { return c == '_' || (c|0x20 >= 'a' && c|0x20 <= 'z') }

func isNameChar(c byte) bool { return isNameStart(c) || (c >= '0' && c <= '9') }

// Expand is "envsubst '<the ${VAR} of allowed>'" with vars as the
// environment (GNU gettext's subst_from_stdin): $NAME and ${NAME} are
// replaced by vars[NAME] (nothing when it is not set) when NAME is
// allowed, and kept as written otherwise; a '$' not followed by a name,
// and a '${NAME' not closed by '}', are kept as written.
func Expand(text string, allowed []string, vars map[string]string) string {
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c != '$' {
			b.WriteByte(c)
			continue
		}
		j := i + 1
		brace := j < len(text) && text[j] == '{'
		if brace {
			j++
		}
		if j >= len(text) || !isNameStart(text[j]) {
			// '$' alone; the '{' (if any) is read again as text.
			b.WriteByte('$')
			continue
		}
		k := j
		for k < len(text) && isNameChar(text[k]) {
			k++
		}
		name := text[j:k]
		end := k // the first byte after what was consumed
		closed := false
		if brace {
			if k < len(text) && text[k] == '}' {
				closed = true
				end = k + 1
			}
		}
		if (!brace || closed) && ok[name] {
			b.WriteString(vars[name])
		} else {
			b.WriteString(text[i:end])
		}
		i = end - 1
	}
	return b.String()
}

// DropBlank is "awk 'NF'" (mawk): the lines with a field kept, those that
// are empty or hold only blanks and tabs dropped, every line ended by a
// newline (the last one too).
func DropBlank(text string) string {
	var b strings.Builder
	lines := strings.Split(text, "\n")
	if strings.HasSuffix(text, "\n") {
		lines = lines[:len(lines)-1]
	}
	for _, l := range lines {
		if strings.Trim(l, " \t") == "" {
			continue
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}
