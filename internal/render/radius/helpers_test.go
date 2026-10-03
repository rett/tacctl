package radius_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/render/radius"
	"github.com/rett/tacctl/internal/yamlpy"
)

const (
	fixtures = "../../../tests/fixtures/"
	golden   = fixtures + "golden/"
)

// backends is the registry tacctl.yaml's schema is built for.
var backends = []string{"tacacs", "radius"}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// loadModel is use_store: the model of a store file.
func loadModel(t *testing.T, path string) *model.Model {
	t.Helper()
	_, m, err := model.LoadStore(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return m
}

// radiusModel is the model of the radius store fixture (use_store
// store.radius.yaml).
func radiusModel(t *testing.T) *model.Model {
	t.Helper()
	return loadModel(t, fixtures+"store.radius.yaml")
}

// cfg is a tacctl.yaml in a temporary directory, with no overrides.
func cfg(t *testing.T) *conf.Config {
	t.Helper()
	return conf.Load(filepath.Join(t.TempDir(), "tacctl.yaml"), backends)
}

// layout is the production layout of a family (no test overrides).
func layout(family string) paths.RadiusPaths {
	return paths.Resolve(paths.NewEnv(nil), "", func(string) bool { return false }).Radius(family)
}

// params is the renderer's parameters for the production layout of family.
func params(family string) radius.Params { return radius.ParamsFor(layout(family)) }

// render is render_as: the radius fixture model, the default view, the
// production paths of family.
func render(t *testing.T, m *model.Model, family string) *radius.Output {
	t.Helper()
	out, err := radius.Render(m, cfg(t).Merged(), params(family))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

// renderErr is a render that must be refused; its message is returned.
func renderErr(t *testing.T, m *model.Model) string {
	t.Helper()
	out, err := radius.Render(m, cfg(t).Merged(), params("debian"))
	if err == nil {
		t.Fatalf("render succeeded, wanted an error; conf:\n%s", out.Conf)
	}
	if out != nil {
		t.Errorf("a refused render returned output")
	}
	return err.Error()
}

var reRenderID = regexp.MustCompile(`(?m)^# render id: (\S*)$`)

// renderID is sed -n 's/^# render id: //p' of the conf.
func renderID(t *testing.T, conf string) string {
	t.Helper()
	m := reRenderID.FindStringSubmatch(conf)
	if m == nil {
		t.Fatal("no render id line in the conf")
	}
	return m[1]
}

// lines is the text split at newlines, without the empty tail.
func lines(s string) []string {
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// between is sed -n '/<from>/,/<to>/p': from the first line matching from
// to the next line matching to (inclusive).
func between(s string, from, to *regexp.Regexp) []string {
	var out []string
	in := false
	for _, l := range lines(s) {
		if !in && from.MatchString(l) {
			in = true
		}
		if in {
			out = append(out, l)
			if to.MatchString(l) {
				break
			}
		}
	}
	return out
}

// clientBlock is client_block: the client{} block of name, lines trimmed.
func clientBlock(conf, name string) []string {
	var out []string
	for _, l := range between(conf, regexp.MustCompile(`^\tclient `+regexp.QuoteMeta(name)+` \{`), regexp.MustCompile(`^\t\}`)) {
		out = append(out, strings.TrimLeft(l, " \t"))
	}
	return out
}

func has(ls []string, want string) bool {
	for _, l := range ls {
		if l == want {
			return true
		}
	}
	return false
}

func count(s string, re *regexp.Regexp) int { return len(re.FindAllString(s, -1)) }

func scope(t *testing.T, m *model.Model, name string) *model.Scope {
	t.Helper()
	s := m.Scope(name)
	if s == nil {
		t.Fatalf("no scope %s", name)
	}
	return s
}

// merged builds a view with the given listeners.radius entries written as
// JSON, through conf's own setter (so the schema vets them).
func mergedWith(t *testing.T, listeners map[string]string, order ...string) *yamlpy.Map {
	t.Helper()
	c := cfg(t)
	for _, name := range order {
		if err := c.SetJSON("listeners.radius."+name, listeners[name]); err != nil {
			t.Fatalf("set listeners.radius.%s: %v", name, err)
		}
	}
	return c.Merged()
}

// loadConf is conf.Load of a file, with the registry of backends.
func loadConf(path string) *conf.Config { return conf.Load(path, backends) }
