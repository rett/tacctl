package tacacs

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// LegacyResult is what the importer of 'store import' (legacy_load,
// lib/model.sh) makes of a tacquito.yaml, as far as the read-back needs
// it: the model it read and the problems it reported.
type LegacyResult struct {
	Model   *model.Model
	Errors  []string // the report's 'errors'
	Dropped []string // the report's 'dropped'
	// Extras are the per-group device settings the importer found (the
	// Junos set_values and the wti service), by group name.
	Extras map[string]*store.GroupExtras
}

// LegacyLoader reads a tacquito.yaml with the importer, without the
// password-date and disabled-hash side files (legacy_load(path)). An error
// is a file the importer refuses outright (it does not parse, its top
// level is not a mapping), worded as the importer words it.
type LegacyLoader func(path string) (*LegacyResult, error)

// canonList is canonical_cidr_list on a list of strings: canonicalised,
// deduplicated and in render order, or the list untouched when an entry
// does not parse.
func canonList(items []string) []string {
	var out []string
	for _, c := range items {
		canon, ok := store.CanonicalCIDR(c)
		if !ok {
			return items
		}
		if !slices.Contains(out, canon) {
			out = append(out, canon)
		}
	}
	return sortCIDRs(out)
}

type groupFacts struct {
	priv  *int
	class string
}

type userFacts struct {
	group  string
	scopes []string
	hash   string // "" for None
}

type scopeFacts struct {
	prefixes []string
	secret   string
}

func intEq(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// ReadbackProblems is readback_problems: read the tacquito.yaml at path
// with the importer and list where it says something other than m: what
// the importer reports (its errors and what it dropped), then 'groups
// differ', 'users differ', 'scopes differ', 'filters.<k> differs'. Command
// rules are not compared (they come from tacctl.yaml; see Readback). An
// error is the importer refusing the file.
func ReadbackProblems(path string, m *model.Model, load LegacyLoader) ([]string, error) {
	if load == nil {
		return nil, &rendered.Error{Msg: "internal: no legacy loader to read the rendered config back with"}
	}
	back, err := load(path)
	if err != nil {
		return nil, err
	}
	var problems []string
	for _, msg := range back.Errors {
		problems = append(problems, "importer reports: "+msg)
	}
	for _, msg := range back.Dropped {
		problems = append(problems, "importer reports: "+msg)
	}
	b := back.Model

	wantG, gotG := map[string]groupFacts{}, map[string]groupFacts{}
	for _, g := range m.Groups {
		wantG[g.Name] = groupFacts{g.PrivLvl, g.JuniperClass}
	}
	for _, g := range b.Groups {
		gotG[g.Name] = groupFacts{g.PrivLvl, g.JuniperClass}
	}
	if !mapsEqual(wantG, gotG, func(a, b groupFacts) bool { return intEq(a.priv, b.priv) && a.class == b.class }) {
		problems = append(problems, "groups differ")
	}

	wantU, gotU := map[string]userFacts{}, map[string]userFacts{}
	for _, u := range m.Users {
		h := RenderedHash(u)
		if h == hash.DisabledMarkerHex {
			h = ""
		}
		var mine []string
		for _, s := range u.Scopes {
			if sc := m.Scope(s); sc != nil && sc.ServedBy(Protocol) {
				mine = append(mine, s)
			}
		}
		wantU[u.Name] = userFacts{u.Group, mine, h}
	}
	for _, u := range b.Users {
		h := u.Hash
		if u.Disabled {
			h = ""
		}
		gotU[u.Name] = userFacts{u.Group, u.Scopes, h}
	}
	if !mapsEqual(wantU, gotU, func(a, b userFacts) bool {
		return a.group == b.group && slices.Equal(a.scopes, b.scopes) && a.hash == b.hash
	}) {
		problems = append(problems, "users differ")
	}

	wantS, gotS := map[string]scopeFacts{}, map[string]scopeFacts{}
	for _, s := range m.Scopes {
		if s.ServedBy(Protocol) {
			wantS[s.Name] = scopeFacts{canonList(s.Prefixes), s.Secret}
		}
	}
	for _, s := range b.Scopes {
		gotS[s.Name] = scopeFacts{canonList(s.Prefixes), s.Secret}
	}
	if !mapsEqual(wantS, gotS, func(a, b scopeFacts) bool {
		return slices.Equal(a.prefixes, b.prefixes) && a.secret == b.secret
	}) {
		problems = append(problems, "scopes differ")
	}

	for _, k := range store.FilterKeys {
		want, got := m.Filters.Allow, b.Filters.Allow
		if k == "deny" {
			want, got = m.Filters.Deny, b.Filters.Deny
		}
		if !slices.Equal(canonList(want), canonList(got)) {
			problems = append(problems, fmt.Sprintf("filters.%s differs", k))
		}
	}
	return problems, nil
}

func mapsEqual[V any](a, b map[string]V, eq func(V, V) bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || !eq(va, vb) {
			return false
		}
	}
	return true
}

// MatchesModel is the 'matches-model' check behind the render gate's
// adoption: the file at path, read with the importer, holds the groups,
// users, scopes and filters of m and nothing the store cannot represent.
// Any failure counts as "does not match".
func MatchesModel(path string, m *model.Model, load LegacyLoader) bool {
	problems, err := ReadbackProblems(path, m, load)
	return err == nil && len(problems) == 0
}

// groupsByName is render_readback's by_name: the top-level mappings of the
// file (yaml.safe_load, store.ReadLegacyYAML) that have a 'services' list,
// by their 'name'; a later one of a name wins.
func groupsByName(path string) (map[string]*yamlpy.Map, error) {
	doc, err := store.ReadLegacyYAML(path)
	if err != nil {
		return nil, err
	}
	out := map[string]*yamlpy.Map{}
	top, ok := doc.(*yamlpy.Map)
	if !ok {
		return out, nil
	}
	for _, v := range top.All() {
		g, ok := v.(*yamlpy.Map)
		if !ok {
			continue
		}
		if svc, _ := g.Get("services"); !isList(svc) {
			continue
		}
		// A name that is not a string never equals a group's name.
		if name, ok := g.Get("name"); ok {
			if s, isStr := name.(string); isStr {
				out[s] = g
			}
		}
	}
	return out, nil
}

func isList(v any) bool {
	_, ok := py.List(v)
	return ok
}

// wantCommands is what the file must say for a group's rules, as
// yaml.safe_load reads it: name, the action's number, and match when there
// is one.
func wantCommands(rules []Rule) []any {
	out := []any{}
	for _, r := range rules {
		c := yamlpy.NewMap("name", r.Name, "action", Actions[r.Action])
		if len(r.Match) > 0 {
			match := make([]any, len(r.Match))
			for i, s := range r.Match {
				match[i] = renderMatch(s)
			}
			c.Set("match", match)
		}
		out = append(out, c)
	}
	return out
}

// Readback is render_readback: read the rendered file at path back with
// the importer and check it says what m says (ReadbackProblems), and that
// every group carries the command rules of tacctl.yaml character for
// character. It guards every render against a quoting or layout bug: a
// file that fails here is never installed.
func Readback(path string, m *model.Model, view *yamlpy.Map, load LegacyLoader) error {
	problems, err := ReadbackProblems(path, m, load)
	if err != nil {
		return err
	}
	devauth, err := devauthProblems(path, m, view, load)
	if err != nil {
		return err
	}
	problems = append(problems, devauth...)
	byName, err := groupsByName(path)
	if err != nil {
		return err
	}
	for _, g := range m.Groups {
		rules, err := GroupCommands(view, g.Name)
		if err != nil {
			return err
		}
		var got any = []any{}
		if grp := byName[g.Name]; grp != nil {
			if c, _ := grp.Get("commands"); truthy(c) {
				got = c
			}
		}
		if !py.Equal(wantCommands(rules), got) {
			problems = append(problems, fmt.Sprintf("command rules of group '%s' differ", g.Name))
		}
	}
	if len(problems) > 0 {
		return &rendered.Error{Msg: "internal error: the rendered config does not read back as the model (" +
			strings.Join(problems, "; ") + "). Nothing was written."}
	}
	return nil
}

// Chowner gives a file to tacquito:tacquito, best effort (nothing happens
// when the account does not exist or the call is not permitted).
type Chowner func(path string)

// RenderToFile is render_to_file: Render, write the text to a temp file
// .tacquito.*.tmp beside out (0640, fsync), read it back (Readback), give
// it to tacquito:tacquito (chown, best effort) and rename it to out. On
// any failure nothing is left behind and out is untouched. It returns the
// rendered text.
func RenderToFile(st *store.Store, view *yamlpy.Map, out string, load LegacyLoader, chown Chowner) ([]byte, error) {
	text, err := Render(st, view)
	if err != nil {
		return nil, err
	}
	d := filepath.Dir(out)
	f, err := os.CreateTemp(d, ".tacquito.*.tmp")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o640); err != nil {
		return nil, err
	}
	if _, err := f.Write(text); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := Readback(tmp, model.FromStore(st), view, load); err != nil {
		return nil, err
	}
	if chown != nil {
		chown(tmp)
	}
	if err := os.Rename(tmp, out); err != nil {
		return nil, err
	}
	ok = true
	return text, nil
}

// CheckOverrides is load_conf_view's guard: a tacctl.yaml that does not
// parse would leave the merged view at the shipped defaults, and with it
// the default command rules, so rendering refuses it ('<path>: <problem>
// (line L, column C) -- fix it before rendering'), and one whose top level
// is not a mapping ('<path>: not a YAML mapping -- fix it before
// rendering'). A missing file (or path "") is fine; a file that cannot be
// read is the file-system error.
func CheckOverrides(path string) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	v, err := pyyaml.Load(data, path)
	if err != nil {
		return &rendered.Error{Msg: yamlProblem(path, err) + " -- fix it before rendering"}
	}
	if v == nil {
		return nil
	}
	if _, ok := v.(*yamlpy.Map); !ok {
		return &rendered.Error{Msg: path + ": not a YAML mapping -- fix it before rendering"}
	}
	return nil
}

// yamlProblem is yaml_problem (lib/store.sh): '<path>: <problem>' plus
// ' (line L, column C)' when PyYAML marked where. Errors 0.1.16 met with a
// Python traceback instead (§3.9 items 15 and 16) give their own text.
func yamlProblem(path string, err error) string {
	var pe *pyyaml.Error
	if errors.As(err, &pe) {
		problem := pe.Problem
		if problem == "" {
			problem = "invalid YAML"
		}
		where := ""
		if pe.ProblemMark != nil {
			where = fmt.Sprintf(" (line %d, column %d)", pe.ProblemMark.Line+1, pe.ProblemMark.Column+1)
		}
		return path + ": " + problem + where
	}
	var why interface{ Why() string }
	if errors.As(err, &why) {
		return path + ": " + why.Why()
	}
	return path + ": " + err.Error()
}

// devauthProblems checks the per-group device settings of 0.2.2 read back
// as tacctl.yaml says them: each group's Junos deny values and the
// priv-lvl of its wti service (none for a group without a WTI level).
func devauthProblems(path string, m *model.Model, view *yamlpy.Map, load LegacyLoader) ([]string, error) {
	back, err := load(path)
	if err != nil {
		return nil, err
	}
	cfg := conf.View(view)
	var problems []string
	for _, g := range m.Groups {
		got := back.Extras[g.Name]
		if got == nil {
			got = &store.GroupExtras{}
		}
		want := map[string]string{}
		for _, attr := range conf.JunosAttrs {
			if items := policy.JunosSet(cfg, g.Name, attr); len(items) > 0 {
				want[conf.JunosArg(attr)] = conf.JunosValue(items)
			}
		}
		if !maps.Equal(want, got.Junos) && (len(want) > 0 || len(got.Junos) > 0) {
			problems = append(problems, fmt.Sprintf("junos values of group '%s' differ", g.Name))
		}
		level, over := policy.WTILevel(cfg, g.Name, 0)
		switch {
		case !over && got.WTI != nil:
			problems = append(problems, fmt.Sprintf("wti service of group '%s' differs", g.Name))
		case over && !py.Equal(policy.WTIPrivLvl(level), got.WTI):
			problems = append(problems, fmt.Sprintf("wti service of group '%s' differs", g.Name))
		}
	}
	return problems, nil
}
